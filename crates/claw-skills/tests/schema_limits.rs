//! Schema resource-limit regression tests.

use std::num::NonZeroUsize;

use claw_skills::{
    ExactJsonDocument, ParameterValidationError, ParameterViolationKind, SchemaErrorKind,
    ValidationLimits, validate_exact_parameters_with_limits, validate_parameters_with_limits,
    validate_schema_with_limits,
};
use serde_json::{Value, json};

const fn limits(max_violations: usize, max_path_bytes: usize) -> ValidationLimits {
    ValidationLimits {
        max_violations: NonZeroUsize::new(max_violations).expect("positive violation limit"),
        max_depth: NonZeroUsize::new(16).expect("positive depth limit"),
        max_path_bytes: NonZeroUsize::new(max_path_bytes).expect("positive path limit"),
        max_schema_nodes: NonZeroUsize::new(32).expect("positive node limit"),
        max_input_nodes: NonZeroUsize::new(32).expect("positive input limit"),
        max_comparison_nodes: NonZeroUsize::new(32).expect("positive comparison limit"),
    }
}

#[test]
fn violation_limit_stops_before_later_path_allocation() {
    let schema = json!({
        "type": "object",
        "additionalProperties": false
    });
    let mut parameters = serde_json::Map::new();
    parameters.insert("a".to_owned(), json!(1));
    parameters.insert("b".to_owned(), json!(2));
    parameters.insert("this-key-would-exceed-the-path-limit".to_owned(), json!(3));

    let error = validate_parameters_with_limits(&schema, &Value::Object(parameters), limits(2, 8))
        .expect_err("input has undeclared properties");
    let ParameterValidationError::Violations {
        violations,
        limit_reached,
    } = error
    else {
        panic!("the violation cap must stop before examining the long third path");
    };
    assert!(limit_reached);
    assert_eq!(violations.len(), 2);
    assert_eq!(violations[0].path, "$.a");
    assert_eq!(violations[1].path, "$.b");
    assert!(
        violations
            .iter()
            .all(|violation| violation.kind == ParameterViolationKind::AdditionalProperty)
    );
}

#[test]
fn schema_paths_are_rejected_before_unbounded_allocation() {
    let schema = json!({
        "type": "object",
        "properties": {
            "this-property-name-is-too-long": {"type": "string"}
        }
    });

    let error = validate_schema_with_limits(&schema, limits(4, 12))
        .expect_err("schema diagnostic paths are bounded");
    assert_eq!(error.kind, SchemaErrorKind::ResourceLimit);
    assert_eq!(error.path, "$");
}

#[test]
fn schema_node_budget_is_enforced_deterministically() {
    let schema = json!({
        "type": "object",
        "properties": {
            "first": {},
            "second": {}
        }
    });
    let mut constrained = limits(4, 128);
    constrained.max_schema_nodes = NonZeroUsize::new(4).expect("positive node limit");

    let error =
        validate_schema_with_limits(&schema, constrained).expect_err("third node exceeds budget");
    assert_eq!(error.kind, SchemaErrorKind::ResourceLimit);
    assert_eq!(error.path, "$.properties.second");
}

#[test]
fn schema_construction_enforces_depth_during_iterative_assembly() {
    let mut schema = json!({});
    for _ in 0..32 {
        schema = json!({"items": schema});
    }
    let mut constrained = limits(4, 128);
    constrained.max_depth = NonZeroUsize::new(4).expect("positive depth limit");

    let error = validate_schema_with_limits(&schema, constrained)
        .expect_err("construction must stop before assembling the fifth level");
    assert_eq!(error.kind, SchemaErrorKind::ResourceLimit);
    assert_eq!(error.path, "$.items.items.items.items");
}

#[test]
fn schema_node_budget_includes_required_and_enum_entries() {
    let required_schema = json!({
        "type": "object",
        "required": ["first", "second"]
    });
    let mut constrained = limits(4, 128);
    constrained.max_schema_nodes = NonZeroUsize::new(4).expect("positive node limit");
    let error = validate_schema_with_limits(&required_schema, constrained)
        .expect_err("required entries consume the schema budget");
    assert_eq!(error.kind, SchemaErrorKind::ResourceLimit);
    assert_eq!(error.path, "$.required[1]");

    let enum_schema = json!({"enum": [1, 2]});
    constrained.max_schema_nodes = NonZeroUsize::new(3).expect("positive node limit");
    let error = validate_schema_with_limits(&enum_schema, constrained)
        .expect_err("enum entries consume the schema budget");
    assert_eq!(error.kind, SchemaErrorKind::ResourceLimit);
    assert_eq!(error.path, "$.enum[1]");
}

#[test]
fn unsupported_keywords_are_rejected_only_after_a_complete_bounded_walk() {
    for keyword in [
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "const",
        "allOf",
        "anyOf",
        "oneOf",
        "not",
        "if",
        "then",
        "else",
        "contains",
        "format",
        "pattern",
        "patternProperties",
        "$ref",
        "$dynamicRef",
    ] {
        let schema: Value =
            serde_json::from_str(&format!(r#"{{"{keyword}":true}}"#)).expect("valid JSON");
        let error = validate_schema_with_limits(&schema, limits(4, 128))
            .expect_err("unsupported assertion and applicator keywords fail closed");
        assert_eq!(error.kind, SchemaErrorKind::UnsupportedKeyword);
        assert_eq!(error.path, format!("$.{keyword}"));
    }

    let schema = json!({"allOf": [{}, {}, {}]});
    let mut constrained = limits(4, 128);
    constrained.max_schema_nodes = NonZeroUsize::new(3).expect("positive node limit");
    let error = validate_schema_with_limits(&schema, constrained)
        .expect_err("complete traversal reaches its bound before keyword admission");
    assert_eq!(error.kind, SchemaErrorKind::ResourceLimit);
    assert_eq!(error.path, "$.allOf[1]");
}

#[test]
fn input_node_budget_bounds_successful_array_traversal() {
    let schema = json!({
        "type": "array",
        "items": {"type": "integer"}
    });
    let mut constrained = limits(4, 128);
    constrained.max_input_nodes = NonZeroUsize::new(2).expect("positive input limit");

    let error = validate_parameters_with_limits(&schema, &json!([1, 2]), constrained)
        .expect_err("the root and first item consume the input budget");
    assert_eq!(
        error,
        ParameterValidationError::ResourceLimit {
            path: "$[1]".to_owned()
        }
    );
}

#[test]
fn unconstrained_schema_still_walks_the_complete_input_tree() {
    let schema = json!({});
    let mut constrained = limits(4, 128);
    constrained.max_input_nodes = NonZeroUsize::new(2).expect("positive input limit");

    let error = validate_parameters_with_limits(&schema, &json!([1, 2]), constrained)
        .expect_err("unconstrained subtrees still consume the input budget");
    assert_eq!(
        error,
        ParameterValidationError::ResourceLimit {
            path: "$[1]".to_owned()
        }
    );
}

#[test]
fn enum_comparison_budget_bounds_nested_value_walks() {
    let schema = json!({"enum": [[1, 2]]});
    let mut constrained = limits(4, 128);
    constrained.max_comparison_nodes = NonZeroUsize::new(2).expect("positive comparison limit");

    let error = validate_parameters_with_limits(&schema, &json!([1, 3]), constrained)
        .expect_err("nested enum comparison exceeds its own budget");
    assert_eq!(
        error,
        ParameterValidationError::ResourceLimit {
            path: "$[1]".to_owned()
        }
    );
}

#[test]
fn decimal_comparison_work_is_charged_per_array_item() {
    let number = "1".repeat(64);
    let schema = ExactJsonDocument::parse(&format!(
        r#"{{"type":"array","items":{{"minimum":{number}}}}}"#
    ))
    .expect("valid exact schema");
    let parameters =
        ExactJsonDocument::parse(&format!("[{number},{number}]")).expect("valid exact parameters");
    let mut constrained = limits(4, 128);
    constrained.max_comparison_nodes = NonZeroUsize::new(3).expect("positive comparison limit");

    let error = validate_exact_parameters_with_limits(&schema, &parameters, constrained)
        .expect_err("the second large-decimal comparison exceeds the work budget");
    assert_eq!(
        error,
        ParameterValidationError::ResourceLimit {
            path: "$[1]".to_owned()
        }
    );
}

#[test]
fn exact_json_rejects_raw_documents_and_decoded_strings_before_value_construction() {
    let oversized_document = format!("{}null", " ".repeat(1_048_576));
    let error = ExactJsonDocument::parse(&oversized_document)
        .expect_err("raw document bytes are bounded before JSON parsing");
    assert!(error.to_string().contains("resource limit at $"));

    let oversized_string = format!("\"{}\"", r"\u0061".repeat(65_537));
    let error = ExactJsonDocument::parse(&oversized_string)
        .expect_err("decoded string bytes are bounded before string allocation");
    assert!(error.to_string().contains("resource limit at $"));
}

#[test]
fn direct_value_inputs_enforce_string_limits_during_exact_construction() {
    let schema = json!({"type": "string"});
    let input = Value::String("a".repeat(65_537));

    assert_eq!(
        validate_parameters_with_limits(&schema, &input, limits(4, 128)),
        Err(ParameterValidationError::ResourceLimit {
            path: "$".to_owned()
        })
    );
}

#[test]
fn string_equality_work_consumes_the_comparison_budget_by_bytes() {
    let value = "a".repeat(64);
    let schema = json!({"enum": [value.clone()]});
    let mut constrained = limits(4, 128);
    constrained.max_comparison_nodes = NonZeroUsize::new(1).expect("positive comparison limit");

    assert_eq!(
        validate_parameters_with_limits(&schema, &json!(value), constrained),
        Err(ParameterValidationError::ResourceLimit {
            path: "$".to_owned()
        })
    );
}

#[test]
fn exact_numbers_beyond_the_numeric_budget_are_resource_limits() {
    let schema = ExactJsonDocument::parse(r#"{"type":"integer"}"#).expect("valid exact schema");
    let parameters =
        ExactJsonDocument::parse("1e1000001").expect("raw exact number remains representable");

    assert_eq!(
        validate_exact_parameters_with_limits(&schema, &parameters, limits(4, 128)),
        Err(ParameterValidationError::ResourceLimit {
            path: "$".to_owned()
        })
    );
}
