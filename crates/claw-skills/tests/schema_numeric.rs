//! Exact numeric comparison regressions for the supported JSON Schema subset.

use claw_skills::{
    ExactJsonDocument, ParameterValidationError, ParameterViolation, ParameterViolationKind,
    SchemaError, SchemaErrorKind, validate_exact_parameters, validate_parameters,
};
use serde_json::{Value, json};

fn assert_violation(schema: &Value, input: &Value, kind: ParameterViolationKind) {
    assert_eq!(
        validate_parameters(schema, input),
        Err(ParameterValidationError::Violations {
            violations: vec![ParameterViolation {
                path: "$".to_owned(),
                kind,
            }],
            limit_reached: false,
        })
    );
}

fn assert_exact_violation(
    schema: &ExactJsonDocument,
    input: &ExactJsonDocument,
    kind: ParameterViolationKind,
) {
    assert_eq!(
        validate_exact_parameters(schema, input),
        Err(ParameterValidationError::Violations {
            violations: vec![ParameterViolation {
                path: "$".to_owned(),
                kind,
            }],
            limit_reached: false,
        })
    );
}

fn assert_exact_schema_error(schema: &str, path: &str, kind: SchemaErrorKind) {
    let schema = ExactJsonDocument::parse(schema).expect("valid schema JSON");
    let input = ExactJsonDocument::parse(r#""""#).expect("valid input");
    assert_eq!(
        validate_exact_parameters(&schema, &input),
        Err(ParameterValidationError::InvalidSchema(SchemaError {
            path: path.to_owned(),
            kind,
        }))
    );
}

#[test]
fn integer_bounds_remain_exact_above_f64_precision() {
    assert_violation(
        &json!({"minimum": 9_007_199_254_740_993_u64}),
        &json!(9_007_199_254_740_992_u64),
        ParameterViolationKind::NumberTooSmall,
    );
    assert_violation(
        &json!({"maximum": 18_446_744_073_709_551_614_u64}),
        &json!(18_446_744_073_709_551_615_u64),
        ParameterViolationKind::NumberTooLarge,
    );
    assert_violation(
        &json!({"minimum": -9_007_199_254_740_993_i64}),
        &json!(-9_007_199_254_740_994_i64),
        ParameterViolationKind::NumberTooSmall,
    );
}

#[test]
fn integer_and_float_bounds_compare_by_mathematical_value() {
    assert_violation(
        &json!({"minimum": 9_007_199_254_740_993_u64}),
        &json!(9_007_199_254_740_992.0_f64),
        ParameterViolationKind::NumberTooSmall,
    );
    assert_eq!(
        validate_parameters(&json!({"minimum": 1.0}), &json!(1_u64)),
        Ok(())
    );
    assert_eq!(
        validate_parameters(&json!({"maximum": 1.5}), &json!(1_u64)),
        Ok(())
    );
}

#[test]
fn enum_uses_json_schema_numeric_equality() {
    assert_eq!(
        validate_parameters(&json!({"enum": [1]}), &json!(1.0)),
        Ok(())
    );
    assert_violation(
        &json!({"enum": [9_007_199_254_740_993_u64]}),
        &json!(9_007_199_254_740_992_u64),
        ParameterViolationKind::NotInEnum,
    );
}

#[test]
fn decimal_lexemes_are_compared_without_binary_float_rounding() {
    let minimum =
        ExactJsonDocument::parse(r#"{"minimum":9007199254740993.0}"#).expect("valid schema");
    let below = ExactJsonDocument::parse("9007199254740992.9").expect("valid input");
    assert_exact_violation(&minimum, &below, ParameterViolationKind::NumberTooSmall);

    let decimal_enum =
        ExactJsonDocument::parse(r#"{"enum":[9007199254740993.0]}"#).expect("valid schema");
    let equal_integer = ExactJsonDocument::parse("9007199254740993").expect("valid input");
    assert_eq!(
        validate_exact_parameters(&decimal_enum, &equal_integer),
        Ok(())
    );
    let rounded_neighbor = ExactJsonDocument::parse("9007199254740992.0").expect("valid input");
    assert_exact_violation(
        &decimal_enum,
        &rounded_neighbor,
        ParameterViolationKind::NotInEnum,
    );

    let huge_exponent = ExactJsonDocument::parse(r#"{"minimum":1e100000}"#).expect("valid schema");
    let smaller = ExactJsonDocument::parse("9e99999").expect("valid input");
    assert_exact_violation(
        &huge_exponent,
        &smaller,
        ParameterViolationKind::NumberTooSmall,
    );

    let integer_schema = ExactJsonDocument::parse(r#"{"type":"integer"}"#).expect("valid schema");
    assert_eq!(
        validate_exact_parameters(
            &integer_schema,
            &ExactJsonDocument::parse("9007199254740993.0").expect("valid input")
        ),
        Ok(())
    );
    assert_exact_violation(
        &integer_schema,
        &ExactJsonDocument::parse("9007199254740993.1").expect("valid input"),
        ParameterViolationKind::TypeMismatch,
    );
}

#[test]
fn exact_length_bounds_accept_only_bounded_representable_integers() {
    let minimum = ExactJsonDocument::parse(r#"{"minLength":1.0}"#).expect("valid schema");
    assert_exact_violation(
        &minimum,
        &ExactJsonDocument::parse(r#""""#).expect("valid input"),
        ParameterViolationKind::StringTooShort,
    );
    assert_eq!(
        validate_exact_parameters(
            &minimum,
            &ExactJsonDocument::parse(r#""x""#).expect("valid input")
        ),
        Ok(())
    );

    for schema in [
        r#"{"minLength":-1}"#,
        r#"{"minLength":1.5}"#,
        r#"{"minLength":18446744073709551616}"#,
        r#"{"minLength":1e1000001}"#,
        r#"{"maxLength":-1}"#,
    ] {
        let path = if schema.contains("maxLength") {
            "$.maxLength"
        } else {
            "$.minLength"
        };
        assert_exact_schema_error(schema, path, SchemaErrorKind::InvalidLengthBound);
    }
}

#[test]
fn oversized_numeric_bounds_are_rejected_during_schema_admission() {
    assert_exact_schema_error(
        r#"{"minimum":1e1000001}"#,
        "$.minimum",
        SchemaErrorKind::ResourceLimit,
    );
}

#[test]
fn duplicate_object_keys_use_the_last_exact_value() {
    let schema =
        ExactJsonDocument::parse(r#"{"enum":[{"value":9007199254740993}]}"#).expect("valid schema");
    let matching =
        ExactJsonDocument::parse(r#"{"value":1,"value":9007199254740993}"#).expect("valid input");
    assert_eq!(validate_exact_parameters(&schema, &matching), Ok(()));

    let nonmatching =
        ExactJsonDocument::parse(r#"{"value":9007199254740993,"value":1}"#).expect("valid input");
    assert_exact_violation(&schema, &nonmatching, ParameterViolationKind::NotInEnum);

    assert!(
        ExactJsonDocument::parse(r#"{"value":1e1000001,"value":1}"#)
            .expect("valid input")
            .value()
            .is_some(),
        "an overwritten lossy value must not taint the retained object"
    );
}
