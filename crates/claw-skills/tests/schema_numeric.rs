//! Exact numeric comparison regressions for the supported JSON Schema subset.

use claw_skills::{
    ParameterValidationError, ParameterViolation, ParameterViolationKind, validate_parameters,
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
