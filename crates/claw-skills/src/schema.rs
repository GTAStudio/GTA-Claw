//! Bounded JSON parameter-schema validation.

use serde_json::{Map, Value};

/// Invalid schema document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaError {
    /// JSON path to the invalid schema keyword.
    pub path: String,
    /// Stable error category.
    pub kind: SchemaErrorKind,
}

/// Stable schema error categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaErrorKind {
    /// Schema node is not an object.
    ExpectedObject,
    /// `type` is not a supported JSON type.
    UnsupportedType,
    /// A keyword has the wrong JSON value type.
    InvalidKeywordType,
    /// A numeric bound is negative or non-integral.
    InvalidLengthBound,
    /// `required` contains duplicate property names.
    DuplicateRequiredProperty,
    /// `enum` is empty.
    EmptyEnum,
}

/// One parameter mismatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParameterViolation {
    /// JSON path to the rejected input value.
    pub path: String,
    /// Stable mismatch category.
    pub kind: ParameterViolationKind,
}

/// Stable parameter mismatch categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterViolationKind {
    /// Value does not match the declared JSON type.
    TypeMismatch,
    /// Required object property is absent.
    MissingRequiredProperty,
    /// Object property is not declared while extras are disabled.
    AdditionalProperty,
    /// Value is not present in the declared enum.
    NotInEnum,
    /// String is shorter than `minLength`.
    StringTooShort,
    /// String is longer than `maxLength`.
    StringTooLong,
    /// Number is lower than `minimum`.
    NumberTooSmall,
    /// Number is greater than `maximum`.
    NumberTooLarge,
}

/// Schema or input errors returned by parameter validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParameterValidationError {
    /// The skill's own schema is invalid.
    InvalidSchema(SchemaError),
    /// Input failed one or more schema constraints.
    Violations(Vec<ParameterViolation>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JsonType {
    Object,
    Array,
    String,
    Number,
    Integer,
    Boolean,
    Null,
}

impl JsonType {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "object" => Some(Self::Object),
            "array" => Some(Self::Array),
            "string" => Some(Self::String),
            "number" => Some(Self::Number),
            "integer" => Some(Self::Integer),
            "boolean" => Some(Self::Boolean),
            "null" => Some(Self::Null),
            _ => None,
        }
    }

    fn matches(self, value: &Value) -> bool {
        match self {
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            Self::String => value.is_string(),
            Self::Number => value.is_number(),
            Self::Integer => {
                value.as_i64().is_some()
                    || value.as_u64().is_some()
                    || value.as_f64().is_some_and(|number| number.fract() == 0.0)
            }
            Self::Boolean => value.is_boolean(),
            Self::Null => value.is_null(),
        }
    }
}

/// Validates the supported JSON Schema subset used for skill parameters.
///
/// Supported keywords are `type`, `properties`, `required`,
/// `additionalProperties`, `items`, `enum`, `minLength`, `maxLength`,
/// `minimum`, and `maximum`. Annotation keywords are ignored.
pub fn validate_schema(schema: &Value) -> Result<(), SchemaError> {
    validate_schema_at(schema, "$")
}

fn validate_schema_at(schema: &Value, path: &str) -> Result<(), SchemaError> {
    let object = schema.as_object().ok_or_else(|| SchemaError {
        path: path.to_owned(),
        kind: SchemaErrorKind::ExpectedObject,
    })?;
    validate_type_keyword(object, path)?;
    validate_object_keywords(object, path)?;
    validate_items_keyword(object, path)?;
    validate_enum_keyword(object, path)?;
    validate_length_keyword(object, path, "minLength")?;
    validate_length_keyword(object, path, "maxLength")?;
    validate_number_keyword(object, path, "minimum")?;
    validate_number_keyword(object, path, "maximum")?;
    Ok(())
}

fn validate_type_keyword(object: &Map<String, Value>, path: &str) -> Result<(), SchemaError> {
    if let Some(value) = object.get("type") {
        let name = value.as_str().ok_or_else(|| SchemaError {
            path: format!("{path}.type"),
            kind: SchemaErrorKind::InvalidKeywordType,
        })?;
        if JsonType::parse(name).is_none() {
            return Err(SchemaError {
                path: format!("{path}.type"),
                kind: SchemaErrorKind::UnsupportedType,
            });
        }
    }
    Ok(())
}

fn validate_object_keywords(object: &Map<String, Value>, path: &str) -> Result<(), SchemaError> {
    if let Some(properties) = object.get("properties") {
        let properties = properties.as_object().ok_or_else(|| SchemaError {
            path: format!("{path}.properties"),
            kind: SchemaErrorKind::InvalidKeywordType,
        })?;
        for (name, property_schema) in properties {
            validate_schema_at(property_schema, &format!("{path}.properties.{name}"))?;
        }
    }
    if let Some(required) = object.get("required") {
        let required = required.as_array().ok_or_else(|| SchemaError {
            path: format!("{path}.required"),
            kind: SchemaErrorKind::InvalidKeywordType,
        })?;
        let mut names = Vec::with_capacity(required.len());
        for (index, value) in required.iter().enumerate() {
            let name = value.as_str().ok_or_else(|| SchemaError {
                path: format!("{path}.required[{index}]"),
                kind: SchemaErrorKind::InvalidKeywordType,
            })?;
            if names.contains(&name) {
                return Err(SchemaError {
                    path: format!("{path}.required[{index}]"),
                    kind: SchemaErrorKind::DuplicateRequiredProperty,
                });
            }
            names.push(name);
        }
    }
    if object
        .get("additionalProperties")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(SchemaError {
            path: format!("{path}.additionalProperties"),
            kind: SchemaErrorKind::InvalidKeywordType,
        });
    }
    Ok(())
}

fn validate_items_keyword(object: &Map<String, Value>, path: &str) -> Result<(), SchemaError> {
    if let Some(items) = object.get("items") {
        validate_schema_at(items, &format!("{path}.items"))?;
    }
    Ok(())
}

fn validate_enum_keyword(object: &Map<String, Value>, path: &str) -> Result<(), SchemaError> {
    if let Some(values) = object.get("enum") {
        let values = values.as_array().ok_or_else(|| SchemaError {
            path: format!("{path}.enum"),
            kind: SchemaErrorKind::InvalidKeywordType,
        })?;
        if values.is_empty() {
            return Err(SchemaError {
                path: format!("{path}.enum"),
                kind: SchemaErrorKind::EmptyEnum,
            });
        }
    }
    Ok(())
}

fn validate_length_keyword(
    object: &Map<String, Value>,
    path: &str,
    keyword: &str,
) -> Result<(), SchemaError> {
    if object
        .get(keyword)
        .is_some_and(|value| value.as_u64().is_none())
    {
        return Err(SchemaError {
            path: format!("{path}.{keyword}"),
            kind: SchemaErrorKind::InvalidLengthBound,
        });
    }
    Ok(())
}

fn validate_number_keyword(
    object: &Map<String, Value>,
    path: &str,
    keyword: &str,
) -> Result<(), SchemaError> {
    if object.get(keyword).is_some_and(|value| !value.is_number()) {
        return Err(SchemaError {
            path: format!("{path}.{keyword}"),
            kind: SchemaErrorKind::InvalidKeywordType,
        });
    }
    Ok(())
}

/// Validates one input document against a previously untrusted schema.
pub fn validate_parameters(
    schema: &Value,
    parameters: &Value,
) -> Result<(), ParameterValidationError> {
    validate_schema(schema).map_err(ParameterValidationError::InvalidSchema)?;
    let mut violations = Vec::new();
    validate_value(schema, parameters, "$", &mut violations);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(ParameterValidationError::Violations(violations))
    }
}

fn validate_value(
    schema: &Value,
    value: &Value,
    path: &str,
    violations: &mut Vec<ParameterViolation>,
) {
    let object = schema
        .as_object()
        .expect("schema validation guarantees object nodes");
    if let Some(values) = object.get("enum").and_then(Value::as_array)
        && !values.contains(value)
    {
        violations.push(ParameterViolation {
            path: path.to_owned(),
            kind: ParameterViolationKind::NotInEnum,
        });
    }
    if let Some(expected) = object
        .get("type")
        .and_then(Value::as_str)
        .and_then(JsonType::parse)
        && !expected.matches(value)
    {
        violations.push(ParameterViolation {
            path: path.to_owned(),
            kind: ParameterViolationKind::TypeMismatch,
        });
        return;
    }
    if let Some(value) = value.as_object() {
        validate_object_value(object, value, path, violations);
    }
    if let Some(value) = value.as_array()
        && let Some(item_schema) = object.get("items")
    {
        for (index, item) in value.iter().enumerate() {
            validate_value(item_schema, item, &format!("{path}[{index}]"), violations);
        }
    }
    if let Some(value) = value.as_str() {
        let length = value.chars().count() as u64;
        if object
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
        {
            violations.push(ParameterViolation {
                path: path.to_owned(),
                kind: ParameterViolationKind::StringTooShort,
            });
        }
        if object
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
        {
            violations.push(ParameterViolation {
                path: path.to_owned(),
                kind: ParameterViolationKind::StringTooLong,
            });
        }
    }
    if let Some(value) = value.as_f64() {
        if object
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|minimum| value < minimum)
        {
            violations.push(ParameterViolation {
                path: path.to_owned(),
                kind: ParameterViolationKind::NumberTooSmall,
            });
        }
        if object
            .get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|maximum| value > maximum)
        {
            violations.push(ParameterViolation {
                path: path.to_owned(),
                kind: ParameterViolationKind::NumberTooLarge,
            });
        }
    }
}

fn validate_object_value(
    schema: &Map<String, Value>,
    value: &Map<String, Value>,
    path: &str,
    violations: &mut Vec<ParameterViolation>,
) {
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !value.contains_key(name) {
                violations.push(ParameterViolation {
                    path: format!("{path}.{name}"),
                    kind: ParameterViolationKind::MissingRequiredProperty,
                });
            }
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    if let Some(properties) = properties {
        for (name, property_schema) in properties {
            if let Some(property_value) = value.get(name) {
                validate_value(
                    property_schema,
                    property_value,
                    &format!("{path}.{name}"),
                    violations,
                );
            }
        }
    }
    if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false) {
        for name in value.keys() {
            if properties.is_none_or(|declared| !declared.contains_key(name)) {
                violations.push(ParameterViolation {
                    path: format!("{path}.{name}"),
                    kind: ParameterViolationKind::AdditionalProperty,
                });
            }
        }
    }
}
