//! Bounded JSON parameter-schema validation.

use std::collections::HashSet;
use std::num::NonZeroUsize;

use serde_json::{Map, Value};

const DEFAULT_MAX_VIOLATIONS: NonZeroUsize = NonZeroUsize::new(64).unwrap();
const DEFAULT_MAX_DEPTH: NonZeroUsize = NonZeroUsize::new(64).unwrap();
const DEFAULT_MAX_PATH_BYTES: NonZeroUsize = NonZeroUsize::new(1_024).unwrap();
const DEFAULT_MAX_SCHEMA_NODES: NonZeroUsize = NonZeroUsize::new(4_096).unwrap();
const DEFAULT_MAX_INPUT_NODES: NonZeroUsize = NonZeroUsize::new(65_536).unwrap();
const DEFAULT_MAX_COMPARISON_NODES: NonZeroUsize = NonZeroUsize::new(65_536).unwrap();

/// Resource limits for untrusted parameter schemas and validation diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationLimits {
    /// Maximum number of parameter violations collected before traversal stops.
    pub max_violations: NonZeroUsize,
    /// Maximum recursive schema/input depth.
    pub max_depth: NonZeroUsize,
    /// Maximum byte length of any allocated diagnostic path.
    pub max_path_bytes: NonZeroUsize,
    /// Maximum number of schema nodes visited during validation.
    pub max_schema_nodes: NonZeroUsize,
    /// Maximum number of input values visited during validation.
    pub max_input_nodes: NonZeroUsize,
    /// Maximum number of value pairs visited while evaluating enums.
    pub max_comparison_nodes: NonZeroUsize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_violations: DEFAULT_MAX_VIOLATIONS,
            max_depth: DEFAULT_MAX_DEPTH,
            max_path_bytes: DEFAULT_MAX_PATH_BYTES,
            max_schema_nodes: DEFAULT_MAX_SCHEMA_NODES,
            max_input_nodes: DEFAULT_MAX_INPUT_NODES,
            max_comparison_nodes: DEFAULT_MAX_COMPARISON_NODES,
        }
    }
}

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
    /// Schema traversal, nesting, or diagnostic path limits were exceeded.
    ResourceLimit,
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
    Violations {
        /// Mismatches collected before traversal stopped.
        violations: Vec<ParameterViolation>,
        /// Whether traversal stopped immediately after reaching the configured cap.
        limit_reached: bool,
    },
    /// Input nesting or a diagnostic path exceeded configured limits.
    ResourceLimit {
        /// Last bounded path reached before validation stopped.
        path: String,
    },
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
///
/// # Errors
///
/// Returns the first [`SchemaError`], carrying the JSON path of the offending
/// node and one of: [`SchemaErrorKind::ExpectedObject`] when a schema node — the
/// root, a `properties` entry, or `items` — is not a JSON object;
/// [`SchemaErrorKind::UnsupportedType`] when `type` names something outside the
/// supported JSON types; [`SchemaErrorKind::InvalidKeywordType`] when
/// `type`, `properties`, `required`, `additionalProperties`, `minimum` or
/// `maximum` has the wrong JSON value type;
/// [`SchemaErrorKind::InvalidLengthBound`] when `minLength` or `maxLength` is
/// not a non-negative integer; [`SchemaErrorKind::DuplicateRequiredProperty`]
/// when `required` names the same property twice; and
/// [`SchemaErrorKind::EmptyEnum`] when `enum` is present but empty, which would
/// otherwise reject every input.
pub fn validate_schema(schema: &Value) -> Result<(), SchemaError> {
    validate_schema_with_limits(schema, ValidationLimits::default())
}

/// Validates a schema under explicit traversal and allocation limits.
///
/// # Errors
///
/// Returns the same errors as [`validate_schema`], including
/// [`SchemaErrorKind::ResourceLimit`] when a configured limit is reached.
pub fn validate_schema_with_limits(
    schema: &Value,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    let mut remaining_nodes = limits.max_schema_nodes.get();
    validate_schema_at(schema, "$", 0, limits, &mut remaining_nodes)
}

fn validate_schema_at(
    schema: &Value,
    path: &str,
    depth: usize,
    limits: ValidationLimits,
    remaining_nodes: &mut usize,
) -> Result<(), SchemaError> {
    if depth >= limits.max_depth.get() || *remaining_nodes == 0 {
        return Err(SchemaError {
            path: path.to_owned(),
            kind: SchemaErrorKind::ResourceLimit,
        });
    }
    *remaining_nodes -= 1;
    let object = schema.as_object().ok_or_else(|| SchemaError {
        path: path.to_owned(),
        kind: SchemaErrorKind::ExpectedObject,
    })?;
    validate_type_keyword(object, path, limits)?;
    validate_object_keywords(object, path, depth, limits, remaining_nodes)?;
    validate_items_keyword(object, path, depth, limits, remaining_nodes)?;
    validate_enum_keyword(object, path, depth, limits, remaining_nodes)?;
    validate_length_keyword(object, path, "minLength", limits)?;
    validate_length_keyword(object, path, "maxLength", limits)?;
    validate_number_keyword(object, path, "minimum", limits)?;
    validate_number_keyword(object, path, "maximum", limits)?;
    Ok(())
}

fn validate_type_keyword(
    object: &Map<String, Value>,
    path: &str,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    if let Some(value) = object.get("type") {
        let type_path = schema_child_path(path, &[".type"], limits)?;
        let name = value.as_str().ok_or_else(|| SchemaError {
            path: type_path.clone(),
            kind: SchemaErrorKind::InvalidKeywordType,
        })?;
        if JsonType::parse(name).is_none() {
            return Err(SchemaError {
                path: type_path,
                kind: SchemaErrorKind::UnsupportedType,
            });
        }
    }
    Ok(())
}

fn validate_object_keywords(
    object: &Map<String, Value>,
    path: &str,
    depth: usize,
    limits: ValidationLimits,
    remaining_nodes: &mut usize,
) -> Result<(), SchemaError> {
    if let Some(properties) = object.get("properties") {
        let properties_path = schema_child_path(path, &[".properties"], limits)?;
        let properties = properties.as_object().ok_or(SchemaError {
            path: properties_path,
            kind: SchemaErrorKind::InvalidKeywordType,
        })?;
        for (name, property_schema) in properties {
            let property_path = schema_child_path(path, &[".properties.", name.as_str()], limits)?;
            validate_schema_at(
                property_schema,
                &property_path,
                depth + 1,
                limits,
                remaining_nodes,
            )?;
        }
    }
    if let Some(required) = object.get("required") {
        let required_path = schema_child_path(path, &[".required"], limits)?;
        let required = required.as_array().ok_or(SchemaError {
            path: required_path,
            kind: SchemaErrorKind::InvalidKeywordType,
        })?;
        let mut names = HashSet::new();
        for (index, value) in required.iter().enumerate() {
            let index_text = index.to_string();
            let required_item_path =
                schema_child_path(path, &[".required[", &index_text, "]"], limits)?;
            consume_schema_node(&required_item_path, remaining_nodes)?;
            let name = value.as_str().ok_or_else(|| SchemaError {
                path: required_item_path.clone(),
                kind: SchemaErrorKind::InvalidKeywordType,
            })?;
            if !names.insert(name) {
                return Err(SchemaError {
                    path: required_item_path,
                    kind: SchemaErrorKind::DuplicateRequiredProperty,
                });
            }
        }
    }
    if object
        .get("additionalProperties")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(SchemaError {
            path: schema_child_path(path, &[".additionalProperties"], limits)?,
            kind: SchemaErrorKind::InvalidKeywordType,
        });
    }
    Ok(())
}

fn validate_items_keyword(
    object: &Map<String, Value>,
    path: &str,
    depth: usize,
    limits: ValidationLimits,
    remaining_nodes: &mut usize,
) -> Result<(), SchemaError> {
    if let Some(items) = object.get("items") {
        let item_path = schema_child_path(path, &[".items"], limits)?;
        validate_schema_at(items, &item_path, depth + 1, limits, remaining_nodes)?;
    }
    Ok(())
}

fn validate_enum_keyword(
    object: &Map<String, Value>,
    path: &str,
    depth: usize,
    limits: ValidationLimits,
    remaining_nodes: &mut usize,
) -> Result<(), SchemaError> {
    if let Some(values) = object.get("enum") {
        let enum_path = schema_child_path(path, &[".enum"], limits)?;
        let values = values.as_array().ok_or(SchemaError {
            path: enum_path,
            kind: SchemaErrorKind::InvalidKeywordType,
        })?;
        if values.is_empty() {
            return Err(SchemaError {
                path: schema_child_path(path, &[".enum"], limits)?,
                kind: SchemaErrorKind::EmptyEnum,
            });
        }
        for (index, value) in values.iter().enumerate() {
            let index_text = index.to_string();
            let value_path = schema_child_path(path, &[".enum[", &index_text, "]"], limits)?;
            validate_json_node(value, &value_path, depth + 1, limits, remaining_nodes)?;
        }
    }
    Ok(())
}

fn validate_length_keyword(
    object: &Map<String, Value>,
    path: &str,
    keyword: &str,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    if object
        .get(keyword)
        .is_some_and(|value| value.as_u64().is_none())
    {
        return Err(SchemaError {
            path: schema_child_path(path, &[".", keyword], limits)?,
            kind: SchemaErrorKind::InvalidLengthBound,
        });
    }
    Ok(())
}

fn validate_number_keyword(
    object: &Map<String, Value>,
    path: &str,
    keyword: &str,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    if object.get(keyword).is_some_and(|value| !value.is_number()) {
        return Err(SchemaError {
            path: schema_child_path(path, &[".", keyword], limits)?,
            kind: SchemaErrorKind::InvalidKeywordType,
        });
    }
    Ok(())
}

fn schema_child_path(
    path: &str,
    suffixes: &[&str],
    limits: ValidationLimits,
) -> Result<String, SchemaError> {
    extend_path(path, suffixes, limits.max_path_bytes.get()).ok_or_else(|| SchemaError {
        path: path.to_owned(),
        kind: SchemaErrorKind::ResourceLimit,
    })
}

fn consume_schema_node(path: &str, remaining_nodes: &mut usize) -> Result<(), SchemaError> {
    if *remaining_nodes == 0 {
        return Err(SchemaError {
            path: path.to_owned(),
            kind: SchemaErrorKind::ResourceLimit,
        });
    }
    *remaining_nodes -= 1;
    Ok(())
}

fn validate_json_node(
    value: &Value,
    path: &str,
    depth: usize,
    limits: ValidationLimits,
    remaining_nodes: &mut usize,
) -> Result<(), SchemaError> {
    if depth >= limits.max_depth.get() {
        return Err(SchemaError {
            path: path.to_owned(),
            kind: SchemaErrorKind::ResourceLimit,
        });
    }
    consume_schema_node(path, remaining_nodes)?;
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let index_text = index.to_string();
                let child_path = schema_child_path(path, &["[", &index_text, "]"], limits)?;
                validate_json_node(value, &child_path, depth + 1, limits, remaining_nodes)?;
            }
        }
        Value::Object(values) => {
            for (name, value) in values {
                let child_path = schema_child_path(path, &[".", name], limits)?;
                validate_json_node(value, &child_path, depth + 1, limits, remaining_nodes)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn extend_path(path: &str, suffixes: &[&str], maximum: usize) -> Option<String> {
    let length = suffixes.iter().try_fold(path.len(), |length, suffix| {
        length.checked_add(suffix.len())
    })?;
    if length > maximum {
        return None;
    }
    let mut extended = String::with_capacity(length);
    extended.push_str(path);
    for suffix in suffixes {
        extended.push_str(suffix);
    }
    Some(extended)
}

/// Validates one input document against a previously untrusted schema.
///
/// # Errors
///
/// Returns [`ParameterValidationError::InvalidSchema`] when `schema` itself is
/// rejected by [`validate_schema`] — the schema is checked first, so a bad
/// schema is never reported as if the caller's input were at fault.
///
/// Returns [`ParameterValidationError::Violations`] with mismatches up to the
/// configured default cap: a wrong JSON type, a missing `required` property, an
/// undeclared property while `additionalProperties` is `false`, a value outside
/// `enum`, a string outside `minLength`/`maxLength`, or a number outside
/// `minimum`/`maximum`. Each violation names the JSON path of the value that
/// failed.
pub fn validate_parameters(
    schema: &Value,
    parameters: &Value,
) -> Result<(), ParameterValidationError> {
    validate_parameters_with_limits(schema, parameters, ValidationLimits::default())
}

/// Validates one input document under explicit traversal and diagnostic limits.
///
/// # Errors
///
/// Returns the same errors as [`validate_parameters`]. A
/// [`ParameterValidationError::Violations`] result reports `limit_reached` when
/// traversal stopped immediately at the configured violation cap.
pub fn validate_parameters_with_limits(
    schema: &Value,
    parameters: &Value,
    limits: ValidationLimits,
) -> Result<(), ParameterValidationError> {
    validate_schema_with_limits(schema, limits).map_err(ParameterValidationError::InvalidSchema)?;
    let mut context = ValidationContext {
        violations: Vec::new(),
        limits,
        limit_reached: false,
        remaining_values: limits.max_input_nodes.get(),
        remaining_comparisons: limits.max_comparison_nodes.get(),
    };
    let _completed = validate_value(schema, parameters, "$", 0, &mut context)?;
    if context.violations.is_empty() {
        Ok(())
    } else {
        Err(ParameterValidationError::Violations {
            violations: context.violations,
            limit_reached: context.limit_reached,
        })
    }
}

struct ValidationContext {
    violations: Vec<ParameterViolation>,
    limits: ValidationLimits,
    limit_reached: bool,
    remaining_values: usize,
    remaining_comparisons: usize,
}

impl ValidationContext {
    fn record(&mut self, path: &str, kind: ParameterViolationKind) -> bool {
        self.violations.push(ParameterViolation {
            path: path.to_owned(),
            kind,
        });
        if self.violations.len() == self.limits.max_violations.get() {
            self.limit_reached = true;
            false
        } else {
            true
        }
    }

    fn child_path(
        &self,
        path: &str,
        suffixes: &[&str],
    ) -> Result<String, ParameterValidationError> {
        extend_path(path, suffixes, self.limits.max_path_bytes.get()).ok_or_else(|| {
            ParameterValidationError::ResourceLimit {
                path: path.to_owned(),
            }
        })
    }
}

fn validate_value(
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
    context: &mut ValidationContext,
) -> Result<bool, ParameterValidationError> {
    if depth >= context.limits.max_depth.get() || context.remaining_values == 0 {
        return Err(ParameterValidationError::ResourceLimit {
            path: path.to_owned(),
        });
    }
    context.remaining_values -= 1;
    let object = schema
        .as_object()
        .expect("schema validation guarantees object nodes");
    if let Some(values) = object.get("enum").and_then(Value::as_array) {
        let contained = enum_contains(values, value, path, context)?;
        if !contained && !context.record(path, ParameterViolationKind::NotInEnum) {
            return Ok(false);
        }
    }
    if let Some(expected) = object
        .get("type")
        .and_then(Value::as_str)
        .and_then(JsonType::parse)
        && !expected.matches(value)
    {
        return Ok(context.record(path, ParameterViolationKind::TypeMismatch));
    }
    if let Some(value) = value.as_object()
        && !validate_object_value(object, value, path, depth, context)?
    {
        return Ok(false);
    }
    if let Some(value) = value.as_array()
        && let Some(item_schema) = object.get("items")
    {
        for (index, item) in value.iter().enumerate() {
            let index_text = index.to_string();
            let item_path = context.child_path(path, &["[", &index_text, "]"])?;
            if !validate_value(item_schema, item, &item_path, depth + 1, context)? {
                return Ok(false);
            }
        }
    }
    if let Some(value) = value.as_str() {
        let length = value.chars().count() as u64;
        if object
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
            && !context.record(path, ParameterViolationKind::StringTooShort)
        {
            return Ok(false);
        }
        if object
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
            && !context.record(path, ParameterViolationKind::StringTooLong)
        {
            return Ok(false);
        }
    }
    if let Some(value) = value.as_f64() {
        if object
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|minimum| value < minimum)
            && !context.record(path, ParameterViolationKind::NumberTooSmall)
        {
            return Ok(false);
        }
        if object
            .get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|maximum| value > maximum)
            && !context.record(path, ParameterViolationKind::NumberTooLarge)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn enum_contains(
    candidates: &[Value],
    value: &Value,
    path: &str,
    context: &mut ValidationContext,
) -> Result<bool, ParameterValidationError> {
    for candidate in candidates {
        if json_equal_bounded(candidate, value, 0, path, context)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn json_equal_bounded(
    candidate: &Value,
    value: &Value,
    depth: usize,
    path: &str,
    context: &mut ValidationContext,
) -> Result<bool, ParameterValidationError> {
    if depth >= context.limits.max_depth.get() || context.remaining_comparisons == 0 {
        return Err(ParameterValidationError::ResourceLimit {
            path: path.to_owned(),
        });
    }
    context.remaining_comparisons -= 1;
    match (candidate, value) {
        (Value::Null, Value::Null) => Ok(true),
        (Value::Bool(left), Value::Bool(right)) => Ok(left == right),
        (Value::Number(left), Value::Number(right)) => Ok(left == right),
        (Value::String(left), Value::String(right)) => Ok(left == right),
        (Value::Array(left), Value::Array(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (index, (left, right)) in left.iter().zip(right).enumerate() {
                let index_text = index.to_string();
                let child_path = context.child_path(path, &["[", &index_text, "]"])?;
                if !json_equal_bounded(left, right, depth + 1, &child_path, context)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (Value::Object(left), Value::Object(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (name, left) in left {
                let Some(right) = right.get(name) else {
                    return Ok(false);
                };
                let child_path = context.child_path(path, &[".", name])?;
                if !json_equal_bounded(left, right, depth + 1, &child_path, context)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::String(_)
            | Value::Array(_)
            | Value::Object(_),
            _,
        ) => Ok(false),
    }
}

fn validate_object_value(
    schema: &Map<String, Value>,
    value: &Map<String, Value>,
    path: &str,
    depth: usize,
    context: &mut ValidationContext,
) -> Result<bool, ParameterValidationError> {
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for name in required.iter().filter_map(Value::as_str) {
            if !value.contains_key(name) {
                let missing_path = context.child_path(path, &[".", name])?;
                if !context.record(
                    &missing_path,
                    ParameterViolationKind::MissingRequiredProperty,
                ) {
                    return Ok(false);
                }
            }
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    if let Some(properties) = properties {
        for (name, property_schema) in properties {
            if let Some(property_value) = value.get(name) {
                let property_path = context.child_path(path, &[".", name])?;
                if !validate_value(
                    property_schema,
                    property_value,
                    &property_path,
                    depth + 1,
                    context,
                )? {
                    return Ok(false);
                }
            }
        }
    }
    if schema.get("additionalProperties").and_then(Value::as_bool) == Some(false) {
        for name in value.keys() {
            if properties.is_none_or(|declared| !declared.contains_key(name)) {
                let additional_path = context.child_path(path, &[".", name])?;
                if !context.record(&additional_path, ParameterViolationKind::AdditionalProperty) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}
