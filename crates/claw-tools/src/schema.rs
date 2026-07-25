//! Typed tool parameter schemas, strict validation, and JSON Schema emission.
//!
//! Model output is treated as hostile input. Validation is closed: unknown
//! fields are rejected rather than ignored, every string is length- and
//! character-checked, and no value reaches a tool implementation before its
//! declared type and bounds are proven.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde_json::{Map, Value, json};

/// Longest sanitized fragment echoed back into an error message.
const MAX_ECHOED_NAME_BYTES: usize = 48;

/// Declared type of one tool parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldType {
    /// UTF-8 text bounded by a byte length, rejecting control characters.
    Text {
        /// Inclusive maximum UTF-8 byte length.
        max_bytes: usize,
    },
    /// UTF-8 text that may contain newlines and tabs, bounded by byte length.
    Blob {
        /// Inclusive maximum UTF-8 byte length.
        max_bytes: usize,
    },
    /// Non-negative integer bounded by an inclusive maximum.
    Count {
        /// Inclusive maximum value.
        max: u64,
    },
    /// Boolean flag.
    Flag,
    /// Closed set of exact, case-sensitive string values.
    Choice {
        /// Accepted values in emission order.
        values: &'static [&'static str],
    },
    /// Homogeneous array of bounded text values.
    TextList {
        /// Inclusive maximum element count.
        max_items: usize,
        /// Inclusive maximum UTF-8 byte length of each element.
        max_item_bytes: usize,
    },
    /// String map with environment-style keys and bounded text values.
    TextMap {
        /// Inclusive maximum entry count.
        max_entries: usize,
        /// Inclusive maximum UTF-8 byte length of each value.
        max_value_bytes: usize,
    },
}

/// One declared tool parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field {
    /// Stable parameter name.
    pub name: &'static str,
    /// Human-readable description emitted to providers.
    pub description: &'static str,
    /// Whether the caller must supply the field.
    pub required: bool,
    /// Declared value type and bounds.
    pub ty: FieldType,
}

/// Closed object schema for one tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParameterSchema {
    fields: &'static [Field],
}

impl ParameterSchema {
    /// Builds a schema from a static field table.
    #[must_use]
    pub const fn new(fields: &'static [Field]) -> Self {
        Self { fields }
    }

    /// Returns the declared fields in emission order.
    #[must_use]
    pub const fn fields(&self) -> &'static [Field] {
        self.fields
    }

    /// Emits a provider-facing JSON Schema object with closed properties.
    #[must_use]
    pub fn to_json_schema(&self) -> Value {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for field in self.fields {
            properties.insert(field.name.to_owned(), field_schema(field));
            if field.required {
                required.push(Value::String(field.name.to_owned()));
            }
        }
        json!({
            "type": "object",
            "properties": Value::Object(properties),
            "required": Value::Array(required),
            "additionalProperties": false,
        })
    }

    /// Validates caller-supplied arguments against the closed schema.
    pub fn validate(&self, value: &Value) -> Result<Arguments, SchemaError> {
        let object = value.as_object().ok_or(SchemaError::NotAnObject)?;
        for key in object.keys() {
            if !self.fields.iter().any(|field| field.name == key) {
                return Err(SchemaError::UnknownField(sanitize_name(key)));
            }
        }
        let mut values = BTreeMap::new();
        for field in self.fields {
            match object.get(field.name) {
                None | Some(Value::Null) => {
                    if field.required {
                        return Err(SchemaError::MissingField(field.name));
                    }
                }
                Some(raw) => {
                    values.insert(field.name, validate_field(field, raw)?);
                }
            }
        }
        Ok(Arguments { values })
    }
}

fn field_schema(field: &Field) -> Value {
    let mut schema = match field.ty {
        FieldType::Text { max_bytes } | FieldType::Blob { max_bytes } => {
            json!({ "type": "string", "maxLength": max_bytes })
        }
        FieldType::Count { max } => json!({ "type": "integer", "minimum": 0, "maximum": max }),
        FieldType::Flag => json!({ "type": "boolean" }),
        FieldType::Choice { values } => json!({ "type": "string", "enum": values }),
        FieldType::TextList {
            max_items,
            max_item_bytes,
        } => json!({
            "type": "array",
            "maxItems": max_items,
            "items": { "type": "string", "maxLength": max_item_bytes },
        }),
        FieldType::TextMap {
            max_entries,
            max_value_bytes,
        } => json!({
            "type": "object",
            "maxProperties": max_entries,
            "propertyNames": { "pattern": "^[A-Za-z_][A-Za-z0-9_]*$" },
            "additionalProperties": { "type": "string", "maxLength": max_value_bytes },
        }),
    };
    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "description".to_owned(),
            Value::String(field.description.to_owned()),
        );
    }
    schema
}

fn validate_field(field: &Field, raw: &Value) -> Result<ArgumentValue, SchemaError> {
    match field.ty {
        FieldType::Text { max_bytes } => {
            let text = raw.as_str().ok_or(SchemaError::TypeMismatch(field.name))?;
            check_text(field.name, text, max_bytes, false)?;
            Ok(ArgumentValue::Text(text.to_owned()))
        }
        FieldType::Blob { max_bytes } => {
            let text = raw.as_str().ok_or(SchemaError::TypeMismatch(field.name))?;
            check_text(field.name, text, max_bytes, true)?;
            Ok(ArgumentValue::Text(text.to_owned()))
        }
        FieldType::Count { max } => {
            let number = raw.as_u64().ok_or(SchemaError::TypeMismatch(field.name))?;
            if number > max {
                return Err(SchemaError::OutOfRange(field.name));
            }
            Ok(ArgumentValue::Count(number))
        }
        FieldType::Flag => {
            let flag = raw.as_bool().ok_or(SchemaError::TypeMismatch(field.name))?;
            Ok(ArgumentValue::Flag(flag))
        }
        FieldType::Choice { values } => {
            let text = raw.as_str().ok_or(SchemaError::TypeMismatch(field.name))?;
            if !values.contains(&text) {
                return Err(SchemaError::NotAChoice(field.name));
            }
            Ok(ArgumentValue::Text(text.to_owned()))
        }
        FieldType::TextList {
            max_items,
            max_item_bytes,
        } => {
            let items = raw
                .as_array()
                .ok_or(SchemaError::TypeMismatch(field.name))?;
            if items.len() > max_items {
                return Err(SchemaError::TooManyItems(field.name));
            }
            let mut list = Vec::with_capacity(items.len());
            for item in items {
                let text = item.as_str().ok_or(SchemaError::TypeMismatch(field.name))?;
                check_text(field.name, text, max_item_bytes, false)?;
                list.push(text.to_owned());
            }
            Ok(ArgumentValue::TextList(list))
        }
        FieldType::TextMap {
            max_entries,
            max_value_bytes,
        } => {
            let entries = raw
                .as_object()
                .ok_or(SchemaError::TypeMismatch(field.name))?;
            if entries.len() > max_entries {
                return Err(SchemaError::TooManyItems(field.name));
            }
            let mut map = BTreeMap::new();
            for (key, item) in entries {
                if !is_identifier(key) {
                    return Err(SchemaError::InvalidKey(field.name));
                }
                let text = item.as_str().ok_or(SchemaError::TypeMismatch(field.name))?;
                check_text(field.name, text, max_value_bytes, false)?;
                map.insert(key.clone(), text.to_owned());
            }
            Ok(ArgumentValue::TextMap(map))
        }
    }
}

fn check_text(
    name: &'static str,
    text: &str,
    max_bytes: usize,
    allow_line_breaks: bool,
) -> Result<(), SchemaError> {
    if text.len() > max_bytes {
        return Err(SchemaError::TooLong(name));
    }
    let forbidden = text.chars().any(|character| {
        if allow_line_breaks && matches!(character, '\n' | '\r' | '\t') {
            false
        } else {
            character.is_control()
        }
    });
    if forbidden {
        return Err(SchemaError::ControlCharacter(name));
    }
    Ok(())
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_alphabetic() || first == b'_' => {}
        _ => return false,
    }
    value.len() <= 128 && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn sanitize_name(value: &str) -> String {
    let mut sanitized: String = value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
        .take(MAX_ECHOED_NAME_BYTES)
        .collect();
    if sanitized.is_empty() {
        sanitized.push_str("<unprintable>");
    }
    sanitized
}

/// One validated argument value.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ArgumentValue {
    Text(String),
    Count(u64),
    Flag(bool),
    TextList(Vec<String>),
    TextMap(BTreeMap<String, String>),
}

/// Validated arguments for exactly one tool invocation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Arguments {
    values: BTreeMap<&'static str, ArgumentValue>,
}

impl Arguments {
    /// Returns a validated text value when the caller supplied it.
    #[must_use]
    pub fn text(&self, name: &str) -> Option<&str> {
        match self.values.get(name) {
            Some(ArgumentValue::Text(text)) => Some(text),
            _ => None,
        }
    }

    /// Returns a required text value.
    pub fn required_text(&self, name: &'static str) -> Result<&str, SchemaError> {
        self.text(name).ok_or(SchemaError::MissingField(name))
    }

    /// Returns a validated integer when the caller supplied it.
    #[must_use]
    pub fn count(&self, name: &str) -> Option<u64> {
        match self.values.get(name) {
            Some(ArgumentValue::Count(value)) => Some(*value),
            _ => None,
        }
    }

    /// Returns a validated flag when the caller supplied it.
    #[must_use]
    pub fn flag(&self, name: &str) -> Option<bool> {
        match self.values.get(name) {
            Some(ArgumentValue::Flag(value)) => Some(*value),
            _ => None,
        }
    }

    /// Returns a validated flag or the declared default.
    #[must_use]
    pub fn flag_or(&self, name: &str, default: bool) -> bool {
        self.flag(name).unwrap_or(default)
    }

    /// Returns a validated string list when the caller supplied it.
    #[must_use]
    pub fn text_list(&self, name: &str) -> Option<&[String]> {
        match self.values.get(name) {
            Some(ArgumentValue::TextList(items)) => Some(items),
            _ => None,
        }
    }

    /// Returns a validated string map when the caller supplied it.
    #[must_use]
    pub fn text_map(&self, name: &str) -> Option<&BTreeMap<String, String>> {
        match self.values.get(name) {
            Some(ArgumentValue::TextMap(entries)) => Some(entries),
            _ => None,
        }
    }
}

/// A rejected argument payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchemaError {
    /// Arguments must be a JSON object.
    NotAnObject,
    /// A field outside the closed schema was supplied.
    UnknownField(String),
    /// A required field is absent.
    MissingField(&'static str),
    /// A field has the wrong JSON type.
    TypeMismatch(&'static str),
    /// A string exceeded its declared byte bound.
    TooLong(&'static str),
    /// An integer exceeded its declared bound.
    OutOfRange(&'static str),
    /// An array or map exceeded its declared element bound.
    TooManyItems(&'static str),
    /// A string contained a forbidden control character.
    ControlCharacter(&'static str),
    /// A map key is not a valid identifier.
    InvalidKey(&'static str),
    /// A value is outside the declared closed choice set.
    NotAChoice(&'static str),
    /// A value that must be non-empty was empty.
    Empty(&'static str),
}

impl Display for SchemaError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnObject => formatter.write_str("tool arguments must be a JSON object"),
            Self::UnknownField(name) => write!(formatter, "unknown argument `{name}`"),
            Self::MissingField(name) => write!(formatter, "missing required argument `{name}`"),
            Self::TypeMismatch(name) => write!(formatter, "argument `{name}` has the wrong type"),
            Self::TooLong(name) => write!(formatter, "argument `{name}` is too long"),
            Self::OutOfRange(name) => write!(formatter, "argument `{name}` is out of range"),
            Self::TooManyItems(name) => write!(formatter, "argument `{name}` has too many items"),
            Self::ControlCharacter(name) => {
                write!(formatter, "argument `{name}` contains a control character")
            }
            Self::InvalidKey(name) => write!(formatter, "argument `{name}` has an invalid key"),
            Self::NotAChoice(name) => {
                write!(formatter, "argument `{name}` is not an accepted value")
            }
            Self::Empty(name) => write!(formatter, "argument `{name}` must not be empty"),
        }
    }
}

impl Error for SchemaError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: ParameterSchema = ParameterSchema::new(&[
        Field {
            name: "path",
            description: "Workspace-relative path",
            required: true,
            ty: FieldType::Text { max_bytes: 16 },
        },
        Field {
            name: "limit",
            description: "Maximum entries",
            required: false,
            ty: FieldType::Count { max: 100 },
        },
        Field {
            name: "mode",
            description: "Write mode",
            required: false,
            ty: FieldType::Choice {
                values: &["create", "overwrite"],
            },
        },
        Field {
            name: "args",
            description: "Arguments",
            required: false,
            ty: FieldType::TextList {
                max_items: 2,
                max_item_bytes: 8,
            },
        },
        Field {
            name: "env",
            description: "Environment",
            required: false,
            ty: FieldType::TextMap {
                max_entries: 2,
                max_value_bytes: 8,
            },
        },
    ]);

    #[test]
    fn emits_closed_json_schema_with_bounds() {
        let schema = SCHEMA.to_json_schema();
        assert_eq!(schema["type"], Value::String("object".to_owned()));
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        assert_eq!(
            schema["required"],
            Value::Array(vec![Value::String("path".to_owned())])
        );
        assert_eq!(schema["properties"]["path"]["maxLength"], Value::from(16));
        assert_eq!(schema["properties"]["limit"]["maximum"], Value::from(100));
        assert_eq!(schema["properties"]["limit"]["minimum"], Value::from(0));
        assert_eq!(
            schema["properties"]["mode"]["enum"],
            Value::Array(vec![
                Value::String("create".to_owned()),
                Value::String("overwrite".to_owned()),
            ])
        );
        assert_eq!(schema["properties"]["args"]["maxItems"], Value::from(2));
        assert_eq!(
            schema["properties"]["args"]["items"]["maxLength"],
            Value::from(8)
        );
        assert_eq!(
            schema["properties"]["env"]["propertyNames"]["pattern"],
            Value::String("^[A-Za-z_][A-Za-z0-9_]*$".to_owned())
        );
        assert_eq!(
            schema["properties"]["path"]["description"],
            Value::String("Workspace-relative path".to_owned())
        );
    }

    #[test]
    fn accepts_a_fully_populated_payload() {
        let arguments = SCHEMA
            .validate(&json!({
                "path": "notes.txt",
                "limit": 5,
                "mode": "overwrite",
                "args": ["--flag", "value"],
                "env": { "PATH_A": "one", "_B2": "two" },
            }))
            .expect("payload matches the schema");
        assert_eq!(arguments.required_text("path"), Ok("notes.txt"));
        assert_eq!(arguments.count("limit"), Some(5));
        assert_eq!(arguments.text("mode"), Some("overwrite"));
        assert_eq!(
            arguments.text_list("args"),
            Some(["--flag".to_owned(), "value".to_owned()].as_slice())
        );
        let env = arguments.text_map("env").expect("map argument");
        assert_eq!(env.get("PATH_A").map(String::as_str), Some("one"));
        assert_eq!(env.get("_B2").map(String::as_str), Some("two"));
        assert_eq!(env.len(), 2);
    }

    #[test]
    fn rejects_unknown_fields_instead_of_ignoring_them() {
        assert_eq!(
            SCHEMA.validate(&json!({ "path": "a.txt", "shell": "rm -rf /" })),
            Err(SchemaError::UnknownField("shell".to_owned()))
        );
    }

    #[test]
    fn rejects_every_declared_bound_violation() {
        let cases: [(Value, SchemaError); 9] = [
            (json!([]), SchemaError::NotAnObject),
            (json!({}), SchemaError::MissingField("path")),
            (json!({ "path": 7 }), SchemaError::TypeMismatch("path")),
            (
                json!({ "path": "0123456789abcdefg" }),
                SchemaError::TooLong("path"),
            ),
            (
                json!({ "path": "a\u{0}b" }),
                SchemaError::ControlCharacter("path"),
            ),
            (
                json!({ "path": "a.txt", "limit": 101 }),
                SchemaError::OutOfRange("limit"),
            ),
            (
                json!({ "path": "a.txt", "mode": "append" }),
                SchemaError::NotAChoice("mode"),
            ),
            (
                json!({ "path": "a.txt", "args": ["a", "b", "c"] }),
                SchemaError::TooManyItems("args"),
            ),
            (
                json!({ "path": "a.txt", "env": { "2BAD": "x" } }),
                SchemaError::InvalidKey("env"),
            ),
        ];
        for (payload, expected) in cases {
            assert_eq!(SCHEMA.validate(&payload), Err(expected), "{payload}");
        }
    }

    #[test]
    fn null_is_treated_as_absent_and_still_fails_closed_when_required() {
        assert_eq!(
            SCHEMA.validate(&json!({ "path": null })),
            Err(SchemaError::MissingField("path"))
        );
        let arguments = SCHEMA
            .validate(&json!({ "path": "a.txt", "limit": null }))
            .expect("optional null is absent");
        assert_eq!(arguments.count("limit"), None);
    }

    #[test]
    fn blob_allows_line_breaks_but_text_does_not() {
        const BLOB: ParameterSchema = ParameterSchema::new(&[
            Field {
                name: "content",
                description: "File content",
                required: true,
                ty: FieldType::Blob { max_bytes: 32 },
            },
            Field {
                name: "name",
                description: "File name",
                required: true,
                ty: FieldType::Text { max_bytes: 32 },
            },
        ]);
        assert_eq!(
            BLOB.validate(&json!({ "content": "a\nb\tc\r\n", "name": "n" }))
                .expect("blob accepts line breaks")
                .required_text("content"),
            Ok("a\nb\tc\r\n")
        );
        assert_eq!(
            BLOB.validate(&json!({ "content": "ok", "name": "a\nb" })),
            Err(SchemaError::ControlCharacter("name"))
        );
        assert_eq!(
            BLOB.validate(&json!({ "content": "a\u{7}b", "name": "n" })),
            Err(SchemaError::ControlCharacter("content"))
        );
    }

    #[test]
    fn unknown_field_names_are_sanitized_before_being_echoed() {
        let error = SCHEMA
            .validate(&json!({ "path": "a.txt", "x\u{1b}[31m\ndrop": 1 }))
            .expect_err("unknown field");
        assert_eq!(error, SchemaError::UnknownField("x31mdrop".to_owned()));
        assert_eq!(error.to_string(), "unknown argument `x31mdrop`");
    }
}
