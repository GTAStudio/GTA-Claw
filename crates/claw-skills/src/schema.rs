//! Bounded JSON parameter-schema validation.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::num::NonZeroUsize;

use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Map, Value};

const DEFAULT_MAX_VIOLATIONS: NonZeroUsize = NonZeroUsize::new(64).unwrap();
const DEFAULT_MAX_DEPTH: NonZeroUsize = NonZeroUsize::new(64).unwrap();
const DEFAULT_MAX_PATH_BYTES: NonZeroUsize = NonZeroUsize::new(1_024).unwrap();
const DEFAULT_MAX_SCHEMA_NODES: NonZeroUsize = NonZeroUsize::new(4_096).unwrap();
const DEFAULT_MAX_INPUT_NODES: NonZeroUsize = NonZeroUsize::new(65_536).unwrap();
const DEFAULT_MAX_COMPARISON_NODES: NonZeroUsize = NonZeroUsize::new(65_536).unwrap();
// Exact decimals stay useful well beyond binary-float precision while bounding
// parse allocation and the exponent arithmetic performed on untrusted values.
const MAX_NUMBER_LEXEME_BYTES: usize = 1_040;
const MAX_NUMBER_MANTISSA_DIGITS: usize = 1_024;
const MAX_NUMBER_EXPONENT: u32 = 1_000_000;
const MAX_NUMBER_EXPONENT_DIGITS: usize = 7;
const COMPARISON_DIGITS_PER_UNIT: usize = 32;
const SUPPORTED_SCHEMA_KEYWORDS: [&str; 18] = [
    "$comment",
    "additionalProperties",
    "default",
    "deprecated",
    "description",
    "enum",
    "examples",
    "items",
    "maximum",
    "maxLength",
    "minimum",
    "minLength",
    "properties",
    "readOnly",
    "required",
    "title",
    "type",
    "writeOnly",
];

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
    /// Maximum work spent on enum traversal and exact numeric comparisons.
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

/// A JSON document that retains every original number lexeme for exact schema
/// comparison without changing workspace-wide `serde_json` behavior.
#[derive(Clone, Eq, PartialEq)]
pub struct ExactJsonDocument {
    value: Value,
    exact: ExactNode,
    lossless_value: bool,
}

impl ExactJsonDocument {
    /// Parses one JSON document while retaining its exact number spellings.
    ///
    /// # Errors
    ///
    /// Returns the underlying JSON syntax or value error.
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        let raw: &RawValue = serde_json::from_str(json)?;
        let limits = RawJsonLimits {
            max_nodes: DEFAULT_MAX_INPUT_NODES.get(),
            max_depth: DEFAULT_MAX_DEPTH.get(),
            max_path_bytes: DEFAULT_MAX_PATH_BYTES.get(),
            reject_unbounded_numbers: false,
            track_paths: true,
        };
        Self::parse_bounded(raw, limits).map_err(|error| match error {
            ExactSchemaDocumentError::Json(error) => error,
            ExactSchemaDocumentError::Schema(error) => {
                <serde_json::Error as serde::de::Error>::custom(format!(
                    "exact JSON resource limit at {}",
                    error.path
                ))
            }
        })
    }

    pub(crate) fn parse_schema(
        raw: &RawValue,
        limits: ValidationLimits,
    ) -> Result<Self, ExactSchemaDocumentError> {
        Self::parse_bounded(
            raw,
            RawJsonLimits {
                max_nodes: limits.max_schema_nodes.get(),
                max_depth: limits.max_depth.get(),
                max_path_bytes: limits.max_path_bytes.get(),
                reject_unbounded_numbers: true,
                track_paths: true,
            },
        )
    }

    fn parse_bounded(
        raw: &RawValue,
        limits: RawJsonLimits,
    ) -> Result<Self, ExactSchemaDocumentError> {
        preflight_raw_json(raw.get(), limits).map_err(ExactSchemaDocumentError::Schema)?;
        ExactNode::parse_document_bounded(raw, limits)
    }

    /// Returns the ordinary JSON value when every exact number is representable
    /// without changing its mathematical value.
    #[must_use]
    pub fn value(&self) -> Option<&Value> {
        self.lossless_value.then_some(&self.value)
    }

    /// Consumes the document, returning its ordinary JSON value when every
    /// number is representable by `serde_json::Number`.
    #[must_use]
    pub fn into_value(self) -> Option<Value> {
        self.lossless_value.then_some(self.value)
    }

    /// Serializes the exact document without rounding retained number lexemes.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if a retained string cannot be serialized.
    pub fn to_json_vec(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut output = Vec::new();
        write_exact_json(&self.value, &self.exact, &mut output)?;
        Ok(output)
    }

    pub(crate) const fn parts(&self) -> (&Value, &ExactNode) {
        (&self.value, &self.exact)
    }
}

impl fmt::Debug for ExactJsonDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = self.to_json_vec().map_err(|_| fmt::Error)?;
        let json = std::str::from_utf8(&json).map_err(|_| fmt::Error)?;
        formatter
            .debug_struct("ExactJsonDocument")
            .field("json", &json)
            .finish()
    }
}

impl From<Value> for ExactJsonDocument {
    fn from(value: Value) -> Self {
        let exact = ExactNode::from_value(&value);
        Self {
            value,
            exact,
            lossless_value: true,
        }
    }
}

pub(crate) enum ExactSchemaDocumentError {
    Json(serde_json::Error),
    Schema(SchemaError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ExactNode {
    Number(ExactNumber),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExactNumber {
    raw: String,
    decimal: Option<ExactDecimal>,
}

impl ExactNumber {
    fn new(raw: String) -> Self {
        let decimal = ExactDecimal::parse_bounded(&raw);
        Self { raw, decimal }
    }

    fn raw(&self) -> &str {
        &self.raw
    }

    const fn decimal(&self) -> Option<&ExactDecimal> {
        self.decimal.as_ref()
    }

    fn nonnegative_integer(&self) -> Option<u64> {
        self.decimal.as_ref().and_then(ExactDecimal::to_u64)
    }

    fn comparison_units(&self) -> usize {
        self.decimal
            .as_ref()
            .map_or(usize::MAX, ExactDecimal::comparison_units)
    }
}

impl ExactNode {
    pub(crate) fn from_value(value: &Value) -> Self {
        Self::from_value_with_limits(value, None)
            .expect("unbounded exact-node construction cannot reach a resource limit")
    }

    fn from_value_bounded(value: &Value, limits: RawJsonLimits) -> Result<Self, SchemaError> {
        Self::from_value_with_limits(value, Some(limits))
    }

    fn from_value_with_limits(
        value: &Value,
        limits: Option<RawJsonLimits>,
    ) -> Result<Self, SchemaError> {
        enum Frame<'a> {
            Visit {
                value: &'a Value,
                depth: usize,
                path: Option<String>,
            },
            Array {
                values: &'a [Value],
                next_index: usize,
                depth: usize,
                path: Option<String>,
                output_start: usize,
            },
            Object {
                values: serde_json::map::Iter<'a>,
                names: Vec<String>,
                depth: usize,
                path: Option<String>,
                output_start: usize,
            },
        }

        let mut remaining_nodes = limits.map_or(usize::MAX, |limits| limits.max_nodes);
        let mut frames = vec![Frame::Visit {
            value,
            depth: 0,
            path: limits.and_then(|limits| limits.track_paths.then(|| "$".to_owned())),
        }];
        let mut output = Vec::new();
        while let Some(frame) = frames.pop() {
            match frame {
                Frame::Visit { value, depth, path } => {
                    if let Some(limits) = limits {
                        if depth >= limits.max_depth || remaining_nodes == 0 {
                            return Err(resource_limit(path.unwrap_or_else(|| "$".to_owned())));
                        }
                        remaining_nodes -= 1;
                    }
                    match value {
                        Value::Number(number) => {
                            let raw = number.to_string();
                            if limits.is_some() && raw.len() > MAX_NUMBER_LEXEME_BYTES {
                                return Err(resource_limit(path.unwrap_or_else(|| "$".to_owned())));
                            }
                            let exact = ExactNumber::new(raw);
                            if limits.is_some_and(|limits| limits.reject_unbounded_numbers)
                                && exact.decimal().is_none()
                            {
                                return Err(resource_limit(path.unwrap_or_else(|| "$".to_owned())));
                            }
                            output.push(Self::Number(exact));
                        }
                        Value::Array(values) => frames.push(Frame::Array {
                            values,
                            next_index: 0,
                            depth,
                            path,
                            output_start: output.len(),
                        }),
                        Value::Object(values) => {
                            let capacity =
                                limits.map_or(values.len(), |_| values.len().min(remaining_nodes));
                            frames.push(Frame::Object {
                                values: values.iter(),
                                names: Vec::with_capacity(capacity),
                                depth,
                                path,
                                output_start: output.len(),
                            });
                        }
                        Value::Null | Value::Bool(_) | Value::String(_) => {
                            output.push(Self::Other);
                        }
                    }
                }
                Frame::Array {
                    values,
                    next_index,
                    depth,
                    path,
                    output_start,
                } => {
                    if let Some(value) = values.get(next_index) {
                        let child_path = bounded_build_path(
                            path.as_deref(),
                            &["[", &next_index.to_string(), "]"],
                            limits,
                        );
                        frames.push(Frame::Array {
                            values,
                            next_index: next_index + 1,
                            depth,
                            path,
                            output_start,
                        });
                        frames.push(Frame::Visit {
                            value,
                            depth: depth + 1,
                            path: child_path,
                        });
                    } else {
                        let children = output.split_off(output_start);
                        output.push(Self::Array(children));
                    }
                }
                Frame::Object {
                    mut values,
                    mut names,
                    depth,
                    path,
                    output_start,
                } => {
                    if let Some((name, value)) = values.next() {
                        let child_path = bounded_build_path(path.as_deref(), &[".", name], limits);
                        names.push(name.clone());
                        frames.push(Frame::Object {
                            values,
                            names,
                            depth,
                            path,
                            output_start,
                        });
                        frames.push(Frame::Visit {
                            value,
                            depth: depth + 1,
                            path: child_path,
                        });
                    } else {
                        let children = output.split_off(output_start);
                        output.push(Self::Object(names.into_iter().zip(children).collect()));
                    }
                }
            }
        }
        debug_assert_eq!(output.len(), 1);
        Ok(output
            .pop()
            .expect("one input value constructs one exact node"))
    }

    fn parse_document_bounded(
        raw: &RawValue,
        limits: RawJsonLimits,
    ) -> Result<ExactJsonDocument, ExactSchemaDocumentError> {
        enum Frame<'a> {
            Visit {
                raw: &'a RawValue,
                depth: usize,
                path: String,
            },
            Array {
                values: std::vec::IntoIter<&'a RawValue>,
                next_index: usize,
                depth: usize,
                path: String,
                output_start: usize,
            },
            Object {
                values: std::vec::IntoIter<(String, &'a RawValue)>,
                names: Vec<String>,
                depth: usize,
                path: String,
                output_start: usize,
            },
        }

        let mut remaining_nodes = limits.max_nodes;
        let mut frames = vec![Frame::Visit {
            raw,
            depth: 0,
            path: "$".to_owned(),
        }];
        let mut output = Vec::new();
        while let Some(frame) = frames.pop() {
            match frame {
                Frame::Visit { raw, depth, path } => {
                    if depth >= limits.max_depth || remaining_nodes == 0 {
                        return Err(ExactSchemaDocumentError::Schema(resource_limit(path)));
                    }
                    remaining_nodes -= 1;
                    let json = raw.get().trim();
                    match json.as_bytes().first() {
                        Some(b'{') => {
                            let RawObject(values) = serde_json::from_str(json)
                                .map_err(ExactSchemaDocumentError::Json)?;
                            frames.push(Frame::Object {
                                names: Vec::with_capacity(values.len()),
                                values: values.into_iter(),
                                depth,
                                path,
                                output_start: output.len(),
                            });
                        }
                        Some(b'[') => {
                            let values: Vec<&RawValue> = serde_json::from_str(json)
                                .map_err(ExactSchemaDocumentError::Json)?;
                            frames.push(Frame::Array {
                                values: values.into_iter(),
                                next_index: 0,
                                depth,
                                path,
                                output_start: output.len(),
                            });
                        }
                        Some(b'-' | b'0'..=b'9') => {
                            if json.len() > MAX_NUMBER_LEXEME_BYTES {
                                return Err(ExactSchemaDocumentError::Schema(resource_limit(path)));
                            }
                            let document = parse_exact_number(json);
                            if limits.reject_unbounded_numbers
                                && document
                                    .exact
                                    .number()
                                    .is_none_or(|number| number.decimal().is_none())
                            {
                                return Err(ExactSchemaDocumentError::Schema(resource_limit(path)));
                            }
                            output.push(document);
                        }
                        Some(_) | None => {
                            let value = serde_json::from_str(json)
                                .map_err(ExactSchemaDocumentError::Json)?;
                            output.push(ExactJsonDocument {
                                value,
                                exact: Self::Other,
                                lossless_value: true,
                            });
                        }
                    }
                }
                Frame::Array {
                    mut values,
                    next_index,
                    depth,
                    path,
                    output_start,
                } => {
                    if let Some(raw) = values.next() {
                        let child_path = bounded_raw_child_path(
                            &path,
                            &["[", &next_index.to_string(), "]"],
                            limits.max_path_bytes,
                        )
                        .map_err(ExactSchemaDocumentError::Schema)?;
                        frames.push(Frame::Array {
                            values,
                            next_index: next_index + 1,
                            depth,
                            path,
                            output_start,
                        });
                        frames.push(Frame::Visit {
                            raw,
                            depth: depth + 1,
                            path: child_path,
                        });
                    } else {
                        let children = output.split_off(output_start);
                        let mut value = Vec::with_capacity(children.len());
                        let mut exact = Vec::with_capacity(children.len());
                        let mut lossless_value = true;
                        for child in children {
                            value.push(child.value);
                            exact.push(child.exact);
                            lossless_value &= child.lossless_value;
                        }
                        output.push(ExactJsonDocument {
                            value: Value::Array(value),
                            exact: Self::Array(exact),
                            lossless_value,
                        });
                    }
                }
                Frame::Object {
                    mut values,
                    mut names,
                    depth,
                    path,
                    output_start,
                } => {
                    if let Some((name, raw)) = values.next() {
                        let child_path =
                            bounded_raw_child_path(&path, &[".", &name], limits.max_path_bytes)
                                .map_err(ExactSchemaDocumentError::Schema)?;
                        names.push(name);
                        frames.push(Frame::Object {
                            values,
                            names,
                            depth,
                            path,
                            output_start,
                        });
                        frames.push(Frame::Visit {
                            raw,
                            depth: depth + 1,
                            path: child_path,
                        });
                    } else {
                        let children = output.split_off(output_start);
                        let mut value = Map::with_capacity(children.len());
                        let mut exact = BTreeMap::new();
                        let mut lossless_by_name = BTreeMap::new();
                        for (name, child) in names.into_iter().zip(children) {
                            value.insert(name.clone(), child.value);
                            exact.insert(name.clone(), child.exact);
                            lossless_by_name.insert(name, child.lossless_value);
                        }
                        output.push(ExactJsonDocument {
                            value: Value::Object(value),
                            exact: Self::Object(exact),
                            lossless_value: lossless_by_name.values().all(|lossless| *lossless),
                        });
                    }
                }
            }
        }
        debug_assert_eq!(output.len(), 1);
        Ok(output
            .pop()
            .expect("one raw JSON value constructs one exact document"))
    }

    const fn number(&self) -> Option<&ExactNumber> {
        if let Self::Number(number) = self {
            Some(number)
        } else {
            None
        }
    }

    fn index(&self, index: usize) -> Option<&Self> {
        if let Self::Array(values) = self {
            values.get(index)
        } else {
            None
        }
    }

    fn key(&self, key: &str) -> Option<&Self> {
        if let Self::Object(values) = self {
            values.get(key)
        } else {
            None
        }
    }
}

fn bounded_build_path(
    path: Option<&str>,
    suffixes: &[&str],
    limits: Option<RawJsonLimits>,
) -> Option<String> {
    let path = path?;
    let maximum = limits.map_or(usize::MAX, |limits| limits.max_path_bytes);
    Some(extend_path(path, suffixes, maximum).unwrap_or_else(|| path.to_owned()))
}

fn parse_exact_number(raw: &str) -> ExactJsonDocument {
    let exact = ExactNumber::new(raw.to_owned());
    let (value, lossless_value) = serde_json::from_str(raw).map_or_else(
        |_| (Value::from(0), false),
        |value: Value| {
            let representable = value.as_number().is_some_and(|number| {
                let normalized = ExactNumber::new(number.to_string());
                exact
                    .decimal()
                    .zip(normalized.decimal())
                    .is_some_and(|(left, right)| left == right)
            });
            (value, representable)
        },
    );
    ExactJsonDocument {
        value,
        exact: ExactNode::Number(exact),
        lossless_value,
    }
}

fn write_exact_json(
    value: &Value,
    exact: &ExactNode,
    output: &mut Vec<u8>,
) -> Result<(), serde_json::Error> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => serde_json::to_writer(output, value),
        Value::Number(_) => {
            output.extend_from_slice(
                exact
                    .number()
                    .expect("exact document mirrors the JSON value")
                    .raw()
                    .as_bytes(),
            );
            Ok(())
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_exact_json(
                    value,
                    exact
                        .index(index)
                        .expect("exact document mirrors the JSON value"),
                    output,
                )?;
            }
            output.push(b']');
            Ok(())
        }
        Value::Object(values) => {
            output.push(b'{');
            for (index, (name, value)) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, name)?;
                output.push(b':');
                write_exact_json(
                    value,
                    exact
                        .key(name)
                        .expect("exact document mirrors the JSON value"),
                    output,
                )?;
            }
            output.push(b'}');
            Ok(())
        }
    }
}

struct RawObject<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for RawObject<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RawObjectVisitor)
    }
}

struct RawObjectVisitor;

impl<'de> Visitor<'de> for RawObjectVisitor {
    type Value = RawObject<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut entries = Vec::with_capacity(map.size_hint().unwrap_or(0));
        while let Some((name, value)) = map.next_entry::<String, &'de RawValue>()? {
            entries.push((name, value));
        }
        Ok(RawObject(entries))
    }
}

#[derive(Clone, Copy)]
struct RawJsonLimits {
    max_nodes: usize,
    max_depth: usize,
    max_path_bytes: usize,
    reject_unbounded_numbers: bool,
    track_paths: bool,
}

enum RawContainer {
    Array {
        path: String,
        depth: usize,
        next_index: usize,
        expect_value: bool,
    },
    Object {
        path: String,
        depth: usize,
        key: Option<String>,
        state: RawObjectState,
    },
}

enum RawObjectState {
    Key,
    Colon,
    Value,
    Comma,
}

#[derive(Clone, Copy)]
enum RawToken<'a> {
    ObjectStart,
    ObjectEnd,
    ArrayStart,
    ArrayEnd,
    Colon,
    Comma,
    String(&'a str, usize),
    Number(usize),
    Scalar,
}

struct RawJsonCursor<'a> {
    json: &'a str,
    offset: usize,
}

impl<'a> RawJsonCursor<'a> {
    const fn new(json: &'a str) -> Self {
        Self { json, offset: 0 }
    }

    fn next(&mut self) -> Option<RawToken<'a>> {
        let bytes = self.json.as_bytes();
        while bytes.get(self.offset).is_some_and(u8::is_ascii_whitespace) {
            self.offset += 1;
        }
        let byte = *bytes.get(self.offset)?;
        self.offset += 1;
        Some(match byte {
            b'{' => RawToken::ObjectStart,
            b'}' => RawToken::ObjectEnd,
            b'[' => RawToken::ArrayStart,
            b']' => RawToken::ArrayEnd,
            b':' => RawToken::Colon,
            b',' => RawToken::Comma,
            b'"' => self.string_token(),
            byte => {
                let start = self.offset - 1;
                while bytes.get(self.offset).is_some_and(|byte| {
                    !byte.is_ascii_whitespace() && !matches!(byte, b',' | b']' | b'}')
                }) {
                    self.offset += 1;
                }
                if matches!(byte, b'-' | b'0'..=b'9') {
                    RawToken::Number(self.offset - start)
                } else {
                    RawToken::Scalar
                }
            }
        })
    }

    fn string_token(&mut self) -> RawToken<'a> {
        let start = self.offset - 1;
        let bytes = self.json.as_bytes();
        let mut decoded_bytes = 0_usize;
        loop {
            let byte = bytes[self.offset];
            self.offset += 1;
            match byte {
                b'"' => {
                    return RawToken::String(&self.json[start..self.offset], decoded_bytes);
                }
                b'\\' => {
                    let escape = bytes[self.offset];
                    self.offset += 1;
                    if escape != b'u' {
                        decoded_bytes += 1;
                        continue;
                    }
                    let first = decode_hex_quad(bytes, self.offset);
                    self.offset += 4;
                    if (0xD800..=0xDBFF).contains(&first) {
                        self.offset += 2;
                        let second = decode_hex_quad(bytes, self.offset);
                        self.offset += 4;
                        let scalar = 0x1_0000
                            + ((u32::from(first) - 0xD800) << 10)
                            + (u32::from(second) - 0xDC00);
                        decoded_bytes += char::from_u32(scalar)
                            .expect("serde_json validated the surrogate pair")
                            .len_utf8();
                    } else {
                        decoded_bytes += char::from_u32(u32::from(first))
                            .expect("serde_json validated the Unicode escape")
                            .len_utf8();
                    }
                }
                byte if byte.is_ascii() => decoded_bytes += 1,
                _ => {
                    let character = self.json[self.offset - 1..]
                        .chars()
                        .next()
                        .expect("serde_json validated the UTF-8 string");
                    let width = character.len_utf8();
                    decoded_bytes += width;
                    self.offset += width - 1;
                }
            }
        }
    }
}

fn decode_hex_quad(bytes: &[u8], offset: usize) -> u16 {
    bytes[offset..offset + 4].iter().fold(0_u16, |value, byte| {
        value * 16
            + u16::from(match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => unreachable!("serde_json validated the hexadecimal escape"),
            })
    })
}

fn preflight_raw_json(json: &str, limits: RawJsonLimits) -> Result<(), SchemaError> {
    let mut cursor = RawJsonCursor::new(json);
    let mut remaining_nodes = limits.max_nodes;
    let mut containers = Vec::new();
    let root = cursor
        .next()
        .expect("serde_json validated a non-empty document");
    start_raw_value(
        root,
        "$".to_owned(),
        0,
        limits,
        &mut remaining_nodes,
        &mut containers,
    )?;
    while let Some(container) = containers.pop() {
        let token = cursor
            .next()
            .expect("serde_json validated the complete document");
        match container {
            RawContainer::Array {
                path,
                depth,
                next_index,
                expect_value: true,
            } => {
                if matches!(token, RawToken::ArrayEnd) {
                    continue;
                }
                let index = next_index.to_string();
                let child_path =
                    bounded_raw_child_path(&path, &["[", &index, "]"], limits.max_path_bytes)?;
                containers.push(RawContainer::Array {
                    path,
                    depth,
                    next_index: next_index + 1,
                    expect_value: false,
                });
                start_raw_value(
                    token,
                    child_path,
                    depth + 1,
                    limits,
                    &mut remaining_nodes,
                    &mut containers,
                )?;
            }
            RawContainer::Array {
                path,
                depth,
                next_index,
                expect_value: false,
            } => match token {
                RawToken::Comma => containers.push(RawContainer::Array {
                    path,
                    depth,
                    next_index,
                    expect_value: true,
                }),
                RawToken::ArrayEnd => {}
                _ => unreachable!("serde_json validated the array separators"),
            },
            RawContainer::Object {
                path,
                depth,
                key: None,
                state: RawObjectState::Key,
            } => match token {
                RawToken::ObjectEnd => {}
                RawToken::String(raw_key, decoded_bytes) => {
                    let minimum_length = path
                        .len()
                        .checked_add(1)
                        .and_then(|length| length.checked_add(decoded_bytes));
                    if minimum_length.is_none_or(|length| length > limits.max_path_bytes) {
                        return Err(resource_limit("$".to_owned()));
                    }
                    let key =
                        serde_json::from_str(raw_key).expect("serde_json validated the object key");
                    containers.push(RawContainer::Object {
                        path,
                        depth,
                        key: Some(key),
                        state: RawObjectState::Colon,
                    });
                }
                _ => unreachable!("serde_json validated the object key"),
            },
            RawContainer::Object {
                path,
                depth,
                key,
                state: RawObjectState::Colon,
            } => {
                debug_assert!(matches!(token, RawToken::Colon));
                containers.push(RawContainer::Object {
                    path,
                    depth,
                    key,
                    state: RawObjectState::Value,
                });
            }
            RawContainer::Object {
                path,
                depth,
                key: Some(key),
                state: RawObjectState::Value,
            } => {
                let child_path =
                    bounded_raw_child_path(&path, &[".", &key], limits.max_path_bytes)?;
                containers.push(RawContainer::Object {
                    path,
                    depth,
                    key: None,
                    state: RawObjectState::Comma,
                });
                start_raw_value(
                    token,
                    child_path,
                    depth + 1,
                    limits,
                    &mut remaining_nodes,
                    &mut containers,
                )?;
            }
            RawContainer::Object {
                path,
                depth,
                key: None,
                state: RawObjectState::Comma,
            } => match token {
                RawToken::Comma => containers.push(RawContainer::Object {
                    path,
                    depth,
                    key: None,
                    state: RawObjectState::Key,
                }),
                RawToken::ObjectEnd => {}
                _ => unreachable!("serde_json validated the object separators"),
            },
            RawContainer::Object { .. } => {
                unreachable!("object keys exist only between key and value states")
            }
        }
    }
    let trailing = cursor.next();
    debug_assert!(trailing.is_none());
    Ok(())
}

fn start_raw_value(
    token: RawToken<'_>,
    path: String,
    depth: usize,
    limits: RawJsonLimits,
    remaining_nodes: &mut usize,
    containers: &mut Vec<RawContainer>,
) -> Result<(), SchemaError> {
    if depth >= limits.max_depth || *remaining_nodes == 0 {
        return Err(resource_limit(path));
    }
    *remaining_nodes -= 1;
    match token {
        RawToken::ObjectStart => containers.push(RawContainer::Object {
            path,
            depth,
            key: None,
            state: RawObjectState::Key,
        }),
        RawToken::ArrayStart => containers.push(RawContainer::Array {
            path,
            depth,
            next_index: 0,
            expect_value: true,
        }),
        RawToken::Number(length) if length > MAX_NUMBER_LEXEME_BYTES => {
            return Err(resource_limit(path));
        }
        RawToken::String(_, _) | RawToken::Number(_) | RawToken::Scalar => {}
        RawToken::ObjectEnd | RawToken::ArrayEnd | RawToken::Colon | RawToken::Comma => {
            unreachable!("serde_json validated a value at this position")
        }
    }
    Ok(())
}

fn bounded_raw_child_path(
    path: &str,
    suffixes: &[&str],
    maximum: usize,
) -> Result<String, SchemaError> {
    extend_path(path, suffixes, maximum).ok_or_else(|| resource_limit("$".to_owned()))
}

const fn resource_limit(path: String) -> SchemaError {
    SchemaError {
        path,
        kind: SchemaErrorKind::ResourceLimit,
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
    /// A schema keyword is outside the explicitly supported subset.
    UnsupportedKeyword,
    /// A keyword has the wrong JSON value type.
    InvalidKeywordType,
    /// A numeric bound is negative or non-integral.
    InvalidLengthBound,
    /// `required` contains duplicate property names.
    DuplicateRequiredProperty,
    /// `enum` is empty.
    EmptyEnum,
    /// Schema traversal, numeric, nesting, or diagnostic path limits were exceeded.
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
    /// Input nesting, exact comparison work, or a diagnostic path exceeded configured limits.
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

    fn matches(self, value: &Value, exact: &ExactNode) -> bool {
        match self {
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            Self::String => value.is_string(),
            Self::Number => value.is_number(),
            Self::Integer => value.is_number() && exact.number().is_some_and(number_is_integer),
            Self::Boolean => value.is_boolean(),
            Self::Null => value.is_null(),
        }
    }
}

/// Validates the supported JSON Schema subset used for skill parameters.
///
/// Supported keywords are `type`, `properties`, `required`,
/// `additionalProperties`, `items`, `enum`, `minLength`, `maxLength`,
/// `minimum`, and `maximum`. Explicitly allowlisted annotation keywords are
/// accepted but do not assert constraints.
///
/// # Errors
///
/// Returns the first [`SchemaError`], carrying the JSON path of the offending
/// node and one of: [`SchemaErrorKind::ExpectedObject`] when a schema node — the
/// root, a `properties` entry, or `items` — is not a JSON object;
/// [`SchemaErrorKind::UnsupportedType`] when `type` names something outside the
/// supported JSON types; [`SchemaErrorKind::UnsupportedKeyword`] when a key is
/// outside the explicit allowlist; [`SchemaErrorKind::InvalidKeywordType`] when
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
    let exact = ExactNode::from_value_bounded(
        schema,
        RawJsonLimits {
            max_nodes: limits.max_schema_nodes.get(),
            max_depth: limits.max_depth.get(),
            max_path_bytes: limits.max_path_bytes.get(),
            reject_unbounded_numbers: true,
            track_paths: true,
        },
    )?;
    validate_schema_at(schema, &exact, "$", 0, limits)
}

pub(crate) fn validate_schema_with_exact(
    schema: &Value,
    exact_schema: &ExactNode,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    preflight_schema_value(schema, limits)?;
    validate_schema_at(schema, exact_schema, "$", 0, limits)
}

fn preflight_schema_value(schema: &Value, limits: ValidationLimits) -> Result<(), SchemaError> {
    enum Frame<'a> {
        Visit {
            value: &'a Value,
            depth: usize,
            path: String,
        },
        Array {
            values: &'a [Value],
            next_index: usize,
            depth: usize,
            path: String,
        },
        Object {
            values: std::iter::Peekable<serde_json::map::Iter<'a>>,
            depth: usize,
            path: String,
        },
    }

    let mut remaining_nodes = limits.max_schema_nodes.get();
    let mut pending = vec![Frame::Visit {
        value: schema,
        depth: 0,
        path: "$".to_owned(),
    }];
    while let Some(frame) = pending.pop() {
        match frame {
            Frame::Visit { value, depth, path } => {
                if depth >= limits.max_depth.get() || remaining_nodes == 0 {
                    return Err(resource_limit(path));
                }
                remaining_nodes -= 1;
                match value {
                    Value::Array(values) if !values.is_empty() => pending.push(Frame::Array {
                        values,
                        next_index: 0,
                        depth,
                        path,
                    }),
                    Value::Object(values) if !values.is_empty() => {
                        pending.push(Frame::Object {
                            values: values.iter().peekable(),
                            depth,
                            path,
                        });
                    }
                    Value::Array(_)
                    | Value::Object(_)
                    | Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::String(_) => {}
                }
            }
            Frame::Array {
                values,
                next_index,
                depth,
                path,
            } => {
                let index = next_index.to_string();
                let child_path =
                    extend_path(&path, &["[", &index, "]"], limits.max_path_bytes.get())
                        .unwrap_or_else(|| path.clone());
                if next_index + 1 < values.len() {
                    pending.push(Frame::Array {
                        values,
                        next_index: next_index + 1,
                        depth,
                        path,
                    });
                }
                pending.push(Frame::Visit {
                    value: &values[next_index],
                    depth: depth + 1,
                    path: child_path,
                });
            }
            Frame::Object {
                mut values,
                depth,
                path,
            } => {
                let (name, value) = values
                    .next()
                    .expect("empty schema objects do not create traversal frames");
                let child_path = extend_path(&path, &[".", name], limits.max_path_bytes.get())
                    .unwrap_or_else(|| path.clone());
                if values.peek().is_some() {
                    pending.push(Frame::Object {
                        values,
                        depth,
                        path,
                    });
                }
                pending.push(Frame::Visit {
                    value,
                    depth: depth + 1,
                    path: child_path,
                });
            }
        }
    }
    Ok(())
}

fn validate_schema_at(
    schema: &Value,
    exact_schema: &ExactNode,
    path: &str,
    depth: usize,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    if depth >= limits.max_depth.get() {
        return Err(SchemaError {
            path: path.to_owned(),
            kind: SchemaErrorKind::ResourceLimit,
        });
    }
    let object = schema.as_object().ok_or_else(|| SchemaError {
        path: path.to_owned(),
        kind: SchemaErrorKind::ExpectedObject,
    })?;
    validate_supported_keywords(object, path, limits)?;
    validate_type_keyword(object, path, limits)?;
    validate_object_keywords(object, exact_schema, path, depth, limits)?;
    validate_items_keyword(object, exact_schema, path, depth, limits)?;
    validate_enum_keyword(object, path, limits)?;
    validate_length_keyword(object, exact_schema, path, "minLength", limits)?;
    validate_length_keyword(object, exact_schema, path, "maxLength", limits)?;
    validate_number_keyword(object, exact_schema, path, "minimum", limits)?;
    validate_number_keyword(object, exact_schema, path, "maximum", limits)?;
    Ok(())
}

fn validate_supported_keywords(
    object: &Map<String, Value>,
    path: &str,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    if let Some(keyword) = object
        .keys()
        .find(|keyword| !SUPPORTED_SCHEMA_KEYWORDS.contains(&keyword.as_str()))
    {
        return Err(SchemaError {
            path: schema_child_path(path, &[".", keyword], limits)?,
            kind: SchemaErrorKind::UnsupportedKeyword,
        });
    }
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
    exact_schema: &ExactNode,
    path: &str,
    depth: usize,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    if let Some(properties) = object.get("properties") {
        let properties_path = schema_child_path(path, &[".properties"], limits)?;
        let properties = properties.as_object().ok_or(SchemaError {
            path: properties_path,
            kind: SchemaErrorKind::InvalidKeywordType,
        })?;
        let exact_properties = exact_schema
            .key("properties")
            .expect("exact schema mirrors the schema value");
        for (name, property_schema) in properties {
            let property_path = schema_child_path(path, &[".properties.", name.as_str()], limits)?;
            let exact_property_schema = exact_properties
                .key(name)
                .expect("exact schema mirrors the schema value");
            validate_schema_at(
                property_schema,
                exact_property_schema,
                &property_path,
                depth + 1,
                limits,
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
    exact_schema: &ExactNode,
    path: &str,
    depth: usize,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    if let Some(items) = object.get("items") {
        let item_path = schema_child_path(path, &[".items"], limits)?;
        let exact_items = exact_schema
            .key("items")
            .expect("exact schema mirrors the schema value");
        validate_schema_at(items, exact_items, &item_path, depth + 1, limits)?;
    }
    Ok(())
}

fn validate_enum_keyword(
    object: &Map<String, Value>,
    path: &str,
    limits: ValidationLimits,
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
    }
    Ok(())
}

fn validate_length_keyword(
    object: &Map<String, Value>,
    exact_schema: &ExactNode,
    path: &str,
    keyword: &str,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    if object.contains_key(keyword)
        && exact_schema
            .key(keyword)
            .and_then(ExactNode::number)
            .and_then(ExactNumber::nonnegative_integer)
            .is_none()
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
    exact_schema: &ExactNode,
    path: &str,
    keyword: &str,
    limits: ValidationLimits,
) -> Result<(), SchemaError> {
    let Some(_) = object.get(keyword) else {
        return Ok(());
    };
    let Some(number) = exact_schema.key(keyword).and_then(ExactNode::number) else {
        return Err(SchemaError {
            path: schema_child_path(path, &[".", keyword], limits)?,
            kind: SchemaErrorKind::InvalidKeywordType,
        });
    };
    if number.decimal().is_none() {
        return Err(SchemaError {
            path: schema_child_path(path, &[".", keyword], limits)?,
            kind: SchemaErrorKind::ResourceLimit,
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

/// Validates exact JSON documents without rounding their original number
/// lexemes through binary floating point.
///
/// # Errors
///
/// Returns the same validation errors as [`validate_parameters`].
pub fn validate_exact_parameters(
    schema: &ExactJsonDocument,
    parameters: &ExactJsonDocument,
) -> Result<(), ParameterValidationError> {
    validate_exact_parameters_with_limits(schema, parameters, ValidationLimits::default())
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
    let exact_schema = ExactNode::from_value_bounded(
        schema,
        RawJsonLimits {
            max_nodes: limits.max_schema_nodes.get(),
            max_depth: limits.max_depth.get(),
            max_path_bytes: limits.max_path_bytes.get(),
            reject_unbounded_numbers: true,
            track_paths: true,
        },
    )
    .map_err(ParameterValidationError::InvalidSchema)?;
    validate_schema_at(schema, &exact_schema, "$", 0, limits)
        .map_err(ParameterValidationError::InvalidSchema)?;
    let mut remaining_values = limits.max_input_nodes.get();
    validate_input_node(
        parameters,
        0,
        limits,
        &mut remaining_values,
        &mut Vec::new(),
    )?;
    let exact_parameters = ExactNode::from_value(parameters);
    validate_parameters_after_preflight(
        schema,
        &exact_schema,
        parameters,
        &exact_parameters,
        limits,
    )
}

/// Validates exact JSON documents under explicit traversal and diagnostic
/// limits.
///
/// # Errors
///
/// Returns the same validation errors as
/// [`validate_parameters_with_limits`].
pub fn validate_exact_parameters_with_limits(
    schema: &ExactJsonDocument,
    parameters: &ExactJsonDocument,
    limits: ValidationLimits,
) -> Result<(), ParameterValidationError> {
    validate_parameters_inner(
        &schema.value,
        &schema.exact,
        &parameters.value,
        &parameters.exact,
        limits,
    )
}

pub(crate) fn validate_parameters_with_exact_schema(
    schema: &Value,
    exact_schema: &ExactNode,
    parameters: &ExactJsonDocument,
) -> Result<(), ParameterValidationError> {
    validate_parameters_inner(
        schema,
        exact_schema,
        &parameters.value,
        &parameters.exact,
        ValidationLimits::default(),
    )
}

fn validate_parameters_inner(
    schema: &Value,
    exact_schema: &ExactNode,
    parameters: &Value,
    exact_parameters: &ExactNode,
    limits: ValidationLimits,
) -> Result<(), ParameterValidationError> {
    validate_schema_with_exact(schema, exact_schema, limits)
        .map_err(ParameterValidationError::InvalidSchema)?;
    let mut remaining_values = limits.max_input_nodes.get();
    validate_input_node(
        parameters,
        0,
        limits,
        &mut remaining_values,
        &mut Vec::new(),
    )?;
    validate_parameters_after_preflight(schema, exact_schema, parameters, exact_parameters, limits)
}

fn validate_parameters_after_preflight(
    schema: &Value,
    exact_schema: &ExactNode,
    parameters: &Value,
    exact_parameters: &ExactNode,
    limits: ValidationLimits,
) -> Result<(), ParameterValidationError> {
    let mut context = ValidationContext {
        violations: Vec::new(),
        limits,
        limit_reached: false,
        remaining_comparisons: limits.max_comparison_nodes.get(),
    };
    let _completed = validate_value(
        schema,
        exact_schema,
        parameters,
        exact_parameters,
        "$",
        0,
        &mut context,
    )?;
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
        parameter_child_path(path, suffixes, self.limits)
    }

    fn consume_comparisons(
        &mut self,
        count: usize,
        path: &str,
    ) -> Result<(), ParameterValidationError> {
        let Some(remaining) = self.remaining_comparisons.checked_sub(count) else {
            return Err(ParameterValidationError::ResourceLimit {
                path: path.to_owned(),
            });
        };
        self.remaining_comparisons = remaining;
        Ok(())
    }

    fn compare_numbers(
        &mut self,
        left: &ExactNumber,
        right: &ExactNumber,
        path: &str,
        unit_already_charged: bool,
    ) -> Result<Ordering, ParameterValidationError> {
        let units = left.comparison_units().max(right.comparison_units());
        let charge = units.saturating_sub(usize::from(unit_already_charged));
        self.consume_comparisons(charge, path)?;
        let (Some(left), Some(right)) = (left.decimal(), right.decimal()) else {
            return Err(ParameterValidationError::ResourceLimit {
                path: path.to_owned(),
            });
        };
        Ok(left.cmp(right))
    }
}

fn validate_input_node<'a>(
    value: &'a Value,
    depth: usize,
    limits: ValidationLimits,
    remaining_values: &mut usize,
    path: &mut Vec<InputPathComponent<'a>>,
) -> Result<(), ParameterValidationError> {
    if depth >= limits.max_depth.get() || *remaining_values == 0 {
        return Err(ParameterValidationError::ResourceLimit {
            path: render_input_path(path, limits.max_path_bytes.get()),
        });
    }
    *remaining_values -= 1;
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                path.push(InputPathComponent::Index(index));
                let result = validate_input_node(value, depth + 1, limits, remaining_values, path);
                path.pop();
                result?;
            }
        }
        Value::Object(values) => {
            for (name, value) in values {
                path.push(InputPathComponent::Key(name));
                let result = validate_input_node(value, depth + 1, limits, remaining_values, path);
                path.pop();
                result?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

enum InputPathComponent<'a> {
    Key(&'a str),
    Index(usize),
}

fn render_input_path(path: &[InputPathComponent<'_>], max_bytes: usize) -> String {
    let mut rendered = "$".to_owned();
    for component in path {
        let next = match component {
            InputPathComponent::Key(name) => extend_path(&rendered, &[".", name], max_bytes),
            InputPathComponent::Index(index) => {
                let index_text = index.to_string();
                extend_path(&rendered, &["[", &index_text, "]"], max_bytes)
            }
        };
        let Some(next) = next else {
            break;
        };
        rendered = next;
    }
    rendered
}

fn parameter_child_path(
    path: &str,
    suffixes: &[&str],
    limits: ValidationLimits,
) -> Result<String, ParameterValidationError> {
    extend_path(path, suffixes, limits.max_path_bytes.get()).ok_or_else(|| {
        ParameterValidationError::ResourceLimit {
            path: path.to_owned(),
        }
    })
}

fn validate_value(
    schema: &Value,
    exact_schema: &ExactNode,
    value: &Value,
    exact_value: &ExactNode,
    path: &str,
    depth: usize,
    context: &mut ValidationContext,
) -> Result<bool, ParameterValidationError> {
    if depth >= context.limits.max_depth.get() {
        return Err(ParameterValidationError::ResourceLimit {
            path: path.to_owned(),
        });
    }
    let object = schema
        .as_object()
        .expect("schema validation guarantees object nodes");
    if let Some(values) = object.get("enum").and_then(Value::as_array) {
        let exact_values = exact_schema
            .key("enum")
            .expect("exact schema mirrors the validated schema");
        let contained = enum_contains(values, exact_values, value, exact_value, path, context)?;
        if !contained && !context.record(path, ParameterViolationKind::NotInEnum) {
            return Ok(false);
        }
    }
    if let Some(expected) = object
        .get("type")
        .and_then(Value::as_str)
        .and_then(JsonType::parse)
        && !expected.matches(value, exact_value)
    {
        return Ok(context.record(path, ParameterViolationKind::TypeMismatch));
    }
    if let Some(value) = value.as_object()
        && !validate_object_value(
            object,
            exact_schema,
            value,
            exact_value,
            path,
            depth,
            context,
        )?
    {
        return Ok(false);
    }
    if let Some(value) = value.as_array()
        && let Some(item_schema) = object.get("items")
    {
        let exact_item_schema = exact_schema
            .key("items")
            .expect("exact schema mirrors the validated schema");
        for (index, item) in value.iter().enumerate() {
            let index_text = index.to_string();
            let item_path = context.child_path(path, &["[", &index_text, "]"])?;
            let exact_item = exact_value
                .index(index)
                .expect("exact parameters mirror the parameter value");
            if !validate_value(
                item_schema,
                exact_item_schema,
                item,
                exact_item,
                &item_path,
                depth + 1,
                context,
            )? {
                return Ok(false);
            }
        }
    }
    if let Some(value) = value.as_str() {
        let length = u64::try_from(value.chars().count()).unwrap_or(u64::MAX);
        if object
            .contains_key("minLength")
            .then(|| {
                exact_schema
                    .key("minLength")
                    .and_then(ExactNode::number)
                    .and_then(ExactNumber::nonnegative_integer)
                    .expect("schema validation guarantees a representable length bound")
            })
            .is_some_and(|minimum| length < minimum)
            && !context.record(path, ParameterViolationKind::StringTooShort)
        {
            return Ok(false);
        }
        if object
            .contains_key("maxLength")
            .then(|| {
                exact_schema
                    .key("maxLength")
                    .and_then(ExactNode::number)
                    .and_then(ExactNumber::nonnegative_integer)
                    .expect("schema validation guarantees a representable length bound")
            })
            .is_some_and(|maximum| length > maximum)
            && !context.record(path, ParameterViolationKind::StringTooLong)
        {
            return Ok(false);
        }
    }
    if value.is_number() {
        let exact_value = exact_value
            .number()
            .expect("exact parameters mirror the parameter value");
        if object.contains_key("minimum") {
            let minimum = exact_schema
                .key("minimum")
                .and_then(ExactNode::number)
                .expect("exact schema mirrors the validated schema");
            if context.compare_numbers(exact_value, minimum, path, false)? == Ordering::Less
                && !context.record(path, ParameterViolationKind::NumberTooSmall)
            {
                return Ok(false);
            }
        }
        if object.contains_key("maximum") {
            let maximum = exact_schema
                .key("maximum")
                .and_then(ExactNode::number)
                .expect("exact schema mirrors the validated schema");
            if context.compare_numbers(exact_value, maximum, path, false)? == Ordering::Greater
                && !context.record(path, ParameterViolationKind::NumberTooLarge)
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn enum_contains(
    candidates: &[Value],
    exact_candidates: &ExactNode,
    value: &Value,
    exact_value: &ExactNode,
    path: &str,
    context: &mut ValidationContext,
) -> Result<bool, ParameterValidationError> {
    for (index, candidate) in candidates.iter().enumerate() {
        let exact_candidate = exact_candidates
            .index(index)
            .expect("exact schema mirrors the validated schema");
        if json_equal_bounded(
            candidate,
            exact_candidate,
            value,
            exact_value,
            0,
            path,
            context,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn json_equal_bounded(
    candidate: &Value,
    exact_candidate: &ExactNode,
    value: &Value,
    exact_value: &ExactNode,
    depth: usize,
    path: &str,
    context: &mut ValidationContext,
) -> Result<bool, ParameterValidationError> {
    if depth >= context.limits.max_depth.get() || context.remaining_comparisons == 0 {
        return Err(ParameterValidationError::ResourceLimit {
            path: path.to_owned(),
        });
    }
    context.consume_comparisons(1, path)?;
    match (candidate, value) {
        (Value::Null, Value::Null) => Ok(true),
        (Value::Bool(left), Value::Bool(right)) => Ok(left == right),
        (Value::Number(_), Value::Number(_)) => context
            .compare_numbers(
                exact_candidate
                    .number()
                    .expect("exact schema mirrors the validated schema"),
                exact_value
                    .number()
                    .expect("exact parameters mirror the parameter value"),
                path,
                true,
            )
            .map(|ordering| ordering == Ordering::Equal),
        (Value::String(left), Value::String(right)) => Ok(left == right),
        (Value::Array(left), Value::Array(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (index, (left, right)) in left.iter().zip(right).enumerate() {
                let index_text = index.to_string();
                let child_path = context.child_path(path, &["[", &index_text, "]"])?;
                let exact_left = exact_candidate
                    .index(index)
                    .expect("exact schema mirrors the validated schema");
                let exact_right = exact_value
                    .index(index)
                    .expect("exact parameters mirror the parameter value");
                if !json_equal_bounded(
                    left,
                    exact_left,
                    right,
                    exact_right,
                    depth + 1,
                    &child_path,
                    context,
                )? {
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
                let exact_left = exact_candidate
                    .key(name)
                    .expect("exact schema mirrors the validated schema");
                let exact_right = exact_value
                    .key(name)
                    .expect("exact parameters mirror the parameter value");
                if !json_equal_bounded(
                    left,
                    exact_left,
                    right,
                    exact_right,
                    depth + 1,
                    &child_path,
                    context,
                )? {
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

fn number_is_integer(number: &ExactNumber) -> bool {
    number.decimal().is_some_and(ExactDecimal::is_integer)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactDecimal {
    negative: bool,
    significant: Vec<u8>,
    highest_exponent: BigSigned,
    least_exponent: BigSigned,
}

impl ExactDecimal {
    fn parse_bounded(raw: &str) -> Option<Self> {
        if raw.len() > MAX_NUMBER_LEXEME_BYTES {
            return None;
        }
        let (negative, unsigned) = raw
            .strip_prefix('-')
            .map_or((false, raw), |unsigned| (true, unsigned));
        let (mantissa, exponent) = unsigned
            .split_once(['e', 'E'])
            .map_or((unsigned, "0"), |parts| parts);
        let (integer, fraction) = mantissa
            .split_once('.')
            .map_or((mantissa, ""), |parts| parts);
        let mantissa_digits = integer.len().checked_add(fraction.len())?;
        if mantissa_digits > MAX_NUMBER_MANTISSA_DIGITS || !bounded_exponent(exponent) {
            return None;
        }
        let digits = integer
            .bytes()
            .chain(fraction.bytes())
            .map(|digit| digit - b'0')
            .collect::<Vec<_>>();
        let Some(first_nonzero) = digits.iter().position(|digit| *digit != 0) else {
            return Some(Self {
                negative: false,
                significant: Vec::new(),
                highest_exponent: BigSigned::zero(),
                least_exponent: BigSigned::zero(),
            });
        };
        let last_nonzero = digits
            .iter()
            .rposition(|digit| *digit != 0)
            .expect("a first nonzero digit implies a last nonzero digit");
        let trailing_zeros = digits.len() - last_nonzero - 1;
        let exponent = BigSigned::parse(exponent);
        let highest_adjustment = BigSigned::from_difference(integer.len(), first_nonzero + 1);
        let least_adjustment = BigSigned::from_difference(trailing_zeros, fraction.len());
        Some(Self {
            negative,
            significant: digits[first_nonzero..=last_nonzero].to_vec(),
            highest_exponent: exponent.clone().add(&highest_adjustment),
            least_exponent: exponent.add(&least_adjustment),
        })
    }

    const fn is_zero(&self) -> bool {
        self.significant.is_empty()
    }

    const fn is_integer(&self) -> bool {
        self.is_zero() || !self.least_exponent.negative
    }

    fn to_u64(&self) -> Option<u64> {
        if self.is_zero() {
            return Some(0);
        }
        if self.negative || !self.is_integer() {
            return None;
        }
        if self.highest_exponent > BigSigned::from_usize(19, false) {
            return None;
        }
        let trailing_zeros = self.least_exponent.to_usize()?;
        let mut value = 0_u64;
        for digit in &self.significant {
            value = value.checked_mul(10)?.checked_add(u64::from(*digit))?;
        }
        for _ in 0..trailing_zeros {
            value = value.checked_mul(10)?;
        }
        Some(value)
    }

    fn comparison_units(&self) -> usize {
        self.significant
            .len()
            .saturating_add(self.highest_exponent.digits.len())
            .saturating_add(self.least_exponent.digits.len())
            .max(1)
            .div_ceil(COMPARISON_DIGITS_PER_UNIT)
    }

    fn cmp_magnitude(&self, other: &Self) -> Ordering {
        match self.highest_exponent.cmp(&other.highest_exponent) {
            Ordering::Equal => {
                let width = self.significant.len().max(other.significant.len());
                (0..width)
                    .map(|index| {
                        (
                            self.significant.get(index).copied().unwrap_or(0),
                            other.significant.get(index).copied().unwrap_or(0),
                        )
                    })
                    .find_map(|(left, right)| match left.cmp(&right) {
                        Ordering::Equal => None,
                        ordering => Some(ordering),
                    })
                    .unwrap_or(Ordering::Equal)
            }
            ordering => ordering,
        }
    }
}

impl Ord for ExactDecimal {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.is_zero(), other.is_zero()) {
            (true, true) => Ordering::Equal,
            (true, false) => {
                if other.negative {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (false, true) => {
                if self.negative {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (false, false) if self.negative != other.negative => {
                if self.negative {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (false, false) => {
                let magnitude = self.cmp_magnitude(other);
                if self.negative {
                    magnitude.reverse()
                } else {
                    magnitude
                }
            }
        }
    }
}

impl PartialOrd for ExactDecimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BigSigned {
    negative: bool,
    digits: Vec<u8>,
}

impl BigSigned {
    const fn zero() -> Self {
        Self {
            negative: false,
            digits: Vec::new(),
        }
    }

    fn parse(raw: &str) -> Self {
        let (negative, magnitude) = match raw.as_bytes().first() {
            Some(b'-') => (true, &raw[1..]),
            Some(b'+') => (false, &raw[1..]),
            _ => (false, raw),
        };
        let magnitude = magnitude.trim_start_matches('0');
        if magnitude.is_empty() {
            return Self::zero();
        }
        Self {
            negative,
            digits: magnitude.bytes().map(|digit| digit - b'0').collect(),
        }
    }

    fn from_difference(positive: usize, negative: usize) -> Self {
        match positive.cmp(&negative) {
            Ordering::Equal => Self::zero(),
            Ordering::Greater => Self::from_usize(positive - negative, false),
            Ordering::Less => Self::from_usize(negative - positive, true),
        }
    }

    fn from_usize(value: usize, negative: bool) -> Self {
        if value == 0 {
            return Self::zero();
        }
        Self {
            negative,
            digits: value
                .to_string()
                .bytes()
                .map(|digit| digit - b'0')
                .collect(),
        }
    }

    fn to_usize(&self) -> Option<usize> {
        if self.negative {
            return None;
        }
        self.digits.iter().try_fold(0_usize, |value, digit| {
            value.checked_mul(10)?.checked_add(usize::from(*digit))
        })
    }

    fn add(self, other: &Self) -> Self {
        if self.negative == other.negative {
            return Self {
                negative: self.negative,
                digits: add_magnitudes(&self.digits, &other.digits),
            };
        }
        match compare_magnitudes(&self.digits, &other.digits) {
            Ordering::Equal => Self::zero(),
            Ordering::Greater => Self {
                negative: self.negative,
                digits: subtract_magnitudes(&self.digits, &other.digits),
            },
            Ordering::Less => Self {
                negative: other.negative,
                digits: subtract_magnitudes(&other.digits, &self.digits),
            },
        }
    }
}

fn bounded_exponent(raw: &str) -> bool {
    let magnitude = match raw.as_bytes().first() {
        Some(b'-' | b'+') => &raw[1..],
        Some(_) | None => raw,
    };
    !magnitude.is_empty()
        && magnitude.len() <= MAX_NUMBER_EXPONENT_DIGITS
        && magnitude
            .parse::<u32>()
            .is_ok_and(|exponent| exponent <= MAX_NUMBER_EXPONENT)
}

impl Ord for BigSigned {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.negative != other.negative {
            return if self.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let magnitude = compare_magnitudes(&self.digits, &other.digits);
        if self.negative {
            magnitude.reverse()
        } else {
            magnitude
        }
    }
}

impl PartialOrd for BigSigned {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_magnitudes(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn add_magnitudes(left: &[u8], right: &[u8]) -> Vec<u8> {
    let width = left.len().max(right.len());
    let mut output = Vec::with_capacity(width + 1);
    let mut carry = 0;
    for offset in 0..width {
        let left = left
            .len()
            .checked_sub(offset + 1)
            .map_or(0, |index| left[index]);
        let right = right
            .len()
            .checked_sub(offset + 1)
            .map_or(0, |index| right[index]);
        let sum = left + right + carry;
        output.push(sum % 10);
        carry = sum / 10;
    }
    if carry != 0 {
        output.push(carry);
    }
    output.reverse();
    output
}

fn subtract_magnitudes(larger: &[u8], smaller: &[u8]) -> Vec<u8> {
    debug_assert_ne!(compare_magnitudes(larger, smaller), Ordering::Less);
    let mut output = Vec::with_capacity(larger.len());
    let mut borrow = 0_i16;
    for offset in 0..larger.len() {
        let larger = i16::from(larger[larger.len() - offset - 1]);
        let smaller = smaller
            .len()
            .checked_sub(offset + 1)
            .map_or(0, |index| i16::from(smaller[index]));
        let mut difference = larger - smaller - borrow;
        if difference < 0 {
            difference += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        output.push(u8::try_from(difference).expect("decimal difference"));
    }
    while output.last() == Some(&0) {
        output.pop();
    }
    output.reverse();
    output
}

fn validate_object_value(
    schema: &Map<String, Value>,
    exact_schema: &ExactNode,
    value: &Map<String, Value>,
    exact_value: &ExactNode,
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
        let exact_properties = exact_schema
            .key("properties")
            .expect("exact schema mirrors the validated schema");
        for (name, property_schema) in properties {
            if let Some(property_value) = value.get(name) {
                let property_path = context.child_path(path, &[".", name])?;
                let exact_property_schema = exact_properties
                    .key(name)
                    .expect("exact schema mirrors the validated schema");
                let exact_property_value = exact_value
                    .key(name)
                    .expect("exact parameters mirror the parameter value");
                if !validate_value(
                    property_schema,
                    exact_property_schema,
                    property_value,
                    exact_property_value,
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
