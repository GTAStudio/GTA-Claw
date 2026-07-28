//! The single ring-zero authority tool that wraps every typed operation.
//!
//! A Crestodian session runs the ordinary agent loop restricted to exactly one
//! `OpenClaw` authority tool, `crestodian`. Normal agent sessions never receive
//! it, and a backend that cannot prove the restriction fails closed before any
//! inference happens rather than running with an unbounded native tool set.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use serde_json::{Map, Value, json};

use crate::mutation::{MutationField, MutationRejection, TypedMutation};

/// Stable name of the only `OpenClaw` authority tool a Crestodian session may call.
pub const RING_ZERO_TOOL: &str = "crestodian";

/// Codex's inert native planning utility, tolerated beside the authority tool.
///
/// It can update the model's temporary checklist but cannot write files or
/// `OpenClaw` configuration, so it carries no authority of its own.
pub const CODEX_PLANNER_TOOL: &str = "update_plan";

/// Longest attacker-chosen fragment echoed back into a refusal.
const MAX_ECHOED_BYTES: usize = 48;

/// Closed set of ring-zero operation names accepted on the wire.
const OPERATIONS: &[&str] = &[
    "config_set",
    "config_set_ref",
    "restart_gateway",
    "status",
    "validate_config",
];

/// Closed set of argument names accepted by the ring-zero tool.
const FIELDS: &[&str] = &["name", "operation", "path", "source", "value"];

/// Privilege class of one backend run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionKind {
    /// The privileged custodian session.
    Crestodian,
    /// An ordinary agent session, which never sees the authority tool.
    NormalAgent,
}

/// How a backend proves which tools one run may call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendToolContract {
    /// Native tool selection is explicit and an empty selection is honoured.
    SelectableNativeTools,
    /// The backend declares no native tools at all.
    NoNativeTools,
    /// Codex app server: one authority tool plus the inert native planner.
    CodexAppServer,
    /// Native tools are always on and cannot be deselected.
    AlwaysOnNativeTools,
    /// The tool-selection contract is unknown to this build.
    UnknownNativeTools,
}

impl BackendToolContract {
    /// Returns the stable operator-facing name of this contract.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SelectableNativeTools => "selectable-native-tools",
            Self::NoNativeTools => "no-native-tools",
            Self::CodexAppServer => "codex-app-server",
            Self::AlwaysOnNativeTools => "always-on-native-tools",
            Self::UnknownNativeTools => "unknown-native-tools",
        }
    }
}

/// Closed set of typed operations the ring-zero tool wraps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrestodianOperation {
    /// Read-only gateway and configuration health.
    Status,
    /// Read-only strict configuration validation.
    ValidateConfig,
    /// One typed configuration mutation.
    Configure(TypedMutation),
    /// Gateway restart.
    RestartGateway,
}

impl CrestodianOperation {
    /// Whether this operation changes durable state.
    #[must_use]
    pub const fn mutating(&self) -> bool {
        matches!(self, Self::Configure(_) | Self::RestartGateway)
    }

    /// Returns the metadata-only audit label, never a mutated value.
    #[must_use]
    pub fn audit_label(&self) -> String {
        match self {
            Self::Status => "status".to_owned(),
            Self::ValidateConfig => "validate_config".to_owned(),
            Self::RestartGateway => "restart_gateway".to_owned(),
            Self::Configure(mutation) => mutation.audit_label(),
        }
    }

    /// Renders the approval proposal shown to the owner.
    #[must_use]
    pub fn proposal(&self) -> String {
        match self {
            Self::Status => "show gateway and config status".to_owned(),
            Self::ValidateConfig => "validate the current configuration".to_owned(),
            Self::RestartGateway => "restart the gateway".to_owned(),
            Self::Configure(mutation) => mutation.proposal(),
        }
    }
}

/// Refusal from the ring-zero authority surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RingZeroDenial {
    /// A normal agent session asked for the custodian tool surface.
    NormalAgentSession,
    /// The backend cannot prove the single-tool restriction.
    BackendCannotRestrictTools {
        /// Contract the backend declared.
        contract: BackendToolContract,
    },
    /// A tool outside the resolved allow-list was invoked.
    ToolNotAllowed {
        /// Sanitized requested tool name.
        requested: String,
    },
    /// An allowed but inert tool was invoked as an authority tool.
    InertTool {
        /// Sanitized requested tool name.
        requested: String,
    },
    /// The payload failed the closed argument schema.
    Arguments(OperationRejection),
}

impl Display for RingZeroDenial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NormalAgentSession => formatter.write_str(
                "the crestodian ring-zero tool is never exposed to a normal agent session",
            ),
            Self::BackendCannotRestrictTools { contract } => write!(
                formatter,
                "backend tool contract {} cannot prove the single-tool ring-zero restriction",
                contract.label()
            ),
            Self::ToolNotAllowed { requested } => write!(
                formatter,
                "tool {requested:?} is outside the ring-zero allow-list"
            ),
            Self::InertTool { requested } => write!(
                formatter,
                "tool {requested:?} carries no OpenClaw authority and cannot run an operation"
            ),
            Self::Arguments(rejection) => Display::fmt(rejection, formatter),
        }
    }
}

impl Error for RingZeroDenial {}

/// Refusal of a ring-zero tool payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationRejection {
    /// The payload is not a JSON object.
    NotAnObject {
        /// Shape actually supplied.
        found: &'static str,
    },
    /// The payload carries a field outside the closed schema.
    UnknownField {
        /// Sanitized rejected field name.
        name: String,
    },
    /// A field required by the operation is missing.
    MissingField {
        /// Missing field name.
        name: &'static str,
    },
    /// A field is not part of the named operation.
    UnexpectedField {
        /// Rejected field name.
        name: &'static str,
        /// Operation that does not accept it.
        operation: &'static str,
    },
    /// A field has the wrong type or shape.
    TypeMismatch {
        /// Field name.
        field: &'static str,
        /// Declared type.
        expected: &'static str,
        /// Shape actually supplied.
        found: &'static str,
    },
    /// The operation name is outside the closed set.
    UnknownOperation {
        /// Sanitized rejected operation name.
        name: String,
    },
    /// The typed mutation surface refused the write.
    Mutation(MutationRejection),
}

impl Display for OperationRejection {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnObject { found } => write!(
                formatter,
                "crestodian tool arguments must be an object, but received {found}"
            ),
            Self::UnknownField { name } => write!(
                formatter,
                "crestodian tool argument {name:?} is outside the closed schema"
            ),
            Self::MissingField { name } => {
                write!(formatter, "crestodian tool argument {name} is required")
            }
            Self::UnexpectedField { name, operation } => write!(
                formatter,
                "crestodian tool argument {name} is not accepted by operation {operation}"
            ),
            Self::TypeMismatch {
                field,
                expected,
                found,
            } => write!(
                formatter,
                "crestodian tool argument {field} expects {expected}, but received {found}"
            ),
            Self::UnknownOperation { name } => write!(
                formatter,
                "crestodian operation {name:?} is outside the closed operation set"
            ),
            Self::Mutation(rejection) => Display::fmt(rejection, formatter),
        }
    }
}

impl Error for OperationRejection {}

/// Static contract of the ring-zero authority tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingZeroToolDescriptor {
    /// Stable tool name.
    pub name: &'static str,
    /// Short human-readable title.
    pub title: &'static str,
    /// Model-facing description of the tool contract.
    pub description: &'static str,
}

/// Returns the static contract of the ring-zero authority tool.
#[must_use]
pub const fn ring_zero_tool_descriptor() -> RingZeroToolDescriptor {
    RingZeroToolDescriptor {
        name: RING_ZERO_TOOL,
        title: "Crestodian",
        description: "Run one typed Crestodian operation. Read-only operations run immediately; \
mutations are staged for the owner's explicit approval.",
    }
}

/// Emits the closed provider-facing JSON Schema of the ring-zero tool.
#[must_use]
pub fn ring_zero_tool_schema() -> Value {
    let paths: Vec<Value> = MutationField::ALL
        .into_iter()
        .map(|field| Value::String(field.path().to_owned()))
        .collect();
    json!({
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": OPERATIONS,
                "description": "Typed Crestodian operation to run.",
            },
            "path": {
                "type": "string",
                "enum": paths,
                "description": "Configuration path for config_set and config_set_ref.",
            },
            "value": {
                "description": "Value for config_set, checked against the declared type of path.",
            },
            "source": {
                "type": "string",
                "enum": ["env"],
                "description": "Secret source for config_set_ref.",
            },
            "name": {
                "type": "string",
                "pattern": "^[A-Za-z_][A-Za-z0-9_]*$",
                "description": "Environment variable name for config_set_ref.",
            },
        },
        "required": ["operation"],
        "additionalProperties": false,
    })
}

/// A ring-zero run, bound to the tools its backend can actually be held to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RingZeroSession {
    allowed: Vec<&'static str>,
}

impl RingZeroSession {
    /// Opens a ring-zero run, failing closed before any inference.
    ///
    /// # Errors
    ///
    /// Returns [`RingZeroDenial::NormalAgentSession`] when an ordinary agent
    /// session asks for the custodian surface, and
    /// [`RingZeroDenial::BackendCannotRestrictTools`] when the backend has
    /// always-on native tools or declares a tool-selection contract this build
    /// does not recognise, because neither can prove the single-tool
    /// restriction.
    pub fn open(
        session: SessionKind,
        backend: BackendToolContract,
    ) -> Result<Self, RingZeroDenial> {
        if session == SessionKind::NormalAgent {
            return Err(RingZeroDenial::NormalAgentSession);
        }
        let allowed = match backend {
            BackendToolContract::SelectableNativeTools | BackendToolContract::NoNativeTools => {
                vec![RING_ZERO_TOOL]
            }
            BackendToolContract::CodexAppServer => vec![CODEX_PLANNER_TOOL, RING_ZERO_TOOL],
            BackendToolContract::AlwaysOnNativeTools | BackendToolContract::UnknownNativeTools => {
                return Err(RingZeroDenial::BackendCannotRestrictTools { contract: backend });
            }
        };
        Ok(Self { allowed })
    }

    /// Returns the exact tool allow-list carried by this run, in stable order.
    #[must_use]
    pub fn allowed_tools(&self) -> &[&'static str] {
        &self.allowed
    }

    /// Validates one tool invocation and returns the typed operation it names.
    ///
    /// # Errors
    ///
    /// Returns [`RingZeroDenial::ToolNotAllowed`] for a tool outside this run's
    /// allow-list, [`RingZeroDenial::InertTool`] when the allowed but
    /// authority-free Codex planner is invoked as an authority tool, and
    /// [`RingZeroDenial::Arguments`] carrying the [`OperationRejection`] when
    /// the payload fails the closed argument schema.
    pub fn invoke(
        &self,
        tool: &str,
        arguments: &Value,
    ) -> Result<CrestodianOperation, RingZeroDenial> {
        if tool != RING_ZERO_TOOL {
            let requested = sanitize(tool);
            return Err(if self.allowed.contains(&tool) {
                RingZeroDenial::InertTool { requested }
            } else {
                RingZeroDenial::ToolNotAllowed { requested }
            });
        }
        parse_operation(arguments).map_err(RingZeroDenial::Arguments)
    }
}

/// Parses a ring-zero payload into a typed operation under a closed schema.
///
/// # Errors
///
/// Returns [`OperationRejection::NotAnObject`] when `arguments` is not a JSON
/// object, [`OperationRejection::UnknownField`] for an argument outside the
/// closed schema, [`OperationRejection::UnknownOperation`] for an operation name
/// outside the closed set, [`OperationRejection::UnexpectedField`] for an
/// argument the named operation does not accept,
/// [`OperationRejection::MissingField`] for a required argument that is absent
/// or null, [`OperationRejection::TypeMismatch`] when a required argument is not
/// a string, and [`OperationRejection::Mutation`] when the typed mutation
/// surface refuses the requested write.
pub fn parse_operation(arguments: &Value) -> Result<CrestodianOperation, OperationRejection> {
    let object = arguments
        .as_object()
        .ok_or_else(|| OperationRejection::NotAnObject {
            found: json_shape(arguments),
        })?;
    for key in object.keys() {
        if !FIELDS.contains(&key.as_str()) {
            return Err(OperationRejection::UnknownField {
                name: sanitize(key),
            });
        }
    }
    let operation = required_text(object, "operation")?;
    if !OPERATIONS.contains(&operation) {
        return Err(OperationRejection::UnknownOperation {
            name: sanitize(operation),
        });
    }
    let accepted: &[&str] = match operation {
        "config_set" => &["operation", "path", "value"],
        "config_set_ref" => &["name", "operation", "path", "source"],
        _ => &["operation"],
    };
    for field in FIELDS {
        if object.contains_key(*field) && !accepted.contains(field) {
            return Err(OperationRejection::UnexpectedField {
                name: field,
                operation: stable_operation(operation),
            });
        }
    }
    match operation {
        "status" => Ok(CrestodianOperation::Status),
        "validate_config" => Ok(CrestodianOperation::ValidateConfig),
        "restart_gateway" => Ok(CrestodianOperation::RestartGateway),
        "config_set" => {
            let path = required_text(object, "path")?;
            let value = object
                .get("value")
                .filter(|value| !value.is_null())
                .ok_or(OperationRejection::MissingField { name: "value" })?;
            TypedMutation::set_json(path, value)
                .map(CrestodianOperation::Configure)
                .map_err(OperationRejection::Mutation)
        }
        _ => {
            let path = required_text(object, "path")?;
            let source = required_text(object, "source")?;
            let name = required_text(object, "name")?;
            TypedMutation::set_reference(path, source, name)
                .map(CrestodianOperation::Configure)
                .map_err(OperationRejection::Mutation)
        }
    }
}

fn required_text<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, OperationRejection> {
    let value = object
        .get(field)
        .filter(|value| !value.is_null())
        .ok_or(OperationRejection::MissingField { name: field })?;
    value
        .as_str()
        .ok_or_else(|| OperationRejection::TypeMismatch {
            field,
            expected: "string",
            found: json_shape(value),
        })
}

/// Maps a validated operation name onto its `'static` spelling.
fn stable_operation(operation: &str) -> &'static str {
    OPERATIONS
        .iter()
        .copied()
        .find(|candidate| *candidate == operation)
        .unwrap_or("unknown")
}

const fn json_shape(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn sanitize(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.' | '$')
        })
        .take(MAX_ECHOED_BYTES)
        .collect();
    if sanitized.is_empty() {
        "<unprintable>".to_owned()
    } else {
        sanitized
    }
}
