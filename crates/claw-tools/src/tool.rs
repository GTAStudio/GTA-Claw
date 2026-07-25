//! The tool trait, descriptors, structured results, and invocation context.

use serde::Serialize;
use serde_json::{Value, json};

use crate::error::ToolError;
use crate::permission::{Authorization, PermissionDescriptor, Resource};
use crate::sandbox::Sandbox;
use crate::schema::{Arguments, ParameterSchema};

/// Static identity, contract, and permission metadata of one tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolDescriptor {
    /// Stable tool name used by providers and audit records.
    pub name: &'static str,
    /// Short human-readable title.
    pub title: &'static str,
    /// Model-facing description of the tool contract.
    pub description: &'static str,
    /// Closed parameter schema.
    pub schema: ParameterSchema,
    /// Capability, risk, and approval requirements.
    pub permission: PermissionDescriptor,
}

impl ToolDescriptor {
    /// Emits the provider tool-calling declaration for this tool.
    #[must_use]
    pub fn to_provider_json(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.schema.to_json_schema(),
            },
        })
    }

    /// Emits the operator-facing catalog entry including its permission model.
    #[must_use]
    pub fn to_catalog_json(&self) -> Value {
        json!({
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "parameters": self.schema.to_json_schema(),
            "permission": {
                "capability": self.permission.capability.as_str(),
                "risk": self.permission.risk,
                "requires_approval": self.permission.requires_approval,
                "gateway_scope": self.permission.gateway_scope,
            },
        })
    }
}

/// Structured result of one successful invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ToolOutput {
    /// Model-facing rendering of the result.
    pub content: String,
    /// Machine-readable result payload.
    pub structured: Value,
    /// Whether a declared limit truncated the result.
    pub truncated: bool,
}

impl ToolOutput {
    /// Builds an untruncated result.
    #[must_use]
    pub fn new(content: impl Into<String>, structured: Value) -> Self {
        Self {
            content: content.into(),
            structured,
            truncated: false,
        }
    }

    /// Marks the result as truncated by a declared limit.
    #[must_use]
    pub const fn truncated(mut self, truncated: bool) -> Self {
        self.truncated = truncated;
        self
    }
}

/// Ambient state shared by every tool in one invocation.
#[derive(Clone, Copy, Debug)]
pub struct ToolContext<'a> {
    /// Workspace confinement root.
    pub sandbox: &'a Sandbox,
    /// Caller-supplied wall-clock instant used for grants and audit records.
    pub unix_millis: u64,
}

/// One agent-callable capability.
///
/// Implementations must treat every argument as hostile. They cannot run
/// without an [`Authorization`], which only the registry can mint after a
/// permission broker granted the request.
pub trait Tool {
    /// Returns the static contract of this tool.
    fn descriptor(&self) -> ToolDescriptor;

    /// Derives the concrete resource the invocation would touch.
    ///
    /// This must be a pure function of the validated arguments so that the
    /// authorized resource and the used resource cannot diverge.
    fn resource(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
    ) -> Result<Resource, ToolError>;

    /// Executes the tool against already-validated, already-authorized input.
    fn invoke(
        &self,
        arguments: &Arguments,
        context: &ToolContext<'_>,
        authorization: &Authorization<'_>,
    ) -> Result<ToolOutput, ToolError>;
}
