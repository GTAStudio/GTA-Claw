//! The invocation choke point: validate, authorize, audit, execute, audit.
//!
//! Every path into a tool goes through [`ToolRegistry::invoke`]. There is no
//! other way to obtain the [`crate::permission::Authorization`] a tool needs,
//! so an unauthorized invocation cannot reach an implementation.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::audit::{AuditOutcome, AuditPhase, AuditReason, ToolAuditRecord, ToolAuditSink, redact};
use crate::error::ToolError;
use crate::permission::{
    Authorization, Capability, DenialReason, PermissionBroker, PermissionDecision, PermissionError,
    PermissionRequest, Resource,
};
use crate::tool::{Tool, ToolContext, ToolDescriptor, ToolOutput};

/// Registry of every tool exposed to a model.
#[derive(Default)]
pub struct ToolRegistry {
    tools: BTreeMap<&'static str, Box<dyn Tool>>,
}

impl ToolRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one tool, refusing duplicate names.
    pub fn register(&mut self, tool: Box<dyn Tool>) -> Result<(), ToolError> {
        let name = tool.descriptor().name;
        if self.tools.contains_key(name) {
            return Err(ToolError::DuplicateTool);
        }
        self.tools.insert(name, tool);
        Ok(())
    }

    /// Returns every descriptor in stable name order.
    #[must_use]
    pub fn descriptors(&self) -> Vec<ToolDescriptor> {
        self.tools.values().map(|tool| tool.descriptor()).collect()
    }

    /// Returns the registered tool names in stable order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.tools.keys().copied().collect()
    }

    /// Emits the provider tool-calling declarations for every tool.
    #[must_use]
    pub fn provider_catalog(&self) -> Value {
        Value::Array(
            self.tools
                .values()
                .map(|tool| tool.descriptor().to_provider_json())
                .collect(),
        )
    }

    /// Emits the operator-facing catalog including the permission model.
    #[must_use]
    pub fn catalog(&self) -> Value {
        json!({
            "tools": Value::Array(
                self.tools
                    .values()
                    .map(|tool| tool.descriptor().to_catalog_json())
                    .collect(),
            ),
        })
    }

    /// Validates, authorizes, audits, and runs exactly one tool invocation.
    ///
    /// Failure at any gate is terminal: no partial execution occurs, and the
    /// refusal is durably audited before the error is returned.
    pub fn invoke<B, S>(
        &self,
        name: &str,
        arguments: &Value,
        context: &ToolContext<'_>,
        broker: &mut B,
        audit: &mut S,
    ) -> Result<ToolOutput, ToolError>
    where
        B: PermissionBroker,
        S: ToolAuditSink,
    {
        let redacted = redact(arguments);
        let Some(tool) = self.tools.get(name) else {
            let record = ToolAuditRecord {
                tool: sanitize_tool_name(name),
                phase: AuditPhase::Completed,
                capability: None,
                resource: None,
                grant: None,
                outcome: AuditOutcome::Denied,
                reason: AuditReason::UnknownTool,
                denial: None,
                arguments: redacted,
                unix_millis: context.unix_millis,
            };
            audit.persist(&record)?;
            return Err(ToolError::UnknownTool);
        };
        let descriptor = tool.descriptor();
        let capability = descriptor.permission.capability;

        let validated = match descriptor.schema.validate(arguments) {
            Ok(validated) => validated,
            Err(error) => {
                self.audit_refusal(
                    audit,
                    &descriptor,
                    None,
                    AuditReason::ValidationRejected,
                    None,
                    redacted,
                    context.unix_millis,
                )?;
                return Err(ToolError::Schema(error));
            }
        };

        let resource = match tool.resource(&validated, context) {
            Ok(resource) => resource,
            Err(error) => {
                let reason = error.audit_reason();
                self.audit_refusal(
                    audit,
                    &descriptor,
                    None,
                    reason,
                    None,
                    redacted,
                    context.unix_millis,
                )?;
                return Err(error);
            }
        };

        let request = PermissionRequest {
            tool: descriptor.name,
            capability,
            resource: resource.clone(),
            requires_approval: descriptor.permission.requires_approval,
            unix_millis: context.unix_millis,
        };
        let grant = match broker.evaluate(&request) {
            PermissionDecision::Granted(grant) => grant,
            PermissionDecision::Denied(reason) => {
                self.audit_refusal(
                    audit,
                    &descriptor,
                    Some(resource),
                    AuditReason::PolicyRejected,
                    Some(reason),
                    redacted,
                    context.unix_millis,
                )?;
                return Err(ToolError::Permission(PermissionError {
                    tool: descriptor.name,
                    capability,
                    reason,
                }));
            }
        };

        // The authorization record is committed before any side effect so a
        // crash during execution still leaves the decision on record.
        audit.persist(&ToolAuditRecord {
            tool: descriptor.name.to_owned(),
            phase: AuditPhase::Authorized,
            capability: Some(capability),
            resource: Some(resource.clone()),
            grant: Some(grant),
            outcome: AuditOutcome::Allowed,
            reason: AuditReason::PolicySatisfied,
            denial: None,
            arguments: redacted.clone(),
            unix_millis: context.unix_millis,
        })?;

        let authorization = Authorization::new(grant, capability);
        let result = tool.invoke(&validated, context, &authorization);
        let (outcome, reason) = match &result {
            Ok(_) => (AuditOutcome::Allowed, AuditReason::PolicySatisfied),
            Err(error) => (AuditOutcome::Failed, error.audit_reason()),
        };
        audit.persist(&ToolAuditRecord {
            tool: descriptor.name.to_owned(),
            phase: AuditPhase::Completed,
            capability: Some(capability),
            resource: Some(resource),
            grant: Some(grant),
            outcome,
            reason,
            denial: None,
            arguments: redacted,
            unix_millis: context.unix_millis,
        })?;
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn audit_refusal<S: ToolAuditSink>(
        &self,
        audit: &mut S,
        descriptor: &ToolDescriptor,
        resource: Option<Resource>,
        reason: AuditReason,
        denial: Option<DenialReason>,
        arguments: Value,
        unix_millis: u64,
    ) -> Result<(), ToolError> {
        let record = ToolAuditRecord {
            tool: descriptor.name.to_owned(),
            phase: AuditPhase::Completed,
            capability: Some(descriptor.permission.capability),
            resource,
            grant: None,
            outcome: AuditOutcome::Denied,
            reason,
            denial,
            arguments,
            unix_millis,
        };
        audit.persist(&record).map_err(ToolError::Audit)
    }
}

/// Keeps an unregistered, attacker-chosen name out of the audit log verbatim.
fn sanitize_tool_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '.'))
        .take(64)
        .collect();
    if sanitized.is_empty() {
        "<unprintable>".to_owned()
    } else {
        sanitized
    }
}

/// Returns the capability every registered tool declares, for policy review.
#[must_use]
pub fn declared_capabilities(registry: &ToolRegistry) -> BTreeMap<&'static str, Capability> {
    registry
        .descriptors()
        .into_iter()
        .map(|descriptor| (descriptor.name, descriptor.permission.capability))
        .collect()
}
