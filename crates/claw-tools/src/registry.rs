//! The invocation choke point: validate, authorize, audit, execute, audit.
//!
//! Every path into a tool goes through [`ToolRegistry::invoke`]. There is no
//! other way to obtain the [`crate::permission::Authorization`] a tool needs,
//! so an unauthorized invocation cannot reach an implementation.

use std::cell::RefCell;
use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::audit::{
    AuditOutcome, AuditPhase, AuditReason, ToolAuditRecord, ToolAuditSink, opaque_arguments,
};
use crate::clock::Clock;
use crate::error::ToolError;
use crate::permission::{
    Authorization, Capability, DenialReason, GrantId, PermissionBroker, PermissionDecision,
    PermissionError, PermissionRequest, Resource, ResourceGate,
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
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::DuplicateTool`] when a tool with the same
    /// descriptor name is already registered. Registration is all-or-nothing:
    /// the registry is unchanged when this fails.
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
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::UnknownTool`] when `name` is not registered,
    /// [`ToolError::Schema`] when `arguments` fail the tool's declared schema
    /// (missing required field, wrong type, value out of bounds),
    /// [`ToolError::Permission`] when the broker denies the capability or the
    /// grant has expired, whatever the tool itself returns (for example
    /// [`ToolError::Sandbox`] for a path outside the workspace root or a file
    /// over the read limit), and [`ToolError::Audit`] when the refusal or
    /// completion record could not be durably persisted — an invocation whose
    /// audit trail cannot be written is reported as failed even when the tool
    /// succeeded.
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
        let now = context.unix_millis();
        let Some(tool) = self.tools.get(name) else {
            // An unregistered name has no schema to project through, so the
            // payload contributes nothing but its shape to the record.
            let record = ToolAuditRecord {
                tool: sanitize_tool_name(name),
                phase: AuditPhase::Completed,
                capability: None,
                resource: None,
                grant: None,
                outcome: AuditOutcome::Denied,
                reason: AuditReason::UnknownTool,
                denial: None,
                arguments: opaque_arguments(arguments),
                unix_millis: now,
            };
            audit.persist(&record)?;
            return Err(ToolError::UnknownTool);
        };
        let descriptor = tool.descriptor();
        let capability = descriptor.permission.capability;
        // Schema-aware projection, not heuristic redaction: a parameter reaches
        // the audit log only when its schema classified it as safe to record.
        let redacted = descriptor.schema.project_audit(arguments);

        let validated = match descriptor.schema.validate(arguments) {
            Ok(validated) => validated,
            Err(error) => {
                audit_refusal(
                    audit,
                    &descriptor,
                    None,
                    AuditReason::ValidationRejected,
                    None,
                    redacted,
                    now,
                )?;
                return Err(ToolError::Schema(error));
            }
        };

        let resource = match tool.resource(&validated, context) {
            Ok(resource) => resource,
            Err(error) => {
                let reason = error.audit_reason();
                audit_refusal(audit, &descriptor, None, reason, None, redacted, now)?;
                return Err(error);
            }
        };

        let request = PermissionRequest {
            tool: descriptor.name,
            capability,
            resource: resource.clone(),
            requires_approval: descriptor.permission.requires_approval,
            unix_millis: now,
        };
        let grant = match broker.evaluate(&request) {
            PermissionDecision::Granted(grant) => grant,
            PermissionDecision::Denied(reason) => {
                audit_refusal(
                    audit,
                    &descriptor,
                    Some(resource),
                    AuditReason::PolicyRejected,
                    Some(reason),
                    redacted,
                    now,
                )?;
                return Err(ToolError::Permission(PermissionError {
                    tool: descriptor.name,
                    capability,
                    reason,
                }));
            }
        };

        let authorization_record = ToolAuditRecord {
            tool: descriptor.name.to_owned(),
            phase: AuditPhase::Authorized,
            capability: Some(capability),
            resource: Some(resource.clone()),
            grant: Some(grant),
            outcome: AuditOutcome::Allowed,
            reason: AuditReason::PolicySatisfied,
            denial: None,
            arguments: redacted.clone(),
            unix_millis: now,
        };
        // The authorization record is committed before any side effect so a
        // crash during execution still leaves the decision on record.
        audit.persist(&authorization_record)?;

        // The broker and the audit sink are lent to the gate for exactly the
        // duration of the call, so a tool that reaches a second resource has to
        // ask the same broker again instead of riding the first decision.
        let result = {
            let gate = BrokerGate {
                broker: RefCell::new(&mut *broker),
                audit: RefCell::new(&mut *audit),
                tool: descriptor.name,
                capability,
                requires_approval: descriptor.permission.requires_approval,
                clock: context.clock,
                arguments: redacted.clone(),
            };
            let authorization = Authorization::new(grant, capability, &gate);
            tool.invoke(&validated, context, &authorization)
        };
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
            unix_millis: now,
        })?;
        result
    }
}

/// Records one terminal refusal before the error leaves the registry.
///
/// Free rather than a method: it needs nothing from the registry, and keeping
/// it out of the impl also keeps it inside the seven-argument budget.
fn audit_refusal<S: ToolAuditSink>(
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

/// Re-authorization gate handed to a tool for the duration of one invocation.
///
/// It re-asks the same broker that authorized the invocation, against the time
/// read at that moment rather than the time the invocation began, and durably
/// records every answer. A tool that widens its resource set mid-flight is
/// therefore re-checked, re-timed, and accounted for.
struct BrokerGate<'a, B: PermissionBroker, S: ToolAuditSink> {
    broker: RefCell<&'a mut B>,
    audit: RefCell<&'a mut S>,
    tool: &'static str,
    capability: Capability,
    requires_approval: bool,
    clock: &'a dyn Clock,
    arguments: Value,
}

impl<B: PermissionBroker, S: ToolAuditSink> BrokerGate<'_, B, S> {
    const fn refusal(&self, reason: DenialReason) -> PermissionError {
        PermissionError {
            tool: self.tool,
            capability: self.capability,
            reason,
        }
    }
}

impl<B: PermissionBroker, S: ToolAuditSink> ResourceGate for BrokerGate<'_, B, S> {
    fn authorize(&self, resource: &Resource) -> Result<GrantId, PermissionError> {
        // Fresh time, read now: a grant that expired while the invocation was
        // in flight must be refused at the moment the next resource is reached.
        let unix_millis = self.clock.unix_millis();
        let request = PermissionRequest {
            tool: self.tool,
            capability: self.capability,
            resource: resource.clone(),
            requires_approval: self.requires_approval,
            unix_millis,
        };
        let decision = self.broker.borrow_mut().evaluate(&request);
        let (grant, outcome, reason, denial) = match decision {
            PermissionDecision::Granted(grant) => (
                Some(grant),
                AuditOutcome::Allowed,
                AuditReason::PolicySatisfied,
                None,
            ),
            PermissionDecision::Denied(denial) => (
                None,
                AuditOutcome::Denied,
                AuditReason::PolicyRejected,
                Some(denial),
            ),
        };
        let record = ToolAuditRecord {
            tool: self.tool.to_owned(),
            phase: AuditPhase::Authorized,
            capability: Some(self.capability),
            resource: Some(resource.clone()),
            grant,
            outcome,
            reason,
            denial,
            arguments: self.arguments.clone(),
            unix_millis,
        };
        // An unrecorded authorization is treated as no authorization.
        if self.audit.borrow_mut().persist(&record).is_err() {
            return Err(self.refusal(DenialReason::AuditUnavailable));
        }
        match decision {
            PermissionDecision::Granted(grant) => Ok(grant),
            PermissionDecision::Denied(denial) => Err(self.refusal(denial)),
        }
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
