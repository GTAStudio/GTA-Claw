use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use claw_application::ports::PortError;
use claw_application::ports::tool::{
    InternalToolAuditPhase, InvocationAuthority, ToolBinding, ToolInvocation, ToolOutcome,
    ToolStatus,
};
use claw_http_api::{ToolDefinition, ToolInvocationContext, ToolPort};
use claw_skills::{
    PreparedSkillInvocation, SkillExecution, SkillManifest, prepare_skill_invocation,
};
use futures_util::FutureExt as _;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::http_api::{DurableSecurityAudit, ModelToolCatalog};
use super::native_tools::WorkspaceTools;
use super::signed_plugins::PluginToolSurface;

const POLICY_BYTES: usize = 64 * 1024;
const MANIFEST_BYTES: usize = 16 * 1024;
const MAX_SKILLS: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SkillPolicy {
    schema_version: u32,
    skills: Vec<Value>,
}

struct PublishedSkill {
    manifest: SkillManifest,
    digest: String,
    validator: Arc<jsonschema::Validator>,
}

pub(super) struct PreparedCall {
    pub(super) invocation: ToolInvocation,
    pub(super) target_binding: ToolBinding,
    pub(super) approval_binding: ToolBinding,
    pub(super) http_response: Option<claw_skills::HttpResponseMode>,
    instructions: Option<String>,
}

pub(crate) struct NativeSkills {
    entries: BTreeMap<String, PublishedSkill>,
    workspace: Option<Arc<WorkspaceTools>>,
    plugins: Arc<PluginToolSurface>,
    tasks: TaskTracker,
    slots: Arc<tokio::sync::Semaphore>,
    accepting: Mutex<bool>,
}

struct SkillCancellation(CancellationToken);

impl Drop for SkillCancellation {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

fn digest(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    Sha256::digest(value)
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .map(char::from)
        .collect()
}

fn public_name(id: &str) -> String {
    let prefix: String = id
        .bytes()
        .take(24)
        .map(|byte| if byte == b'.' { '_' } else { char::from(byte) })
        .collect();
    format!("skill_{prefix}_{}", &digest(id.as_bytes())[..24])
}

fn parse_policy(encoded: &str) -> Result<BTreeMap<String, PublishedSkill>, String> {
    if encoded.len() > POLICY_BYTES {
        return Err("native skill policy exceeds its byte limit".to_owned());
    }
    let document = claw_memory::json::from_json_value_reader(encoded.as_bytes(), POLICY_BYTES)
        .map_err(|_| "native skill policy exceeds structural limits or is ambiguous".to_owned())?;
    let policy: SkillPolicy = serde_json::from_value(document)
        .map_err(|_| "native skill policy must match its closed schema".to_owned())?;
    if policy.schema_version != 1 || policy.skills.len() > MAX_SKILLS {
        return Err("native skill policy version or entry count is unsupported".to_owned());
    }
    let mut entries = BTreeMap::new();
    let mut identifiers = BTreeSet::new();
    for value in policy.skills {
        let encoded = serde_json::to_string(&value)
            .map_err(|_| "native skill manifest cannot be encoded".to_owned())?;
        if encoded.len() > MANIFEST_BYTES {
            return Err("native skill manifest exceeds its byte limit".to_owned());
        }
        let manifest = claw_skills::load_manifest(&encoded)
            .map_err(|_| "native skill manifest is invalid".to_owned())?;
        if manifest.description().len() > 2048
            || manifest.description().chars().any(char::is_control)
            || manifest.parameters().get("type").and_then(Value::as_str) != Some("object")
            || !identifiers.insert(manifest.id().to_owned())
        {
            return Err(
                "native skill identity, description or root parameter schema is invalid".to_owned(),
            );
        }
        if let SkillExecution::Http { request } = manifest.execution() {
            let endpoint = url::Url::parse(&request.url)
                .map_err(|_| "declarative HTTP skill endpoint is invalid".to_owned())?;
            if request.method != claw_skills::HttpMethod::Get
                || !request.headers.is_empty()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
            {
                return Err("HTTP skills require GET with query-encoded parameters and no static query, fragment or custom headers".to_owned());
            }
        }
        let name = public_name(manifest.id());
        let validator = jsonschema::options().offline().with_pattern_options(
            jsonschema::PatternOptions::regex().size_limit(256 * 1024).dfa_size_limit(512 * 1024)
        ).build(manifest.parameters()).map_err(|_| "skill parameter schema requires invalid or unsupported external resources or patterns".to_owned())?;
        if entries
            .insert(
                name,
                PublishedSkill {
                    manifest,
                    digest: digest(encoded.as_bytes()),
                    validator: Arc::new(validator),
                },
            )
            .is_some()
        {
            return Err("native skill publication names conflict".to_owned());
        }
    }
    Ok(entries)
}

fn skill_binding(
    skill: &PublishedSkill,
    target_name: &str,
    target: &ToolBinding,
    arguments: &str,
) -> Result<ToolBinding, PortError> {
    let identity = serde_json::to_vec(&(
        &skill.digest,
        target_name,
        target.identity(),
        target.revision(),
        target.resource(),
        digest(arguments.as_bytes()),
    ))
    .map_err(|_| PortError::Invalid("skill binding cannot be encoded".to_owned()))?;
    ToolBinding::new(&format!("skill-{}", digest(&identity)), target.revision())?.with_resource(
        format!(
            "skill={}; manifestSha256={}; target={target_name}; publication={}; revision={}; {}",
            skill.manifest.id(),
            skill.digest,
            target.identity(),
            target.revision(),
            target.resource().unwrap_or("no additional target resource"),
        ),
    )
}

impl NativeSkills {
    pub(crate) fn from_environment(
        workspace: Option<Arc<WorkspaceTools>>,
        plugins: Arc<PluginToolSurface>,
    ) -> Result<Arc<Self>, String> {
        let entries = match std::env::var("GTA_CLAW_SKILL_POLICY") {
            Ok(encoded) => parse_policy(&encoded)?,
            Err(std::env::VarError::NotPresent) => BTreeMap::new(),
            Err(_) => return Err("native skill policy must be UTF-8".to_owned()),
        };
        let skills = Arc::new(Self {
            entries,
            workspace,
            plugins,
            tasks: TaskTracker::new(),
            slots: Arc::new(tokio::sync::Semaphore::new(4)),
            accepting: Mutex::new(true),
        });
        let plugin_names: BTreeSet<String> = skills
            .plugins
            .definitions()
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        if skills
            .entries
            .iter()
            .any(|(name, skill)| !skills.available(skill) || plugin_names.contains(name))
        {
            return Err(
                "native skill target is not an explicitly configured and published tool".to_owned(),
            );
        }
        Ok(skills)
    }

    fn available(&self, skill: &PublishedSkill) -> bool {
        if !self.accepting.lock().is_ok_and(|accepting| *accepting) {
            return false;
        }
        if !matches!(
            self.plugins.resolve(&public_name(skill.manifest.id())),
            Err(error) if error.kind == claw_http_api::PortErrorKind::NotFound
        ) {
            return false;
        }
        match skill.manifest.execution() {
            SkillExecution::Instructions { .. } => true,
            SkillExecution::Native { handler } => self
                .workspace
                .as_ref()
                .is_some_and(|workspace| workspace.contains(handler)),
            SkillExecution::Wasm { plugin_id, export } => {
                self.plugins.skill_target(plugin_id, export).is_ok()
            }
            SkillExecution::Http { request } => self
                .workspace
                .as_ref()
                .is_some_and(|workspace| workspace.network_resource(&request.url).is_ok()),
        }
    }

    pub(super) fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    pub(crate) fn definitions(&self) -> Vec<ToolDefinition> {
        self.entries
            .iter()
            .filter(|(_, skill)| self.available(skill))
            .map(|(name, skill)| ToolDefinition {
                name: name.clone(),
                description: Some(format!(
                    "Skill {}: {}",
                    skill.manifest.id(),
                    skill.manifest.description()
                )),
                input_schema: skill.manifest.parameters().clone(),
            })
            .collect()
    }

    pub(crate) fn summary(&self) -> Value {
        let entries: Vec<Value> = self.entries.iter().map(|(name, skill)| {
            let active = self.available(skill);
            let instructions = matches!(skill.manifest.execution(), SkillExecution::Instructions { .. });
            json!({"id":skill.manifest.id(),"name":name,"manifestSha256":skill.digest,"active":active,"executable":active && !instructions,"instructionOnly":instructions,"requiresApproval":true})
        }).collect();
        let active = entries.iter().filter(|entry| entry["active"] == true).count();
        let executable = entries.iter().filter(|entry| entry["executable"] == true).count();
        let instructions = active.saturating_sub(executable);
        json!({
            "configured": self.entries.len(),
            "validated": self.entries.len(),
            "active": active,
            "executable": executable,
            "instructions": instructions,
            "policyMutableAtRuntime": false,
            "httpSupported": self.workspace.as_ref().is_some_and(|workspace| workspace.contains("net_fetch")),
            "httpMode": "fixed-address-get",
            "entries": entries,
        })
    }

    pub(super) fn mutates(&self, name: &str) -> bool {
        self.entries
            .get(name)
            .is_none_or(|skill| match skill.manifest.execution() {
                SkillExecution::Instructions { .. } => false,
                SkillExecution::Native { handler } => WorkspaceTools::mutates(handler),
                SkillExecution::Wasm { .. } | SkillExecution::Http { .. } => true,
            })
    }

    pub(super) fn prepare(
        &self,
        invocation: &ToolInvocation,
        authority: &InvocationAuthority,
    ) -> Result<PreparedCall, PortError> {
        if !authority.can_execute() || invocation.call.arguments.len() > MANIFEST_BYTES {
            return Err(PortError::Invalid(
                "skill authority or argument bound is invalid".to_owned(),
            ));
        }
        let skill = self
            .entries
            .get(&invocation.call.name)
            .ok_or_else(|| PortError::NotFound("skill is not configured".to_owned()))?;
        match self.plugins.resolve(&invocation.call.name) {
            Err(error) if error.kind == claw_http_api::PortErrorKind::NotFound => {}
            Ok(_) => {
                return Err(PortError::Invalid(
                    "skill name conflicts with a plugin publication".to_owned(),
                ));
            }
            Err(_) => {
                return Err(PortError::Unavailable(
                    "skill target catalog could not be checked".to_owned(),
                ));
            }
        }
        let parameters = claw_memory::json::from_json_value_reader(
            invocation.call.arguments.as_bytes(),
            MANIFEST_BYTES,
        )
        .map_err(|_| PortError::Invalid("skill parameters must be unambiguous JSON".to_owned()))?;
        if !skill.validator.is_valid(&parameters) {
            return Err(PortError::Invalid(
                "skill parameters violate the published schema".to_owned(),
            ));
        }
        let prepared = prepare_skill_invocation(&skill.manifest, parameters).map_err(|_| {
            PortError::Invalid("skill parameters do not satisfy its manifest".to_owned())
        })?;
        let mut target = invocation.clone();
        let mut http_response = None;
        let mut instructions = None;
        let target_binding = match prepared {
            PreparedSkillInvocation::Instructions { content } => {
                if !authority.is_owner() {
                    return Err(PortError::Invalid("configured instruction content requires an owner".to_owned()));
                }
                "instruction_content".clone_into(&mut target.call.name);
                instructions = Some(content);
                ToolBinding::new(&format!("instruction-{}", skill.digest), 1)?
                    .with_resource("Owner-only instruction data; no execution permission is granted".to_owned())?
            }
            PreparedSkillInvocation::Native {
                handler,
                parameters,
            } => {
                target.call.name = handler;
                target.call.arguments = parameters.to_string();
                self.workspace
                    .as_ref()
                    .ok_or_else(|| {
                        PortError::Invalid("native workspace policy is not configured".to_owned())
                    })?
                    .binding(&target, authority)?
            }
            PreparedSkillInvocation::Wasm {
                plugin_id,
                export,
                parameters,
            } => {
                target.call.name =
                    self.plugins
                        .skill_target(&plugin_id, &export)
                        .map_err(|_| {
                            PortError::NotFound("skill plugin target is not published".to_owned())
                        })?;
                target.call.arguments = parameters.to_string();
                self.plugins
                    .validate_arguments(&target.call.name, &parameters)
                    .map_err(|_| {
                        PortError::Invalid(
                            "skill arguments or plugin publication are invalid".to_owned(),
                        )
                    })?
            }
            PreparedSkillInvocation::Http { request, response } => {
                if request.method != claw_skills::HttpMethod::Get
                    || !request.headers.is_empty()
                    || !request.body.is_empty()
                {
                    return Err(PortError::Invalid(
                        "HTTP skill request is outside the approved GET contract".to_owned(),
                    ));
                }
                "net_fetch".clone_into(&mut target.call.name);
                target.call.arguments = json!({"url":request.url,"method":"GET"}).to_string();
                http_response = Some(response);
                self.workspace
                    .as_ref()
                    .ok_or_else(|| {
                        PortError::Invalid("HTTP skill network policy is absent".to_owned())
                    })?
                    .binding(&target, authority)?
            }
        };
        let mut approval_binding = skill_binding(
            skill,
            &target.call.name,
            &target_binding,
            &target.call.arguments,
        )?;
        if let SkillExecution::Http { request } = skill.manifest.execution() {
            let resource = format!(
                "{}; GET {}; parameters={:?}; response={:?}",
                approval_binding.resource().unwrap_or(""),
                request.url,
                request.parameters,
                request.response
            );
            approval_binding = approval_binding.with_resource(resource)?;
        }
        Ok(PreparedCall {
            invocation: target,
            target_binding,
            approval_binding,
            http_response,
            instructions,
        })
    }

    fn decode_output(
        mut outcome: ToolOutcome,
        response: Option<claw_skills::HttpResponseMode>,
    ) -> Result<ToolOutcome, PortError> {
        let Some(response) = response else {
            return Ok(outcome);
        };
        if outcome.status != ToolStatus::Ok {
            return Ok(outcome);
        }
        let output: Value = serde_json::from_str(&outcome.output).map_err(|_| {
            PortError::OutcomeUnknown("HTTP skill returned an invalid result envelope".to_owned())
        })?;
        if output["truncated"] != false {
            return Err(PortError::OutcomeUnknown(
                "HTTP skill response was not complete".to_owned(),
            ));
        }
        let status = output["structured"]["status"]
            .as_u64()
            .and_then(|status| u16::try_from(status).ok())
            .ok_or_else(|| {
                PortError::OutcomeUnknown("HTTP skill response has no confirmed status".to_owned())
            })?;
        let body = output["structured"]["body"]
            .as_str()
            .ok_or_else(|| {
                PortError::OutcomeUnknown(
                    "HTTP skill response has no complete text body".to_owned(),
                )
            })?
            .as_bytes()
            .to_vec();
        let decoded = claw_skills::decode_http_response(claw_skills::HttpResponse { status, body }, response).map_err(|_| PortError::OutcomeUnknown("HTTP skill response failed its declared status or representation; do not automatically repeat the request".to_owned()))?;
        outcome.output = serde_json::to_string(&decoded).map_err(|_| {
            PortError::OutcomeUnknown("HTTP skill response could not be encoded".to_owned())
        })?;
        Ok(outcome)
    }

    pub(super) async fn invoke(
        self: &Arc<Self>,
        invocation: ToolInvocation,
        authority: InvocationAuthority,
        binding: ToolBinding,
        cancellation: CancellationToken,
        audit: Arc<DurableSecurityAudit>,
    ) -> Result<ToolOutcome, PortError> {
        if cancellation.is_cancelled()
            || self.prepare(&invocation, &authority)?.approval_binding != binding
        {
            return Err(PortError::Invalid(
                "skill was cancelled or its approved target changed".to_owned(),
            ));
        }
        let _cancellation = SkillCancellation(cancellation.clone());
        let task = {
            let accepting = self
                .accepting
                .lock()
                .map_err(|_| PortError::Unavailable("skill admission gate failed".to_owned()))?;
            if !*accepting {
                return Err(PortError::Unavailable(
                    "skill execution is closed".to_owned(),
                ));
            }
            let slot = Arc::clone(&self.slots).try_acquire_owned().map_err(|_| {
                PortError::Unavailable("skill invocation capacity exceeded".to_owned())
            })?;
            let skills = Arc::clone(self);
            let task = self.tasks.spawn(async move {
                let _slot = slot;
                skills
                    .invoke_owned(invocation, authority, binding, cancellation, audit)
                    .await
            });
            drop(accepting);
            task
        };
        task.await.map_err(|_| {
            PortError::OutcomeUnknown(
                "skill task did not confirm its result; reconcile before repeating".to_owned(),
            )
        })?
    }

    async fn invoke_owned(
        &self,
        invocation: ToolInvocation,
        authority: InvocationAuthority,
        binding: ToolBinding,
        cancellation: CancellationToken,
        audit: Arc<DurableSecurityAudit>,
    ) -> Result<ToolOutcome, PortError> {
        let prepared = self.prepare(&invocation, &authority)?;
        if cancellation.is_cancelled() || prepared.approval_binding != binding {
            return Err(PortError::Invalid(
                "skill authority or publication changed before execution".to_owned(),
            ));
        }
        let target = prepared.invocation.call.name.clone();
        audit
            .persist_skill_tool(
                &invocation,
                &authority,
                &binding,
                &target,
                InternalToolAuditPhase::Authorized,
            )
            .map_err(|_| {
                PortError::Unavailable(
                    "skill authorization audit could not be persisted".to_owned(),
                )
            })?;
        let result = std::panic::AssertUnwindSafe(self.invoke_target(
            prepared,
            authority.clone(),
            cancellation,
        ))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| {
            Err(PortError::OutcomeUnknown(
                "skill target failed without a confirmed outcome".to_owned(),
            ))
        });
        let phase = if result
            .as_ref()
            .is_ok_and(|outcome| outcome.status == ToolStatus::Ok)
        {
            InternalToolAuditPhase::Completed
        } else {
            InternalToolAuditPhase::Failed
        };
        audit
            .persist_skill_tool(&invocation, &authority, &binding, &target, phase)
            .map_err(|_| {
                PortError::OutcomeUnknown(
                    "skill completion audit was not confirmed; reconcile effects before retrying"
                        .to_owned(),
                )
            })?;
        result
    }

    async fn invoke_target(
        &self,
        prepared: PreparedCall,
        authority: InvocationAuthority,
        cancellation: CancellationToken,
    ) -> Result<ToolOutcome, PortError> {
        if cancellation.is_cancelled() || !authority.can_execute() {
            return Err(PortError::Invalid(
                "skill authority was withdrawn before effects".to_owned(),
            ));
        }
        if let Some(content) = prepared.instructions {
            if !authority.is_owner() {
                return Err(PortError::Invalid("instruction content authority was withdrawn".to_owned()));
            }
            return Ok(ToolOutcome {
                call_id: prepared.invocation.call.call_id,
                status: ToolStatus::Ok,
                output: json!({"kind":"instructions","content":content,"executionGranted":false}).to_string(),
                changed_workspace: false,
            });
        }
        if let Some(workspace) = self
            .workspace
            .as_ref()
            .filter(|workspace| workspace.contains(&prepared.invocation.call.name))
        {
            return workspace
                .invoke(
                    prepared.invocation,
                    authority,
                    prepared.target_binding,
                    cancellation,
                )
                .await
                .and_then(|outcome| Self::decode_output(outcome, prepared.http_response));
        }
        let invocation = prepared.invocation;
        let arguments: Value = serde_json::from_str(&invocation.call.arguments)
            .map_err(|_| PortError::Invalid("prepared skill arguments are invalid".to_owned()))?;
        let outcome = self
            .plugins
            .invoke(
                claw_http_api::ToolInvocation {
                    name: invocation.call.name,
                    arguments,
                    action: None,
                    context: ToolInvocationContext {
                        authority: Some(authority.clone()),
                        binding: Some(prepared.target_binding),
                        session_key: Some(invocation.session_id.to_string()),
                        idempotency_key: Some(invocation.call.call_id.to_string()),
                        account_id: authority.account().map(str::to_owned),
                        sender_is_owner: authority.is_owner(),
                        agent_id: None,
                        message_channel: None,
                        agent_to: None,
                        agent_thread_id: None,
                        dry_run: false,
                    },
                },
                cancellation,
            )
            .await
            .map_err(|error| match error.kind {
                claw_http_api::PortErrorKind::InvalidRequest => PortError::Invalid(error.message),
                claw_http_api::PortErrorKind::NotFound => PortError::NotFound(error.message),
                claw_http_api::PortErrorKind::OutcomeUnknown
                | claw_http_api::PortErrorKind::CommittedButNotDurable => {
                    PortError::OutcomeUnknown(error.message)
                }
                _ => PortError::Unavailable(error.message),
            })?;
        if !outcome.ok {
            return Err(PortError::OutcomeUnknown(
                "skill plugin target did not confirm success".to_owned(),
            ));
        }
        Ok(ToolOutcome {
            call_id: invocation.call.call_id,
            status: ToolStatus::Ok,
            output: serde_json::to_string(&outcome.result.unwrap_or(Value::Null)).map_err(
                |_| PortError::OutcomeUnknown("skill result could not be encoded".to_owned()),
            )?,
            changed_workspace: true,
        })
    }

    pub(super) async fn shutdown(&self) {
        {
            let mut accepting = self
                .accepting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *accepting = false;
            drop(accepting);
            self.tasks.close();
        }
        self.tasks.wait().await;
    }
}

impl ModelToolCatalog for NativeSkills {
    fn definitions(&self) -> Vec<ToolDefinition> {
        Self::definitions(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static NEXT_ROOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct Root(std::path::PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn manifest() -> Value {
        json!({"id":"project.read","description":"Read a project file","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false},"execution":{"kind":"native","handler":"fs_read"}})
    }

    #[tokio::test]
    async fn native_skill_instruction_content_is_owner_scoped_and_grants_no_execution() {
        use claw_application::model::ids::{ToolCallId, TurnId};
        use claw_application::model::message::ToolCall;
        use claw_application::ports::tool::{InvocationAccess, InvocationSource};

        use crate::adapters::http_api::{DependencyReadiness, Diagnostics};

        let root = Root(std::env::temp_dir().join(format!(
            "claw-skill-instructions-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )));
        std::fs::create_dir_all(&root.0).expect("owned audit directory");
        let audit_path = root.0.join("audit.jsonl");
        let audit = Arc::new(DurableSecurityAudit::open(&audit_path, Arc::new(DependencyReadiness::new(["audit"]))).expect("durable audit"));
        let policy = json!({"schemaVersion":1,"skills":[{
            "id":"project.review", "description":"Reviewed workflow instructions",
            "parameters":{"type":"object","properties":{},"additionalProperties":false},
            "execution":{"kind":"instructions","content":"Inspect the source.\nAsk before effects."}
        }]});
        let skills = Arc::new(NativeSkills {
            entries: parse_policy(&policy.to_string()).expect("instruction policy"),
            workspace: None,
            plugins: PluginToolSurface::new(Arc::new(Diagnostics::new(8))),
            tasks: TaskTracker::new(),
            slots: Arc::new(tokio::sync::Semaphore::new(4)),
            accepting: Mutex::new(true),
        });
        let name = skills.definitions().first().expect("instruction tool").name.clone();
        assert!(!skills.mutates(&name));
        let summary = skills.summary();
        assert_eq!(summary["active"], 1);
        assert_eq!(summary["instructions"], 1);
        assert_eq!(summary["executable"], 0);
        assert_eq!(summary["entries"][0]["instructionOnly"], true);
        let invocation = ToolInvocation {
            session_id: claw_domain::SessionId::new("instruction-session").expect("session"),
            turn: TurnId::FIRST,
            call: ToolCall {
                call_id: ToolCallId::new("instruction-call").expect("call"),
                name,
                arguments: "{}".to_owned(),
            },
        };
        let authority = |access| InvocationAuthority::new(InvocationSource::Gateway, "instruction-test", None, access, 0).expect("test authority");
        assert!(skills.prepare(&invocation, &authority(InvocationAccess::ReadOnly)).is_err());
        assert!(skills.prepare(&invocation, &authority(InvocationAccess::Execute)).is_err());
        let owner = authority(InvocationAccess::Owner);
        let binding = skills.prepare(&invocation, &owner).expect("owner content binding").approval_binding;
        assert!(binding.resource().expect("review resource").contains("no execution permission"));
        let result = skills.invoke(invocation, owner, binding, CancellationToken::new(), audit).await.expect("approved content");
        assert_eq!(result.status, ToolStatus::Ok);
        assert!(!result.changed_workspace);
        let content: Value = serde_json::from_str(&result.output).expect("content JSON");
        assert_eq!(content["kind"], "instructions");
        assert_eq!(content["content"], "Inspect the source.\nAsk before effects.");
        assert_eq!(content["executionGranted"], false);
        skills.shutdown().await;
        assert_eq!(std::fs::read_dir(&root.0).expect("owned files").count(), 1);
        let records = std::fs::read_to_string(audit_path).expect("content audit");
        assert_eq!(records.lines().count(), 2);
        assert!(!records.contains("Inspect the source"));
        assert_eq!(skills.summary()["active"], 0);
    }

    #[tokio::test]
    async fn native_skill_dropped_waiter_settles_audit_and_drains_network() {
        use claw_application::model::ids::{ToolCallId, TurnId};
        use claw_application::model::message::ToolCall;
        use claw_application::ports::tool::{InvocationAccess, InvocationSource};
        use tokio::io::AsyncReadExt as _;

        use crate::adapters::http_api::{DependencyReadiness, Diagnostics};

        let root = Root(std::env::temp_dir().join(format!(
            "claw-skill-cancel-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )));
        std::fs::create_dir_all(root.0.join("workspace")).expect("owned workspace");
        let audit_path = root.0.join("audit.jsonl");
        let audit = Arc::new(
            DurableSecurityAudit::open(&audit_path, Arc::new(DependencyReadiness::new(["audit"])))
                .expect("owned audit"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("owned listener");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let (accepted, received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("skill connection");
            let mut request = Vec::new();
            let mut bytes = [0_u8; 1024];
            while !request.windows(4).any(|value| value == b"\r\n\r\n") {
                let count = socket.read(&mut bytes).await.expect("request read");
                assert_ne!(count, 0);
                request.extend_from_slice(&bytes[..count]);
                assert!(request.len() <= 4096);
            }
            accepted.send(()).expect("request signal");
            let closed = socket.read(&mut bytes).await;
            assert!(
                matches!(closed, Ok(0) | Err(_)),
                "cancelled skill connection must close"
            );
        });
        let workspace = WorkspaceTools::from_json(
            &json!({"root":root.0.join("workspace"),"allowOwner":true,"allowNetwork":true,"networkTargets":[{"origin":origin,"addresses":["127.0.0.1"]}]}).to_string(),
            Arc::clone(&audit),
        ).expect("fixed-address workspace");
        let policy = json!({"schemaVersion":1,"skills":[{
            "id":"network.wait","description":"Wait for the reviewed test response",
            "parameters":{"type":"object","additionalProperties":false},
            "execution":{"kind":"http","request":{"method":"GET","url":format!("{origin}/wait"),"parameters":{"kind":"query_parameter","name":"input"},"response":"text"}}
        }]});
        let skills = Arc::new(NativeSkills {
            entries: parse_policy(&policy.to_string()).expect("reviewed skill"),
            workspace: Some(Arc::clone(&workspace)),
            plugins: PluginToolSurface::new(Arc::new(Diagnostics::new(8))),
            tasks: TaskTracker::new(),
            slots: Arc::new(tokio::sync::Semaphore::new(4)),
            accepting: Mutex::new(true),
        });
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "skill-test-device",
            None,
            InvocationAccess::Owner,
            0,
        )
        .expect("owner authority");
        let invocation = ToolInvocation {
            session_id: claw_domain::SessionId::new("skill-cancellation").expect("session"),
            turn: TurnId::FIRST,
            call: ToolCall {
                call_id: ToolCallId::new("skill-cancel-call").expect("call"),
                name: skills
                    .definitions()
                    .first()
                    .expect("active HTTP skill")
                    .name
                    .clone(),
                arguments: "{}".to_owned(),
            },
        };
        let binding = skills
            .prepare(&invocation, &authority)
            .expect("bound call")
            .approval_binding;
        let worker = Arc::clone(&skills);
        let task_audit = Arc::clone(&audit);
        let task_invocation = invocation.clone();
        let task_authority = authority.clone();
        let task_binding = binding.clone();
        let caller = tokio::spawn(async move {
            worker
                .invoke(
                    task_invocation,
                    task_authority,
                    task_binding,
                    CancellationToken::new(),
                    task_audit,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), received)
            .await
            .expect("request deadline")
            .expect("request received");
        caller.abort();
        assert!(
            caller
                .await
                .expect_err("owned caller was aborted")
                .is_cancelled()
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), skills.shutdown())
            .await
            .expect("skill tasks drained");
        assert!(skills.definitions().is_empty());
        assert_eq!(skills.summary()["executable"], 0);
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("socket close deadline")
            .expect("owned server finished");
        let records: Vec<Value> = std::fs::read_to_string(&audit_path)
            .expect("durable audit")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("audit JSON"))
            .filter(|record| record["action"] == "skill_tool")
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["phase"], "authorized");
        assert_eq!(records[1]["phase"], "failed");
        assert_eq!(records[0]["skillBinding"], records[1]["skillBinding"]);
        assert_eq!(records[0]["callId"], records[1]["callId"]);
        assert!(matches!(
            skills
                .invoke(
                    invocation,
                    authority,
                    binding,
                    CancellationToken::new(),
                    audit
                )
                .await,
            Err(PortError::Unavailable(_))
        ));
        workspace.shutdown().await;
    }

    #[test]
    fn native_skill_schema_enforces_full_constraints_and_never_fetches_references() {
        let mut value = manifest();
        value["parameters"] = json!({"type":"object","required":["names"],"properties":{"names":{"type":"array","maxItems":1,"items":{"type":"string","pattern":"^safe$"}}},"additionalProperties":false});
        let parsed = parse_policy(&json!({"schemaVersion":1,"skills":[value.clone()]}).to_string())
            .expect("bounded full schema");
        let validator = &parsed.values().next().expect("skill").validator;
        assert!(validator.is_valid(&json!({"names":["safe"]})));
        assert!(!validator.is_valid(&json!({"names":["safe","safe"]})));
        assert!(!validator.is_valid(&json!({"names":["unsafe"]})));
        value["parameters"] =
            json!({"type":"object","$ref":"https://example.invalid/no-schema-fetch"});
        assert!(parse_policy(&json!({"schemaVersion":1,"skills":[value]}).to_string()).is_err());
    }

    #[test]
    fn native_skill_policy_requires_closed_versioned_bounded_manifests() {
        let policy = json!({"schemaVersion":1,"skills":[manifest()]});
        let entries = parse_policy(&policy.to_string()).expect("reviewed policy");
        assert_eq!(entries.len(), 1);
        let name = entries.keys().next().expect("published name");
        assert!(name.len() <= 64);
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        );
        for policy in [
            json!({"schemaVersion":2,"skills":[manifest()]}),
            json!({"schemaVersion":1,"skills":[manifest(),manifest()]}),
            json!({"schemaVersion":1,"skills":vec![manifest();33]}),
            json!({"schemaVersion":1,"skills":[manifest()],"allowAll":true}),
        ] {
            assert!(parse_policy(&policy.to_string()).is_err());
        }
        for execution in [
            json!({"kind":"javascript","code":"not executable"}),
            json!({"kind":"http","request":{"method":"POST","url":"https://example.test"}}),
        ] {
            let mut value = manifest();
            value["execution"] = execution;
            assert!(
                parse_policy(&json!({"schemaVersion":1,"skills":[value]}).to_string()).is_err()
            );
        }
    }

    #[test]
    fn native_http_skill_policy_and_complete_response_contract_fail_closed() {
        let mut value = manifest();
        value["execution"] = json!({"kind":"http","request":{"method":"GET","url":"https://example.test/data","parameters":{"kind":"query_parameter","name":"input"},"response":"json"}});
        assert!(
            parse_policy(&json!({"schemaVersion":1,"skills":[value.clone()]}).to_string()).is_ok()
        );
        for replacement in [
            json!({"method":"POST","url":"https://example.test/data"}),
            json!({"method":"GET","url":"https://example.test/data?secret=static","parameters":{"kind":"query_parameter","name":"input"}}),
            json!({"method":"GET","url":"https://example.test/data","headers":{"x-extra":"value"},"parameters":{"kind":"query_parameter","name":"input"}}),
        ] {
            let mut invalid = value.clone();
            invalid["execution"]["request"] = replacement;
            assert!(
                parse_policy(&json!({"schemaVersion":1,"skills":[invalid]}).to_string()).is_err()
            );
        }
        let outcome = |status: u16, body: &str, truncated: bool| ToolOutcome {
            call_id: claw_application::model::ids::ToolCallId::new("http-skill-call")
                .expect("call ID"),
            status: ToolStatus::Ok,
            output: json!({"truncated":truncated,"structured":{"status":status,"body":body}})
                .to_string(),
            changed_workspace: false,
        };
        let decoded = NativeSkills::decode_output(
            outcome(200, "{\"result\":42}", false),
            Some(claw_skills::HttpResponseMode::Json),
        )
        .expect("complete JSON");
        assert_eq!(decoded.output, "{\"result\":42}");
        let text = NativeSkills::decode_output(
            outcome(200, "plain response", false),
            Some(claw_skills::HttpResponseMode::Text),
        )
        .expect("complete text");
        assert_eq!(text.output, "\"plain response\"");
        for invalid in [
            outcome(503, "unavailable", false),
            outcome(200, "incomplete", false),
            outcome(200, "{}", true),
        ] {
            assert!(matches!(
                NativeSkills::decode_output(invalid, Some(claw_skills::HttpResponseMode::Json)),
                Err(PortError::OutcomeUnknown(_))
            ));
        }
    }

    #[test]
    fn native_skill_binding_identifies_manifest_and_underlying_publication() {
        let entries = parse_policy(&json!({"schemaVersion":1,"skills":[manifest()]}).to_string())
            .expect("policy");
        let skill = entries.values().next().expect("skill");
        let target = ToolBinding::new("workspace-resource", 1)
            .expect("binding")
            .with_resource("workspace=test; path=note.txt".to_owned())
            .expect("resource");
        let original = skill_binding(skill, "fs_read", &target, "{\"path\":\"note.txt\"}")
            .expect("composite binding");
        assert!(
            original
                .resource()
                .expect("preview")
                .contains("skill=project.read; manifestSha256=")
        );
        assert!(
            original
                .resource()
                .expect("preview")
                .contains("path=note.txt")
        );
        assert_ne!(
            original,
            skill_binding(skill, "fs_write", &target, "{\"path\":\"note.txt\"}")
                .expect("target change")
        );
        assert_ne!(
            original,
            skill_binding(skill, "fs_read", &target, "{\"path\":\"other.txt\"}")
                .expect("arguments change")
        );
        assert_ne!(
            original,
            skill_binding(
                skill,
                "fs_read",
                &ToolBinding::new("workspace-resource", 2).expect("replacement"),
                "{\"path\":\"note.txt\"}"
            )
            .expect("revision change")
        );
        let mut replacement = manifest();
        replacement["description"] = json!("Changed reviewed description");
        let entries = parse_policy(&json!({"schemaVersion":1,"skills":[replacement]}).to_string())
            .expect("replacement policy");
        assert_ne!(
            original,
            skill_binding(
                entries.values().next().expect("replacement skill"),
                "fs_read",
                &target,
                "{\"path\":\"note.txt\"}"
            )
            .expect("manifest change")
        );
    }
}
