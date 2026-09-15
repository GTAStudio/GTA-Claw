//! Explicit workspace policy over the existing native tool registry and durable audit sink.

mod network;

use std::fmt::Write as _;
#[cfg(test)]
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use claw_application::ports::PortError;
use claw_application::ports::tool::{
    InvocationAuthority, InvocationSource, ToolBinding, ToolInvocation, ToolOutcome, ToolStatus,
};
use claw_http_api::ToolDefinition;
use claw_provider_sdk::http::ProxyPolicy;
use claw_tools::{
    Approval, ArgvPolicy, AuditError, AuditPhase, Capability, Clock, DenialReason, EnvPolicy,
    ExecPolicy, FsGlobTool, FsListTool, FsPatchTool, FsReadTool, FsSearchTool, FsWriteTool,
    GrantLedger, GrantRequest, GrantScope, PermissionBroker, PermissionDecision, PermissionRequest,
    ProcessExecTool, Resource, Sandbox, SandboxLimits, SystemClock, ToolAuditRecord, ToolAuditSink,
    ToolContext, ToolRegistry,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::http_api::DurableSecurityAudit;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Trusted policy has independent opt-ins for owner, write, process and network capabilities"
)]
struct WorkspacePolicy {
    root: PathBuf,
    #[serde(default)]
    allow_owner: bool,
    #[serde(default)]
    allow_write: bool,
    #[serde(default)]
    subjects: Vec<WorkspaceSubject>,
    #[serde(default)]
    allow_process: bool,
    #[serde(default)]
    programs: Vec<WorkspaceProgram>,
    #[serde(default)]
    allow_network: bool,
    #[serde(default)]
    network_targets: Vec<network::Target>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WorkspaceProgram {
    name: String,
    path: PathBuf,
    sha256: String,
    args: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceSubject {
    source: String,
    subject: String,
    account: Option<String>,
}

pub(crate) struct WorkspaceTools {
    sandbox: Sandbox,
    policy: WorkspacePolicy,
    audit: Arc<DurableSecurityAudit>,
    tasks: TaskTracker,
    slots: Arc<tokio::sync::Semaphore>,
    accepting: std::sync::Mutex<bool>,
    process_policy: ExecPolicy,
    network: Option<network::NativeNetwork>,
}

struct ProcessCancellation(claw_tools::CancellationToken);

impl Drop for ProcessCancellation {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
fn executable_digest(path: &std::path::Path) -> Result<String, String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000).share_mode(1);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let file = options
        .open(path)
        .map_err(|_| "configured process executable is unavailable".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "configured process executable cannot be inspected".to_owned())?;
    if !metadata.is_file() || metadata.len() > 128 * 1024 * 1024 {
        return Err("configured process executable is not a bounded regular file".to_owned());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("configured process executable is a reparse point".to_owned());
        }
    }
    let mut source = file.take(128 * 1024 * 1024 + 1);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut total = 0_u64;
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| "configured process executable hash failed".to_owned())?;
        if read == 0 {
            break;
        }
        total += u64::try_from(read)
            .map_err(|_| "configured process executable size overflow".to_owned())?;
        if total > 128 * 1024 * 1024 {
            return Err("configured process executable grew beyond its bound".to_owned());
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
        .map(char::from)
        .collect())
}

const fn source_label(source: InvocationSource) -> &'static str {
    match source {
        InvocationSource::Gateway => "gateway",
        InvocationSource::Http => "http",
        InvocationSource::Mcp => "mcp",
        InvocationSource::Channel => "channel",
    }
}

fn registry(
    writable: bool,
    process: Option<(ExecPolicy, claw_tools::CancellationToken)>,
    network: Option<Box<dyn claw_tools::Tool>>,
) -> Result<ToolRegistry, PortError> {
    let mut registry = ToolRegistry::new();
    let mut tools: Vec<Box<dyn claw_tools::Tool>> = vec![
        Box::new(FsReadTool),
        Box::new(FsListTool),
        Box::new(FsGlobTool),
        Box::new(FsSearchTool),
    ];
    if writable {
        tools.extend([
            Box::new(FsWriteTool) as Box<dyn claw_tools::Tool>,
            Box::new(FsPatchTool),
        ]);
    }
    if let Some((policy, cancellation)) = process {
        tools.push(Box::new(
            ProcessExecTool::new(policy).with_cancellation(cancellation),
        ));
    }
    if let Some(network) = network {
        tools.push(network);
    }
    for tool in tools {
        registry
            .register(tool)
            .map_err(|error| PortError::Invalid(error.to_string()))?;
    }
    Ok(registry)
}

impl WorkspaceTools {
    pub(super) fn root(&self) -> std::path::PathBuf {
        self.sandbox.resolve_root().native()
    }

    pub(crate) fn from_environment(
        audit: Arc<DurableSecurityAudit>,
        proxy: &ProxyPolicy,
    ) -> Result<Option<Arc<Self>>, String> {
        match std::env::var("GTA_CLAW_WORKSPACE_POLICY") {
            Ok(encoded) => Self::from_json_with_proxy(&encoded, audit, proxy).map(Some),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err("GTA_CLAW_WORKSPACE_POLICY must be UTF-8".to_owned()),
        }
    }

    #[cfg(test)]
    pub(super) fn from_json(
        encoded: &str,
        audit: Arc<DurableSecurityAudit>,
    ) -> Result<Arc<Self>, String> {
        Self::from_json_with_proxy(encoded, audit, &ProxyPolicy::Disabled)
    }

    fn from_json_with_proxy(
        encoded: &str,
        audit: Arc<DurableSecurityAudit>,
        proxy: &ProxyPolicy,
    ) -> Result<Arc<Self>, String> {
        if encoded.len() > 32 * 1024 {
            return Err("workspace policy exceeds 32768 bytes".to_owned());
        }
        let policy: WorkspacePolicy = serde_json::from_str(encoded)
            .map_err(|_| "workspace policy must match the closed native schema".to_owned())?;
        if !policy.root.is_absolute() || policy.subjects.len() > 128 {
            return Err("workspace requires an absolute root and bounded subjects".to_owned());
        }
        for subject in &policy.subjects {
            if !matches!(
                subject.source.as_str(),
                "gateway" | "http" | "mcp" | "channel"
            ) || std::iter::once(subject.subject.as_str())
                .chain(subject.account.as_deref())
                .any(|value| {
                    value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
                })
            {
                return Err("workspace subject rule is invalid".to_owned());
            }
        }
        let metadata = std::fs::symlink_metadata(&policy.root)
            .map_err(|_| "workspace root is unavailable".to_owned())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("workspace root must be an existing non-link directory".to_owned());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("workspace root cannot be a reparse point".to_owned());
            }
        }
        let sandbox = Sandbox::new_pinned(
            &policy.root,
            SandboxLimits {
                max_file_bytes: 1024 * 1024,
                max_directory_entries: 2048,
                max_walked_files: 4096,
                ..SandboxLimits::default()
            },
        )
        .map_err(|error| error.to_string())?;
        if policy.programs.len() > 16 || (!policy.allow_process && !policy.programs.is_empty()) {
            return Err(
                "process programs require explicit allowProcess and a bounded allowlist".to_owned(),
            );
        }
        let mut process_policy = ExecPolicy::deny_all()
            .with_writable_root(sandbox.root())
            .with_timeout(std::time::Duration::from_secs(30))
            .with_max_output_bytes(4096);
        if policy.allow_process && !policy.programs.is_empty() {
            process_policy = process_policy.with_env(
                EnvPolicy::empty()
                    .with_platform_minimum()
                    .map_err(|_| "minimal process environment is unavailable".to_owned())?,
            );
        }
        let mut names = std::collections::BTreeSet::new();
        for program in &policy.programs {
            if !names.insert(&program.name)
                || program.args.len() > 64
                || program
                    .args
                    .iter()
                    .any(|argument| argument.len() > 4096 || argument.chars().any(char::is_control))
                || program.sha256.len() != 64
                || !program
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("invalid fixed program name, digest or argument vector".to_owned());
            }
            let mut expected = [0_u8; 32];
            for (target, pair) in expected
                .iter_mut()
                .zip(program.sha256.as_bytes().as_chunks::<2>().0)
            {
                let high = char::from(pair[0])
                    .to_digit(16)
                    .ok_or_else(|| "invalid executable digest".to_owned())?;
                let low = char::from(pair[1])
                    .to_digit(16)
                    .ok_or_else(|| "invalid executable digest".to_owned())?;
                *target = u8::try_from(high * 16 + low)
                    .map_err(|_| "invalid executable digest".to_owned())?;
            }
            process_policy
                .allow_program_with_sha256(
                    &program.name,
                    &program.path,
                    ArgvPolicy::exactly(&program.args).with_max_arguments(program.args.len()),
                    expected,
                )
                .map_err(|_| "configured process program violates executable policy".to_owned())?;
        }
        if !policy.allow_network && !policy.network_targets.is_empty() {
            return Err("network targets require explicit allowNetwork".to_owned());
        }
        let network = if policy.allow_network {
            Some(network::NativeNetwork::new(&policy.network_targets, proxy)?)
        } else {
            None
        };
        Ok(Arc::new(Self {
            sandbox,
            policy,
            audit,
            tasks: TaskTracker::new(),
            slots: Arc::new(tokio::sync::Semaphore::new(4)),
            accepting: std::sync::Mutex::new(true),
            process_policy,
            network,
        }))
    }

    fn permitted(&self, authority: &InvocationAuthority) -> bool {
        authority.can_execute()
            && ((self.policy.allow_owner && authority.is_owner())
                || self.policy.subjects.iter().any(|rule| {
                    rule.source == source_label(authority.source())
                        && rule.subject == authority.subject()
                        && rule.account.as_deref() == authority.account()
                }))
    }

    pub(super) fn definitions(&self) -> Vec<ToolDefinition> {
        self.registry(claw_tools::CancellationToken::new())
            .map(|registry| {
                registry
                    .descriptors()
                    .into_iter()
                    .map(|descriptor| ToolDefinition {
                        name: descriptor.name.to_owned(),
                        description: Some(descriptor.description.to_owned()),
                        input_schema: descriptor.schema.to_json_schema(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(super) fn contains(&self, name: &str) -> bool {
        matches!(name, "fs_read" | "fs_list" | "fs_glob" | "fs_search")
            || (self.policy.allow_write && matches!(name, "fs_write" | "fs_patch"))
            || (self.policy.allow_process
                && !self.policy.programs.is_empty()
                && name == "process_exec")
            || (self.network.is_some() && name == "net_fetch")
    }

    pub(super) fn network_resource(&self, url: &str) -> Result<String, PortError> {
        self.network
            .as_ref()
            .ok_or_else(|| PortError::Invalid("native network policy is absent".to_owned()))?
            .resource(url)
            .map_err(PortError::Invalid)
    }

    pub(super) fn mutates(name: &str) -> bool {
        matches!(name, "fs_write" | "fs_patch" | "process_exec" | "net_fetch")
    }

    fn registry(
        &self,
        cancellation: claw_tools::CancellationToken,
    ) -> Result<ToolRegistry, PortError> {
        let network = self
            .network
            .as_ref()
            .map(|network| network.tool(&cancellation));
        registry(
            self.policy.allow_write,
            self.contains("process_exec")
                .then(|| (self.process_policy.clone(), cancellation)),
            network,
        )
    }

    fn validate_process(
        &self,
        arguments: &Value,
        authority: &InvocationAuthority,
    ) -> Result<(), PortError> {
        if !authority.is_owner() {
            return Err(PortError::Invalid(
                "native process execution requires an authenticated owner".to_owned(),
            ));
        }
        let program = self
            .policy
            .programs
            .iter()
            .find(|program| arguments["program"].as_str() == Some(program.name.as_str()))
            .ok_or_else(|| PortError::Invalid("process program is not configured".to_owned()))?;
        let supplied: Vec<&str> = match arguments.get("args") {
            Some(Value::Array(values)) => values
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    PortError::Invalid("process arguments must be strings".to_owned())
                })?,
            None => Vec::new(),
            _ => {
                return Err(PortError::Invalid(
                    "process argument vector is invalid".to_owned(),
                ));
            }
        };
        if !supplied
            .iter()
            .copied()
            .eq(program.args.iter().map(String::as_str))
        {
            return Err(PortError::Invalid(
                "process arguments must exactly match the configured vector".to_owned(),
            ));
        }
        self.process_policy
            .verify_program(&program.name)
            .map_err(|_| {
                PortError::Invalid("process executable changed after policy enrollment".to_owned())
            })?;
        Ok(())
    }

    pub(super) fn binding(
        &self,
        invocation: &ToolInvocation,
        authority: &InvocationAuthority,
    ) -> Result<ToolBinding, PortError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        if !self.permitted(authority) || !self.contains(&invocation.call.name) {
            return Err(PortError::Invalid(
                "caller has no grant for this workspace tool".to_owned(),
            ));
        }
        self.sandbox
            .validate_root()
            .map_err(|error| PortError::Invalid(error.to_string()))?;
        if invocation.call.arguments.len() > 64 * 1024 {
            return Err(PortError::Invalid(
                "workspace arguments exceed the native bound".to_owned(),
            ));
        }
        let arguments: Value = serde_json::from_str(&invocation.call.arguments)
            .map_err(|_| PortError::Invalid("workspace arguments must be JSON".to_owned()))?;
        if invocation.call.name == "process_exec" {
            self.validate_process(&arguments, authority)?;
        }
        let network_scope =
            if invocation.call.name == "net_fetch" {
                if !authority.is_owner() {
                    return Err(PortError::Invalid(
                        "native network access requires authenticated owner".to_owned(),
                    ));
                }
                Some(
                    self.network
                        .as_ref()
                        .ok_or_else(|| {
                            PortError::Invalid("native network policy is absent".to_owned())
                        })?
                        .resource(arguments["url"].as_str().ok_or_else(|| {
                            PortError::Invalid("network URL is required".to_owned())
                        })?)
                        .map_err(PortError::Invalid)?,
                )
            } else {
                None
            };
        let registry = self.registry(claw_tools::CancellationToken::new())?;
        let (_, resource) = registry
            .prepare(
                &invocation.call.name,
                &arguments,
                &ToolContext {
                    sandbox: &self.sandbox,
                    clock: &SystemClock,
                },
            )
            .map_err(|error| PortError::Invalid(error.to_string()))?;
        let mut resource_description = format!(
            "workspace={}; resource={resource:?}",
            self.sandbox.root().display()
        );
        if let Some(scope) = network_scope {
            write!(resource_description, "; {scope}").map_err(|_| {
                PortError::Invalid("network resource preview encoding failed".to_owned())
            })?;
        }
        if let Resource::Program(name) = &resource
            && let Some(program) = self
                .policy
                .programs
                .iter()
                .find(|program| &program.name == name)
        {
            write!(
                resource_description,
                "; executable={}; sha256={}; process retains host OS permissions",
                program.path.display(),
                program.sha256
            )
            .map_err(|_| {
                PortError::Invalid("process resource preview encoding failed".to_owned())
            })?;
        }
        let bytes = serde_json::to_vec(&(
            self.sandbox.root(),
            &invocation.call.name,
            &resource,
            &arguments,
        ))
        .map_err(|_| PortError::Invalid("workspace binding encoding failed".to_owned()))?;
        let identity: String = Sha256::digest(bytes)
            .iter()
            .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]])
            .map(char::from)
            .collect();
        ToolBinding::new(&format!("workspace-{identity}"), 1)?.with_resource(resource_description)
    }

    pub(super) async fn invoke(
        self: &Arc<Self>,
        invocation: ToolInvocation,
        authority: InvocationAuthority,
        binding: ToolBinding,
        cancellation: CancellationToken,
    ) -> Result<ToolOutcome, PortError> {
        if self.binding(&invocation, &authority)? != binding {
            return Err(PortError::Invalid(
                "workspace resource or arguments changed after approval".to_owned(),
            ));
        }
        let process_cancel = ProcessCancellation(claw_tools::CancellationToken::new());
        let task_cancel = process_cancel.0.clone();
        let execution_authority = authority.clone();
        let caller_cancellation = cancellation.clone();
        let task = {
            let accepting = self.accepting.lock().map_err(|_| {
                PortError::Unavailable("workspace admission gate failed".to_owned())
            })?;
            if !*accepting {
                return Err(PortError::Unavailable(
                    "workspace tools are closed".to_owned(),
                ));
            }
            let slot = Arc::clone(&self.slots).try_acquire_owned().map_err(|_| {
                PortError::Unavailable("workspace tool capacity exceeded".to_owned())
            })?;
            let runtime = Arc::clone(self);
            let task = self.tasks.spawn_blocking(move || {
                let _slot = slot;
                if cancellation.is_cancelled() {
                    return Err(PortError::Unavailable(
                        "workspace call cancelled before execution".to_owned(),
                    ));
                }
                runtime.invoke_blocking(&invocation, &authority, &cancellation, task_cancel)
            });
            drop(accepting);
            task
        };
        let mut task = task;
        let outcome = tokio::select! {
            result = &mut task => result,
            () = caller_cancellation.cancelled() => { process_cancel.0.cancel(); task.await },
            () = execution_authority.revoked() => { process_cancel.0.cancel(); task.await },
        };
        outcome.map_err(|_| {
            PortError::OutcomeUnknown(
                "workspace task ended without a confirmed result; inspect audit before retry"
                    .to_owned(),
            )
        })?
    }

    fn invoke_blocking(
        &self,
        invocation: &ToolInvocation,
        authority: &InvocationAuthority,
        cancellation: &CancellationToken,
        process_cancellation: claw_tools::CancellationToken,
    ) -> Result<ToolOutcome, PortError> {
        if !self.permitted(authority) {
            return Err(PortError::Invalid(
                "workspace authority is not granted".to_owned(),
            ));
        }
        let arguments: Value = serde_json::from_str(&invocation.call.arguments)
            .map_err(|_| PortError::Invalid("invalid workspace arguments".to_owned()))?;
        if invocation.call.name == "process_exec" {
            self.validate_process(&arguments, authority)?;
        }
        let registry = self.registry(process_cancellation)?;
        let context = ToolContext {
            sandbox: &self.sandbox,
            clock: &SystemClock,
        };
        let (descriptor, resource) = registry
            .prepare(&invocation.call.name, &arguments, &context)
            .map_err(|error| PortError::Invalid(error.to_string()))?;
        let scope = match resource {
            Resource::Path(path) => GrantScope::PathPrefix(path),
            Resource::Program(program) if self.policy.allow_process && authority.is_owner() => {
                GrantScope::Program(program)
            }
            Resource::Host(host) if self.network.is_some() && authority.is_owner() => {
                GrantScope::Host(host)
            }
            _ => {
                return Err(PortError::Invalid(
                    "workspace tool cannot grant this resource".to_owned(),
                ));
            }
        };
        let mut ledger = GrantLedger::new();
        ledger.grant(GrantRequest {
            capability: descriptor.permission.capability,
            scope,
            expires_unix_millis: Some(SystemClock.unix_millis().saturating_add(120_000)),
            max_uses: None,
            approval: Approval::Explicit,
        });
        let mut broker = InvocationBroker {
            ledger,
            cancellation,
        };
        let mut audit = InvocationAudit {
            sink: &self.audit,
            authority,
            invocation,
            authorized: false,
        };
        let result = registry.invoke(
            &invocation.call.name,
            &arguments,
            &context,
            &mut broker,
            &mut audit,
        );
        match result {
            Ok(output) => Ok(ToolOutcome {
                call_id: invocation.call.call_id.clone(),
                status: ToolStatus::Ok,
                output: serde_json::to_string(&output).map_err(|_| {
                    PortError::OutcomeUnknown("workspace result encoding failed".to_owned())
                })?,
                changed_workspace: matches!(
                    descriptor.permission.capability,
                    Capability::FilesystemWrite | Capability::ProcessExecute
                ),
            }),
            Err(error)
                if audit.authorized
                    && matches!(
                        descriptor.permission.capability,
                        Capability::FilesystemWrite
                            | Capability::ProcessExecute
                            | Capability::NetworkFetch
                    ) =>
            {
                Err(PortError::OutcomeUnknown(format!(
                    "native tool outcome must be reconciled before repeating the operation: {error}"
                )))
            }
            Err(error) => Err(PortError::Invalid(error.to_string())),
        }
    }

    pub(super) async fn shutdown(&self) {
        {
            let mut accepting = self
                .accepting
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *accepting = false;
            self.tasks.close();
            drop(accepting);
        }
        self.tasks.wait().await;
    }
}

struct InvocationBroker<'a> {
    ledger: GrantLedger,
    cancellation: &'a CancellationToken,
}
impl PermissionBroker for InvocationBroker<'_> {
    fn evaluate(&mut self, request: &PermissionRequest) -> PermissionDecision {
        if self.cancellation.is_cancelled() {
            PermissionDecision::Denied(DenialReason::BrokerDeniesAll)
        } else {
            self.ledger.evaluate(request)
        }
    }
}

struct InvocationAudit<'a> {
    sink: &'a DurableSecurityAudit,
    authority: &'a InvocationAuthority,
    invocation: &'a ToolInvocation,
    authorized: bool,
}
impl ToolAuditSink for InvocationAudit<'_> {
    fn persist(&mut self, record: &ToolAuditRecord) -> Result<(), AuditError> {
        self.sink
            .persist_tool(record, self.authority, self.invocation)
            .map_err(|_| AuditError::new("native audit persistence failed"))?;
        if record.phase == AuditPhase::Authorized {
            self.authorized = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::http_api::DependencyReadiness;
    use claw_application::model::ids::{ToolCallId, TurnId};
    use claw_application::model::message::ToolCall;
    use claw_application::ports::tool::InvocationAccess;
    use claw_domain::SessionId;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Root(PathBuf);
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture(writable: bool) -> (Root, Arc<WorkspaceTools>, InvocationAuthority) {
        let root = Root(std::env::temp_dir().join(format!(
            "claw-native-tools-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        std::fs::create_dir_all(root.0.join("workspace")).expect("fixture workspace");
        let audit = Arc::new(
            DurableSecurityAudit::open(
                &root.0.join("audit.jsonl"),
                Arc::new(DependencyReadiness::new(["audit"])),
            )
            .expect("durable audit"),
        );
        let policy = json!({"root": root.0.join("workspace"), "allowWrite": writable, "subjects": [{"source": "gateway", "subject": "allowed-device", "account": null}]}).to_string();
        let tools = WorkspaceTools::from_json(&policy, audit).expect("native tools");
        let authority = InvocationAuthority::new(
            InvocationSource::Gateway,
            "allowed-device",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("authority");
        (root, tools, authority)
    }

    fn invocation(name: &str, arguments: &Value) -> ToolInvocation {
        ToolInvocation {
            session_id: SessionId::new("native-workspace").expect("session"),
            turn: TurnId::FIRST,
            call: ToolCall {
                call_id: ToolCallId::new("host-call").expect("call"),
                name: name.to_owned(),
                arguments: arguments.to_string(),
            },
        }
    }

    #[test]
    #[ignore = "re-executed only as the explicitly allowlisted native process fixture"]
    fn native_process_fixture_entry() {
        use std::io::Write;
        let cwd = std::env::current_dir().expect("fixture working directory");
        let parent = cwd
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .expect("owned temporary root");
        assert!(parent.starts_with("claw-native-tools-"));
        assert!(std::env::var_os("GITHUB_TOKEN").is_none());
        assert!(std::env::var_os("GTA_CLAW_GATEWAY_TOKEN").is_none());
        let mut marker = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open("process-result.txt")
            .expect("new owned marker");
        marker
            .write_all(b"native process verified")
            .expect("fixture marker");
        println!("native process verified");
    }

    #[tokio::test]
    async fn native_workspace_process_requires_owner_digest_and_exact_argv() {
        let (root, base, _) = fixture(true);
        assert!(!base.contains("process_exec"));
        let executable = std::env::current_exe().expect("owned test executable");
        let digest = executable_digest(&executable).expect("owned executable digest");
        let args = vec![
            "--exact",
            "adapters::native_tools::tests::native_process_fixture_entry",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ];
        let policy = json!({"root":root.0.join("workspace"),"allowOwner":true,"allowProcess":true,"programs":[{"name":"fixture","path":executable,"sha256":digest,"args":args}]}).to_string();
        let tools = WorkspaceTools::from_json(&policy, Arc::clone(&base.audit))
            .expect("explicit process policy");
        let owner = InvocationAuthority::new(
            InvocationSource::Gateway,
            "owner",
            None,
            InvocationAccess::Owner,
            0,
        )
        .expect("owner");
        let writer = InvocationAuthority::new(
            InvocationSource::Gateway,
            "writer",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("writer");
        let call = invocation("process_exec", &json!({"program":"fixture","args":args}));
        assert!(tools.binding(&call, &writer).is_err());
        let wrong = invocation(
            "process_exec",
            &json!({"program":"fixture","args":["--nocapture","--exact"]}),
        );
        assert!(tools.binding(&wrong, &owner).is_err());
        let binding = tools
            .binding(&call, &owner)
            .expect("owner-approved program");
        assert!(
            binding
                .resource()
                .expect("resource preview")
                .contains("process retains host OS permissions")
        );
        assert!(
            binding
                .resource()
                .expect("resource preview")
                .contains(&digest)
        );
        assert!(!root.0.join("workspace/process-result.txt").exists());
        let outcome = tools
            .invoke(call, owner, binding, CancellationToken::new())
            .await
            .expect("owned allowlisted execution");
        assert!(outcome.output.contains("native process verified"));
        assert!(outcome.changed_workspace);
        assert_eq!(
            std::fs::read_to_string(root.0.join("workspace/process-result.txt"))
                .expect("owned process output"),
            "native process verified"
        );
        let audit = std::fs::read_to_string(root.0.join("audit.jsonl")).expect("process audit");
        assert!(audit.contains("process_execute"));
        let mut invalid: Value = serde_json::from_str(&policy).expect("policy fixture");
        invalid["programs"][0]["sha256"] = json!("0".repeat(64));
        assert!(WorkspaceTools::from_json(&invalid.to_string(), Arc::clone(&base.audit)).is_err());
        invalid["allowProcess"] = json!(false);
        assert!(WorkspaceTools::from_json(&invalid.to_string(), Arc::clone(&base.audit)).is_err());
        tools.shutdown().await;
        base.shutdown().await;
    }

    #[test]
    #[ignore = "owned blocking subprocess for native process cancellation tests"]
    fn native_process_cancel_fixture_entry() {
        use std::io::{Read, Write};
        let cwd = std::env::current_dir().expect("fixture working directory");
        assert!(
            cwd.parent()
                .and_then(|parent| parent.file_name())
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("claw-native-tools-"))
        );
        let address: std::net::SocketAddr = std::fs::read_to_string("process-fixture-address")
            .expect("owned fixture address")
            .parse()
            .expect("loopback address");
        assert!(address.ip().is_loopback());
        let mut connection =
            std::net::TcpStream::connect(address).expect("owned readiness channel");
        connection.write_all(b"started").expect("readiness");
        let mut finish = [0_u8; 1];
        let _ = connection.read(&mut finish);
    }

    #[tokio::test]
    async fn native_workspace_process_cancellation_and_drop_join_the_owned_child() {
        use tokio::io::AsyncReadExt;
        for drop_call in [false, true] {
            let (root, base, _) = fixture(true);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("owned readiness listener");
            std::fs::write(
                root.0.join("workspace/process-fixture-address"),
                listener.local_addr().expect("fixture address").to_string(),
            )
            .expect("owned fixture configuration");
            let executable = std::env::current_exe().expect("test executable");
            let digest = executable_digest(&executable).expect("test executable digest");
            let args = vec![
                "--exact",
                "adapters::native_tools::tests::native_process_cancel_fixture_entry",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ];
            let policy = json!({"root":root.0.join("workspace"),"allowOwner":true,"allowProcess":true,"programs":[{"name":"fixture","path":executable,"sha256":digest,"args":args}]}).to_string();
            let tools = WorkspaceTools::from_json(&policy, Arc::clone(&base.audit))
                .expect("bounded process policy");
            let owner = InvocationAuthority::new(
                InvocationSource::Gateway,
                "owner",
                None,
                InvocationAccess::Owner,
                0,
            )
            .expect("owner");
            let call = invocation("process_exec", &json!({"program":"fixture","args":args}));
            let binding = tools.binding(&call, &owner).expect("approved process");
            let cancellation = CancellationToken::new();
            let cancelled = cancellation.clone();
            let running = Arc::clone(&tools);
            let task =
                tokio::spawn(async move { running.invoke(call, owner, binding, cancelled).await });
            let (mut connection, _) =
                tokio::time::timeout(std::time::Duration::from_secs(8), listener.accept())
                    .await
                    .expect("process start deadline")
                    .expect("owned child connected");
            let mut started = [0_u8; 7];
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                connection.read_exact(&mut started),
            )
            .await
            .expect("readiness deadline")
            .expect("readiness marker");
            assert_eq!(&started, b"started");
            if drop_call {
                task.abort();
                assert!(
                    task.await
                        .expect_err("only wrapper task was cancelled")
                        .is_cancelled()
                );
            } else {
                cancellation.cancel();
                assert!(matches!(
                    tokio::time::timeout(std::time::Duration::from_secs(4), task)
                        .await
                        .expect("cancellation deadline")
                        .expect("task joined"),
                    Err(PortError::OutcomeUnknown(_))
                ));
            }
            tokio::time::timeout(std::time::Duration::from_secs(4), tools.shutdown())
                .await
                .expect("native tasks drain after cancellation or drop");
            assert_eq!(tools.tasks.len(), 0);
            let mut closed = [0_u8; 1];
            let ended = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                connection.read(&mut closed),
            )
            .await
            .expect("owned process releases its socket");
            assert!(matches!(ended, Ok(0) | Err(_)));
            base.shutdown().await;
        }
    }

    #[tokio::test]
    async fn native_workspace_network_requires_exact_origin_pins_owner_and_safe_response() {
        use axum::response::IntoResponse;
        use axum::routing::get;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (root, base, _) = fixture(true);
        assert!(!base.contains("net_fetch"));
        let requests = Arc::new(AtomicUsize::new(0));
        let received = Arc::clone(&requests);
        let router = axum::Router::new()
            .route(
                "/data",
                get(move |headers: axum::http::HeaderMap| {
                    let received = Arc::clone(&received);
                    async move {
                        assert!(
                            !headers.contains_key("authorization")
                                && !headers.contains_key("cookie")
                        );
                        assert_eq!(headers["accept-encoding"], "identity");
                        received.fetch_add(1, Ordering::SeqCst);
                        "native network fixture"
                    }
                }),
            )
            .route(
                "/redirect",
                get(|| async {
                    (
                        axum::http::StatusCode::FOUND,
                        [("location", "http://169.254.169.254/latest/meta-data/")],
                        "",
                    )
                        .into_response()
                }),
            )
            .route("/oversize", get(|| async { "x".repeat(4097) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("owned network fixture");
        let address = listener.local_addr().expect("fixture address");
        let stop = CancellationToken::new();
        let stopped = stop.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(stopped.cancelled_owned())
                .await
                .expect("owned fixture server");
        });
        let policy = serde_json::json!({"root":root.0.join("workspace"),"allowOwner":true,"allowNetwork":true,"networkTargets":[{"origin":format!("http://{address}"),"addresses":["127.0.0.1"]}]}).to_string();
        let tools = WorkspaceTools::from_json(&policy, Arc::clone(&base.audit))
            .expect("explicit network policy");
        let owner = InvocationAuthority::new(
            InvocationSource::Http,
            "owner",
            None,
            InvocationAccess::Owner,
            0,
        )
        .expect("owner");
        let writer = InvocationAuthority::new(
            InvocationSource::Http,
            "writer",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("writer");
        let call = invocation(
            "net_fetch",
            &json!({"url":format!("http://{address}/data")}),
        );
        assert!(tools.binding(&call, &writer).is_err());
        for url in [
            "http://169.254.169.254/latest/meta-data/".to_owned(),
            "https://example.test/".to_owned(),
            format!("http://user:secret@{address}/data"),
        ] {
            assert!(
                tools
                    .binding(&invocation("net_fetch", &json!({"url":url})), &owner)
                    .is_err()
            );
        }
        let binding = tools.binding(&call, &owner).expect("approved origin");
        assert!(
            binding
                .resource()
                .expect("network resource preview")
                .contains("pinned=[127.0.0.1]")
        );
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        let output = tools
            .invoke(call, owner.clone(), binding, CancellationToken::new())
            .await
            .expect("actual native HTTP fetch");
        assert!(output.output.contains("native network fixture") && !output.changed_workspace);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        for path in ["redirect", "oversize"] {
            let call = invocation(
                "net_fetch",
                &json!({"url":format!("http://{address}/{path}")}),
            );
            let binding = tools.binding(&call, &owner).expect("same explicit origin");
            assert!(matches!(
                tools
                    .invoke(call, owner.clone(), binding, CancellationToken::new())
                    .await,
                Err(PortError::OutcomeUnknown(_))
            ));
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let audit = std::fs::read_to_string(root.0.join("audit.jsonl")).expect("network audit");
        assert!(
            audit.contains("network_fetch")
                && !audit.contains("native network fixture")
                && !audit.contains("meta-data")
        );
        tools.shutdown().await;
        base.shutdown().await;
        stop.cancel();
        server.await.expect("fixture joined");
    }

    #[tokio::test]
    async fn native_workspace_network_cancellation_and_drop_close_the_owned_socket() {
        use tokio::io::AsyncReadExt;

        for drop_call in [false, true] {
            let (root, base, _) = fixture(true);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("owned response-stall fixture");
            let address = listener.local_addr().expect("fixture address");
            let policy = json!({"root":root.0.join("workspace"),"allowOwner":true,"allowNetwork":true,"networkTargets":[{"origin":format!("http://{address}"),"addresses":["127.0.0.1"]}]}).to_string();
            let tools = WorkspaceTools::from_json(&policy, Arc::clone(&base.audit))
                .expect("network policy");
            let owner = InvocationAuthority::new(
                InvocationSource::Http,
                "owner",
                None,
                InvocationAccess::Owner,
                0,
            )
            .expect("owner");
            let call = invocation(
                "net_fetch",
                &json!({"url":format!("http://{address}/stall")}),
            );
            let binding = tools.binding(&call, &owner).expect("exact network target");
            let cancellation = CancellationToken::new();
            let cancelled = cancellation.clone();
            let running = Arc::clone(&tools);
            let task =
                tokio::spawn(async move { running.invoke(call, owner, binding, cancelled).await });
            let (mut socket, _) =
                tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept())
                    .await
                    .expect("native connection deadline")
                    .expect("owned connection");
            let mut header = Vec::new();
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                let mut chunk = [0_u8; 512];
                while !header.ends_with(b"\r\n\r\n") {
                    let read = socket.read(&mut chunk).await.expect("request header");
                    assert!(read != 0 && header.len() + read <= 8192);
                    header.extend_from_slice(&chunk[..read]);
                }
            })
            .await
            .expect("complete request deadline");
            if drop_call {
                task.abort();
                assert!(task.await.expect_err("wrapper cancelled").is_cancelled());
            } else {
                cancellation.cancel();
                assert!(matches!(
                    tokio::time::timeout(std::time::Duration::from_secs(2), task)
                        .await
                        .expect("cancelled network settled")
                        .expect("wrapper joined"),
                    Err(PortError::OutcomeUnknown(_))
                ));
            }
            tokio::time::timeout(std::time::Duration::from_secs(2), tools.shutdown())
                .await
                .expect("network task drained");
            assert_eq!(tools.tasks.len(), 0);
            let mut closed = [0_u8; 1];
            assert!(matches!(
                tokio::time::timeout(std::time::Duration::from_secs(2), socket.read(&mut closed))
                    .await
                    .expect("socket closes after cancellation"),
                Ok(0) | Err(_)
            ));
            base.shutdown().await;
        }
    }

    #[tokio::test]
    async fn native_workspace_executes_existing_registry_after_scoped_binding_and_durable_audit() {
        let (root, tools, authority) = fixture(true);
        let write = invocation(
            "fs_write",
            &json!({"path": "result.txt", "content": "retained native content"}),
        );
        let binding = tools.binding(&write, &authority).expect("bound resource");
        assert!(binding.resource().expect("scope").contains("result.txt"));
        let outcome = tools
            .invoke(write, authority.clone(), binding, CancellationToken::new())
            .await
            .expect("native write");
        assert!(outcome.changed_workspace);
        let read = invocation("fs_read", &json!({"path": "result.txt"}));
        let binding = tools.binding(&read, &authority).expect("read binding");
        let output = tools
            .invoke(read, authority, binding, CancellationToken::new())
            .await
            .expect("native read");
        assert!(output.output.contains("retained native content"));
        assert!(!output.changed_workspace);
        let records =
            std::fs::read_to_string(root.0.join("audit.jsonl")).expect("durable audit bytes");
        let values: Vec<Value> = records
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit JSON"))
            .collect();
        assert_eq!(values.len(), 4);
        assert_eq!(values[0]["record"]["phase"], "authorized");
        assert_eq!(values[1]["record"]["phase"], "completed");
        assert_eq!(values[0]["subject"], "allowed-device");
        assert!(!records.contains("retained native content"));
        tools.shutdown().await;
    }

    #[tokio::test]
    async fn native_workspace_root_cannot_be_replaced_under_an_existing_approval() {
        let (root, tools, authority) = fixture(true);
        let request = invocation(
            "fs_write",
            &json!({"path": "approved.txt", "content": "approved"}),
        );
        let binding = tools
            .binding(&request, &authority)
            .expect("original workspace approval");
        let replacement = root.0.join("moved-workspace");
        let renamed = std::fs::rename(root.0.join("workspace"), &replacement);
        #[cfg(windows)]
        {
            assert!(
                renamed.is_err(),
                "Windows must retain the original root without delete sharing"
            );
            tools
                .invoke(request, authority, binding, CancellationToken::new())
                .await
                .expect("original pinned workspace still usable");
            assert_eq!(
                std::fs::read_to_string(root.0.join("workspace/approved.txt"))
                    .expect("original result"),
                "approved"
            );
        }
        #[cfg(unix)]
        {
            renamed.expect("Unix directory rename");
            std::fs::create_dir(root.0.join("workspace")).expect("replacement directory");
            assert!(tools.binding(&request, &authority).is_err());
            assert!(
                tools
                    .invoke(request, authority, binding, CancellationToken::new())
                    .await
                    .is_err()
            );
            assert!(!root.0.join("workspace/approved.txt").exists());
            assert!(!replacement.join("approved.txt").exists());
        }
        tools.shutdown().await;
        drop(tools);
    }

    #[tokio::test]
    async fn native_workspace_hard_links_cannot_read_or_overwrite_external_files() {
        let (root, tools, authority) = fixture(true);
        let external = root.0.join("outside.txt");
        std::fs::write(&external, "outside-private-content").expect("external fixture");
        std::fs::hard_link(&external, root.0.join("workspace/alias.txt"))
            .expect("hard-link fixture");
        let path = tools
            .sandbox
            .relative("alias.txt")
            .expect("valid relative name");
        assert_eq!(
            tools
                .sandbox
                .read_file(&path)
                .expect_err("read is not confined"),
            claw_tools::sandbox::SandboxError::HardLinksForbidden
        );
        assert_eq!(
            tools
                .sandbox
                .write_file(
                    &path,
                    b"must not overwrite",
                    claw_tools::sandbox::WriteMode::Overwrite
                )
                .expect_err("write is not confined"),
            claw_tools::sandbox::SandboxError::HardLinksForbidden
        );
        let request = invocation(
            "fs_write",
            &json!({"path": "alias.txt", "content": "must not overwrite"}),
        );
        let binding = tools
            .binding(&request, &authority)
            .expect("path preparation does not grant file access");
        assert!(
            tools
                .invoke(request, authority, binding, CancellationToken::new())
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(&external).expect("external file"),
            "outside-private-content"
        );
        tools.shutdown().await;
    }

    #[tokio::test]
    async fn native_workspace_denies_wrong_subject_scope_schema_path_and_changed_arguments() {
        let (root, tools, authority) = fixture(true);
        for arguments in [
            json!({"path": "../escape", "content": "bad"}),
            json!({"path": "ok.txt", "content": "bad", "owner": true}),
        ] {
            assert!(
                tools
                    .binding(&invocation("fs_write", &arguments), &authority)
                    .is_err()
            );
        }
        let request = invocation(
            "fs_write",
            &json!({"path": "ok.txt", "content": "approved"}),
        );
        let other = InvocationAuthority::new(
            InvocationSource::Mcp,
            "allowed-device",
            None,
            InvocationAccess::Execute,
            0,
        )
        .expect("other ingress");
        assert!(tools.binding(&request, &other).is_err());
        let binding = tools
            .binding(&request, &authority)
            .expect("approved binding");
        let changed = invocation(
            "fs_write",
            &json!({"path": "changed.txt", "content": "approved"}),
        );
        assert!(
            tools
                .invoke(
                    changed,
                    authority.clone(),
                    binding.clone(),
                    CancellationToken::new()
                )
                .await
                .is_err()
        );
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        assert!(
            tools
                .invoke(request, authority, binding, cancelled)
                .await
                .is_err()
        );
        assert!(!root.0.join("workspace/ok.txt").exists());
        assert!(!root.0.join("workspace/changed.txt").exists());
        tools.shutdown().await;
        let (_root, readonly, authority) = fixture(false);
        assert!(!readonly.contains("fs_write"));
        assert!(
            readonly
                .binding(
                    &invocation("fs_write", &json!({"path": "no.txt", "content": "no"})),
                    &authority
                )
                .is_err()
        );
        readonly.shutdown().await;
    }
}
