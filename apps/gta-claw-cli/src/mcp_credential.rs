use std::ffi::OsString;
use std::fs::File;
use std::io::IsTerminal as _;
use std::path::Path;
use std::time::Duration;

use claw_mcp::{
    client::StdioClientConfig,
    oauth::{CredentialBinding, NativeTokenStatus, NativeTokenStore, TokenStore as _},
};
use claw_provider_sdk::secret::{CredentialKey, SecretStore, SecretString};
use claw_tools::sandbox::{Sandbox, SandboxError, SandboxLimits};
use serde_json::{Value, json};
use tokio::io::AsyncReadExt as _;
use zeroize::Zeroizing;

use super::{ParseFailure, RenderedResult, parse_failure};

#[derive(Clone, Copy)]
enum Action {
    Reference,
    Status,
    Set,
    Delete,
}

impl Action {
    const fn label(self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::Status => "status",
            Self::Set => "set",
            Self::Delete => "delete",
        }
    }
}

pub(super) struct CredentialCommand {
    action: Action,
    reference: String,
    key: CredentialKey,
    oauth_binding: Option<Box<CredentialBinding>>,
}

#[derive(Clone, Copy, Debug)]
struct Failure {
    message: &'static str,
    may_have_changed: bool,
}

pub(super) struct OAuthProfileLock {
    _file: File,
    _directory: Sandbox,
}

impl OAuthProfileLock {
    pub(super) fn acquire(binding: &CredentialBinding) -> Result<Self, &'static str> {
        let directory = claw_platform::identity::native_lock_directory()
            .map_err(|_| "OAuth coordination directory is unavailable or unsafe")?;
        Self::at(binding, &directory)
    }

    fn at(binding: &CredentialBinding, directory: &Path) -> Result<Self, &'static str> {
        let unavailable = "OAuth profile is busy or its coordination path is unsafe";
        if !directory.is_absolute() {
            return Err(unavailable);
        }
        let directory = Sandbox::new_pinned(
            directory,
            SandboxLimits {
                max_file_bytes: 0,
                ..SandboxLimits::default()
            },
        )
        .map_err(|_| unavailable)?;
        let reference = NativeTokenStore::keyring_reference(binding);
        let account = reference.rsplit('/').next().ok_or(unavailable)?;
        let relative = directory
            .relative(&format!("mcp-oauth-{account}.lock"))
            .map_err(|_| unavailable)?;
        match directory.create_new_file(&relative) {
            Ok(file) => drop(file),
            Err(SandboxError::AlreadyExists) => {}
            Err(_) => return Err(unavailable),
        }
        let resolved = directory.resolve_file(&relative).map_err(|_| unavailable)?;
        let file = directory
            .open_existing_for_coordination(&resolved)
            .map_err(|_| unavailable)?;
        file.try_lock().map_err(|_| unavailable)?;
        if file.metadata().map_err(|_| unavailable)?.len() != 0 {
            return Err(unavailable);
        }
        directory.validate_root().map_err(|_| unavailable)?;
        Ok(Self {
            _file: file,
            _directory: directory,
        })
    }
}

pub(super) fn parse(arguments: &[OsString]) -> Result<CredentialCommand, ParseFailure> {
    let oauth = arguments.get(1).and_then(|value| value.to_str()) == Some("oauth");
    let invalid = || {
        parse_failure(
            if oauth {
                "expected mcp oauth <reference|status|logout> --server <id> --endpoint <url>; logout requires --confirm-logout"
            } else {
                "expected mcp credential <reference|status|set|delete> --server <id> with --endpoint <url> or --program-sha256 <sha256> --environment-name <name>; set requires --token-stdin --confirm-write, delete requires --confirm-delete"
            },
            arguments,
        )
    };
    if !oauth && arguments.get(1).and_then(|value| value.to_str()) != Some("credential") {
        return Err(invalid());
    }
    let action = match arguments.get(2).and_then(|value| value.to_str()) {
        Some("reference") => Action::Reference,
        Some("status") => Action::Status,
        Some("set") if !oauth => Action::Set,
        Some("delete") if !oauth => Action::Delete,
        Some("logout") if oauth => Action::Delete,
        _ => return Err(invalid()),
    };
    let mut server = None;
    let mut endpoint = None;
    let mut program_sha256 = None;
    let mut environment_name = None;
    let mut stdin = false;
    let mut write = false;
    let mut delete = false;
    let mut json_seen = false;
    let mut index = 3;
    while index < arguments.len() {
        match arguments[index].to_str() {
            Some("--server") if server.is_none() => {
                server = Some(
                    arguments
                        .get(index + 1)
                        .and_then(|value| value.to_str())
                        .ok_or_else(invalid)?,
                );
                index += 2;
            }
            Some("--endpoint") if endpoint.is_none() => {
                endpoint = Some(
                    arguments
                        .get(index + 1)
                        .and_then(|value| value.to_str())
                        .ok_or_else(invalid)?,
                );
                index += 2;
            }
            Some("--program-sha256") if program_sha256.is_none() => {
                program_sha256 = Some(
                    arguments
                        .get(index + 1)
                        .and_then(|value| value.to_str())
                        .ok_or_else(invalid)?,
                );
                index += 2;
            }
            Some("--environment-name") if environment_name.is_none() => {
                environment_name = Some(
                    arguments
                        .get(index + 1)
                        .and_then(|value| value.to_str())
                        .ok_or_else(invalid)?,
                );
                index += 2;
            }
            Some("--token-stdin") if !stdin => {
                stdin = true;
                index += 1;
            }
            Some("--confirm-write") if !write => {
                write = true;
                index += 1;
            }
            Some("--confirm-delete") if !delete && !oauth => {
                delete = true;
                index += 1;
            }
            Some("--confirm-logout") if !delete && oauth => {
                delete = true;
                index += 1;
            }
            Some("--json") if !json_seen => {
                json_seen = true;
                index += 1;
            }
            _ => return Err(invalid()),
        }
    }
    let server = server
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
        .ok_or_else(invalid)?;
    let valid_flags = match action {
        Action::Reference | Action::Status => !stdin && !write && !delete,
        Action::Set => stdin && write && !delete,
        Action::Delete => delete && !stdin && !write,
    };
    if !valid_flags {
        return Err(invalid());
    }
    let mut oauth_binding = None;
    let (reference, service) = match (endpoint, program_sha256, environment_name) {
        (Some(endpoint), None, None) => {
            if endpoint.len() > 2048
                || endpoint.contains('\\')
                || endpoint
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
            {
                return Err(invalid());
            }
            let endpoint = url::Url::parse(endpoint).map_err(|_| invalid())?;
            if !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
            {
                return Err(invalid());
            }
            match endpoint.scheme() {
                "http" => {
                    claw_mcp::HttpRoutePolicy::direct_loopback(endpoint.clone())
                        .map_err(|_| invalid())?;
                }
                "https" => {
                    let host = endpoint.host_str().ok_or_else(invalid)?;
                    let port = endpoint.port_or_known_default().ok_or_else(invalid)?;
                    claw_tools::net::UrlPolicy::exact_hosts([host])
                        .map_err(|_| invalid())?
                        .with_allowed_ports([port])
                        .validate(endpoint.as_str())
                        .map_err(|_| invalid())?;
                }
                _ => return Err(invalid()),
            }
            let binding = CredentialBinding::new(server, &endpoint).map_err(|_| invalid())?;
            if oauth {
                let reference = NativeTokenStore::keyring_reference(&binding);
                oauth_binding = Some(Box::new(binding));
                (reference, "gta-claw.mcp-oauth")
            } else {
                (binding.keyring_reference(), "gta-claw.mcp-outbound")
            }
        }
        (None, Some(sha256), Some(name)) if !oauth => (
            StdioClientConfig::keyring_reference(server, sha256, name).map_err(|_| invalid())?,
            "gta-claw.mcp-stdio",
        ),
        _ => return Err(invalid()),
    };
    let account = reference
        .strip_prefix(&format!("keyring://{service}/"))
        .ok_or_else(invalid)?;
    let key = CredentialKey::new(service, account).map_err(|_| invalid())?;
    Ok(CredentialCommand {
        action,
        reference,
        key,
        oauth_binding,
    })
}

fn parse_token(bytes: &[u8]) -> Result<SecretString, Failure> {
    let invalid = || Failure {
        message: "token must be one nonblank UTF-8 line of 16 through 4096 bytes",
        may_have_changed: false,
    };
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if !(16..=4096).contains(&text.len())
        || text.trim() != text
        || text.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    Ok(SecretString::new(text))
}

fn perform(
    command: &CredentialCommand,
    token: Option<SecretString>,
    store: &dyn SecretStore,
) -> Result<Value, Failure> {
    let failure = |message, may_have_changed| Failure {
        message,
        may_have_changed,
    };
    let mut result = json!({"schema_version":1,"method":format!("mcp.credential.{}", command.action.label()),
        "ok":true,"tokenRef":command.reference,"backend":store.backend(),"credentialsIncluded":false,"networkContacted":false,"automaticRetry":false});
    match command.action {
        Action::Reference => {}
        Action::Status => {
            result["present"] = json!(
                store
                    .get(&command.key)
                    .map_err(|_| failure("native credential status is unavailable", false))?
                    .is_some()
            );
        }
        Action::Set => {
            let token = token.ok_or_else(|| failure("credential input is absent", false))?;
            if command.key.service() == "gta-claw.mcp-stdio" && token.len() > 2048 {
                return Err(failure(
                    "stdio environment credential exceeds 2048 bytes",
                    false,
                ));
            }
            store.set(&command.key, &token).map_err(|_| {
                failure(
                    "native credential write was not confirmed; inspect status before retrying",
                    true,
                )
            })?;
            let observed = store.get(&command.key).map_err(|_| {
                failure(
                    "credential write readback failed; do not retry automatically",
                    true,
                )
            })?;
            if observed.as_ref() != Some(&token) {
                return Err(failure(
                    "credential changed during write verification; do not retry automatically",
                    true,
                ));
            }
            result["present"] = json!(true);
            result["verifiedReadback"] = json!(true);
            result["atomicCompareAndSwap"] = json!(false);
        }
        Action::Delete => {
            let removed = store.delete(&command.key).map_err(|_| {
                failure(
                    "native credential deletion was not confirmed; inspect status before retrying",
                    true,
                )
            })?;
            if store
                .get(&command.key)
                .map_err(|_| failure("credential deletion readback failed", true))?
                .is_some()
            {
                return Err(failure(
                    "credential reappeared during deletion verification; do not retry automatically",
                    true,
                ));
            }
            result["removed"] = json!(removed);
            result["present"] = json!(false);
            result["atomicCompareAndSwap"] = json!(false);
        }
    }
    Ok(result)
}

fn native_store() -> Result<Box<dyn SecretStore>, Failure> {
    #[cfg(target_os = "windows")]
    let store = claw_provider_sdk::secret::WindowsCredentialManagerStore::new()
        .map(|store| Box::new(store) as Box<dyn SecretStore>);
    #[cfg(target_os = "macos")]
    let store = claw_provider_sdk::secret::AppleKeychainStore::new()
        .map(|store| Box::new(store) as Box<dyn SecretStore>);
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        store.map_err(|_| Failure {
            message: "native credential store is unavailable; no fallback is allowed",
            may_have_changed: false,
        })
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Err(Failure {
            message: "native MCP credential management is unsupported on this platform",
            may_have_changed: false,
        })
    }
}

fn render_failure(error: Failure) -> RenderedResult {
    render_failure_for("mcp.credential", error)
}

fn render_failure_for(method: &'static str, error: Failure) -> RenderedResult {
    RenderedResult {
        exit_code: 2,
        stdout: format!(
            "{}\n",
            json!({"schema_version":1,"method":method,"ok":false,
        "credentialsIncluded":false,"networkContacted":false,"automaticRetry":false,"mayHaveChanged":error.may_have_changed,
        "error":{"code":"credential_refused","message":error.message}})
        ),
        stderr: String::new(),
    }
}

fn oauth_status(status: NativeTokenStatus) -> Value {
    match status {
        NativeTokenStatus::Absent => json!({"state":"absent"}),
        NativeTokenStatus::ReauthorizationRequired => json!({"state":"reauthorization_required"}),
        NativeTokenStatus::Available {
            fresh,
            can_refresh,
            expiry_known,
        } => {
            json!({"state":"available","fresh":fresh,"refreshAvailable":can_refresh,"expiryKnown":expiry_known})
        }
    }
}

async fn run_oauth(action: Action, binding: CredentialBinding) -> RenderedResult {
    let reference = NativeTokenStore::keyring_reference(&binding);
    if matches!(action, Action::Reference) {
        return RenderedResult::success(format!(
            "{}\n",
            json!({"schema_version":1,"method":"mcp.oauth.reference","ok":true,
            "credentialRef":reference,"credentialsIncluded":false,"networkContacted":false,"storeAccessed":false})
        ));
    }
    let may_have_changed = matches!(action, Action::Delete);
    let result = tokio::task::spawn_blocking(move || {
        let _profile_lock = if may_have_changed {
            Some(OAuthProfileLock::acquire(&binding).map_err(|message| Failure { message, may_have_changed: false })?)
        } else { None };
        let store = NativeTokenStore::new().map_err(|_| Failure { message: "native OAuth storage is unavailable; no fallback is allowed", may_have_changed: false })?;
        let record = match action {
            Action::Status => store.status(&binding).map_err(|_| Failure { message: "native OAuth record is unavailable or invalid", may_have_changed: false })?,
            Action::Delete => {
                store.delete(&binding).map_err(|_| Failure { message: "local OAuth logout was not confirmed; do not retry automatically", may_have_changed: true })?;
                NativeTokenStatus::Absent
            }
            Action::Reference | Action::Set => return Err(Failure { message: "OAuth tokens cannot be provisioned as raw credentials", may_have_changed: false }),
        };
        Ok::<_, Failure>(json!({"schema_version":1,"method":if may_have_changed { "mcp.oauth.logout" } else { "mcp.oauth.status" },"ok":true,
            "credentialRef":reference,"record":oauth_status(record),"credentialsIncluded":false,"networkContacted":false,"storeAccessed":true,
            "remoteAuthenticationVerified":false,"remoteRevoked":false,"daemonNotified":false,"automaticRetry":false,"atomicCompareAndSwap":false,"cooperatingCliExclusive":may_have_changed}))
    }).await;
    match result {
        Ok(Ok(value)) => RenderedResult::success(format!("{value}\n")),
        Ok(Err(error)) => render_failure_for("mcp.oauth", error),
        Err(_) => render_failure_for(
            "mcp.oauth",
            Failure {
                message: "native OAuth worker ended without a confirmed result",
                may_have_changed,
            },
        ),
    }
}

pub(super) async fn run(mut command: CredentialCommand) -> RenderedResult {
    if let Some(binding) = command.oauth_binding.take() {
        return run_oauth(command.action, *binding).await;
    }
    if matches!(command.action, Action::Reference) {
        return RenderedResult::success(format!(
            "{}\n",
            json!({"schema_version":1,"method":"mcp.credential.reference","ok":true,
            "tokenRef":command.reference,"credentialsIncluded":false,"networkContacted":false,"storeAccessed":false})
        ));
    }
    let token = if matches!(command.action, Action::Set) {
        if std::io::stdin().is_terminal() {
            return render_failure(Failure {
                message: "credential input requires a protected pipe, not an echoing terminal",
                may_have_changed: false,
            });
        }
        let mut bytes = Zeroizing::new(Vec::new());
        let read = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::io::stdin().take(4099).read_to_end(&mut bytes),
        )
        .await;
        if !matches!(read, Ok(Ok(_))) || bytes.len() > 4098 {
            return render_failure(Failure {
                message: "token stdin must end within 30 seconds and 4098 bytes",
                may_have_changed: false,
            });
        }
        match parse_token(&bytes) {
            Ok(token) => Some(token),
            Err(error) => return render_failure(error),
        }
    } else {
        None
    };
    match tokio::task::spawn_blocking(move || perform(&command, token, native_store()?.as_ref()))
        .await
    {
        Ok(Ok(value)) => RenderedResult::success(format!("{value}\n")),
        Ok(Err(error)) => render_failure(error),
        Err(_) => render_failure(Failure {
            message: "credential worker ended without a confirmed result; do not retry automatically",
            may_have_changed: true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claw_provider_sdk::secret::{MemorySecretStore, SecretStoreError};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn args(action: &str) -> Vec<OsString> {
        [
            "mcp",
            "credential",
            action,
            "--server",
            "fixture",
            "--endpoint",
            "http://127.0.0.1:32109/mcp",
        ]
        .into_iter()
        .map(Into::into)
        .collect()
    }

    #[test]
    fn oauth_profile_coordination_is_nonblocking_origin_bound_and_rejects_replaced_files() {
        struct Root(std::path::PathBuf);
        impl Drop for Root {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Root(std::env::temp_dir().join(format!(
                "claw-oauth-lock-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir(&root.0).expect("owned directory");
        let endpoint = url::Url::parse("http://127.0.0.1:32109/mcp").expect("endpoint");
        let binding = CredentialBinding::new("fixture", &endpoint).expect("binding");
        let held = OAuthProfileLock::at(&binding, &root.0).expect("first lock");
        assert!(OAuthProfileLock::at(&binding, &root.0).is_err());
        let same_origin =
            CredentialBinding::new("fixture", &endpoint.join("/other").expect("other path"))
                .expect("same origin");
        assert!(OAuthProfileLock::at(&same_origin, &root.0).is_err());
        let other = CredentialBinding::new("other", &endpoint).expect("other profile");
        assert!(OAuthProfileLock::at(&other, &root.0).is_ok());
        let reference = NativeTokenStore::keyring_reference(&binding);
        let lock_path = root.0.join(format!(
            "mcp-oauth-{}.lock",
            reference.rsplit('/').next().expect("account")
        ));
        assert_eq!(
            std::fs::metadata(&lock_path)
                .expect("empty lock file")
                .len(),
            0
        );
        #[cfg(windows)]
        {
            assert!(std::fs::rename(&lock_path, root.0.join("moved.lock")).is_err());
            assert!(std::fs::rename(&root.0, root.0.with_extension("moved")).is_err());
        }
        drop(held);
        assert!(OAuthProfileLock::at(&binding, &root.0).is_ok());
        std::fs::write(&lock_path, b"not-empty").expect("owned corruption fixture");
        assert!(OAuthProfileLock::at(&binding, &root.0).is_err());
        std::fs::remove_file(&lock_path).expect("owned corruption cleanup");
        let other_file = root.0.join("unrelated-file");
        std::fs::write(&other_file, b"").expect("owned link target");
        std::fs::hard_link(&other_file, &lock_path).expect("owned hard link fixture");
        assert!(OAuthProfileLock::at(&binding, &root.0).is_err());
        assert!(OAuthProfileLock::at(&binding, Path::new("relative")).is_err());
    }

    #[test]
    fn oauth_commands_use_a_separate_namespace_and_require_explicit_local_logout() {
        let arguments = |action: &str| {
            let mut arguments = args(action);
            arguments[1] = "oauth".into();
            arguments
        };
        let command = parse(&arguments("reference"))
            .ok()
            .expect("OAuth reference");
        assert!(command.oauth_binding.is_some());
        assert!(
            command
                .reference
                .starts_with("keyring://gta-claw.mcp-oauth/")
        );
        assert_ne!(
            command.reference,
            parse(&args("reference"))
                .ok()
                .expect("static reference")
                .reference
        );
        assert!(parse(&arguments("status")).is_ok());
        assert!(parse(&arguments("set")).is_err());
        assert!(parse(&arguments("delete")).is_err());
        assert!(parse(&arguments("logout")).is_err());
        let mut logout = arguments("logout");
        logout.push("--confirm-logout".into());
        assert!(parse(&logout).is_ok());
        for flag in [
            "--confirm-delete",
            "--token-stdin",
            "--confirm-write",
            "--confirm-logout",
        ] {
            let mut invalid = logout.clone();
            invalid.push(flag.into());
            assert!(parse(&invalid).is_err());
        }
        let mut stdio = arguments("reference");
        stdio.truncate(5);
        stdio.extend(
            [
                "--program-sha256",
                &"a".repeat(64),
                "--environment-name",
                "API_TOKEN",
            ]
            .into_iter()
            .map(OsString::from),
        );
        assert!(parse(&stdio).is_err());
        assert_eq!(oauth_status(NativeTokenStatus::Absent)["state"], "absent");
        assert_eq!(
            oauth_status(NativeTokenStatus::ReauthorizationRequired)["state"],
            "reauthorization_required"
        );
        let available = oauth_status(NativeTokenStatus::Available {
            fresh: false,
            can_refresh: true,
            expiry_known: true,
        });
        assert_eq!(
            available,
            json!({"state":"available","fresh":false,"refreshAvailable":true,"expiryKnown":true})
        );
    }

    #[test]
    fn credential_commands_require_bound_targets_and_explicit_stdin_mutation_flags() {
        assert!(parse(&args("reference")).is_ok());
        assert!(parse(&args("status")).is_ok());
        assert!(parse(&args("set")).is_err());
        assert!(parse(&args("delete")).is_err());
        let mut set = args("set");
        set.extend(
            ["--token-stdin", "--confirm-write"]
                .into_iter()
                .map(OsString::from),
        );
        assert!(parse(&set).is_ok());
        let mut delete = args("delete");
        delete.push("--confirm-delete".into());
        assert!(parse(&delete).is_ok());
        for flag in [
            "--token",
            "--token-file",
            "--request-stdin",
            "--confirm-delete",
            "--token-stdin",
        ] {
            let mut invalid = set.clone();
            invalid.push(flag.into());
            assert!(parse(&invalid).is_err());
        }
        for endpoint in [
            "http://remote.example/mcp",
            "http://localhost/mcp",
            "https://127.0.0.1/mcp",
            "https://secret@remote.example/mcp",
            "https://remote.example/mcp?token=secret",
            "https://169.254.169.254/mcp",
        ] {
            let mut invalid = args("reference");
            invalid[6] = endpoint.into();
            assert!(parse(&invalid).is_err());
        }
        for token in [
            b"too-short".as_slice(),
            b"private-token-example\nsecond",
            b" private-token-example",
            b"private-token-example\0",
            &[0xff; 32],
        ] {
            assert!(parse_token(token).is_err());
        }
        assert!(parse_token(b"private-token-example\r\n").is_ok());
        assert!(parse_token(&vec![b'a'; 4097]).is_err());
        let first = parse(&args("reference")).ok().expect("reference");
        let mut same_origin = args("reference");
        same_origin[6] = "http://127.0.0.1:32109/other".into();
        assert_eq!(
            first.reference,
            parse(&same_origin).ok().expect("same origin").reference
        );
        assert_eq!(
            first.reference,
            CredentialBinding::new(
                "fixture",
                &url::Url::parse("http://127.0.0.1:32109/mcp").expect("endpoint")
            )
            .expect("binding")
            .keyring_reference()
        );
    }

    #[test]
    fn mcp_credential_stdio_targets_use_the_exact_sdk_binding_and_smaller_secret_limit() {
        let sha256 = "a".repeat(64);
        let stdio = |action: &str| {
            [
                "mcp",
                "credential",
                action,
                "--server",
                "fixture",
                "--program-sha256",
                &sha256,
                "--environment-name",
                "API_TOKEN",
            ]
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
        };
        let command = parse(&stdio("reference")).ok().expect("stdio reference");
        assert_eq!(
            command.reference,
            StdioClientConfig::keyring_reference("fixture", &sha256, "API_TOKEN")
                .expect("SDK binding")
        );
        assert_eq!(command.key.service(), "gta-claw.mcp-stdio");
        assert_ne!(
            command.reference,
            parse(&args("reference"))
                .ok()
                .expect("HTTP reference")
                .reference
        );
        for extra in [
            vec!["--endpoint", "http://127.0.0.1/mcp"],
            vec!["--program-sha256", &sha256],
            vec!["--environment-name", "OTHER"],
        ] {
            let mut invalid = stdio("reference");
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid).is_err());
        }
        assert!(parse(&stdio("reference")[..7]).is_err());
        let mut set = stdio("set");
        set.extend(
            ["--token-stdin", "--confirm-write"]
                .into_iter()
                .map(OsString::from),
        );
        let command = parse(&set).ok().expect("stdio set");
        let store = FixtureStore::new(StoreFault::None);
        let oversized = parse_token(&vec![b'a'; 2049]).expect("valid UTF-8 stdin");
        let error =
            perform(&command, Some(oversized), &store).expect_err("stdio bound before writing");
        assert!(!error.may_have_changed);
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
        assert!(
            perform(
                &command,
                Some(parse_token(&vec![b'a'; 2048]).expect("valid boundary")),
                &store
            )
            .is_ok()
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mcp_credential_rejects_duplicate_and_non_utf8_option_values() {
        for extra in [
            vec!["--server", "other"],
            vec!["--endpoint", "https://fixture.example/mcp"],
            vec!["--json", "--json"],
        ] {
            let mut arguments = args("status");
            arguments.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&arguments).is_err());
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt as _;
            for flag in ["--server", "--endpoint"] {
                let mut arguments = args("status");
                arguments.splice(3..3, [OsString::from(flag), OsString::from_wide(&[0xd800])]);
                assert!(parse(&arguments).is_err());
            }
        }
        assert!(parse_token(&[b'a'; 16]).is_ok());
        assert!(parse_token(&[b'a'; 4096]).is_ok());
        assert!(parse_token(&[b'a'; 15]).is_err());
    }

    #[derive(Clone, Copy, Debug)]
    enum StoreFault {
        None,
        ReadDenied,
        SetDenied,
        DeleteDenied,
        ReadbackDenied,
        ReadbackChanged,
        DeleteReplaced,
    }

    #[derive(Debug)]
    struct FixtureStore {
        inner: MemorySecretStore,
        fault: StoreFault,
        writes: AtomicUsize,
        deletes: AtomicUsize,
        reads: AtomicUsize,
    }

    impl FixtureStore {
        fn new(fault: StoreFault) -> Self {
            Self {
                inner: MemorySecretStore::new(),
                fault,
                writes: AtomicUsize::new(0),
                deletes: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
            }
        }

        fn error() -> SecretStoreError {
            SecretStoreError::Backend {
                backend: "fixture",
                detail: "mcp-cli-private-token-error",
            }
        }
    }

    impl SecretStore for FixtureStore {
        fn backend(&self) -> &'static str {
            "fixture"
        }

        fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, SecretStoreError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let writes = self.writes.load(Ordering::SeqCst);
            let deletes = self.deletes.load(Ordering::SeqCst);
            match self.fault {
                StoreFault::ReadDenied => Err(Self::error()),
                StoreFault::ReadbackDenied if writes + deletes > 0 => Err(Self::error()),
                StoreFault::ReadbackChanged if writes > 0 => {
                    Ok(Some(SecretString::new("mcp-cli-private-token-replaced")))
                }
                StoreFault::DeleteReplaced if deletes > 0 => {
                    Ok(Some(SecretString::new("mcp-cli-private-token-replaced")))
                }
                _ => self.inner.get(key),
            }
        }

        fn set(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), SecretStoreError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.inner.set(key, secret)?;
            if matches!(self.fault, StoreFault::SetDenied) {
                return Err(Self::error());
            }
            Ok(())
        }

        fn delete(&self, key: &CredentialKey) -> Result<bool, SecretStoreError> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            let removed = self.inner.delete(key)?;
            if matches!(self.fault, StoreFault::DeleteDenied) {
                return Err(Self::error());
            }
            Ok(removed)
        }
    }

    #[test]
    fn mcp_credential_changes_verify_readback_without_secret_output_or_retries() {
        let mut command = parse(&args("status")).ok().expect("status command");
        let store = FixtureStore::new(StoreFault::None);
        assert_eq!(
            perform(&command, None, &store).expect("absent status")["present"],
            false
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
        assert_eq!(store.deletes.load(Ordering::SeqCst), 0);
        command.action = Action::Set;
        let token = SecretString::new("mcp-cli-private-token-initial");
        let result = perform(&command, Some(token.clone()), &store).expect("set credential");
        assert_eq!(result["verifiedReadback"], true);
        assert_eq!(result["atomicCompareAndSwap"], false);
        assert!(!result.to_string().contains("mcp-cli-private-token"));
        assert_eq!(
            store.inner.get(&command.key).expect("stored value"),
            Some(token)
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 1);
        command.action = Action::Delete;
        assert_eq!(
            perform(&command, None, &store).expect("delete")["removed"],
            true
        );
        assert_eq!(
            perform(&command, None, &store).expect("already absent")["removed"],
            false
        );
        assert!(store.inner.is_empty());
    }

    #[test]
    fn mcp_credential_unknown_mutations_never_retry_or_roll_back_external_values() {
        for (fault, action) in [
            (StoreFault::ReadDenied, Action::Status),
            (StoreFault::SetDenied, Action::Set),
            (StoreFault::ReadbackDenied, Action::Set),
            (StoreFault::ReadbackChanged, Action::Set),
            (StoreFault::DeleteDenied, Action::Delete),
            (StoreFault::ReadbackDenied, Action::Delete),
            (StoreFault::DeleteReplaced, Action::Delete),
        ] {
            let mut command = parse(&args("status")).ok().expect("bound command");
            command.action = action;
            let store = FixtureStore::new(fault);
            let token = matches!(action, Action::Set)
                .then(|| SecretString::new("mcp-cli-private-token-initial"));
            let error = perform(&command, token, &store).expect_err("unconfirmed operation");
            assert_eq!(error.may_have_changed, !matches!(action, Action::Status));
            let rendered = render_failure(error);
            assert_eq!(rendered.exit_code, 2);
            assert!(rendered.stderr.is_empty());
            assert!(!rendered.stdout.contains("mcp-cli-private-token"));
            let value: Value = serde_json::from_str(&rendered.stdout).expect("error metadata");
            assert_eq!(value["automaticRetry"], false);
            assert_eq!(value["networkContacted"], false);
            assert_eq!(
                store.writes.load(Ordering::SeqCst),
                usize::from(matches!(action, Action::Set))
            );
            assert_eq!(
                store.deletes.load(Ordering::SeqCst),
                usize::from(matches!(action, Action::Delete))
            );
            assert_eq!(
                store.reads.load(Ordering::SeqCst),
                usize::from(!matches!(
                    fault,
                    StoreFault::SetDenied | StoreFault::DeleteDenied
                ))
            );
        }
    }
}
