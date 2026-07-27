//! Host-side implementations of every import in the plugin world.
//!
//! Each function follows the same shape:
//!
//! 1. [`PluginState::enter`] proves the capability was granted, the call is
//!    inside the wall-clock budget and a host-call slot is free.
//! 2. The arguments are validated against the *grant's* scope, not just
//!    against the capability. A granted capability with a narrower scope still
//!    refuses out-of-scope calls.
//! 3. Only then is the embedder's service reached.
//!
//! Every refusal is recorded in the instance audit log before it is turned
//! into `permission-denied` (or a trap, under [`crate::ViolationPolicy::Trap`]).

use std::path::{Path, PathBuf};

use claw_plugin_api::capability::{
    Capability, CapabilityDenial, ConfigScope, HttpMethod, MAX_KEY_LEN, host_matches,
    join_under_root, validate_key, validate_relative_path,
};
use claw_security::ssrf::{TargetPolicy, ValidatedTarget, validate_redirect, validate_target};

use crate::bindings::gta_claw::plugin::types::{Error as WitError, ErrorCode, Event as WitEvent};
use crate::bindings::gta_claw::plugin::{
    host_clock, host_config, host_events, host_fs, host_http, host_log, host_random, host_store,
    host_tools, types,
};
use crate::convert::{event_kind_from_wit, level_from_wit};
use crate::services::{HostEvent, InboundResponse, LogRecord, OutboundRequest, ToolRegistration};
use crate::state::{PluginState, wit_error};

/// Headers a plugin may never set, because the host owns them.
const FORBIDDEN_HEADERS: [&str; 8] = [
    "authorization",
    "connection",
    "cookie",
    "host",
    "proxy-authorization",
    "te",
    "transfer-encoding",
    "upgrade",
];

/// How many `Location` hops the host will follow before giving up.
///
/// Each hop is a full re-validation, so this is a cost bound rather than a
/// safety bound, but it also stops a redirect loop from occupying a host-call
/// slot indefinitely.
const MAX_HTTP_REDIRECTS: u32 = 3;

type HostResult<T> = wasmtime::Result<Result<T, WitError>>;

impl types::Host for PluginState {}

impl host_log::Host for PluginState {
    fn log(&mut self, lvl: host_log::Level, message: String) -> HostResult<()> {
        let permit = match self.enter(Capability::Log, "log") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let level = level_from_wit(lvl);
        let Some(grant) = self.capabilities().log().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(Capability::Log, "log"));
        };
        if level < grant.min_level {
            drop(permit);
            return self.deny(CapabilityDenial::out_of_scope(
                Capability::Log,
                "log",
                format!(
                    "severity {level:?} is below the granted floor {:?}",
                    grant.min_level
                ),
            ));
        }
        let ceiling = grant.max_message_bytes.min(self.limits().max_payload_bytes);
        let ceiling = usize::try_from(ceiling).unwrap_or(usize::MAX);
        let message = truncate_utf8(&message, ceiling);
        self.services().logs.record(LogRecord {
            plugin_id: self.plugin_id().to_owned(),
            level,
            message,
        });
        drop(permit);
        Ok(Ok(()))
    }
}

impl host_config::Host for PluginState {
    fn get(&mut self, key: String) -> HostResult<Option<String>> {
        let permit = match self.enter(Capability::Config, "get") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        if let Err(reason) = validate_key(&key) {
            drop(permit);
            return self.deny(CapabilityDenial::invalid_argument(
                Capability::Config,
                "get",
                reason,
            ));
        }
        let Some(grant) = self.capabilities().config().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(Capability::Config, "get"));
        };
        if let ConfigScope::Keys(keys) = &grant.scope
            && !keys.contains(&key)
        {
            drop(permit);
            return self.deny(CapabilityDenial::out_of_scope(
                Capability::Config,
                "get",
                format!("key `{key}` is not in the granted key list"),
            ));
        }
        let value = self.services().config.get(self.plugin_id(), &key);
        drop(permit);
        Ok(Ok(value))
    }

    fn list_keys(&mut self) -> HostResult<Vec<String>> {
        let permit = match self.enter(Capability::Config, "list-keys") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let Some(grant) = self.capabilities().config().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(
                Capability::Config,
                "list-keys",
            ));
        };
        let mut keys = self.services().config.keys(self.plugin_id());
        if let ConfigScope::Keys(allowed) = &grant.scope {
            keys.retain(|key| allowed.contains(key));
        }
        keys.sort_unstable();
        keys.dedup();
        drop(permit);
        Ok(Ok(keys))
    }
}

impl host_store::Host for PluginState {
    fn get(&mut self, key: String) -> HostResult<Option<Vec<u8>>> {
        let permit = match self.enter(Capability::Store, "get") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        if let Err(reason) = validate_key(&key) {
            drop(permit);
            return self.deny(CapabilityDenial::invalid_argument(
                Capability::Store,
                "get",
                reason,
            ));
        }
        let value = self.services().store.get(self.plugin_id(), &key);
        drop(permit);
        Ok(Ok(value))
    }

    fn set(&mut self, key: String, value: Vec<u8>) -> HostResult<()> {
        let permit = match self.enter(Capability::Store, "set") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        if let Err(reason) = validate_key(&key) {
            drop(permit);
            return self.deny(CapabilityDenial::invalid_argument(
                Capability::Store,
                "set",
                reason,
            ));
        }
        let Some(grant) = self.capabilities().store().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(Capability::Store, "set"));
        };
        let value_len = value.len() as u64;
        if value_len > u64::from(grant.max_value_bytes) {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::Store,
                "set",
                format!(
                    "value is {value_len} bytes, the grant allows {}",
                    grant.max_value_bytes
                ),
            ));
        }
        if value_len > u64::from(self.limits().max_payload_bytes) {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::Store,
                "set",
                format!(
                    "value is {value_len} bytes, the host payload limit is {}",
                    self.limits().max_payload_bytes
                ),
            ));
        }
        let plugin_id = self.plugin_id().to_owned();
        let existing = self.services().store.get(&plugin_id, &key);
        let existing_len = existing.as_ref().map_or(0, |bytes| bytes.len() as u64);
        let total = self
            .services()
            .store
            .total_bytes(&plugin_id)
            .saturating_sub(existing_len)
            .saturating_add(value_len);
        if total > grant.max_total_bytes {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::Store,
                "set",
                format!(
                    "the write would take the store to {total} bytes, the grant allows {}",
                    grant.max_total_bytes
                ),
            ));
        }
        if existing.is_none() {
            let keys = self.services().store.key_count(&plugin_id);
            if keys >= grant.max_keys {
                drop(permit);
                return self.deny(CapabilityDenial::quota_exceeded(
                    Capability::Store,
                    "set",
                    format!("the grant allows at most {} keys", grant.max_keys),
                ));
            }
        }
        self.services().store.set(&plugin_id, &key, value);
        drop(permit);
        Ok(Ok(()))
    }

    fn delete(&mut self, key: String) -> HostResult<bool> {
        let permit = match self.enter(Capability::Store, "delete") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        if let Err(reason) = validate_key(&key) {
            drop(permit);
            return self.deny(CapabilityDenial::invalid_argument(
                Capability::Store,
                "delete",
                reason,
            ));
        }
        let removed = self.services().store.delete(self.plugin_id(), &key);
        drop(permit);
        Ok(Ok(removed))
    }
}

/// Resolves a guest path under one of `roots` and proves containment twice:
/// lexically before touching the filesystem and again after canonicalisation.
fn resolve_under_roots(roots: &[PathBuf], relative: &Path) -> Option<PathBuf> {
    for root in roots {
        let joined = join_under_root(root, relative);
        let Ok(canonical) = std::fs::canonicalize(&joined) else {
            continue;
        };
        if canonical.starts_with(root) {
            return Some(canonical);
        }
    }
    None
}

/// Resolves the *parent* of a guest path for writes, where the leaf may not
/// exist yet. The parent must already exist inside a granted root.
fn resolve_parent_under_roots(roots: &[PathBuf], relative: &Path) -> Option<PathBuf> {
    let file_name = relative.file_name()?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    for root in roots {
        let joined = join_under_root(root, parent);
        let Ok(canonical) = std::fs::canonicalize(&joined) else {
            continue;
        };
        if !canonical.starts_with(root) {
            continue;
        }
        let target = canonical.join(file_name);
        // If the leaf already exists it must not be a link out of the root.
        if let Ok(existing) = std::fs::canonicalize(&target)
            && !existing.starts_with(root)
        {
            continue;
        }
        return Some(target);
    }
    None
}

impl host_fs::Host for PluginState {
    fn read_file(&mut self, path: String) -> HostResult<Vec<u8>> {
        let permit = match self.enter(Capability::FilesystemRead, "read-file") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let relative = match validate_relative_path(&path) {
            Ok(relative) => relative,
            Err(reason) => {
                drop(permit);
                return self.deny(CapabilityDenial::invalid_argument(
                    Capability::FilesystemRead,
                    "read-file",
                    reason,
                ));
            }
        };
        let Some(grant) = self.capabilities().filesystem_read().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(
                Capability::FilesystemRead,
                "read-file",
            ));
        };
        let Some(resolved) = resolve_under_roots(self.read_roots(), &relative) else {
            drop(permit);
            return self.deny(CapabilityDenial::out_of_scope(
                Capability::FilesystemRead,
                "read-file",
                format!("`{path}` does not resolve inside a granted read root"),
            ));
        };
        let ceiling = grant
            .max_file_bytes
            .min(u64::from(self.limits().max_payload_bytes));
        match std::fs::metadata(&resolved) {
            Ok(metadata) if metadata.len() > ceiling => {
                drop(permit);
                return self.deny(CapabilityDenial::quota_exceeded(
                    Capability::FilesystemRead,
                    "read-file",
                    format!("`{path}` is larger than the {ceiling} byte limit"),
                ));
            }
            Ok(metadata) if !metadata.is_file() => {
                drop(permit);
                return self.deny(CapabilityDenial::out_of_scope(
                    Capability::FilesystemRead,
                    "read-file",
                    format!("`{path}` is not a regular file"),
                ));
            }
            Ok(_) => {}
            Err(error) => {
                drop(permit);
                return Ok(Err(wit_error(ErrorCode::NotFound, error.to_string())));
            }
        }
        let outcome = std::fs::read(&resolved)
            .map_err(|error| wit_error(ErrorCode::Internal, error.to_string()));
        drop(permit);
        Ok(outcome)
    }

    fn write_file(&mut self, path: String, contents: Vec<u8>) -> HostResult<()> {
        let permit = match self.enter(Capability::FilesystemWrite, "write-file") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let relative = match validate_relative_path(&path) {
            Ok(relative) => relative,
            Err(reason) => {
                drop(permit);
                return self.deny(CapabilityDenial::invalid_argument(
                    Capability::FilesystemWrite,
                    "write-file",
                    reason,
                ));
            }
        };
        let Some(grant) = self.capabilities().filesystem_write().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(
                Capability::FilesystemWrite,
                "write-file",
            ));
        };
        let ceiling = grant
            .max_file_bytes
            .min(u64::from(self.limits().max_payload_bytes));
        if contents.len() as u64 > ceiling {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::FilesystemWrite,
                "write-file",
                format!("{} bytes exceeds the {ceiling} byte limit", contents.len()),
            ));
        }
        let Some(resolved) = resolve_parent_under_roots(self.write_roots(), &relative) else {
            drop(permit);
            return self.deny(CapabilityDenial::out_of_scope(
                Capability::FilesystemWrite,
                "write-file",
                format!("`{path}` does not resolve inside a granted write root"),
            ));
        };
        let outcome = std::fs::write(&resolved, &contents)
            .map_err(|error| wit_error(ErrorCode::Internal, error.to_string()));
        drop(permit);
        Ok(outcome)
    }

    fn list_dir(&mut self, path: String) -> HostResult<Vec<String>> {
        let permit = match self.enter(Capability::FilesystemRead, "list-dir") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let relative = match validate_relative_path(&path) {
            Ok(relative) => relative,
            Err(reason) => {
                drop(permit);
                return self.deny(CapabilityDenial::invalid_argument(
                    Capability::FilesystemRead,
                    "list-dir",
                    reason,
                ));
            }
        };
        if self.capabilities().filesystem_read().is_none() {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(
                Capability::FilesystemRead,
                "list-dir",
            ));
        }
        let Some(resolved) = resolve_under_roots(self.read_roots(), &relative) else {
            drop(permit);
            return self.deny(CapabilityDenial::out_of_scope(
                Capability::FilesystemRead,
                "list-dir",
                format!("`{path}` does not resolve inside a granted read root"),
            ));
        };
        let entries = match std::fs::read_dir(&resolved) {
            Ok(entries) => entries,
            Err(error) => {
                drop(permit);
                return Ok(Err(wit_error(ErrorCode::NotFound, error.to_string())));
            }
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    drop(permit);
                    return Ok(Err(wit_error(ErrorCode::Internal, error.to_string())));
                }
            };
            let Ok(name) = entry.file_name().into_string() else {
                drop(permit);
                return Ok(Err(wit_error(
                    ErrorCode::Unsupported,
                    "directory contains a non-UTF-8 name",
                )));
            };
            names.push(name);
        }
        names.sort_unstable();
        drop(permit);
        Ok(Ok(names))
    }
}

impl host_http::Host for PluginState {
    fn send(&mut self, req: host_http::Request) -> HostResult<host_http::Response> {
        let permit = match self.enter(Capability::Http, "send") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let Some(grant) = self.capabilities().http().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(Capability::Http, "send"));
        };

        let method = req.method.to_ascii_uppercase();
        let allowed = grant
            .methods
            .iter()
            .any(|candidate| HttpMethod::as_str(*candidate) == method);
        if !allowed {
            drop(permit);
            return self.deny(CapabilityDenial::out_of_scope(
                Capability::Http,
                "send",
                format!("method `{method}` is not in the granted method list"),
            ));
        }

        // `claw-security` rejects userinfo, fragments, non-HTTP schemes and any
        // address that is not publicly routable; that check, the grant host
        // allowlist and DNS revalidation all run per hop in `attempt_http`.
        let mut headers = Vec::with_capacity(req.headers.len());
        for (name, value) in req.headers {
            let lowered = name.to_ascii_lowercase();
            if FORBIDDEN_HEADERS.contains(&lowered.as_str()) {
                drop(permit);
                return self.deny(CapabilityDenial::out_of_scope(
                    Capability::Http,
                    "send",
                    format!("header `{lowered}` is owned by the host"),
                ));
            }
            if lowered.is_empty()
                || !lowered.bytes().all(|b| b.is_ascii_graphic() && b != b':')
                || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
            {
                drop(permit);
                return self.deny(CapabilityDenial::invalid_argument(
                    Capability::Http,
                    "send",
                    "header name or value is not a valid HTTP field",
                ));
            }
            headers.push((lowered, value));
        }

        let body_len = req.body.as_ref().map_or(0, Vec::len) as u64;
        if body_len > u64::from(self.limits().max_payload_bytes) {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::Http,
                "send",
                format!(
                    "request body is {body_len} bytes, the host payload limit is {}",
                    self.limits().max_payload_bytes
                ),
            ));
        }

        // Redirects are followed by the host, never by the transport, so that
        // every hop re-runs the whole check chain: scheme, grant allowlist,
        // resolution and address policy. A transport that followed a `Location`
        // itself would be making an unchecked request on the plugin's behalf.
        let mut url = req.url;
        let mut method = method;
        let mut body = req.body;
        let mut hops = 0_u32;
        loop {
            let attempt = match self.attempt_http(&grant, &method, &url, &headers, body.clone()) {
                Ok(Ok(attempt)) => attempt,
                Ok(Err(error)) => {
                    drop(permit);
                    return Ok(Err(error));
                }
                Err(denial) => {
                    drop(permit);
                    return self.deny(denial);
                }
            };
            let Some(location) = redirect_location(&attempt.response) else {
                drop(permit);
                return Ok(Ok(host_http::Response {
                    status: attempt.response.status,
                    headers: attempt.response.headers,
                    body: attempt.response.body,
                }));
            };
            hops += 1;
            if hops > MAX_HTTP_REDIRECTS {
                drop(permit);
                return self.deny(CapabilityDenial::quota_exceeded(
                    Capability::Http,
                    "send",
                    format!("more than {MAX_HTTP_REDIRECTS} redirects"),
                ));
            }
            // Resolving the `Location` against the hop that produced it is what
            // makes a relative redirect unambiguous; `validate_redirect` then
            // re-runs the full target policy on the result.
            let next = match validate_redirect(
                &attempt.target,
                &location,
                &TargetPolicy::PublicInternet,
            ) {
                Ok(next) => next,
                Err(error) => {
                    drop(permit);
                    return self.deny(CapabilityDenial::out_of_scope(
                        Capability::Http,
                        "send",
                        format!("redirect to `{location}` refused: {error}"),
                    ));
                }
            };
            if attempt.response.status == 303 {
                "GET".clone_into(&mut method);
                body = None;
                if !grant
                    .methods
                    .iter()
                    .any(|candidate| HttpMethod::as_str(*candidate) == method)
                {
                    drop(permit);
                    return self.deny(CapabilityDenial::out_of_scope(
                        Capability::Http,
                        "send",
                        "a 303 redirect requires `GET`, which is not in the granted method list",
                    ));
                }
            }
            next.as_str().clone_into(&mut url);
        }
    }
}

/// One completed hop: the target the host actually validated and connected to,
/// paired with the response it produced.
struct HttpAttempt {
    target: ValidatedTarget,
    response: InboundResponse,
}

impl PluginState {
    /// Validates, resolves and issues exactly one hop.
    ///
    /// The outer `Result` separates a capability denial (which the caller must
    /// route through the audit log) from a transport error (which is reported
    /// to the guest as-is).
    fn attempt_http(
        &self,
        grant: &claw_plugin_api::capability::HttpGrant,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
    ) -> Result<Result<HttpAttempt, WitError>, CapabilityDenial> {
        // `claw-security` rejects userinfo, fragments, non-HTTP schemes and any
        // address literal that is not publicly routable, which is what stops a
        // plugin reaching the host's own loopback or link-local services.
        let target = validate_target(url, &TargetPolicy::PublicInternet).map_err(|error| {
            CapabilityDenial::out_of_scope(
                Capability::Http,
                "send",
                format!("target refused: {error}"),
            )
        })?;
        if !grant.allow_plaintext && !target.as_str().starts_with("https://") {
            return Err(CapabilityDenial::out_of_scope(
                Capability::Http,
                "send",
                "plaintext HTTP is not enabled for this plugin",
            ));
        }
        let host = target.host().as_str();
        if !grant
            .hosts
            .iter()
            .any(|pattern| host_matches(pattern, &host))
        {
            return Err(CapabilityDenial::out_of_scope(
                Capability::Http,
                "send",
                format!("host `{host}` is not in the granted host list"),
            ));
        }

        // Resolution happens here, in the host, immediately before the request
        // is issued, and the *addresses* are what the transport is given. A
        // hostile authoritative server can therefore not answer a second,
        // unchecked lookup inside the transport with a loopback or metadata
        // address.
        let addresses = self
            .services()
            .dns
            .resolve(&host, target.port())
            .map_err(|error| {
                CapabilityDenial::out_of_scope(
                    Capability::Http,
                    "send",
                    format!("`{host}` could not be resolved: {error}"),
                )
            })?;
        target.validate_resolution(&addresses).map_err(|error| {
            CapabilityDenial::out_of_scope(
                Capability::Http,
                "send",
                format!("`{host}` resolved to an address that is not reachable: {error}"),
            )
        })?;

        let outbound = OutboundRequest {
            method: method.to_owned(),
            url: target.as_str().to_owned(),
            host,
            port: target.port(),
            addresses,
            headers: headers.to_vec(),
            body,
        };
        let response = match self.services().http.send(self.plugin_id(), outbound) {
            Ok(response) => response,
            Err(message) => return Ok(Err(wit_error(ErrorCode::Internal, message))),
        };
        let response_len = response.body.len() as u64;
        if response_len > grant.max_response_bytes
            || response_len > u64::from(self.limits().max_payload_bytes)
        {
            return Err(CapabilityDenial::quota_exceeded(
                Capability::Http,
                "send",
                format!(
                    "response body is {response_len} bytes, the grant allows {}",
                    grant.max_response_bytes
                ),
            ));
        }
        Ok(Ok(HttpAttempt { target, response }))
    }
}

/// Extracts a redirect destination, if the response is one.
fn redirect_location(response: &InboundResponse) -> Option<String> {
    if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
        .map(|(_, value)| value.clone())
}

impl host_clock::Host for PluginState {
    fn now_ms(&mut self) -> HostResult<u64> {
        let permit = match self.enter(Capability::Clock, "now-ms") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let Some(grant) = self.capabilities().clock().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(Capability::Clock, "now-ms"));
        };
        let raw = self.services().clock.now_ms();
        let resolution = grant.resolution_ms.max(1);
        drop(permit);
        Ok(Ok(raw - (raw % resolution)))
    }

    fn resolution_ms(&mut self) -> HostResult<u64> {
        let permit = match self.enter(Capability::Clock, "resolution-ms") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let Some(grant) = self.capabilities().clock().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(
                Capability::Clock,
                "resolution-ms",
            ));
        };
        drop(permit);
        Ok(Ok(grant.resolution_ms.max(1)))
    }
}

impl host_random::Host for PluginState {
    fn get_bytes(&mut self, len: u32) -> HostResult<Vec<u8>> {
        let permit = match self.enter(Capability::Random, "get-bytes") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let Some(grant) = self.capabilities().random().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(
                Capability::Random,
                "get-bytes",
            ));
        };
        if len > grant.max_bytes_per_call {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::Random,
                "get-bytes",
                format!(
                    "{len} bytes exceeds the {} byte per-call grant",
                    grant.max_bytes_per_call
                ),
            ));
        }
        if len > self.limits().max_payload_bytes {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::Random,
                "get-bytes",
                format!(
                    "{len} bytes exceeds the host payload limit of {}",
                    self.limits().max_payload_bytes
                ),
            ));
        }
        let mut buffer = vec![0_u8; usize::try_from(len).unwrap_or(0)];
        let outcome = self
            .services()
            .random
            .fill(&mut buffer)
            .map(|()| buffer)
            .map_err(|message| wit_error(ErrorCode::Internal, message));
        drop(permit);
        Ok(outcome)
    }
}

impl host_tools::Host for PluginState {
    fn register(&mut self, tool: host_tools::ToolDescriptor) -> HostResult<()> {
        let permit = match self.enter(Capability::Tools, "register") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let Some(grant) = self.capabilities().tools().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(Capability::Tools, "register"));
        };
        if let Err(reason) = validate_tool_name(&tool.name) {
            drop(permit);
            return self.deny(CapabilityDenial::invalid_argument(
                Capability::Tools,
                "register",
                reason,
            ));
        }
        if tool.summary.len() > MAX_TOOL_SUMMARY_BYTES {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::Tools,
                "register",
                format!("summary is longer than {MAX_TOOL_SUMMARY_BYTES} bytes"),
            ));
        }
        if tool.input_schema.len() > usize::try_from(grant.max_schema_bytes).unwrap_or(usize::MAX) {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::Tools,
                "register",
                format!(
                    "input schema is longer than the granted {} bytes",
                    grant.max_schema_bytes
                ),
            ));
        }
        if serde_json::from_str::<serde_json::Value>(&tool.input_schema).is_err() {
            drop(permit);
            return self.deny(CapabilityDenial::invalid_argument(
                Capability::Tools,
                "register",
                "input schema is not valid JSON",
            ));
        }
        // The quota counts distinct names this instance currently holds, so
        // replacing an existing registration is always allowed and only a new
        // name can push the plugin over its ceiling.
        let already_registered = self.registered_tools().contains(&tool.name);
        if !already_registered {
            let held = self.registered_tools().len() as u64;
            if held >= u64::from(grant.max_tools) {
                drop(permit);
                return self.deny(CapabilityDenial::quota_exceeded(
                    Capability::Tools,
                    "register",
                    format!(
                        "this plugin already holds {held} of its {} granted tools",
                        grant.max_tools
                    ),
                ));
            }
        }
        let plugin_id = self.plugin_id().to_owned();
        let name = tool.name.clone();
        self.services().tools.register(ToolRegistration {
            plugin_id,
            name: tool.name,
            summary: tool.summary,
            input_schema: tool.input_schema,
        });
        self.note_tool_registered(name);
        drop(permit);
        Ok(Ok(()))
    }

    fn unregister(&mut self, name: String) -> HostResult<bool> {
        let permit = match self.enter(Capability::Tools, "unregister") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        if let Err(reason) = validate_tool_name(&name) {
            drop(permit);
            return self.deny(CapabilityDenial::invalid_argument(
                Capability::Tools,
                "unregister",
                reason,
            ));
        }
        let removed = self.services().tools.unregister(self.plugin_id(), &name);
        self.note_tool_unregistered(&name);
        drop(permit);
        Ok(Ok(removed))
    }
}

impl host_events::Host for PluginState {
    fn emit(&mut self, evt: WitEvent) -> HostResult<()> {
        let permit = match self.enter(Capability::Events, "emit") {
            Ok(permit) => permit,
            Err(denial) => return self.deny(denial),
        };
        let Some(grant) = self.capabilities().events().cloned() else {
            drop(permit);
            return self.deny(CapabilityDenial::not_granted(Capability::Events, "emit"));
        };
        let kind = event_kind_from_wit(evt.kind);
        if !grant.emit_kinds.contains(&kind) {
            drop(permit);
            return self.deny(CapabilityDenial::out_of_scope(
                Capability::Events,
                "emit",
                format!("event kind `{kind:?}` is not in the granted emit list"),
            ));
        }
        let payload_len = evt.payload.len() as u64;
        if payload_len > u64::from(grant.max_payload_bytes)
            || payload_len > u64::from(self.limits().max_payload_bytes)
        {
            drop(permit);
            return self.deny(CapabilityDenial::quota_exceeded(
                Capability::Events,
                "emit",
                format!(
                    "payload is {payload_len} bytes, the grant allows {}",
                    grant.max_payload_bytes
                ),
            ));
        }
        if evt.source.len() > MAX_KEY_LEN {
            drop(permit);
            return self.deny(CapabilityDenial::invalid_argument(
                Capability::Events,
                "emit",
                format!("source is longer than {MAX_KEY_LEN} bytes"),
            ));
        }
        if serde_json::from_str::<serde_json::Value>(&evt.payload).is_err() {
            drop(permit);
            return self.deny(CapabilityDenial::invalid_argument(
                Capability::Events,
                "emit",
                "payload is not valid JSON",
            ));
        }
        // The guest never gets to choose its own sequence number.
        let sequence = self.next_sequence();
        let plugin_id = self.plugin_id().to_owned();
        self.services().events.publish(
            &plugin_id,
            HostEvent {
                kind,
                sequence,
                source: evt.source,
                payload: evt.payload,
            },
        );
        drop(permit);
        Ok(Ok(()))
    }
}

/// Longest tool summary the host accepts.
pub(crate) const MAX_TOOL_SUMMARY_BYTES: usize = 512;

fn validate_tool_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("tool name must not be empty".to_owned());
    }
    if name.len() > 64 {
        return Err("tool name is longer than 64 bytes".to_owned());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(
            "tool name may only contain lowercase ASCII letters, digits, `-` and `_`".to_owned(),
        );
    }
    Ok(())
}

/// Truncates on a character boundary so the host never emits invalid UTF-8.
fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// Builds the ABI event the host hands to `handle-event`.
pub(crate) fn wit_event(event: &HostEvent) -> WitEvent {
    WitEvent {
        kind: crate::convert::event_kind_to_wit(event.kind),
        sequence: event.sequence,
        source: event.source.clone(),
        payload: event.payload.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FORBIDDEN_HEADERS, resolve_parent_under_roots, resolve_under_roots, truncate_utf8,
        validate_tool_name,
    };
    use std::path::{Path, PathBuf};

    /// A self-deleting directory, replacing the `tempfile` crate.
    ///
    /// `tempfile` seeds its name generator from a newer `getrandom` line than
    /// the one already resolved in the root dependency graph, and the frozen
    /// root `deny.toml` denies duplicate crate versions.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            let path = std::env::temp_dir().join(format!(
                "claw-plugin-unit-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("the temporary directory must be writable");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn truncation_never_splits_a_character() {
        assert_eq!(truncate_utf8("hello", 5), "hello");
        assert_eq!(truncate_utf8("hello", 10), "hello");
        assert_eq!(truncate_utf8("hello", 2), "he");
        // `é` is two bytes, so a 1-byte ceiling must drop it entirely.
        assert_eq!(truncate_utf8("é", 1), "");
        assert_eq!(truncate_utf8("aé", 2), "a");
        assert_eq!(truncate_utf8("aé", 3), "aé");
    }

    #[test]
    fn tool_names_are_restricted_to_a_safe_alphabet() {
        assert_eq!(validate_tool_name("summarise-2"), Ok(()));
        assert_eq!(validate_tool_name("a_b"), Ok(()));
        assert_eq!(
            validate_tool_name(""),
            Err("tool name must not be empty".to_owned())
        );
        assert_eq!(
            validate_tool_name("Upper"),
            Err(
                "tool name may only contain lowercase ASCII letters, digits, `-` and `_`"
                    .to_owned()
            )
        );
        assert_eq!(
            validate_tool_name("../etc"),
            Err(
                "tool name may only contain lowercase ASCII letters, digits, `-` and `_`"
                    .to_owned()
            )
        );
        assert_eq!(
            validate_tool_name(&"a".repeat(65)),
            Err("tool name is longer than 64 bytes".to_owned())
        );
    }

    #[test]
    fn the_forbidden_header_list_is_lowercase_and_sorted() {
        let mut sorted = FORBIDDEN_HEADERS;
        sorted.sort_unstable();
        assert_eq!(sorted, FORBIDDEN_HEADERS);
        for header in FORBIDDEN_HEADERS {
            assert_eq!(header, header.to_ascii_lowercase());
        }
    }

    #[test]
    fn resolution_only_succeeds_inside_a_root() {
        let temp = TempDir::new();
        let root = std::fs::canonicalize(temp.path()).expect("canonical root");
        std::fs::create_dir_all(root.join("nested")).expect("nested");
        std::fs::write(root.join("nested").join("file.txt"), b"data").expect("write");

        let roots = vec![root.clone()];
        let resolved =
            resolve_under_roots(&roots, Path::new("nested/file.txt")).expect("the file resolves");
        assert_eq!(
            resolved,
            std::fs::canonicalize(root.join("nested").join("file.txt")).expect("canonical")
        );
        assert_eq!(resolve_under_roots(&roots, Path::new("missing.txt")), None);
        assert_eq!(resolve_under_roots(&[], Path::new("nested/file.txt")), None);
    }

    #[test]
    fn a_write_target_needs_an_existing_parent_inside_a_root() {
        let temp = TempDir::new();
        let root = std::fs::canonicalize(temp.path()).expect("canonical root");
        std::fs::create_dir_all(root.join("out")).expect("out dir");

        let roots = vec![root.clone()];
        let target = resolve_parent_under_roots(&roots, Path::new("out/new.txt"))
            .expect("the parent exists");
        assert_eq!(
            target,
            std::fs::canonicalize(root.join("out"))
                .expect("canonical")
                .join("new.txt")
        );
        assert_eq!(
            resolve_parent_under_roots(&roots, Path::new("missing/new.txt")),
            None
        );
        let empty: Vec<PathBuf> = Vec::new();
        assert_eq!(
            resolve_parent_under_roots(&empty, Path::new("out/new.txt")),
            None
        );
    }
}
