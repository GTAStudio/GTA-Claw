use std::ffi::OsString;
use std::sync::Arc;
use std::time::Duration;

use claw_application::model::ids::ApprovalId;
use claw_gateway_client::{
    AuthorizationExpectation, ClientTimeouts, ConnectionEpoch, GatewayClient, GatewayClientConfig,
    GatewayEventStream, ReconnectPolicy,
};
use claw_protocol::gateway::{
    AUTHENTICATED_MAX_FRAME_BYTES, GatewayMethodName, RequestId, resolve_core_method,
};
use claw_security::authorization::{Scope, ScopeSet};
use serde_json::{Value, json};
use tokio::io::AsyncReadExt as _;
use zeroize::Zeroizing;

use super::{
    DiagnosticFailure, ExitCategory, GatewayOptions, ParseFailure, RenderedResult,
    generate_ephemeral_identity, map_client_error, option_value, parse_failure,
    parse_gateway_options, read_credential, validate_endpoint,
};

pub(super) struct NativeCommand {
    options: GatewayOptions,
    method: &'static str,
    scope: Scope,
    params: Value,
    preview_fingerprint: Option<String>,
    memory: Option<Box<MemoryRequest>>,
    partial_export: Option<std::path::PathBuf>,
    accounting_export: Option<std::path::PathBuf>,
    model_export: Option<std::path::PathBuf>,
}

struct MemoryRequest {
    arguments: Value,
    content_stdin: bool,
    archive_stdin: bool,
    request_stdin: bool,
    export_file: Option<std::path::PathBuf>,
    import_file: Option<std::path::PathBuf>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartialRunReply {
    run_id: String,
    session_id: String,
    revision: u64,
    turn: Option<u64>,
    status: String,
    partial: PartialTextReply,
    durable: bool,
    acknowledged: bool,
    automatic_replay: bool,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartialTextReply {
    available: bool,
    text: Option<String>,
    offset: Option<usize>,
    next_offset: Option<usize>,
    total_bytes: Option<usize>,
    sha256: Option<String>,
    message_complete: Option<bool>,
    untrusted: Option<bool>,
    reasoning_included: Option<bool>,
    tool_arguments_included: Option<bool>,
}

fn check_partial_page(
    encoded: &str,
    parameters: &Value,
) -> Result<PartialRunReply, DiagnosticFailure> {
    let invalid = || {
        DiagnosticFailure::protocol(
            "invalid_partial_page",
            "Gateway partial page changed identity, bounds, cursor or digest",
        )
    };
    if encoded.len() > 16 * 1024 {
        return Err(invalid());
    }
    let reply: PartialRunReply = serde_json::from_str(encoded).map_err(|_| invalid())?;
    if parameters["runId"].as_str() != Some(&reply.run_id)
        || parameters["partialPage"]["revision"].as_u64() != Some(reply.revision)
        || reply.revision == 0
        || reply.session_id.is_empty()
        || reply.session_id.len() > 128
        || reply.session_id.chars().any(char::is_control)
        || !reply.durable
        || reply.acknowledged
        || reply.automatic_replay
        || !matches!(
            reply.status.as_str(),
            "completed" | "completed_with_changes" | "cancelled" | "failed" | "outcome_unknown"
        )
    {
        return Err(invalid());
    }
    let page = &reply.partial;
    if !page.available {
        if parameters["partialPage"]["offset"].as_u64() != Some(0)
            || parameters["partialPage"].get("sha256").is_some()
            || page.text.is_some()
            || page.offset.is_some()
            || page.next_offset.is_some()
            || page.total_bytes.is_some()
            || page.sha256.is_some()
            || page.message_complete.is_some()
            || page.untrusted.is_some()
            || page.reasoning_included.is_some()
            || page.tool_arguments_included.is_some()
        {
            return Err(invalid());
        }
        return Ok(reply);
    }
    let text = page.text.as_deref().ok_or_else(invalid)?;
    let offset = page.offset.ok_or_else(invalid)?;
    let total = page.total_bytes.ok_or_else(invalid)?;
    let digest = page.sha256.as_deref().ok_or_else(invalid)?;
    let end = offset.checked_add(text.len()).ok_or_else(invalid)?;
    if reply.turn.is_none()
        || parameters["partialPage"]["offset"].as_u64() != u64::try_from(offset).ok()
        || text.len() > 2048
        || total > 4 * 1024 * 1024
        || end > total
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || parameters["partialPage"]["sha256"]
            .as_str()
            .is_some_and(|expected| expected != digest)
        || page.message_complete != Some(false)
        || page.untrusted != Some(true)
        || page.reasoning_included != Some(false)
        || page.tool_arguments_included != Some(false)
        || page.next_offset.map_or(end != total, |next| {
            text.is_empty() || next != end || next >= total
        })
        || (offset == 0 && end == total && memory_sha256(text.as_bytes()) != digest)
    {
        return Err(invalid());
    }
    Ok(reply)
}

fn check_accounting_page(encoded: &str, parameters: &Value) -> Result<(), DiagnosticFailure> {
    claw_protocol::native_accounting::validate_page(encoded, parameters)
        .map_err(|_| invalid_accounting_page())
}

const fn invalid_accounting_page() -> DiagnosticFailure {
    DiagnosticFailure::protocol(
        "invalid_accounting_page",
        "Gateway accounting page changed identity, counters, provenance or snapshot",
    )
}

#[derive(Default)]
struct ModelExportPages {
    first: Option<Value>,
    models: Vec<Value>,
    complete: bool,
    pages: usize,
}

impl ModelExportPages {
    fn parameters(&self) -> Value {
        let mut parameters = json!({"nativeCatalogPage":{"offset":self.models.len()}});
        if let Some(first) = &self.first {
            parameters["nativeCatalogPage"]["sha256"] = first["sha256"].clone();
        }
        parameters
    }

    fn push(&mut self, encoded: &str) -> Result<bool, DiagnosticFailure> {
        let invalid = || {
            DiagnosticFailure::protocol(
                "invalid_model_export",
                "Model export changed identity or exceeded its bounded snapshot",
            )
        };
        if self.complete || self.pages >= 1024 {
            return Err(invalid());
        }
        claw_protocol::native_models::validate_page(
            encoded,
            self.models.len(),
            self.first
                .as_ref()
                .and_then(|first| first["sha256"].as_str()),
        )
        .map_err(|_| invalid())?;
        let page: Value = serde_json::from_str(encoded).map_err(|_| invalid())?;
        if page["available"] != true {
            return Err(DiagnosticFailure::protocol(
                "model_catalogue_unavailable",
                "The provider has no available cached model catalogue",
            ));
        }
        if let Some(first) = &self.first {
            if [
                "totalModels",
                "sha256",
                "provider",
                "providerGeneration",
                "selectedModel",
                "selectionPinned",
                "observedAtMs",
                "source",
                "liveCapabilitiesVerified",
            ]
            .iter()
            .any(|field| first[field] != page[field])
            {
                return Err(invalid());
            }
        } else {
            self.first = Some(page.clone());
        }
        self.models.extend(
            page["models"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .cloned(),
        );
        self.pages += 1;
        self.complete = page["nextOffset"].is_null();
        Ok(self.complete)
    }

    fn finish(self) -> Result<Value, DiagnosticFailure> {
        let invalid = || {
            DiagnosticFailure::protocol(
                "invalid_model_export",
                "Model export is incomplete or its full catalogue digest is invalid",
            )
        };
        if !self.complete {
            return Err(invalid());
        }
        let mut snapshot = self.first.ok_or_else(invalid)?;
        snapshot["endOffset"] = json!(self.models.len());
        snapshot["nextOffset"] = Value::Null;
        snapshot["models"] = json!(self.models);
        claw_protocol::native_models::validate_snapshot(
            &snapshot.to_string(),
            snapshot["sha256"].as_str().ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        Ok(snapshot)
    }
}

struct AccountingExportPages {
    run_id: String,
    revision: u64,
    first: Option<Value>,
    rounds: Vec<Value>,
    complete: bool,
    pages: usize,
}

impl AccountingExportPages {
    const fn new(run_id: String, revision: u64) -> Self {
        Self {
            run_id,
            revision,
            first: None,
            rounds: Vec::new(),
            complete: false,
            pages: 0,
        }
    }

    fn parameters(&self) -> Value {
        let mut parameters = json!({"runId":self.run_id,"accountingPage":{"revision":self.revision,"offset":self.rounds.len()}});
        if let Some(first) = &self.first {
            parameters["accountingPage"]["sha256"] = first["accounting"]["sha256"].clone();
        }
        parameters
    }

    fn push(&mut self, encoded: &str) -> Result<bool, DiagnosticFailure> {
        let invalid = || {
            DiagnosticFailure::protocol(
                "invalid_accounting_export",
                "Accounting export changed identity or continued beyond its bounded snapshot",
            )
        };
        if self.complete || self.pages >= 1024 {
            return Err(invalid());
        }
        check_accounting_page(encoded, &self.parameters())?;
        let page: Value = serde_json::from_str(encoded).map_err(|_| invalid())?;
        if page["accounting"]["available"] != true {
            return Err(DiagnosticFailure::protocol(
                "accounting_unavailable",
                "The owned run has no retained provider accounting snapshot",
            ));
        }
        if let Some(first) = &self.first {
            if ["sessionId", "turn", "status"]
                .iter()
                .any(|field| first[field] != page[field])
                || ["totalRounds", "sha256", "summary"]
                    .iter()
                    .any(|field| first["accounting"][field] != page["accounting"][field])
            {
                return Err(invalid());
            }
        } else {
            self.first = Some(page.clone());
        }
        self.rounds.extend(
            page["accounting"]["rounds"]
                .as_array()
                .expect("validated rounds")
                .iter()
                .cloned(),
        );
        self.pages += 1;
        self.complete = page["accounting"]["nextOffset"].is_null();
        Ok(self.complete)
    }

    fn finish(self) -> Result<Value, DiagnosticFailure> {
        if !self.complete {
            return Err(DiagnosticFailure::protocol(
                "invalid_accounting_export",
                "Accounting export is incomplete",
            ));
        }
        let mut reply = self.first.expect("completed snapshot");
        reply["accounting"]["offset"] = json!(0);
        reply["accounting"]["endOffset"] = json!(self.rounds.len());
        reply["accounting"]["nextOffset"] = Value::Null;
        reply["accounting"]["rounds"] = json!(self.rounds);
        claw_protocol::native_accounting::validate_snapshot(
            &reply.to_string(),
            &self.run_id,
            self.revision,
        )
        .map_err(|_| invalid_accounting_page())?;
        Ok(reply)
    }
}

#[derive(Eq, PartialEq)]
struct PartialExportIdentity {
    session_id: String,
    turn: u64,
    status: String,
    total_bytes: usize,
    sha256: String,
}

struct PartialExportPages {
    run_id: String,
    revision: u64,
    bytes: Zeroizing<Vec<u8>>,
    identity: Option<PartialExportIdentity>,
    complete: bool,
    pages: usize,
}

impl PartialExportPages {
    fn new(run_id: String, revision: u64) -> Self {
        Self {
            run_id,
            revision,
            bytes: Zeroizing::new(Vec::new()),
            identity: None,
            complete: false,
            pages: 0,
        }
    }

    fn parameters(&self) -> Value {
        let mut parameters = json!({"runId":self.run_id,"partialPage":{"revision":self.revision,"offset":self.bytes.len()}});
        if let Some(identity) = &self.identity {
            parameters["partialPage"]["sha256"] = json!(identity.sha256);
        }
        parameters
    }

    fn push(&mut self, encoded: &str) -> Result<bool, DiagnosticFailure> {
        let invalid = || {
            DiagnosticFailure::protocol(
                "invalid_partial_export",
                "Partial export changed its identity, exceeded its page budget or continued after completion",
            )
        };
        if self.complete || self.pages >= 4096 {
            return Err(invalid());
        }
        let reply = check_partial_page(encoded, &self.parameters())?;
        if !reply.partial.available {
            return Err(DiagnosticFailure::protocol(
                "partial_unavailable",
                "The owned run has no retained partial text",
            ));
        }
        let identity = PartialExportIdentity {
            session_id: reply.session_id,
            turn: reply.turn.expect("validated turn"),
            status: reply.status,
            total_bytes: reply.partial.total_bytes.expect("validated byte count"),
            sha256: reply.partial.sha256.expect("validated digest"),
        };
        if self
            .identity
            .as_ref()
            .is_some_and(|previous| previous != &identity)
        {
            return Err(invalid());
        }
        if self.identity.is_none() {
            self.bytes
                .try_reserve_exact(identity.total_bytes)
                .map_err(|_| invalid())?;
            self.identity = Some(identity);
        }
        self.bytes
            .extend_from_slice(reply.partial.text.expect("validated text").as_bytes());
        self.pages += 1;
        self.complete = reply.partial.next_offset.is_none();
        Ok(self.complete)
    }

    fn finish(self) -> Result<Zeroizing<Vec<u8>>, DiagnosticFailure> {
        if !self.complete
            || self.identity.as_ref().is_none_or(|identity| {
                self.bytes.len() != identity.total_bytes
                    || memory_sha256(&self.bytes) != identity.sha256
            })
        {
            return Err(DiagnosticFailure::protocol(
                "invalid_partial_export",
                "Partial export is incomplete or its whole-content digest does not match",
            ));
        }
        Ok(self.bytes)
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MemoryExportPage {
    archive_schema_version: u64,
    notebook_revision: u64,
    sha256: String,
    total_bytes: usize,
    offset: usize,
    data: String,
    next_offset: Option<usize>,
    plaintext: bool,
    untrusted_content: bool,
    grants_authority: bool,
}

struct MemoryArchivePages {
    revision: u64,
    bytes: Zeroizing<Vec<u8>>,
    identity: Option<(usize, String)>,
    complete: bool,
}

impl MemoryArchivePages {
    fn new(revision: u64) -> Self {
        Self {
            revision,
            bytes: Zeroizing::new(Vec::new()),
            identity: None,
            complete: false,
        }
    }

    fn push(&mut self, encoded: &str) -> Result<bool, &'static str> {
        if encoded.len() > 16 * 1024 || self.complete {
            return Err("Memory export page exceeds its limit or follows a complete archive");
        }
        let page: MemoryExportPage = serde_json::from_str(encoded)
            .map_err(|_| "Memory export page does not match its closed schema")?;
        let end = page
            .offset
            .checked_add(page.data.len())
            .ok_or("Memory export offset overflow")?;
        if page.archive_schema_version != 1
            || page.notebook_revision != self.revision
            || !page.plaintext
            || !page.untrusted_content
            || page.grants_authority
            || page.total_bytes == 0
            || page.total_bytes > claw_state::MAX_MEMORY_ARCHIVE_BYTES
            || page.offset != self.bytes.len()
            || page.data.is_empty()
            || page.data.len() > 2_048
            || page.sha256.len() != 64
            || !page
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || end > page.total_bytes
            || match page.next_offset {
                Some(next) => next != end || next >= page.total_bytes,
                None => end != page.total_bytes,
            }
            || self
                .identity
                .as_ref()
                .is_some_and(|(total, digest)| *total != page.total_bytes || *digest != page.sha256)
        {
            return Err(
                "Memory export page changed identity, length, revision or contiguous cursor",
            );
        }
        if self.identity.is_none() {
            self.bytes
                .try_reserve_exact(page.total_bytes)
                .map_err(|_| "Memory export allocation failed")?;
            self.identity = Some((page.total_bytes, page.sha256));
        }
        self.bytes.extend_from_slice(page.data.as_bytes());
        self.complete = page.next_offset.is_none();
        Ok(self.complete)
    }

    fn finish(self) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let (total, expected) = self.identity.as_ref().ok_or("Memory export has no pages")?;
        if !self.complete || self.bytes.len() != *total || memory_sha256(&self.bytes) != *expected {
            return Err("Memory export is incomplete or its full digest does not match");
        }
        let archive: claw_state::MemoryArchive = serde_json::from_slice(&self.bytes)
            .map_err(|_| "Memory export archive schema is invalid")?;
        if archive.notebook.revision != self.revision || archive.validate().is_err() {
            return Err("Memory export archive has invalid content, identities or revisions");
        }
        Ok(self.bytes)
    }
}

fn memory_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_ref() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 15)]));
    }
    encoded
}

fn explicit_tool_message(name: &str, arguments: &Value) -> Result<String, &'static str> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        || !arguments.is_object()
    {
        return Err("native tool identity or parameters are invalid");
    }
    let encoded = serde_json::to_string(&json!({"name":name,"arguments":arguments}))
        .map_err(|_| "native tool parameters cannot be encoded")?;
    if encoded.len() > 16 * 1024 {
        return Err("native tool parameters exceed the bounded command size");
    }
    Ok(format!("!tool {encoded}"))
}

#[cfg(test)]
mod explicit_tool_tests {
    use super::*;

    #[test]
    fn model_export_command_requires_a_new_destination_and_a_complete_read() {
        let target = std::env::temp_dir().join("gta-claw-models.json");
        let base: Vec<OsString> = ["export-models", "--ephemeral-device", "--destination"]
            .into_iter()
            .map(OsString::from)
            .chain([target.as_os_str().to_owned()])
            .chain(
                ["--endpoint", "ws://127.0.0.1:18789/"]
                    .into_iter()
                    .map(OsString::from),
            )
            .collect();
        let parsed = parse(&base, 0).ok().expect("model export");
        assert_eq!(parsed.model_export.as_deref(), Some(target.as_path()));
        assert_eq!(parsed.method, "models.list");
        assert_eq!(parsed.scope, Scope::OperatorRead);
        assert_eq!(parsed.params, json!({"nativeCatalogPage":{"offset":0}}));
        let mut missing = base.clone();
        missing.drain(2..4);
        assert!(parse(&missing, 0).is_err());
        let mut relative = base.clone();
        relative[3] = "relative.json".into();
        assert!(parse(&relative, 0).is_err());
        for extra in [
            vec!["--destination", "another.json"],
            vec!["--offset", "8"],
            vec!["--sha256", &"a".repeat(64)],
            vec!["--wait-ms", "0"],
            vec!["--idempotency-key", "no-inference"],
            vec!["--overwrite"],
        ] {
            let mut invalid = base.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid, 0).is_err());
        }
    }

    #[test]
    fn model_export_verifies_all_pages_without_inventing_a_directory_or_alias_target() {
        for scenario in [
            "valid",
            "tampered",
            "identity",
            "cross-page-id",
            "cross-page-alias",
            "incomplete",
            "missing",
        ] {
            let mut snapshot = json!({"provider":"fixture","providerGeneration":1,"selectedModel":"exact-0","selectionPinned":true,
                "observedAtMs":123,"source":"provider_sdk_catalogue","liveCapabilitiesVerified":false,
                "models":(0..17).map(|ordinal| json!({"id":format!("exact-{ordinal}"),"displayName":null,"contextWindow":null,"maxOutputTokens":null,"advertisedCapabilities":[]})).collect::<Vec<_>>()});
            snapshot["models"][0]["aliases"] = json!(["work"]);
            if scenario == "cross-page-id" {
                snapshot["models"][16]["id"] = json!("exact-1");
            } else if scenario == "cross-page-alias" {
                snapshot["models"][16]["aliases"] = json!(["work"]);
            }
            let digest = memory_sha256(&serde_json::to_vec(&snapshot).expect("snapshot"));
            let mut collector = ModelExportPages::default();
            assert_eq!(
                collector.parameters(),
                json!({"nativeCatalogPage":{"offset":0}})
            );
            for offset in [0, 8, 16] {
                let end = (offset + 8).min(17);
                let mut page = snapshot.clone();
                page["schemaVersion"] = json!(1);
                page["available"] = json!(true);
                page["selectionChanged"] = json!(false);
                page["networkContacted"] = json!(false);
                page["sha256"] = json!(digest);
                page["offset"] = json!(offset);
                page["endOffset"] = json!(end);
                page["nextOffset"] = json!((end < 17).then_some(end));
                page["totalModels"] = json!(17);
                page["models"] =
                    json!(&snapshot["models"].as_array().expect("models")[offset..end]);
                if offset == 0 && scenario == "missing" {
                    page = json!({"schemaVersion":1,"available":false,"selectionChanged":false,"networkContacted":false});
                    assert!(collector.push(&page.to_string()).is_err());
                    break;
                }
                if offset > 0 {
                    assert_eq!(
                        collector.parameters(),
                        json!({"nativeCatalogPage":{"offset":offset,"sha256":digest}})
                    );
                }
                if offset == 16 {
                    if scenario == "incomplete" {
                        break;
                    }
                    if scenario == "identity" {
                        page["providerGeneration"] = json!(2);
                        assert!(collector.push(&page.to_string()).is_err());
                        break;
                    }
                    if scenario == "tampered" {
                        page["models"][0]["displayName"] = json!("changed-after-first-page");
                    }
                }
                assert_eq!(collector.push(&page.to_string()).ok(), Some(end == 17));
                if end == 17 {
                    assert!(collector.push(&page.to_string()).is_err());
                }
            }
            let result = collector.finish();
            assert_eq!(result.is_ok(), scenario == "valid", "{scenario}");
            if let Ok(complete) = result {
                assert_eq!(complete["models"], snapshot["models"]);
                assert_eq!(complete["sha256"], digest);
                assert_eq!(complete["nextOffset"], Value::Null);
            }
        }
    }

    #[test]
    fn model_catalogue_commands_separate_read_and_explicit_snapshot_refresh() {
        let base: Vec<OsString> = [
            "models",
            "--endpoint",
            "ws://127.0.0.1:18789",
            "--ephemeral-device",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let read = parse(&base, 0).ok().expect("catalogue read");
        assert_eq!(read.scope, Scope::OperatorRead);
        assert_eq!(read.params, json!({"nativeCatalogPage":{"offset":0}}));
        let mut status = base.clone();
        status.push("--availability".into());
        let parsed = parse(&status, 0)
            .ok()
            .expect("explicit availability request");
        assert_eq!(parsed.scope, Scope::OperatorRead);
        assert_eq!(
            parsed.params,
            json!({"nativeCatalogPage":{"offset":0,"includeAvailability":true}})
        );
        status.push("--availability".into());
        assert!(parse(&status, 0).is_err());
        let mut continued = base.clone();
        continued.extend(["--offset", "8"].into_iter().map(OsString::from));
        assert!(
            parse(&continued, 0).is_err(),
            "continuation requires original digest"
        );
        continued.extend(
            ["--sha256", &"a".repeat(64)]
                .into_iter()
                .map(OsString::from),
        );
        assert!(parse(&continued, 0).is_ok());
        let mut refresh = base;
        refresh[0] = "refresh-models".into();
        assert!(parse(&refresh, 0).is_err());
        refresh.extend(
            ["--sha256", &"a".repeat(64)]
                .into_iter()
                .map(OsString::from),
        );
        let parsed = parse(&refresh, 0).ok().expect("explicit refresh");
        assert_eq!(parsed.scope, Scope::OperatorWrite);
        assert_eq!(
            parsed.params,
            json!({"nativeCatalogRefresh":{"sha256":"a".repeat(64)}})
        );
        for extra in [
            vec!["--offset", "0"],
            vec!["--sha256", &"b".repeat(64)],
            vec!["--wait-ms", "0"],
            vec!["--idempotency-key", "no-inference"],
        ] {
            let mut invalid = refresh.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid, 0).is_err());
        }
    }

    #[test]
    fn accounting_export_command_requires_a_new_local_target_and_a_complete_read() {
        let target = std::env::temp_dir().join("gta-claw-accounting.json");
        let base: Vec<OsString> = [
            "export-accounting",
            &"a".repeat(64),
            "4",
            "--device-profile",
            "work",
            "--destination",
        ]
        .into_iter()
        .map(OsString::from)
        .chain([target.as_os_str().to_owned()])
        .chain(
            ["--endpoint", "ws://127.0.0.1:18789/"]
                .into_iter()
                .map(OsString::from),
        )
        .collect();
        let parsed = parse(&base, 0).unwrap_or_else(|_| panic!("valid export"));
        assert_eq!(parsed.accounting_export.as_deref(), Some(target.as_path()));
        assert_eq!(parsed.scope, Scope::OperatorRead);
        assert_eq!(parsed.method, "agent.wait");
        assert_eq!(
            parsed.params,
            json!({"runId":"a".repeat(64),"accountingPage":{"revision":4,"offset":0}})
        );
        assert!(parsed.partial_export.is_none() && parsed.memory.is_none());
        let mut missing = base.clone();
        missing.drain(5..7);
        assert!(parse(&missing, 0).is_err());
        let mut relative = base.clone();
        relative[6] = "relative.json".into();
        assert!(parse(&relative, 0).is_err());
        for extra in [
            vec!["--destination", "duplicate.json"],
            vec!["--offset", "16"],
            vec!["--sha256", &"b".repeat(64)],
            vec!["--wait-ms", "10"],
            vec!["--idempotency-key", "no-replay"],
            vec!["--overwrite"],
        ] {
            let mut arguments = base.clone();
            arguments.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&arguments, 0).is_err());
        }
    }

    #[test]
    fn accounting_export_verifies_the_entire_snapshot_not_only_individual_pages() {
        for scenario in [
            "valid",
            "corrupt",
            "inflated-total",
            "identity",
            "summary",
            "incomplete",
        ] {
            let tokens = json!({"inputTokens":1,"outputTokens":0,"totalTokens":1,"cachedInputTokens":0,"reasoningTokens":0});
            let mut snapshot = json!({
                "summary":{"available":true,"recordedRounds":17,"completeCounterRounds":17,
                    "partialCounterRounds":0,"unreportedRounds":0,"allPrimaryCountersReported":true,
                    "observedTokens":{"inputTokens":17,"outputTokens":0,"totalTokens":17,"cachedInputTokens":0,"reasoningTokens":0},
                    "aggregationOverflow":false,"costCalculated":false,"billingReconciled":false,
                    "recordSource":"terminal_turn","attemptsMayBeUnsent":true},
                "rounds":(0..17).map(|round| json!({"round":round,"response":{"provider":"fixture","model":"fixture-model",
                    "responseId":format!("response-{round}"),"usageReporting":"complete","finishReason":"stop","observedTokens":tokens}})).collect::<Vec<_>>()
            });
            if scenario == "inflated-total" {
                snapshot["summary"]["observedTokens"]["inputTokens"] = json!(18);
                snapshot["summary"]["observedTokens"]["totalTokens"] = json!(18);
            }
            let digest = memory_sha256(&serde_json::to_vec(&snapshot).expect("snapshot"));
            let mut first = json!({"runId":"a".repeat(64),"sessionId":"owned","revision":4,"turn":0,"status":"outcome_unknown",
                "durable":true,"acknowledged":false,"automaticReplay":false,
                "accounting":{"available":true,"offset":0,"endOffset":16,"nextOffset":16,"totalRounds":17,"sha256":digest,
                    "summary":snapshot["summary"],"rounds":&snapshot["rounds"].as_array().expect("rounds")[..16]}});
            let mut collector = AccountingExportPages::new("a".repeat(64), 4);
            assert!(matches!(collector.push(&first.to_string()), Ok(false)));
            assert_eq!(collector.parameters()["accountingPage"]["offset"], 16);
            assert_eq!(collector.parameters()["accountingPage"]["sha256"], digest);
            if scenario == "incomplete" {
                assert!(collector.finish().is_err());
                continue;
            }
            first["accounting"]["offset"] = json!(16);
            first["accounting"]["endOffset"] = json!(17);
            first["accounting"]["nextOffset"] = Value::Null;
            first["accounting"]["rounds"] = json!([snapshot["rounds"][16]]);
            if scenario == "corrupt" {
                first["accounting"]["rounds"][0]["response"]["model"] = json!("different-model");
            } else if scenario == "identity" {
                first["sessionId"] = json!("another-session");
            } else if scenario == "summary" {
                first["accounting"]["summary"]["attemptsMayBeUnsent"] = json!(false);
            }
            assert!(check_accounting_page(&first.to_string(), &collector.parameters()).is_ok());
            if matches!(scenario, "identity" | "summary") {
                assert!(collector.push(&first.to_string()).is_err(), "{scenario}");
                continue;
            }
            assert!(matches!(collector.push(&first.to_string()), Ok(true)));
            assert!(
                collector.push(&first.to_string()).is_err(),
                "no pages after completion"
            );
            let result = collector.finish();
            assert_eq!(result.is_ok(), scenario == "valid", "{scenario}");
            if let Ok(result) = result {
                assert_eq!(result["accounting"]["rounds"], snapshot["rounds"]);
                assert_eq!(result["accounting"]["summary"], snapshot["summary"]);
            }
        }
    }

    #[test]
    fn accounting_run_command_is_bounded_read_only_and_pins_continuations() {
        let base: Vec<OsString> = [
            "accounting-run",
            &"a".repeat(64),
            "4",
            "--device-profile",
            "work",
            "--endpoint",
            "ws://127.0.0.1:18789/",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let parsed = parse(&base, 0).ok().expect("accounting read");
        assert_eq!(parsed.scope, Scope::OperatorRead);
        assert_eq!(parsed.method, "agent.wait");
        assert_eq!(
            parsed.params,
            json!({"runId":"a".repeat(64),"accountingPage":{"revision":4,"offset":0}})
        );
        assert!(parsed.partial_export.is_none() && parsed.memory.is_none());
        let mut continuation = base.clone();
        continuation.extend(
            ["--offset", "16", "--sha256", &"b".repeat(64)]
                .into_iter()
                .map(OsString::from),
        );
        assert_eq!(
            parse(&continuation, 0)
                .ok()
                .expect("pinned continuation")
                .params["accountingPage"],
            json!({"revision":4,"offset":16,"sha256":"b".repeat(64)})
        );
        for extra in [
            vec!["--offset", "1"],
            vec!["--offset", "1025"],
            vec!["--offset", "-1"],
            vec!["--offset", "0.5"],
            vec!["--offset", "0", "--offset", "0"],
            vec!["--sha256", "bad"],
            vec!["--wait-ms", "0"],
            vec!["--limit", "16"],
            vec!["--idempotency-key", "read-only"],
            vec!["--after", "0"],
            vec!["--destination", "output.json"],
        ] {
            let mut invalid = base.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid, 0).is_err());
        }
        let mut invalid = base;
        invalid[2] = "0".into();
        assert!(parse(&invalid, 0).is_err());
    }

    fn stamp_accounting_fixture(page: &mut Value) {
        let snapshot =
            json!({"summary":page["accounting"]["summary"],"rounds":page["accounting"]["rounds"]});
        page["accounting"]["sha256"] = json!(memory_sha256(
            &serde_json::to_vec(&snapshot).expect("snapshot JSON")
        ));
    }

    fn accounting_fixture() -> Value {
        let mut page = json!({
            "runId":"a".repeat(64),"sessionId":"owned-session","revision":4,"turn":2,
            "status":"outcome_unknown","durable":true,"acknowledged":false,"automaticReplay":false,
            "accounting":{"available":true,"offset":0,"endOffset":2,"nextOffset":null,"totalRounds":2,
                "summary":{"available":true,"recordedRounds":2,"completeCounterRounds":1,"partialCounterRounds":0,
                    "unreportedRounds":1,"allPrimaryCountersReported":false,"aggregationOverflow":false,
                    "costCalculated":false,"billingReconciled":false,"recordSource":"provider_journal",
                    "journalRevision":2,"journalClosed":false,"attemptsMayBeUnsent":true,
                    "observedTokens":{"inputTokens":5,"outputTokens":2,"totalTokens":7,"cachedInputTokens":1,"reasoningTokens":1}},
                "rounds":[{"round":0,"response":{"provider":"actual-provider","model":"actual-model",
                    "responseId":"remote-response","usageReporting":"complete","finishReason":"length",
                    "observedTokens":{"inputTokens":5,"outputTokens":2,"totalTokens":7,"cachedInputTokens":1,"reasoningTokens":1}}},
                    {"round":1,"response":null}]},
        });
        stamp_accounting_fixture(&mut page);
        page
    }

    #[test]
    fn accounting_pages_validate_counts_and_provenance_even_with_a_matching_digest() {
        let parameters = json!({"runId":"a".repeat(64),"accountingPage":{"revision":4,"offset":0}});
        let original = accounting_fixture();
        assert!(check_accounting_page(&original.to_string(), &parameters).is_ok());
        for (pointer, value) in [
            ("/runId", json!("b".repeat(64))),
            ("/sessionId", json!("")),
            ("/revision", json!(5)),
            ("/turn", Value::Null),
            ("/status", json!("running")),
            ("/durable", json!(false)),
            ("/acknowledged", json!(true)),
            ("/automaticReplay", json!(true)),
            ("/accounting/offset", json!(1)),
            ("/accounting/endOffset", json!(1)),
            ("/accounting/nextOffset", json!(0)),
            ("/accounting/totalRounds", json!(1025)),
            ("/accounting/summary/completeCounterRounds", json!(0)),
            ("/accounting/summary/costCalculated", json!(true)),
            ("/accounting/summary/billingReconciled", json!(true)),
            ("/accounting/summary/journalRevision", json!(0)),
            ("/accounting/summary/recordSource", json!("future-source")),
            ("/accounting/summary/observedTokens/totalTokens", json!(9)),
            ("/accounting/rounds/0/round", json!(1)),
            ("/accounting/rounds/1/round", json!(0)),
            (
                "/accounting/rounds/0/response/provider",
                json!("bad\nidentity"),
            ),
            (
                "/accounting/rounds/0/response/model",
                json!("x".repeat(513)),
            ),
            ("/accounting/rounds/0/response/responseId", json!("")),
            (
                "/accounting/rounds/0/response/finishReason",
                json!("unknown"),
            ),
            (
                "/accounting/rounds/0/response/usageReporting",
                json!("unreported"),
            ),
            (
                "/accounting/rounds/0/response/observedTokens/cachedInputTokens",
                json!(6),
            ),
            (
                "/accounting/rounds/0/response/observedTokens/reasoningTokens",
                json!(3),
            ),
            (
                "/accounting/rounds/0/response/observedTokens/totalTokens",
                json!(8),
            ),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).expect("fixture field") = value;
            stamp_accounting_fixture(&mut changed);
            assert!(
                check_accounting_page(&changed.to_string(), &parameters).is_err(),
                "{pointer}"
            );
        }
        let mut changed = original.clone();
        changed["accounting"]["rounds"][0]["response"]["prompt"] = json!("private-content");
        stamp_accounting_fixture(&mut changed);
        assert!(check_accounting_page(&changed.to_string(), &parameters).is_err());
        changed = original.clone();
        changed["accounting"]["summary"]["observedTokens"]["inputTokens"] = json!(6);
        changed["accounting"]["summary"]["observedTokens"]["totalTokens"] = json!(8);
        stamp_accounting_fixture(&mut changed);
        assert!(check_accounting_page(&changed.to_string(), &parameters).is_err());
        changed = original.clone();
        changed["accounting"]["sha256"] = json!("0".repeat(64));
        assert!(check_accounting_page(&changed.to_string(), &parameters).is_err());
        changed = original.clone();
        changed["accounting"] = json!({"available":false});
        assert!(check_accounting_page(&changed.to_string(), &parameters).is_ok());
        changed["accounting"]["rounds"] = json!([]);
        assert!(check_accounting_page(&changed.to_string(), &parameters).is_err());
        let mut zero = original;
        let zero_tokens = json!({"inputTokens":0,"outputTokens":0,"totalTokens":0,"cachedInputTokens":0,"reasoningTokens":0});
        zero["accounting"]["summary"]["observedTokens"] = zero_tokens.clone();
        zero["accounting"]["rounds"][0]["response"]["observedTokens"] = zero_tokens;
        stamp_accounting_fixture(&mut zero);
        assert!(check_accounting_page(&zero.to_string(), &parameters).is_ok());
    }

    #[test]
    fn accounting_continuations_require_snapshot_and_contiguous_rounds() {
        let mut snapshot = accounting_fixture();
        snapshot["accounting"]["totalRounds"] = json!(17);
        snapshot["accounting"]["endOffset"] = json!(17);
        snapshot["accounting"]["summary"]["recordedRounds"] = json!(17);
        snapshot["accounting"]["summary"]["unreportedRounds"] = json!(16);
        let first = snapshot["accounting"]["rounds"][0].clone();
        snapshot["accounting"]["rounds"] = json!(
            std::iter::once(first)
                .chain((1..17).map(|round| json!({"round":round,"response":null})))
                .collect::<Vec<_>>()
        );
        stamp_accounting_fixture(&mut snapshot);
        let digest = snapshot["accounting"]["sha256"].clone();
        let mut first = snapshot.clone();
        first["accounting"]["rounds"]
            .as_array_mut()
            .expect("rounds")
            .truncate(16);
        first["accounting"]["endOffset"] = json!(16);
        first["accounting"]["nextOffset"] = json!(16);
        let mut parameters =
            json!({"runId":"a".repeat(64),"accountingPage":{"revision":4,"offset":0}});
        assert!(check_accounting_page(&first.to_string(), &parameters).is_ok());
        assert!(check_accounting_page(&snapshot.to_string(), &parameters).is_err());
        let mut last = snapshot;
        last["accounting"]["offset"] = json!(16);
        last["accounting"]["rounds"] = json!([{"round":16,"response":null}]);
        parameters["accountingPage"]["offset"] = json!(16);
        assert!(check_accounting_page(&last.to_string(), &parameters).is_err());
        parameters["accountingPage"]["sha256"] = digest;
        assert!(check_accounting_page(&last.to_string(), &parameters).is_ok());
        last["accounting"]["rounds"][0]["round"] = json!(15);
        assert!(check_accounting_page(&last.to_string(), &parameters).is_err());
        last["accounting"]["rounds"][0]["round"] = json!(16);
        parameters["accountingPage"]["sha256"] = json!("0".repeat(64));
        assert!(check_accounting_page(&last.to_string(), &parameters).is_err());
    }

    #[test]
    fn partial_export_pages_pin_all_identity_fields_and_verify_the_complete_utf8_digest() {
        let run_id = "a".repeat(64);
        let text = format!("{}\u{754c}tail", "x".repeat(2047));
        let digest = memory_sha256(text.as_bytes());
        let page = |offset: usize, end: usize| {
            json!({"runId":run_id,"sessionId":"owned-session","revision":7,"turn":0,"status":"outcome_unknown","durable":true,"acknowledged":false,"automaticReplay":false,
            "partial":{"available":true,"text":&text[offset..end],"offset":offset,"nextOffset":(end < text.len()).then_some(end),"totalBytes":text.len(),"sha256":digest,"messageComplete":false,"untrusted":true,"reasoningIncluded":false,"toolArgumentsIncluded":false}})
        };
        let first = page(0, 2047);
        let last = page(2047, text.len());
        let mut pages = PartialExportPages::new(run_id.clone(), 7);
        assert!(matches!(pages.push(&first.to_string()), Ok(false)));
        assert_eq!(pages.parameters()["partialPage"]["offset"], 2047);
        assert_eq!(pages.parameters()["partialPage"]["sha256"], digest);
        assert!(matches!(pages.push(&last.to_string()), Ok(true)));
        assert!(pages.push(&last.to_string()).is_err());
        assert_eq!(
            pages.finish().ok().expect("whole hash").as_slice(),
            text.as_bytes()
        );
        for (pointer, value) in [
            ("/sessionId", json!("other")),
            ("/turn", json!(1)),
            ("/status", json!("failed")),
            ("/revision", json!(8)),
            ("/partial/totalBytes", json!(text.len() + 1)),
            ("/partial/offset", json!(2046)),
            ("/partial/sha256", json!("0".repeat(64))),
        ] {
            let mut changed = last.clone();
            *changed.pointer_mut(pointer).expect("fixture field") = value;
            let mut pages = PartialExportPages::new(run_id.clone(), 7);
            assert!(matches!(pages.push(&first.to_string()), Ok(false)));
            assert!(pages.push(&changed.to_string()).is_err(), "{pointer}");
        }
        let mut changed = last;
        changed["partial"]["text"] = json!("q".repeat(text.len() - 2047));
        let mut pages = PartialExportPages::new(run_id.clone(), 7);
        assert!(matches!(pages.push(&first.to_string()), Ok(false)));
        assert!(matches!(pages.push(&changed.to_string()), Ok(true)));
        assert!(pages.finish().is_err());
        let mut pages = PartialExportPages::new(run_id, 7);
        pages.pages = 4096;
        assert!(pages.push(&first.to_string()).is_err());
        assert!(pages.finish().is_err());
    }

    #[test]
    fn partial_run_reply_refuses_changed_identity_unbounded_text_and_false_completeness() {
        let parameters = json!({"runId":"a".repeat(64),"partialPage":{"revision":3,"offset":0}});
        let original = json!({"runId":parameters["runId"],"sessionId":"owned-session","revision":3,"turn":0,"status":"outcome_unknown","durable":true,"acknowledged":false,"automaticReplay":false,
            "partial":{"available":true,"text":"abc","offset":0,"nextOffset":null,"totalBytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","messageComplete":false,"untrusted":true,"reasoningIncluded":false,"toolArgumentsIncluded":false}});
        assert!(check_partial_page(&original.to_string(), &parameters).is_ok());
        for (pointer, value) in [
            ("/runId", json!("b".repeat(64))),
            ("/revision", json!(4)),
            ("/turn", Value::Null),
            ("/acknowledged", json!(true)),
            ("/automaticReplay", json!(true)),
            ("/durable", json!(false)),
            ("/partial/text", json!("z".repeat(2049))),
            ("/partial/sha256", json!("0".repeat(64))),
            ("/partial/offset", json!(1)),
            ("/partial/totalBytes", json!(4)),
            ("/partial/nextOffset", json!(0)),
            ("/partial/messageComplete", json!(true)),
            ("/partial/untrusted", json!(false)),
            ("/partial/reasoningIncluded", json!(true)),
            ("/partial/toolArgumentsIncluded", json!(true)),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).expect("field") = value;
            assert!(
                check_partial_page(&changed.to_string(), &parameters).is_err(),
                "{pointer}"
            );
        }
        let mut absent = original;
        absent["partial"] = json!({"available":false});
        assert!(check_partial_page(&absent.to_string(), &parameters).is_ok());
        absent["partial"]["text"] = json!("must not leak");
        assert!(check_partial_page(&absent.to_string(), &parameters).is_err());
    }

    #[test]
    fn partial_export_command_requires_a_new_absolute_destination_and_no_cursor_overrides() {
        let destination = std::env::temp_dir().join("owned-partial-export.txt");
        let mut base: Vec<OsString> = [
            "export-partial",
            &"a".repeat(64),
            "3",
            "--endpoint",
            "ws://127.0.0.1:18789/",
            "--device-profile",
            "work",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert!(parse(&base, 0).is_err());
        base.extend([
            OsString::from("--destination"),
            destination.as_os_str().to_owned(),
        ]);
        let parsed = parse(&base, 0).ok().expect("complete partial export");
        assert_eq!(parsed.scope, Scope::OperatorRead);
        assert_eq!(parsed.method, "agent.wait");
        assert_eq!(parsed.partial_export, Some(destination));
        assert_eq!(
            parsed.params,
            json!({"runId":"a".repeat(64),"partialPage":{"revision":3,"offset":0}})
        );
        for extra in [
            vec!["--offset", "1"],
            vec!["--sha256", "bad"],
            vec!["--wait-ms", "0"],
            vec!["--idempotency-key", "export"],
            vec!["--destination", "another.txt"],
        ] {
            let mut invalid = base.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid, 0).is_err());
        }
        *base.last_mut().expect("destination") = OsString::from("relative.txt");
        assert!(parse(&base, 0).is_err());
    }

    #[test]
    fn partial_run_command_pins_revision_offset_and_digest_without_ack_or_wait() {
        let run_id = "a".repeat(64);
        let base: Vec<OsString> = [
            "partial-run",
            run_id.as_str(),
            "3",
            "--device-profile",
            "work",
            "--endpoint",
            "ws://127.0.0.1:18789/",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let parsed = parse(&base, 0).ok().expect("first partial page");
        assert_eq!(parsed.method, "agent.wait");
        assert_eq!(parsed.scope, Scope::OperatorRead);
        assert_eq!(
            parsed.params,
            json!({"runId":run_id,"partialPage":{"revision":3,"offset":0}})
        );
        let digest = "b".repeat(64);
        let mut next = base.clone();
        next.extend(
            ["--offset", "2048", "--sha256", digest.as_str()]
                .into_iter()
                .map(OsString::from),
        );
        let parsed = parse(&next, 0).ok().expect("pinned continuation");
        assert_eq!(
            parsed.params["partialPage"],
            json!({"revision":3,"offset":2048,"sha256":digest})
        );
        for extra in [
            vec!["--offset", "1"],
            vec!["--offset", "-1"],
            vec!["--offset", "4194305"],
            vec!["--sha256", "bad"],
            vec!["--offset", "0", "--offset", "0"],
            vec!["--wait-ms", "0"],
            vec!["--after", "0"],
            vec!["--limit", "1"],
        ] {
            let mut invalid = base.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse(&invalid, 0).is_err());
        }
        let mut invalid = base;
        invalid[2] = OsString::from("0");
        assert!(parse(&invalid, 0).is_err());
    }

    #[test]
    fn memory_encrypted_export_requires_a_new_local_file_and_separate_secret_input() {
        let mut arguments: Vec<OsString> = [
            "export",
            "session",
            "--revision",
            "0",
            "--device-profile",
            "work",
            "--idempotency-key",
            "archive-key",
            "--destination",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        arguments.push(
            std::env::temp_dir()
                .join("owned-memory-export.age")
                .into_os_string(),
        );
        arguments.extend([
            OsString::from("--endpoint"),
            OsString::from("ws://127.0.0.1:18789"),
        ]);
        arguments.push(OsString::from("--passphrase-stdin"));
        let parsed = parse_memory(&arguments, 0)
            .ok()
            .expect("encrypted export arguments");
        assert!(parsed.memory.expect("memory").export_file.is_some());
        assert!(parse_memory(&arguments[..arguments.len() - 1], 0).is_err());
        for extra in [
            vec!["--offset", "0"],
            vec!["--token-stdin"],
            vec!["--passphrase-stdin"],
            vec!["--overwrite"],
        ] {
            let mut invalid = arguments.clone();
            invalid.extend(extra.into_iter().map(OsString::from));
            assert!(parse_memory(&invalid, 0).is_err());
        }
        arguments[9] = OsString::from("relative.age");
        assert!(parse_memory(&arguments, 0).is_err());
        assert!(super::super::state_snapshot::parse_passphrase(b"tiny").is_err());
        assert!(
            super::super::state_snapshot::parse_passphrase(b"long test passphrase\r\n").is_ok()
        );
        let mut import: Vec<OsString> = [
            "import",
            "session",
            "--expected-revision",
            "0",
            "--device-profile",
            "work",
            "--idempotency-key",
            "import-key",
            "--endpoint",
            "ws://127.0.0.1:18789",
            "--archive-file",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        import.push(
            std::env::temp_dir()
                .join("owned-memory-export.age")
                .into_os_string(),
        );
        import.push("--request-stdin".into());
        assert!(parse_memory(&import, 0).is_ok());
        assert!(parse_memory(&import[..import.len() - 1], 0).is_err());
        import.push("--archive-stdin".into());
        assert!(parse_memory(&import, 0).is_err());
        assert!(
            memory_export_credentials(
                br#"{"token":"fixture-token","passphrase":"fixture archive passphrase"}"#
            )
            .is_ok()
        );
        for input in [br#"{"token":"fixture-token","passphrase":"short"}"#.as_slice(), br#"{"token":"fixture-token","passphrase":"fixture archive passphrase","passphrase":"other"}"#.as_slice(), br#"{"token":"fixture-token","passphrase":"fixture archive passphrase","content":"unexpected"}"#.as_slice()] {
            assert!(memory_export_credentials(input).is_err());
        }
    }

    #[test]
    fn memory_archive_pages_require_contiguous_utf8_identity_and_final_digest() {
        let archive = json!({"schemaVersion":1,"notebook":{"revision":7,"entries":[{"id":"Note","kind":"fact","content":"\u{4e2d}\u{6587}".repeat(1_000),"sourceSession":"source-session","revision":7}]}}).to_string();
        let digest = memory_sha256(archive.as_bytes());
        let mut pages = Vec::new();
        let mut offset = 0;
        while offset < archive.len() {
            let mut end = archive.len().min(offset + 2_048);
            while !archive.is_char_boundary(end) {
                end -= 1;
            }
            pages.push(json!({"archiveSchemaVersion":1,"notebookRevision":7,"sha256":digest,"totalBytes":archive.len(),"offset":offset,"data":&archive[offset..end],"nextOffset":(end < archive.len()).then_some(end),"plaintext":true,"untrustedContent":true,"grantsAuthority":false}));
            offset = end;
        }
        assert!(pages.len() > 2);
        let mut collector = MemoryArchivePages::new(7);
        for (index, page) in pages.iter().enumerate() {
            assert_eq!(
                collector.push(&page.to_string()).expect("valid page"),
                index + 1 == pages.len()
            );
        }
        assert!(collector.push(&pages[0].to_string()).is_err());
        assert_eq!(
            collector.finish().expect("verified archive").as_slice(),
            archive.as_bytes()
        );
        let mut collector = MemoryArchivePages::new(7);
        collector.push(&pages[0].to_string()).expect("first page");
        assert!(collector.push(&pages[0].to_string()).is_err());
        assert!(collector.finish().is_err());
        for (field, replacement) in [
            ("offset", json!(1)),
            ("notebookRevision", json!(8)),
            (
                "totalBytes",
                json!(claw_state::MAX_MEMORY_ARCHIVE_BYTES + 1),
            ),
            ("nextOffset", json!(0)),
            ("plaintext", json!(false)),
            ("grantsAuthority", json!(true)),
            ("data", json!("x".repeat(2_049))),
        ] {
            let mut bad = pages[0].clone();
            bad[field] = replacement;
            assert!(
                MemoryArchivePages::new(7).push(&bad.to_string()).is_err(),
                "{field}"
            );
        }
        let mut collector = MemoryArchivePages::new(7);
        for page in &pages {
            let mut page = page.clone();
            page["sha256"] = json!("0".repeat(64));
            collector
                .push(&page.to_string())
                .expect("digest is verified only after all pages");
        }
        assert!(collector.finish().is_err());
        let mut collector = MemoryArchivePages::new(7);
        collector.push(&pages[0].to_string()).expect("first page");
        let mut changed = pages[1].clone();
        changed["sha256"] = json!("0".repeat(64));
        assert!(collector.push(&changed.to_string()).is_err());
        assert!(
            MemoryArchivePages::new(7)
                .push(r#"{"offset":0,"offset":0}"#)
                .is_err()
        );
    }

    #[test]
    fn explicit_tool_message_keeps_parameters_as_data() {
        let arguments = json!({"action":"save","content":"note\n!goal do not execute"});
        let message =
            explicit_tool_message("memory_notes", &arguments).expect("explicit tool message");
        assert_eq!(message.lines().count(), 1);
        let decoded: Value =
            serde_json::from_str(message.strip_prefix("!tool ").expect("native directive"))
                .expect("JSON body");
        assert_eq!(
            decoded,
            json!({"name":"memory_notes","arguments":arguments})
        );
        for name in ["", "../tool", "name\n!goal", "tool name"] {
            assert!(explicit_tool_message(name, &json!({})).is_err());
        }
        assert!(explicit_tool_message("memory_notes", &json!([])).is_err());
        assert!(
            explicit_tool_message("memory_notes", &json!({"content":"x".repeat(16 * 1024)}))
                .is_err()
        );
    }
}

pub(super) fn parse(
    arguments: &[OsString],
    command_index: usize,
) -> Result<NativeCommand, ParseFailure> {
    let invalid = || parse_failure("invalid native Gateway command or arguments", arguments);
    let command = arguments
        .get(command_index)
        .and_then(|argument| argument.to_str())
        .ok_or_else(invalid)?;
    if command == "memory" {
        return parse_memory(arguments, command_index + 1);
    }
    let mut index = command_index + 1;
    let mut positional = || -> Result<String, ParseFailure> {
        let value = option_value(arguments, index, "missing native command argument")?
            .to_str()
            .ok_or_else(invalid)?
            .to_owned();
        index += 1;
        Ok(value)
    };
    let (method, scope, mut params) = match command {
        "device" => ("device.profile", Scope::OperatorRead, json!({})),
        "forget-device" => ("device.forget", Scope::OperatorRead, json!({})),
        "sessions" => ("sessions.list", Scope::OperatorRead, json!({})),
        "models" | "export-models" => (
            "models.list",
            Scope::OperatorRead,
            json!({"nativeCatalogPage":{"offset":0}}),
        ),
        "refresh-models" => (
            "models.list",
            Scope::OperatorWrite,
            json!({"nativeCatalogRefresh":{}}),
        ),
        "describe" | "history" | "abort" | "send" | "results" => {
            let session = positional()?;
            if session.is_empty() || session.len() > 128 || session.chars().any(char::is_control) {
                return Err(invalid());
            }
            let (method, scope) = match command {
                "describe" => ("sessions.describe", Scope::OperatorRead),
                "history" => ("chat.history", Scope::OperatorRead),
                "abort" => ("chat.abort", Scope::OperatorWrite),
                "results" => ("sessions.get", Scope::OperatorRead),
                _ => ("chat.send", Scope::OperatorWrite),
            };
            let mut params = if command == "describe" {
                json!({"key": session})
            } else {
                json!({"sessionKey": session})
            };
            if command == "send" {
                let message = positional()?;
                if message.trim().is_empty() || message.len() > 60 * 1024 {
                    return Err(invalid());
                }
                params["message"] = Value::String(message);
            }
            (method, scope, params)
        }
        "run" | "ack-run" | "partial-run" | "export-partial" | "accounting-run"
        | "export-accounting" => {
            let id = positional()?;
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid());
            }
            let mut params = json!({"runId": id});
            if matches!(
                command,
                "ack-run"
                    | "partial-run"
                    | "export-partial"
                    | "accounting-run"
                    | "export-accounting"
            ) {
                let revision = positional()?
                    .parse::<u64>()
                    .ok()
                    .filter(|revision| *revision > 0)
                    .ok_or_else(invalid)?;
                if matches!(command, "accounting-run" | "export-accounting") {
                    params["accountingPage"] = json!({"revision":revision,"offset":0});
                } else if matches!(command, "partial-run" | "export-partial") {
                    params["partialPage"] = json!({"revision":revision,"offset":0});
                } else {
                    params["acknowledgeRevision"] = json!(revision);
                }
            }
            ("agent.wait", Scope::OperatorRead, params)
        }
        "approval" | "approve" | "deny" => {
            let id = ApprovalId::new(positional()?).map_err(|_| invalid())?;
            let mut params = json!({"id": id.as_str()});
            let method = if command == "approval" {
                "exec.approval.get"
            } else {
                params["decision"] = Value::String(command.to_owned());
                "exec.approval.resolve"
            };
            (method, Scope::OperatorApprovals, params)
        }
        "approvals" => {
            let mut params = json!({});
            if arguments
                .get(index)
                .and_then(|argument| argument.to_str())
                .is_some_and(|argument| !argument.starts_with('-'))
            {
                let session = arguments[index].to_str().ok_or_else(invalid)?;
                if session.is_empty()
                    || session.len() > 128
                    || session.chars().any(char::is_control)
                {
                    return Err(invalid());
                }
                params["sessionId"] = Value::String(session.to_owned());
                index += 1;
            }
            ("exec.approval.list", Scope::OperatorApprovals, params)
        }
        _ => return Err(invalid()),
    };
    let mut options = Vec::new();
    let mut idempotency = None;
    let mut wait_seen = false;
    let mut cursor_seen = false;
    let mut partial_offset_seen = false;
    let mut run_seen = false;
    let mut preview_fingerprint = None;
    let mut partial_export = None;
    let mut accounting_export = None;
    let mut model_export = None;
    while index < arguments.len() {
        if arguments[index] == "--availability" {
            if command != "models"
                || params["nativeCatalogPage"]
                    .get("includeAvailability")
                    .is_some()
            {
                return Err(invalid());
            }
            params["nativeCatalogPage"]["includeAvailability"] = json!(true);
        } else if arguments[index] == "--destination" {
            if !matches!(
                command,
                "export-partial" | "export-accounting" | "export-models"
            ) || partial_export.is_some()
                || accounting_export.is_some()
                || model_export.is_some()
            {
                return Err(invalid());
            }
            index += 1;
            let destination = std::path::PathBuf::from(option_value(
                arguments,
                index,
                "missing run export destination",
            )?);
            if !super::state_snapshot::local_absolute(&destination) {
                return Err(invalid());
            }
            if command == "export-models" {
                model_export = Some(destination);
            } else if command == "export-accounting" {
                accounting_export = Some(destination);
            } else {
                partial_export = Some(destination);
            }
        } else if arguments[index] == "--idempotency-key" {
            if method != "chat.send" || idempotency.is_some() {
                return Err(invalid());
            }
            index += 1;
            let key = option_value(arguments, index, "missing idempotency key")?
                .to_str()
                .ok_or_else(invalid)?;
            if key.is_empty() || key.len() > 128 || key.chars().any(char::is_control) {
                return Err(invalid());
            }
            idempotency = Some(key.to_owned());
        } else if arguments[index] == "--preview-fingerprint" {
            if !matches!(command, "approve" | "deny") || preview_fingerprint.is_some() {
                return Err(invalid());
            }
            index += 1;
            let fingerprint = option_value(arguments, index, "missing preview fingerprint")?
                .to_str()
                .ok_or_else(invalid)?;
            if fingerprint.len() != 64
                || !fingerprint
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid());
            }
            preview_fingerprint = Some(fingerprint.to_owned());
        } else if arguments[index] == "--run-id" {
            if command != "abort" || run_seen {
                return Err(invalid());
            }
            index += 1;
            let id = option_value(arguments, index, "missing run identity")?
                .to_str()
                .ok_or_else(invalid)?;
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid());
            }
            params["runId"] = json!(id);
            run_seen = true;
        } else if arguments[index] == "--limit" {
            if command != "history" || params.get("limit").is_some() {
                return Err(invalid());
            }
            index += 1;
            let limit = option_value(arguments, index, "missing history limit")?
                .to_str()
                .ok_or_else(invalid)?
                .parse::<u16>()
                .ok()
                .filter(|value| (1..=1000).contains(value))
                .ok_or_else(invalid)?;
            params["limit"] = json!(limit);
        } else if arguments[index] == "--offset" {
            if !matches!(command, "partial-run" | "accounting-run" | "models")
                || partial_offset_seen
            {
                return Err(invalid());
            }
            index += 1;
            let offset = option_value(arguments, index, "missing partial byte offset")?
                .to_str()
                .ok_or_else(invalid)?
                .parse::<usize>()
                .ok()
                .filter(|offset| {
                    *offset
                        <= if matches!(command, "accounting-run" | "models") {
                            1024
                        } else {
                            4 * 1024 * 1024
                        }
                })
                .ok_or_else(invalid)?;
            params[match command {
                "accounting-run" => "accountingPage",
                "models" => "nativeCatalogPage",
                _ => "partialPage",
            }]["offset"] = json!(offset);
            partial_offset_seen = true;
        } else if arguments[index] == "--sha256" {
            let page = match command {
                "accounting-run" => "accountingPage",
                "models" => "nativeCatalogPage",
                "refresh-models" => "nativeCatalogRefresh",
                _ => "partialPage",
            };
            if !matches!(
                command,
                "partial-run" | "accounting-run" | "models" | "refresh-models"
            ) || params[page].get("sha256").is_some()
            {
                return Err(invalid());
            }
            index += 1;
            let digest = option_value(arguments, index, "missing partial content digest")?
                .to_str()
                .ok_or_else(invalid)?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid());
            }
            params[page]["sha256"] = json!(digest);
        } else if arguments[index] == "--wait-ms" {
            if command != "run" || wait_seen {
                return Err(invalid());
            }
            index += 1;
            let millis = option_value(arguments, index, "missing wait bound")?
                .to_str()
                .ok_or_else(invalid)?
                .parse::<u64>()
                .ok()
                .filter(|value| *value <= 120_000)
                .ok_or_else(invalid)?;
            params["timeoutMs"] = json!(millis);
            wait_seen = true;
        } else if arguments[index] == "--after" {
            if command != "results" || cursor_seen {
                return Err(invalid());
            }
            index += 1;
            let cursor = option_value(arguments, index, "missing result cursor")?
                .to_str()
                .ok_or_else(invalid)?;
            if cursor.len() != 64
                || !cursor
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid());
            }
            params["after"] = json!(cursor);
            cursor_seen = true;
        } else {
            options.push(arguments[index].clone());
        }
        index += 1;
    }
    if method == "chat.send" {
        params["idempotencyKey"] = Value::String(idempotency.ok_or_else(|| {
            parse_failure("send requires an explicit --idempotency-key", arguments)
        })?);
    }
    let page = match command {
        "accounting-run" => "accountingPage",
        "models" => "nativeCatalogPage",
        _ => "partialPage",
    };
    if params["nativeCatalogPage"]
        .get("includeAvailability")
        .is_some()
        && (params["nativeCatalogPage"]["offset"] != 0
            || params["nativeCatalogPage"].get("sha256").is_some())
    {
        return Err(invalid());
    }
    if matches!(command, "partial-run" | "accounting-run" | "models")
        && params[page]["offset"]
            .as_u64()
            .is_some_and(|offset| offset > 0)
        && params[page].get("sha256").is_none()
    {
        return Err(invalid());
    }
    if matches!(command, "approve" | "deny") && preview_fingerprint.is_none() {
        return Err(parse_failure(
            "approval decisions require --preview-fingerprint from a complete gateway approval preview",
            arguments,
        ));
    }
    if command == "export-partial" && partial_export.is_none() {
        return Err(parse_failure(
            "export-partial requires an explicit new local --destination",
            arguments,
        ));
    }
    if command == "refresh-models" && params["nativeCatalogRefresh"]["sha256"].as_str().is_none() {
        return Err(parse_failure(
            "refresh-models requires --sha256 from an observed native catalogue",
            arguments,
        ));
    }
    if command == "export-accounting" && accounting_export.is_none() {
        return Err(parse_failure(
            "export-accounting requires an explicit new local --destination",
            arguments,
        ));
    }
    if command == "export-models" && model_export.is_none() {
        return Err(parse_failure(
            "export-models requires an explicit new local --destination",
            arguments,
        ));
    }
    let options = parse_gateway_options(&options, 0, true)?;
    if matches!(command, "device" | "forget-device") && options.device_profile.is_none() {
        return Err(parse_failure(
            "local device commands require --device-profile",
            arguments,
        ));
    }
    Ok(NativeCommand {
        options,
        method,
        scope,
        params,
        preview_fingerprint,
        memory: None,
        partial_export,
        accounting_export,
        model_export,
    })
}

fn parse_memory(arguments: &[OsString], start: usize) -> Result<NativeCommand, ParseFailure> {
    let invalid = || {
        parse_failure(
            "invalid memory command; use list/get/search/save/delete/export/import with an explicit session, persistent profile and idempotency key",
            arguments,
        )
    };
    let action = arguments
        .get(start)
        .and_then(|value| value.to_str())
        .ok_or_else(invalid)?;
    if !matches!(
        action,
        "list" | "get" | "search" | "save" | "delete" | "export" | "import"
    ) {
        return Err(invalid());
    }
    let session = arguments
        .get(start + 1)
        .and_then(|value| value.to_str())
        .ok_or_else(invalid)?;
    if session.is_empty() || session.len() > 128 || session.chars().any(char::is_control) {
        return Err(invalid());
    }
    let mut parameters = json!({"action":action});
    let mut options = Vec::new();
    let mut content_stdin = false;
    let mut archive_stdin = false;
    let mut request_stdin = false;
    let mut export_file = None;
    let mut import_file = None;
    let mut passphrase_stdin = false;
    let mut idempotency = None;
    let mut index = start + 2;
    while index < arguments.len() {
        let flag = arguments[index].to_str().ok_or_else(invalid)?;
        if flag == "--archive-file" {
            if action != "import" || import_file.is_some() {
                return Err(invalid());
            }
            let path = std::path::PathBuf::from(option_value(
                arguments,
                index + 1,
                "missing encrypted archive source",
            )?);
            if !super::state_snapshot::local_absolute(&path) {
                return Err(invalid());
            }
            import_file = Some(path);
            index += 2;
            continue;
        }
        if flag == "--destination" {
            if action != "export" || export_file.is_some() {
                return Err(invalid());
            }
            let path = std::path::PathBuf::from(option_value(
                arguments,
                index + 1,
                "missing export destination",
            )?);
            if !super::state_snapshot::local_absolute(&path) {
                return Err(invalid());
            }
            export_file = Some(path);
            index += 2;
            continue;
        }
        if flag == "--passphrase-stdin" {
            if !matches!(action, "export" | "import") || passphrase_stdin {
                return Err(invalid());
            }
            passphrase_stdin = true;
            index += 1;
            continue;
        }
        if flag == "--request-stdin" {
            if !matches!(action, "save" | "import" | "export") || request_stdin {
                return Err(invalid());
            }
            request_stdin = true;
            index += 1;
            continue;
        }
        if flag == "--content-stdin" {
            if action != "save" || content_stdin {
                return Err(invalid());
            }
            content_stdin = true;
            index += 1;
            continue;
        }
        if flag == "--archive-stdin" {
            if action != "import" || archive_stdin {
                return Err(invalid());
            }
            archive_stdin = true;
            index += 1;
            continue;
        }
        if flag == "--overwrite" {
            if action != "import" || parameters.get("overwrite").is_some() {
                return Err(invalid());
            }
            parameters["overwrite"] = json!(true);
            index += 1;
            continue;
        }
        let field = match flag {
            "--note-id" if matches!(action, "get" | "save" | "delete") => "id",
            "--kind" if action == "save" => "kind",
            "--query" if action == "search" => "query",
            "--expected-revision" if matches!(action, "save" | "delete" | "import") => {
                "expectedRevision"
            }
            "--revision" if matches!(action, "list" | "get" | "export") => "revision",
            "--offset" if matches!(action, "get" | "export") => "offset",
            "--after" if action == "list" => "after",
            "--limit" if matches!(action, "list" | "search") => "limit",
            "--idempotency-key" => "idempotencyKey",
            "--note-id"
            | "--kind"
            | "--query"
            | "--expected-revision"
            | "--revision"
            | "--offset"
            | "--after"
            | "--limit" => return Err(invalid()),
            _ => {
                options.push(arguments[index].clone());
                index += 1;
                continue;
            }
        };
        let value = option_value(arguments, index + 1, "missing memory command option")?
            .to_str()
            .ok_or_else(invalid)?;
        if parameters.get(field).is_some() || field == "idempotencyKey" && idempotency.is_some() {
            return Err(invalid());
        }
        if field == "idempotencyKey" {
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                return Err(invalid());
            }
            idempotency = Some(value.to_owned());
        } else if matches!(field, "revision" | "expectedRevision" | "offset" | "limit") {
            let number = value.parse::<u64>().map_err(|_| invalid())?;
            if field == "offset"
                && number
                    > if action == "export" {
                        claw_state::MAX_MEMORY_ARCHIVE_BYTES as u64
                    } else {
                        claw_state::MAX_MEMORY_CONTENT_BYTES as u64
                    }
                || field == "limit"
                    && !(1..=if action == "search" { 8 } else { 32 }).contains(&number)
            {
                return Err(invalid());
            }
            parameters[field] = json!(number);
        } else {
            let valid = match field {
                "id" | "after" => {
                    !value.is_empty()
                        && value.len() <= 64
                        && value.bytes().enumerate().all(|(position, byte)| {
                            byte.is_ascii_alphanumeric()
                                || position > 0 && matches!(byte, b'_' | b'-' | b'.')
                        })
                }
                "kind" => matches!(value, "fact" | "preference" | "procedure"),
                "query" => !value.trim().is_empty() && value.len() <= 4096,
                _ => false,
            };
            if !valid {
                return Err(invalid());
            }
            parameters[field] = json!(value);
        }
        index += 2;
    }
    let required: &[&str] = match action {
        "list" => &[],
        "get" => &["id"],
        "search" => &["query"],
        "save" => &["id", "kind", "expectedRevision"],
        "delete" => &["id", "expectedRevision"],
        "export" => &["revision"],
        "import" => &["expectedRevision"],
        _ => return Err(invalid()),
    };
    if required
        .iter()
        .any(|field| parameters.get(*field).is_none())
        || action == "save" && !content_stdin && !request_stdin
        || action == "import" && !archive_stdin && !request_stdin && import_file.is_none()
        || request_stdin && (content_stdin || archive_stdin)
        || passphrase_stdin && export_file.is_none() && import_file.is_none()
        || (export_file.is_some() || import_file.is_some()) && !passphrase_stdin && !request_stdin
        || action == "export" && request_stdin && export_file.is_none()
        || import_file.is_some() && (content_stdin || archive_stdin)
        || passphrase_stdin && request_stdin
        || export_file.is_some() && parameters.get("offset").is_some()
        || (parameters.get("after").is_some()
            || parameters["offset"]
                .as_u64()
                .is_some_and(|offset| offset > 0))
            && parameters.get("revision").is_none()
    {
        return Err(invalid());
    }
    let options = parse_gateway_options(&options, 0, true)?;
    if options.device_profile.is_none()
        || request_stdin && !matches!(options.secret_source, super::SecretSourceKind::None)
        || (content_stdin || archive_stdin || passphrase_stdin)
            && matches!(options.secret_source, super::SecretSourceKind::Stdin)
    {
        return Err(parse_failure(
            "memory commands require --device-profile; choose one stdin mode, using --request-stdin for token plus content/archive",
            arguments,
        ));
    }
    let key = idempotency.ok_or_else(invalid)?;
    Ok(NativeCommand {
        options,
        method: "chat.send",
        scope: Scope::OperatorWrite,
        params: json!({"sessionKey":session,"idempotencyKey":key}),
        preview_fingerprint: None,
        memory: Some(Box::new(MemoryRequest {
            arguments: parameters,
            content_stdin,
            archive_stdin,
            request_stdin,
            export_file,
            import_file,
        })),
        partial_export: None,
        accounting_export: None,
        model_export: None,
    })
}

fn memory_content(bytes: &[u8]) -> Result<&str, DiagnosticFailure> {
    let invalid = || {
        DiagnosticFailure::usage(
            "invalid_memory_content",
            "memory content must be nonblank UTF-8, at most 8192 bytes, with no controls except tab, CR and LF",
        )
    };
    if bytes.len() > claw_state::MAX_MEMORY_CONTENT_BYTES {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    if text.trim().is_empty()
        || text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(invalid());
    }
    Ok(text)
}

fn memory_archive(bytes: &[u8]) -> Result<claw_state::MemoryArchive, DiagnosticFailure> {
    let invalid = || {
        DiagnosticFailure::usage(
            "invalid_memory_archive",
            "memory archive must be bounded schema-v1 JSON with unique ordered note IDs and valid content/source revisions; no command was sent",
        )
    };
    if bytes.len() > 16 * 1024 {
        return Err(invalid());
    }
    let archive: claw_state::MemoryArchive =
        serde_json::from_slice(bytes).map_err(|_| invalid())?;
    archive.validate().map_err(|_| invalid())?;
    Ok(archive)
}

fn memory_request_input(
    bytes: &[u8],
    action: &str,
) -> Result<(claw_gateway_client::GatewayCredential, Value), DiagnosticFailure> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input<'a> {
        #[serde(borrow)]
        token: &'a serde_json::value::RawValue,
        content: Option<String>,
        archive: Option<claw_state::MemoryArchive>,
    }
    let invalid = || {
        DiagnosticFailure::usage(
            "invalid_memory_request_input",
            "request stdin must be bounded JSON containing token and exactly the content or archive required by the memory action",
        )
    };
    if bytes.len() > 64 * 1024 {
        return Err(invalid());
    }
    let input: Input<'_> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let token =
        Zeroizing::new(serde_json::from_str::<String>(input.token.get()).map_err(|_| invalid())?);
    if token
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid());
    }
    let credential =
        super::parse_secret(token.as_bytes()).map(claw_gateway_client::GatewayCredential::Token)?;
    let field = match (action, input.content, input.archive) {
        ("save", Some(content), None) => {
            memory_content(content.as_bytes())?;
            json!({"content":content})
        }
        ("import", None, Some(archive)) => {
            archive.validate().map_err(|_| invalid())?;
            json!({"archive":archive})
        }
        _ => return Err(invalid()),
    };
    Ok((credential, field))
}

fn memory_export_credentials(
    bytes: &[u8],
) -> Result<
    (
        claw_gateway_client::GatewayCredential,
        age::secrecy::SecretString,
    ),
    DiagnosticFailure,
> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input<'a> {
        #[serde(borrow)]
        token: &'a serde_json::value::RawValue,
        #[serde(borrow)]
        passphrase: &'a serde_json::value::RawValue,
    }
    let invalid = || {
        DiagnosticFailure::usage(
            "invalid_export_credentials",
            "Memory file request stdin must contain only a valid token and passphrase",
        )
    };
    if bytes.len() > 64 * 1024 {
        return Err(invalid());
    }
    let input: Input<'_> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let token =
        Zeroizing::new(serde_json::from_str::<String>(input.token.get()).map_err(|_| invalid())?);
    let passphrase = Zeroizing::new(
        serde_json::from_str::<String>(input.passphrase.get()).map_err(|_| invalid())?,
    );
    if token
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
        || passphrase.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let credential =
        super::parse_secret(token.as_bytes()).map(claw_gateway_client::GatewayCredential::Token)?;
    let secret =
        super::state_snapshot::parse_passphrase(passphrase.as_bytes()).map_err(|_| invalid())?;
    Ok((credential, secret))
}

fn check_memory_capabilities(health: &Value) -> Result<(), DiagnosticFailure> {
    let native = &health["native"];
    let direct = &native["directTool"];
    let memory = &native["explicitMemory"];
    if health["ok"] != true
        || health["protocol"] != 4
        || native["schemaVersion"] != 1
        || direct["version"] != 1
        || direct["prefix"] != "!tool "
        || direct["modelInvoked"] != false
        || direct["authenticated"] != true
        || direct["durableRuns"] != true
        || direct["approvalPolicy"] != "per-tool"
        || direct["accepting"] != true
        || memory["enabled"] != true
        || memory["accepting"] != true
        || memory["requiresApproval"] != true
        || memory["partition"] != "source/subject/account"
        || memory["automaticContextInjection"] != false
    {
        return Err(DiagnosticFailure::protocol(
            "native_memory_unavailable",
            "Gateway does not advertise the required authenticated, model-free memory contract; no memory command was sent",
        ));
    }
    Ok(())
}

fn check_memory_receipt(receipt: &Value, session: &Value) -> Result<(), DiagnosticFailure> {
    if receipt["sessionId"] != *session
        || receipt["durable"] != true
        || receipt["status"] != "accepted"
        || receipt["revision"]
            .as_u64()
            .is_none_or(|revision| revision == 0)
        || !receipt["runId"].as_str().is_some_and(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        || !matches!(
            receipt["phase"].as_str(),
            Some("queued" | "executing" | "finished" | "outcome_unknown")
        )
    {
        return Err(DiagnosticFailure::protocol(
            "malformed_memory_receipt",
            "Gateway did not confirm the exact durable memory run; keep the original idempotency key and inspect state before retrying",
        ));
    }
    Ok(())
}

async fn memory_export_request(
    client: &GatewayClient,
    epoch: ConnectionEpoch,
    id: String,
    method: &'static str,
    params: &Value,
) -> Result<Value, DiagnosticFailure> {
    let response = client
        .request_for_epoch(
            epoch,
            RequestId::new(id, AUTHENTICATED_MAX_FRAME_BYTES)
                .expect("bounded export request identity"),
            GatewayMethodName::Core(resolve_core_method(method).expect("fixed export method")),
            params,
        )
        .await
        .map_err(|error| map_client_error(&error))?;
    if !response.ok() {
        return Err(DiagnosticFailure::protocol(
            "memory_export_refused",
            "Memory export request was refused; retain original page keys and inspect existing runs before retrying",
        ));
    }
    let payload = response.payload().value().ok_or_else(|| {
        DiagnosticFailure::protocol(
            "memory_export_invalid_response",
            "Memory export response is missing",
        )
    })?;
    claw_protocol::gateway::Codec::authenticated()
        .decode_opaque(payload)
        .map_err(|_| {
            DiagnosticFailure::protocol(
                "memory_export_invalid_response",
                "Memory export response is not unambiguous JSON",
            )
        })
}

async fn collect_memory_archive(
    client: &GatewayClient,
    epoch: ConnectionEpoch,
    events: &mut GatewayEventStream,
    parameters: &Value,
    revision: u64,
    progress: &mut Value,
) -> Result<(Zeroizing<Vec<u8>>, usize), DiagnosticFailure> {
    let invalid = |message| DiagnosticFailure::protocol("memory_export_invalid", message);
    let mut collector = MemoryArchivePages::new(revision);
    let mut page_count = 0;
    loop {
        if page_count >= 4_096 {
            return Err(invalid("Memory export exceeded the bounded page count"));
        }
        let offset = collector.bytes.len();
        if offset > 0 {
            let health = memory_export_request(
                client,
                epoch,
                format!("memory-export-health-{offset}"),
                "health",
                &json!({}),
            )
            .await?;
            check_memory_capabilities(&health)?;
            if health["native"]["explicitMemory"]["archiveSchemaVersion"] != 1 {
                return Err(invalid("Memory archive capability changed during export"));
            }
        }
        let mut params = parameters.clone();
        if offset > 0 {
            params["idempotencyKey"] = json!(format!(
                "memory-export-{}",
                memory_sha256(
                    json!([
                        "memory-export/v1",
                        parameters["idempotencyKey"],
                        parameters["sessionKey"],
                        revision,
                        offset
                    ])
                    .to_string()
                    .as_bytes()
                )
            ));
        }
        params["message"] = json!(
            explicit_tool_message(
                "memory_notes",
                &json!({"action":"export","revision":revision,"offset":offset})
            )
            .map_err(invalid)?
        );
        *progress = json!({"offset":offset,"idempotencyKey":params["idempotencyKey"],"runId":null});
        let receipt = memory_export_request(
            client,
            epoch,
            format!("memory-export-send-{offset}"),
            "chat.send",
            &params,
        )
        .await?;
        check_memory_receipt(&receipt, &parameters["sessionKey"])?;
        let run_id = receipt["runId"].as_str().expect("validated run identity");
        progress["runId"] = json!(run_id);
        let mut wait_sequence = 0_u64;
        let text = loop {
            let run = memory_export_request(
                client,
                epoch,
                format!("memory-export-wait-{offset}-{wait_sequence}"),
                "agent.wait",
                &json!({"runId":run_id}),
            )
            .await?;
            if run["durable"] != true
                || run["sessionId"] != parameters["sessionKey"]
                || run["runId"] != run_id
                || run["revision"]
                    .as_u64()
                    .is_none_or(|revision| revision == 0)
            {
                return Err(invalid(
                    "Memory page result does not match the exact durable session and run",
                ));
            }
            if matches!(run["phase"].as_str(), Some("finished" | "outcome_unknown")) {
                if run["result"]["status"] != "completed" {
                    return Err(invalid(
                        "Memory page did not complete successfully; no archive file was written",
                    ));
                }
                break run["result"]["text"]
                    .as_str()
                    .filter(|text| text.len() <= 16 * 1024)
                    .ok_or_else(|| invalid("Memory export result is missing or oversized"))?
                    .to_owned();
            }
            if !matches!(run["phase"].as_str(), Some("queued" | "executing"))
                || !run["result"].is_null()
            {
                return Err(invalid(
                    "Memory export run has an invalid nonterminal state",
                ));
            }
            loop {
                let event = events.recv().await.ok_or_else(|| {
                    invalid("Memory export event stream closed before the page completed")
                })?;
                if event.epoch() != epoch {
                    return Err(invalid("Memory export connection epoch changed"));
                }
                if let Some(payload) = event.frame().payload().value()
                    && let Ok(payload) = claw_protocol::gateway::Codec::authenticated()
                        .decode_opaque::<Value>(payload)
                    && payload["runId"] == run_id
                    && payload["sessionId"] == parameters["sessionKey"]
                {
                    break;
                }
            }
            wait_sequence += 1;
            if wait_sequence > 4_096 {
                return Err(invalid(
                    "Memory export exceeded the bounded page notification limit",
                ));
            }
        };
        page_count += 1;
        if collector.push(&text).map_err(invalid)? {
            break;
        }
    }
    Ok((collector.finish().map_err(invalid)?, page_count))
}

async fn collect_model_export(
    client: &GatewayClient,
    epoch: ConnectionEpoch,
) -> Result<(Zeroizing<Vec<u8>>, Value), DiagnosticFailure> {
    let mut collector = ModelExportPages::default();
    loop {
        let response = client
            .request_for_epoch(
                epoch,
                RequestId::new(
                    format!("native-model-export-{}", collector.pages),
                    AUTHENTICATED_MAX_FRAME_BYTES,
                )
                .expect("bounded request ID"),
                GatewayMethodName::Core(resolve_core_method("models.list").expect("known method")),
                &collector.parameters(),
            )
            .await
            .map_err(|error| map_client_error(&error))?;
        if !response.ok() {
            return Err(DiagnosticFailure::protocol(
                "model_export_refused",
                "Gateway refused a model catalogue page; no file was created",
            ));
        }
        let encoded = response.payload().value().ok_or_else(|| {
            DiagnosticFailure::protocol(
                "invalid_model_export",
                "Gateway model catalogue page is missing",
            )
        })?;
        if collector.push(encoded.as_json())? {
            break;
        }
    }
    let pages = collector.pages;
    let snapshot = collector.finish()?;
    let archive = json!({"schemaVersion":1,"kind":"gta-claw.provider-model-catalogue",
        "snapshot":snapshot,"plaintext":true,"untrusted":true});
    let bytes = Zeroizing::new(serde_json::to_vec(&archive).map_err(|_| {
        DiagnosticFailure::internal(
            "model_export_encoding",
            "Model catalogue export could not be encoded",
        )
    })?);
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(DiagnosticFailure::protocol(
            "model_export_size_limit",
            "Model catalogue export exceeds its bounded file size",
        ));
    }
    let receipt = json!({"provider":snapshot["provider"],"providerGeneration":snapshot["providerGeneration"],
        "selectedModel":snapshot["selectedModel"],"selectionPinned":snapshot["selectionPinned"],
        "observedAtMs":snapshot["observedAtMs"],"totalModels":snapshot["totalModels"],"sha256":snapshot["sha256"],
        "pages":pages,"fileSha256":memory_sha256(&bytes),"bytes":bytes.len(),"snapshotVerified":true,
        "fileCreated":false,"plaintext":true,"untrusted":true,"selectionChanged":false,
        "networkContacted":false,"inferenceInvoked":false,"liveCapabilitiesVerified":false,"directoryDurabilityVerified":false});
    Ok((bytes, receipt))
}

async fn collect_accounting_export(
    client: &GatewayClient,
    epoch: ConnectionEpoch,
    parameters: &Value,
) -> Result<(Zeroizing<Vec<u8>>, Value), DiagnosticFailure> {
    let mut collector = AccountingExportPages::new(
        parameters["runId"].as_str().expect("parsed run").to_owned(),
        parameters["accountingPage"]["revision"]
            .as_u64()
            .expect("parsed revision"),
    );
    loop {
        let response = client
            .request_for_epoch(
                epoch,
                RequestId::new(
                    format!("native-accounting-export-{}", collector.pages),
                    AUTHENTICATED_MAX_FRAME_BYTES,
                )
                .expect("bounded request ID"),
                GatewayMethodName::Core(resolve_core_method("agent.wait").expect("known method")),
                &collector.parameters(),
            )
            .await
            .map_err(|error| map_client_error(&error))?;
        if !response.ok() {
            return Err(DiagnosticFailure::protocol(
                "accounting_export_refused",
                "Gateway refused an accounting export page; no file was created",
            ));
        }
        let encoded = response.payload().value().ok_or_else(|| {
            DiagnosticFailure::protocol(
                "invalid_accounting_page",
                "Gateway accounting export page is missing",
            )
        })?;
        if collector.push(encoded.as_json())? {
            break;
        }
    }
    let pages = collector.pages;
    let snapshot = collector.finish()?;
    let archive = json!({"schemaVersion":1,"kind":"gta-claw.provider-accounting",
        "snapshot":snapshot,"plaintext":true,"untrusted":true});
    let bytes = Zeroizing::new(serde_json::to_vec(&archive).map_err(|_| {
        DiagnosticFailure::internal(
            "accounting_export_encoding",
            "Accounting export could not be encoded",
        )
    })?);
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(DiagnosticFailure::protocol(
            "accounting_export_size_limit",
            "Accounting export exceeds its bounded file size; no file was created",
        ));
    }
    let receipt = json!({"runId":snapshot["runId"],"sessionId":snapshot["sessionId"],
        "revision":snapshot["revision"],"turn":snapshot["turn"],"status":snapshot["status"],
        "totalRounds":snapshot["accounting"]["totalRounds"],"sha256":snapshot["accounting"]["sha256"],
        "pages":pages,"fileSha256":memory_sha256(&bytes),"bytes":bytes.len(),"snapshotVerified":true,
        "fileCreated":false,"plaintext":true,"untrusted":true,"acknowledged":false,"automaticReplay":false,
        "costCalculated":false,"billingReconciled":false,"directoryDurabilityVerified":false});
    Ok((bytes, receipt))
}

async fn collect_partial_export(
    client: &GatewayClient,
    epoch: ConnectionEpoch,
    parameters: &Value,
) -> Result<(Zeroizing<Vec<u8>>, Value), DiagnosticFailure> {
    let mut collector = PartialExportPages::new(
        parameters["runId"].as_str().expect("parsed run").to_owned(),
        parameters["partialPage"]["revision"]
            .as_u64()
            .expect("parsed revision"),
    );
    loop {
        if collector.pages >= 4096 {
            return Err(DiagnosticFailure::protocol(
                "partial_export_page_limit",
                "Partial export exceeds its bounded page count",
            ));
        }
        let request = RequestId::new(
            format!("native-partial-export-{}", collector.pages),
            AUTHENTICATED_MAX_FRAME_BYTES,
        )
        .expect("bounded request ID");
        let response = client
            .request_for_epoch(
                epoch,
                request,
                GatewayMethodName::Core(resolve_core_method("agent.wait").expect("known method")),
                &collector.parameters(),
            )
            .await
            .map_err(|error| map_client_error(&error))?;
        if !response.ok() {
            return Err(DiagnosticFailure::protocol(
                "partial_export_refused",
                "Gateway refused a partial export page; no file was created",
            ));
        }
        let encoded = response.payload().value().ok_or_else(|| {
            DiagnosticFailure::protocol(
                "invalid_partial_page",
                "Gateway partial export page is missing",
            )
        })?;
        if collector.push(encoded.as_json())? {
            break;
        }
    }
    let identity = collector
        .identity
        .as_ref()
        .expect("validated export identity");
    let receipt = json!({"runId":collector.run_id,"revision":collector.revision,"sessionId":identity.session_id,
        "turn":identity.turn,"status":identity.status,"bytes":identity.total_bytes,"sha256":identity.sha256,
        "pages":collector.pages,"fileCreated":false,"plaintext":true,"untrusted":true,"messageComplete":false,
        "acknowledged":false,"automaticReplay":false,"reasoningIncluded":false,"toolArgumentsIncluded":false});
    Ok((collector.finish()?, receipt))
}

pub(super) async fn run(command: NativeCommand) -> RenderedResult {
    let diagnostics = super::Diagnostics::for_verbosity(command.options.verbosity);
    let mut client = None;
    let mut submitted = false;
    let mut prepared_export = None;
    let mut prepared_run_export = None;
    let mut run_file_started = false;
    let mut import_task = None;
    let mut export_progress = Value::Null;
    let deadline = tokio::time::Instant::now() + command.options.timeout;
    let mut result = {
        let operation = async {
            diagnostics.install(command.options.log_file.as_deref())?;
            let endpoint = validate_endpoint(
                &command.options.endpoint,
                command.options.allow_insecure_remote_ws,
            )?;
            diagnostics.set_endpoint(&endpoint.origin);
            let mut parameters = command.params.clone();
            let mut request_credential = None;
            let mut export_passphrase = None;
            if let Some(memory) = &command.memory {
                let mut arguments = memory.arguments.clone();
                if memory.export_file.is_some() || memory.import_file.is_some() {
                    let mut bytes = Zeroizing::new(Vec::new());
                    let limit = if memory.request_stdin {
                        64 * 1024
                    } else {
                        1024
                    };
                    tokio::io::stdin()
                        .take(limit + 1)
                        .read_to_end(&mut bytes)
                        .await
                        .map_err(|_| {
                            DiagnosticFailure::usage(
                                "memory_export_stdin_failed",
                                "Memory export secret input could not be read",
                            )
                        })?;
                    if memory.request_stdin {
                        let (credential, passphrase) = memory_export_credentials(&bytes)?;
                        request_credential = Some(credential);
                        export_passphrase = Some(passphrase);
                    } else {
                        export_passphrase = Some(
                            super::state_snapshot::parse_passphrase(&bytes).map_err(|message| {
                                DiagnosticFailure::usage("memory_export_passphrase", message)
                            })?,
                        );
                    }
                    if let Some(source) = memory.import_file.clone() {
                        let passphrase = export_passphrase.take().expect("archive passphrase");
                        import_task = Some(tokio::task::spawn_blocking(move || {
                            super::state_snapshot::read_memory_archive(&source, passphrase)
                        }));
                        let opened = import_task.as_mut().expect("archive reader").await;
                        import_task.take();
                        let bytes = opened
                            .map_err(|_| {
                                DiagnosticFailure::internal(
                                    "memory_archive_reader_failed",
                                    "Encrypted memory archive reader ended without a result",
                                )
                            })?
                            .map_err(|message| {
                                DiagnosticFailure::usage("memory_archive_refused", message)
                            })?;
                        arguments["archive"] = json!(memory_archive(&bytes)?);
                    }
                } else if memory.content_stdin || memory.archive_stdin || memory.request_stdin {
                    let mut bytes = Zeroizing::new(Vec::new());
                    let limit = if memory.request_stdin {
                        64 * 1024
                    } else if memory.archive_stdin {
                        16 * 1024
                    } else {
                        claw_state::MAX_MEMORY_CONTENT_BYTES
                    };
                    tokio::io::stdin()
                        .take((limit + 1) as u64)
                        .read_to_end(&mut bytes)
                        .await
                        .map_err(|_| {
                            DiagnosticFailure::usage(
                                "memory_stdin_failed",
                                "memory content could not be read from stdin",
                            )
                        })?;
                    if memory.request_stdin {
                        let (credential, fields) = memory_request_input(
                            &bytes,
                            memory.arguments["action"].as_str().unwrap_or("unknown"),
                        )?;
                        request_credential = Some(credential);
                        arguments
                            .as_object_mut()
                            .expect("parsed command object")
                            .extend(fields.as_object().expect("input fields").clone());
                    } else if memory.archive_stdin {
                        arguments["archive"] = json!(memory_archive(&bytes)?);
                    } else {
                        arguments["content"] = json!(memory_content(&bytes)?);
                    }
                }
                parameters["message"] =
                    json!(explicit_tool_message("memory_notes", &arguments).map_err(
                        |message| DiagnosticFailure::usage("invalid_memory_command", message)
                    )?);
            }
            let profile = command.options.device_profile.clone();
            let forget = command.method == "device.forget";
            let persistent = if let Some(profile) = profile {
                let endpoint = endpoint.url.as_str().to_owned();
                Some(tokio::task::spawn_blocking(move || {
                    let store = claw_platform::identity::native_store()?;
                    let root = claw_platform::identity::native_lock_directory()?;
                    let profile = claw_platform::identity::DeviceProfile::new(&endpoint, &profile, root)?;
                    if forget { profile.forget(store.as_ref()).map(|removed| (None, removed)) }
                    else { profile.load_or_create(store.as_ref()).map(|identity| (Some(identity), false)) }
                }).await.map_err(|_| DiagnosticFailure::internal("identity_task_failed", "native identity operation failed; retry the same profile"))?
                    .map_err(|_| DiagnosticFailure::usage("identity_storage_unavailable", "device profile could not be loaded safely; do not replace or fall back to an ephemeral identity"))?)
            } else {
                None
            };
            if forget {
                return Ok(
                    json!({"removed": persistent.is_some_and(|(_, removed)| removed), "remoteGrantsRevoked": false}),
                );
            }
            let identity = Arc::new(match persistent.and_then(|(identity, _)| identity) {
                Some(identity) => identity,
                None => generate_ephemeral_identity()?,
            });
            if command.method == "device.profile" {
                return Ok(
                    json!({"deviceId": identity.device_id().gateway_wire_id(), "persistent": true, "storage": "native-keyring"}),
                );
            }
            let credential = match request_credential {
                Some(credential) => credential,
                None => read_credential(&command.options).await?,
            };
            let mut config = GatewayClientConfig::new(endpoint.url, identity);
            config.credential = credential;
            config.scopes = if command.memory.is_some()
                || command.params.get("nativeCatalogRefresh").is_some()
            {
                ScopeSet::from_scopes([Scope::OperatorRead, Scope::OperatorWrite])
            } else {
                ScopeSet::from_scopes([command.scope])
            };
            config.authorization_expectation = AuthorizationExpectation::ExactRequested;
            config.reconnect = ReconnectPolicy::Never;
            config.allow_insecure_remote_ws = command.options.allow_insecure_remote_ws;
            config.timeouts = ClientTimeouts {
                connect: command.options.timeout,
                authentication: command.options.timeout,
                request: command.options.timeout,
                shutdown: Duration::from_secs(2).min(command.options.timeout),
            };
            let (connected, events) =
                GatewayClient::start(config).map_err(|error| map_client_error(&error))?;
            let mut export_events = command
                .memory
                .as_ref()
                .is_some_and(|memory| memory.export_file.is_some())
                .then_some(events);
            client = Some(connected);
            let ready = client
                .as_ref()
                .expect("started client")
                .wait_ready()
                .await
                .map_err(|error| map_client_error(&error))?;
            if let Some(destination) = command
                .partial_export
                .as_ref()
                .or(command.accounting_export.as_ref())
                .or(command.model_export.as_ref())
            {
                submitted = true;
                let (bytes, receipt) = if command.model_export.is_some() {
                    collect_model_export(client.as_ref().expect("started client"), ready.epoch)
                        .await?
                } else if command.accounting_export.is_some() {
                    collect_accounting_export(
                        client.as_ref().expect("started client"),
                        ready.epoch,
                        &parameters,
                    )
                    .await?
                } else {
                    collect_partial_export(
                        client.as_ref().expect("started client"),
                        ready.epoch,
                        &parameters,
                    )
                    .await?
                };
                prepared_run_export = Some((destination.clone(), bytes));
                return Ok(receipt);
            }
            if command.memory.is_some() {
                let health = client
                    .as_ref()
                    .expect("started client")
                    .request_for_epoch(
                        ready.epoch,
                        RequestId::new(
                            "native-memory-capabilities-1",
                            AUTHENTICATED_MAX_FRAME_BYTES,
                        )
                        .expect("capability request identity"),
                        GatewayMethodName::Core(
                            resolve_core_method("health").expect("health method"),
                        ),
                        &json!({}),
                    )
                    .await
                    .map_err(|error| map_client_error(&error))?;
                if !health.ok() {
                    return Err(DiagnosticFailure::protocol(
                        "native_memory_unavailable",
                        "Gateway refused native capability discovery; no memory command was sent",
                    ));
                }
                let payload = health
                    .payload()
                    .value()
                    .and_then(|payload| serde_json::from_str::<Value>(payload.as_json()).ok())
                    .ok_or_else(|| {
                        DiagnosticFailure::protocol(
                            "native_memory_unavailable",
                            "Gateway capability response is incomplete; no memory command was sent",
                        )
                    })?;
                check_memory_capabilities(&payload)?;
                if command.memory.as_ref().is_some_and(|memory| {
                    matches!(
                        memory.arguments["action"].as_str(),
                        Some("export" | "import")
                    )
                }) && payload["native"]["explicitMemory"]["archiveSchemaVersion"] != 1
                {
                    return Err(DiagnosticFailure::protocol(
                        "native_memory_unavailable",
                        "Gateway does not advertise the required memory archive version; no memory command was sent",
                    ));
                }
            }
            if let Some(memory) = command
                .memory
                .as_ref()
                .filter(|memory| memory.export_file.is_some())
            {
                submitted = true;
                let revision = memory.arguments["revision"]
                    .as_u64()
                    .expect("parsed export revision");
                let (bytes, pages) = collect_memory_archive(
                    client.as_ref().expect("started client"),
                    ready.epoch,
                    export_events.as_mut().expect("export event stream"),
                    &parameters,
                    revision,
                    &mut export_progress,
                )
                .await?;
                let result = json!({"notebookRevision":revision,"archiveBytes":bytes.len(),"sha256":memory_sha256(&bytes),"pages":pages,"archiveSchemaVersion":1,"archiveValidated":true,"fileCreated":false,"encryption":"age-scrypt","scryptWorkFactor":18,"contentIncluded":false,"runResultsAcknowledged":false,"directoryDurabilityVerified":false,"automaticRetry":false});
                prepared_export = Some((
                    memory.export_file.clone().expect("export path"),
                    bytes,
                    export_passphrase.take().expect("export passphrase"),
                ));
                return Ok(result);
            }
            if let Some(expected) = command.preview_fingerprint.as_deref() {
                let preview_response = client
                    .as_ref()
                    .expect("started client")
                    .request_for_epoch(
                        ready.epoch,
                        RequestId::new("native-approval-preview-1", AUTHENTICATED_MAX_FRAME_BYTES)
                            .expect("static preview ID"),
                        GatewayMethodName::Core(
                            resolve_core_method("exec.approval.get").expect("known preview method"),
                        ),
                        &json!({"id": parameters["id"]}),
                    )
                    .await
                    .map_err(|error| map_client_error(&error))?;
                if !preview_response.ok() {
                    return Err(DiagnosticFailure::protocol(
                        "rpc_rejected",
                        "Gateway refused the approval preview",
                    ));
                }
                let preview = preview_response
                    .payload()
                    .value()
                    .and_then(|payload| serde_json::from_str::<Value>(payload.as_json()).ok())
                    .ok_or_else(|| {
                        DiagnosticFailure::protocol(
                            "invalid_preview",
                            "Gateway did not return a complete approval preview",
                        )
                    })?;
                let token = checked_preview_token(&preview, &parameters["id"], expected)?;
                parameters["bindingToken"] = json!(token);
            }
            let method = GatewayMethodName::Core(
                resolve_core_method(command.method).expect("closed native method catalog"),
            );
            let request = RequestId::new("native-command-1", AUTHENTICATED_MAX_FRAME_BYTES)
                .expect("static request identity");
            submitted = true;
            super::tracing::debug!(
                action = "native.rpc",
                outcome = "submitted",
                rpc.method = command.method
            );
            let response = client
                .as_ref()
                .expect("started client")
                .request_for_epoch(ready.epoch, request, method, &parameters)
                .await
                .map_err(|error| map_client_error(&error))?;
            if !response.ok() {
                let code = response.error().map(|error| error.code.as_str());
                if matches!(
                    code,
                    Some(
                        "INVALID_REQUEST"
                            | "UNAUTHORIZED"
                            | "NOT_FOUND"
                            | "METHOD_NOT_FOUND"
                            | "NOT_IMPLEMENTED"
                    )
                ) {
                    submitted = false;
                    return Err(DiagnosticFailure::protocol(
                        "rpc_rejected",
                        "Gateway refused the native request",
                    ));
                }
                return Err(DiagnosticFailure::protocol(
                    "outcome_unknown",
                    "Gateway could not confirm the outcome; query the existing run or retry only its original key",
                ));
            }
            if parameters.get("partialPage").is_some() {
                let encoded = response.payload().value().ok_or_else(|| {
                    DiagnosticFailure::protocol(
                        "invalid_partial_page",
                        "Gateway partial page is missing",
                    )
                })?;
                check_partial_page(encoded.as_json(), &parameters)?;
            }
            if parameters.get("accountingPage").is_some() {
                let encoded = response.payload().value().ok_or_else(|| {
                    DiagnosticFailure::protocol(
                        "invalid_accounting_page",
                        "Gateway accounting page is missing",
                    )
                })?;
                check_accounting_page(encoded.as_json(), &parameters)?;
            }
            if let Some(page) = parameters.get("nativeCatalogPage") {
                let invalid = || {
                    DiagnosticFailure::protocol(
                        "invalid_model_catalogue",
                        "Gateway model catalogue changed identity, bounds, metadata or digest",
                    )
                };
                let encoded = response.payload().value().ok_or_else(invalid)?;
                claw_protocol::native_models::validate_page(
                    encoded.as_json(),
                    page["offset"]
                        .as_u64()
                        .and_then(|value| usize::try_from(value).ok())
                        .ok_or_else(invalid)?,
                    page["sha256"].as_str(),
                )
                .map_err(|_| invalid())?;
            }
            if parameters.get("nativeCatalogRefresh").is_some() {
                let invalid = || {
                    DiagnosticFailure::protocol(
                        "invalid_model_refresh",
                        "Gateway catalogue refresh receipt is invalid or claims an unrelated operation",
                    )
                };
                let encoded = response.payload().value().ok_or_else(invalid)?;
                claw_protocol::native_models::validate_refresh(
                    encoded.as_json(),
                    parameters["nativeCatalogRefresh"]["sha256"]
                        .as_str()
                        .ok_or_else(invalid)?,
                )
                .map_err(|_| invalid())?;
            }
            let payload = response
                .payload()
                .value()
                .and_then(|value| serde_json::from_str::<Value>(value.as_json()).ok())
                .filter(Value::is_object)
                .ok_or_else(|| {
                    DiagnosticFailure::protocol(
                        "malformed_result",
                        "Gateway native result is missing or malformed",
                    )
                })?;
            if command.memory.is_some() {
                check_memory_receipt(&payload, &parameters["sessionKey"])?;
            }
            Ok(payload)
        };
        tokio::pin!(operation);
        tokio::select! {
            biased;
            signal = tokio::signal::ctrl_c() => Err(if signal.is_ok() {
                DiagnosticFailure::timeout("cancelled", "native Gateway command cancelled; check state before retry")
            } else { DiagnosticFailure::internal("signal_error", "interrupt handler failed") }),
            () = tokio::time::sleep_until(deadline) => Err(DiagnosticFailure::timeout("timeout", "native Gateway command timed out; check state before retry")),
            result = &mut operation => result,
        }
    };
    if let Some(task) = import_task.take() {
        let _ = task.await;
    }
    if result.is_ok()
        && let Some((destination, bytes)) = prepared_run_export.take()
    {
        run_file_started = true;
        match tokio::task::spawn_blocking(move || {
            super::state_snapshot::write_run_export(&destination, &bytes)
        })
        .await
        {
            Ok(Ok(())) => {
                if let Ok(receipt) = &mut result {
                    receipt["fileCreated"] = json!(true);
                }
            }
            Ok(Err(message)) => {
                result = Err(DiagnosticFailure::internal(
                    if command.model_export.is_some() {
                        "model_export_file_failed"
                    } else if command.accounting_export.is_some() {
                        "accounting_export_file_failed"
                    } else {
                        "partial_export_file_failed"
                    },
                    message,
                ));
            }
            Err(_) => {
                result = Err(DiagnosticFailure::internal(
                    if command.model_export.is_some() {
                        "model_export_file_unknown"
                    } else if command.accounting_export.is_some() {
                        "accounting_export_file_unknown"
                    } else {
                        "partial_export_file_unknown"
                    },
                    "Local export writer ended without confirmation; preserve any output file",
                ));
            }
        }
    }
    if result.is_ok()
        && let Some((destination, bytes, passphrase)) = prepared_export.take()
    {
        match tokio::task::spawn_blocking(move || {
            super::state_snapshot::seal_memory_archive(&destination, &bytes, passphrase)
        })
        .await
        {
            Ok(Ok(())) => {
                if let Ok(payload) = &mut result {
                    payload["fileCreated"] = json!(true);
                }
            }
            Ok(Err(message)) => {
                result = Err(DiagnosticFailure::internal(
                    "memory_export_file_failed",
                    message,
                ));
            }
            Err(_) => {
                result = Err(DiagnosticFailure::internal(
                    "memory_export_file_unknown",
                    "Memory archive writer ended without confirmation; preserve any partial file",
                ));
            }
        }
    }
    let shutdown_ok = if let Some(client) = client.take() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let grace = if remaining.is_zero() {
            super::CANCELLED_SHUTDOWN_GRACE
        } else {
            remaining.min(Duration::from_secs(2))
        };
        matches!(
            tokio::time::timeout(grace, client.shutdown()).await,
            Ok(Ok(()))
        )
    } else {
        true
    };
    drop(client);
    let (exit_code, mut document) = match result {
        Ok(payload) => (
            if shutdown_ok {
                0
            } else {
                ExitCategory::TimeoutCancel.code()
            },
            json!({"schema_version": 1, "method": command.method, "ok": shutdown_ok, "result": payload, "shutdown_clean": shutdown_ok}),
        ),
        Err(failure) => (
            failure.category.code(),
            json!({
                "schema_version": 1, "method": command.method, "ok": false,
                "delivery": if failure.status == "rpc_rejected" { "rejected" } else if submitted { "unknown" } else { "not_sent" },
                "status": failure.status, "message": failure.message, "shutdown_clean": shutdown_ok,
            }),
        ),
    };
    if let Some(memory) = &command.memory {
        document["operation"] = json!(format!(
            "memory.{}",
            memory.arguments["action"].as_str().unwrap_or("unknown")
        ));
        if memory.export_file.is_some() {
            document["operation"] = json!("memory.export_file");
            document["lastPage"] = export_progress;
            document["originalIdempotencyKey"] = command.params["idempotencyKey"].clone();
            document["targetMayExist"] = json!(submitted);
        } else if memory.import_file.is_some() {
            document["operation"] = json!("memory.import_file");
            document["sourceModified"] = json!(false);
        }
    }
    if command.partial_export.is_some()
        || command.accounting_export.is_some()
        || command.model_export.is_some()
    {
        document["operation"] = json!(if command.model_export.is_some() {
            "models.export_catalogue"
        } else if command.accounting_export.is_some() {
            "run.export_accounting"
        } else {
            "run.export_partial"
        });
        document["fileMayExist"] = json!(run_file_started);
        document["sourceModified"] = json!(false);
        document["acknowledged"] = json!(false);
        document["automaticReplay"] = json!(false);
    }
    render_result(command.method, exit_code, &document)
}

fn checked_preview_token(
    preview: &Value,
    id: &Value,
    expected: &str,
) -> Result<String, DiagnosticFailure> {
    let changed = || {
        DiagnosticFailure::usage(
            "approval_preview_changed",
            "Approval preview changed or is incomplete; review it again before deciding",
        )
    };
    if preview["id"] != *id
        || claw_protocol::native_approval::checked_bound_approval_prompt(preview, 32 * 1024)
            .is_none()
    {
        return Err(changed());
    }
    let token = preview["bindingToken"].as_str().ok_or_else(changed)?;
    let fingerprint =
        claw_security::authorization::approval_preview_fingerprint(token).ok_or_else(changed)?;
    if fingerprint != expected
        || preview["previewFingerprint"].as_str() != Some(fingerprint.as_str())
    {
        return Err(changed());
    }
    Ok(token.to_owned())
}

fn render_result(method: &str, exit_code: u8, document: &Value) -> RenderedResult {
    let stdout = format!("{document}\n");
    let stdout = if stdout.len() > super::MAX_RENDERED_OUTPUT_BYTES {
        format!(
            "{}\n",
            json!({
                "schema_version": 1, "method": method, "ok": false,
                "status": "result_too_large", "delivery": "response_received",
                "rpc_succeeded": document.get("result").is_some(),
                "shutdown_clean": document["shutdown_clean"],
                "message": "The response exceeds the CLI output limit. It was not truncated. Do not replay a write; use a bounded history or preview client.",
            })
        )
    } else {
        return RenderedResult {
            exit_code,
            stdout,
            stderr: String::new(),
        };
    };
    RenderedResult {
        exit_code: ExitCategory::Internal.code(),
        stdout,
        stderr: String::new(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn memory_request_stdin_separates_credentials_and_rejects_ambiguous_frames() {
        use serde_json::json;
        let (credential, fields) = super::memory_request_input(
            br#"{"token":"fixture-token","content":"private-framed-note"}"#,
            "save",
        )
        .unwrap_or_else(|_| panic!("valid framed memory input"));
        assert!(matches!(
            credential,
            claw_gateway_client::GatewayCredential::Token(_)
        ));
        assert_eq!(fields, json!({"content":"private-framed-note"}));
        assert!(!fields.to_string().contains("fixture-token"));
        let archive = br#"{"token":"fixture-token","archive":{"schemaVersion":1,"notebook":{"revision":0,"entries":[]}}}"#;
        assert!(super::memory_request_input(archive, "import").is_ok());
        for body in [
            br#"{"token":"fixture-token","token":"other","content":"private-framed-note"}"#.as_slice(),
            br#"{"token":"fixture-token","content":"private-framed-note","owner":true}"#,
            br#"{"token":"fixture-token\n","content":"private-framed-note"}"#,
            br#"{"content":"private-framed-note"}"#,
            br#"{"token":"","content":"private-framed-note"}"#,
            br#"{"token":"fixture-token","content":"private-framed-note","archive":{"schemaVersion":1,"notebook":{"revision":0,"entries":[]}}}"#,
        ] {
            let Err(error) = super::memory_request_input(body, "save") else { panic!("ambiguous input accepted") };
            assert!(!error.message.contains("fixture-token") && !error.message.contains("private-framed-note"));
        }
        assert!(super::memory_request_input(archive, "save").is_err());
        assert!(super::memory_request_input(&vec![b' '; 64 * 1024 + 1], "save").is_err());
    }

    #[test]
    fn memory_archive_input_refuses_duplicates_versions_and_invalid_notes() {
        use serde_json::json;
        let valid = json!({"schemaVersion":1,"notebook":{"revision":3,"entries":[{"id":"units","kind":"preference","content":"private-imported-note","sourceSession":"source","revision":2}]}});
        assert!(super::memory_archive(valid.to_string().as_bytes()).is_ok());
        assert!(
            super::memory_archive(
                br#"{"schemaVersion":1,"schemaVersion":1,"notebook":{"revision":0,"entries":[]}}"#
            )
            .is_err()
        );
        for pointer in [
            "/schemaVersion",
            "/notebook/revision",
            "/notebook/entries/0/id",
            "/notebook/entries/0/kind",
            "/notebook/entries/0/content",
            "/notebook/entries/0/sourceSession",
            "/notebook/entries/0/revision",
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(pointer).expect("archive field") = serde_json::Value::Null;
            let Err(failure) = super::memory_archive(changed.to_string().as_bytes()) else {
                panic!("invalid archive accepted");
            };
            assert!(!failure.message.contains("private-imported-note"));
        }
        let mut duplicate = valid.clone();
        duplicate["notebook"]["entries"]
            .as_array_mut()
            .expect("entries")
            .push(valid["notebook"]["entries"][0].clone());
        assert!(super::memory_archive(duplicate.to_string().as_bytes()).is_err());
        assert!(super::memory_archive(&vec![b' '; 16 * 1024 + 1]).is_err());
    }

    #[test]
    fn memory_content_and_capabilities_fail_closed_without_echoing_notes() {
        use serde_json::json;
        assert_eq!(
            super::memory_content(b"private-note\n!goal remains data")
                .unwrap_or_else(|_| panic!("valid UTF-8 note")),
            "private-note\n!goal remains data"
        );
        for content in [
            Vec::new(),
            vec![0xff],
            b" \n\t".to_vec(),
            b"private-note\0".to_vec(),
            vec![b'x'; 8193],
        ] {
            let failure = super::memory_content(&content).expect_err("invalid content");
            assert!(!failure.message.contains("private-note"));
        }
        let valid = json!({"ok":true,"protocol":4,"native":{"schemaVersion":1,"directTool":{"version":1,"prefix":"!tool ","modelInvoked":false,"authenticated":true,"durableRuns":true,"approvalPolicy":"per-tool","accepting":true},"explicitMemory":{"enabled":true,"accepting":true,"requiresApproval":true,"partition":"source/subject/account","automaticContextInjection":false}}});
        assert!(super::check_memory_capabilities(&valid).is_ok());
        assert!(super::check_memory_capabilities(&json!({"ok":true,"protocol":4})).is_err());
        for pointer in [
            "/native/schemaVersion",
            "/native/directTool/version",
            "/native/directTool/prefix",
            "/native/directTool/modelInvoked",
            "/native/directTool/authenticated",
            "/native/directTool/durableRuns",
            "/native/directTool/approvalPolicy",
            "/native/directTool/accepting",
            "/native/explicitMemory/enabled",
            "/native/explicitMemory/accepting",
            "/native/explicitMemory/requiresApproval",
            "/native/explicitMemory/partition",
            "/native/explicitMemory/automaticContextInjection",
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(pointer).expect("capability field") = serde_json::Value::Null;
            assert!(
                super::check_memory_capabilities(&changed).is_err(),
                "{pointer}"
            );
        }
        let receipt = json!({"sessionId":"notes","runId":"a".repeat(64),"revision":1,"phase":"queued","status":"accepted","durable":true});
        assert!(super::check_memory_receipt(&receipt, &json!("notes")).is_ok());
        assert!(super::check_memory_receipt(&receipt, &json!("other")).is_err());
        for field in ["runId", "revision", "phase", "status", "durable"] {
            let mut invalid = receipt.clone();
            invalid[field] = serde_json::Value::Null;
            assert!(super::check_memory_receipt(&invalid, &json!("notes")).is_err());
        }
    }

    #[test]
    fn memory_commands_preserve_action_fields_and_require_persistent_identity() {
        use serde_json::json;
        use std::ffi::OsString;
        for (action, fields, expected) in [
            ("list", vec![], json!({"action":"list"})),
            (
                "list",
                vec!["--after", "note01", "--revision", "3", "--limit", "32"],
                json!({"action":"list","after":"note01","revision":3,"limit":32}),
            ),
            (
                "get",
                vec!["--note-id", "units", "--offset", "3", "--revision", "4"],
                json!({"action":"get","id":"units","offset":3,"revision":4}),
            ),
            (
                "search",
                vec!["--query", "metric", "--limit", "8"],
                json!({"action":"search","query":"metric","limit":8}),
            ),
            (
                "save",
                vec![
                    "--note-id",
                    "units",
                    "--kind",
                    "preference",
                    "--content-stdin",
                    "--expected-revision",
                    "0",
                ],
                json!({"action":"save","id":"units","kind":"preference","expectedRevision":0}),
            ),
            (
                "delete",
                vec!["--note-id", "units", "--expected-revision", "4"],
                json!({"action":"delete","id":"units","expectedRevision":4}),
            ),
            (
                "save",
                vec![
                    "--note-id",
                    "units",
                    "--kind",
                    "fact",
                    "--expected-revision",
                    "0",
                    "--request-stdin",
                ],
                json!({"action":"save","id":"units","kind":"fact","expectedRevision":0}),
            ),
            (
                "import",
                vec!["--expected-revision", "1", "--request-stdin"],
                json!({"action":"import","expectedRevision":1}),
            ),
            (
                "export",
                vec!["--revision", "3", "--offset", "2048"],
                json!({"action":"export","revision":3,"offset":2048}),
            ),
            (
                "import",
                vec!["--archive-stdin", "--expected-revision", "3", "--overwrite"],
                json!({"action":"import","expectedRevision":3,"overwrite":true}),
            ),
        ] {
            let mut arguments = vec!["gateway", "memory", action, "notes"];
            arguments.extend(fields);
            arguments.extend([
                "--endpoint",
                "ws://127.0.0.1:18789",
                "--device-profile",
                "work",
                "--idempotency-key",
                "original-key",
            ]);
            let arguments: Vec<OsString> = arguments.into_iter().map(OsString::from).collect();
            let command = super::parse(&arguments, 1)
                .unwrap_or_else(|_| panic!("valid memory action {action}"));
            assert_eq!(command.method, "chat.send");
            assert_eq!(
                command.params,
                json!({"sessionKey":"notes","idempotencyKey":"original-key"})
            );
            let memory = command.memory.expect("memory command");
            assert_eq!(memory.arguments, expected);
            assert_eq!(
                memory.content_stdin,
                action == "save" && !memory.request_stdin
            );
            assert_eq!(
                memory.archive_stdin,
                action == "import" && !memory.request_stdin
            );
        }
        for fields in [
            vec!["save"],
            vec!["list", "--request-stdin"],
            vec![
                "import",
                "--expected-revision",
                "0",
                "--request-stdin",
                "--archive-stdin",
            ],
            vec![
                "import",
                "--expected-revision",
                "0",
                "--request-stdin",
                "--token-stdin",
            ],
            vec![
                "import",
                "--expected-revision",
                "0",
                "--request-stdin",
                "--request-stdin",
            ],
            vec!["export"],
            vec!["export", "--revision", "3", "--offset", "4194305"],
            vec!["import", "--expected-revision", "0"],
            vec![
                "import",
                "--archive-stdin",
                "--expected-revision",
                "0",
                "--token-stdin",
            ],
            vec![
                "import",
                "--archive-stdin",
                "--archive-stdin",
                "--expected-revision",
                "0",
            ],
            vec!["list", "--overwrite"],
            vec!["delete", "--note-id", "units"],
            vec!["list", "--after", "units"],
            vec!["get", "--note-id", "units", "--offset", "1"],
            vec!["search", "--query", "metric", "--limit", "9"],
            vec!["list", "--limit", "1", "--limit", "2"],
            vec!["get", "--note-id", "../units"],
            vec!["delete", "--note-id", "units", "--expected-revision", "-1"],
            vec![
                "save",
                "--note-id",
                "units",
                "--kind",
                "fact",
                "--expected-revision",
                "0",
                "--content-stdin",
                "--token-stdin",
            ],
        ] {
            let mut arguments = vec!["gateway", "memory", fields[0], "notes"];
            arguments.extend(fields.into_iter().skip(1));
            arguments.extend([
                "--endpoint",
                "ws://127.0.0.1:18789",
                "--device-profile",
                "work",
                "--idempotency-key",
                "original-key",
            ]);
            assert!(
                super::parse(
                    &arguments
                        .into_iter()
                        .map(OsString::from)
                        .collect::<Vec<_>>(),
                    1
                )
                .is_err()
            );
        }
        let arguments: Vec<OsString> = [
            "gateway",
            "memory",
            "list",
            "notes",
            "--endpoint",
            "ws://127.0.0.1:18789",
            "--ephemeral-device",
            "--idempotency-key",
            "key",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert!(super::parse(&arguments, 1).is_err());
    }

    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn native_output_limit_remains_json_and_does_not_claim_non_delivery() {
        let rendered = render_result(
            "chat.history",
            0,
            &json!({
                "result": {"text": "private-history".repeat(super::super::MAX_RENDERED_OUTPUT_BYTES)},
                "shutdown_clean": true,
            }),
        );
        assert_ne!(rendered.exit_code, 0);
        assert!(rendered.stdout.len() <= super::super::MAX_RENDERED_OUTPUT_BYTES);
        assert!(!rendered.stdout.contains("private-history"));
        let document: Value = serde_json::from_str(&rendered.stdout).expect("bounded JSON output");
        assert_eq!(document["status"], "result_too_large");
        assert_eq!(document["rpc_succeeded"], true);
        assert_eq!(document["delivery"], "response_received");
    }

    #[test]
    fn native_commands_require_explicit_endpoint_identity_and_idempotency() {
        let common = ["--endpoint", "ws://127.0.0.1:18789", "--ephemeral-device"];
        for command in ["sessions", "approvals"] {
            let mut args = arguments(&["gateway", command]);
            args.extend(arguments(&common));
            assert!(parse(&args, 1).is_ok());
        }
        let mut args = arguments(&["send", "session-one", "hello"]);
        args.extend(arguments(&common));
        assert!(parse(&args, 0).is_err());
        args.extend(arguments(&["--idempotency-key", "once-1"]));
        let parsed = parse(&args, 0).unwrap_or_else(|_| panic!("valid native send"));
        assert_eq!(parsed.method, "chat.send");
        assert_eq!(parsed.scope, Scope::OperatorWrite);
        assert_eq!(parsed.params["idempotencyKey"], "once-1");
        args.extend(arguments(&["--idempotency-key", "again"]));
        assert!(parse(&args, 0).is_err());
        assert!(parse(&arguments(&["gateway", "sessions"]), 1).is_err());
    }

    #[test]
    fn native_history_limit_is_optional_bounded_and_not_reusable_on_other_commands() {
        let common = ["--endpoint", "ws://127.0.0.1:18789", "--ephemeral-device"];
        for limit in ["1", "256", "1000"] {
            let mut args = arguments(&["gateway", "history", "session-one", "--limit", limit]);
            args.extend(arguments(&common));
            let parsed = parse(&args, 1).unwrap_or_else(|_| panic!("valid history limit"));
            assert_eq!(parsed.method, "chat.history");
            assert_eq!(parsed.scope, Scope::OperatorRead);
            assert_eq!(
                parsed.params["limit"],
                limit.parse::<u16>().expect("fixture number")
            );
            args.extend(arguments(&["--limit", limit]));
            assert!(parse(&args, 1).is_err());
        }
        for limit in ["0", "1001", "-1", "1.5", "null", ""] {
            let mut args = arguments(&["gateway", "history", "session-one", "--limit", limit]);
            args.extend(arguments(&common));
            assert!(parse(&args, 1).is_err());
        }
        let mut wrong_command = arguments(&["gateway", "abort", "session-one", "--limit", "1"]);
        wrong_command.extend(arguments(&common));
        assert!(parse(&wrong_command, 1).is_err());
    }

    #[test]
    fn durable_run_commands_preserve_exact_run_revision_and_bounds() {
        let id = "a".repeat(64);
        let common = ["--endpoint", "ws://127.0.0.1:18789", "--ephemeral-device"];
        let mut args = arguments(&["gateway", "run", &id, "--wait-ms", "1000"]);
        args.extend(arguments(&common));
        let parsed = parse(&args, 1).unwrap_or_else(|_| panic!("run query"));
        assert_eq!(parsed.method, "agent.wait");
        assert_eq!(parsed.scope, Scope::OperatorRead);
        assert_eq!(parsed.params, json!({"runId": id, "timeoutMs": 1000}));
        let mut aborted = arguments(&["gateway", "abort", "session-1", "--run-id", &id]);
        aborted.extend(arguments(&[
            "--endpoint",
            "ws://127.0.0.1:18789",
            "--ephemeral-device",
        ]));
        let parsed = parse(&aborted, 1).unwrap_or_else(|_| panic!("run-bound cancellation"));
        assert_eq!(
            parsed.params,
            json!({"sessionKey": "session-1", "runId": id})
        );
        aborted.extend(arguments(&["--run-id", &id]));
        assert!(parse(&aborted, 1).is_err());
        let mut args = arguments(&["gateway", "ack-run", &id, "4"]);
        args.extend(arguments(&common));
        assert_eq!(
            parse(&args, 1)
                .unwrap_or_else(|_| panic!("result ACK"))
                .params,
            json!({"runId": id, "acknowledgeRevision": 4})
        );
        let mut invalid = arguments(&["gateway", "run", &id, "--wait-ms", "120001"]);
        invalid.extend(arguments(&common));
        assert!(parse(&invalid, 1).is_err());
        let mut invalid = arguments(&["gateway", "ack-run", &id, "0"]);
        invalid.extend(arguments(&common));
        assert!(parse(&invalid, 1).is_err());
    }

    #[test]
    fn native_device_profiles_are_explicit_and_never_mixed_with_ephemeral_identity() {
        let args = arguments(&[
            "gateway",
            "device",
            "--endpoint",
            "wss://gateway.test",
            "--device-profile",
            "main",
        ]);
        let parsed = parse(&args, 1).unwrap_or_else(|_| panic!("explicit native profile"));
        assert_eq!(parsed.options.device_profile.as_deref(), Some("main"));
        assert!(!parsed.options.ephemeral_device);
        let mut mixed = args;
        mixed.push("--ephemeral-device".into());
        assert!(parse(&mixed, 1).is_err());
        assert!(
            parse(
                &arguments(&[
                    "gateway",
                    "device",
                    "--endpoint",
                    "wss://gateway.test",
                    "--ephemeral-device"
                ]),
                1
            )
            .is_err()
        );
        assert!(
            super::super::parse_invocation(&arguments(&[
                "gateway",
                "health",
                "--endpoint",
                "wss://gateway.test",
                "--device-profile",
                "main"
            ]))
            .is_err()
        );
    }

    #[test]
    fn native_approval_commands_request_only_approval_scope() {
        for command in ["approval", "approve", "deny"] {
            let mut args = arguments(&[
                "gateway",
                command,
                "approval-1",
                "--endpoint",
                "ws://127.0.0.1:18789",
                "--ephemeral-device",
            ]);
            if command != "approval" {
                args.extend(arguments(&["--preview-fingerprint", &"a".repeat(64)]));
            }
            let parsed = parse(&args, 1).unwrap_or_else(|_| panic!("valid approval command"));
            assert_eq!(parsed.scope, Scope::OperatorApprovals);
            assert_eq!(parsed.params["id"], "approval-1");
            assert!(parsed.params.get("sender_is_owner").is_none());
        }
    }

    #[test]
    fn approval_fingerprint_cannot_bind_another_request_or_incomplete_preview() {
        let token = "b".repeat(64);
        let fingerprint = claw_security::authorization::approval_preview_fingerprint(&token)
            .expect("fingerprint");
        let mut preview = json!({"id": "approval-1", "sessionId": "native-session", "tool": "fs_write", "previewComplete": true, "bindingToken": token, "previewFingerprint": fingerprint,
            "toolPublication": "workspace-fixture", "toolRevision": 1, "resourceScope": "workspace: reviewed.txt",
            "caller": {"source": "Http", "subject": "verified-device", "account": null, "permissionGeneration": 0, "owner": true}});
        preview["prompt"] = json!(format!(
            "{}fs_write\n{{}}",
            claw_protocol::native_approval::bound_approval_context_header(&preview)
                .expect("context")
        ));
        assert!(checked_preview_token(&preview, &json!("approval-1"), &fingerprint).is_ok());
        assert!(checked_preview_token(&preview, &json!("other-request"), &fingerprint).is_err());
        assert!(checked_preview_token(&preview, &json!("approval-1"), &"a".repeat(64)).is_err());
        for field in ["caller", "toolPublication", "toolRevision", "resourceScope"] {
            let mut incomplete = preview.clone();
            incomplete.as_object_mut().expect("preview").remove(field);
            assert!(
                checked_preview_token(&incomplete, &json!("approval-1"), &fingerprint).is_err()
            );
        }
        let mut oversized = preview;
        oversized["prompt"] = json!("x".repeat(32 * 1024 + 1));
        assert!(checked_preview_token(&oversized, &json!("approval-1"), &fingerprint).is_err());
    }
}
