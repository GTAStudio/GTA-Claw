//! Local, read-only `OpenClaw` inspection with bounded paginated JSON output.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

use super::{ParseFailure, RenderedResult, parse_failure};

pub(super) struct PreviewCommand {
    source: PathBuf,
    after: Option<String>,
    fingerprint: Option<String>,
}

pub(super) fn parse(arguments: &[OsString]) -> Result<PreviewCommand, ParseFailure> {
    let invalid = || {
        parse_failure(
            "expected migrate openclaw preview --source <absolute-state-root> [--after <path> --fingerprint <sha256>]",
            arguments,
        )
    };
    if arguments.get(1).and_then(|value| value.to_str()) != Some("openclaw")
        || arguments.get(2).and_then(|value| value.to_str()) != Some("preview")
    {
        return Err(invalid());
    }
    let mut source = None;
    let mut after = None;
    let mut fingerprint = None;
    let mut index = 3;
    while index < arguments.len() {
        let option = arguments[index].to_str().ok_or_else(invalid)?;
        if option == "--json" {
            index += 1;
            continue;
        }
        let value = arguments.get(index + 1).ok_or_else(invalid)?;
        match option {
            "--source" if source.is_none() => source = Some(PathBuf::from(value)),
            "--after" if after.is_none() => {
                let value = value
                    .to_str()
                    .filter(|value| {
                        !value.is_empty()
                            && value.len() <= 1024
                            && !value.chars().any(char::is_control)
                    })
                    .ok_or_else(invalid)?;
                after = Some(value.to_owned());
            }
            "--fingerprint" if fingerprint.is_none() => {
                let value = value
                    .to_str()
                    .filter(|value| {
                        value.len() == 64
                            && value
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                    .ok_or_else(invalid)?;
                fingerprint = Some(value.to_owned());
            }
            _ => return Err(invalid()),
        }
        index += 2;
    }
    let source = source
        .filter(|source| source.is_absolute())
        .ok_or_else(invalid)?;
    if after.is_some() && fingerprint.is_none() {
        return Err(invalid());
    }
    Ok(PreviewCommand {
        source,
        after,
        fingerprint,
    })
}

fn result(exit_code: u8, document: &Value) -> RenderedResult {
    RenderedResult {
        exit_code,
        stdout: format!("{document}\n"),
        stderr: String::new(),
    }
}

fn failure(code: &str, message: &str) -> RenderedResult {
    result(
        2,
        &json!({"schema_version":1,"method":"migration.openclaw.preview","ok":false,"sourceModified":false,"error":{"code":code,"message":message}}),
    )
}

pub(super) async fn run(command: PreviewCommand) -> RenderedResult {
    let source = command.source;
    let task = tokio::task::spawn_blocking(move || claw_migrate::openclaw::inspect(&source));
    let inspected = match tokio::time::timeout(Duration::from_secs(10), task).await {
        Ok(Ok(Ok(preview))) => preview,
        Ok(Ok(Err(error))) => return failure("source_refused", &error.to_string()),
        Ok(Err(_)) => {
            return failure(
                "inspection_failed",
                "Read-only inspection task failed; no import or activation was attempted",
            );
        }
        Err(_) => {
            return failure(
                "inspection_timeout",
                "Read-only inspection exceeded its deadline; no import or activation was attempted",
            );
        }
    };
    if command
        .fingerprint
        .as_ref()
        .is_some_and(|fingerprint| fingerprint != &inspected.fingerprint)
    {
        return failure(
            "preview_changed",
            "Source metadata or inspected content changed; restart the preview before paging",
        );
    }
    if !inspected.recognized {
        return failure(
            "unrecognized_source",
            "The selected root has no recognized OpenClaw configuration or per-agent session data",
        );
    }
    let total = inspected.entries.len();
    let start = if let Some(after) = &command.after {
        let Some(position) = inspected
            .entries
            .iter()
            .position(|entry| &entry.path == after)
        else {
            return failure("invalid_cursor", "Cursor does not belong to this preview");
        };
        position + 1
    } else {
        0
    };
    let page: Vec<_> = inspected.entries.iter().skip(start).take(8).collect();
    let next = (start + page.len() < total)
        .then(|| page.last().map(|entry| entry.path.clone()))
        .flatten();
    let diagnostics: Vec<_> = inspected.diagnostics.iter().take(8).collect();
    let document = json!({
        "schema_version":1,"method":"migration.openclaw.preview","ok":true,"sourceModified":false,
        "referenceCommit":inspected.reference_commit,"recordedVersion":inspected.recorded_version,"profileHint":inspected.profile_hint,
        "fingerprint":inspected.fingerprint,"fingerprintScope":"inspected_content_and_inventory_metadata",
        "snapshotVerified":false,"migrationReady":false,"resumeExecution":false,
        "entryCount":total,"bytesRead":inspected.bytes_read,"configuredSurfaces":inspected.configured_surfaces,
        "entries":page,"nextCursor":next,"diagnostics":diagnostics,"diagnosticCount":inspected.diagnostics.len(),
        "diagnosticsComplete":inspected.diagnostics.len() <= diagnostics.len(),
    });
    if document.to_string().len() + 1 > super::MAX_RENDERED_OUTPUT_BYTES {
        return failure(
            "preview_page_too_large",
            "Preview metadata exceeds the bounded CLI output size; no partial page was printed",
        );
    }
    result(0, &document)
}
