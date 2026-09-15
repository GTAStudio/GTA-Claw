//! `OpenClaw` preview only: isolated fixtures, no state writes or external activation.

mod common;

use claw_migrate::openclaw::{SourceKind, inspect};
use common::TestDir;
use serde_json::json;

#[test]
fn openclaw_preview_counts_state_without_returning_secrets_or_chat_text() {
    let root = TestDir::new("openclaw-preview");
    std::fs::create_dir_all(root.join("agents/main/sessions")).expect("session fixture");
    std::fs::create_dir(root.join("credentials")).expect("credentials directory");
    std::fs::write(
        root.join("credentials/secret.json"),
        "not even parsed as JSON",
    )
    .expect("excluded secret fixture");
    let config = "{meta:{lastTouchedVersion:'2026.9.4'},gateway:{auth:{token:'private-config-secret'}},agents:{defaults:{workspace:'D:/outside'}},$include:'../outside.json5'}";
    std::fs::write(root.join("openclaw.json"), config).expect("JSON5 configuration");
    std::fs::write(
        root.join("agents/main/sessions/sessions.json"),
        json!({"agent:main:main":{"sessionId":"one","sessionFile":"sqlite:one"}}).to_string(),
    )
    .expect("session index");
    std::fs::write(root.join("agents/main/sessions/one.jsonl"), "{\"type\":\"session\",\"version\":3}\n{\"type\":\"message\",\"message\":{\"role\":\"user\",\"content\":\"private-chat-text\"}}\n").expect("transcript");
    std::fs::write(root.join("sessions.sqlite-wal"), b"unread database journal")
        .expect("WAL metadata");
    std::fs::write(root.join("unported.js"), b"unread execution artifact")
        .expect("script metadata");
    let preview = inspect(root.path()).expect("bounded read-only preview");
    assert!(preview.recognized);
    assert_eq!(preview.recorded_version.as_deref(), Some("2026.9.4"));
    assert!(!preview.snapshot_verified && !preview.migration_ready && !preview.resume_execution);
    assert!(
        preview
            .entries
            .iter()
            .any(|entry| entry.kind == SourceKind::Transcript && entry.records == Some(2))
    );
    assert!(
        preview
            .entries
            .iter()
            .filter(|entry| matches!(
                entry.kind,
                SourceKind::CredentialsExcluded
                    | SourceKind::SqliteSnapshotRequired
                    | SourceKind::ExecutionReviewRequired
            ))
            .all(|entry| !entry.content_read)
    );
    let rendered = serde_json::to_string(&preview).expect("metadata JSON");
    assert!(
        !rendered.contains("private-config-secret")
            && !rendered.contains("private-chat-text")
            && !rendered.contains("D:/outside")
    );
    assert_eq!(
        std::fs::read_to_string(root.join("openclaw.json")).expect("unchanged source"),
        config
    );
    assert_eq!(
        preview.fingerprint,
        inspect(root.path()).expect("same inspection").fingerprint
    );
    assert!(
        preview
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "CONFIG_INCLUDES_NOT_RESOLVED")
    );
}

#[test]
fn openclaw_preview_refuses_malformed_or_hard_linked_primary_state() {
    let root = TestDir::new("openclaw-invalid");
    std::fs::write(root.join("openclaw.json"), "{invalid-private-payload")
        .expect("malformed fixture");
    let error = inspect(root.path()).expect_err("invalid JSON5");
    assert!(!error.to_string().contains("private-payload"));
    assert_eq!(
        std::fs::read_to_string(root.join("openclaw.json")).expect("preserved malformed data"),
        "{invalid-private-payload"
    );
    std::fs::write(root.join("openclaw.json"), "{}").expect("valid fixture");
    std::fs::hard_link(root.join("openclaw.json"), root.join("alias.json"))
        .expect("hard-linked fixture");
    assert!(inspect(root.path()).is_err());
    assert_eq!(
        std::fs::read_to_string(root.join("alias.json")).expect("external identity unchanged"),
        "{}"
    );
}

#[test]
fn openclaw_preview_refuses_deep_wide_duplicate_and_nonfinite_documents_before_mapping() {
    let root = TestDir::new("openclaw-structural-bounds");
    for configuration in [
        format!("{{nested:{}0{}}}", "[".repeat(10_000), "]".repeat(10_000)),
        format!("{{wide:[{}0]}}", "0,".repeat(16_384)),
        "{gateway:{token:'first-secret'},gateway:{token:'second-secret'}}".to_owned(),
        "{number:NaN}".to_owned(),
        "{number:Infinity}".to_owned(),
    ] {
        std::fs::write(root.join("openclaw.json"), &configuration)
            .expect("bounded adversarial fixture");
        let error = inspect(root.path()).expect_err("source requires explicit bounded mapping");
        assert!(!error.to_string().contains("secret"));
        assert_eq!(
            std::fs::read_to_string(root.join("openclaw.json")).expect("source unchanged"),
            configuration
        );
    }
    let valid = "{comment:'[[[ not nesting ]]]', // [{ comment\n arrays:[1,true,null],hex:0x10,number:1.25,trailing:'ok',}";
    std::fs::write(root.join("openclaw.json"), valid).expect("ordinary JSON5 fixture");
    assert!(
        inspect(root.path())
            .expect("genuine JSON5 grammar remains supported")
            .recognized
    );
    std::fs::create_dir_all(root.join("agents/main/sessions")).expect("session fixture");
    std::fs::write(
        root.join("agents/main/sessions/sessions.json"),
        r#"{"same":{"sessionId":"one"},"same":{"sessionId":"two"}}"#,
    )
    .expect("duplicate session index");
    assert!(inspect(root.path()).is_err());
    std::fs::write(root.join("agents/main/sessions/sessions.json"), "{}")
        .expect("restore owned valid index");
    std::fs::write(
        root.join("agents/main/sessions/one.jsonl"),
        r#"{"type":"message","type":"session"}"#,
    )
    .expect("ambiguous transcript");
    assert!(inspect(root.path()).is_err());
}

#[test]
fn openclaw_preview_stops_at_depth_and_file_budgets_without_writes() {
    let root = TestDir::new("openclaw-limits");
    std::fs::write(root.join("openclaw.json"), "{}").expect("source configuration");
    let mut deepest = root.path().to_path_buf();
    for _ in 0..13 {
        deepest.push("level");
    }
    std::fs::create_dir_all(&deepest).expect("deep source tree");
    assert!(inspect(root.path()).is_err());
    assert!(deepest.is_dir());
    assert_eq!(
        std::fs::read_to_string(root.join("openclaw.json")).expect("source preserved"),
        "{}"
    );
    let oversized = TestDir::new("openclaw-large-config");
    let file = std::fs::File::create(oversized.join("openclaw.json")).expect("oversized source");
    file.set_len(8 * 1024 * 1024 + 1)
        .expect("file byte limit fixture");
    drop(file);
    assert!(inspect(oversized.path()).is_err());
    assert_eq!(
        std::fs::metadata(oversized.join("openclaw.json"))
            .expect("preserved metadata")
            .len(),
        8 * 1024 * 1024 + 1
    );
}

#[cfg(windows)]
#[test]
fn openclaw_preview_rejects_unc_without_attempting_remote_access() {
    assert_eq!(
        inspect(std::path::Path::new(r"\\example.invalid\share\state"))
            .expect_err("UNC is outside local preview policy"),
        claw_migrate::openclaw::PreviewError::UnsafeRoot
    );
    assert_eq!(
        inspect(std::path::Path::new(r"\\.\PhysicalDrive0"))
            .expect_err("device path is not a state root"),
        claw_migrate::openclaw::PreviewError::UnsafeRoot
    );
}
