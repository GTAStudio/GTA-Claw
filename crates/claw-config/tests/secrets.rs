//! Secret redaction and platform-store routing tests.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use claw_config::{
    PlatformSecretStore, SecretMaterial, SecretRef, SecretStoreError, parse_json5, store_secret,
};

const VALID: &str = r#"
{
  schema_version: 1,
  core: {
    auth: { github: { pat: "env:PRIVATE_GITHUB_TOKEN", device: { enabled: false } } },
    role: { source_url: "https://roles.example.test/default.json" },
    channels: { teams: { enabled: false } },
    server: {},
    logging: {},
    sessions: {},
    copilot: {},
    legacy: {},
    updates: {},
    admin: {},
    network: {},
  },
}
"#;

#[derive(Debug)]
struct StoreFailure;

impl Display for StoreFailure {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("backend unavailable")
    }
}

impl Error for StoreFailure {}

#[derive(Default)]
struct RecordingStore {
    labels: Vec<String>,
    values: Vec<String>,
    fail: bool,
}

impl PlatformSecretStore for RecordingStore {
    type Error = StoreFailure;

    fn store(&mut self, label: &str, secret: SecretMaterial<'_>) -> Result<SecretRef, Self::Error> {
        self.labels.push(label.to_owned());
        self.values.push(secret.expose().to_owned());
        if self.fail {
            Err(StoreFailure)
        } else {
            SecretRef::parse("keyring://gta-claw/github-token").map_err(|_| StoreFailure)
        }
    }
}

#[test]
fn secret_reference_and_material_formatters_and_serializers_are_redacted() {
    let reference = SecretRef::parse("keyring://private-service/private-account").expect("ref");
    let material = SecretMaterial::new("literal-super-secret");

    assert_eq!(format!("{reference:?}"), "SecretRef([REDACTED])");
    assert_eq!(reference.to_string(), "secret-ref:[REDACTED]");
    assert_eq!(
        serde_json::to_string(&reference).expect("serialize ref"),
        "\"secret-ref:[REDACTED]\""
    );
    assert_eq!(format!("{material:?}"), "SecretMaterial([REDACTED])");
    assert_eq!(material.to_string(), "[REDACTED]");
    assert_eq!(
        serde_json::to_string(&material).expect("serialize material"),
        "\"[REDACTED]\""
    );
}

#[test]
fn complete_snapshot_debug_output_does_not_reveal_reference_identifiers() {
    let snapshot = parse_json5(VALID, "secret.json5").expect("snapshot");
    let debug = format!("{snapshot:?}");

    assert!(!debug.contains("PRIVATE_GITHUB_TOKEN"));
    assert!(debug.contains("SecretRef([REDACTED])"));
}

#[test]
fn plaintext_is_routed_to_store_and_only_reference_is_returned() {
    let mut store = RecordingStore::default();
    let reference =
        store_secret(&mut store, "github-token", "literal-super-secret").expect("store secret");

    assert_eq!(store.labels, vec!["github-token"]);
    assert_eq!(store.values, vec!["literal-super-secret"]);
    assert_eq!(reference.as_str(), "keyring://gta-claw/github-token");
    assert!(!format!("{reference:?}").contains("literal-super-secret"));
}

#[test]
fn backend_errors_and_invalid_labels_never_include_plaintext() {
    let mut store = RecordingStore {
        fail: true,
        ..RecordingStore::default()
    };
    let backend =
        store_secret(&mut store, "github-token", "literal-super-secret").expect_err("failure");
    match backend {
        SecretStoreError::Backend(StoreFailure) => {}
        SecretStoreError::InvalidLabel => panic!("expected backend failure"),
    }
    assert_eq!(
        backend.to_string(),
        "platform secret store failed: backend unavailable"
    );
    assert!(!backend.to_string().contains("literal-super-secret"));

    let invalid =
        store_secret(&mut store, "bad label", "literal-super-secret").expect_err("invalid label");
    match invalid {
        SecretStoreError::InvalidLabel => {}
        SecretStoreError::Backend(StoreFailure) => panic!("backend must not run"),
    }
    assert_eq!(store.values.len(), 1);
}
