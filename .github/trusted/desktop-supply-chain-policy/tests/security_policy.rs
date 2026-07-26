use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use desktop_supply_chain_policy::bootstrap_decisions::{
    BootstrapSourceDecisionEvidence, validate_bootstrap_source_decisions,
};
use desktop_supply_chain_policy::changes::{
    ChangeManifest, ChangedPath, MAX_GIT_PACK_FILES, MAX_PULL_REQUEST_COMMITS, compute_manifest,
    has_policy_relevant_change, is_policy_relevant, read_manifest,
    validate_pull_request_commit_count, validate_tree_entries, write_manifest,
};
use desktop_supply_chain_policy::identity::canonical_caseless;
use desktop_supply_chain_policy::input::{SafeRoot, compare_trees, sha256};
use desktop_supply_chain_policy::metadata::{
    MetadataTools, release_version_from_metadata_documents, validate_desktop_metadata,
    validate_desktop_metadata_document, validate_root_metadata,
};
use desktop_supply_chain_policy::ownership::{
    CODEOWNER, CODEOWNERS_PATH, canonical_codeowners, frozen_surfaces, validate_codeowners,
    validate_codeowners_text,
};
use desktop_supply_chain_policy::policy::{
    BootstrapSnapshotArchive, BootstrapSnapshotChangeStatus, bootstrap_fingerprint,
    bootstrap_snapshot, expected_bootstrap_fingerprint, is_bootstrap_state,
    validate_build_artifact_pin_table, validate_casefold_paths, validate_final_static,
    write_bootstrap_snapshot, write_final_dependency_fixtures,
};
use desktop_supply_chain_policy::process::{CommandSpec, run, run_checked};
use desktop_supply_chain_policy::repository_policy::validate_repository_policy_transition;
use desktop_supply_chain_policy::validation::{
    BaseState, ValidationRequest, candidate_requires_final, validate_request,
};
use desktop_supply_chain_policy::workflows::{
    AUTHORITATIVE_JOB_NAME, AUTHORITATIVE_PATH, AUTHORITATIVE_WORKFLOW_NAME, ActionlintTool,
    BOOTSTRAP_JOB_NAME, BOOTSTRAP_PATH, BOOTSTRAP_WORKFLOW_NAME, validate_final_workflows,
    validate_inventory, validate_protected_files,
};

mod mutations;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MutationArtifact {
    RustWorkflow,
    MacosWorkflow,
    RootDeny,
    DesktopDeny,
    Audit,
    DesktopManifest,
    AppManifest,
}

impl MutationArtifact {
    const fn production_error(self) -> &'static str {
        match self {
            Self::RustWorkflow => {
                "candidate workflow does not match trusted final P04f policy: .github/workflows/rust.yml"
            }
            Self::MacosWorkflow => {
                "candidate workflow does not match trusted final P04f policy: .github/workflows/macos-packaging.yml"
            }
            Self::RootDeny => "exact security policy file changed: deny.toml",
            Self::DesktopDeny => "exact security policy file changed: desktop/deny.toml",
            Self::Audit => "exact security policy file changed: .cargo/audit.toml",
            Self::DesktopManifest => "exact security policy file changed: desktop/Cargo.toml",
            Self::AppManifest => {
                "exact security policy file changed: desktop/apps/gta-claw-desktop/Cargo.toml"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ExpectedMutation {
    name: &'static str,
    mutation: &'static str,
    artifact: MutationArtifact,
    expected: &'static str,
}

const fn expected_mutation(
    name: &'static str,
    mutation: &'static str,
    artifact: MutationArtifact,
    expected: &'static str,
) -> ExpectedMutation {
    ExpectedMutation {
        name,
        mutation,
        artifact,
        expected,
    }
}

const P04F_MUTATION_ORACLE: [ExpectedMutation; 48] = [
    expected_mutation(
        "root-audit-continue-on-error",
        "root-audit-continue-on-error",
        MutationArtifact::RustWorkflow,
        "Audit root lockfile must not set continue-on-error",
    ),
    expected_mutation(
        "desktop-audit-disabled",
        "desktop-audit-disabled",
        MutationArtifact::RustWorkflow,
        "Audit desktop lockfile must not have an if condition",
    ),
    expected_mutation(
        "desktop-audit-redirected",
        "desktop-audit-redirected",
        MutationArtifact::RustWorkflow,
        "Audit desktop lockfile must not set working-directory",
    ),
    expected_mutation(
        "cargo-audit-install-latest",
        "cargo-audit-install-latest",
        MutationArtifact::RustWorkflow,
        "Bootstrap verified Rust security tools script hash changed",
    ),
    expected_mutation(
        "windows-arm64-deny-missing",
        "windows-arm64-deny-missing",
        MutationArtifact::RustWorkflow,
        "missing Check Windows ARM64 desktop dependency policy step",
    ),
    expected_mutation(
        "supply-checkout-action-substitution",
        "supply-checkout-action-substitution",
        MutationArtifact::RustWorkflow,
        "supply-chain checkout action or inputs changed",
    ),
    expected_mutation(
        "job-checks-write",
        "job-checks-write",
        MutationArtifact::RustWorkflow,
        "job supply-chain permissions exceed read-only allow-list",
    ),
    expected_mutation(
        "job-write-all",
        "job-write-all",
        MutationArtifact::RustWorkflow,
        "job supply-chain permissions must be a read-only mapping",
    ),
    expected_mutation(
        "negative-desktop-path",
        "negative-desktop-path",
        MutationArtifact::RustWorkflow,
        "pull_request paths must exactly match the ordered dependency policy inputs",
    ),
    expected_mutation(
        "rust-branches-ignore",
        "rust-branches-ignore",
        MutationArtifact::RustWorkflow,
        "rust pull_request trigger keys changed",
    ),
    expected_mutation(
        "rust-types-filter",
        "rust-types-filter",
        MutationArtifact::RustWorkflow,
        "rust pull_request trigger keys changed",
    ),
    expected_mutation(
        "macos-branches-ignore",
        "macos-branches-ignore",
        MutationArtifact::MacosWorkflow,
        "macOS pull_request trigger changed",
    ),
    expected_mutation(
        "macos-types-filter",
        "macos-types-filter",
        MutationArtifact::MacosWorkflow,
        "macOS pull_request trigger changed",
    ),
    expected_mutation(
        "supply-job-disabled",
        "supply-job-disabled",
        MutationArtifact::RustWorkflow,
        "supply-chain job must not set if",
    ),
    expected_mutation(
        "supply-job-env-shadow",
        "supply-job-env-shadow",
        MutationArtifact::RustWorkflow,
        "supply-chain job must not set env",
    ),
    expected_mutation(
        "supply-unknown-shadow-step",
        "supply-unknown-shadow-step",
        MutationArtifact::RustWorkflow,
        "supply-chain ordered steps changed",
    ),
    expected_mutation(
        "bootstrap-wrapper-env",
        "bootstrap-wrapper-env",
        MutationArtifact::RustWorkflow,
        "verified tool bootstrap environment changed",
    ),
    expected_mutation(
        "bootstrap-inherited-shell",
        "bootstrap-inherited-shell",
        MutationArtifact::RustWorkflow,
        "verified tool bootstrap shell must clear the startup environment",
    ),
    expected_mutation(
        "bootstrap-shadow-path-change",
        "bootstrap-shadow-path-change",
        MutationArtifact::RustWorkflow,
        "verified tool bootstrap environment changed",
    ),
    expected_mutation(
        "policy-step-runner-env",
        "policy-step-runner-env",
        MutationArtifact::RustWorkflow,
        "Check root dependency policy step schema changed",
    ),
    expected_mutation(
        "native-matrix-runner-collapse",
        "native-matrix-runner-collapse",
        MutationArtifact::MacosWorkflow,
        "native macOS matrix must cover exact ARM64 and Intel runners",
    ),
    expected_mutation(
        "source-policy-disabled",
        "source-policy-disabled",
        MutationArtifact::MacosWorkflow,
        "macOS source-policy job must not set if",
    ),
    expected_mutation(
        "native-arch-assertion-removed",
        "native-arch-assertion-removed",
        MutationArtifact::MacosWorkflow,
        "native macOS architecture assertion or test command changed",
    ),
    expected_mutation(
        "native-format-replaced",
        "native-format-replaced",
        MutationArtifact::MacosWorkflow,
        "Format both Cargo workspaces script hash changed",
    ),
    expected_mutation(
        "native-arch-shell-added",
        "native-arch-shell-added",
        MutationArtifact::MacosWorkflow,
        "Test both Cargo workspaces natively step schema changed",
    ),
    expected_mutation(
        "native-workflow-env-shadow",
        "native-workflow-env-shadow",
        MutationArtifact::MacosWorkflow,
        "macOS workflow inherited environment changed",
    ),
    expected_mutation(
        "native-matrix-extra-key",
        "native-matrix-extra-key",
        MutationArtifact::MacosWorkflow,
        "native macOS matrix row schema changed",
    ),
    expected_mutation(
        "deny-no-locked",
        "deny-no-locked",
        MutationArtifact::RustWorkflow,
        "Check Windows x64 desktop dependency policy command is not exact",
    ),
    expected_mutation(
        "deny-advisory-ignore",
        "deny-advisory-ignore",
        MutationArtifact::DesktopDeny,
        "desktop deny advisories.ignore must be empty",
    ),
    expected_mutation(
        "audit-config-ignore",
        "audit-config-ignore",
        MutationArtifact::Audit,
        "cargo audit advisories.ignore must be empty",
    ),
    expected_mutation(
        "deny-git-source",
        "deny-git-source",
        MutationArtifact::DesktopDeny,
        "desktop deny sources.allow-git must be empty",
    ),
    expected_mutation(
        "deny-license-widening",
        "deny-license-widening",
        MutationArtifact::DesktopDeny,
        "desktop deny license allow-list changed",
    ),
    expected_mutation(
        "deny-graph-exclude",
        "deny-graph-exclude",
        MutationArtifact::DesktopDeny,
        "desktop deny graph policy keys changed",
    ),
    expected_mutation(
        "root-deny-license-widening",
        "root-deny-license-widening",
        MutationArtifact::RootDeny,
        "root deny license policy changed",
    ),
    expected_mutation(
        "root-deny-inline-exception",
        "root-deny-inline-exception",
        MutationArtifact::RootDeny,
        "root deny license policy changed",
    ),
    expected_mutation(
        "root-deny-source-widening",
        "root-deny-source-widening",
        MutationArtifact::RootDeny,
        "root deny source policy changed",
    ),
    expected_mutation(
        "root-deny-ban-skip",
        "root-deny-ban-skip",
        MutationArtifact::RootDeny,
        "root deny bans policy changed",
    ),
    expected_mutation(
        "root-deny-string-skip",
        "root-deny-string-skip",
        MutationArtifact::RootDeny,
        "root deny bans policy changed",
    ),
    expected_mutation(
        "root-deny-crate-skip",
        "root-deny-crate-skip",
        MutationArtifact::RootDeny,
        "root deny bans policy changed",
    ),
    expected_mutation(
        "root-deny-versionless-name-skip",
        "root-deny-versionless-name-skip",
        MutationArtifact::RootDeny,
        "root deny bans policy changed",
    ),
    expected_mutation(
        "slint-wildcard-version",
        "slint-wildcard-version",
        MutationArtifact::AppManifest,
        "desktop Slint dependency policy changed",
    ),
    expected_mutation(
        "slint-build-caret-version",
        "slint-build-caret-version",
        MutationArtifact::AppManifest,
        "desktop slint-build dependency policy changed",
    ),
    expected_mutation(
        "duplicate-target-slint-widening",
        "duplicate-target-slint-widening",
        MutationArtifact::AppManifest,
        "desktop target table schema changed",
    ),
    expected_mutation(
        "renamed-slint-package",
        "renamed-slint-package",
        MutationArtifact::AppManifest,
        "desktop contains unexpected Slint package aliases",
    ),
    expected_mutation(
        "workspace-renamed-slint-package",
        "workspace-renamed-slint-package",
        MutationArtifact::DesktopManifest,
        "desktop workspace dependency policy changed: claw-application",
    ),
    expected_mutation(
        "desktop-replace-slint-build",
        "desktop-replace-slint-build",
        MutationArtifact::DesktopManifest,
        "desktop must not patch or replace registry sources",
    ),
    expected_mutation(
        "app-claw-application-registry",
        "app-claw-application-registry",
        MutationArtifact::AppManifest,
        "desktop app workspace dependency policy changed: claw-application",
    ),
    expected_mutation(
        "app-claw-platform-path",
        "app-claw-platform-path",
        MutationArtifact::AppManifest,
        "desktop app workspace dependency policy changed: claw-platform",
    ),
];

const P04F_MUTATED_ARTIFACT_SHA256: [&str; 48] = [
    "90e24e0c9fc0d53b0f916c78c5a68412cf26d03a9c1e247dc4d63a75b57fa970",
    "61c7ff94f9f7030e9ddab3e43dd81a5af90d1676ecba5ac2109a26870f6e59d7",
    "748b4fe8c75731d4af37df67feb12440538cbfb6f00c2d37f743033b54cd67c0",
    "c16d255135044fc70e6804c0beda1653fa4c51a913d3fa27bc30580c9ddf4771",
    "ada5d293265b7f62be3e813c901bc32a67562ce83c3da329f8efa46e33535b7f",
    "d3aa806687c3f70ad56e79aaf3e03f447b0eaacd2be960a5b0f95522fd52a34f",
    "93bc016b4eff2f2856d63c63ff1a7884fba5142d702c689aa1b65fafd114a3e7",
    "11bf6afdb402b75010f93578d1b23eefc809f724789805cecf905004dda02a82",
    "69d4dd13274184df81e40850af72b43a61616d39053756e4b9af048c6258d300",
    "9753cc1eadca7a09df356d08dafec088e646c94c0ce2868f84710df1943a2441",
    "3467fde87a6a406cc94335bd2bd63f0b8e3522c134e063976328a630de1dcaa7",
    "085007bef5ab5c3f9fb20620e0503b521c8e94cc38c64aec7deb162d59266821",
    "2aa5d8512048ef3d63d10a0629ee341f219bc14774bf2142ada000620167040b",
    "167036eb447029f002f216247434daa4bb2e4134c0d5bc93267aaed0cc069327",
    "a8bbfc6d471d39ed81ad4676e57f477b5b50afd82129068eb6bc6d6f57733342",
    "a20a835fd001a0eca4eb665cf735848ff18c5fa311de33e905d6306f31bc3140",
    "26b9dfaacb1ebafbc10112322f708fc9b8e65f2c136e1a2c1e1d0e1c4e4515ca",
    "ec82eef948d01d5cab301b32086204cb966db73dd01644070f6c6777a4b45924",
    "0bdd763bd89d491d9b8b35421b4ad3654a4679c86f1822bbf1c909c87374e00e",
    "5aee908db7a976b943b26425e848cfa90931ee626f804e39cb252486cf047383",
    "d129c46d34da8a7c90a1c3980e96cbaba1c65f98ecee60fc026301042fa884ba",
    "3304ae34abc2ae57e4f3b8550d86175dba2a5569035795a689e015809a8d5b1f",
    "67ed5a587d7d97a6dbd2371a4bd6de4267f3ea48c8c3770359a11d3d209a88a4",
    "903bd89be9e6965e5e28e301d589fbc8c9940aa7484b0a7fee188dddeb779b2f",
    "07d7afedc58029cda95d9fce97bc18a7cfa92ed3a3bb80d773871cc0b7b67f7d",
    "ddbec13b0ae19529ee1fc55e09be7d85e8e5e05bf2809d4a2558a42539452a9f",
    "7d6b59069f0cdc0fcc3333be14522f9ac1d1b348d5a5c632bf073a13df4b0772",
    "6323a7af697145771d2c7347e8d58b7473a03aebdd9f4f454373265cd878b109",
    "6f9e9832a4b82fb713d312da5003f65c5c95324fc10a1ec64f5f59cc28bafcb0",
    "d25d49c53c9c183dd0686e25d714c17a8658992615b1c51b5154af2d5795eec7",
    "1419ffd6b5eba450fe1971895ee7f8ce390706bd01b57d4e8bfbf57987fd41c7",
    "8cdb8b459b89f41ac4a34f8ae604f6ed21f8bb457c257c6076fe806df4f65efe",
    "774426b359f177abf4fa535d352bc172233e1c65d715ef29659459f7bb82dc1d",
    "bb0765a3cde2b1e2ccad68918c4bc639aceedfbab4a4f53a28c8afcd600f9686",
    "fc996a176592a7222eae3ae544c373e0a926f6d9086fed9d47307666ef745fae",
    "0bf5edd919b09327fee1b6f45aea8a0a6432d3800990a21fe7ed40fbf4a040b5",
    "2832f430e8b38e365b58ca1583cfe84f0975f4f3655697a2f26fa9876f88bae7",
    "b9452f32eec46f9400af6dd0a8c6160d83580bce1f163a6587cc88ff2de56213",
    "226007c6e9d0dcf1e48f5b2a4b083f1b5669dfb91f235e999b97e1f7fc1a00f2",
    "4c663a6cebb27c4cb285c5587e019ae503b2ec352ba83c95dc94f48cf8fa5b18",
    "dbbf5e53488e8977958a95ab58e03ba89ee9da7503ffe0e58dd946946afb8179",
    "bb2febc949e862a6e5c0904f4041b19853e7bde3f06f17627f4c828519b856d7",
    "781a04de8ae53429a22b602b303fe9f870def0c545f7a056c7ea322677984409",
    "8fcfb80aae55f86784ae9beb5156adbc0fc39d1fd94e4c38168eb98d2b2eb673",
    "9c80415e5ee8df92ffd430eccb522092c976a664e465a2ff0b1f1b005bee9b98",
    "615596b62a471f0770006a9c0cc42b2c0693550f2fbdee876478b060f176b4f9",
    "3491150028a9366726ce7d277138d1e28603a1d6f94fa1f2c22db61297659d07",
    "a2575b5c38377babd9418a0d7741c1e3bebf551b5dcac449c306e3fcc3352567",
];

const SUPERSEDED_FINAL_DEPENDENCY_SHA256: [&str; 3] = [
    "597bfbaf79ac07fa1cbddb25acba7ac1446a8e1d02296149e5a3fe715ce85f06",
    "d1cc4a296b767bcb4082506c572d30d91369ec99db4ce5182ea24e93526d8a79",
    "c0bf44bbc8a93fbe08f33fcc990354cc36dac8da1a556e9a4b05e8686d3b50ae",
];

const P03B_SQLITE_FILE_CONTROL_MANIFEST_SHA256: &str =
    "b2ce476ecc84143cfa0c071d6289ab35ec1f425ac4aa5af5fc47e6cc3258da82";
const P03B_SQLITE_FILE_CONTROL_MEMBER: &str = "crates/claw-sqlite-file-control";
const FINAL_ROOT_DENY_SHA256: &str =
    "75dedb874582f2f6d32890e21cca11186112d13dd51f4140ada96c69989594d0";
const SUPERSEDED_ROOT_DENY_SHA256: &str =
    "a822bdccf7d6e235f03fdadbc6d43e381f7219d02abad80d8253c10c7e1529db";
const P03B_SQLITE_FILE_CONTROL_MANIFEST: &str = r#"[package]
name = "claw-sqlite-file-control"
description = "Audited SQLite file-control boundary for GTA Claw"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
futures-core = "=0.3.32"
libsqlite3-sys = "0.37.0"
sqlx.workspace = true
tokio.workspace = true
sha2.workspace = true

[target.'cfg(unix)'.dependencies]
rustix.workspace = true
xattr.workspace = true

[target.'cfg(windows)'.dependencies]
windows-sys.workspace = true

[dev-dependencies]
tempfile = "3.27.0"

[lints.rust]
missing_docs = "warn"
unsafe_code = "allow"
unsafe_op_in_unsafe_fn = "deny"
unreachable_pub = "warn"

[lints.clippy]
all = "warn"
"#;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("trusted crate is under repository/.github/trusted")
        .to_path_buf()
}

struct TempTree {
    path: PathBuf,
}

impl TempTree {
    fn new(label: &str) -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "gta-claw-policy-{label}-{}-{unique}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove prior temporary policy tree");
        }
        fs::create_dir_all(&path).expect("create temporary policy tree");
        Self { path }
    }

    fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.path.join(relative)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).expect("remove temporary policy tree");
        }
    }
}

fn copy_directory(source: &Path, destination: &Path) -> io::Result<()> {
    fs::create_dir_all(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name();
        if name == ".git" || name == "target" {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        let destination = destination.join(name);
        if metadata.is_dir() {
            copy_directory(&entry.path(), &destination)?;
        } else if metadata.is_file() {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), destination)?;
        } else {
            return Err(io::Error::other(
                "repository fixture contains a non-regular entry",
            ));
        }
    }
    Ok(())
}

fn copy_repo(label: &str) -> TempTree {
    let tree = TempTree::new(label);
    copy_directory(&repo_root(), &tree.path).expect("copy repository fixture");
    tree
}

fn bootstrap_tree(label: &str) -> TempTree {
    let tree = TempTree::new(label);
    let snapshot = fs::read(
        repo_root().join(".github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"),
    )
    .expect("read immutable bootstrap snapshot");
    let archive =
        BootstrapSnapshotArchive::parse(&snapshot).expect("parse immutable bootstrap snapshot");
    assert_eq!(archive.entries().len(), 28);
    for (path, payload) in archive.entries() {
        let destination = tree.join(path);
        fs::create_dir_all(destination.parent().expect("snapshot path parent"))
            .expect("create snapshot parent");
        fs::write(destination, payload).expect("write snapshot file");
    }
    copy_directory(
        &repo_root().join(".github/trusted/desktop-supply-chain-policy"),
        &tree.join(".github/trusted/desktop-supply-chain-policy"),
    )
    .expect("copy protected trust root into bootstrap fixture");
    tree
}

fn write_from_policy(tree: &TempTree, source: &str, destination: &str) {
    let source = repo_root()
        .join(".github/trusted/desktop-supply-chain-policy/policy/final")
        .join(source);
    let destination = tree.join(destination);
    fs::create_dir_all(destination.parent().expect("fixture destination parent"))
        .expect("create fixture destination");
    fs::copy(source, destination).expect("copy final policy overlay");
}

fn final_tree(label: &str) -> TempTree {
    let tree = copy_repo(label);
    for (source, destination) in [
        (".github/workflows/rust.yml", ".github/workflows/rust.yml"),
        (
            ".github/workflows/macos-packaging.yml",
            ".github/workflows/macos-packaging.yml",
        ),
        ("root-deny.toml.fixture", "deny.toml"),
        ("desktop/Cargo.toml.fixture", "desktop/Cargo.toml"),
        ("desktop/Cargo.lock.fixture", "desktop/Cargo.lock"),
        (
            "desktop/apps/gta-claw-desktop/Cargo.toml.fixture",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
        ),
        (
            "desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs",
            "desktop/apps/gta-claw-desktop/tests/macos_winit_smoke.rs",
        ),
        ("desktop/deny.toml.fixture", "desktop/deny.toml"),
        (
            ".github/fixtures/cargo-audit/unmaintained/Cargo.lock.fixture",
            ".github/fixtures/cargo-audit/unmaintained/Cargo.lock.fixture",
        ),
        (
            ".github/fixtures/cargo-audit/vulnerable/Cargo.lock.fixture",
            ".github/fixtures/cargo-audit/vulnerable/Cargo.lock.fixture",
        ),
        (
            ".github/fixtures/security-tools/bash-env-poison.sh",
            ".github/fixtures/security-tools/bash-env-poison.sh",
        ),
        (
            ".github/fixtures/security-tools/shadow-bin/sha256sum",
            ".github/fixtures/security-tools/shadow-bin/sha256sum",
        ),
        (
            ".github/fixtures/security-tools/shadow-bin/tar",
            ".github/fixtures/security-tools/shadow-bin/tar",
        ),
    ] {
        write_from_policy(&tree, source, destination);
    }
    tree
}

fn replace(path: &Path, from: &str, to: &str) {
    let text = fs::read_to_string(path).expect("read mutation input");
    assert!(text.contains(from), "mutation source missing: {from:?}");
    fs::write(path, text.replacen(from, to, 1)).expect("write mutation");
}

fn assert_unique_sorted_root_members(members: &[toml::Value]) {
    let members = members
        .iter()
        .map(|member| member.as_str().expect("root workspace member string"))
        .collect::<Vec<_>>();
    assert!(
        members.windows(2).all(|pair| pair[0] < pair[1]),
        "synthetic setup requires unique sorted root workspace members"
    );
}

fn add_new_root_member(tree: &TempTree, member: &str, member_manifest: &str) {
    let root_manifest_path = tree.join("Cargo.toml");
    let mut root_manifest: toml::Value = toml::from_str(
        &fs::read_to_string(&root_manifest_path).expect("read root member fixture manifest"),
    )
    .expect("parse root member fixture manifest");
    let members = root_manifest
        .get_mut("workspace")
        .and_then(|workspace| workspace.get_mut("members"))
        .and_then(toml::Value::as_array_mut)
        .expect("root workspace member array");
    assert_unique_sorted_root_members(members);
    let position = match members.binary_search_by(|candidate| {
        candidate
            .as_str()
            .expect("root workspace member string")
            .cmp(member)
    }) {
        Ok(_) => panic!(
            "fixture member `{member}` now exists in the real repository; rename the fixture member - it must be a name no crate will ever take"
        ),
        Err(position) => position,
    };
    members.insert(position, toml::Value::String(member.to_owned()));
    fs::write(
        root_manifest_path,
        toml::to_string(&root_manifest).expect("serialize root member fixture manifest"),
    )
    .expect("write root member fixture manifest");

    let member_manifest_value: toml::Value =
        toml::from_str(member_manifest).expect("parse synthetic member manifest");
    let package_name = member_manifest_value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .expect("synthetic member package name");
    let manifest_path = tree.join(member).join("Cargo.toml");
    fs::create_dir_all(manifest_path.parent().expect("synthetic member parent"))
        .expect("create synthetic member");
    fs::write(&manifest_path, member_manifest).expect("write synthetic member manifest");
    fs::create_dir_all(tree.join(member).join("src")).expect("create synthetic member source");
    fs::write(tree.join(member).join("src/lib.rs"), "").expect("write synthetic member source");

    let mut lock = fs::read_to_string(tree.join("Cargo.lock")).expect("read root lock");
    lock.push_str(&format!(
        "\n[[package]]\nname = \"{package_name}\"\nversion = \"0.1.0\"\n"
    ));
    fs::write(tree.join("Cargo.lock"), lock).expect("write synthetic member lock entry");
}

fn ensure_existing_root_member(tree: &TempTree, member: &str, member_manifest: &str) {
    assert!(
        member == P03B_SQLITE_FILE_CONTROL_MEMBER,
        "only the exact native-FFI member setup may use the existing-member helper"
    );
    assert!(
        member_manifest == P03B_SQLITE_FILE_CONTROL_MANIFEST,
        "existing native-FFI member must use the canonical manifest"
    );

    let root_manifest: toml::Value = toml::from_str(
        &fs::read_to_string(tree.join("Cargo.toml")).expect("read existing root member manifest"),
    )
    .expect("parse existing root member manifest");
    let members = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .expect("root workspace member array");
    assert_unique_sorted_root_members(members);
    assert!(
        members
            .binary_search_by(|candidate| {
                candidate
                    .as_str()
                    .expect("root workspace member string")
                    .cmp(member)
            })
            .is_ok(),
        "existing native-FFI member is missing from the root workspace"
    );
    assert!(
        fs::read_to_string(tree.join(member).join("Cargo.toml"))
            .expect("read existing native-FFI member manifest")
            .replace("\r\n", "\n")
            == P03B_SQLITE_FILE_CONTROL_MANIFEST,
        "existing native-FFI member manifest changed"
    );
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .expect("panic payload string")
}

const REPOSITORY_POLICY_MANIFEST: &str = r#"[package]
name = "claw-repo-policy"
description = "Repository-wide architecture policy gates for GTA Claw"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true
"#;

const REPOSITORY_POLICY_MEMBER: &str = "crates/claw-repo-policy";
const REPOSITORY_POLICY_PACKAGE: &str = "claw-repo-policy";

const REPOSITORY_POLICY_TEST_FIXTURE: &str = r#"const FORBIDDEN_FILE_NAMES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
    "deno.json",
    "deno.jsonc",
];
const FORBIDDEN_DIRECTORY_NAMES: &[&str] = &["node_modules", ".yarn", ".pnpm-store"];
const FORBIDDEN_EXTENSIONS: &[&str] =
    &["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "node"];
const FORBIDDEN_WORKFLOW_COMMANDS: &[&str] = &[
    "node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "corepack",
];
const LEGACY_RUNTIME_INVENTORY: &[&str] = &[
    "Dockerfile",
    "package-lock.json",
    "package.json",
    "src/auth/deviceFlow.ts",
    "src/bot/teamsBot.ts",
    "src/channels/discordGateway.ts",
    "src/channels/messageProcessor.ts",
    "src/channels/telegramPolling.ts",
    "src/channels/whatsappWebhook.ts",
    "src/config.ts",
    "src/engine/copilotEngine.ts",
    "src/engine/sessionManager.ts",
    "src/engine/toolExecutor.ts",
    "src/index.ts",
    "src/loader/roleLoader.ts",
    "src/loader/skillLoader.ts",
    "src/server.ts",
    "src/updater/sdkUpdater.ts",
    "src/utils/logger.ts",
    "src/utils/proxy.ts",
    "src/utils/splitMessage.ts",
    "tsconfig.json",
];
const ALLOWED_ADVERSARIAL_SHELL_FIXTURES: &[&str] =
    &[".github/fixtures/security-tools/bash-env-poison.sh"];
const ALLOWED_COMPAT_FIXTURES: &[&str] = &[];

#[test]
fn repository_legacy_javascript_surface_does_not_grow() {}

#[test]
fn new_typescript_path_outside_legacy_inventory_is_rejected() {
    fixture.write("src/newFeature.ts", b"new");
    assert_eq!(violations, ["src/newFeature.ts"]);
}

#[test]
fn removing_allowlisted_legacy_entry_keeps_ratchet_green() {
    fs::remove_file(fixture.path().join("src/index.ts")).unwrap();
}

#[test]
fn workflow_commands_are_checked_without_rejecting_inert_search_patterns() {}

#[test]
fn tracked_symlink_and_gitlink_modes_are_rejected() {
    let _ = b"120000 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let _ = b"160000 cccccccccccccccccccccccccccccccccccccccc";
}
"#;

const ACTIVE_REPOSITORY_POLICY_WORKFLOW: &str = r#"name: pinned upstream Gateway reference

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  policy:
    name: Repository policy
    runs-on: windows-latest
    timeout-minutes: 30
    steps:
      - name: Checkout GTA Claw
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      - name: Reject JavaScript toolchain artifacts
        run: cargo test --locked --package claw-repo-policy --test repository_policy
"#;

fn deactivate_repository_policy(tree: &TempTree) {
    let root_manifest_path = tree.join("Cargo.toml");
    let mut root_manifest: toml::Value = toml::from_str(
        &fs::read_to_string(&root_manifest_path).expect("read active policy root manifest"),
    )
    .expect("parse active policy root manifest");
    let members = root_manifest
        .get_mut("workspace")
        .and_then(|workspace| workspace.get_mut("members"))
        .and_then(toml::Value::as_array_mut)
        .expect("active policy root workspace members");
    assert_unique_sorted_root_members(members);
    let position = members
        .binary_search_by(|candidate| {
            candidate
                .as_str()
                .expect("root workspace member string")
                .cmp(REPOSITORY_POLICY_MEMBER)
        })
        .expect("active policy root workspace member");
    members.remove(position);
    assert_unique_sorted_root_members(members);
    fs::write(
        root_manifest_path,
        toml::to_string(&root_manifest).expect("serialize inactive policy root manifest"),
    )
    .expect("write inactive policy root manifest");

    let policy_root = tree.join(REPOSITORY_POLICY_MEMBER);
    for path in ["Cargo.toml", "src/lib.rs", "tests/repository_policy.rs"] {
        fs::remove_file(policy_root.join(path)).expect("remove active repository policy file");
    }
    fs::remove_dir(policy_root.join("src")).expect("remove empty repository policy source");
    fs::remove_dir(policy_root.join("tests")).expect("remove empty repository policy tests");
    fs::remove_dir(policy_root).expect("remove empty repository policy crate");

    let root_lock_path = tree.join("Cargo.lock");
    let mut root_lock: toml::Value =
        toml::from_str(&fs::read_to_string(&root_lock_path).expect("read active policy root lock"))
            .expect("parse active policy root lock");
    let packages = root_lock
        .get_mut("package")
        .and_then(toml::Value::as_array_mut)
        .expect("active policy root lock packages");
    let package_count = packages.len();
    packages.retain(|package| {
        package.get("name").and_then(toml::Value::as_str) != Some(REPOSITORY_POLICY_PACKAGE)
    });
    assert_eq!(
        package_count,
        packages.len() + 1,
        "active policy lock must contain exactly one claw-repo-policy package"
    );
    fs::write(
        root_lock_path,
        toml::to_string(&root_lock).expect("serialize inactive policy root lock"),
    )
    .expect("write inactive policy root lock");
}

fn activate_repository_policy(tree: &TempTree) {
    add_new_root_member(tree, REPOSITORY_POLICY_MEMBER, REPOSITORY_POLICY_MANIFEST);
    fs::write(
        tree.join(REPOSITORY_POLICY_MEMBER).join("src/lib.rs"),
        "//! Repository-wide architecture policy gates for GTA Claw.\n",
    )
    .expect("write repository policy library");
    fs::create_dir_all(tree.join(REPOSITORY_POLICY_MEMBER).join("tests"))
        .expect("create repository policy tests");
    fs::write(
        tree.join(REPOSITORY_POLICY_MEMBER)
            .join("tests/repository_policy.rs"),
        REPOSITORY_POLICY_TEST_FIXTURE,
    )
    .expect("write repository policy test fixture");
    fs::write(
        tree.join(".github/workflows/upstream-gateway-reference.yml"),
        ACTIVE_REPOSITORY_POLICY_WORKFLOW,
    )
    .expect("write active repository policy workflow");
}

fn write_release_workspace(
    root: &Path,
    name: &str,
    version: &str,
    alternative_formatting: bool,
    second_version: Option<&str>,
) -> PathBuf {
    fs::create_dir_all(root.join("member/src")).expect("create release metadata member");
    let mut members = vec!["member"];
    if second_version.is_some() {
        members.push("other");
        fs::create_dir_all(root.join("other/src")).expect("create second metadata member");
    }
    let manifest = if alternative_formatting {
        format!(
            "[workspace] # formatting must not affect semantic version extraction\nmembers = [ {} ]\nresolver=\"3\"\n\n[workspace.package]\nversion=  \"{version}\" # deliberately spaced\n",
            members
                .iter()
                .map(|member| format!("\"{member}\","))
                .collect::<Vec<_>>()
                .join(" ")
        )
    } else {
        format!(
            "[workspace]\nmembers = [{}]\nresolver = \"3\"\n\n[workspace.package]\nversion = \"{version}\"\n",
            members
                .iter()
                .map(|member| format!("\"{member}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    fs::create_dir_all(root).expect("create release metadata workspace");
    fs::write(root.join("Cargo.toml"), manifest).expect("write release workspace manifest");
    fs::write(
        root.join("member/Cargo.toml"),
        format!(
            "[package]\nname = \"{name}-member\"\nversion.workspace = true\nedition = \"2024\"\nbuild = \"build.rs\"\n"
        ),
    )
    .expect("write release member manifest");
    fs::write(root.join("member/src/lib.rs"), "").expect("write release member source");
    fs::write(
        root.join("member/build.rs"),
        "fn main() { panic!(\"cargo metadata executed build.rs\"); }\n",
    )
    .expect("write non-executing build script");
    let mut lock_packages = vec![(format!("{name}-member"), version.to_owned())];
    if let Some(second_version) = second_version {
        fs::write(
            root.join("other/Cargo.toml"),
            format!(
                "[package]\nname = \"{name}-other\"\nversion = \"{second_version}\"\nedition = \"2024\"\n"
            ),
        )
        .expect("write second release member manifest");
        fs::write(root.join("other/src/lib.rs"), "").expect("write second release member source");
        lock_packages.push((format!("{name}-other"), second_version.to_owned()));
    }
    lock_packages.sort();
    let mut lock =
        "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n"
            .to_owned();
    for (package, package_version) in lock_packages {
        lock.push_str(&format!(
            "\n[[package]]\nname = \"{package}\"\nversion = \"{package_version}\"\n"
        ));
    }
    fs::write(root.join("Cargo.lock"), lock).expect("write release metadata lock");
    root.join("Cargo.toml")
}

fn run_release_metadata_fixture(
    tools: &MetadataTools,
    manifest: &Path,
    isolation: &Path,
) -> std::process::Output {
    fs::create_dir_all(isolation.join("home")).expect("create metadata fixture home");
    fs::create_dir_all(isolation.join("cargo-home")).expect("create metadata fixture Cargo home");
    fs::create_dir_all(isolation.join("target")).expect("create metadata fixture target");
    fs::create_dir_all(isolation.join("temp")).expect("create metadata fixture temp");
    fs::create_dir_all(isolation.join("cwd")).expect("create metadata fixture cwd");
    Command::new(&tools.cargo)
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(manifest)
        .current_dir(isolation.join("cwd"))
        .env_clear()
        .env("HOME", isolation.join("home"))
        .env("CARGO_HOME", isolation.join("cargo-home"))
        .env("CARGO_TARGET_DIR", isolation.join("target"))
        .env("CARGO_NET_OFFLINE", "true")
        .env("RUSTC", &tools.rustc)
        .env("TMPDIR", isolation.join("temp"))
        .env("TEMP", isolation.join("temp"))
        .env("TMP", isolation.join("temp"))
        .env("LC_ALL", "C")
        .output()
        .expect("run release metadata fixture")
}

fn local_metadata_tools() -> MetadataTools {
    let cargo = PathBuf::from(env::var_os("CARGO").expect("Cargo exposes CARGO to tests"));
    let rustc_name = if cfg!(windows) { "rustc.exe" } else { "rustc" };
    let rustc = cargo.parent().expect("Cargo has a parent").join(rustc_name);
    MetadataTools {
        cargo_sha256: sha256(&fs::read(&cargo).expect("read local Cargo")),
        rustc_sha256: sha256(&fs::read(&rustc).expect("read local rustc")),
        cargo,
        rustc,
    }
}

fn local_actionlint() -> Option<ActionlintTool> {
    let path = PathBuf::from(env::var_os("ACTIONLINT_BIN")?);
    Some(ActionlintTool {
        sha256: sha256(&fs::read(&path).expect("read local actionlint")),
        path,
    })
}

fn fake_manifest(path: &Path, relevant: bool) {
    let changed = if relevant {
        "desktop/deny.toml"
    } else {
        "crates/claw-domain/src/lib.rs"
    };
    write_manifest(
        path,
        &ChangeManifest {
            base: "1111111111111111111111111111111111111111".to_owned(),
            head: "2222222222222222222222222222222222222222".to_owned(),
            paths: vec![ChangedPath {
                status: 'M',
                path: changed.to_owned(),
            }],
        },
    )
    .expect("write fake trusted manifest");
}

#[test]
fn residual_bootstrap_coupling_does_not_shadow_workflow_or_static_diagnostics() {
    let cases = [
        (
            "protected-workflow",
            AUTHORITATIVE_PATH,
            "\n# planted protected workflow mutation\n",
            format!("protected workflow changed: {AUTHORITATIVE_PATH}"),
        ),
        (
            "root-static",
            "deny.toml",
            "\n# planted root policy mutation\n",
            "exact security policy file changed: deny.toml".to_owned(),
        ),
    ];
    for (label, changed_path, suffix, expected) in cases {
        let trusted = bootstrap_tree(&format!("{label}-trusted"));
        let candidate = final_tree(&format!("{label}-candidate"));
        for protected in [CODEOWNERS_PATH, AUTHORITATIVE_PATH, BOOTSTRAP_PATH] {
            fs::copy(trusted.join(protected), candidate.join(protected))
                .expect("align protected Bootstrap fixture bytes");
        }
        let path = candidate.join(changed_path);
        let mut bytes = fs::read(&path).expect("read planted ordering input");
        bytes.extend_from_slice(suffix.as_bytes());
        fs::write(path, bytes).expect("write planted ordering mutation");
        let artifacts = TempTree::new(&format!("{label}-artifacts"));
        let changes = artifacts.join("changes.json");
        write_manifest(
            &changes,
            &ChangeManifest {
                base: "1111111111111111111111111111111111111111".to_owned(),
                head: "2222222222222222222222222222222222222222".to_owned(),
                paths: vec![ChangedPath {
                    status: 'M',
                    path: changed_path.to_owned(),
                }],
            },
        )
        .expect("write ordering manifest");
        let error = validate_request(&ValidationRequest {
            trusted_root: trusted.path.clone(),
            candidate_root: candidate.path.clone(),
            changes,
            metadata_tools: MetadataTools {
                cargo: artifacts.join("unreachable-cargo"),
                cargo_sha256: "0".repeat(64),
                rustc: artifacts.join("unreachable-rustc"),
                rustc_sha256: "0".repeat(64),
            },
            actionlint: ActionlintTool {
                path: artifacts.join("unreachable-actionlint"),
                sha256: "0".repeat(64),
            },
            isolation_root: artifacts.join("isolation"),
        })
        .expect_err("planted preexisting diagnostic unexpectedly passed")
        .to_string();
        assert_eq!(
            error, expected,
            "{label} was shadowed by the residual Bootstrap coupling rule"
        );
    }
}

#[test]
fn residual_bootstrap_coupling_does_not_shadow_repository_ratchet_diagnostic() {
    let Some(actionlint) = local_actionlint() else {
        eprintln!("ACTIONLINT_BIN is not set; hosted bootstrap requires and runs this test");
        return;
    };
    let trusted = final_tree("residual-repository-trusted");
    let candidate = final_tree("residual-repository-candidate");
    deactivate_repository_policy(&trusted);
    deactivate_repository_policy(&candidate);
    fs::write(candidate.join("src/newFeature.ts"), "new legacy feature")
        .expect("plant repository ratchet violation");
    let root_manifest = candidate.join("Cargo.toml");
    let mut manifest_bytes = fs::read(&root_manifest).expect("read candidate root manifest");
    manifest_bytes.extend_from_slice(b"\n# planted Bootstrap source change\n");
    fs::write(root_manifest, manifest_bytes).expect("write Bootstrap source change");
    let artifacts = TempTree::new("residual-repository-artifacts");
    let changes = artifacts.join("changes.json");
    write_manifest(
        &changes,
        &ChangeManifest {
            base: "1111111111111111111111111111111111111111".to_owned(),
            head: "2222222222222222222222222222222222222222".to_owned(),
            paths: vec![
                ChangedPath {
                    status: 'M',
                    path: "Cargo.toml".to_owned(),
                },
                ChangedPath {
                    status: 'A',
                    path: "src/newFeature.ts".to_owned(),
                },
            ],
        },
    )
    .expect("write repository ordering manifest");
    let error = validate_request(&ValidationRequest {
        trusted_root: trusted.path.clone(),
        candidate_root: candidate.path.clone(),
        changes,
        metadata_tools: local_metadata_tools(),
        actionlint,
        isolation_root: artifacts.join("isolation"),
    })
    .expect_err("repository ratchet violation unexpectedly passed")
    .to_string();
    assert!(
        error.contains("legacy Node artifacts outside the exact ceiling"),
        "repository ratchet was shadowed by the residual Bootstrap coupling rule: {error}"
    );
}

/// Bootstrap sources that carry no standing preservation and are not already byte-pinned by an
/// earlier rule, so an otherwise-valid live change to one still reaches the residual diagnostic.
///
/// The other nine fully coupled sources are refused earlier and more strictly: CODEOWNERS by
/// `validate_codeowners`/`validate_protected_files`, `rust.yml` and `macos-packaging.yml` by
/// `validate_final_workflows`, the two policy workflows by `validate_protected_files`, and
/// `.cargo/audit.toml`, `.gitattributes`, `rust-toolchain.toml` and `rustfmt.toml` by
/// `validate_final_fixed_files`. Only these four can reach the residual through the full stack.
const RESIDUAL_REACHABLE_SOURCES: [&str; 4] = [
    ".github/workflows/docker-publish.yml",
    ".github/workflows/linux-packaging.yml",
    ".github/workflows/upstream-gateway-reference.yml",
    ".github/workflows/windows-packaging.yml",
];

#[test]
fn otherwise_valid_bootstrap_source_change_reaches_exact_residual_diagnostic() {
    let Some(actionlint) = local_actionlint() else {
        eprintln!("ACTIONLINT_BIN is not set; hosted bootstrap requires and runs this test");
        return;
    };
    let trusted = final_tree("residual-exact-trusted");
    for path in RESIDUAL_REACHABLE_SOURCES {
        let label = path.rsplit('/').next().expect("Bootstrap source file name");
        let candidate = final_tree(&format!("residual-exact-candidate-{label}"));
        let source = candidate.join(path);
        let mut source_bytes = fs::read(&source).expect("read candidate Bootstrap source");
        source_bytes.extend_from_slice(b"\n# otherwise-valid Bootstrap source change\n");
        fs::write(source, source_bytes).expect("write otherwise-valid source change");
        let artifacts = TempTree::new(&format!("residual-exact-artifacts-{label}"));
        let changes = artifacts.join("changes.json");
        write_manifest(
            &changes,
            &ChangeManifest {
                base: "1111111111111111111111111111111111111111".to_owned(),
                head: "2222222222222222222222222222222222222222".to_owned(),
                paths: vec![ChangedPath {
                    status: 'M',
                    path: path.to_owned(),
                }],
            },
        )
        .expect("write otherwise-valid source manifest");
        let error = validate_request(&ValidationRequest {
            trusted_root: trusted.path.clone(),
            candidate_root: candidate.path.clone(),
            changes,
            metadata_tools: local_metadata_tools(),
            actionlint: actionlint.clone(),
            isolation_root: artifacts.join("isolation"),
        })
        .expect_err("silent Bootstrap source change unexpectedly passed")
        .to_string();
        assert_eq!(
            error,
            format!(
                "Bootstrap source change requires synchronized snapshot/fingerprint or a new bound preservation decision: {path}"
            )
        );
    }
}

/// Twin of the residual test: the same otherwise-valid change on a standing-covered path must
/// reach `preserved` through the full stack, writing nothing inside the protected trust root.
///
/// The pair is what pins the boundary. Alone, neither test says where the line is.
#[test]
fn otherwise_valid_standing_covered_source_change_reaches_preserved_instead() {
    let Some(actionlint) = local_actionlint() else {
        eprintln!("ACTIONLINT_BIN is not set; hosted bootstrap requires and runs this test");
        return;
    };
    let trusted = final_tree("standing-preserved-trusted");
    let candidate = final_tree("standing-preserved-candidate");
    let root_manifest = candidate.join("Cargo.toml");
    let mut manifest_bytes = fs::read(&root_manifest).expect("read candidate root manifest");
    manifest_bytes.extend_from_slice(b"\n# otherwise-valid Bootstrap source change\n");
    fs::write(root_manifest, manifest_bytes).expect("write standing-covered source change");

    let trusted_root = SafeRoot::new(&trusted.path).expect("open trusted root");
    let candidate_root = SafeRoot::new(&candidate.path).expect("open candidate root");
    compare_trees(
        &trusted_root,
        &candidate_root,
        ".github/trusted/desktop-supply-chain-policy",
    )
    .expect("a standing-covered change writes nothing inside the protected trust root");

    let artifacts = TempTree::new("standing-preserved-artifacts");
    let changes = artifacts.join("changes.json");
    let manifest = ChangeManifest {
        base: "1111111111111111111111111111111111111111".to_owned(),
        head: "2222222222222222222222222222222222222222".to_owned(),
        paths: vec![ChangedPath {
            status: 'M',
            path: "Cargo.toml".to_owned(),
        }],
    };
    write_manifest(&changes, &manifest).expect("write standing-covered source manifest");
    validate_request(&ValidationRequest {
        trusted_root: trusted.path.clone(),
        candidate_root: candidate.path.clone(),
        changes,
        metadata_tools: local_metadata_tools(),
        actionlint,
        isolation_root: artifacts.join("isolation"),
    })
    .expect("standing-covered Bootstrap source change passes the complete authoritative stack");

    assert_eq!(
        validate_bootstrap_source_decisions(&trusted_root, &candidate_root, &manifest)
            .expect("standing preservation covers the changed Bootstrap source"),
        BootstrapSourceDecisionEvidence {
            changed_paths: 1,
            synchronized_paths: 0,
            preserved_paths: 1,
        }
    );
}

#[test]
fn live_tree_is_a_valid_bootstrap_or_final_policy_state() {
    let tree = copy_repo("live-policy-state");
    let root = SafeRoot::new(&tree.path).expect("open copied live repository");
    let identities = validate_inventory(&root).expect("validate live workflow inventory");
    assert_eq!(identities.len(), 8);
    assert!(identities.iter().any(|identity| {
        identity.path == AUTHORITATIVE_PATH
            && identity.workflow_name == AUTHORITATIVE_WORKFLOW_NAME
            && identity.jobs
                == [(
                    "trusted-desktop-supply-chain-policy".to_owned(),
                    AUTHORITATIVE_JOB_NAME.to_owned(),
                )]
    }));
    assert!(identities.iter().any(|identity| {
        identity.path == BOOTSTRAP_PATH
            && identity.workflow_name == BOOTSTRAP_WORKFLOW_NAME
            && identity.jobs
                == [(
                    "candidate-validator-bootstrap".to_owned(),
                    BOOTSTRAP_JOB_NAME.to_owned(),
                )]
    }));
    if is_bootstrap_state(&root).expect("classify live policy state") {
        assert_eq!(
            bootstrap_fingerprint(&root).expect("compute bootstrap fingerprint"),
            expected_bootstrap_fingerprint()
        );
    } else {
        validate_final_workflows(&root).expect("live final workflows");
        validate_final_static(&root).expect("live final static policy");
    }
}

#[test]
fn immutable_bootstrap_snapshot_matches_the_transition_fingerprint() {
    let tree = bootstrap_tree("immutable-bootstrap");
    let root = SafeRoot::new(&tree.path).expect("open immutable bootstrap fixture");
    validate_inventory(&root).expect("bootstrap workflow inventory");
    assert_eq!(
        bootstrap_fingerprint(&root).expect("compute immutable bootstrap fingerprint"),
        expected_bootstrap_fingerprint()
    );
    assert!(is_bootstrap_state(&root).expect("classify immutable bootstrap fixture"));
}

#[test]
fn immutable_bootstrap_snapshot_is_canonical_validator_output() {
    let tree = bootstrap_tree("canonical-bootstrap");
    let root = SafeRoot::new(&tree.path).expect("open immutable bootstrap fixture");
    let expected = bootstrap_snapshot(&root).expect("generate canonical Bootstrap snapshot");
    let actual = fs::read(
        repo_root().join(".github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"),
    )
    .expect("read committed Bootstrap snapshot");
    assert_eq!(actual, expected);
}

fn committed_bootstrap_snapshot() -> Vec<u8> {
    fs::read(
        repo_root().join(".github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"),
    )
    .expect("read committed Bootstrap snapshot")
}

#[test]
fn bootstrap_snapshot_writer_reports_an_exact_no_op() {
    let tree = bootstrap_tree("snapshot-writer-no-op");
    let output = tree.join("output.snapshot");
    fs::write(&output, committed_bootstrap_snapshot()).expect("seed existing snapshot");

    let delta = write_bootstrap_snapshot(
        &SafeRoot::new(&tree.path).expect("open Bootstrap materialization"),
        &output,
    )
    .expect("write no-op snapshot");

    assert_eq!(delta.changed_count(), 0);
    assert_eq!(delta.preserved_count(), 28);
    assert!(delta.changes().is_empty());
    assert_eq!(
        delta.to_string(),
        "bootstrap_snapshot_delta changed_count=0 preserved_count=28"
    );
}

#[test]
fn bootstrap_snapshot_writer_reports_one_reviewed_workflow_change() {
    let tree = bootstrap_tree("snapshot-writer-one-entry");
    let output = tree.join("output.snapshot");
    fs::write(&output, committed_bootstrap_snapshot()).expect("seed existing snapshot");
    let changed_path = ".github/workflows/upstream-gateway-reference.yml";
    let mut payload = fs::read(tree.join(changed_path)).expect("read reviewed workflow");
    payload.extend_from_slice(b"\n# reviewed replacement\n");
    fs::write(tree.join(changed_path), payload).expect("plant reviewed workflow replacement");

    let delta = write_bootstrap_snapshot(
        &SafeRoot::new(&tree.path).expect("open Bootstrap materialization"),
        &output,
    )
    .expect("write surgical snapshot");

    assert_eq!(delta.changed_count(), 1);
    assert_eq!(delta.preserved_count(), 27);
    assert_eq!(delta.changes()[0].path(), changed_path);
    assert_eq!(
        delta.changes()[0].status(),
        BootstrapSnapshotChangeStatus::Modified
    );
    assert_eq!(
        delta.to_string(),
        "bootstrap_snapshot_delta changed_count=1 preserved_count=27\nchanged_path=\".github/workflows/upstream-gateway-reference.yml\" status=modified"
    );
}

#[test]
fn bootstrap_snapshot_writer_cannot_hide_a_wholesale_rebaseline() {
    let tree = bootstrap_tree("snapshot-writer-rebaseline");
    let output = tree.join("output.snapshot");
    let committed = committed_bootstrap_snapshot();
    fs::write(&output, &committed).expect("seed existing snapshot");
    let archive =
        BootstrapSnapshotArchive::parse(&committed).expect("parse committed Bootstrap snapshot");
    for (path, _) in archive.entries() {
        let mut payload = fs::read(tree.join(path)).expect("read Bootstrap input");
        payload.extend_from_slice(b"\n# planted rebaseline\n");
        fs::write(tree.join(path), payload).expect("plant rebaseline input");
    }

    let delta = write_bootstrap_snapshot(
        &SafeRoot::new(&tree.path).expect("open Bootstrap materialization"),
        &output,
    )
    .expect("write rebaseline snapshot");

    assert_eq!(delta.changed_count(), 28);
    assert_eq!(delta.preserved_count(), 0);
    assert_eq!(delta.changes().len(), 28);
    assert!(
        delta
            .changes()
            .iter()
            .all(|change| change.status() == BootstrapSnapshotChangeStatus::Modified)
    );
}

#[test]
fn bootstrap_snapshot_writer_rejects_malformed_existing_archive_without_overwrite() {
    let tree = bootstrap_tree("snapshot-writer-malformed");
    let output = tree.join("output.snapshot");
    let malformed = b"GTABOOT1\x01\x00";
    fs::write(&output, malformed).expect("seed malformed snapshot");

    let error = write_bootstrap_snapshot(
        &SafeRoot::new(&tree.path).expect("open Bootstrap materialization"),
        &output,
    )
    .expect_err("malformed snapshot must fail closed");

    assert!(
        error
            .to_string()
            .contains("parse existing Bootstrap snapshot")
    );
    assert_eq!(
        fs::read(output).expect("read rejected malformed snapshot"),
        malformed
    );
}

#[test]
fn bootstrap_snapshot_writer_reports_inventory_additions_and_removals() {
    let tree = bootstrap_tree("snapshot-writer-inventory");
    let output = tree.join("output.snapshot");
    let mut existing = committed_bootstrap_snapshot();
    let expected = b".cargo/audit.toml";
    let planted = b".cargo/zudit.toml";
    let offset = existing
        .windows(expected.len())
        .position(|window| window == expected)
        .expect("find first Bootstrap path");
    existing[offset..offset + expected.len()].copy_from_slice(planted);
    BootstrapSnapshotArchive::parse(&existing).expect("planted inventory remains canonical");
    fs::write(&output, existing).expect("seed changed inventory");

    let delta = write_bootstrap_snapshot(
        &SafeRoot::new(&tree.path).expect("open Bootstrap materialization"),
        &output,
    )
    .expect("write changed inventory snapshot");

    assert_eq!(delta.changed_count(), 2);
    assert_eq!(delta.preserved_count(), 27);
    assert_eq!(delta.changes()[0].path(), ".cargo/audit.toml");
    assert_eq!(
        delta.changes()[0].status(),
        BootstrapSnapshotChangeStatus::Added
    );
    assert_eq!(delta.changes()[1].path(), ".cargo/zudit.toml");
    assert_eq!(
        delta.changes()[1].status(),
        BootstrapSnapshotChangeStatus::Removed
    );
}

#[test]
fn bootstrap_snapshot_writer_preserves_existing_archive_when_generation_fails() {
    let tree = bootstrap_tree("snapshot-writer-generation-failure");
    let output = tree.join("output.snapshot");
    let existing = committed_bootstrap_snapshot();
    fs::write(&output, &existing).expect("seed existing snapshot");
    fs::remove_file(tree.join("rustfmt.toml")).expect("remove one required input");

    write_bootstrap_snapshot(
        &SafeRoot::new(&tree.path).expect("open incomplete Bootstrap materialization"),
        &output,
    )
    .expect_err("missing input must fail generation");

    assert_eq!(
        fs::read(output).expect("read preserved existing snapshot"),
        existing
    );
}

#[test]
fn bootstrap_snapshot_writer_pins_first_write_semantics() {
    let tree = bootstrap_tree("snapshot-writer-first-write");
    let output = tree.join("first.snapshot");

    let delta = write_bootstrap_snapshot(
        &SafeRoot::new(&tree.path).expect("open Bootstrap materialization"),
        &output,
    )
    .expect("write first snapshot");

    assert_eq!(delta.changed_count(), 28);
    assert_eq!(delta.preserved_count(), 0);
    assert_eq!(delta.changes().len(), 28);
    assert!(
        delta
            .changes()
            .iter()
            .all(|change| change.status() == BootstrapSnapshotChangeStatus::Added)
    );
    assert_eq!(
        fs::read(output).expect("read first snapshot"),
        committed_bootstrap_snapshot()
    );
}

#[cfg(unix)]
#[test]
fn bootstrap_snapshot_writer_accepts_a_symlinked_output_directory() {
    use std::os::unix::fs::symlink;

    let tree = bootstrap_tree("snapshot-writer-symlinked-parent");
    let real_parent = tree.join("real-output");
    let linked_parent = tree.join("linked-output");
    fs::create_dir(&real_parent).expect("create real output directory");
    symlink(&real_parent, &linked_parent).expect("symlink output directory");
    let output = linked_parent.join("output.snapshot");

    let delta = write_bootstrap_snapshot(
        &SafeRoot::new(&tree.path).expect("open Bootstrap materialization"),
        &output,
    )
    .expect("write through symlinked output directory");

    assert_eq!(delta.changed_count(), 28);
    assert_eq!(
        fs::read(real_parent.join("output.snapshot")).expect("read canonical-parent output"),
        committed_bootstrap_snapshot()
    );
    assert_eq!(
        fs::read_dir(real_parent)
            .expect("list canonical output directory")
            .count(),
        1,
        "staged file must be renamed within the canonical output directory"
    );
}

#[cfg(unix)]
#[test]
fn bootstrap_snapshot_writer_rejects_an_existing_output_symlink() {
    use std::os::unix::fs::symlink;

    let tree = bootstrap_tree("snapshot-writer-symlinked-output");
    let target = tree.join("target.snapshot");
    let output = tree.join("output.snapshot");
    let sentinel = b"unchanged symlink target";
    fs::write(&target, sentinel).expect("write symlink target");
    symlink(&target, &output).expect("symlink existing output");

    let error = write_bootstrap_snapshot(
        &SafeRoot::new(&tree.path).expect("open Bootstrap materialization"),
        &output,
    )
    .expect_err("existing output symlink must fail closed");

    assert!(error.to_string().contains("symlink or reparse point"));
    assert!(
        fs::symlink_metadata(&output)
            .expect("inspect output symlink")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read(target).expect("read unchanged symlink target"),
        sentinel
    );
}

#[test]
fn authoritative_workflow_has_no_path_filter() {
    let workflow = fs::read_to_string(repo_root().join(AUTHORITATIVE_PATH))
        .expect("read authoritative workflow");
    let yaml: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&workflow).expect("parse authoritative workflow");
    let events = yaml
        .get("on")
        .and_then(|value| value.get("pull_request_target"))
        .and_then(serde_yaml_ng::Value::as_mapping)
        .expect("pull_request_target mapping");
    assert!(!events.contains_key(serde_yaml_ng::Value::String("paths".to_owned())));
    assert!(!events.contains_key(serde_yaml_ng::Value::String("paths-ignore".to_owned())));
    assert!(
        workflow.contains("BASE_REPOSITORY: ${{ github.event.pull_request.base.repo.full_name }}")
    );
    assert!(!workflow.contains("${{ github.event.pull_request.head.repo.full_name }}\""));
}

#[test]
fn authoritative_ruleset_workflow_queues_instead_of_cancelling() {
    let workflow = fs::read_to_string(repo_root().join(AUTHORITATIVE_PATH))
        .expect("read authoritative workflow");
    let yaml: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&workflow).expect("parse authoritative workflow");
    let concurrency = yaml
        .get("concurrency")
        .and_then(serde_yaml_ng::Value::as_mapping)
        .expect("authoritative concurrency mapping");
    assert_eq!(concurrency.len(), 1);
    assert_eq!(
        concurrency
            .get(serde_yaml_ng::Value::String("group".to_owned()))
            .and_then(serde_yaml_ng::Value::as_str),
        Some("trusted-desktop-policy-${{ github.event.pull_request.number }}")
    );
    assert!(
        !workflow.contains("cancel-in-progress"),
        "GitHub ruleset workflows must queue rather than cancel in-progress runs"
    );

    for value in ["true", "false", "\"${{ true }}\""] {
        let tree = copy_repo(&format!(
            "authoritative-cancellation-{}",
            value.replace(['$', '{', '}', '"'], "")
        ));
        replace(
            &tree.join(AUTHORITATIVE_PATH),
            "  group: trusted-desktop-policy-${{ github.event.pull_request.number }}\n",
            &format!(
                "  group: trusted-desktop-policy-${{{{ github.event.pull_request.number }}}}\n  cancel-in-progress: {value}\n"
            ),
        );
        assert!(
            validate_inventory(&SafeRoot::new(&tree.path).expect("open cancellation mutation"))
                .is_err(),
            "cancel-in-progress setting unexpectedly passed with value {value}"
        );
    }

    let job_scoped = copy_repo("authoritative-job-cancellation");
    replace(
        &job_scoped.join(AUTHORITATIVE_PATH),
        "    runs-on: ubuntu-24.04\n",
        "    runs-on: ubuntu-24.04\n    concurrency:\n      group: authoritative-job\n      cancel-in-progress: true\n",
    );
    assert!(
        validate_inventory(&SafeRoot::new(&job_scoped.path).expect("open job cancellation"))
            .is_err(),
        "job-scoped cancel-in-progress setting unexpectedly passed"
    );
}

#[test]
fn tagged_yaml_values_fail_closed_in_every_workflow_position() {
    validate_inventory(&SafeRoot::new(repo_root()).expect("open canonical workflows"))
        .expect("canonical workflows remain accepted");

    let cases = [
        (
            "job-concurrency",
            AUTHORITATIVE_PATH,
            "    runs-on: ubuntu-24.04\n",
            "    runs-on: ubuntu-24.04\n    concurrency: !job\n      group: authoritative-job\n      cancel-in-progress: true\n",
        ),
        (
            "workflow-root",
            AUTHORITATIVE_PATH,
            "name: GTA Claw authoritative desktop supply-chain policy\n",
            "--- !workflow\nname: GTA Claw authoritative desktop supply-chain policy\n",
        ),
        (
            "workflow-concurrency",
            AUTHORITATIVE_PATH,
            "concurrency:\n  group: trusted-desktop-policy-${{ github.event.pull_request.number }}\n",
            "concurrency: !workflow\n  group: trusted-desktop-policy-${{ github.event.pull_request.number }}\n  cancel-in-progress: true\n",
        ),
        (
            "nested-sequence-value",
            AUTHORITATIVE_PATH,
            "      - opened\n",
            "      - !activity opened\n",
        ),
        (
            "nested-mapping-key",
            AUTHORITATIVE_PATH,
            "          BASH_ENV: \"\"\n",
            "          !environment BASH_ENV: \"\"\n",
        ),
        (
            "nested-mapping-value",
            AUTHORITATIVE_PATH,
            "          ENV: \"\"\n",
            "          ENV: !empty \"\"\n",
        ),
        (
            "non-authoritative-workflow",
            BOOTSTRAP_PATH,
            "      - name: Checkout candidate validator\n",
            "      - !step\n        name: Checkout candidate validator\n",
        ),
    ];

    for (label, path, from, to) in cases {
        let tree = copy_repo(&format!("tagged-yaml-{label}"));
        replace(&tree.join(path), from, to);
        let error = validate_inventory(&SafeRoot::new(&tree.path).expect("open tagged workflow"))
            .expect_err("tagged workflow unexpectedly passed");
        assert!(
            error
                .to_string()
                .contains("tagged YAML values are forbidden"),
            "{label} failed for the wrong reason: {error}"
        );
    }
}

#[test]
fn dynamic_and_matrix_workflow_identities_cannot_spoof_reserved_checks() {
    validate_inventory(&SafeRoot::new(repo_root()).expect("open canonical workflow inventory"))
        .expect("audited dynamic job-name prefixes remain safe");
    let cases = [
        (
            "dynamic-workflow-name",
            ".github/workflows/rust.yml",
            "name: rust\n",
            "name: ${{ matrix.name }}\n",
        ),
        (
            "exact-expression-job-name",
            ".github/workflows/rust.yml",
            "    name: Headless (${{ matrix.os }})\n",
            "    name: ${{ matrix.name }}\n",
        ),
        (
            "reserved-prefix-job-name",
            ".github/workflows/rust.yml",
            "    name: Headless (${{ matrix.os }})\n",
            "    name: \"[AUTHORITATIVE] ${{ matrix.tail }}\"\n",
        ),
        (
            "reserved-suffix-job-name",
            ".github/workflows/rust.yml",
            "    name: Headless (${{ matrix.os }})\n",
            "    name: \"${{ matrix.head }} desktop supply-chain policy\"\n",
        ),
        (
            "reserved-matrix-value",
            ".github/workflows/rust.yml",
            "          - ubuntu-latest\n",
            "          - trusted_desktop_supply_chain_policy\n",
        ),
        (
            "dynamic-matrix-value",
            ".github/workflows/rust.yml",
            "          - ubuntu-latest\n",
            "          - \"${{ fromJSON('ubuntu-latest') }}\"\n",
        ),
        (
            "unnamed-split-matrix-identity",
            ".github/workflows/rust.yml",
            "  headless:\n    name: Headless (${{ matrix.os }})\n",
            "  trusted-desktop:\n",
        ),
        (
            "punctuated-reserved-workflow",
            ".github/workflows/rust.yml",
            "name: rust\n",
            "name: \"GTA-CLAW authoritative.desktop_supply chain POLICY\"\n",
        ),
    ];
    for (label, path, from, to) in cases {
        let tree = copy_repo(&format!("workflow-identity-{label}"));
        replace(&tree.join(path), from, to);
        assert!(
            validate_inventory(&SafeRoot::new(&tree.path).expect("open spoof workflow")).is_err(),
            "workflow identity spoof unexpectedly passed: {label}"
        );
    }

    let split = copy_repo("workflow-identity-unnamed-split-render");
    replace(
        &split.join(".github/workflows/rust.yml"),
        "  headless:\n    name: Headless (${{ matrix.os }})\n",
        "  trusted-desktop:\n",
    );
    replace(
        &split.join(".github/workflows/rust.yml"),
        "          - ubuntu-latest\n",
        "          - supply-chain-policy\n",
    );
    assert!(
        validate_inventory(&SafeRoot::new(&split.path).expect("open split matrix spoof")).is_err(),
        "unnamed matrix split reserved identity unexpectedly passed"
    );
}

fn mobile_workflow_stub(name: &str, job_id: &str, job_name: &str) -> String {
    format!(
        "name: \"{name}\"\n\
         \n\
         on:\n\
         \x20 pull_request:\n\
         \x20   branches:\n\
         \x20     - main\n\
         \n\
         permissions:\n\
         \x20 contents: read\n\
         \n\
         jobs:\n\
         \x20 {job_id}:\n\
         \x20   name: \"{job_name}\"\n\
         \x20   runs-on: ubuntu-latest\n\
         \x20   steps:\n\
         \x20     - name: Placeholder\n\
         \x20       run: echo packaging\n"
    )
}

#[test]
fn mobile_packaging_workflows_are_admitted_but_the_inventory_stays_closed() {
    let base = copy_repo("mobile-inventory-baseline");
    let identities = validate_inventory(&SafeRoot::new(&base.path).expect("open baseline tree"))
        .expect("the eight required workflows are a valid inventory");
    assert_eq!(identities.len(), 8);

    for (label, added) in [
        ("ios", &[".github/workflows/ios-packaging.yml"][..]),
        ("android", &[".github/workflows/android-packaging.yml"][..]),
        (
            "both",
            &[
                ".github/workflows/android-packaging.yml",
                ".github/workflows/ios-packaging.yml",
            ][..],
        ),
    ] {
        let tree = copy_repo(&format!("mobile-inventory-{label}"));
        for (index, path) in added.iter().enumerate() {
            fs::write(
                tree.join(path),
                mobile_workflow_stub(
                    &format!("mobile packaging {index}"),
                    &format!("package{index}"),
                    &format!("Mobile package {index}"),
                ),
            )
            .expect("write admitted mobile workflow");
        }
        let identities =
            validate_inventory(&SafeRoot::new(&tree.path).expect("open admitted mobile tree"))
                .expect("admitted mobile workflows pass the inventory");
        assert_eq!(identities.len(), 8 + added.len(), "{label}");
    }

    for (label, path) in [
        ("unknown-name", ".github/workflows/linux-mobile.yml"),
        (
            "near-miss-extension",
            ".github/workflows/ios-packaging.yaml",
        ),
        ("nested", ".github/workflows/mobile/ios-packaging.yml"),
    ] {
        let tree = copy_repo(&format!("mobile-inventory-{label}"));
        let destination = tree.join(path);
        fs::create_dir_all(destination.parent().expect("workflow parent"))
            .expect("create workflow parent");
        fs::write(
            &destination,
            mobile_workflow_stub("unadmitted packaging", "package", "Unadmitted package"),
        )
        .expect("write unadmitted workflow");
        let error =
            validate_inventory(&SafeRoot::new(&tree.path).expect("open unadmitted mobile tree"))
                .expect_err("unadmitted workflow unexpectedly passed the inventory");
        assert!(
            error
                .to_string()
                .contains("workflow directory inventory changed"),
            "{label} failed for the wrong reason: {error}"
        );
    }

    let removed = copy_repo("mobile-inventory-missing-required");
    fs::write(
        removed.join(".github/workflows/ios-packaging.yml"),
        mobile_workflow_stub("ios packaging", "package", "iOS package"),
    )
    .expect("write admitted iOS workflow");
    fs::remove_file(removed.join(".github/workflows/windows-packaging.yml"))
        .expect("remove required workflow");
    let error = validate_inventory(&SafeRoot::new(&removed.path).expect("open reduced tree"))
        .expect_err("missing required workflow unexpectedly passed the inventory");
    assert!(
        error
            .to_string()
            .contains("workflow directory inventory changed"),
        "removed required workflow failed for the wrong reason: {error}"
    );

    let spoof = copy_repo("mobile-inventory-spoof");
    fs::write(
        spoof.join(".github/workflows/android-packaging.yml"),
        mobile_workflow_stub("android packaging", "package", AUTHORITATIVE_JOB_NAME),
    )
    .expect("write spoofing admitted workflow");
    let error = validate_inventory(&SafeRoot::new(&spoof.path).expect("open spoofing tree"))
        .expect_err("admitted workflow spoofed the authoritative identity");
    assert!(
        error
            .to_string()
            .contains("authoritative workflow identity is spoofed"),
        "admitted spoof failed for the wrong reason: {error}"
    );
}

#[test]
fn authoritative_workflow_checkout_and_event_controls_are_exact() {
    let workflow = fs::read_to_string(repo_root().join(AUTHORITATIVE_PATH))
        .expect("read authoritative workflow");
    assert!(!workflow.contains("secrets."));
    assert!(!workflow.contains("permissions: write-all"));
    let yaml: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&workflow).expect("parse authoritative workflow");
    let permissions = yaml
        .get("permissions")
        .and_then(serde_yaml_ng::Value::as_mapping)
        .expect("permissions mapping");
    assert_eq!(permissions.len(), 1);
    assert_eq!(
        permissions
            .get(serde_yaml_ng::Value::String("contents".to_owned()))
            .and_then(serde_yaml_ng::Value::as_str),
        Some("read")
    );
    let job = yaml
        .get("jobs")
        .and_then(|jobs| jobs.get("trusted-desktop-supply-chain-policy"))
        .expect("authoritative job");
    assert!(job.get("if").is_none());
    assert_eq!(
        job.get("runs-on").and_then(serde_yaml_ng::Value::as_str),
        Some("ubuntu-24.04")
    );
    let steps = job
        .get("steps")
        .and_then(serde_yaml_ng::Value::as_sequence)
        .expect("authoritative steps");
    let checkout_steps = steps
        .iter()
        .filter(|step| {
            step.get("uses")
                .and_then(serde_yaml_ng::Value::as_str)
                .is_some_and(|action| action.starts_with("actions/checkout@"))
        })
        .collect::<Vec<_>>();
    assert_eq!(checkout_steps.len(), 2);
    assert!(!workflow.contains("fetch-depth: 0"));
    for (name, repository, reference, path, depth) in [
        (
            "Checkout exact protected base",
            "GTAStudio/GTA-Claw",
            "${{ github.event.pull_request.base.sha }}",
            "policy-checkouts/trusted",
            1_u64,
        ),
        (
            "Checkout exact immutable candidate",
            "${{ github.event.pull_request.head.repo.full_name }}",
            "${{ github.event.pull_request.head.sha }}",
            "policy-checkouts/candidate",
            u64::try_from(MAX_PULL_REQUEST_COMMITS + 1).expect("checkout depth fits u64"),
        ),
    ] {
        let checkout = checkout_steps
            .iter()
            .find(|step| step.get("name").and_then(serde_yaml_ng::Value::as_str) == Some(name))
            .unwrap_or_else(|| panic!("missing checkout step: {name}"));
        assert_eq!(
            checkout.get("uses").and_then(serde_yaml_ng::Value::as_str),
            Some("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
        );
        let inputs = checkout
            .get("with")
            .and_then(serde_yaml_ng::Value::as_mapping)
            .expect("checkout inputs");
        assert_eq!(inputs.len(), 11);
        for (key, expected) in [
            (
                "repository",
                serde_yaml_ng::Value::String(repository.to_owned()),
            ),
            ("ref", serde_yaml_ng::Value::String(reference.to_owned())),
            ("path", serde_yaml_ng::Value::String(path.to_owned())),
            ("fetch-depth", serde_yaml_ng::Value::Number(depth.into())),
            ("fetch-tags", serde_yaml_ng::Value::Bool(false)),
            ("persist-credentials", serde_yaml_ng::Value::Bool(false)),
            ("submodules", serde_yaml_ng::Value::Bool(false)),
            ("lfs", serde_yaml_ng::Value::Bool(false)),
            ("clean", serde_yaml_ng::Value::Bool(true)),
            ("set-safe-directory", serde_yaml_ng::Value::Bool(false)),
            ("show-progress", serde_yaml_ng::Value::Bool(false)),
        ] {
            assert_eq!(
                inputs.get(serde_yaml_ng::Value::String(key.to_owned())),
                Some(&expected),
                "checkout input changed: {key}"
            );
        }
    }
    for step in steps {
        if let Some(run) = step.get("run").and_then(serde_yaml_ng::Value::as_str) {
            assert!(
                !run.contains("github.event.pull_request"),
                "pull_request_target event data was interpolated into shell source"
            );
        }
        if let Some(action) = step.get("uses").and_then(serde_yaml_ng::Value::as_str) {
            assert!(
                !action.starts_with("./"),
                "candidate local action is forbidden"
            );
        }
    }
}

#[test]
fn validator_dependency_graph_has_only_reviewed_build_and_proc_targets() {
    let manifest = repo_root().join(".github/trusted/desktop-supply-chain-policy/Cargo.toml");
    let lock = fs::read_to_string(
        repo_root().join(".github/trusted/desktop-supply-chain-policy/Cargo.lock"),
    )
    .expect("read validator lock");
    let lock: toml::Value = toml::from_str(&lock).expect("parse validator lock");
    for package in lock
        .get("package")
        .and_then(toml::Value::as_array)
        .expect("validator lock packages")
    {
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .expect("locked package name");
        if name == "desktop-supply-chain-policy" {
            assert!(package.get("source").is_none());
        } else {
            assert_eq!(
                package.get("source").and_then(toml::Value::as_str),
                Some("registry+https://github.com/rust-lang/crates.io-index")
            );
            let checksum = package
                .get("checksum")
                .and_then(toml::Value::as_str)
                .expect("registry checksum");
            assert_eq!(checksum.len(), 64);
            assert!(checksum.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
    }

    let cargo = PathBuf::from(env::var_os("CARGO").expect("Cargo exposes CARGO"));
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--manifest-path",
            manifest.to_str().expect("manifest path UTF-8"),
            "--locked",
            "--format-version",
            "1",
        ])
        .output()
        .expect("run validator metadata");
    assert!(
        output.status.success(),
        "validator metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse validator metadata");
    let actual = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .expect("metadata packages")
        .iter()
        .flat_map(|package| {
            let name = package
                .get("name")
                .and_then(serde_json::Value::as_str)
                .expect("metadata package name");
            let version = package
                .get("version")
                .and_then(serde_json::Value::as_str)
                .expect("metadata package version");
            package
                .get("targets")
                .and_then(serde_json::Value::as_array)
                .expect("metadata targets")
                .iter()
                .flat_map(move |target| {
                    target
                        .get("kind")
                        .and_then(serde_json::Value::as_array)
                        .expect("target kinds")
                        .iter()
                        .filter_map(move |kind| {
                            let kind = kind.as_str()?;
                            matches!(kind, "custom-build" | "proc-macro")
                                .then(|| (name.to_owned(), version.to_owned(), kind.to_owned()))
                        })
                })
        })
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        (
            "libc".to_owned(),
            "0.2.186".to_owned(),
            "custom-build".to_owned(),
        ),
        (
            "proc-macro2".to_owned(),
            "1.0.106".to_owned(),
            "custom-build".to_owned(),
        ),
        (
            "quote".to_owned(),
            "1.0.46".to_owned(),
            "custom-build".to_owned(),
        ),
        (
            "serde".to_owned(),
            "1.0.228".to_owned(),
            "custom-build".to_owned(),
        ),
        (
            "serde_core".to_owned(),
            "1.0.228".to_owned(),
            "custom-build".to_owned(),
        ),
        (
            "serde_derive".to_owned(),
            "1.0.228".to_owned(),
            "proc-macro".to_owned(),
        ),
        (
            "serde_json".to_owned(),
            "1.0.149".to_owned(),
            "custom-build".to_owned(),
        ),
        (
            "zmij".to_owned(),
            "1.0.23".to_owned(),
            "custom-build".to_owned(),
        ),
    ]);
    assert_eq!(actual, expected);
}

#[test]
fn relevant_change_after_three_hundred_entries_is_not_omitted() {
    let mut paths = (0..350)
        .map(|index| ChangedPath {
            status: 'M',
            path: format!("docs/generated-{index:03}.txt"),
        })
        .collect::<Vec<_>>();
    paths.push(ChangedPath {
        status: 'M',
        path: "desktop/apps/gta-claw-desktop/Cargo.toml".to_owned(),
    });
    let manifest = ChangeManifest {
        base: "1111111111111111111111111111111111111111".to_owned(),
        head: "2222222222222222222222222222222222222222".to_owned(),
        paths,
    };
    assert!(has_policy_relevant_change(&manifest));
    assert!(!candidate_requires_final(BaseState::Bootstrap, false));
    assert!(candidate_requires_final(BaseState::Bootstrap, true));
    assert!(candidate_requires_final(BaseState::Final, false));
    assert!(candidate_requires_final(BaseState::Final, true));
}

#[test]
fn casefolded_policy_aliases_and_collisions_fail_on_every_host() {
    for paths in [
        vec![".cargo/Config.toml".to_owned()],
        vec!["desktop/cargo.toml".to_owned()],
        vec!["desktop/Cargo.loc\u{212a}".to_owned()],
        vec![".cargo/Conf\u{2139}g.toml".to_owned()],
        vec!["Desktop/Cargo.toml".to_owned()],
        vec![
            "crates/example/Cargo.toml".to_owned(),
            "crates/Example/Cargo.toml".to_owned(),
        ],
        vec![".GitHub/workflows/spoof.yml".to_owned()],
        vec!["CODEOWNERS".to_owned()],
        vec!["docs/CODEOWNERS".to_owned()],
        vec![".github/codeowners".to_owned()],
        vec![".github/CODEOWNER\u{212a}".to_owned()],
        vec![".github/CODEOWNERS.".to_owned()],
        vec![".github/CODEOWNERS ".to_owned()],
        vec![
            ".github/CODEOWNERS".to_owned(),
            ".github/CODEOWNERS".to_owned(),
        ],
        vec![
            "crates/example/src/caf\u{00e9}.rs".to_owned(),
            "crates/example/src/cafe\u{0301}.rs".to_owned(),
        ],
        vec![
            "docs/q\u{0307}\u{0323}.md".to_owned(),
            "docs/q\u{0323}\u{0307}.md".to_owned(),
        ],
        vec![
            "crates/example/src/\u{0394}elta.rs".to_owned(),
            "crates/example/src/\u{03b4}elta.rs".to_owned(),
        ],
        vec![
            "crates/example/src/\u{0130}.rs".to_owned(),
            "crates/example/src/i\u{0307}.rs".to_owned(),
        ],
        vec!["docs/\u{1e9e}.md".to_owned(), "docs/\u{00df}.md".to_owned()],
        vec![
            "docs/caf\u{00e9}/a.md".to_owned(),
            "docs/cafe\u{0301}/b.md".to_owned(),
        ],
        vec!["docs/evil\u{0007}.md".to_owned()],
        vec!["docs/evil\u{0085}.md".to_owned()],
        vec![
            "docs/strasse.md".to_owned(),
            "docs/stra\u{00df}e.md".to_owned(),
        ],
        vec!["docs/\u{03c3}.md".to_owned(), "docs/\u{03c2}.md".to_owned()],
        vec![
            "docs/source.rs".to_owned(),
            "docs/\u{017f}ource.rs".to_owned(),
        ],
        vec!["rust-toolchain".to_owned()],
        vec!["nested/rust-toolchain".to_owned()],
        vec!["nested/RUST-TOOLCHAIN".to_owned()],
        vec!["nested/ru\u{017f}t-toolchain".to_owned()],
        vec![".github/workflow\u{017f}/spoof.yml".to_owned()],
    ] {
        assert!(
            validate_casefold_paths(&paths).is_err(),
            "case-folded alias unexpectedly passed: {paths:?}"
        );
    }
    assert!(
        validate_casefold_paths(&[
            "Cargo.toml".to_owned(),
            "crates/example/Cargo.toml".to_owned(),
            "crates/example/src/\u{65e5}\u{672c}\u{8a9e}.rs".to_owned(),
            "crates/example/src/ma\u{00f1}ana.rs".to_owned(),
            "docs/guide-\u{2460}.md".to_owned(),
            "docs/guide-1.md".to_owned(),
        ])
        .is_ok()
    );
    assert!(!is_policy_relevant("docs/config"));
    assert!(!is_policy_relevant("docs/config.toml"));
    assert!(is_policy_relevant(".cargo/Config.toml"));
    assert!(is_policy_relevant("desktop/Cargo.loc\u{212a}"));
    assert!(is_policy_relevant(CODEOWNERS_PATH));
    assert!(is_policy_relevant("docs/CODEOWNERS"));
    assert!(is_policy_relevant(".github/CODEOWNER\u{212a}"));
    assert!(is_policy_relevant("nested/ru\u{017f}t-toolchain"));
    assert_eq!(
        canonical_caseless("Stra\u{00df}e"),
        canonical_caseless("STRASSE")
    );
    assert_eq!(
        canonical_caseless("\u{03a3}"),
        canonical_caseless("\u{03c2}")
    );
    assert_ne!(canonical_caseless("\u{2460}"), canonical_caseless("1"));
}

#[test]
fn canonical_codeowners_is_exact_and_does_not_freeze_root_growth() {
    let root = SafeRoot::new(repo_root()).expect("open live ownership tree");
    validate_codeowners(&root).expect("validate canonical CODEOWNERS");
    validate_codeowners_text(canonical_codeowners(), frozen_surfaces())
        .expect("canonical ownership covers every frozen surface");
    assert!(canonical_codeowners().lines().all(|line| {
        line.starts_with('#') || line.trim().is_empty() || line.ends_with(&format!(" {CODEOWNER}"))
    }));
    assert!(!canonical_codeowners().contains("\n/Cargo.toml "));
    assert!(!canonical_codeowners().contains("\n/Cargo.lock "));
    assert!(!canonical_codeowners().contains("/apps/**"));
    assert!(!canonical_codeowners().contains("/crates/**"));
    assert!(
        canonical_codeowners()
            .replace("\r\n", "\n")
            .contains("\nrust-toolchain @aizhihuxiao\n")
    );
}

#[test]
fn codeowners_deletion_widening_owner_and_surface_removal_fail() {
    let canonical = canonical_codeowners().replace("\r\n", "\n");
    let mutations = [
        canonical.replace(CODEOWNER, "@untrusted"),
        canonical.replace(
            "/desktop/Cargo.toml @aizhihuxiao",
            "/desktop/** @aizhihuxiao",
        ),
        canonical.replace("/desktop/Cargo.lock @aizhihuxiao\n", ""),
        format!("{canonical}\n/.github/** @aizhihuxiao\n",),
    ];
    for (index, mutation) in mutations.iter().enumerate() {
        let tree = copy_repo(&format!("codeowners-mutation-{index}"));
        fs::write(tree.join(CODEOWNERS_PATH), mutation).expect("write CODEOWNERS mutation");
        assert!(
            validate_codeowners(&SafeRoot::new(&tree.path).expect("open mutation")).is_err(),
            "CODEOWNERS mutation unexpectedly passed: {mutation}"
        );
    }

    let deleted = copy_repo("codeowners-deleted");
    fs::remove_file(deleted.join(CODEOWNERS_PATH)).expect("delete CODEOWNERS");
    assert!(validate_codeowners(&SafeRoot::new(&deleted.path).expect("open deletion")).is_err());

    let mut expanded = frozen_surfaces().to_vec();
    expanded.push("desktop/new-exact-policy.toml");
    assert!(
        validate_codeowners_text(canonical_codeowners(), &expanded).is_err(),
        "new frozen surface passed without canonical ownership"
    );
}

#[test]
fn alternate_codeowners_locations_fail_final_inventory() {
    let alternates = vec!["CODEOWNERS", "docs/CODEOWNERS"];
    #[cfg(not(windows))]
    let alternates = {
        let mut values = alternates;
        values.push(".github/codeowners");
        values
    };
    for alternate in alternates {
        let tree = final_tree(&format!("alternate-{}", alternate.replace('/', "-")));
        let path = tree.join(alternate);
        fs::create_dir_all(path.parent().unwrap_or(&tree.path))
            .expect("create alternate CODEOWNERS parent");
        fs::write(path, canonical_codeowners()).expect("write alternate CODEOWNERS");
        assert!(
            validate_final_static(&SafeRoot::new(&tree.path).expect("open alternate")).is_err(),
            "alternate CODEOWNERS unexpectedly passed: {alternate}"
        );
    }
}

#[test]
fn manifest_path_keys_cannot_bless_a_file_the_workspace_never_declared() {
    // The manifest inventory is derived from `[workspace] members` only. `path` is also
    // the source field of a dependency table, which is candidate-controlled, so a rule
    // that treated any manifest `path =` as authorising would let one line of TOML admit
    // an orphan crate. This pins both halves of that being closed.
    let orphan_manifest = "[package]\nname = \"claw-orphan\"\nversion = \"0.1.0\"\n\
         edition = \"2024\"\n\n[lints]\nworkspace = true\n";

    let tree = final_tree("manifest-path-orphan-undeclared");
    fs::create_dir_all(tree.join("crates/claw-orphan/src")).expect("create orphan crate");
    fs::write(tree.join("crates/claw-orphan/Cargo.toml"), orphan_manifest)
        .expect("write orphan manifest");
    fs::write(tree.join("crates/claw-orphan/src/lib.rs"), "").expect("write orphan source");
    let error = validate_final_static(&SafeRoot::new(&tree.path).expect("open orphan tree"))
        .expect_err("an undeclared crate manifest must not enter the inventory");
    // Mobile admission split this inventory into required and admitted halves, so an extra
    // manifest is now reported by the more precise unadmitted branch. It must still be the
    // inventory rule that rejects it, and it must name the orphan.
    let error = error.to_string();
    assert!(
        error.starts_with("Cargo.toml inventory")
            && error.contains("crates/claw-orphan/Cargo.toml"),
        "orphan manifest was rejected by an unrelated rule: {error}"
    );

    // Now point a workspace dependency at it, which is the "bless it with one line of
    // TOML" move. Measured: this is caught earlier still, by the dependency rule, because
    // a `path` dependency must resolve to an already-declared member. The inventory check
    // above is the independent backstop, so both halves are closed by separate rules.
    let tree = final_tree("manifest-path-orphan-blessed");
    fs::create_dir_all(tree.join("crates/claw-orphan/src")).expect("create orphan crate");
    fs::write(tree.join("crates/claw-orphan/Cargo.toml"), orphan_manifest)
        .expect("write orphan manifest");
    fs::write(tree.join("crates/claw-orphan/src/lib.rs"), "").expect("write orphan source");
    replace(
        &tree.join("Cargo.toml"),
        "[workspace.dependencies]\n",
        "[workspace.dependencies]\n\
         claw-orphan = { path = \"crates/claw-orphan\", version = \"0.1.0\" }\n",
    );
    let error = validate_final_static(&SafeRoot::new(&tree.path).expect("open blessed tree"))
        .expect_err("a dependency path must not admit an undeclared crate");
    assert_eq!(
        error.to_string(),
        "path dependency is not a declared root member: claw-orphan -> crates/claw-orphan"
    );
}

#[test]
fn complete_final_fixture_passes_static_policy() {
    let tree = final_tree("final-static");
    let root = SafeRoot::new(&tree.path).expect("open final fixture");
    validate_inventory(&root).expect("validate final workflow inventory");
    validate_final_workflows(&root).expect("validate exact final workflows");
    validate_final_static(&root).expect("validate final static policy");
}

#[test]
fn final_dependency_fixture_writer_is_canonical() {
    let tree = copy_repo("final-dependency-writer");
    let root = SafeRoot::new(&tree.path).expect("open Final dependency writer fixture");
    for fixture in [
        ".github/trusted/desktop-supply-chain-policy/policy/final/root-deny.toml.fixture",
        ".github/trusted/desktop-supply-chain-policy/policy/final/desktop/Cargo.toml.fixture",
        ".github/trusted/desktop-supply-chain-policy/policy/final/desktop/apps/gta-claw-desktop/Cargo.toml.fixture",
        ".github/trusted/desktop-supply-chain-policy/policy/final/desktop/Cargo.lock.fixture",
        ".github/trusted/desktop-supply-chain-policy/policy/final/desktop/deny.toml.fixture",
    ] {
        fs::write(tree.join(fixture), b"stale\n").expect("stale Final dependency fixture");
    }
    write_final_dependency_fixtures(&root).expect("write canonical Final dependency fixtures");
    for (live, fixture) in [
        (
            "deny.toml",
            ".github/trusted/desktop-supply-chain-policy/policy/final/root-deny.toml.fixture",
        ),
        (
            "desktop/Cargo.toml",
            ".github/trusted/desktop-supply-chain-policy/policy/final/desktop/Cargo.toml.fixture",
        ),
        (
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            ".github/trusted/desktop-supply-chain-policy/policy/final/desktop/apps/gta-claw-desktop/Cargo.toml.fixture",
        ),
        (
            "desktop/Cargo.lock",
            ".github/trusted/desktop-supply-chain-policy/policy/final/desktop/Cargo.lock.fixture",
        ),
        (
            "desktop/deny.toml",
            ".github/trusted/desktop-supply-chain-policy/policy/final/desktop/deny.toml.fixture",
        ),
    ] {
        assert_eq!(
            fs::read(tree.join(live)).expect("read live dependency artifact"),
            fs::read(tree.join(fixture)).expect("read Final dependency fixture"),
            "canonical writer diverged for {live}"
        );
    }
}

#[test]
fn final_root_deny_accepts_only_the_reviewed_bytes() {
    let canonical = final_tree("reviewed-root-deny");
    let canonical_text = fs::read_to_string(canonical.join("deny.toml"))
        .expect("read canonical root deny")
        .replace("\r\n", "\n");
    assert_eq!(sha256(canonical_text.as_bytes()), FINAL_ROOT_DENY_SHA256);
    validate_final_static(
        &SafeRoot::new(&canonical.path).expect("open reviewed root deny fixture"),
    )
    .expect("accept exact reviewed root deny");

    let bootstrap = bootstrap_tree("superseded-root-deny-source");
    let superseded_text = fs::read_to_string(bootstrap.join("deny.toml"))
        .expect("read immutable superseded root deny")
        .replace("\r\n", "\n")
        .replace("version = \"0.6.4\"", "version = \"=0.6.4\"")
        .replace("version = \"0.52.0\"", "version = \"=0.52.0\"");
    assert_eq!(
        sha256(superseded_text.as_bytes()),
        SUPERSEDED_ROOT_DENY_SHA256
    );
    let superseded = final_tree("superseded-root-deny");
    fs::write(superseded.join("deny.toml"), superseded_text).expect("write superseded root deny");
    assert_eq!(
        validate_final_static(
            &SafeRoot::new(&superseded.path).expect("open superseded root deny fixture")
        )
        .expect_err("superseded root deny unexpectedly passed")
        .to_string(),
        "exact security policy file changed: deny.toml"
    );

    for (label, from, to) in [
        ("wildcard-skip", "version = \"=0.10.9\"", "version = \"*\""),
        (
            "extra-skip",
            "[sources]",
            "[[bans.skip]]\nname = \"extra\"\nversion = \"=1.0.0\"\n\n[sources]",
        ),
        (
            "advisory-ignore",
            "ignore = []",
            "ignore = [\"RUSTSEC-0000-0000\"]",
        ),
    ] {
        let tree = final_tree(label);
        replace(&tree.join("deny.toml"), from, to);
        assert_eq!(
            validate_final_static(&SafeRoot::new(&tree.path).expect("open root deny mutation"))
                .expect_err("root deny drift unexpectedly passed")
                .to_string(),
            "exact security policy file changed: deny.toml",
            "root deny mutation escaped exact policy: {label}"
        );
    }
}

#[test]
fn sqlite_file_control_synthetic_setup_is_idempotent() {
    for (label, already_present) in [("member-absent", false), ("member-present", true)] {
        let tree = TempTree::new(label);
        let member_line = if already_present {
            format!("  \"{P03B_SQLITE_FILE_CONTROL_MEMBER}\",\n")
        } else {
            String::new()
        };
        fs::write(
            tree.join("Cargo.toml"),
            format!(
                "[workspace]\nmembers = [\n  \"apps/fixture\",\n{member_line}  \"crates/fixture\",\n]\n"
            ),
        )
        .expect("write synthetic root manifest");
        fs::write(
            tree.join("Cargo.lock"),
            if already_present {
                "version = 4\n\n[[package]]\nname = \"claw-sqlite-file-control\"\nversion = \"0.1.0\"\n"
            } else {
                "version = 4\n"
            },
        )
        .expect("write synthetic root lock");
        let manifest_path = tree
            .join(P03B_SQLITE_FILE_CONTROL_MEMBER)
            .join("Cargo.toml");
        if already_present {
            fs::create_dir_all(manifest_path.parent().expect("native-FFI member parent"))
                .expect("create native-FFI member");
            fs::write(
                &manifest_path,
                P03B_SQLITE_FILE_CONTROL_MANIFEST.replace('\n', "\r\n"),
            )
            .expect("write exact native-FFI member manifest");
        }
        let manifest_before = already_present
            .then(|| fs::read(&manifest_path).expect("read native-FFI manifest before setup"));

        if already_present {
            ensure_existing_root_member(
                &tree,
                P03B_SQLITE_FILE_CONTROL_MEMBER,
                P03B_SQLITE_FILE_CONTROL_MANIFEST,
            );
        } else {
            add_new_root_member(
                &tree,
                P03B_SQLITE_FILE_CONTROL_MEMBER,
                P03B_SQLITE_FILE_CONTROL_MANIFEST,
            );
        }
        ensure_existing_root_member(
            &tree,
            P03B_SQLITE_FILE_CONTROL_MEMBER,
            P03B_SQLITE_FILE_CONTROL_MANIFEST,
        );

        assert_eq!(
            fs::read_to_string(tree.join("Cargo.toml"))
                .expect("read synthetic root manifest after setup")
                .matches(P03B_SQLITE_FILE_CONTROL_MEMBER)
                .count(),
            1,
            "native-FFI member setup was not idempotent: {label}"
        );
        assert_eq!(
            fs::read_to_string(&manifest_path)
                .expect("read native-FFI member manifest after setup")
                .replace("\r\n", "\n"),
            P03B_SQLITE_FILE_CONTROL_MANIFEST
        );
        assert_eq!(
            fs::read_to_string(tree.join("Cargo.lock"))
                .expect("read synthetic root lock after setup")
                .matches("name = \"claw-sqlite-file-control\"")
                .count(),
            1,
            "native-FFI lock setup was not idempotent: {label}"
        );
        if already_present {
            assert_eq!(
                fs::read(&manifest_path).expect("read existing native-FFI manifest after setup"),
                manifest_before.expect("present manifest snapshot")
            );
        }
    }

    let noncanonical = P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(
        "futures-core = \"=0.3.32\"",
        "futures-core = \"=0.3.31\"",
        1,
    );
    let tree = final_tree("sqlite-file-control-noncanonical-input");
    add_new_root_member(
        &tree,
        P03B_SQLITE_FILE_CONTROL_MEMBER,
        P03B_SQLITE_FILE_CONTROL_MANIFEST,
    );
    ensure_existing_root_member(
        &tree,
        P03B_SQLITE_FILE_CONTROL_MEMBER,
        P03B_SQLITE_FILE_CONTROL_MANIFEST,
    );
    let rejection = std::panic::catch_unwind(|| {
        ensure_existing_root_member(&tree, P03B_SQLITE_FILE_CONTROL_MEMBER, &noncanonical);
    })
    .expect_err("noncanonical existing-member manifest unexpectedly passed");
    assert_eq!(
        panic_message(rejection.as_ref()),
        "existing native-FFI member must use the canonical manifest"
    );

    for (label, from, to) in [
        ("dependency-removed", "futures-core = \"=0.3.32\"\n", ""),
        (
            "version-drift",
            "futures-core = \"=0.3.32\"",
            "futures-core = \"=0.3.31\"",
        ),
        (
            "name-drift",
            "futures-core = \"=0.3.32\"",
            "futures-util = \"=0.3.32\"",
        ),
        (
            "broader-extra-dependency",
            "futures-core = \"=0.3.32\"\n",
            "futures-core = \"=0.3.32\"\nfutures-util = \"=0.3.32\"\n",
        ),
    ] {
        let drifted = P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(from, to, 1);
        assert_ne!(
            sha256(drifted.as_bytes()),
            P03B_SQLITE_FILE_CONTROL_MANIFEST_SHA256,
            "unauthorized helper manifest drift matched the reviewed digest: {label}"
        );
        let tree = final_tree(label);
        add_new_root_member(
            &tree,
            P03B_SQLITE_FILE_CONTROL_MEMBER,
            P03B_SQLITE_FILE_CONTROL_MANIFEST,
        );
        ensure_existing_root_member(
            &tree,
            P03B_SQLITE_FILE_CONTROL_MEMBER,
            P03B_SQLITE_FILE_CONTROL_MANIFEST,
        );
        fs::write(
            tree.join(P03B_SQLITE_FILE_CONTROL_MEMBER)
                .join("Cargo.toml"),
            drifted,
        )
        .expect("write unauthorized helper manifest drift");
        let rejection = std::panic::catch_unwind(|| {
            ensure_existing_root_member(
                &tree,
                P03B_SQLITE_FILE_CONTROL_MEMBER,
                P03B_SQLITE_FILE_CONTROL_MANIFEST,
            );
        })
        .expect_err("unauthorized helper manifest drift escaped the exact fixture");
        assert_eq!(
            panic_message(rejection.as_ref()),
            "existing native-FFI member manifest changed",
            "unauthorized helper manifest drift failed imprecisely: {label}"
        );
    }
}

#[test]
fn add_new_root_member_rejects_real_repository_collision() {
    let tree = copy_repo("root-member-collision");
    let member = "crates/claw-memory";
    let manifest = fs::read_to_string(tree.join(member).join("Cargo.toml"))
        .expect("read real root member manifest");
    let rejection = std::panic::catch_unwind(|| {
        add_new_root_member(&tree, member, &manifest);
    })
    .expect_err("real repository member unexpectedly accepted as a new fixture member");
    assert_eq!(
        panic_message(rejection.as_ref()),
        "fixture member `crates/claw-memory` now exists in the real repository; rename the fixture member - it must be a name no crate will ever take"
    );
}

#[test]
fn sqlite_file_control_native_ffi_lints_are_exactly_identity_bound() {
    assert_eq!(
        sha256(P03B_SQLITE_FILE_CONTROL_MANIFEST.as_bytes()),
        P03B_SQLITE_FILE_CONTROL_MANIFEST_SHA256
    );
    let accepted = final_tree("sqlite-file-control-lints");
    add_new_root_member(
        &accepted,
        P03B_SQLITE_FILE_CONTROL_MEMBER,
        P03B_SQLITE_FILE_CONTROL_MANIFEST,
    );
    ensure_existing_root_member(
        &accepted,
        P03B_SQLITE_FILE_CONTROL_MEMBER,
        P03B_SQLITE_FILE_CONTROL_MANIFEST,
    );
    let workspace = validate_final_static(
        &SafeRoot::new(&accepted.path).expect("open exact native-FFI member fixture"),
    )
    .expect("accept the exact reviewed native-FFI lint exception");
    assert_eq!(
        workspace
            .members
            .get("crates/claw-sqlite-file-control")
            .map(String::as_str),
        Some("claw-sqlite-file-control")
    );

    let cases = [
        (
            "sibling-path",
            "crates/claw-native-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(
                "name = \"claw-sqlite-file-control\"",
                "name = \"claw-native-control\"",
                1,
            ),
            "lints must inherit exactly from workspace",
        ),
        (
            "apps-path",
            "apps/claw-sqlite-file-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.to_owned(),
            "lints must inherit exactly from workspace",
        ),
        (
            "prefix-path",
            "crates/claw-sqlite-file-control-extra",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(
                "name = \"claw-sqlite-file-control\"",
                "name = \"claw-sqlite-file-control-extra\"",
                1,
            ),
            "lints must inherit exactly from workspace",
        ),
        (
            "package-alias",
            "crates/claw-sqlite-file-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(
                "name = \"claw-sqlite-file-control\"",
                "name = \"sqlite-file-control-alias\"",
                1,
            ),
            "package name must match its canonical directory",
        ),
        (
            "unsafe-level-drift",
            "crates/claw-sqlite-file-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(
                "unsafe_code = \"allow\"",
                "unsafe_code = \"warn\"",
                1,
            ),
            "audited native-FFI lint exception changed",
        ),
        (
            "missing-docs-weakened",
            "crates/claw-sqlite-file-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(
                "missing_docs = \"warn\"",
                "missing_docs = \"allow\"",
                1,
            ),
            "audited native-FFI lint exception changed",
        ),
        (
            "unsafe-op-weakened",
            "crates/claw-sqlite-file-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(
                "unsafe_op_in_unsafe_fn = \"deny\"",
                "unsafe_op_in_unsafe_fn = \"allow\"",
                1,
            ),
            "audited native-FFI lint exception changed",
        ),
        (
            "additional-allow",
            "crates/claw-sqlite-file-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(
                "unsafe_code = \"allow\"",
                "unsafe_code = \"allow\"\nunused_variables = \"allow\"",
                1,
            ),
            "audited native-FFI lint exception changed",
        ),
        (
            "renamed-lint",
            "crates/claw-sqlite-file-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen(
                "unsafe_op_in_unsafe_fn",
                "unsafe_op_in_unsafe_block",
                1,
            ),
            "audited native-FFI lint exception changed",
        ),
        (
            "missing-rust-warning",
            "crates/claw-sqlite-file-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen("missing_docs = \"warn\"\n", "", 1),
            "audited native-FFI lint exception changed",
        ),
        (
            "missing-clippy-warning",
            "crates/claw-sqlite-file-control",
            P03B_SQLITE_FILE_CONTROL_MANIFEST.replacen("all = \"warn\"\n", "", 1),
            "audited native-FFI lint exception changed",
        ),
    ];
    for (label, member, manifest, expected) in cases {
        let tree = final_tree(label);
        if member == P03B_SQLITE_FILE_CONTROL_MEMBER {
            add_new_root_member(
                &tree,
                P03B_SQLITE_FILE_CONTROL_MEMBER,
                P03B_SQLITE_FILE_CONTROL_MANIFEST,
            );
            ensure_existing_root_member(
                &tree,
                P03B_SQLITE_FILE_CONTROL_MEMBER,
                P03B_SQLITE_FILE_CONTROL_MANIFEST,
            );
            fs::write(tree.join(member).join("Cargo.toml"), manifest)
                .expect("write native-FFI manifest mutation");
        } else {
            add_new_root_member(&tree, member, &manifest);
        }
        let error =
            validate_final_static(&SafeRoot::new(&tree.path).expect("open lint mutation fixture"))
                .expect_err("unauthorized local lint policy unexpectedly passed")
                .to_string();
        assert!(
            error.contains(expected),
            "lint mutation failed through the wrong rule: {label}: {error}"
        );
    }

    for mutation in ["duplicate", "unsorted"] {
        let tree = final_tree(&format!("sqlite-file-control-{mutation}"));
        add_new_root_member(
            &tree,
            P03B_SQLITE_FILE_CONTROL_MEMBER,
            P03B_SQLITE_FILE_CONTROL_MANIFEST,
        );
        ensure_existing_root_member(
            &tree,
            P03B_SQLITE_FILE_CONTROL_MEMBER,
            P03B_SQLITE_FILE_CONTROL_MANIFEST,
        );
        let root_manifest_path = tree.join("Cargo.toml");
        let mut root_manifest: toml::Value = toml::from_str(
            &fs::read_to_string(&root_manifest_path).expect("read root member mutation manifest"),
        )
        .expect("parse root member mutation manifest");
        let members = root_manifest
            .get_mut("workspace")
            .and_then(|workspace| workspace.get_mut("members"))
            .and_then(toml::Value::as_array_mut)
            .expect("root workspace member array");
        match mutation {
            "duplicate" => {
                let position = members
                    .iter()
                    .position(|member| member.as_str() == Some(P03B_SQLITE_FILE_CONTROL_MEMBER))
                    .expect("exact native-FFI member");
                members.insert(
                    position,
                    toml::Value::String(P03B_SQLITE_FILE_CONTROL_MEMBER.to_owned()),
                );
            }
            "unsorted" => members.swap(0, 1),
            _ => unreachable!(),
        }
        fs::write(
            root_manifest_path,
            toml::to_string(&root_manifest).expect("serialize root member mutation manifest"),
        )
        .expect("write root member mutation manifest");
        assert_eq!(
            validate_final_static(
                &SafeRoot::new(&tree.path).expect("open root member mutation fixture")
            )
            .expect_err("malicious root member mutation unexpectedly passed")
            .to_string(),
            "root workspace members must be unique and sorted",
            "root member mutation failed through the wrong rule: {mutation}"
        );
    }
}

#[test]
fn superseded_final_and_dependency_surface_mutations_are_rejected() {
    let canonical = final_tree("dependency-transition-canonical");
    let paths = [
        "desktop/Cargo.toml",
        "desktop/apps/gta-claw-desktop/Cargo.toml",
        "desktop/Cargo.lock",
    ];
    for (path, superseded) in paths.iter().zip(SUPERSEDED_FINAL_DEPENDENCY_SHA256) {
        let current = sha256(&fs::read(canonical.join(path)).expect("read canonical dependency"));
        assert_ne!(
            current, superseded,
            "canonical Final retained superseded bytes: {path}"
        );
    }

    let superseded_desktop = final_tree("superseded-desktop-manifest");
    let mut desktop = fs::read_to_string(superseded_desktop.join("desktop/Cargo.toml"))
        .expect("read canonical desktop manifest")
        .replace("\r\n", "\n");
    for addition in [
        "claw-gateway-client = { path = \"../crates/claw-gateway-client\", version = \"0.1.0\" }\n",
        "claw-protocol = { path = \"../crates/claw-protocol\", version = \"0.1.0\" }\n",
        "claw-security = { path = \"../crates/claw-security\", version = \"0.1.0\" }\n",
    ] {
        desktop = desktop.replacen(addition, "", 1);
    }
    assert_eq!(
        sha256(desktop.as_bytes()),
        SUPERSEDED_FINAL_DEPENDENCY_SHA256[0]
    );
    fs::write(superseded_desktop.join("desktop/Cargo.toml"), desktop)
        .expect("write superseded desktop manifest");
    assert_eq!(
        validate_final_static(
            &SafeRoot::new(&superseded_desktop.path).expect("open superseded desktop manifest")
        )
        .expect_err("superseded desktop manifest unexpectedly passed")
        .to_string(),
        "exact security policy file changed: desktop/Cargo.toml"
    );

    let superseded_app = final_tree("superseded-app-manifest");
    let mut app =
        fs::read_to_string(superseded_app.join("desktop/apps/gta-claw-desktop/Cargo.toml"))
            .expect("read canonical app manifest")
            .replace("\r\n", "\n");
    for addition in [
        "claw-gateway-client.workspace = true\n",
        "claw-protocol.workspace = true\n",
        "claw-security.workspace = true\n",
        "getrandom = { version = \"=0.4.3\", features = [\"sys_rng\"] }\n",
        "secrecy = \"=0.10.3\"\n",
        "serde_json = { version = \"=1.0.150\", features = [\"raw_value\"] }\n",
        "tokio = { version = \"=1.52.3\", features = [\"io-util\", \"macros\", \"net\", \"rt-multi-thread\", \"sync\", \"time\"] }\n",
        "tokio-util = { version = \"=0.7.18\", features = [\"rt\"] }\n",
        "url = \"=2.5.8\"\n",
        "\n[target.'cfg(any(target_os = \"windows\", target_os = \"macos\"))'.dev-dependencies]\nbase64 = \"=0.22.1\"\nfastwebsockets = { version = \"=0.10.0\", default-features = false }\nhttparse = \"=1.10.1\"\nsha1 = \"=0.11.0\"\n",
    ] {
        app = app.replacen(addition, "", 1);
    }
    assert_eq!(
        sha256(app.as_bytes()),
        SUPERSEDED_FINAL_DEPENDENCY_SHA256[1]
    );
    fs::write(
        superseded_app.join("desktop/apps/gta-claw-desktop/Cargo.toml"),
        app,
    )
    .expect("write superseded app manifest");
    assert_eq!(
        validate_final_static(
            &SafeRoot::new(&superseded_app.path).expect("open superseded app manifest")
        )
        .expect_err("superseded app manifest unexpectedly passed")
        .to_string(),
        "exact security policy file changed: desktop/apps/gta-claw-desktop/Cargo.toml"
    );

    for (label, file, from, to) in [
        (
            "gateway-registry",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "claw-gateway-client.workspace = true",
            "claw-gateway-client = \"=0.1.0\"",
        ),
        (
            "security-path",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "claw-security.workspace = true",
            "claw-security = { path = \"../../../../crates/claw-security\" }",
        ),
        (
            "tokio-extra-feature",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "\"sync\", \"time\"]",
            "\"sync\", \"time\", \"tracing\"]",
        ),
        (
            "extra-dependency",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "url = \"=2.5.8\"",
            "url = \"=2.5.8\"\nzeroize = \"=1.9.0\"",
        ),
        (
            "dependency-alias",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "claw-security.workspace = true",
            "security-alias = { package = \"claw-security\", workspace = true }",
        ),
        (
            "linux-slint",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "[lints]",
            "[target.'cfg(target_os = \"linux\")'.dependencies]\nslint = \"=1.17.1\"\n\n[lints]",
        ),
    ] {
        let tree = final_tree(label);
        replace(&tree.join(file), from, to);
        assert!(
            validate_final_static(&SafeRoot::new(&tree.path).expect("open dependency mutation"))
                .is_err(),
            "dependency surface mutation unexpectedly passed: {label}"
        );
    }

    for package in [
        "extra-audit-lock",
        "quick-xml",
        "wayland-client",
        "smithay-client-toolkit",
    ] {
        let tree = final_tree(&format!("lock-{package}"));
        let mut lock = fs::read_to_string(tree.join("desktop/Cargo.lock"))
            .expect("read canonical desktop lock");
        lock.push_str(&format!(
            "\n[[package]]\nname = \"{package}\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"0000000000000000000000000000000000000000000000000000000000000000\"\n"
        ));
        fs::write(tree.join("desktop/Cargo.lock"), lock).expect("write desktop lock mutation");
        assert_eq!(
            validate_final_static(&SafeRoot::new(&tree.path).expect("open lock mutation"))
                .expect_err("desktop lock mutation unexpectedly passed")
                .to_string(),
            "exact security policy file changed: desktop/Cargo.lock",
            "desktop lock mutation failed through the wrong rule: {package}"
        );
    }
}

#[test]
fn root_gui_family_aliases_and_lock_packages_fail_closed() {
    for (label, dependency) in [
        ("gtk4-direct", "gtk4-helper = \"=1.0.0\"\n"),
        (
            "gdk4-renamed",
            "friendly-ui = { package = \"gdk4-sys\", version = \"=1.0.0\" }\n",
        ),
        (
            "gsk4-renamed",
            "friendly-ui = { package = \"GSK4_helper\", version = \"=1.0.0\" }\n",
        ),
        (
            "invalid-package-type",
            "friendly-ui = { package = 4, version = \"=1.0.0\" }\n",
        ),
    ] {
        let tree = final_tree(&format!("root-gui-{label}"));
        replace(
            &tree.join("Cargo.toml"),
            "serde = { version = \"=1.0.228\", features = [\"derive\"] }\n",
            &format!("serde = {{ version = \"=1.0.228\", features = [\"derive\"] }}\n{dependency}"),
        );
        assert!(
            validate_final_static(&SafeRoot::new(&tree.path).expect("open GUI mutation")).is_err(),
            "root GUI dependency mutation unexpectedly passed: {label}"
        );
    }

    let lock = final_tree("root-gui-lock");
    let mut lock_text = fs::read_to_string(lock.join("Cargo.lock")).expect("read root lock");
    lock_text.push_str(
        "\n[[package]]\nname = \"gsk4-sys\"\nversion = \"0.1.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
    );
    fs::write(lock.join("Cargo.lock"), lock_text).expect("write GUI lock mutation");
    assert!(
        validate_final_static(&SafeRoot::new(&lock.path).expect("open GUI lock mutation")).is_err(),
        "transitive GTK4-family lock package unexpectedly passed"
    );

    let positive = final_tree("root-gui-positive");
    replace(
        &positive.join("Cargo.toml"),
        "serde = { version = \"=1.0.228\", features = [\"derive\"] }\n",
        "serde = { version = \"=1.0.228\", features = [\"derive\"] }\ntoolkit-helper = { package = \"serde\", version = \"=1.0.228\" }\n",
    );
    validate_final_static(&SafeRoot::new(&positive.path).expect("open GUI positive"))
        .expect("unrelated dependency name remains accepted");
}

#[test]
fn executable_security_fixtures_require_raw_lf_bytes() {
    let fixture_root = repo_root().join(".github/trusted/desktop-supply-chain-policy/policy/final");
    for path in [
        ".github/fixtures/security-tools/bash-env-poison.sh",
        ".github/fixtures/security-tools/shadow-bin/sha256sum",
        ".github/fixtures/security-tools/shadow-bin/tar",
    ] {
        let bytes = fs::read(fixture_root.join(path)).expect("read LF security fixture");
        assert!(
            !bytes.contains(&b'\r'),
            "security fixture contains CR: {path}"
        );
        assert_eq!(bytes.last(), Some(&b'\n'));

        let tree = final_tree(&format!(
            "security-crlf-{}",
            path.rsplit('/').next().expect("fixture basename")
        ));
        let crlf = String::from_utf8(bytes)
            .expect("security fixture is UTF-8")
            .replace('\n', "\r\n");
        fs::write(tree.join(path), crlf).expect("write CRLF security mutation");
        assert!(
            validate_final_static(&SafeRoot::new(&tree.path).expect("open CRLF mutation")).is_err(),
            "CRLF security fixture unexpectedly passed: {path}"
        );
    }

    #[cfg(unix)]
    for path in [
        ".github/fixtures/security-tools/shadow-bin/sha256sum",
        ".github/fixtures/security-tools/shadow-bin/tar",
    ] {
        use std::os::unix::fs::PermissionsExt as _;
        let tree = final_tree(&format!(
            "security-mode-{}",
            path.rsplit('/').next().expect("fixture basename")
        ));
        let file = tree.join(path);
        let mut permissions = fs::metadata(&file)
            .expect("inspect shadow fixture")
            .permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(file, permissions).expect("remove shadow executable mode");
        assert!(
            validate_final_static(&SafeRoot::new(&tree.path).expect("open mode mutation")).is_err(),
            "non-executable shadow tool unexpectedly passed: {path}"
        );
    }
}

#[test]
fn protected_macos_release_version_uses_locked_offline_metadata() {
    let mut policy_runs = Vec::new();
    for path in [
        ".github/workflows/macos-packaging.yml",
        ".github/trusted/desktop-supply-chain-policy/policy/final/.github/workflows/macos-packaging.yml",
    ] {
        let workflow = fs::read_to_string(repo_root().join(path)).expect("read macOS workflow");
        let yaml: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&workflow).expect("parse macOS workflow");
        let run = yaml
            .get("jobs")
            .and_then(|jobs| jobs.get("release-policy"))
            .and_then(|job| job.get("steps"))
            .and_then(serde_yaml_ng::Value::as_sequence)
            .and_then(|steps| {
                steps.iter().find(|step| {
                    step.get("name").and_then(serde_yaml_ng::Value::as_str)
                        == Some("Enforce protected main and semantic tag policy")
                })
            })
            .and_then(|step| step.get("run"))
            .and_then(serde_yaml_ng::Value::as_str)
            .expect("release policy script");
        assert!(!run.contains(r#"$1 == "version""#));
        for required in [
            ".github/trusted/desktop-supply-chain-policy/scripts/release-metadata-version.sh",
            "/bin/bash \"$metadata_script\"",
            "\"$cargo_bin\"",
            "\"$rustc_bin\"",
            "\"$GITHUB_WORKSPACE\"",
            "\"$version\"",
            "\"$REQUESTED_VERSION\"",
        ] {
            assert!(
                run.contains(required),
                "release metadata policy is missing {required:?} in {path}"
            );
        }
        policy_runs.push(run.to_owned());
    }
    assert_eq!(
        policy_runs[0], policy_runs[1],
        "live and protected final release policies diverged"
    );
    let script =
        fs::read_to_string(repo_root().join(
            ".github/trusted/desktop-supply-chain-policy/scripts/release-metadata-version.sh",
        ))
        .expect("read trusted release metadata script");
    for required in [
        "--locked",
        "--offline",
        "--no-deps",
        "--format-version 1",
        "CARGO_NET_OFFLINE=true",
        "workspace_members is invalid or duplicated",
        "workspace packages do not have one exact version",
        "root_version\" == \"$desktop_version",
        "root_version\" == \"$tag_version",
    ] {
        assert!(
            script.contains(required),
            "trusted release metadata script is missing {required:?}"
        );
    }
    assert!(!script.contains("python"));
}

#[test]
fn protected_macos_signing_binds_one_exact_bundle_executable() {
    let verifier = fs::read_to_string(
        repo_root().join(".github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh"),
    )
    .expect("read trusted macOS verifier");
    for required in [
        "/usr/bin/cmp -s",
        "CFBundleExecutable raw -expect string",
        "/usr/bin/printf 'gta-claw-desktop\\n'",
        "-mindepth 1 -maxdepth 1 -print0",
        "\"${#entries[@]}\" -eq 1",
        "-f \"$executable\" && ! -L \"$executable\" && -x \"$executable\"",
    ] {
        assert!(
            verifier.contains(required),
            "trusted macOS verifier is missing {required:?}"
        );
    }

    let mut protected_jobs = Vec::new();
    for path in [
        ".github/workflows/macos-packaging.yml",
        ".github/trusted/desktop-supply-chain-policy/policy/final/.github/workflows/macos-packaging.yml",
    ] {
        let workflow = fs::read_to_string(repo_root().join(path)).expect("read macOS workflow");
        assert!(
            workflow.matches("/bin/bash \"$verifier\"").count() >= 8,
            "macOS release boundaries are not all verified in {path}"
        );
        assert!(workflow.contains("dependencies=\"$(otool -L \"$binary\")\" || {"));
        assert!(workflow.contains("load_commands=\"$(otool -l \"$binary\")\" || {"));
        assert!(!workflow.contains("if otool -L \"$binary\" |"));
        assert!(!workflow.contains("if otool -l \"$binary\" |"));
        assert!(workflow.contains(
            "sparse-checkout: .github/trusted/desktop-supply-chain-policy/scripts/verify-macos-app.sh"
        ));
        let yaml: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&workflow).expect("parse macOS workflow");
        protected_jobs.push(
            yaml.get("jobs")
                .and_then(|jobs| jobs.get("protected-release-contract"))
                .cloned()
                .expect("protected release job"),
        );
    }
    assert_eq!(
        protected_jobs[0], protected_jobs[1],
        "live and protected Final signing contracts diverged"
    );
}

#[test]
fn release_metadata_version_is_format_independent_and_requires_agreement() {
    let fixture = TempTree::new("release-metadata");
    let tools = local_metadata_tools();
    let root_manifest = write_release_workspace(&fixture.path, "root", "1.2.3", true, None);
    let desktop_manifest =
        write_release_workspace(&fixture.join("desktop"), "desktop", "1.2.3", false, None);
    let root =
        run_release_metadata_fixture(&tools, &root_manifest, &fixture.join("root-isolation"));
    let desktop = run_release_metadata_fixture(
        &tools,
        &desktop_manifest,
        &fixture.join("desktop-isolation"),
    );
    assert!(
        root.status.success(),
        "formatted root metadata failed: {}",
        String::from_utf8_lossy(&root.stderr)
    );
    assert!(
        desktop.status.success(),
        "desktop metadata failed: {}",
        String::from_utf8_lossy(&desktop.stderr)
    );
    assert_eq!(
        release_version_from_metadata_documents(&root.stdout, &desktop.stdout)
            .expect("formatted metadata versions agree"),
        "1.2.3"
    );
    let mut duplicated: serde_json::Value =
        serde_json::from_slice(&root.stdout).expect("parse root metadata for duplicate mutation");
    let first_member = duplicated["workspace_members"][0].clone();
    duplicated["workspace_members"]
        .as_array_mut()
        .expect("workspace_members array")
        .push(first_member);
    assert!(
        release_version_from_metadata_documents(
            &serde_json::to_vec(&duplicated).expect("serialize duplicate metadata"),
            &desktop.stdout,
        )
        .is_err(),
        "duplicate workspace member unexpectedly passed"
    );

    #[cfg(not(windows))]
    {
        let script = repo_root().join(
            ".github/trusted/desktop-supply-chain-policy/scripts/release-metadata-version.sh",
        );
        let script_isolation = fixture.join("exact-script-isolation");
        let output = Command::new("/bin/bash")
            .arg(script)
            .args([
                tools.cargo.as_os_str(),
                tools.rustc.as_os_str(),
                fixture.path.as_os_str(),
                script_isolation.as_os_str(),
                std::ffi::OsStr::new("1.2.3"),
                std::ffi::OsStr::new("1.2.3"),
            ])
            .env_clear()
            .output()
            .expect("run exact release metadata script");
        assert!(
            output.status.success(),
            "exact release metadata script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"1.2.3\n");
    }

    let disagreement_manifest = write_release_workspace(
        &fixture.join("disagreement"),
        "disagreement",
        "1.2.4",
        false,
        None,
    );
    let disagreement = run_release_metadata_fixture(
        &tools,
        &disagreement_manifest,
        &fixture.join("disagreement-isolation"),
    );
    assert!(disagreement.status.success());
    assert!(
        release_version_from_metadata_documents(&root.stdout, &disagreement.stdout).is_err(),
        "root/desktop release version disagreement unexpectedly passed"
    );

    let multiple_manifest = write_release_workspace(
        &fixture.join("multiple"),
        "multiple",
        "1.2.3",
        false,
        Some("1.2.4"),
    );
    let multiple = run_release_metadata_fixture(
        &tools,
        &multiple_manifest,
        &fixture.join("multiple-isolation"),
    );
    assert!(
        multiple.status.success(),
        "multiple-version metadata command failed before semantic validation: {}",
        String::from_utf8_lossy(&multiple.stderr)
    );
    assert!(
        release_version_from_metadata_documents(&multiple.stdout, &desktop.stdout).is_err(),
        "multiple workspace package versions unexpectedly passed"
    );

    fs::write(
        &root_manifest,
        "[workspace]\nmembers = [\"member\"]\n[workspace.package]\nversion = [\n",
    )
    .expect("write malformed release manifest");
    let malformed =
        run_release_metadata_fixture(&tools, &root_manifest, &fixture.join("malformed-isolation"));
    assert!(
        !malformed.status.success(),
        "malformed Cargo metadata manifest unexpectedly passed"
    );
}

#[test]
fn compliant_declared_root_member_and_lock_evolution_pass() {
    let tree = final_tree("root-growth");
    let jjj_manifest = r#"[package]
name = "claw-jjj-root-growth-fixture"
description = "Compliant future root crate in the h through n range"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true
"#;
    let kkk_manifest = r#"[package]
name = "claw-kkk-root-growth-fixture"
description = "Compliant future root crate"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true
"#;
    add_new_root_member(&tree, "crates/claw-jjj-root-growth-fixture", jjj_manifest);
    add_new_root_member(&tree, "crates/claw-kkk-root-growth-fixture", kkk_manifest);

    let root = SafeRoot::new(&tree.path).expect("open evolved fixture");
    let workspace = validate_final_static(&root).expect("accept compliant root growth");
    assert_eq!(
        workspace
            .members
            .get("crates/claw-jjj-root-growth-fixture")
            .map(String::as_str),
        Some("claw-jjj-root-growth-fixture"),
        "a pre-existing h through n member must not invalidate ordinal insertion"
    );
    assert_eq!(
        workspace
            .members
            .get("crates/claw-kkk-root-growth-fixture")
            .map(String::as_str),
        Some("claw-kkk-root-growth-fixture")
    );
    let isolation = TempTree::new("root-growth-metadata");
    validate_root_metadata(&root, &workspace, &local_metadata_tools(), &isolation.path)
        .expect("Cargo accepts compliant declared root member and lock evolution");

    replace(
        &tree.join("deny.toml"),
        "ignore = []",
        "ignore = [\"RUSTSEC-0000-0000\"]",
    );
    assert_eq!(
        validate_final_static(&root)
            .expect_err("root deny policy violation unexpectedly passed after compliant growth")
            .to_string(),
        "exact security policy file changed: deny.toml"
    );
}

#[test]
fn git_tree_inventory_rejects_symlinks_and_gitlinks() {
    let regular = b"100644 blob aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tREADME.md\0\
100755 blob bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\tdeploy/run.sh\0";
    validate_tree_entries(regular, "fixture").expect("accept regular tracked files");

    for (mode, kind, expected) in [
        ("120000", "blob", "tracked symbolic link"),
        ("160000", "commit", "tracked gitlink"),
    ] {
        let fixture =
            format!("{mode} {kind} cccccccccccccccccccccccccccccccccccccccc\tvendor/runtime\0");
        let error = validate_tree_entries(fixture.as_bytes(), "fixture")
            .expect_err("tracked indirection unexpectedly passed")
            .to_string();
        assert!(
            error.contains(expected),
            "tracked mode failed through the wrong rule: {error}"
        );
    }
}

#[test]
fn base_owned_repository_ratchet_rejects_addition_and_allows_deletion() {
    let trusted = final_tree("repository-ratchet-base");
    let candidate = final_tree("repository-ratchet-candidate");
    deactivate_repository_policy(&trusted);
    deactivate_repository_policy(&candidate);
    fs::write(candidate.join("src/newFeature.ts"), "new legacy feature")
        .expect("plant TypeScript addition");
    let trusted_root = SafeRoot::new(&trusted.path).expect("open ratchet base");
    let candidate_root = SafeRoot::new(&candidate.path).expect("open ratchet candidate");
    let error = validate_repository_policy_transition(&trusted_root, &candidate_root)
        .expect_err("new TypeScript artifact unexpectedly passed")
        .to_string();
    assert!(
        error.contains("outside the exact ceiling"),
        "new TypeScript artifact failed through the wrong rule: {error}"
    );

    fs::remove_file(candidate.join("src/newFeature.ts")).expect("remove planted addition");
    fs::remove_file(candidate.join("src/utils/proxy.ts"))
        .expect("remove one grandfathered TypeScript file");
    validate_repository_policy_transition(&trusted_root, &candidate_root)
        .expect("deleting a grandfathered artifact must keep the ratchet green");

    let reduced_base = final_tree("repository-ratchet-reduced-base");
    deactivate_repository_policy(&reduced_base);
    fs::remove_file(reduced_base.join("src/utils/proxy.ts"))
        .expect("remove grandfathered artifact from protected-base fixture");
    let reintroduced_candidate = final_tree("repository-ratchet-reintroduced-candidate");
    deactivate_repository_policy(&reintroduced_candidate);
    let error = validate_repository_policy_transition(
        &SafeRoot::new(&reduced_base.path).expect("open reduced protected base"),
        &SafeRoot::new(&reintroduced_candidate.path).expect("open reintroduced candidate"),
    )
    .expect_err("reintroduced grandfathered artifact unexpectedly passed")
    .to_string();
    assert!(
        error.contains("reintroduced or added legacy Node artifacts"),
        "reintroduced artifact failed through the wrong rule: {error}"
    );
}

#[test]
fn base_owned_repository_ratchet_rejects_node_in_future_mobile_workflows() {
    for (workflow, step) in [
        (
            "ios-packaging.yml",
            "      - uses: actions/setup-node@0123456789abcdef0123456789abcdef01234567\n",
        ),
        ("android-packaging.yml", "      - run: npm ci\n"),
    ] {
        let trusted = final_tree(&format!("repository-{workflow}-ratchet-base"));
        let candidate = final_tree(&format!("repository-{workflow}-ratchet-candidate"));
        deactivate_repository_policy(&trusted);
        deactivate_repository_policy(&candidate);
        let path = format!(".github/workflows/{workflow}");
        fs::write(
            candidate.join(&path),
            format!(
                "name: forbidden mobile Node dependency\non: workflow_dispatch\njobs:\n  package:\n    runs-on: ubuntu-latest\n    steps:\n{step}"
            ),
        )
        .expect("plant Node dependency in a future mobile workflow");
        let error = validate_repository_policy_transition(
            &SafeRoot::new(&trusted.path).expect("open mobile workflow ratchet base"),
            &SafeRoot::new(&candidate.path).expect("open mobile workflow ratchet candidate"),
        )
        .expect_err("new mobile Node workflow debt unexpectedly passed")
        .to_string();
        assert!(
            error.contains("introduced new Node workflow/action violations")
                && error.contains(&path),
            "{workflow} addition failed through the wrong rule: {error}"
        );
    }
}

#[test]
fn repository_policy_activation_requires_exact_shape_and_zero_node_workflows() {
    let trusted = final_tree("repository-policy-inactive-base");
    let candidate = final_tree("repository-policy-active-candidate");
    deactivate_repository_policy(&trusted);
    deactivate_repository_policy(&candidate);
    activate_repository_policy(&candidate);
    let trusted_root = SafeRoot::new(&trusted.path).expect("open inactive policy base");
    let candidate_root = SafeRoot::new(&candidate.path).expect("open active policy candidate");
    validate_repository_policy_transition(&trusted_root, &candidate_root)
        .expect("accept the exact first repository-policy activation");

    fs::remove_file(candidate.join("crates/claw-repo-policy/tests/repository_policy.rs"))
        .expect("remove required policy self-tests");
    let error = validate_repository_policy_transition(&trusted_root, &candidate_root)
        .expect_err("repository policy without self-tests unexpectedly passed")
        .to_string();
    assert!(
        error.contains("claw-repo-policy file inventory changed"),
        "missing self-tests failed through the wrong rule: {error}"
    );
}

#[test]
fn repository_policy_activation_rejects_self_hosted_runners() {
    let trusted = final_tree("repository-policy-runner-base");
    deactivate_repository_policy(&trusted);
    let trusted_root = SafeRoot::new(&trusted.path).expect("open inactive policy base");

    for runner in ["self-hosted", "[self-hosted, windows]"] {
        let candidate = final_tree("repository-policy-runner-candidate");
        deactivate_repository_policy(&candidate);
        activate_repository_policy(&candidate);
        replace(
            &candidate.join(".github/workflows/upstream-gateway-reference.yml"),
            "runs-on: windows-latest",
            &format!("runs-on: {runner}"),
        );

        let error = validate_repository_policy_transition(
            &trusted_root,
            &SafeRoot::new(&candidate.path).expect("open self-hosted runner candidate"),
        )
        .expect_err("candidate-controlled repository-policy runner unexpectedly passed")
        .to_string();
        assert_eq!(
            error, "repository-policy test job shape or execution order changed",
            "self-hosted runner {runner:?} failed through the wrong rule"
        );
    }
}

#[test]
fn root_workspace_growth_rejects_orphans_nested_locks_sources_and_gui() {
    let cases = [
        "orphan",
        "nested-workspace",
        "alternate-lock",
        "git-source",
        "legacy-policy-deps",
        "slint",
    ];
    for case in cases {
        let tree = final_tree(case);
        match case {
            "orphan" => {
                let manifest = tree.join("crates/orphan/Cargo.toml");
                fs::create_dir_all(manifest.parent().expect("orphan parent"))
                    .expect("create orphan directory");
                fs::write(
                    manifest,
                    "[package]\nname = \"orphan\"\nversion = \"0.1.0\"\n",
                )
                .expect("write orphan manifest");
            }
            "nested-workspace" => {
                replace(
                    &tree.join("crates/claw-domain/Cargo.toml"),
                    "[package]\n",
                    "[workspace]\n\n[package]\n",
                );
            }
            "alternate-lock" => {
                fs::write(tree.join("crates/claw-domain/Cargo.lock"), "version = 4\n")
                    .expect("write alternate lock");
            }
            "git-source" => {
                let path = tree.join("crates/claw-domain/Cargo.toml");
                let mut text = fs::read_to_string(&path).expect("read member manifest");
                text.push_str(
                    "\n[dependencies.untrusted]\ngit = \"https://example.invalid/repo\"\n",
                );
                fs::write(path, text).expect("write git dependency");
            }
            "legacy-policy-deps" => {
                let path = tree.join("crates/claw-security/Cargo.toml");
                let mut text = fs::read_to_string(&path).expect("read security manifest");
                text.push_str("\n[dev-dependencies.serde_yaml_ng]\nversion = \"=0.10.0\"\n");
                fs::write(path, text).expect("write obsolete policy dependency");
            }
            "slint" => {
                let path = tree.join("crates/claw-domain/Cargo.toml");
                let mut text = fs::read_to_string(&path).expect("read member manifest");
                text.push_str("\n[dependencies.slint]\nversion = \"=1.17.1\"\n");
                fs::write(path, text).expect("write Slint dependency");
            }
            _ => unreachable!(),
        }
        let root = SafeRoot::new(&tree.path).expect("open negative root fixture");
        assert!(
            validate_final_static(&root).is_err(),
            "negative root workspace case unexpectedly passed: {case}"
        );
    }
}

#[test]
fn exact_desktop_binding_rejects_member_package_build_and_target_mutations() {
    let cases = [
        (
            "member-swap",
            "desktop/Cargo.toml",
            "members = [\"apps/gta-claw-desktop\"]",
            "members = [\"apps/replacement\"]",
        ),
        (
            "member-duplicate",
            "desktop/Cargo.toml",
            "members = [\"apps/gta-claw-desktop\"]",
            "members = [\"apps/gta-claw-desktop\", \"./apps/gta-claw-desktop\"]",
        ),
        (
            "package-rename",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "name = \"gta-claw-desktop\"",
            "name = \"gta-claw-lookalike\"",
        ),
        (
            "build-path",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "build = \"build.rs\"",
            "build = \"../outside.rs\"",
        ),
        (
            "inheritance",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "version.workspace = true",
            "version = \"0.1.0\"",
        ),
        (
            "target-widening",
            "desktop/apps/gta-claw-desktop/Cargo.toml",
            "[lints]",
            "[target.'cfg(target_os = \"linux\")'.dependencies]\nslint = \"*\"\n\n[lints]",
        ),
    ];
    for (label, file, from, to) in cases {
        let tree = final_tree(label);
        replace(&tree.join(file), from, to);
        let root = SafeRoot::new(&tree.path).expect("open desktop negative fixture");
        assert!(
            validate_final_static(&root).is_err(),
            "desktop mutation unexpectedly passed: {label}"
        );
    }
}

#[test]
fn protected_tree_and_reserved_identity_spoofs_fail() {
    let trusted = copy_repo("protected-trusted");
    let candidate = copy_repo("protected-candidate");
    let candidate_root = SafeRoot::new(&candidate.path).expect("open candidate");
    validate_protected_files(
        &SafeRoot::new(&trusted.path).expect("open trusted"),
        &candidate_root,
    )
    .expect("identical protected trees pass");
    let protected = candidate.join(".github/trusted/desktop-supply-chain-policy/src/lib.rs");
    let mut text = fs::read_to_string(&protected).expect("read protected source");
    text.push_str("\n// candidate replacement\n");
    fs::write(&protected, text).expect("mutate protected source");
    assert!(
        compare_trees(
            &SafeRoot::new(&trusted.path).expect("open trusted"),
            &SafeRoot::new(&candidate.path).expect("open candidate"),
            ".github/trusted/desktop-supply-chain-policy",
        )
        .is_err()
    );

    let spoof = copy_repo("workflow-spoof");
    replace(
        &spoof.join(".github/workflows/docker-publish.yml"),
        "name: docker-publish",
        &format!("name: {AUTHORITATIVE_WORKFLOW_NAME}"),
    );
    assert!(validate_inventory(&SafeRoot::new(&spoof.path).expect("open spoof")).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_policy_input_and_path_escape_fail() {
    use std::os::unix::fs::symlink;

    let tree = final_tree("symlink");
    let outside = TempTree::new("symlink-outside");
    fs::write(outside.join("Cargo.toml"), "[workspace]\n").expect("write outside manifest");
    fs::remove_file(tree.join("desktop/Cargo.toml")).expect("remove real manifest");
    symlink(outside.join("Cargo.toml"), tree.join("desktop/Cargo.toml"))
        .expect("create malicious symlink");
    let root = SafeRoot::new(&tree.path).expect("open symlink fixture");
    assert!(root.read_text("desktop/Cargo.toml", 1024).is_err());
    assert!(root.read_text("../outside", 1024).is_err());
}

#[test]
fn candidate_cargo_config_and_build_marker_never_execute() {
    let tree = final_tree("cargo-poison");
    let marker = tree.join("marker-executed");
    #[cfg(windows)]
    let wrapper = {
        let path = tree.join("poison-wrapper.cmd");
        fs::write(
            &path,
            format!("@echo executed>\"{}\"\r\n@exit /b 1\r\n", marker.display()),
        )
        .expect("write Windows poison wrapper");
        path
    };
    #[cfg(not(windows))]
    let wrapper = {
        use std::os::unix::fs::PermissionsExt as _;
        let path = tree.join("poison-wrapper.sh");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf executed >'{}'\nexit 1\n",
                marker.display()
            ),
        )
        .expect("write Unix poison wrapper");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("make poison wrapper executable");
        path
    };
    let config = tree.join(".cargo/config.toml");
    fs::write(
        &config,
        format!(
            "[build]\nrustc-wrapper = \"{}\"\n",
            wrapper.to_string_lossy().replace('\\', "/")
        ),
    )
    .expect("write candidate Cargo poison");
    fs::write(
        tree.join("desktop/apps/gta-claw-desktop/build.rs"),
        format!(
            "fn main() {{ std::fs::write(r\"{}\", b\"executed\").unwrap(); }}\n",
            marker.display()
        ),
    )
    .expect("write marker build script");

    let root = SafeRoot::new(&tree.path).expect("open poison fixture");
    let isolation = TempTree::new("cargo-poison-isolation");
    validate_desktop_metadata(&root, "0.1.0", &local_metadata_tools(), &isolation.path)
        .expect("isolated metadata ignores candidate Cargo config and build script");
    assert!(!marker.exists(), "candidate marker command executed");
    assert!(
        validate_final_static(&root).is_err(),
        "final policy must still reject repository Cargo config"
    );
}

#[test]
fn crafted_metadata_manifest_path_escape_fails_closed() {
    let tree = final_tree("metadata-escape");
    let outside = TempTree::new("metadata-escape-outside");
    let outside_manifest = outside.join("Cargo.toml");
    fs::write(
        &outside_manifest,
        "[package]\nname = \"escape\"\nversion = \"0.1.0\"\n",
    )
    .expect("write outside manifest");
    let target = outside.join("target");
    fs::create_dir_all(&target).expect("create expected target directory");
    let root = SafeRoot::new(&tree.path).expect("open metadata escape fixture");
    let package_id = "path+file:///trusted/gta-claw-desktop#0.1.0";
    let document = serde_json::to_vec(&serde_json::json!({
        "workspace_root": tree.join("desktop"),
        "target_directory": target,
        "workspace_members": [package_id],
        "workspace_default_members": [package_id],
        "packages": [{
            "id": package_id,
            "name": "gta-claw-desktop",
            "version": "0.1.0",
            "edition": "2024",
            "rust_version": "1.94.0",
            "license": "MIT",
            "repository": "https://github.com/GTAStudio/GTA-Claw",
            "source": null,
            "manifest_path": outside_manifest,
            "targets": [],
            "dependencies": [],
        }],
    }))
    .expect("serialize crafted metadata");
    assert!(
        validate_desktop_metadata_document(&root, "0.1.0", &target, &document).is_err(),
        "metadata manifest path escape unexpectedly passed"
    );
}

#[test]
fn bounded_subprocess_rejects_timeout_and_output_flood() {
    let executable = env::current_exe().expect("resolve current test executable");
    let cwd = TempTree::new("bounded-process");
    let timeout = CommandSpec::new(&executable, &cwd.path)
        .expect("create timeout command")
        .args(["--exact", "bounded_child_sleep", "--ignored", "--nocapture"])
        .timeout(Duration::from_millis(50))
        .output_limits(1024, 1024);
    assert!(
        run(&timeout).is_err(),
        "timed-out child unexpectedly passed"
    );

    let flood = CommandSpec::new(&executable, &cwd.path)
        .expect("create flood command")
        .args(["--exact", "bounded_child_flood", "--ignored", "--nocapture"])
        .timeout(Duration::from_secs(10))
        .output_limits(64, 1024);
    assert!(run(&flood).is_err(), "output flood unexpectedly passed");
}

#[test]
#[ignore = "bounded subprocess child"]
fn bounded_child_sleep() {
    std::thread::sleep(Duration::from_secs(2));
}

#[test]
#[ignore = "bounded subprocess child"]
fn bounded_child_flood() {
    print!("{}", "x".repeat(1024 * 1024));
}

fn run_git(git: &Path, cwd: &Path, args: &[&str]) -> String {
    let output = Command::new(git)
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .output()
        .expect("run Git fixture command");
    assert!(
        output.status.success(),
        "Git fixture command failed: args={args:?} stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Git output is UTF-8")
        .trim()
        .to_owned()
}

#[test]
fn trusted_git_manifest_covers_more_than_three_hundred_files() {
    let Some(git) = env::var_os("GIT_BIN").map(PathBuf::from) else {
        eprintln!("GIT_BIN is not set; hosted bootstrap requires and runs this test");
        return;
    };
    assert!(git.is_absolute());
    let fixture = TempTree::new("git-diff");
    let trusted = fixture.join("trusted");
    let candidate = fixture.join("candidate");
    fs::create_dir_all(&trusted).expect("create trusted Git fixture");
    run_git(&git, &trusted, &["init", "--quiet"]);
    run_git(&git, &trusted, &["config", "user.name", "Policy Test"]);
    run_git(
        &git,
        &trusted,
        &["config", "user.email", "policy@example.invalid"],
    );
    fs::write(trusted.join("README.txt"), "base\n").expect("write base fixture");
    run_git(&git, &trusted, &["add", "."]);
    run_git(&git, &trusted, &["commit", "--quiet", "-m", "base"]);
    let base = run_git(&git, &trusted, &["rev-parse", "HEAD"]);
    let fixture_path = fixture.path.to_string_lossy().to_string();
    run_git(
        &git,
        &fixture.path,
        &[
            "clone",
            "--quiet",
            "--no-hardlinks",
            trusted.to_str().expect("trusted path UTF-8"),
            candidate.to_str().expect("candidate path UTF-8"),
        ],
    );
    run_git(&git, &candidate, &["config", "user.name", "Policy Test"]);
    run_git(
        &git,
        &candidate,
        &["config", "user.email", "policy@example.invalid"],
    );
    fs::create_dir_all(candidate.join("docs")).expect("create changed docs");
    for index in 0..350 {
        fs::write(
            candidate.join(format!("docs/generated-{index:03}.txt")),
            format!("{index}\n"),
        )
        .expect("write changed fixture");
    }
    fs::write(candidate.join("docs/source.pack"), "ordinary source data\n")
        .expect("write unrelated worktree pack-suffix file");
    fs::create_dir_all(candidate.join("desktop")).expect("create relevant directory");
    fs::write(candidate.join("desktop/Cargo.toml"), "[workspace]\n")
        .expect("write late relevant path");
    run_git(&git, &candidate, &["add", "."]);
    run_git(&git, &candidate, &["commit", "--quiet", "-m", "head"]);
    fs::write(candidate.join("README.txt"), "second head\n").expect("write second head fixture");
    run_git(&git, &candidate, &["add", "README.txt"]);
    run_git(
        &git,
        &candidate,
        &["commit", "--quiet", "-m", "second head"],
    );
    let head = run_git(&git, &candidate, &["rev-parse", "HEAD"]);
    assert_eq!(
        run_git(
            &git,
            &candidate,
            &["rev-list", "--count", &format!("{base}..{head}")]
        ),
        "2"
    );
    let isolated_home = fixture.join("home");
    fs::create_dir_all(&isolated_home).expect("create Git isolation home");
    let manifest = compute_manifest(&git, &trusted, &candidate, &isolated_home, &base, &head)
        .unwrap_or_else(|error| panic!("compute complete Git manifest in {fixture_path}: {error}"));
    assert_eq!(manifest.paths.len(), 353);
    assert!(has_policy_relevant_change(&manifest));
    assert!(
        manifest
            .paths
            .iter()
            .any(|entry| entry.path == "desktop/Cargo.toml")
    );
    assert!(
        manifest
            .paths
            .iter()
            .any(|entry| entry.path == "docs/source.pack"),
        "worktree .pack file was incorrectly treated as Git object storage"
    );
    assert!(!is_policy_relevant("docs/source.pack"));
    let pack_root = candidate.join(".git/objects/pack");
    let mut fake_packs = Vec::new();
    for index in 0..=MAX_GIT_PACK_FILES {
        let path = pack_root.join(format!("pack-fake-{index:03}.pack"));
        fs::write(&path, []).expect("write bounded fake Git pack entry");
        fake_packs.push(path);
    }
    let pack_error = compute_manifest(&git, &trusted, &candidate, &isolated_home, &base, &head)
        .expect_err("oversized Git pack inventory unexpectedly passed");
    assert!(pack_error.to_string().contains("Git pack storage exceeds"));
    for path in fake_packs {
        fs::remove_file(path).expect("remove fake Git pack entry");
    }
    validate_pull_request_commit_count(1).expect("one commit is accepted");
    validate_pull_request_commit_count(MAX_PULL_REQUEST_COMMITS)
        .expect("exact pull request commit cap is accepted");
    assert!(validate_pull_request_commit_count(0).is_err());
    assert!(validate_pull_request_commit_count(MAX_PULL_REQUEST_COMMITS + 1).is_err());

    fs::write(trusted.join("TRUSTED.txt"), "advanced base\n").expect("write advanced base");
    run_git(&git, &trusted, &["add", "TRUSTED.txt"]);
    run_git(
        &git,
        &trusted,
        &["commit", "--quiet", "-m", "advanced base"],
    );
    let advanced_base = run_git(&git, &trusted, &["rev-parse", "HEAD"]);
    let stale = compute_manifest(
        &git,
        &trusted,
        &candidate,
        &isolated_home,
        &advanced_base,
        &head,
    )
    .expect_err("stale pull request unexpectedly passed");
    assert!(stale.to_string().contains("base is not an ancestor"));

    let unrelated = fixture.join("unrelated");
    fs::create_dir_all(&unrelated).expect("create unrelated Git fixture");
    run_git(&git, &unrelated, &["init", "--quiet"]);
    run_git(&git, &unrelated, &["config", "user.name", "Policy Test"]);
    run_git(
        &git,
        &unrelated,
        &["config", "user.email", "policy@example.invalid"],
    );
    fs::write(unrelated.join("UNRELATED.txt"), "unrelated\n").expect("write unrelated fixture");
    run_git(&git, &unrelated, &["add", "."]);
    run_git(&git, &unrelated, &["commit", "--quiet", "-m", "unrelated"]);
    let unrelated_head = run_git(&git, &unrelated, &["rev-parse", "HEAD"]);
    assert!(
        compute_manifest(
            &git,
            &trusted,
            &unrelated,
            &isolated_home,
            &advanced_base,
            &unrelated_head,
        )
        .is_err(),
        "unrelated pull request history unexpectedly passed"
    );
}

#[test]
fn full_state_machine_accepts_final_candidate_from_either_valid_base_state() {
    let Some(actionlint) = local_actionlint() else {
        eprintln!("ACTIONLINT_BIN is not set; hosted bootstrap requires and runs this test");
        return;
    };
    let trusted = copy_repo("state-trusted");
    let candidate = final_tree("state-candidate");
    let artifacts = TempTree::new("state-artifacts");
    let changes = artifacts.join("changes.json");
    fake_manifest(&changes, true);
    let expected_base_state =
        if is_bootstrap_state(&SafeRoot::new(&trusted.path).expect("open trusted state fixture"))
            .expect("classify trusted state fixture")
        {
            BaseState::Bootstrap
        } else {
            BaseState::Final
        };
    let evidence = validate_request(&ValidationRequest {
        trusted_root: trusted.path.clone(),
        candidate_root: candidate.path.clone(),
        changes: changes.clone(),
        metadata_tools: local_metadata_tools(),
        actionlint,
        isolation_root: artifacts.join("isolation"),
    })
    .expect("trusted base validator accepts exact final P04f candidate");
    assert_eq!(evidence.base_state, expected_base_state);
    assert!(evidence.relevant_change);
    assert!(evidence.candidate_final);
    assert_eq!(
        read_manifest(&changes).expect("read manifest").paths.len(),
        1
    );
}

#[test]
fn final_base_enforces_final_policy_for_an_unrelated_change() {
    let Some(actionlint) = local_actionlint() else {
        eprintln!("ACTIONLINT_BIN is not set; hosted bootstrap requires and runs this test");
        return;
    };
    let trusted = final_tree("final-state-trusted");
    let candidate = final_tree("final-state-candidate");
    let artifacts = TempTree::new("final-state-artifacts");
    let changes = artifacts.join("changes.json");
    fake_manifest(&changes, false);
    let evidence = validate_request(&ValidationRequest {
        trusted_root: trusted.path.clone(),
        candidate_root: candidate.path.clone(),
        changes,
        metadata_tools: local_metadata_tools(),
        actionlint,
        isolation_root: artifacts.join("isolation"),
    })
    .expect("final base enforces final policy for unrelated candidate");
    assert_eq!(evidence.base_state, BaseState::Final);
    assert!(!evidence.relevant_change);
    assert!(evidence.candidate_final);
}

#[test]
fn archived_p04f_mutations_are_actionlint_valid_and_rejected() {
    let root = repo_root();
    let canonical = final_tree("mutation-canonical-baseline");
    let canonical_root = SafeRoot::new(&canonical.path).expect("open canonical mutation baseline");
    validate_final_workflows(&canonical_root).expect("canonical workflow baseline passes");
    validate_final_static(&canonical_root).expect("canonical static baseline passes");

    let cases = fs::read_to_string(root.join(
        ".github/trusted/desktop-supply-chain-policy/policy/final/crates/claw-security/tests/fixtures/desktop_supply_chain_policy/negative-cases.toml",
    ))
    .expect("read canonical P04f negative cases");
    let parsed: toml::Value = toml::from_str(&cases).expect("parse negative cases");
    let cases = parsed
        .get("case")
        .and_then(toml::Value::as_array)
        .expect("negative cases array");
    assert_eq!(cases.len(), P04F_MUTATION_ORACLE.len());
    for (fixture, oracle) in cases.iter().zip(P04F_MUTATION_ORACLE) {
        assert_eq!(
            fixture.get("name").and_then(toml::Value::as_str),
            Some(oracle.name)
        );
        assert_eq!(
            fixture.get("mutation").and_then(toml::Value::as_str),
            Some(oracle.mutation)
        );
        assert_eq!(
            fixture.get("expected").and_then(toml::Value::as_str),
            Some(oracle.expected)
        );
    }

    let reference = root.join(".github/trusted/desktop-supply-chain-policy/policy");
    let baseline_workflow: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        &fs::read_to_string(reference.join("final/.github/workflows/rust.yml"))
            .expect("read canonical Final Rust workflow"),
    )
    .expect("parse original PR22 Rust workflow");
    let baseline_macos: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        &fs::read_to_string(reference.join("final/.github/workflows/macos-packaging.yml"))
            .expect("read canonical macOS workflow"),
    )
    .expect("parse canonical macOS workflow");
    let baseline_root_deny: toml::Value = toml::from_str(
        &fs::read_to_string(reference.join("final/root-deny.toml.fixture"))
            .expect("read final root deny"),
    )
    .expect("parse final root deny");
    let baseline_deny: toml::Value = toml::from_str(
        &fs::read_to_string(reference.join("final/desktop/deny.toml.fixture"))
            .expect("read final desktop deny"),
    )
    .expect("parse final desktop deny");
    let baseline_audit: toml::Value = toml::from_str(
        &fs::read_to_string(root.join(".cargo/audit.toml")).expect("read root audit policy"),
    )
    .expect("parse root audit policy");
    let baseline_desktop: toml::Value = toml::from_str(
        &fs::read_to_string(reference.join("final/desktop/Cargo.toml.fixture"))
            .expect("read final desktop manifest"),
    )
    .expect("parse final desktop manifest");
    let baseline_app: toml::Value = toml::from_str(
        &fs::read_to_string(
            reference.join("final/desktop/apps/gta-claw-desktop/Cargo.toml.fixture"),
        )
        .expect("read final desktop app manifest"),
    )
    .expect("parse final desktop app manifest");

    let actionlint_fixture = TempTree::new("actual-actionlint-mutations");
    let mut actionlint_paths = Vec::new();
    let mut mutated_hashes = Vec::with_capacity(P04F_MUTATION_ORACLE.len());
    let mut names = BTreeSet::new();
    for (case, oracle) in cases.iter().zip(P04F_MUTATION_ORACLE) {
        let name = oracle.name;
        let mutation = oracle.mutation;
        assert!(names.insert(name));
        assert_eq!(
            case.get("expected").and_then(toml::Value::as_str),
            Some(oracle.expected)
        );

        let mut workflow = baseline_workflow.clone();
        let mut macos = baseline_macos.clone();
        let mut root_deny = baseline_root_deny.clone();
        let mut deny = baseline_deny.clone();
        let mut audit = baseline_audit.clone();
        let mut desktop = baseline_desktop.clone();
        let mut app = baseline_app.clone();
        mutations::mutate_negative_case(
            mutation,
            &mut workflow,
            &mut macos,
            &mut root_deny,
            &mut deny,
            &mut audit,
            (&mut desktop, &mut app),
        );
        let changed = [
            (
                workflow != baseline_workflow,
                MutationArtifact::RustWorkflow,
            ),
            (macos != baseline_macos, MutationArtifact::MacosWorkflow),
            (root_deny != baseline_root_deny, MutationArtifact::RootDeny),
            (deny != baseline_deny, MutationArtifact::DesktopDeny),
            (audit != baseline_audit, MutationArtifact::Audit),
            (
                desktop != baseline_desktop,
                MutationArtifact::DesktopManifest,
            ),
            (app != baseline_app, MutationArtifact::AppManifest),
        ]
        .into_iter()
        .filter_map(|(changed, artifact)| changed.then_some(artifact))
        .collect::<Vec<_>>();
        assert_eq!(
            changed,
            [oracle.artifact],
            "archived mutation changed the wrong policy artifact: {mutation}"
        );
        let mutated_bytes = match oracle.artifact {
            MutationArtifact::RustWorkflow => {
                serde_yaml_ng::to_string(&workflow).expect("serialize oracle Rust workflow")
            }
            MutationArtifact::MacosWorkflow => {
                serde_yaml_ng::to_string(&macos).expect("serialize oracle macOS workflow")
            }
            MutationArtifact::RootDeny => {
                toml::to_string(&root_deny).expect("serialize oracle root deny")
            }
            MutationArtifact::DesktopDeny => {
                toml::to_string(&deny).expect("serialize oracle desktop deny")
            }
            MutationArtifact::Audit => toml::to_string(&audit).expect("serialize oracle audit"),
            MutationArtifact::DesktopManifest => {
                toml::to_string(&desktop).expect("serialize oracle desktop manifest")
            }
            MutationArtifact::AppManifest => {
                toml::to_string(&app).expect("serialize oracle app manifest")
            }
        };
        mutated_hashes.push(sha256(mutated_bytes.as_bytes()));

        let rust_path = actionlint_fixture.join(format!("{name}-rust.yml"));
        let macos_path = actionlint_fixture.join(format!("{name}-macos.yml"));
        fs::write(
            &rust_path,
            serde_yaml_ng::to_string(&workflow).expect("serialize mutated Rust workflow"),
        )
        .expect("write mutated Rust workflow");
        fs::write(
            &macos_path,
            serde_yaml_ng::to_string(&macos).expect("serialize mutated macOS workflow"),
        )
        .expect("write mutated macOS workflow");
        actionlint_paths.push(rust_path);
        actionlint_paths.push(macos_path);

        let tree = final_tree(&format!("actual-mutation-{name}"));
        if workflow != baseline_workflow {
            fs::write(
                tree.join(".github/workflows/rust.yml"),
                serde_yaml_ng::to_string(&workflow).expect("serialize candidate Rust workflow"),
            )
            .expect("write candidate Rust workflow");
        }
        if macos != baseline_macos {
            fs::write(
                tree.join(".github/workflows/macos-packaging.yml"),
                serde_yaml_ng::to_string(&macos).expect("serialize candidate macOS workflow"),
            )
            .expect("write candidate macOS workflow");
        }
        for (changed, path, value) in [
            (root_deny != baseline_root_deny, "deny.toml", &root_deny),
            (deny != baseline_deny, "desktop/deny.toml", &deny),
            (audit != baseline_audit, ".cargo/audit.toml", &audit),
            (desktop != baseline_desktop, "desktop/Cargo.toml", &desktop),
            (
                app != baseline_app,
                "desktop/apps/gta-claw-desktop/Cargo.toml",
                &app,
            ),
        ] {
            if changed {
                fs::write(
                    tree.join(path),
                    toml::to_string(value).expect("serialize mutated TOML"),
                )
                .expect("write mutated policy TOML");
            }
        }
        let candidate = SafeRoot::new(&tree.path).expect("open actual mutation fixture");
        let error = match oracle.artifact {
            MutationArtifact::RustWorkflow | MutationArtifact::MacosWorkflow => {
                validate_final_workflows(&candidate)
                    .expect_err("trusted final workflow policy accepted archived mutation")
            }
            _ => validate_final_static(&candidate)
                .expect_err("trusted final static policy accepted archived mutation"),
        };
        assert_eq!(
            error.to_string(),
            oracle.artifact.production_error(),
            "mutation was rejected by the wrong production rule class: {mutation} ({})",
            oracle.expected
        );
    }
    assert_eq!(names.len(), P04F_MUTATION_ORACLE.len());
    assert_eq!(actionlint_paths.len(), P04F_MUTATION_ORACLE.len() * 2);
    assert_eq!(
        mutated_hashes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        P04F_MUTATED_ARTIFACT_SHA256,
        "mutation bytes do not match the independent rule oracle"
    );

    if let Some(actionlint) = local_actionlint() {
        let mut spec = CommandSpec::new(&actionlint.path, &actionlint_fixture.path)
            .expect("create actionlint mutation command")
            .args(["-shellcheck=", "-pyflakes=", "-ignore", "macos-15-intel"])
            .timeout(Duration::from_secs(30))
            .output_limits(4 * 1024 * 1024, 4 * 1024 * 1024);
        for path in actionlint_paths {
            spec = spec.arg(path);
        }
        run_checked(&spec, "actual actionlint-valid P04f mutations")
            .expect("all archived P04f workflow mutations remain actionlint-valid");
    } else {
        eprintln!("ACTIONLINT_BIN is not set; hosted bootstrap requires actionlint mutation proof");
    }
}

// Mobile workspace admission.
//
// Every case below starts from an ACCEPTED baseline and then mutates exactly one thing, so a
// rejection proves the rule under test rather than an unrelated defect in the fixture. Expectations
// are derived from `repo_root()` through `final_tree`, never from the artifact under test.

const MOBILE_WORKSPACE_MANIFEST: &str = r#"[workspace]
members = ["apps/gta-claw-PLATFORM-shell"]
resolver = "3"

[workspace.dependencies]
claw-protocol = { path = "../crates/claw-protocol", version = "0.1.0" }

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.94.0"
license = "MIT"
repository = "https://github.com/GTAStudio/GTA-Claw"

[workspace.lints.rust]
missing_docs = "warn"
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"
unreachable_pub = "warn"

[workspace.lints.clippy]
all = "warn"

[profile.release]
codegen-units = 1
lto = "thin"
strip = "symbols"
"#;

const MOBILE_APP_MANIFEST: &str = r#"[package]
name = "gta-claw-PLATFORM-shell"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true
"#;

const MOBILE_DENY: &str = r#"[graph]
all-features = true

[advisories]
ignore = []

[licenses]
allow = ["Apache-2.0", "BSD-3-Clause", "ISC", "LicenseRef-Slint-Royalty-free-2.0", "MIT", "Unicode-3.0", "Zlib"]
confidence-threshold = 0.8

[bans]
multiple-versions = "deny"
wildcards = "deny"
highlight = "all"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
"#;

const MOBILE_CHECKSUM: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn mobile_lock(platform: &str, extra: &str) -> String {
    format!(
        "version = 4\n\n[[package]]\nname = \"gta-claw-{platform}-shell\"\nversion = \"0.1.0\"\ndependencies = []\n{extra}"
    )
}

fn registry_lock_entry(name: &str, version: &str) -> String {
    format!(
        "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{MOBILE_CHECKSUM}\"\n"
    )
}

fn desktop_slint_version(tree: &TempTree) -> String {
    let lock: toml::Value = toml::from_str(
        &fs::read_to_string(tree.join("desktop/Cargo.lock")).expect("read desktop lock"),
    )
    .expect("parse desktop lock");
    lock.get("package")
        .and_then(toml::Value::as_array)
        .expect("desktop lock packages")
        .iter()
        .find(|package| package.get("name").and_then(toml::Value::as_str) == Some("slint"))
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .expect("desktop lock declares slint")
        .to_owned()
}

fn write_mobile_file(tree: &TempTree, relative: &str, contents: &str) {
    let path = tree.join(relative);
    fs::create_dir_all(path.parent().expect("mobile fixture parent"))
        .expect("create mobile parent");
    fs::write(path, contents).expect("write mobile fixture");
}

/// Writes one complete, compliant mobile workspace unit.
///
/// A dependency policy is deliberately absent: nothing executes a mobile `deny.toml` yet, so the
/// validator rejects one outright. `a_mobile_dependency_policy_is_rejected_until_ci_executes_it`
/// pins that.
fn write_mobile_workspace(tree: &TempTree, platform: &str, lock: &str) {
    write_mobile_file(
        tree,
        &format!("{platform}/Cargo.toml"),
        &MOBILE_WORKSPACE_MANIFEST.replace("PLATFORM", platform),
    );
    write_mobile_file(
        tree,
        &format!("{platform}/apps/gta-claw-{platform}-shell/Cargo.toml"),
        &MOBILE_APP_MANIFEST.replace("PLATFORM", platform),
    );
    write_mobile_file(
        tree,
        &format!("{platform}/apps/gta-claw-{platform}-shell/src/lib.rs"),
        "",
    );
    write_mobile_file(tree, &format!("{platform}/Cargo.lock"), lock);
}

fn retarget_root_exclude(tree: &TempTree) {
    let path = tree.join("Cargo.toml");
    let text = fs::read_to_string(&path).expect("read root manifest");
    assert!(
        text.contains(r#"exclude = ["android", "desktop", "ios"]"#),
        "root manifest must already pin the mobile-aware exclude list"
    );
}

fn accepted_android_tree(label: &str) -> TempTree {
    let tree = final_tree(label);
    retarget_root_exclude(&tree);
    write_mobile_workspace(&tree, "android", &mobile_lock("android", ""));
    let root = SafeRoot::new(&tree.path).expect("open android baseline");
    validate_final_static(&root).expect("compliant android workspace is admitted");
    tree
}

fn rejection(tree: &TempTree, label: &str) -> String {
    let root = SafeRoot::new(&tree.path).expect("open mutated mobile fixture");
    validate_final_static(&root).expect_err(label).to_string()
}

#[test]
fn live_tree_admits_mobile_paths_without_requiring_them() {
    let tree = final_tree("mobile-absent");
    let root = SafeRoot::new(&tree.path).expect("open mobile-free tree");
    for platform in ["android", "ios"] {
        assert!(
            !tree.join(platform).exists(),
            "baseline must contain no {platform} workspace"
        );
    }
    validate_final_static(&root).expect("mobile paths are admitted, never required");
}

#[test]
fn mobile_admission_does_not_reclassify_the_bootstrap_state() {
    let tree = bootstrap_tree("mobile-bootstrap");
    let root = SafeRoot::new(&tree.path).expect("open bootstrap fixture");
    assert!(
        is_bootstrap_state(&root).expect("classify bootstrap fixture"),
        "widening the admitted lock inventory must not rewrite the historical bootstrap inventory"
    );
    assert_eq!(
        bootstrap_fingerprint(&root).expect("bootstrap fingerprint"),
        expected_bootstrap_fingerprint()
    );
}

#[test]
fn compliant_mobile_workspace_is_admitted_and_partial_units_are_rejected() {
    let baseline = accepted_android_tree("mobile-complete");
    drop(baseline);

    for omitted in [
        "android/Cargo.toml",
        "android/apps/gta-claw-android-shell/Cargo.toml",
        "android/Cargo.lock",
    ] {
        let tree = accepted_android_tree("mobile-partial");
        fs::remove_file(tree.join(omitted)).expect("remove one unit member");
        let error = rejection(&tree, "partial mobile workspace is rejected");
        assert!(
            error.contains("android workspace is incomplete") || error.contains(omitted),
            "removing {omitted} must be reported precisely, got: {error}"
        );
    }
}

#[test]
fn mobile_lock_sources_checksums_and_local_packages_are_bound() {
    let git = accepted_android_tree("mobile-git-source");
    write_mobile_file(
        &git,
        "android/Cargo.lock",
        &mobile_lock(
            "android",
            "\n[[package]]\nname = \"smuggled\"\nversion = \"0.1.0\"\nsource = \"git+https://example.invalid/smuggled\"\n",
        ),
    );
    assert!(
        rejection(&git, "git-sourced mobile lock entry is rejected")
            .contains("forbidden package source"),
        "a git source in a mobile lock must be rejected"
    );

    let unchecked = accepted_android_tree("mobile-missing-checksum");
    write_mobile_file(
        &unchecked,
        "android/Cargo.lock",
        &mobile_lock(
            "android",
            "\n[[package]]\nname = \"unchecked\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        ),
    );
    assert!(
        rejection(&unchecked, "unchecksummed registry entry is rejected")
            .contains("registry package checksum is invalid"),
        "a registry entry without a checksum must be rejected"
    );

    let orphan = accepted_android_tree("mobile-orphan-local");
    write_mobile_file(
        &orphan,
        "android/Cargo.lock",
        &mobile_lock(
            "android",
            "\n[[package]]\nname = \"undeclared-local\"\nversion = \"0.1.0\"\n",
        ),
    );
    assert!(
        rejection(&orphan, "undeclared local package is rejected")
            .contains("local package is not a declared workspace package"),
        "a path package outside the declared workspaces must be rejected"
    );
}

#[test]
fn mobile_workspace_cannot_reintroduce_exclusion_or_weaken_lints() {
    let excluded = accepted_android_tree("mobile-exclude");
    let manifest = MOBILE_WORKSPACE_MANIFEST
        .replace("PLATFORM", "android")
        .replace(
            "resolver = \"3\"",
            "resolver = \"3\"\nexclude = [\"vendor\"]",
        );
    write_mobile_file(&excluded, "android/Cargo.toml", &manifest);
    assert!(
        rejection(&excluded, "nested exclusion is rejected").contains("workspace schema changed"),
        "a mobile workspace must not reopen the excluded-workspace route"
    );

    let unsafe_allowed = accepted_android_tree("mobile-unsafe");
    let manifest = MOBILE_WORKSPACE_MANIFEST
        .replace("PLATFORM", "android")
        .replace("unsafe_code = \"deny\"", "unsafe_code = \"allow\"");
    write_mobile_file(&unsafe_allowed, "android/Cargo.toml", &manifest);
    assert!(
        rejection(&unsafe_allowed, "weakened unsafe policy is rejected")
            .contains("lint policy is weaker"),
        "a mobile workspace must not allow unsafe code"
    );

    let member = accepted_android_tree("mobile-member-lints");
    let app = MOBILE_APP_MANIFEST.replace("PLATFORM", "android").replace(
        "[lints]\nworkspace = true",
        "[lints.rust]\nunsafe_code = \"allow\"",
    );
    write_mobile_file(
        &member,
        "android/apps/gta-claw-android-shell/Cargo.toml",
        &app,
    );
    assert!(
        rejection(&member, "member lint override is rejected")
            .contains("lints must inherit exactly from workspace"),
        "a mobile member must inherit the workspace lint table exactly"
    );
}

#[test]
fn mobile_admission_stays_bounded_to_the_two_declared_platforms() {
    let extra = final_tree("mobile-unadmitted");
    write_mobile_workspace(&extra, "web", &mobile_lock("web", ""));
    let error = rejection(&extra, "an unadmitted sibling workspace is rejected");
    assert!(
        error.contains("Cargo.lock inventory contains unadmitted locations")
            && error.contains("web/Cargo.lock"),
        "admission must be a bounded path list, not a prefix rule, got: {error}"
    );

    let aliased = accepted_android_tree("mobile-case-alias");
    assert!(
        validate_casefold_paths(&[
            "android/Cargo.lock".to_owned(),
            "ANDROID/Cargo.lock".to_owned(),
        ])
        .is_err(),
        "a mobile directory and its case alias must collide"
    );
    drop(aliased);
}

#[test]
fn mobile_manifest_dependencies_cannot_escape_the_repository_or_use_forbidden_sources() {
    for (label, replacement, expected) in [
        (
            "path escape",
            "claw-protocol = { path = \"../../../../elsewhere/claw-protocol\", version = \"0.1.0\" }",
            "escapes repository root",
        ),
        (
            "undeclared member path",
            "claw-protocol = { path = \"../crates/not-a-member\", version = \"0.1.0\" }",
            "not a declared root member",
        ),
        (
            "git source",
            "claw-protocol = { git = \"https://example.invalid/claw-protocol\" }",
            "source/schema is forbidden",
        ),
        (
            "wildcard version",
            "claw-protocol = { path = \"../crates/claw-protocol\", version = \"*\" }",
            "bounded registry version",
        ),
    ] {
        let tree = accepted_android_tree("mobile-dependency");
        let manifest = MOBILE_WORKSPACE_MANIFEST
            .replace("PLATFORM", "android")
            .replace(
                "claw-protocol = { path = \"../crates/claw-protocol\", version = \"0.1.0\" }",
                replacement,
            );
        write_mobile_file(&tree, "android/Cargo.toml", &manifest);
        let error = rejection(&tree, "forbidden mobile dependency is rejected");
        assert!(
            error.contains(expected),
            "mobile {label} must be rejected with {expected:?}, got: {error}"
        );
    }

    // Slint itself must remain permitted, or the admission would be pointless.
    let slint = accepted_android_tree("mobile-dependency-slint");
    let manifest = MOBILE_WORKSPACE_MANIFEST
        .replace("PLATFORM", "android")
        .replace(
            "claw-protocol = { path = \"../crates/claw-protocol\", version = \"0.1.0\" }",
            "slint = { version = \"=1.17.1\", default-features = false }",
        );
    write_mobile_file(&slint, "android/Cargo.toml", &manifest);
    let root = SafeRoot::new(&slint.path).expect("open mobile Slint fixture");
    validate_final_static(&root).expect("a mobile workspace may depend on Slint");
}

#[test]
fn a_mobile_dependency_policy_is_rejected_until_ci_executes_it() {
    // `android-packaging.yml` and `ios-packaging.yml` are admitted workflow paths but do not
    // exist, so nothing runs cargo-deny against a mobile policy file. A policy file that nothing
    // executes is worse than none, because it reads as protection. Admitting one belongs in the
    // change that also lands the workflow executing it, so today it fails closed.
    for platform in ["android", "ios"] {
        assert!(
            !Path::new(&repo_root())
                .join(format!(".github/workflows/{platform}-packaging.yml"))
                .exists(),
            "this rule is only correct while no {platform} packaging workflow exists"
        );
    }

    let tree = accepted_android_tree("mobile-deny-unexecuted");
    write_mobile_file(&tree, "android/deny.toml", MOBILE_DENY);
    let error = rejection(&tree, "an unexecuted mobile dependency policy is rejected");
    assert!(
        error.contains("unexpected deny/audit policy file") && error.contains("android/deny.toml"),
        "a mobile deny.toml must fail closed until a workflow runs it, got: {error}"
    );

    let audit = accepted_android_tree("mobile-audit-unexecuted");
    write_mobile_file(&audit, "android/audit.toml", "[advisories]\nignore = []\n");
    assert!(
        rejection(&audit, "an unexecuted mobile audit policy is rejected")
            .contains("unexpected deny/audit policy file"),
        "the same rule must cover audit configuration"
    );
}
#[test]
fn an_admitted_mobile_workspace_cannot_impersonate_or_reach_outside_itself() {
    // What can ios/Cargo.toml declare that would let it claim to be something trusted, or reach
    // a file outside its own directory? Each case starts from the ACCEPTED baseline.
    for (label, from, to, expected) in [
        (
            "member escaping into the frozen desktop tree",
            "members = [\"apps/gta-claw-android-shell\"]",
            "members = [\"../desktop/apps/gta-claw-desktop\"]",
            "must declare exactly one member",
        ),
        (
            "member claiming a root workspace app",
            "members = [\"apps/gta-claw-android-shell\"]",
            "members = [\"apps/gta-claw-daemon\"]",
            "must declare exactly one member",
        ),
        (
            "path dependency reaching into the frozen desktop tree",
            "claw-protocol = { path = \"../crates/claw-protocol\", version = \"0.1.0\" }",
            "gta-claw-desktop = { path = \"../desktop/apps/gta-claw-desktop\", version = \"0.1.0\" }",
            "not a declared root member",
        ),
        (
            "path dependency reaching into the trust root itself",
            "claw-protocol = { path = \"../crates/claw-protocol\", version = \"0.1.0\" }",
            "policy = { path = \"../.github/trusted/desktop-supply-chain-policy\", version = \"0.1.0\" }",
            "not a declared root member",
        ),
        (
            // `path` also appears in section form, not only inline. If the parsing were not
            // section-aware this would bless an orphan file with one line of TOML.
            "section-form path dependency escaping the repository",
            "claw-protocol = { path = \"../crates/claw-protocol\", version = \"0.1.0\" }",
            "[workspace.dependencies.claw-protocol]\npath = \"../../../../elsewhere/claw-protocol\"\nversion = \"0.1.0\"",
            "escapes repository root",
        ),
        (
            "patched registry",
            "[profile.release]",
            "[patch.crates-io]\nslint = { path = \"../elsewhere/slint\" }\n\n[profile.release]",
            "top-level schema changed",
        ),
        (
            "workspace metadata smuggling",
            "resolver = \"3\"",
            "resolver = \"3\"\nmetadata = { trusted = true }",
            "workspace schema changed",
        ),
    ] {
        let tree = accepted_android_tree("mobile-impersonation");
        let manifest = MOBILE_WORKSPACE_MANIFEST.replace("PLATFORM", "android");
        assert!(manifest.contains(from), "fixture lost {from:?}");
        write_mobile_file(&tree, "android/Cargo.toml", &manifest.replace(from, to));
        let error = rejection(&tree, "impersonation attempt is rejected");
        assert!(
            error.contains(expected),
            "{label} must be rejected with {expected:?}, got: {error}"
        );
    }

    // The app member must not be able to rename itself into a trusted package.
    let renamed = accepted_android_tree("mobile-impersonation-package");
    let app = MOBILE_APP_MANIFEST.replace("PLATFORM", "android").replace(
        "name = \"gta-claw-android-shell\"",
        "name = \"gta-claw-desktop\"",
    );
    write_mobile_file(
        &renamed,
        "android/apps/gta-claw-android-shell/Cargo.toml",
        &app,
    );
    assert!(
        rejection(&renamed, "renamed mobile package is rejected")
            .contains("package name must be gta-claw-android-shell"),
        "a mobile member must not be able to claim a trusted package name"
    );

    // Nor may its lock claim to contain one.
    let lock = accepted_android_tree("mobile-impersonation-lock");
    write_mobile_file(
        &lock,
        "android/Cargo.lock",
        &mobile_lock(
            "android",
            "\n[[package]]\nname = \"gta-claw-desktop\"\nversion = \"0.1.0\"\n",
        ),
    );
    assert!(
        rejection(&lock, "impersonating local lock entry is rejected")
            .contains("local package is not a declared workspace package"),
        "a mobile lock must not be able to claim a trusted local package"
    );
}

#[test]
fn admitted_lock_and_skia_target_sets_are_derived_from_the_platform_table() {
    // A second hardcoded list could silently disagree with the platforms it is meant to describe.
    for platform in ["android", "ios"] {
        let tree = final_tree("mobile-derived-inventory");
        retarget_root_exclude(&tree);
        write_mobile_file(
            &tree,
            &format!("{platform}/Cargo.lock"),
            &mobile_lock(platform, ""),
        );
        let error = rejection(&tree, "a lone admitted lock is still an incomplete unit");
        assert!(
            error.contains(&format!("{platform} workspace is incomplete")),
            "{platform}/Cargo.lock must be admitted by path yet rejected as a partial unit, got: {error}"
        );
    }

    let stray = final_tree("mobile-derived-inventory-stray");
    retarget_root_exclude(&stray);
    write_mobile_file(&stray, "windows/Cargo.lock", "version = 4\n");
    assert!(
        rejection(&stray, "an undeclared platform lock is rejected").contains("windows/Cargo.lock"),
        "only locks belonging to a declared platform may be admitted"
    );
}

#[test]
fn reviewed_build_artifact_pin_table_shape_is_enforced() {
    const DIGEST: &str = "500ddee961ef415f36fce4fcd300aca7bfaf9a4f676cf2332f2e4048621fce37";
    let url = "https://github.com/rust-skia/skia-binaries/releases/download/0.99.0/skia-binaries-aarch64-apple-ios.tar.gz";
    validate_build_artifact_pin_table(&[(
        "skia-bindings",
        "0.99.0",
        "aarch64-apple-ios",
        url,
        DIGEST,
    )])
    .expect("a well formed reviewed pin is accepted");
    validate_build_artifact_pin_table(&[]).expect("an empty reviewed pin table is well formed");

    for (label, pins) in [
        (
            "package that does not fetch at build time",
            vec![("serde", "0.99.0", "aarch64-apple-ios", url, DIGEST)],
        ),
        (
            "release other than the admitted one",
            vec![("skia-bindings", "0.98.0", "aarch64-apple-ios", url, DIGEST)],
        ),
        (
            "unadmitted target",
            vec![("skia-bindings", "0.99.0", "x86_64-apple-ios", url, DIGEST)],
        ),
        (
            "duplicate package and target",
            vec![
                ("skia-bindings", "0.99.0", "aarch64-apple-ios", url, DIGEST),
                ("skia-bindings", "0.99.0", "aarch64-apple-ios", url, DIGEST),
            ],
        ),
        (
            "short digest",
            vec![(
                "skia-bindings",
                "0.99.0",
                "aarch64-apple-ios",
                url,
                "abc123",
            )],
        ),
        (
            "plaintext URL",
            vec![(
                "skia-bindings",
                "0.99.0",
                "aarch64-apple-ios",
                "http://example.invalid/skia-aarch64-apple-ios.tar.gz",
                DIGEST,
            )],
        ),
        (
            "traversal in URL",
            vec![(
                "skia-bindings",
                "0.99.0",
                "aarch64-apple-ios",
                "https://example.invalid/../aarch64-apple-ios.tar.gz",
                DIGEST,
            )],
        ),
        (
            "URL naming a different target",
            vec![(
                "skia-bindings",
                "0.99.0",
                "aarch64-apple-ios-sim",
                url,
                DIGEST,
            )],
        ),
    ] {
        assert!(
            validate_build_artifact_pin_table(&pins).is_err(),
            "reviewed build-artifact pin table must reject: {label}"
        );
    }
}

#[test]
fn case_aliased_mobile_directories_fail_on_every_host() {
    for path in [
        "Android/Cargo.toml",
        "ANDROID/Cargo.lock",
        "iOS/Cargo.toml",
        "IOS/deny.toml",
        "Android/apps/gta-claw-android-shell/Cargo.toml",
    ] {
        assert!(
            validate_casefold_paths(&[path.to_owned()]).is_err(),
            "case-aliased mobile path must be rejected on every host: {path}"
        );
    }
    for path in [
        "android/Cargo.toml",
        "android/Cargo.lock",
        "ios/Cargo.toml",
        "ios/deny.toml",
    ] {
        validate_casefold_paths(&[path.to_owned()]).expect("canonical mobile paths stay portable");
    }
}

#[test]
fn ios_cannot_land_until_its_prebuilt_skia_archive_is_pinned() {
    let slint = {
        let probe = final_tree("mobile-ios-slint-probe");
        desktop_slint_version(&probe)
    };

    // Everything except the reviewed archive digest is satisfied, so the reported failure proves
    // the digest gate is the sole remaining blocker rather than a defect elsewhere in the fixture.
    let pinned = final_tree("mobile-ios-pinned");
    retarget_root_exclude(&pinned);
    let lock = mobile_lock(
        "ios",
        &format!(
            "{}{}",
            registry_lock_entry("skia-bindings", "0.99.0"),
            registry_lock_entry("slint", &slint)
        ),
    );
    write_mobile_workspace(&pinned, "ios", &lock);
    let error = rejection(&pinned, "iOS without a reviewed Skia digest is rejected");
    assert!(
        error.contains("uses skia-bindings, which fetches at build time")
            && error.contains("aarch64-apple-ios")
            && error.contains("aarch64-apple-ios-sim"),
        "iOS admission must require a reviewed digest for every admitted target, got: {error}"
    );

    let drifted = final_tree("mobile-ios-drift");
    retarget_root_exclude(&drifted);
    let lock = mobile_lock(
        "ios",
        &format!(
            "{}{}",
            registry_lock_entry("skia-bindings", "0.98.0"),
            registry_lock_entry("slint", &slint)
        ),
    );
    write_mobile_workspace(&drifted, "ios", &lock);
    assert!(
        rejection(&drifted, "unpinned skia-bindings release is rejected")
            .contains("must pin skia-bindings to exactly 0.99.0"),
        "the pinned Skia release must be bound before the archive digest is even consulted"
    );

    let missing = final_tree("mobile-ios-no-skia");
    retarget_root_exclude(&missing);
    write_mobile_workspace(&missing, "ios", &mobile_lock("ios", ""));
    assert!(
        rejection(&missing, "iOS lock without skia-bindings is rejected")
            .contains("cannot avoid Skia"),
        "an iOS Slint build cannot avoid Skia, so its absence signals an unresolved lock"
    );

    // Android can select femtovg or the software renderer, so Skia is optional there — but the
    // moment its lock contains skia-bindings the same version pin and digest gate apply.
    let android_skia = final_tree("mobile-android-skia");
    retarget_root_exclude(&android_skia);
    write_mobile_workspace(
        &android_skia,
        "android",
        &mobile_lock("android", &registry_lock_entry("skia-bindings", "0.99.0")),
    );
    let error = rejection(&android_skia, "Android Skia without digests is rejected");
    assert!(
        error.contains("uses skia-bindings, which fetches at build time")
            && error.contains("aarch64-linux-android"),
        "Android must not be able to consume an unverified Skia archive, got: {error}"
    );

    let android_drift = final_tree("mobile-android-skia-drift");
    retarget_root_exclude(&android_drift);
    write_mobile_workspace(
        &android_drift,
        "android",
        &mobile_lock("android", &registry_lock_entry("skia-bindings", "0.98.0")),
    );
    assert!(
        rejection(&android_drift, "Android skia-bindings drift is rejected")
            .contains("must pin skia-bindings to exactly 0.99.0"),
        "the pinned Skia release binds every mobile lock, not only iOS"
    );
}

#[test]
fn mobile_slint_release_cannot_diverge_from_the_protected_desktop_release() {
    let tree = final_tree("mobile-slint-drift");
    retarget_root_exclude(&tree);
    let desktop = desktop_slint_version(&tree);
    assert_ne!(
        desktop, "0.0.1",
        "fixture requires a real desktop Slint pin"
    );
    write_mobile_workspace(
        &tree,
        "android",
        &mobile_lock("android", &registry_lock_entry("slint", "0.0.1")),
    );
    let error = rejection(&tree, "divergent Slint release is rejected");
    assert!(
        error.contains("single repository Slint release") && error.contains(&desktop),
        "a mobile workspace must not introduce a second Slint line, got: {error}"
    );

    let agreed = final_tree("mobile-slint-agreed");
    retarget_root_exclude(&agreed);
    let desktop = desktop_slint_version(&agreed);
    write_mobile_workspace(
        &agreed,
        "android",
        &mobile_lock("android", &registry_lock_entry("slint", &desktop)),
    );
    let root = SafeRoot::new(&agreed.path).expect("open agreed Slint fixture");
    validate_final_static(&root).expect("a matching Slint release is admitted");
}
