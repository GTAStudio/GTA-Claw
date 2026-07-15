use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use desktop_supply_chain_policy::changes::{
    ChangeManifest, ChangedPath, compute_manifest, has_policy_relevant_change, is_policy_relevant,
    read_manifest, write_manifest,
};
use desktop_supply_chain_policy::input::{SafeRoot, compare_trees, sha256};
use desktop_supply_chain_policy::metadata::{
    MetadataTools, validate_desktop_metadata, validate_desktop_metadata_document,
    validate_root_metadata,
};
use desktop_supply_chain_policy::ownership::{
    CODEOWNER, CODEOWNERS_PATH, canonical_codeowners, frozen_surfaces, validate_codeowners,
    validate_codeowners_text,
};
use desktop_supply_chain_policy::policy::{
    bootstrap_fingerprint, expected_bootstrap_fingerprint, is_bootstrap_state,
    validate_casefold_paths, validate_final_static,
};
use desktop_supply_chain_policy::process::{CommandSpec, run, run_checked};
use desktop_supply_chain_policy::validation::{
    BaseState, ValidationRequest, candidate_requires_final, validate_request,
};
use desktop_supply_chain_policy::workflows::{
    AUTHORITATIVE_JOB_NAME, AUTHORITATIVE_PATH, AUTHORITATIVE_WORKFLOW_NAME, ActionlintTool,
    BOOTSTRAP_JOB_NAME, BOOTSTRAP_PATH, BOOTSTRAP_WORKFLOW_NAME, validate_final_workflows,
    validate_inventory, validate_protected_files,
};

mod mutations;

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

fn read_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    let end = offset.checked_add(4).expect("snapshot u32 offset");
    let value = u32::from_le_bytes(
        bytes[*offset..end]
            .try_into()
            .expect("snapshot contains complete u32"),
    );
    *offset = end;
    value
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> u64 {
    let end = offset.checked_add(8).expect("snapshot u64 offset");
    let value = u64::from_le_bytes(
        bytes[*offset..end]
            .try_into()
            .expect("snapshot contains complete u64"),
    );
    *offset = end;
    value
}

fn bootstrap_tree(label: &str) -> TempTree {
    let tree = TempTree::new(label);
    let snapshot = fs::read(
        repo_root().join(".github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"),
    )
    .expect("read immutable bootstrap snapshot");
    assert!(snapshot.starts_with(b"GTABOOT1"));
    let mut offset = 8;
    let count = read_u32(&snapshot, &mut offset);
    assert_eq!(count, 26);
    for _ in 0..count {
        let path_length = read_u32(&snapshot, &mut offset) as usize;
        let data_length =
            usize::try_from(read_u64(&snapshot, &mut offset)).expect("snapshot data length");
        let path_end = offset.checked_add(path_length).expect("snapshot path end");
        let path = std::str::from_utf8(&snapshot[offset..path_end])
            .expect("snapshot path is UTF-8")
            .to_owned();
        offset = path_end;
        let data_end = offset.checked_add(data_length).expect("snapshot data end");
        let destination = tree.join(&path);
        fs::create_dir_all(destination.parent().expect("snapshot path parent"))
            .expect("create snapshot parent");
        fs::write(destination, &snapshot[offset..data_end]).expect("write snapshot file");
        offset = data_end;
    }
    assert_eq!(offset, snapshot.len());
    copy_directory(
        &repo_root().join(".github/trusted/desktop-supply-chain-policy"),
        &tree.join(".github/trusted/desktop-supply-chain-policy"),
    )
    .expect("copy protected trust root into bootstrap fixture");
    for workflow in [AUTHORITATIVE_PATH, BOOTSTRAP_PATH] {
        let destination = tree.join(workflow);
        fs::create_dir_all(destination.parent().expect("workflow parent"))
            .expect("create workflow parent");
        fs::copy(repo_root().join(workflow), destination)
            .expect("copy protected workflow into bootstrap fixture");
    }
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
        "desktop/Cargo.toml"
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
    for checkout in checkout_steps {
        assert_eq!(
            checkout.get("uses").and_then(serde_yaml_ng::Value::as_str),
            Some("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
        );
        let inputs = checkout
            .get("with")
            .and_then(serde_yaml_ng::Value::as_mapping)
            .expect("checkout inputs");
        for (key, expected) in [
            ("fetch-depth", serde_yaml_ng::Value::Number(0_u64.into())),
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
fn complete_final_fixture_passes_static_policy() {
    let tree = final_tree("final-static");
    let root = SafeRoot::new(&tree.path).expect("open final fixture");
    validate_inventory(&root).expect("validate final workflow inventory");
    validate_final_workflows(&root).expect("validate exact final workflows");
    validate_final_static(&root).expect("validate final static policy");
}

#[test]
fn compliant_declared_root_member_and_lock_evolution_pass() {
    let tree = final_tree("root-growth");
    replace(
        &tree.join("Cargo.toml"),
        "  \"crates/claw-gateway-client\",\n",
        "  \"crates/claw-gateway-client\",\n  \"crates/claw-new\",\n",
    );
    let manifest = tree.join("crates/claw-new/Cargo.toml");
    fs::create_dir_all(manifest.parent().expect("new member parent")).expect("create new member");
    fs::write(
        &manifest,
        r#"[package]
name = "claw-new"
description = "Compliant future root crate"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true
"#,
    )
    .expect("write new member manifest");
    fs::create_dir_all(tree.join("crates/claw-new/src")).expect("create new member source");
    fs::write(tree.join("crates/claw-new/src/lib.rs"), "").expect("write new member source");
    let mut lock = fs::read_to_string(tree.join("Cargo.lock")).expect("read root lock");
    lock.push_str(
        r#"
[[package]]
name = "claw-new"
version = "0.1.0"
"#,
    );
    fs::write(tree.join("Cargo.lock"), lock).expect("write evolved root lock");

    let root = SafeRoot::new(&tree.path).expect("open evolved fixture");
    let workspace = validate_final_static(&root).expect("accept compliant root growth");
    assert_eq!(
        workspace.members.get("crates/claw-new").map(String::as_str),
        Some("claw-new")
    );
    let isolation = TempTree::new("root-growth-metadata");
    validate_root_metadata(&root, &workspace, &local_metadata_tools(), &isolation.path)
        .expect("Cargo accepts compliant declared root member and lock evolution");
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
    validate_desktop_metadata(&root, &local_metadata_tools(), &isolation.path)
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
        validate_desktop_metadata_document(&root, &target, &document).is_err(),
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
    fs::create_dir_all(candidate.join("desktop")).expect("create relevant directory");
    fs::write(candidate.join("desktop/Cargo.toml"), "[workspace]\n")
        .expect("write late relevant path");
    run_git(&git, &candidate, &["add", "."]);
    run_git(&git, &candidate, &["commit", "--quiet", "-m", "head"]);
    let head = run_git(&git, &candidate, &["rev-parse", "HEAD"]);
    let isolated_home = fixture.join("home");
    fs::create_dir_all(&isolated_home).expect("create Git isolation home");
    let manifest = compute_manifest(&git, &trusted, &candidate, &isolated_home, &base, &head)
        .unwrap_or_else(|error| panic!("compute complete Git manifest in {fixture_path}: {error}"));
    assert_eq!(manifest.paths.len(), 351);
    assert!(has_policy_relevant_change(&manifest));
    assert!(
        manifest
            .paths
            .iter()
            .any(|entry| entry.path == "desktop/Cargo.toml")
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
    let cases = fs::read_to_string(root.join(
        ".github/trusted/desktop-supply-chain-policy/policy/final/crates/claw-security/tests/fixtures/desktop_supply_chain_policy/negative-cases.toml",
    ))
    .expect("read canonical P04f negative cases");
    let parsed: toml::Value = toml::from_str(&cases).expect("parse negative cases");
    let cases = parsed
        .get("case")
        .and_then(toml::Value::as_array)
        .expect("negative cases array");
    assert_eq!(cases.len(), 48);

    let reference = root.join(".github/trusted/desktop-supply-chain-policy/policy");
    let baseline_workflow: serde_yaml_ng::Value = serde_yaml_ng::from_str(
        &fs::read_to_string(reference.join("reference/rust-pr22.yml.fixture"))
            .expect("read original PR22 Rust workflow"),
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
    let mut names = BTreeSet::new();
    for case in cases {
        let name = case
            .get("name")
            .and_then(toml::Value::as_str)
            .expect("negative case name");
        let mutation = case
            .get("mutation")
            .and_then(toml::Value::as_str)
            .expect("negative mutation name");
        let expected = case
            .get("expected")
            .and_then(toml::Value::as_str)
            .expect("negative expected violation");
        assert!(!expected.is_empty());
        assert!(names.insert(name));

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
        let changed = workflow != baseline_workflow
            || macos != baseline_macos
            || root_deny != baseline_root_deny
            || deny != baseline_deny
            || audit != baseline_audit
            || desktop != baseline_desktop
            || app != baseline_app;
        assert!(
            changed,
            "archived mutation changed no policy data: {mutation}"
        );

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
        assert!(
            validate_final_workflows(&candidate).is_err()
                || validate_final_static(&candidate).is_err(),
            "trusted final policy accepted archived mutation {mutation} ({expected})"
        );
    }
    assert_eq!(names.len(), 48);

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
