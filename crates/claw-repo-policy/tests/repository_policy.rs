//! Repository-wide policy that prevents the legacy JavaScript surface from growing.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const FORBIDDEN_FILE_NAMES: &[&str] = &[
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
// No dist path is listed because the audited repository tracks no generated output.
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
// The legacy build roots. Each one may be listed above or absent from the tree,
// but never absent from both: dropping a root from the inventory while the file
// survives would silently un-audit it.
const LEGACY_BUILD_ROOTS: &[&str] = &[
    "Dockerfile",
    "package-lock.json",
    "package.json",
    "tsconfig.json",
];
// High-water mark for grandfathered TypeScript. This number may only ever be
// lowered; raising it re-opens the surface the ratchet exists to close.
const LEGACY_TYPESCRIPT_CEILING: usize = 18;
// Container definitions that may still build a Node runtime. Every entry must
// also appear in LEGACY_RUNTIME_INVENTORY, so the exemption disappears the
// moment the container itself leaves the inventory.
const LEGACY_CONTAINER_RUNTIMES: &[&str] = &["Dockerfile"];
const NODE_BASE_IMAGE_NAMES: &[&str] = &["node", "nodejs"];
const NODE_IMAGE: &str =
    "node:26-bookworm-slim@sha256:2d49d876e96237d76de412761cf05dbfe5aee325cc4406a4d41d5824c5bb8beb";
const ALLOWED_INSTALL_SCRIPTS: &[&str] = &["isolated-vm@7.0.0", "koffi@3.1.2"];
const EXACT_NODE_ROOT_REQUIREMENTS: &[(&str, &str)] = &[
    ("@github/copilot-sdk", "1.0.8"),
    ("@types/bunyan", "1.8.11"),
    ("@types/node", "26.1.2"),
    ("@types/restify", "8.5.12"),
    ("botbuilder", "4.23.3"),
    ("isolated-vm", "7.0.0"),
    ("pino", "10.3.1"),
    ("restify", "11.1.0"),
    ("ts-node", "10.9.2"),
    ("typescript", "7.0.2"),
    ("undici", "8.9.0"),
    ("ws", "8.21.1"),
];
const DOCKER_WORKFLOW_ACTION_PINS: &[&str] = &[
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
    "docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9",
    "docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051",
];
const SETUP_PYTHON_ACTION: &str = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065";
const ALLOWED_LEGACY_WORKFLOW_LINES: &[(&str, &str)] = &[
    (
        ".github/workflows/docker-publish.yml",
        "docker run --rm --entrypoint node \"$IMAGE_TAG\" --input-type=module -e '",
    ),
    (
        ".github/workflows/docker-publish.yml",
        "import { access } from \"node:fs/promises\";",
    ),
    (
        ".github/workflows/docker-publish.yml",
        "import { constants } from \"node:fs\";",
    ),
    (
        ".github/workflows/macos-packaging.yml",
        "if grep -RInE '(^|[[:space:]])(npm|npx|node|bun|pnpm)([[:space:]]|$)' \\",
    ),
    (
        ".github/workflows/macos-packaging.yml",
        "-iname 'node' -o -iname 'npm' -o -iname 'bun' -o -iname 'pnpm' -o \\",
    ),
    (
        ".github/workflows/macos-packaging.yml",
        "-iname '*.js' -o -iname '*.mjs' -o -iname '*.cjs' -o -iname '*.node' \\",
    ),
];
const ALLOWED_ADVERSARIAL_SHELL_FIXTURES: &[&str] =
    &[".github/fixtures/security-tools/bash-env-poison.sh"];

// Every exception must name one inert fixture file. This is intentionally empty:
// the current compat trees contain JSON contract data, but no script fixtures.
const ALLOWED_COMPAT_FIXTURES: &[&str] = &[];

#[test]
fn repository_legacy_javascript_surface_does_not_grow() {
    let root = workspace_root();
    let mut sorted_inventory = LEGACY_RUNTIME_INVENTORY.to_vec();
    sorted_inventory.sort_unstable();
    sorted_inventory.dedup();
    assert_eq!(
        sorted_inventory.len(),
        LEGACY_RUNTIME_INVENTORY.len(),
        "legacy runtime inventory contains duplicate paths"
    );
    assert!(
        LEGACY_RUNTIME_INVENTORY
            .iter()
            .filter(|path| has_legacy_typescript_extension(path))
            .count()
            <= LEGACY_TYPESCRIPT_CEILING,
        "the binding legacy TypeScript ceiling was raised instead of lowered"
    );
    for required_root in LEGACY_BUILD_ROOTS {
        assert!(
            LEGACY_RUNTIME_INVENTORY.contains(required_root) || !root.join(required_root).exists(),
            "legacy build root left the explicit inventory while it still exists: {required_root}"
        );
    }
    for exempt_container in LEGACY_CONTAINER_RUNTIMES {
        assert!(
            LEGACY_RUNTIME_INVENTORY.contains(exempt_container),
            "container runtime exemption escapes the legacy inventory: {exempt_container}"
        );
    }
    assert!(
        stale_inventory_entries(&root, LEGACY_RUNTIME_INVENTORY).is_empty(),
        "the legacy inventory must shrink in the same commit that deletes its files: {:?}",
        stale_inventory_entries(&root, LEGACY_RUNTIME_INVENTORY)
    );
    for allowed in LEGACY_RUNTIME_INVENTORY {
        assert!(
            !allowed.starts_with('/') && !allowed.contains('\\') && !allowed.contains("/../"),
            "legacy runtime inventory path is not repository-relative and normalized: {allowed}"
        );
    }
    for allowed in ALLOWED_COMPAT_FIXTURES {
        assert!(
            allowed.starts_with("compat/legacy/") || allowed.starts_with("compat/upstream/"),
            "compat fixture allowlist entry escapes the compatibility trees: {allowed}"
        );
        assert!(
            !FORBIDDEN_DIRECTORY_NAMES.iter().any(|name| allowed
                .split('/')
                .any(|component| component.eq_ignore_ascii_case(name))),
            "dependency directories cannot be allowlisted: {allowed}"
        );
    }
    for allowed in ALLOWED_ADVERSARIAL_SHELL_FIXTURES {
        assert!(
            allowed.starts_with(".github/fixtures/security-tools/")
                && Path::new(allowed).extension() == Some(OsStr::new("sh")),
            "adversarial shell fixture allowlist entry escapes its frozen tree: {allowed}"
        );
        assert!(
            root.join(allowed).is_file(),
            "allowlisted adversarial shell fixture is missing: {allowed}"
        );
    }
    let mut allowed_artifacts = LEGACY_RUNTIME_INVENTORY.to_vec();
    allowed_artifacts.extend_from_slice(ALLOWED_COMPAT_FIXTURES);
    let mut violations =
        scan_tree(&root, &allowed_artifacts).expect("scan repository policy surface");
    violations.extend(scan_git_index(&root).expect("scan tracked repository entry modes"));
    violations.extend(scan_workflows(&root).expect("scan workflow command policy"));
    violations.extend(scan_local_actions(&root).expect("scan repository-owned action runtimes"));
    violations.extend(scan_containers(&root).expect("scan container runtime policy"));
    violations.sort();

    assert!(
        violations.is_empty(),
        "the legacy JavaScript/Node surface may only shrink; unlisted artifacts are forbidden:\n{}",
        violations.join("\n")
    );
}

#[test]
fn new_typescript_path_outside_legacy_inventory_is_rejected() {
    let fixture = TemporaryTree::new("new-typescript");
    fixture.write("src/index.ts", b"grandfathered");
    fixture.write("src/newFeature.ts", b"new");

    let violations =
        scan_tree(fixture.path(), &["src/index.ts"]).expect("scan ratchet addition fixture");

    assert_eq!(violations, ["src/newFeature.ts"]);
}

#[test]
fn removing_allowlisted_legacy_entry_keeps_ratchet_green() {
    let fixture = TemporaryTree::new("legacy-removal");
    fixture.write("package.json", b"grandfathered");
    fixture.write("src/index.ts", b"grandfathered");
    let allowlist = ["package.json", "src/index.ts"];
    assert!(
        scan_tree(fixture.path(), &allowlist)
            .expect("scan complete legacy fixture")
            .is_empty()
    );

    fs::remove_file(fixture.path().join("src/index.ts")).expect("remove grandfathered entry");

    assert!(
        scan_tree(fixture.path(), &allowlist)
            .expect("scan reduced legacy fixture")
            .is_empty(),
        "deleting an allowlisted legacy entry must not require a replacement"
    );
}

#[test]
fn other_planted_violations_are_detected() {
    let fixture = TemporaryTree::new("planted");
    let planted_files = [
        "package.json",
        "nested/package-lock.json",
        "nested/npm-shrinkwrap.json",
        "nested/PACKAGE.JSON",
        "nested/yarn.lock",
        "nested/pnpm-lock.yaml",
        "nested/hidden.cjs",
        "nested/component.tsx",
        "nested/component.JS",
        "compat/legacy/fixtures/not-allowlisted.mjs",
    ];
    for relative in planted_files {
        fixture.write(relative, b"fixture");
    }
    fixture.write("vendor/node_modules", b"symlink-shaped fixture");

    let violations = scan_tree(fixture.path(), &[]).expect("scan planted violations");

    for relative in planted_files {
        assert!(
            violations.iter().any(|violation| violation == relative),
            "gate missed planted violation: {relative}; found {violations:?}"
        );
    }
    assert!(
        violations
            .iter()
            .any(|violation| violation == "vendor/node_modules"),
        "gate missed planted node_modules path: {violations:?}"
    );
}

#[test]
fn cargo_target_directories_are_excluded_from_legacy_surface() {
    let fixture = TemporaryTree::new("cargo-target");
    for relative in [
        "target/doc/search.index/root.js",
        "target/doc/trait.impl/core/marker/impl.js",
        "desktop/target/doc/search.index/desktop.js",
        "workspaces/future/target/doc/trait.impl/future.js",
    ] {
        fixture.write(relative, b"generated rustdoc output");
    }

    assert!(
        scan_tree(fixture.path(), &[])
            .expect("scan Cargo target fixture")
            .is_empty(),
        "generated files below exact target directory components must be ignored"
    );
}

#[test]
fn cargo_target_directory_match_is_exact() {
    let fixture = TemporaryTree::new("cargo-target-boundary");
    fixture.write("src/target/doc/search.index/generated.js", b"generated");
    fixture.write("targeted/doc/search.index/generated.js", b"prohibited");
    fixture.write("ordinary/generated.js", b"prohibited");
    fixture.write("ordinary/newFeature.ts", b"prohibited");

    let violations = scan_tree(fixture.path(), &[]).expect("scan Cargo target boundary fixture");

    assert_eq!(
        violations,
        [
            "ordinary/generated.js",
            "ordinary/newFeature.ts",
            "targeted/doc/search.index/generated.js"
        ]
    );
}

#[test]
fn compat_allowlist_is_exact_not_a_prefix() {
    let fixture = TemporaryTree::new("allowlist");
    fixture.write("compat/legacy/fixtures/inert.ts", b"fixture");
    fixture.write("compat/legacy/fixtures/sibling.ts", b"fixture");
    fixture.write("outside/fixtures/inert.ts", b"fixture");

    let violations = scan_tree(fixture.path(), &["compat/legacy/fixtures/inert.ts"])
        .expect("scan exact allowlist");

    assert_eq!(
        violations,
        [
            "compat/legacy/fixtures/sibling.ts",
            "outside/fixtures/inert.ts"
        ]
    );
}

#[test]
fn workflow_commands_are_checked_without_rejecting_inert_search_patterns() {
    let fixture = TemporaryTree::new("workflows");
    fixture.write(
        ".github/workflows/macos-packaging.yml",
        b"          if grep -RInE '(^|[[:space:]])(npm|npx|node|bun|pnpm)([[:space:]]|$)' \\\n",
    );
    fixture.write(
        ".github/workflows/direct.yml",
        br#"jobs:
  direct:
    steps:
      - "uses": actions/setup-node@v4
      - "run": npm.cmd ci
      - {run: sh -c 'npm ci'}
      - "run": "n\u0070m ci"
      - run: n'p'm ci
      - run: NODE.EXE script
      - run: corepack yarn
"#,
    );
    fixture.write(
        "tools/local/action.yml",
        br#"name: local
runs:
  "using": "n\u006fde20"
  main: entrypoint
"#,
    );
    fixture.write(
        "vendor/composite/action.yaml",
        b"name: composite\nruns:\n  using: composite\n  steps:\n    - run: pnpm install\n",
    );

    let mut violations = scan_workflows(fixture.path()).expect("scan planted workflow commands");
    violations.extend(scan_local_actions(fixture.path()).expect("scan planted local action"));

    for expected in [
        "actions/setup-node",
        "npm",
        "node",
        "corepack",
        "yarn",
        "pnpm",
    ] {
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "workflow gate missed {expected}: {violations:?}"
        );
    }
    assert!(
        violations
            .iter()
            .all(|violation| !violation.contains("macos-packaging.yml")),
        "inert search patterns must remain valid: {violations:?}"
    );
}

#[test]
fn container_definitions_cannot_reintroduce_a_node_runtime() {
    let fixture = TemporaryTree::new("containers");
    fixture.write(
        "services/web/Dockerfile",
        b"FROM node:20-bookworm-slim\nRUN npm install\nCMD [\"node\", \"dist/index.js\"]\n",
    );
    fixture.write(
        "services/api/Dockerfile.build",
        b"# FROM node:20 is only a comment\nFROM --platform=linux/amd64 docker.io/library/node:22 AS builder\nRUN corepack yarn install\n",
    );
    fixture.write(
        "packaging/linux/Dockerfile.build",
        b"FROM rust:1.97.0-bookworm@sha256:aaaa\nRUN apt-get install -y python3\n",
    );
    fixture.write("packaging/linux/notes.txt", b"FROM node:20\n");

    let violations = scan_containers(fixture.path()).expect("scan planted container definitions");

    for expected in [
        "services/web/Dockerfile:1: node base image node",
        "services/web/Dockerfile:2: forbidden container token npm",
        "services/web/Dockerfile:3: forbidden container token node",
        "services/api/Dockerfile.build:2: node base image node",
        "services/api/Dockerfile.build:3: forbidden container token corepack",
        "services/api/Dockerfile.build:3: forbidden container token yarn",
    ] {
        assert!(
            violations.iter().any(|violation| violation == expected),
            "container gate missed {expected}: {violations:?}"
        );
    }
    assert!(
        violations
            .iter()
            .all(|violation| !violation.starts_with("services/api/Dockerfile.build:1")),
        "commented instructions must not be flagged: {violations:?}"
    );
    assert!(
        violations
            .iter()
            .all(|violation| !violation.starts_with("packaging/")),
        "a pinned Rust builder and a plain text file must stay clean: {violations:?}"
    );
}

#[test]
fn an_inventoried_container_is_exempt_only_while_it_is_inventoried() {
    let fixture = TemporaryTree::new("container-exemption");
    fixture.write(
        "Dockerfile",
        format!(
            "FROM {NODE_IMAGE} AS builder\n\
             COPY package.json package-lock.json ./\n\
             RUN npm ci --ignore-scripts --no-audit --no-fund && \\\n\
             npm rebuild --foreground-scripts isolated-vm@7.0.0 koffi@3.1.2\n\
             FROM {NODE_IMAGE}\n\
             COPY --from=builder /app/package.json /app/package-lock.json ./\n\
             ENV NODE_ENV=\"production\"\n\
             ENV COPILOT_CLI_PATH=\"/app/node_modules/.bin/copilot\"\n"
        )
        .as_bytes(),
    );
    fixture.write(
        "package.json",
        br#"{
  "dependencies": {
    "@github/copilot-sdk": "1.0.8",
    "botbuilder": "4.23.3",
    "pino": "10.3.1",
    "restify": "11.1.0",
    "undici": "8.9.0",
    "ws": "8.21.1"
  },
  "optionalDependencies": {"isolated-vm": "7.0.0"},
  "devDependencies": {
    "@types/bunyan": "1.8.11",
    "@types/node": "26.1.2",
    "@types/restify": "8.5.12",
    "ts-node": "10.9.2",
    "typescript": "7.0.2"
  },
  "allowScripts": {
    "isolated-vm@7.0.0": true,
    "koffi@3.1.2": true,
    "dtrace-provider": false
  }
}"#,
    );
    fixture.write(
        "package-lock.json",
        br#"{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "@github/copilot-sdk": "1.0.8",
        "botbuilder": "4.23.3",
        "pino": "10.3.1",
        "restify": "11.1.0",
        "undici": "8.9.0",
        "ws": "8.21.1"
      },
      "optionalDependencies": {"isolated-vm": "7.0.0"},
      "devDependencies": {
        "@types/bunyan": "1.8.11",
        "@types/node": "26.1.2",
        "@types/restify": "8.5.12",
        "ts-node": "10.9.2",
        "typescript": "7.0.2"
      }
    },
    "node_modules/@github/copilot": {"version": "1.0.75"},
    "node_modules/@github/copilot-sdk": {"version": "1.0.8"}
  }
}"#,
    );

    assert!(
        LEGACY_CONTAINER_RUNTIMES
            .iter()
            .all(|exempt| LEGACY_RUNTIME_INVENTORY.contains(exempt)),
        "an exempt container escaped the legacy inventory"
    );
    assert!(
        scan_containers(fixture.path())
            .expect("scan exempt container")
            .is_empty()
    );

    fixture.write("second/Dockerfile", b"FROM node:20\n");

    assert_eq!(
        scan_containers(fixture.path()).expect("scan unexempt sibling"),
        [
            "second/Dockerfile:1: forbidden container token node",
            "second/Dockerfile:1: node base image node"
        ]
    );
}

#[test]
fn legacy_node_supply_chain_rejects_mutable_or_uncoupled_inputs() {
    let root = workspace_root();
    let package = fs::read_to_string(root.join("package.json")).expect("read package manifest");
    let lock = fs::read_to_string(root.join("package-lock.json")).expect("read package lock");
    let docker = fs::read_to_string(root.join("Dockerfile")).expect("read Dockerfile");
    assert!(
        legacy_node_supply_chain_violations(&package, &lock, &docker).is_empty(),
        "repository Node supply-chain roots are not compliant"
    );

    for (label, mutated, expected) in [
        (
            "mutable base image",
            docker.replacen(
                &format!("{NODE_IMAGE} AS builder"),
                "node:26-bookworm-slim AS builder",
                1,
            ),
            "base image is not digest-pinned",
        ),
        (
            "optional lock copy",
            docker.replace(
                "COPY package.json package-lock.json ./",
                "COPY package.json package-lock.json* ./",
            ),
            "exact package roots",
        ),
        (
            "mutable install",
            docker.replace("npm ci --ignore-scripts", "npm install"),
            "npm install is forbidden",
        ),
        (
            "mutable command runner",
            docker.replace("./node_modules/.bin/tsc", "npx tsc"),
            "npx network fallback is forbidden",
        ),
        (
            "remote installer",
            format!("{docker}\nRUN curl -fsSL https://gh.io/copilot-install | bash\n"),
            "remote Copilot installer",
        ),
    ] {
        let violations = legacy_node_supply_chain_violations(&package, &lock, &mutated);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "{label} failed through the wrong rule: {violations:?}"
        );
    }

    let mutable_package = package.replace(
        "\"@github/copilot-sdk\": \"1.0.8\"",
        "\"@github/copilot-sdk\": \"^1.0.8\"",
    );
    assert!(
        legacy_node_supply_chain_violations(&mutable_package, &lock, &docker)
            .iter()
            .any(|violation| violation.contains("exact versions")),
        "mutable package constraint unexpectedly passed"
    );
}

#[test]
fn legacy_runtime_updates_and_production_isolation_fail_closed() {
    let root = workspace_root();
    let config = fs::read_to_string(root.join("src/config.ts")).expect("read runtime config");
    let executor =
        fs::read_to_string(root.join("src/engine/toolExecutor.ts")).expect("read tool executor");
    let updater =
        fs::read_to_string(root.join("src/updater/sdkUpdater.ts")).expect("read SDK updater");
    assert!(
        legacy_runtime_source_violations(&config, &executor, &updater).is_empty(),
        "legacy runtime update and isolation policy is not fail-closed"
    );

    for (label, config, executor, updater, expected) in [
        (
            "auto-update bypass",
            config.replace("if (AUTO_UPDATE) {", "if (false) {"),
            executor.clone(),
            updater.clone(),
            "AUTO_UPDATE=true must fail configuration",
        ),
        (
            "production node:vm fallback",
            config.clone(),
            executor.replace(
                "if (nodeEnvironment === \"production\")",
                "if (nodeEnvironment === \"disabled-production\")",
            ),
            updater.clone(),
            "production must reject reduced node:vm isolation",
        ),
        (
            "mutable updater",
            config.clone(),
            executor.clone(),
            format!("{updater}\nconst removedInstaller = \"gh.io/copilot-install\";\n"),
            "mutable runtime update logic is forbidden",
        ),
    ] {
        let violations = legacy_runtime_source_violations(&config, &executor, &updater);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "{label} failed through the wrong rule: {violations:?}"
        );
    }
}

#[test]
fn python_compatibility_policy_is_interpreter_and_hash_locked() {
    let root = workspace_root();
    let workflow =
        fs::read_to_string(root.join(".github/workflows/rust.yml")).expect("read Rust workflow");
    let requirements = fs::read_to_string(root.join("compat/legacy/scripts/requirements.txt"))
        .expect("read Python requirements");
    assert!(
        python_supply_chain_violations(&workflow, &requirements).is_empty(),
        "Python compatibility policy is not fully locked"
    );
    let (_, remaining_requirements) = requirements
        .split_once("\njsonschema==")
        .expect("requirements contain the locked jsonschema entry");
    let unhashed_requirements = format!("attrs==26.1.0 \\\njsonschema=={remaining_requirements}");

    for (label, workflow, requirements, expected) in [
        (
            "mutable setup action",
            workflow.replace(SETUP_PYTHON_ACTION, "actions/setup-python@v6"),
            requirements.clone(),
            "setup-python action is not pinned",
        ),
        (
            "unhashed install",
            workflow.replace("            --require-hashes \\\n", ""),
            requirements.clone(),
            "pip install does not require hashes",
        ),
        (
            "unhashed requirement",
            workflow.clone(),
            unhashed_requirements,
            "requirement entry has no SHA-256 hash",
        ),
    ] {
        let violations = python_supply_chain_violations(&workflow, &requirements);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "{label} failed through the wrong rule: {violations:?}"
        );
    }
}

#[test]
fn docker_publish_builds_validates_and_pushes_one_image() {
    let workflow =
        fs::read_to_string(workspace_root().join(".github/workflows/docker-publish.yml"))
            .expect("read Docker publish workflow");
    assert!(
        docker_publish_violations(&workflow).is_empty(),
        "Docker publish workflow violates the build-once contract"
    );

    for (label, mutated, expected) in [
        (
            "mutable action",
            workflow.replace(
                DOCKER_WORKFLOW_ACTION_PINS[1],
                "docker/setup-buildx-action@v3",
            ),
            "Docker workflow action pin changed",
        ),
        (
            "missing pull request build",
            workflow.replacen("  pull_request:\n", "", 1),
            "secret-free pull request build is missing",
        ),
        (
            "second image build",
            workflow.replace(
                "docker buildx build \\",
                "docker buildx build \\\n          docker buildx build \\",
            ),
            "Docker publish workflow must build exactly once",
        ),
        (
            "broken digest parser",
            workflow.replace(
                "for (i = 1; i <= NF; i++) if ($i ~ /^sha256:/) print $i",
                "print $2",
            ),
            "Docker publish digest parser changed",
        ),
    ] {
        let violations = docker_publish_violations(&mutated);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "{label} failed through the wrong rule: {violations:?}"
        );
    }
}

#[test]
fn inventory_entries_that_no_longer_exist_are_reported_as_stale() {
    let fixture = TemporaryTree::new("stale-inventory");
    fixture.write("package.json", b"grandfathered");
    fixture.write("src/index.ts", b"grandfathered");
    let inventory = ["package.json", "src/index.ts", "src/config.ts"];

    assert_eq!(
        stale_inventory_entries(fixture.path(), &inventory),
        ["src/config.ts"]
    );

    fs::remove_file(fixture.path().join("src/index.ts")).expect("remove grandfathered entry");

    assert_eq!(
        stale_inventory_entries(fixture.path(), &inventory),
        ["src/config.ts", "src/index.ts"],
        "deleting a file must force its inventory entry out in the same commit"
    );
}

#[test]
fn tracked_symlink_and_gitlink_modes_are_rejected() {
    let fixture = b"100644 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0\tREADME.md\0\
120000 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 0\tlinked-runtime\0\
160000 cccccccccccccccccccccccccccccccccccccccc 0\tvendor/runtime\0";

    assert_eq!(
        forbidden_index_entries(fixture),
        [
            "linked-runtime (tracked symbolic link)",
            "vendor/runtime (tracked gitlink)"
        ]
    );
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository policy crate is under workspace/crates")
        .to_path_buf()
}

fn scan_tree(root: &Path, allowlist: &[&str]) -> io::Result<Vec<String>> {
    let mut violations = Vec::new();
    walk(root, root, allowlist, &mut violations)?;
    violations.sort();
    Ok(violations)
}

fn walk(
    root: &Path,
    directory: &Path,
    allowlist: &[&str],
    violations: &mut Vec<String>,
) -> io::Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::path);

    for entry in entries {
        let path = entry.path();
        let relative = normalized_relative(root, &path);
        if relative == ".git" {
            continue;
        }

        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            violations.push(format!("{relative} (symbolic link)"));
            continue;
        }
        if file_type.is_dir() && entry.file_name() == OsStr::new("target") {
            continue;
        }
        if relative.starts_with(".github/fixtures/security-tools/")
            && path.extension() == Some(OsStr::new("sh"))
            && !ALLOWED_ADVERSARIAL_SHELL_FIXTURES.contains(&relative.as_str())
        {
            violations.push(format!("{relative} (unapproved adversarial shell fixture)"));
            continue;
        }
        if is_forbidden_directory(&path) && !allowlist.contains(&relative.as_str()) {
            violations.push(relative);
            continue;
        }
        if file_type.is_dir() {
            walk(root, &path, allowlist, violations)?;
        } else if is_forbidden_file(&path) && !allowlist.contains(&relative.as_str()) {
            violations.push(relative);
        }
    }

    Ok(())
}

fn scan_git_index(root: &Path) -> io::Result<Vec<String>> {
    let output = Command::new("git")
        .args(["ls-files", "--stage", "-z"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(forbidden_index_entries(&output.stdout))
}

fn forbidden_index_entries(output: &[u8]) -> Vec<String> {
    let mut violations = Vec::new();
    for entry in output
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let entry = String::from_utf8_lossy(entry);
        let Some((metadata, path)) = entry.split_once('\t') else {
            violations.push(format!("malformed git index entry: {entry}"));
            continue;
        };
        let mode = metadata.split_whitespace().next().unwrap_or_default();
        match mode {
            "120000" => violations.push(format!("{path} (tracked symbolic link)")),
            "160000" => violations.push(format!("{path} (tracked gitlink)")),
            _ => {}
        }
    }
    violations.sort();
    violations
}

fn scan_workflows(root: &Path) -> io::Result<Vec<String>> {
    let directory = root.join(".github").join("workflows");
    if !directory.exists() {
        return Ok(Vec::new());
    }
    if fs::symlink_metadata(&directory)?.file_type().is_symlink() {
        return Ok(Vec::new());
    }

    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::path);
    let mut violations = Vec::new();
    for entry in entries {
        let path = entry.path();
        if entry.file_type()?.is_symlink() {
            continue;
        }
        let extension = path.extension().and_then(OsStr::to_str);
        if !matches!(extension, Some("yml" | "yaml")) {
            continue;
        }
        let relative = normalized_relative(root, &path);
        let workflow = fs::read_to_string(&path)?;
        scan_policy_document(&relative, &workflow, &mut violations);
    }
    violations.sort();
    Ok(violations)
}

fn scan_local_actions(root: &Path) -> io::Result<Vec<String>> {
    let mut action_files = Vec::new();
    collect_action_files(root, &mut action_files)?;
    action_files.sort();
    let mut violations = Vec::new();
    for path in action_files {
        let relative = normalized_relative(root, &path);
        let action = fs::read_to_string(path)?;
        scan_policy_document(&relative, &action, &mut violations);
    }
    violations.sort();
    Ok(violations)
}

fn collect_action_files(directory: &Path, action_files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if entry.file_name() == OsStr::new(".git") {
                continue;
            }
            collect_action_files(&path, action_files)?;
        } else if path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| {
                name.eq_ignore_ascii_case("action.yml") || name.eq_ignore_ascii_case("action.yaml")
            })
        {
            action_files.push(path);
        }
    }
    Ok(())
}

fn stale_inventory_entries(root: &Path, inventory: &[&str]) -> Vec<String> {
    let mut stale = inventory
        .iter()
        .filter(|relative| !root.join(relative).exists())
        .map(|relative| (*relative).to_owned())
        .collect::<Vec<_>>();
    stale.sort();
    stale
}

fn scan_containers(root: &Path) -> io::Result<Vec<String>> {
    let mut container_files = Vec::new();
    collect_container_files(root, &mut container_files)?;
    container_files.sort();
    let mut violations = Vec::new();
    for path in container_files {
        let relative = normalized_relative(root, &path);
        if LEGACY_CONTAINER_RUNTIMES.contains(&relative.as_str()) {
            let package = fs::read_to_string(root.join("package.json"))?;
            let lock = fs::read_to_string(root.join("package-lock.json"))?;
            let docker = fs::read_to_string(path)?;
            violations.extend(
                legacy_node_supply_chain_violations(&package, &lock, &docker)
                    .into_iter()
                    .map(|violation| format!("{relative}: {violation}")),
            );
            continue;
        }
        let document = fs::read_to_string(path)?;
        scan_container_document(&relative, &document, &mut violations);
    }
    violations.sort();
    Ok(violations)
}

fn legacy_node_supply_chain_violations(
    package_json: &str,
    package_lock: &str,
    dockerfile: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    if package_json.contains("\": \"^") || package_json.contains("\": \"~") {
        violations.push("package.json direct dependencies must use exact versions".to_owned());
    }
    for (name, version) in EXACT_NODE_ROOT_REQUIREMENTS {
        let exact = format!("\"{name}\": \"{version}\"");
        if !package_json.contains(&exact) {
            violations.push(format!(
                "package.json direct dependencies must use exact versions: {exact}"
            ));
        }
        if !package_lock.contains(&exact) {
            violations.push(format!(
                "package-lock.json does not bind direct requirement: {exact}"
            ));
        }
    }
    for required in [
        "\"isolated-vm@7.0.0\": true",
        "\"koffi@3.1.2\": true",
        "\"dtrace-provider\": false",
    ] {
        if !package_json.contains(required) {
            violations.push(format!("package.json is missing install policy {required}"));
        }
    }
    for required in [
        "\"lockfileVersion\": 3",
        "\"@github/copilot-sdk\": \"1.0.8\"",
        "\"node_modules/@github/copilot\": {",
        "\"version\": \"1.0.75\"",
        "\"node_modules/@github/copilot-sdk\": {",
    ] {
        if !package_lock.contains(required) {
            violations.push(format!(
                "package-lock.json is missing locked input {required}"
            ));
        }
    }

    let from_lines = dockerfile
        .lines()
        .map(str::trim)
        .filter(|line| line.to_ascii_lowercase().starts_with("from "))
        .collect::<Vec<_>>();
    if from_lines.len() != 2
        || from_lines.iter().any(|line| {
            !line
                .split_ascii_whitespace()
                .any(|token| token == NODE_IMAGE)
        })
    {
        violations.push("Dockerfile base image is not digest-pinned exactly".to_owned());
    }
    for required in [
        "COPY package.json package-lock.json ./",
        "COPY --from=builder /app/package.json /app/package-lock.json ./",
        "npm ci --ignore-scripts --no-audit --no-fund",
        "npm rebuild --foreground-scripts isolated-vm@7.0.0 koffi@3.1.2",
        "ENV NODE_ENV=\"production\"",
        "ENV COPILOT_CLI_PATH=\"/app/node_modules/.bin/copilot\"",
    ] {
        if !dockerfile.contains(required) {
            violations.push(format!(
                "Dockerfile does not couple exact package roots: {required}"
            ));
        }
    }
    for forbidden in [
        "npm install",
        "npx ",
        "package-lock.json*",
        "gh.io/copilot-install",
    ] {
        if dockerfile.contains(forbidden) {
            let label = if forbidden == "npm install" {
                "npm install is forbidden"
            } else if forbidden == "npx " {
                "npx network fallback is forbidden"
            } else if forbidden == "gh.io/copilot-install" {
                "remote Copilot installer is forbidden"
            } else {
                "optional package lock copy is forbidden"
            };
            violations.push(label.to_owned());
        }
    }
    let rebuild = format!(
        "npm rebuild --foreground-scripts {}",
        ALLOWED_INSTALL_SCRIPTS.join(" ")
    );
    if !dockerfile.contains(&rebuild) {
        violations.push("Dockerfile install-script allowlist changed".to_owned());
    }
    violations.sort();
    violations
}

fn legacy_runtime_source_violations(config: &str, executor: &str, updater: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for required in [
        "if (AUTO_UPDATE) {",
        "AUTO_UPDATE is unsupported: update package.json and package-lock.json through review",
    ] {
        if !config.contains(required) {
            violations.push(format!(
                "AUTO_UPDATE=true must fail configuration: missing {required}"
            ));
        }
    }
    for required in [
        "if (nodeEnvironment === \"production\")",
        "isolated-vm is required in production; node:vm provides reduced isolation and is development-only",
    ] {
        if !executor.contains(required) {
            violations.push(format!(
                "production must reject reduced node:vm isolation: missing {required}"
            ));
        }
    }
    if !updater.contains("export async function checkForUpdates(): Promise<VersionInfo>")
        || [
            "performSdkUpdate",
            "performCliUpdate",
            "gh.io/copilot-install",
            "[\"update\", \"@github/copilot-sdk\"]",
        ]
        .iter()
        .any(|forbidden| updater.contains(forbidden))
    {
        violations.push("mutable runtime update logic is forbidden".to_owned());
    }
    violations.sort();
    violations
}

fn python_supply_chain_violations(workflow: &str, requirements: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let setup_python_use = format!("uses: {SETUP_PYTHON_ACTION}");
    for required in [
        setup_python_use.as_str(),
        "python-version: \"3.13.5\"",
        "python3 -m pip install",
        "--require-hashes",
        "--requirement compat/legacy/scripts/requirements.txt",
        "python3 compat/legacy/scripts/validate.py",
    ] {
        if !workflow.contains(required) {
            let label = if required.starts_with("uses:") {
                "setup-python action is not pinned"
            } else if required == "--require-hashes" {
                "pip install does not require hashes"
            } else {
                "Python workflow invocation is not exact"
            };
            violations.push(format!("{label}: {required}"));
        }
    }

    let mut current_requirement = None;
    let mut current_has_hash = false;
    for line in requirements.lines().filter(|line| !line.trim().is_empty()) {
        if line.starts_with(char::is_whitespace) {
            if line
                .trim()
                .strip_prefix("--hash=sha256:")
                .is_some_and(|hash| {
                    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            {
                current_has_hash = true;
            }
            continue;
        }
        if let Some(previous) = current_requirement.replace(line) {
            if !current_has_hash {
                violations.push(format!("requirement entry has no SHA-256 hash: {previous}"));
            }
        }
        current_has_hash = false;
        if !line.contains("==") {
            violations.push(format!("Python requirement is not exact: {line}"));
        }
    }
    if let Some(previous) = current_requirement {
        if !current_has_hash {
            violations.push(format!("requirement entry has no SHA-256 hash: {previous}"));
        }
    }
    violations.sort();
    violations
}

fn docker_publish_violations(workflow: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if !workflow.contains("on:\n  pull_request:\n") {
        violations.push("Docker secret-free pull request build is missing".to_owned());
    }
    for pin in DOCKER_WORKFLOW_ACTION_PINS {
        if !workflow.contains(&format!("uses: {pin}")) {
            violations.push(format!("Docker workflow action pin changed: {pin}"));
        }
    }
    let docker_action_count = workflow
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("uses: docker/"))
        .count();
    if docker_action_count != 3 || workflow.contains("docker/build-push-action@") {
        violations.push("Docker workflow action set changed".to_owned());
    }
    if workflow.matches("docker buildx build \\").count() != 1 {
        violations.push("Docker publish workflow must build exactly once".to_owned());
    }
    for required in [
        "- name: Validate exact built image",
        "EXPECTED_IMAGE_ID: ${{ steps.build.outputs.image-id }}",
        "test \"$(docker image inspect --format '{{.Id}}' \"$IMAGE_TAG\")\" = \"$EXPECTED_IMAGE_ID\"",
        "await access(\"/app/package-lock.json\", constants.R_OK);",
        "await access(process.env.COPILOT_CLI_PATH, constants.X_OK);",
        "selectIsolationMode(false, \"production\")",
        "- name: Log in to Docker Hub\n        if: github.event_name != 'pull_request'",
        "- name: Push the validated image digest\n        if: github.event_name != 'pull_request'",
        "for (i = 1; i <= NF; i++) if ($i ~ /^sha256:/) print $i",
        "test \"$digest\" = \"$pushed_digest\"",
    ] {
        if !workflow.contains(required) {
            let label = if required.contains("for (i = 1") {
                "Docker publish digest parser changed"
            } else {
                "Docker build/validate/push coupling changed"
            };
            violations.push(format!("{label}: {required}"));
        }
    }
    violations.sort();
    violations
}

fn collect_container_files(directory: &Path, container_files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if matches!(entry.file_name().to_str(), Some(".git" | "target")) {
                continue;
            }
            collect_container_files(&path, container_files)?;
        } else if path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| {
                let lower = name.to_ascii_lowercase();
                matches!(lower.as_str(), "dockerfile" | "containerfile")
                    || lower.starts_with("dockerfile.")
                    || lower.starts_with("containerfile.")
                    || lower.ends_with(".dockerfile")
            })
        {
            container_files.push(path);
        }
    }
    Ok(())
}

// A container definition can reintroduce the whole Node runtime without writing
// a single forbidden token into a workflow, because the build happens inside
// the image. The workflow scanner cannot see that, so containers are scanned
// directly.
fn scan_container_document(path: &str, document: &str, violations: &mut Vec<String>) {
    for (line_index, line) in document.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let line_number = line_index + 1;
        if let Some(image) = base_image_reference(trimmed)
            && NODE_BASE_IMAGE_NAMES.contains(&image.as_str())
        {
            violations.push(format!("{path}:{line_number}: node base image {image}"));
        }
        let mut commands = std::collections::BTreeSet::new();
        let decoded = decode_policy_escapes(trimmed);
        for token in decoded.split(|character: char| {
            !(character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '.' | '/' | '\\'))
        }) {
            let command = normalized_command_token(token);
            if is_forbidden_workflow_token(&command) {
                commands.insert(command);
            }
        }
        violations.extend(
            commands.into_iter().map(|command| {
                format!("{path}:{line_number}: forbidden container token {command}")
            }),
        );
    }
}

// Returns the bare repository name of a `FROM` instruction: no registry, no
// tag, no digest. `--platform=` flags and `AS <stage>` aliases are discarded so
// they cannot hide the image behind an option.
fn base_image_reference(line: &str) -> Option<String> {
    let mut tokens = line.split_ascii_whitespace();
    if !tokens.next()?.eq_ignore_ascii_case("from") {
        return None;
    }
    let reference = tokens.find(|token| !token.starts_with("--"))?;
    let repository = reference
        .split_once('@')
        .map_or(reference, |(repository, _)| repository);
    let repository = repository
        .rsplit_once(':')
        .filter(|(head, _)| !head.is_empty())
        .map_or(repository, |(repository, _)| repository);
    Some(
        repository
            .rsplit('/')
            .next()
            .unwrap_or(repository)
            .to_ascii_lowercase(),
    )
}

fn scan_policy_document(path: &str, document: &str, violations: &mut Vec<String>) {
    for (line_index, line) in document.lines().enumerate() {
        let trimmed = line.trim();
        if ALLOWED_LEGACY_WORKFLOW_LINES
            .iter()
            .any(|(allowed_path, allowed_line)| path == *allowed_path && trimmed == *allowed_line)
        {
            continue;
        }

        let decoded = decode_policy_escapes(line);
        let compact = decoded
            .chars()
            .filter(|character| !matches!(character, '\'' | '"' | '`' | '\\'))
            .collect::<String>();
        if [decoded.as_str(), compact.as_str()]
            .iter()
            .any(|candidate| {
                candidate
                    .to_ascii_lowercase()
                    .contains("actions/setup-node")
            })
        {
            violations.push(format!("{path}:{}: actions/setup-node", line_index + 1));
        }
        let mut commands = std::collections::BTreeSet::new();
        for candidate in [decoded.as_str(), compact.as_str()] {
            for token in candidate.split(|character: char| {
                !(character.is_ascii_alphanumeric()
                    || matches!(character, '_' | '-' | '.' | '/' | '\\'))
            }) {
                let command = normalized_command_token(token);
                if is_forbidden_workflow_token(&command) {
                    commands.insert(command);
                }
            }
        }
        violations.extend(commands.into_iter().map(|command| {
            format!(
                "{path}:{}: forbidden workflow token {command}",
                line_index + 1
            )
        }));
    }
}

fn decode_policy_escapes(input: &str) -> String {
    let mut decoded = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        let Some(marker) = characters.next() else {
            decoded.push('\\');
            break;
        };
        let digits = match marker {
            'x' => 2,
            'u' => 4,
            'U' => 8,
            _ => {
                decoded.push('\\');
                decoded.push(marker);
                continue;
            }
        };
        let mut hexadecimal = String::with_capacity(digits);
        while hexadecimal.len() < digits {
            let Some(next) = characters.peek().copied() else {
                break;
            };
            if !next.is_ascii_hexdigit() {
                break;
            }
            hexadecimal.push(next);
            characters.next();
        }
        let value = (hexadecimal.len() == digits)
            .then(|| u32::from_str_radix(&hexadecimal, 16).ok())
            .flatten()
            .and_then(char::from_u32);
        if let Some(value) = value {
            decoded.push(value);
        } else {
            decoded.push('\\');
            decoded.push(marker);
            decoded.push_str(&hexadecimal);
        }
    }
    decoded
}

fn normalized_command_token(token: &str) -> String {
    let lower = token.to_ascii_lowercase();
    let command = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
    for suffix in [".exe", ".cmd", ".bat", ".ps1"] {
        if let Some(command) = command.strip_suffix(suffix) {
            return command.to_owned();
        }
    }
    command.to_owned()
}

fn is_forbidden_workflow_token(token: &str) -> bool {
    FORBIDDEN_WORKFLOW_COMMANDS.contains(&token)
        || token.strip_prefix("node").is_some_and(|version| {
            !version.is_empty() && version.chars().all(|c| c.is_ascii_digit())
        })
}

fn normalized_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .expect("walked path is below root")
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

// A `.TS` entry must count against the ceiling exactly like a `.ts` one, so the
// match ignores ASCII case. `Path::extension` is deliberately not used: a file
// named exactly `.ts` has no extension by that definition and would slip past
// the count that this ratchet bounds.
fn has_legacy_typescript_extension(path: &str) -> bool {
    ["ts", "tsx"].into_iter().any(|extension| {
        path.len()
            .checked_sub(extension.len() + 1)
            .and_then(|dot| path.get(dot..))
            .is_some_and(|suffix| {
                suffix.starts_with('.') && suffix[1..].eq_ignore_ascii_case(extension)
            })
    })
}

fn is_forbidden_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| {
            FORBIDDEN_DIRECTORY_NAMES
                .iter()
                .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        })
}

fn is_forbidden_file(path: &Path) -> bool {
    let forbidden_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| {
            FORBIDDEN_FILE_NAMES
                .iter()
                .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        });
    let forbidden_extension = path
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|extension| {
            FORBIDDEN_EXTENSIONS
                .iter()
                .any(|forbidden| extension.eq_ignore_ascii_case(forbidden))
        });

    forbidden_name || forbidden_extension
}

struct TemporaryTree {
    path: PathBuf,
}

impl TemporaryTree {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gta-claw-repository-policy-{label}-{}-{id}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove stale policy fixture");
        }
        fs::create_dir_all(&path).expect("create policy fixture");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, relative: &str, contents: &[u8]) {
        let path = self.path.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(path, contents).expect("write policy fixture");
    }
}

impl Drop for TemporaryTree {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            eprintln!(
                "failed to remove repository-policy fixture {}: {error}",
                self.path.display()
            );
        }
    }
}
