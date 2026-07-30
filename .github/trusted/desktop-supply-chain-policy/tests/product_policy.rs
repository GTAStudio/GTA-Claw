use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use desktop_supply_chain_policy::input::SafeRoot;
use desktop_supply_chain_policy::product_policy::{
    HARDENING_TRANSITION_PATHS, validate_hardened_product_policy,
    validate_product_policy_transition,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempTree {
    path: PathBuf,
}

impl TempTree {
    fn new(label: &str) -> Self {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gta-claw-product-policy-{}-{label}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create product-policy fixture");
        Self { path }
    }

    fn write(&self, path: &str, contents: impl AsRef<[u8]>) {
        let destination = self.path.join(path);
        fs::create_dir_all(destination.parent().expect("fixture parent"))
            .expect("create fixture parent");
        fs::write(destination, contents).expect("write product-policy fixture");
    }

    fn replace(&self, path: &str, from: &str, to: &str) {
        let destination = self.path.join(path);
        let contents = fs::read_to_string(&destination).expect("read mutation input");
        assert!(
            contents.contains(from),
            "mutation source is absent from {path}: {from:?}"
        );
        fs::write(destination, contents.replacen(from, to, 1)).expect("write mutation");
    }

    fn root(&self) -> SafeRoot {
        SafeRoot::new(&self.path).expect("open product-policy fixture")
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove product-policy fixture");
    }
}

fn write_hardened_fixture(tree: &TempTree) {
    tree.write(
        "package.json",
        r#"{
  "name": "gta-claw",
  "version": "1.0.0",
  "scripts": {
    "start": "NODE_ENV=production node dist/index.js",
    "dev": "NODE_ENV=development GTA_CLAW_ALLOW_REDUCED_ISOLATION=true node src/index.ts",
    "test:isolation-policy": "node --test test/toolExecutorIsolation.test.mjs"
  },
  "dependencies": {"@github/copilot-sdk": "1.0.8"},
  "optionalDependencies": {"isolated-vm": "7.0.0"},
  "devDependencies": {},
  "allowScripts": {
    "isolated-vm@7.0.0": true,
    "koffi@3.1.2": true,
    "dtrace-provider": false
  }
}"#,
    );
    tree.write(
        "package-lock.json",
        r#"{
  "name": "gta-claw",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "gta-claw",
      "version": "1.0.0",
      "dependencies": {"@github/copilot-sdk": "1.0.8"},
      "optionalDependencies": {"isolated-vm": "7.0.0"},
      "devDependencies": {}
    },
    "node_modules/@github/copilot-sdk": {
      "version": "1.0.8",
      "dependencies": {"@github/copilot": "^1.0.73"}
    },
    "node_modules/@github/copilot": {"version": "1.0.75"},
    "node_modules/isolated-vm": {"version": "7.0.0"},
    "node_modules/koffi": {"version": "3.1.2"}
  }
}"#,
    );
    tree.write(
        "Dockerfile",
        r#"FROM node:26-bookworm-slim@sha256:2d49d876e96237d76de412761cf05dbfe5aee325cc4406a4d41d5824c5bb8beb AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund && \
  npm rebuild --foreground-scripts isolated-vm@7.0.0 koffi@3.1.2
RUN npm prune --omit=dev --ignore-scripts
FROM node:26-bookworm-slim@sha256:2d49d876e96237d76de412761cf05dbfe5aee325cc4406a4d41d5824c5bb8beb
WORKDIR /app
COPY --from=builder /app/package.json /app/package-lock.json ./
ENV NODE_ENV="production"
ENV COPILOT_CLI_PATH="/app/node_modules/.bin/copilot"
CMD ["node", "dist/index.js"]
"#,
    );
    tree.write(
        "src/config.ts",
        r#"const AUTO_UPDATE = parseBooleanEnv("AUTO_UPDATE", false);
if (AUTO_UPDATE) {
  throw new Error("AUTO_UPDATE is unsupported: update package.json and package-lock.json through review");
}
"#,
    );
    tree.write(
        "src/engine/toolExecutor.ts",
        r#"import { Script } from "node:vm";
if (
  nodeEnvironment === "development" &&
  process.env["GTA_CLAW_ALLOW_REDUCED_ISOLATION"] === "true"
) {
  console.warn("development-only node:vm reduced isolation");
}
"#,
    );
    tree.write(
        "src/index.ts",
        "import { checkForUpdates } from \"./updater/sdkUpdater.js\";\ncheckForUpdates();\n",
    );
    tree.write(
        "src/updater/sdkUpdater.ts",
        "export async function checkForUpdates() { return { current: \"1.0.8\" }; }\n",
    );
    tree.write(
        "crates/claw-config/src/domains.rs",
        r#"if name == "AUTO_UPDATE" && value == "true" {
    return Err("AUTO_UPDATE must remain false");
}
"#,
    );
    tree.write(
        "crates/claw-config/src/migration.rs",
        r#"MappingId::AutoUpdate => {
    return Err(invalid(mapping, "AUTO_UPDATE must remain false"));
}
"#,
    );

    let mapping = r#"{
  "source_revision": "3f2dfebcab1a1395f2445e9261b908cc4093f602",
  "mappings": [{
    "legacy_env": "AUTO_UPDATE",
    "default": false,
    "validation": "Boolean; true is rejected because dependency updates are review-only.",
    "known_legacy_quirk": "AUTO_UPDATE=true fails and must use review."
  }]
}"#;
    tree.write("crates/claw-config/data/env-mapping.json", mapping);
    tree.write("compat/legacy/config/env-mapping.json", mapping);
    for path in [
        "compat/legacy/fixtures/http/examples.json",
        "compat/legacy/inventory/bundled-skills.json",
        "compat/legacy/inventory/source-coverage.json",
        "compat/legacy/ledger/behaviors.json",
        "compat/legacy/ledger/features.json",
    ] {
        tree.write(
            path,
            r#"{"source_revision":"3f2dfebcab1a1395f2445e9261b908cc4093f602"}"#,
        );
    }
    tree.write(
        "compat/legacy/contract.json",
        r#"{"source_revision":"3f2dfebcab1a1395f2445e9261b908cc4093f602"}"#,
    );
    tree.write(
        "compat/legacy/scripts/requirements.txt",
        "attrs==26.1.0 \\\n    --hash=sha256:c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309\n",
    );
    tree.write(
        ".github/workflows/rust.yml",
        r#"name: rust
on:
  pull_request:
  push:
jobs:
  policy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065
        with:
          python-version: "3.13.5"
      - run: |
          git fetch --no-tags --depth=1 origin 3f2dfebcab1a1395f2445e9261b908cc4093f602
          python3 -m pip install --require-hashes --requirement compat/legacy/scripts/requirements.txt
          python3 -m pip check
          python3 compat/legacy/scripts/validate.py
          cargo +1.94.0 check --target aarch64-pc-windows-msvc --locked
          cargo deny --manifest-path desktop/Cargo.toml --locked --all-features check --config desktop/deny.toml
          echo cargo-deny 0.19.8
"#,
    );
    tree.write(
        ".github/workflows/upstream-gateway-reference.yml",
        "name: pinned upstream Gateway reference\non:\n  pull_request:\n",
    );
    for (path, workspace, targets) in [
        (
            ".github/workflows/android-packaging.yml",
            "android",
            "aarch64-linux-android x86_64-linux-android",
        ),
        (
            ".github/workflows/ios-packaging.yml",
            "ios",
            "aarch64-apple-ios aarch64-apple-ios-sim",
        ),
    ] {
        tree.write(
            path,
            format!(
                r#"name: {workspace}
on:
  pull_request:
jobs:
  policy:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          apt-get install libfontconfig-dev=2.15.0-1.1ubuntu2 pkgconf=1.8.1-2build1
          cargo +1.94.0 check --manifest-path {workspace}/Cargo.toml --workspace --all-targets --locked
          cargo deny --manifest-path {workspace}/Cargo.toml --locked --all-features check --config {workspace}/deny.toml
          echo cargo-deny 0.19.8
          echo {targets}
"#
            ),
        );
    }
    tree.write(
        "desktop/apps/gta-claw-desktop/build.rs",
        r#"fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let style = match target_os.as_str() {
        "windows" => "fluent",
        "macos" => "cupertino",
        _ => panic!("gta-claw-desktop requires a Windows or macOS build host"),
    };
}
"#,
    );
    tree.write(
        ".github/workflows/docker-publish.yml",
        r#"name: docker-publish
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f
      - if: github.event_name != 'pull_request'
        uses: docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9
      - uses: docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051
      - id: build
        run: docker buildx build --load .
      - name: Validate exact built image
        env:
          EXPECTED_IMAGE_ID: ${{ steps.build.outputs.image-id }}
        run: docker run --rm --entrypoint /app/node_modules/.bin/copilot "$IMAGE_TAG" --version
      - name: Push the validated image digest
        if: github.event_name != 'pull_request'
        run: |
          docker tag "$IMAGE_TAG" "$tag"
          test "$(docker image inspect --format '{{.Id}}' "$tag")" = "$EXPECTED_IMAGE_ID"
          echo "digest: sha256:$digest"
          test "$digest" = "$pushed_digest"
"#,
    );
    tree.write(
        "crates/claw-repo-policy/tests/repository_policy.rs",
        r#"const LEGACY_TYPESCRIPT_CEILING: usize = 18;
const ALLOWED_COMPAT_FIXTURES: &[&str] = &[
    "test/deviceFlow.test.mjs",
    "test/discordGateway.test.mjs",
    "test/splitMessage.test.mjs",
    "test/telegramPolling.test.mjs",
    "test/whatsappRawBody.test.mjs",
    "test/whatsappWebhook.test.mjs",
];
"#,
    );
    tree.write("test/toolExecutorIsolation.test.mjs", "export {};\n");
}

#[test]
fn hardened_policy_parses_and_enforces_actual_product_files() {
    let tree = TempTree::new("valid");
    write_hardened_fixture(&tree);
    validate_hardened_product_policy(&tree.root()).expect("valid hardened policy");
}

#[test]
fn deterministic_mutations_reach_case_specific_diagnostics() {
    for (label, path, from, to, expected) in [
        (
            "package-range",
            "package.json",
            "\"@github/copilot-sdk\": \"1.0.8\"",
            "\"@github/copilot-sdk\": \"^1.0.8\"",
            "one exact package version",
        ),
        (
            "lock-latest",
            "package-lock.json",
            "\"node_modules/@github/copilot\": {\"version\": \"1.0.75\"}",
            "\"node_modules/@github/copilot\": {\"version\": \"latest\"}",
            "mutable or non-registry version",
        ),
        (
            "docker-installer",
            "Dockerfile",
            "RUN npm prune --omit=dev --ignore-scripts",
            "RUN npm prune --omit=dev --ignore-scripts\nRUN npm install latest",
            "forbidden mutable installer command",
        ),
        (
            "typescript-auto-update",
            "src/config.ts",
            "if (AUTO_UPDATE)",
            "if (false)",
            "AUTO_UPDATE",
        ),
        (
            "reduced-isolation-opt-in",
            "src/engine/toolExecutor.ts",
            "GTA_CLAW_ALLOW_REDUCED_ISOLATION",
            "ALLOW_REDUCED_ISOLATION",
            "GTA_CLAW_ALLOW_REDUCED_ISOLATION",
        ),
        (
            "rust-auto-update",
            "crates/claw-config/src/migration.rs",
            "must remain false",
            "may be enabled",
            "must remain false",
        ),
        (
            "mapping-drift",
            "compat/legacy/config/env-mapping.json",
            "review-only",
            "automatic",
            "canonically equal",
        ),
        (
            "requirements-hash",
            "compat/legacy/scripts/requirements.txt",
            "--hash=sha256:c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309",
            "--hash=sha256:short",
            "invalid SHA-256",
        ),
        (
            "compat-revision-fetch",
            ".github/workflows/rust.yml",
            "3f2dfebcab1a1395f2445e9261b908cc4093f602",
            "92c2329b151d4b71b342a54d944254da2f3c61a5",
            "does not fetch the exact declared",
        ),
        (
            "pip-upgrade",
            ".github/workflows/rust.yml",
            "python3 -m pip install --require-hashes",
            "python3 -m pip install --upgrade --require-hashes",
            "upgrades pip",
        ),
        (
            "cargo-deny-order",
            ".github/workflows/rust.yml",
            "check --config desktop/deny.toml",
            "--config desktop/deny.toml check",
            "check --config",
        ),
        (
            "windows-arm64-msrv",
            ".github/workflows/rust.yml",
            "aarch64-pc-windows-msvc",
            "x86_64-pc-windows-msvc",
            "Windows ARM64 coverage",
        ),
        (
            "desktop-host-blanket",
            "desktop/apps/gta-claw-desktop/build.rs",
            "let target_os",
            "let host = std::env::var(\"HOST\").unwrap();\n    let target_os",
            "HOST==TARGET blanket",
        ),
        (
            "mobile-host-package",
            ".github/workflows/android-packaging.yml",
            "pkgconf=1.8.1-2build1",
            "pkgconf",
            "Linux host policy",
        ),
        (
            "mobile-shipped-target",
            ".github/workflows/ios-packaging.yml",
            "aarch64-apple-ios aarch64-apple-ios-sim",
            "aarch64-apple-ios",
            "lost shipped-target coverage",
        ),
        (
            "docker-second-build",
            ".github/workflows/docker-publish.yml",
            "docker buildx build --load .",
            "docker buildx build --load . && docker buildx build --load .",
            "build exactly once",
        ),
        (
            "docker-action-pin",
            ".github/workflows/docker-publish.yml",
            "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
            "docker/setup-buildx-action@v3",
            "Docker workflow action pin changed",
        ),
    ] {
        let tree = TempTree::new(label);
        write_hardened_fixture(&tree);
        tree.replace(path, from, to);
        let error = validate_hardened_product_policy(&tree.root())
            .expect_err("deterministic mutation unexpectedly passed")
            .to_string();
        assert!(
            error.contains(expected),
            "{label} reached the wrong diagnostic: {error}"
        );
    }
}

#[test]
fn legacy_state_is_preserved_only_until_a_transition_input_changes() {
    let trusted = TempTree::new("legacy-trusted");
    let candidate = TempTree::new("legacy-candidate");
    validate_product_policy_transition(&trusted.root(), &candidate.root())
        .expect("unchanged legacy state");

    candidate.write("package.json", "{}");
    let error = validate_product_policy_transition(&trusted.root(), &candidate.root())
        .expect_err("partial transition unexpectedly passed")
        .to_string();
    assert!(
        error.contains("must update all declared inputs atomically"),
        "partial transition reached the wrong diagnostic: {error}"
    );
    assert_eq!(
        HARDENING_TRANSITION_PATHS
            .iter()
            .filter(|path| Path::new(path).is_absolute())
            .count(),
        0,
        "transition paths must remain repository-relative"
    );
}
