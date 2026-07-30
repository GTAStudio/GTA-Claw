//! Base-owned shrink-only policy for the legacy Node runtime.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map as JsonMap, Value as JsonValue};
use serde_yaml_ng::{Mapping as YamlMapping, Value as YamlValue};
use toml::Value as TomlValue;

use crate::input::{DEFAULT_FILE_LIMIT, SafeRoot, sha256};
use crate::{PolicyError, PolicyResult, error};

const MAX_REPOSITORY_FILES: usize = 50_000;
const MAX_REPOSITORY_BYTES: u64 = 512 * 1024 * 1024;
const POLICY_CRATE: &str = "crates/claw-repo-policy";
const POLICY_MANIFEST: &str = "crates/claw-repo-policy/Cargo.toml";
const POLICY_LIBRARY: &str = "crates/claw-repo-policy/src/lib.rs";
const POLICY_TEST: &str = "crates/claw-repo-policy/tests/repository_policy.rs";
const UPSTREAM_WORKFLOW: &str = ".github/workflows/upstream-gateway-reference.yml";
const RUST_WORKFLOW: &str = ".github/workflows/rust.yml";
const DOCKER_WORKFLOW: &str = ".github/workflows/docker-publish.yml";
const POLICY_TEST_STEP_NAME: &str = "Reject JavaScript toolchain artifacts";
const ALLOWED_SHELL_FIXTURE: &str = ".github/fixtures/security-tools/bash-env-poison.sh";
const NODE_IMAGE: &str =
    "node:26-bookworm-slim@sha256:2d49d876e96237d76de412761cf05dbfe5aee325cc4406a4d41d5824c5bb8beb";
const SETUP_PYTHON_ACTION: &str =
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065";
const EXACT_NODE_ROOT_REQUIREMENTS: [(&str, &str, &str); 12] = [
    ("dependencies", "@github/copilot-sdk", "1.0.8"),
    ("dependencies", "botbuilder", "4.23.3"),
    ("dependencies", "pino", "10.3.1"),
    ("dependencies", "restify", "11.1.0"),
    ("dependencies", "undici", "8.9.0"),
    ("dependencies", "ws", "8.21.1"),
    ("optionalDependencies", "isolated-vm", "7.0.0"),
    ("devDependencies", "@types/bunyan", "1.8.11"),
    ("devDependencies", "@types/node", "26.1.2"),
    ("devDependencies", "@types/restify", "8.5.12"),
    ("devDependencies", "ts-node", "10.9.2"),
    ("devDependencies", "typescript", "7.0.2"),
];
const EXACT_PYTHON_REQUIREMENTS: [(&str, &str); 5] = [
    ("attrs", "26.1.0"),
    ("jsonschema", "4.26.0"),
    ("jsonschema-specifications", "2025.9.1"),
    ("referencing", "0.37.0"),
    ("rpds-py", "2026.6.3"),
];
const EXACT_NODE_OVERRIDES: [(&str, &str); 2] =
    [("find-my-way", "8.2.2"), ("send", "0.19.0")];
const LEGACY_SOURCE_REVISION: &str = "b2896426f3fcc5bb149402a38e09aac5e836d70b";
const LEGACY_REVISION_DOCUMENTS: [&str; 8] = [
    "compat/legacy/contract.json",
    "compat/legacy/ledger/features.json",
    "compat/legacy/ledger/behaviors.json",
    "compat/legacy/config/env-mapping.json",
    "compat/legacy/fixtures/http/examples.json",
    "compat/legacy/inventory/bundled-skills.json",
    "compat/legacy/inventory/source-coverage.json",
    "crates/claw-config/data/env-mapping.json",
];
const DOCKER_WORKFLOW_ACTION_PINS: [&str; 4] = [
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    "docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f",
    "docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9",
    "docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051",
];
const REVIEWED_POLICY_INPUTS: [(&str, &str); 17] = [
    (
        "package.json",
        "4f2041df7a9998a47174b80c2fad8b89de6fec96998eda635f085395b6f5ba0c",
    ),
    (
        "package-lock.json",
        "4b24a70ec191ec913a18b6a70cb42e1922681bc8e97472ef9cb97616959a96e8",
    ),
    (
        "Dockerfile",
        "ab573ea4f28fdce7a6c29c810fe2649a5cc8d288e732494f657e425f3a9bde1d",
    ),
    (
        "compat/legacy/scripts/requirements.txt",
        "6e0174c6d9b84dce3dde8c913537b368cddf0ccef285c90733dd314d786a14b5",
    ),
    (
        "src/config.ts",
        "9527a8e788b23d545acbdb60156492fa3864ad545e0b3662269896a089b28c8e",
    ),
    (
        "src/engine/toolExecutor.ts",
        "8aa2e289e3f255e6f087eac09ebcd8da83cb1ec1fc6653876c248ae07c454a86",
    ),
    (
        "src/updater/sdkUpdater.ts",
        "849a5ac2e91cc3ed3beeb0c03bbf1422a7fa2638d4bca10fdc7538e60562d86f",
    ),
    (
        DOCKER_WORKFLOW,
        "450374a98fa60c7f2b5864b020de8ed240e043972a5b652a34373a3b9cf08c68",
    ),
    (
        ".env.example",
        "dfe75f6efbbb1fde1d3ff0cd09c1dd0f34e691e81bef7d59d69fc60399484fec",
    ),
    (
        "compat/legacy/config/env-mapping.json",
        "66fc62ad2018d3a30d23ec79338590783101b124bce872a2abae947904663753",
    ),
    (
        "crates/claw-config/data/env-mapping.json",
        "66fc62ad2018d3a30d23ec79338590783101b124bce872a2abae947904663753",
    ),
    (
        "crates/claw-config/build_support.rs",
        "d302473b1bde6f53628218ec5bfbe27be4f12c621f4e046bcac6ae729d7f4d3a",
    ),
    (
        "crates/claw-config/src/domains.rs",
        "f8f54faafa5cb291f718e07c9e8a954d3ad09108510d2e4825a7f738491f5ea4",
    ),
    (
        "crates/claw-config/src/domains/imported.rs",
        "974f00d9f365167e4d0f7f112e25bc31840c9d5e008af9cd4c8e9a07ea37e478",
    ),
    (
        "crates/claw-config/src/migration.rs",
        "4214fe33cbc8d59c9b949101b422e4cab29d30e876b8f4c628f5db4cdd79a152",
    ),
    (
        "crates/claw-config/src/model.rs",
        "e4ad5ab2e97f91a13c2217c90b28a34c3bc9c5b84de08328ba486d3ae0b06ef0",
    ),
    (
        "crates/claw-config/src/wire.rs",
        "c76b1f84756e5bebdceec65493d7a93528d2820692d3409990bfa6981140386f",
    ),
];
const REVIEWED_LEGACY_TESTS: [(&str, &str); 6] = [
    (
        "test/deviceFlow.test.mjs",
        "eb7231732b94c9e8d59da1b9d1ce25b7b47451a7adbc6ca635c1a44f3794f48a",
    ),
    (
        "test/discordGateway.test.mjs",
        "2ab2345817e5e791c3da53f4b9954f8b8d5edd3518ce1c5a4c0a1c9f45002ca2",
    ),
    (
        "test/splitMessage.test.mjs",
        "e2352a91223f040727c00c28937587b5da3ab8af0c556a5753b383529bedf0ea",
    ),
    (
        "test/telegramPolling.test.mjs",
        "ef91cfac867fbb7b50200f2af1f56e59f181da7aeea52e8f65a55f055068f5fd",
    ),
    (
        "test/whatsappRawBody.test.mjs",
        "4ee4845f4ea88c32b1d72315e744998f2b1fcf59e61fe0124d1a555ece407a11",
    ),
    (
        "test/whatsappWebhook.test.mjs",
        "d3fea6d3371aa7286b23ec3673b7d830ec89aea6625452e06fb84f15f3043ad5",
    ),
];
type ExactFile = (&'static str, &'static [u8]);
const PR227_AUTHORITY_LEDGER: &str =
    ".github/trusted/desktop-supply-chain-policy/policy/pr227-asset-map.toml";
const PR227_AUTHORITY_LEDGER_BYTES: &[u8] = include_bytes!("../policy/pr227-asset-map.toml");
const PR227_EXACT_CONTRACT_INPUTS: [ExactFile; 5] = [
    (
        "compat/legacy/config/env-mapping.json",
        include_bytes!("../policy/final/legacy-policy/compat/legacy/config/env-mapping.json"),
    ),
    (
        "crates/claw-config/data/env-mapping.json",
        include_bytes!("../policy/final/legacy-policy/crates/claw-config/data/env-mapping.json"),
    ),
    (
        "crates/claw-config/src/domains.rs",
        include_bytes!("../policy/final/legacy-policy/crates/claw-config/src/domains.rs"),
    ),
    (
        "crates/claw-config/src/migration.rs",
        include_bytes!("../policy/final/legacy-policy/crates/claw-config/src/migration.rs"),
    ),
    (
        "crates/claw-config/src/model.rs",
        include_bytes!("../policy/final/legacy-policy/crates/claw-config/src/model.rs"),
    ),
];
const PR227_PROVISIONAL_CONTRACT_DIGESTS: [(&str, &str); 2] = [
    (
        "crates/claw-config/src/domains/imported.rs",
        "974f00d9f365167e4d0f7f112e25bc31840c9d5e008af9cd4c8e9a07ea37e478",
    ),
    (
        "crates/claw-config/src/wire.rs",
        "c76b1f84756e5bebdceec65493d7a93528d2820692d3409990bfa6981140386f",
    ),
];
const PR233_ADMISSION_INPUTS: [ExactFile; 3] = [
    (
        "android/scripts/workflow-self-test.sh",
        include_bytes!("../policy/pr233-base/android/scripts/workflow-self-test.sh"),
    ),
    (
        "ios/scripts/workflow-self-test.sh",
        include_bytes!("../policy/pr233-base/ios/scripts/workflow-self-test.sh"),
    ),
    (
        "packaging/macos/workflow-self-test.sh",
        include_bytes!("../policy/pr233-base/packaging/macos/workflow-self-test.sh"),
    ),
];
const PR233_FINAL_INPUTS: [ExactFile; 7] = [
    (
        "android/scripts/emulator-smoke.sh",
        include_bytes!("../policy/final/android/scripts/emulator-smoke.sh"),
    ),
    (
        "android/scripts/validate-apk-native-member.sh",
        include_bytes!("../policy/final/android/scripts/validate-apk-native-member.sh"),
    ),
    (
        "android/scripts/workflow-self-test.sh",
        include_bytes!("../policy/final/android/scripts/workflow-self-test.sh"),
    ),
    (
        "ios/scripts/simulator-smoke.sh",
        include_bytes!("../policy/final/ios/scripts/simulator-smoke.sh"),
    ),
    (
        "ios/scripts/workflow-self-test.sh",
        include_bytes!("../policy/final/ios/scripts/workflow-self-test.sh"),
    ),
    (
        "packaging/macos/joint-release-self-test.sh",
        include_bytes!("../policy/final/packaging/macos/joint-release-self-test.sh"),
    ),
    (
        "packaging/macos/workflow-self-test.sh",
        include_bytes!("../policy/final/packaging/macos/workflow-self-test.sh"),
    ),
];
const PR233_ADDED_INPUTS: [&str; 4] = [
    "android/scripts/emulator-smoke.sh",
    "android/scripts/validate-apk-native-member.sh",
    "ios/scripts/simulator-smoke.sh",
    "packaging/macos/joint-release-self-test.sh",
];
const ROTATION_BASE_INPUTS: [(&str, &str); 16] = [
    (
        "package.json",
        "478fad39b0adc5d4cb82d5e415076126f4870c9edfaa682903965b562f9f2f90",
    ),
    (
        "package-lock.json",
        "addbda1c94f70e69d1bcf2ff7d04ab42d3067b98b5d635872975e70b1818b1b0",
    ),
    (
        "Dockerfile",
        "5082f4ae97bb20f85c1a68c33369447dfb622e95029bda8c0badc95cf4789529",
    ),
    (
        "compat/legacy/scripts/requirements.txt",
        "9cba6d4508d006391ab899893990d5ac5d03b4811a0f71f152c5883897ee8120",
    ),
    (
        "src/config.ts",
        "1eb7df8a619ed7527fa0b1062be0697c9a5d06b9bfacd93cebfbc52eb812915b",
    ),
    (
        "src/engine/toolExecutor.ts",
        "c63876b140f0c771f9d531639c53d9e20e531cad64bec25e69aa0c782ef2524d",
    ),
    (
        "src/updater/sdkUpdater.ts",
        "3883d6917b132548b238b4e7166581e18d5d96dd48cb28bc2283bb01f59ea2bc",
    ),
    (
        "deny.toml",
        "75dedb874582f2f6d32890e21cca11186112d13dd51f4140ada96c69989594d0",
    ),
    (
        "desktop/deny.toml",
        "48c06a691c96db3085338f72b2fa2f2b0de37c4c4fc53849dd114a563e3f5b6f",
    ),
    (
        "desktop/apps/gta-claw-desktop/build.rs",
        "a7a4b9165975d06a23e61d17e6af6c83c4fb0aafdf5a2414e8431ff49bced784",
    ),
    (
        ".github/workflows/rust.yml",
        "d803009db095f829bb3a385db043574c4767568c7300ea8bbbdf40563db94e35",
    ),
    (
        ".github/workflows/docker-publish.yml",
        "766395e8c8f5924e4e4c591d8b50c7b6c26ec8083572ca8977c30acc091ca044",
    ),
    (
        ".github/workflows/android-packaging.yml",
        "3615bd735c28a2002a756f96ae788210ae971c08586882cc29e3f3ef5f7f2e6d",
    ),
    (
        ".github/workflows/ios-packaging.yml",
        "588cbb2357a3eccdb1e735eafa268aa9480c1108cb969452c6bf3d51f5d7f9f6",
    ),
    (
        ".github/workflows/macos-packaging.yml",
        "66f9947e7e41166d5598acb14cb28ee04f2316cf81f843734da6cc7b6206d6ff",
    ),
    (
        ".github/workflows/windows-packaging.yml",
        "932b1d74d4adb6742e62d8e45d626e8df80e0e944a484912fdc3da8bd395f4ed",
    ),
];

/// Exact historical ceiling: 18 TypeScript files and four load-bearing roots.
pub const LEGACY_RUNTIME_CEILING: [&str; 22] = [
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

const FORBIDDEN_FILE_NAMES: [&str; 9] = [
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
const FORBIDDEN_DIRECTORY_NAMES: [&str; 3] = ["node_modules", ".yarn", ".pnpm-store"];
const FORBIDDEN_EXTENSIONS: [&str; 9] =
    ["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "node"];
const FORBIDDEN_WORKFLOW_COMMANDS: [&str; 8] = [
    "node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "corepack",
];
const ALLOWED_LEGACY_WORKFLOW_LINES: [(&str, &str); 6] = [
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

fn repository_files(root: &SafeRoot) -> PolicyResult<Vec<String>> {
    Ok(root
        .list_all(MAX_REPOSITORY_FILES, MAX_REPOSITORY_BYTES)?
        .into_iter()
        .map(|file| file.relative)
        .collect())
}

/// Recognizes the base-owned PR #227 admission marker installed by the audited rotation.
pub fn has_pr227_admission_authority(root: &SafeRoot) -> PolicyResult<bool> {
    Ok(root.exists(PR227_AUTHORITY_LEDGER)?
        && root.read_bytes(PR227_AUTHORITY_LEDGER, DEFAULT_FILE_LIMIT)?
            == PR227_AUTHORITY_LEDGER_BYTES)
}

fn pr227_contract_matches(root: &SafeRoot) -> PolicyResult<bool> {
    for (path, expected) in PR227_EXACT_CONTRACT_INPUTS {
        if !root.exists(path)? || root.read_bytes(path, DEFAULT_FILE_LIMIT)? != expected {
            return Ok(false);
        }
    }
    for (path, expected) in PR227_PROVISIONAL_CONTRACT_DIGESTS {
        if !root.exists(path)?
            || sha256(&root.read_bytes(path, DEFAULT_FILE_LIMIT)?) != expected
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Recognizes the one reviewed base-owned gap between the trust rotation and
/// the product-policy absorption. The listed bytes are the exact PR #227,
/// pre-PR #233, and pre-PR #234 inputs.
pub fn is_rotation_base(root: &SafeRoot) -> PolicyResult<bool> {
    for (path, expected) in ROTATION_BASE_INPUTS
        .into_iter()
        .chain(REVIEWED_LEGACY_TESTS)
    {
        if !root.exists(path)? {
            return Ok(false);
        }
        if sha256(&root.read_bytes(path, DEFAULT_FILE_LIMIT)?) != expected {
            return Ok(false);
        }
    }
    Ok(pr227_contract_matches(root)?
        && is_pr233_admission_base(root)?
        && !root.exists(".github/workflows/joint-release-finalize.yml")?)
}

/// Requires the only candidate admitted from the base-owned PR #227 transition.
pub fn validate_pr227_candidate(root: &SafeRoot) -> PolicyResult<()> {
    if !is_rotation_base(root)? {
        return Err(PolicyError::new(
            "PR #227 candidate must match the exact six-test inventory and synchronized protected contract",
        ));
    }
    Ok(())
}

/// Recognizes the exact PR #234 base that may admit only the reviewed PR #233 script bytes.
pub fn is_pr233_admission_base(root: &SafeRoot) -> PolicyResult<bool> {
    for (path, expected) in PR233_ADMISSION_INPUTS {
        if !root.exists(path)? || root.read_bytes(path, DEFAULT_FILE_LIMIT)? != expected {
            return Ok(false);
        }
    }
    for path in PR233_ADDED_INPUTS {
        if root.exists(path)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Requires every workflow-executed PR #233 script to match its protected final bytes.
pub fn validate_pr233_final_assets(root: &SafeRoot) -> PolicyResult<()> {
    for (path, expected) in PR233_FINAL_INPUTS {
        if !root.exists(path)? || root.read_bytes(path, DEFAULT_FILE_LIMIT)? != expected {
            return Err(PolicyError::new(format!(
                "PR #233 workflow script does not match the protected final bytes: {path}"
            )));
        }
    }
    Ok(())
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn extension(path: &str) -> Option<&str> {
    file_name(path)
        .rsplit_once('.')
        .map(|(_, extension)| extension)
}

fn is_forbidden_artifact(path: &str) -> bool {
    path.split('/').any(|component| {
        FORBIDDEN_DIRECTORY_NAMES
            .iter()
            .any(|forbidden| component.eq_ignore_ascii_case(forbidden))
    }) || FORBIDDEN_FILE_NAMES
        .iter()
        .any(|forbidden| file_name(path).eq_ignore_ascii_case(forbidden))
        || extension(path).is_some_and(|extension| {
            FORBIDDEN_EXTENSIONS
                .iter()
                .any(|forbidden| extension.eq_ignore_ascii_case(forbidden))
        })
}

fn legacy_artifacts(files: &[String]) -> BTreeSet<String> {
    files
        .iter()
        .filter(|path| {
            LEGACY_RUNTIME_CEILING.contains(&path.as_str())
                || is_forbidden_artifact(path)
                    && !REVIEWED_LEGACY_TESTS
                        .iter()
                        .any(|(reviewed, _)| path == reviewed)
        })
        .cloned()
        .collect()
}

fn require_artifacts_within_ceiling(artifacts: &BTreeSet<String>, label: &str) -> PolicyResult<()> {
    let ceiling = LEGACY_RUNTIME_CEILING
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let outside = artifacts.difference(&ceiling).cloned().collect::<Vec<_>>();
    if outside.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::new(format!(
            "{label} contains legacy Node artifacts outside the exact ceiling: {outside:?}"
        )))
    }
}

fn require_candidate_subset(
    trusted: &BTreeSet<String>,
    candidate: &BTreeSet<String>,
) -> PolicyResult<()> {
    let additions = candidate.difference(trusted).cloned().collect::<Vec<_>>();
    if additions.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::new(format!(
            "candidate reintroduced or added legacy Node artifacts absent from the protected base: {additions:?}"
        )))
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
            !version.is_empty() && version.chars().all(|value| value.is_ascii_digit())
        })
}

fn record_violation(violations: &mut BTreeMap<String, usize>, key: String) -> PolicyResult<()> {
    let count = violations.entry(key).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| PolicyError::new("workflow violation count overflow"))?;
    Ok(())
}

fn scan_policy_document(
    path: &str,
    document: &str,
    violations: &mut BTreeMap<String, usize>,
) -> PolicyResult<()> {
    for line in document.lines() {
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
            record_violation(violations, format!("{path}|actions/setup-node|{trimmed}"))?;
        }
        let mut commands = BTreeSet::new();
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
        for command in commands {
            record_violation(
                violations,
                format!("{path}|forbidden workflow token {command}|{trimmed}"),
            )?;
        }
    }
    Ok(())
}

fn workflow_violations(root: &SafeRoot, files: &[String]) -> PolicyResult<BTreeMap<String, usize>> {
    let mut violations = BTreeMap::new();
    for path in files {
        let name = file_name(path);
        let workflow = path.starts_with(".github/workflows/")
            && extension(path).is_some_and(|extension| {
                extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
            });
        let local_action =
            name.eq_ignore_ascii_case("action.yml") || name.eq_ignore_ascii_case("action.yaml");
        if workflow || local_action {
            let document = root.read_text(path, DEFAULT_FILE_LIMIT)?;
            scan_policy_document(path, &document, &mut violations)?;
        }
    }
    Ok(violations)
}

fn require_violation_subset(
    trusted: &BTreeMap<String, usize>,
    candidate: &BTreeMap<String, usize>,
) -> PolicyResult<()> {
    let additions = candidate
        .iter()
        .filter(|(violation, count)| trusted.get(*violation).copied().unwrap_or(0) < **count)
        .map(|(violation, count)| format!("{violation} (candidate count {count})"))
        .collect::<Vec<_>>();
    if additions.is_empty() {
        Ok(())
    } else {
        Err(PolicyError::new(format!(
            "candidate introduced new Node workflow/action violations: {additions:?}"
        )))
    }
}

fn toml_keys(table: &toml::map::Map<String, TomlValue>) -> BTreeSet<&str> {
    table.keys().map(String::as_str).collect()
}

fn expected_toml_keys<'a>(keys: &'a [&'a str]) -> BTreeSet<&'a str> {
    keys.iter().copied().collect()
}

fn require_workspace_inheritance(
    package: &toml::map::Map<String, TomlValue>,
    key: &str,
) -> PolicyResult<()> {
    let value = package.get(key).and_then(TomlValue::as_table);
    if value.is_none_or(|value| {
        value.len() != 1 || value.get("workspace").and_then(TomlValue::as_bool) != Some(true)
    }) {
        return Err(PolicyError::new(format!(
            "{POLICY_MANIFEST} package.{key} must inherit exactly from workspace"
        )));
    }
    Ok(())
}

fn validate_policy_manifest(root: &SafeRoot) -> PolicyResult<()> {
    let root_manifest: TomlValue =
        toml::from_str(&root.read_text("Cargo.toml", DEFAULT_FILE_LIMIT)?)
            .map_err(|cause| error("parse root Cargo.toml for repository policy", cause))?;
    let members = root_manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(TomlValue::as_array)
        .ok_or_else(|| PolicyError::new("root workspace members are missing"))?;
    if !members
        .iter()
        .any(|member| member.as_str() == Some(POLICY_CRATE))
    {
        return Err(PolicyError::new(
            "claw-repo-policy must remain a declared root workspace member",
        ));
    }

    let manifest: TomlValue = toml::from_str(&root.read_text(POLICY_MANIFEST, DEFAULT_FILE_LIMIT)?)
        .map_err(|cause| error("parse claw-repo-policy manifest", cause))?;
    let root_table = manifest
        .as_table()
        .ok_or_else(|| PolicyError::new("claw-repo-policy manifest must be a table"))?;
    if toml_keys(root_table) != expected_toml_keys(&["lints", "package"]) {
        return Err(PolicyError::new(
            "claw-repo-policy manifest top-level schema changed",
        ));
    }
    let package = manifest
        .get("package")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("claw-repo-policy package table is missing"))?;
    if toml_keys(package)
        != expected_toml_keys(&[
            "description",
            "edition",
            "license",
            "name",
            "repository",
            "rust-version",
            "version",
        ])
        || package.get("name").and_then(TomlValue::as_str) != Some("claw-repo-policy")
        || package.get("description").and_then(TomlValue::as_str)
            != Some("Repository-wide architecture policy gates for GTA Claw")
    {
        return Err(PolicyError::new(
            "claw-repo-policy package identity or schema changed",
        ));
    }
    for key in [
        "version",
        "edition",
        "rust-version",
        "license",
        "repository",
    ] {
        require_workspace_inheritance(package, key)?;
    }
    let lints = manifest
        .get("lints")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new("claw-repo-policy lints table is missing"))?;
    if lints.len() != 1 || lints.get("workspace").and_then(TomlValue::as_bool) != Some(true) {
        return Err(PolicyError::new(
            "claw-repo-policy lints must inherit exactly from workspace",
        ));
    }
    Ok(())
}

fn rust_string_array(source: &str, name: &str) -> PolicyResult<Vec<String>> {
    let marker = format!("const {name}:");
    let declaration = source
        .find(&marker)
        .ok_or_else(|| PolicyError::new(format!("repository policy is missing {name}")))?;
    let array = source[declaration..]
        .find("&[")
        .map(|offset| declaration + offset + 2)
        .ok_or_else(|| PolicyError::new(format!("repository policy {name} is not an array")))?;
    let end = source[array..]
        .find("];")
        .map(|offset| array + offset)
        .ok_or_else(|| PolicyError::new(format!("repository policy {name} is unterminated")))?;
    let body = &source[array..end];
    let bytes = body.as_bytes();
    let mut values = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let start = index + 1;
        index = start;
        while index < bytes.len() && bytes[index] != b'"' {
            if bytes[index] == b'\\' {
                return Err(PolicyError::new(format!(
                    "repository policy {name} contains an escaped inventory value"
                )));
            }
            index += 1;
        }
        if index == bytes.len() {
            return Err(PolicyError::new(format!(
                "repository policy {name} contains an unterminated string"
            )));
        }
        values.push(body[start..index].to_owned());
        index += 1;
    }
    Ok(values)
}

fn validate_policy_source(root: &SafeRoot) -> PolicyResult<()> {
    let library = root
        .read_text(POLICY_LIBRARY, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    if library != "//! Repository-wide architecture policy gates for GTA Claw.\n" {
        return Err(PolicyError::new(
            "claw-repo-policy library identity changed",
        ));
    }
    let source = root
        .read_text(POLICY_TEST, DEFAULT_FILE_LIMIT)?
        .replace("\r\n", "\n");
    for (name, expected) in [
        ("FORBIDDEN_FILE_NAMES", FORBIDDEN_FILE_NAMES.as_slice()),
        (
            "FORBIDDEN_DIRECTORY_NAMES",
            FORBIDDEN_DIRECTORY_NAMES.as_slice(),
        ),
        ("FORBIDDEN_EXTENSIONS", FORBIDDEN_EXTENSIONS.as_slice()),
        (
            "FORBIDDEN_WORKFLOW_COMMANDS",
            FORBIDDEN_WORKFLOW_COMMANDS.as_slice(),
        ),
        (
            "LEGACY_RUNTIME_INVENTORY",
            LEGACY_RUNTIME_CEILING.as_slice(),
        ),
        ("ALLOWED_COMPAT_FIXTURES", &[]),
        (
            "ALLOWED_ADVERSARIAL_SHELL_FIXTURES",
            &[ALLOWED_SHELL_FIXTURE],
        ),
    ] {
        let values = rust_string_array(&source, name)?;
        if values.iter().map(String::as_str).collect::<Vec<_>>() != expected {
            return Err(PolicyError::new(format!(
                "repository policy {name} changed from the base-owned contract"
            )));
        }
    }
    for required in [
        "#[test]\nfn repository_legacy_javascript_surface_does_not_grow()",
        "#[test]\nfn new_typescript_path_outside_legacy_inventory_is_rejected()",
        "fixture.write(\"src/newFeature.ts\", b\"new\");",
        "assert_eq!(violations, [\"src/newFeature.ts\"]);",
        "#[test]\nfn removing_allowlisted_legacy_entry_keeps_ratchet_green()",
        "fs::remove_file(fixture.path().join(\"src/index.ts\"))",
        "#[test]\nfn workflow_commands_are_checked_without_rejecting_inert_search_patterns()",
        "#[test]\nfn tracked_symlink_and_gitlink_modes_are_rejected()",
        "120000 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "160000 cccccccccccccccccccccccccccccccccccccccc",
    ] {
        if !source.contains(required) {
            return Err(PolicyError::new(format!(
                "repository policy self-test contract is missing: {required:?}"
            )));
        }
    }
    Ok(())
}

fn yaml_key(key: &str) -> YamlValue {
    YamlValue::String(key.to_owned())
}

fn yaml_mapping(value: &YamlValue) -> Option<&YamlMapping> {
    if let YamlValue::Mapping(mapping) = value {
        Some(mapping)
    } else {
        None
    }
}

fn yaml_get<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    yaml_mapping(value)?.get(yaml_key(key))
}

fn yaml_string(value: Option<&YamlValue>) -> Option<&str> {
    if let Some(YamlValue::String(value)) = value {
        Some(value)
    } else {
        None
    }
}

fn require_reviewed_digest(root: &SafeRoot, path: &str, expected: &str) -> PolicyResult<()> {
    let actual = sha256(&root.read_bytes(path, DEFAULT_FILE_LIMIT)?);
    if actual != expected {
        return Err(PolicyError::new(format!(
            "reviewed legacy policy input bytes changed: {path}; expected {expected}, found {actual}"
        )));
    }
    Ok(())
}

fn validate_reviewed_legacy_tests(root: &SafeRoot, files: &[String]) -> PolicyResult<()> {
    let actual = files
        .iter()
        .filter(|path| path.starts_with("test/") && path.ends_with(".mjs"))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = REVIEWED_LEGACY_TESTS
        .iter()
        .map(|(path, _)| *path)
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(PolicyError::new(format!(
            "reviewed legacy runtime test inventory changed: expected {expected:?}, found {actual:?}"
        )));
    }
    for (path, digest) in REVIEWED_LEGACY_TESTS {
        require_reviewed_digest(root, path, digest)?;
    }
    Ok(())
}

fn parse_json(root: &SafeRoot, path: &str) -> PolicyResult<JsonValue> {
    serde_json::from_str(&root.read_text(path, DEFAULT_FILE_LIMIT)?)
        .map_err(|cause| error(&format!("parse reviewed JSON policy input {path}"), cause))
}

fn json_object<'a>(value: &'a JsonValue, label: &str) -> PolicyResult<&'a JsonMap<String, JsonValue>> {
    value
        .as_object()
        .ok_or_else(|| PolicyError::new(format!("{label} must be a JSON object")))
}

fn json_member_object<'a>(
    object: &'a JsonMap<String, JsonValue>,
    key: &str,
    label: &str,
) -> PolicyResult<&'a JsonMap<String, JsonValue>> {
    object
        .get(key)
        .and_then(JsonValue::as_object)
        .ok_or_else(|| PolicyError::new(format!("{label}.{key} must be a JSON object")))
}

fn require_json_string(
    object: &JsonMap<String, JsonValue>,
    key: &str,
    expected: &str,
    label: &str,
) -> PolicyResult<()> {
    let actual = object.get(key).and_then(JsonValue::as_str);
    if actual != Some(expected) {
        return Err(PolicyError::new(format!(
            "{label}.{key} must be the exact reviewed value {expected:?}, found {actual:?}"
        )));
    }
    Ok(())
}

fn is_exact_npm_version(value: &str) -> bool {
    let components = value.split('.').collect::<Vec<_>>();
    components.len() == 3
        && components
            .iter()
            .all(|component| {
                !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
            })
}

fn validate_npm_section(
    package: &JsonMap<String, JsonValue>,
    lock_root: &JsonMap<String, JsonValue>,
    section: &str,
    expected: &BTreeMap<&str, &str>,
) -> PolicyResult<()> {
    let package_section = json_member_object(package, section, "package.json")?;
    let lock_section = json_member_object(lock_root, section, "package-lock.json packages[\"\"]")?;
    for (name, value) in package_section {
        let value = value.as_str().ok_or_else(|| {
            PolicyError::new(format!("package.json.{section}.{name} must be a string"))
        })?;
        if !is_exact_npm_version(value) {
            return Err(PolicyError::new(format!(
                "package.json direct dependency specs must be exact numeric versions; \
                 latest, semver ranges, URL, git, file, link, and workspace references are forbidden: \
                 {section}.{name}={value:?}"
            )));
        }
    }
    let actual = package_section
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|version| (name.as_str(), version))
                .ok_or_else(|| {
                    PolicyError::new(format!("package.json.{section}.{name} must be a string"))
                })
        })
        .collect::<PolicyResult<BTreeMap<_, _>>>()?;
    if &actual != expected {
        return Err(PolicyError::new(format!(
            "package.json.{section} exact requirement set changed: expected {expected:?}, found {actual:?}"
        )));
    }
    let locked = lock_section
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|version| (name.as_str(), version))
                .ok_or_else(|| {
                    PolicyError::new(format!(
                        "package-lock.json packages[\"\"].{section}.{name} must be a string"
                    ))
                })
        })
        .collect::<PolicyResult<BTreeMap<_, _>>>()?;
    if locked != actual {
        return Err(PolicyError::new(format!(
            "package-lock.json packages[\"\"].{section} does not exactly bind package.json"
        )));
    }
    Ok(())
}

fn validate_node_package_policy(root: &SafeRoot) -> PolicyResult<()> {
    let package = parse_json(root, "package.json")?;
    let package = json_object(&package, "package.json")?;
    let lock = parse_json(root, "package-lock.json")?;
    let lock = json_object(&lock, "package-lock.json")?;
    if lock.get("lockfileVersion").and_then(JsonValue::as_u64) != Some(3) {
        return Err(PolicyError::new(
            "package-lock.json lockfileVersion must remain exactly 3",
        ));
    }
    let packages = json_member_object(lock, "packages", "package-lock.json")?;
    let lock_root = packages
        .get("")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| PolicyError::new("package-lock.json packages[\"\"] must be an object"))?;

    for section in ["dependencies", "optionalDependencies", "devDependencies"] {
        let expected = EXACT_NODE_ROOT_REQUIREMENTS
            .iter()
            .filter(|(expected_section, _, _)| *expected_section == section)
            .map(|(_, name, version)| (*name, *version))
            .collect::<BTreeMap<_, _>>();
        validate_npm_section(package, lock_root, section, &expected)?;
    }
    let overrides = json_member_object(package, "overrides", "package.json")?;
    let actual_overrides = overrides
        .iter()
        .map(|(name, value)| {
            let value = value.as_str().ok_or_else(|| {
                PolicyError::new(format!("package.json.overrides.{name} must be a string"))
            })?;
            if !is_exact_npm_version(value) {
                return Err(PolicyError::new(format!(
                    "package.json override must be an exact numeric version: {name}={value:?}"
                )));
            }
            Ok((name.as_str(), value))
        })
        .collect::<PolicyResult<BTreeMap<_, _>>>()?;
    let expected_overrides = EXACT_NODE_OVERRIDES.into_iter().collect::<BTreeMap<_, _>>();
    if actual_overrides != expected_overrides {
        return Err(PolicyError::new(format!(
            "package.json override set changed: expected {expected_overrides:?}, found {actual_overrides:?}"
        )));
    }

    let allow_scripts = json_member_object(package, "allowScripts", "package.json")?;
    let expected_scripts = BTreeMap::from([
        ("dtrace-provider", false),
        ("isolated-vm@7.0.0", true),
        ("koffi@3.1.2", true),
    ]);
    let actual_scripts = allow_scripts
        .iter()
        .map(|(name, value)| {
            value
                .as_bool()
                .map(|enabled| (name.as_str(), enabled))
                .ok_or_else(|| {
                    PolicyError::new(format!(
                        "package.json allowScripts.{name} must be a boolean"
                    ))
                })
        })
        .collect::<PolicyResult<BTreeMap<_, _>>>()?;
    if actual_scripts != expected_scripts {
        return Err(PolicyError::new(format!(
            "package.json install-script allowlist changed: expected {expected_scripts:?}, found {actual_scripts:?}"
        )));
    }

    let scripts = json_member_object(package, "scripts", "package.json")?;
    let script_keys = scripts.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if script_keys != BTreeSet::from(["build", "dev", "start", "test:isolation-policy"]) {
        return Err(PolicyError::new(format!(
            "package.json script set changed: {script_keys:?}"
        )));
    }
    require_json_string(
        scripts,
        "start",
        "node --no-node-snapshot dist/index.js",
        "package.json.scripts",
    )?;
    let isolation_test = scripts
        .get("test:isolation-policy")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| PolicyError::new("package.json isolation-policy test must be a string"))?;
    for required in [
        "delete process.env.NODE_ENV",
        "delete process.env.GTA_CLAW_ALLOW_REDUCED_ISOLATION",
        "selectIsolationMode(false, 'development', 'true'), 'node-vm'",
        "['production', 'true']",
        "['development', '']",
        "['development', 'TRUE']",
    ] {
        if !isolation_test.contains(required) {
            return Err(PolicyError::new(format!(
                "package.json isolation-policy test is incomplete: {required}"
            )));
        }
    }

    for (path, version) in [
        ("node_modules/@github/copilot", "1.0.75"),
        ("node_modules/@github/copilot-sdk", "1.0.8"),
    ] {
        let package = packages
            .get(path)
            .and_then(JsonValue::as_object)
            .ok_or_else(|| PolicyError::new(format!("package-lock.json is missing {path}")))?;
        require_json_string(
            package,
            "version",
            version,
            &format!("package-lock.json packages[{path:?}]"),
        )?;
    }
    Ok(())
}

fn docker_statements(source: &str) -> PolicyResult<Vec<String>> {
    let mut statements = Vec::new();
    let mut current = String::new();
    for line in source.replace("\r\n", "\n").lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let continued = trimmed.ends_with('\\');
        let fragment = trimmed.strip_suffix('\\').unwrap_or(trimmed).trim_end();
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(fragment);
        if !continued {
            statements.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        return Err(PolicyError::new(
            "Dockerfile ends with an unterminated continuation",
        ));
    }
    Ok(statements)
}

fn validate_dockerfile_policy(root: &SafeRoot) -> PolicyResult<()> {
    let source = root.read_text("Dockerfile", DEFAULT_FILE_LIMIT)?;
    let statements = docker_statements(&source)?;
    let from = statements
        .iter()
        .filter(|statement| statement.starts_with("FROM "))
        .map(String::as_str)
        .collect::<Vec<_>>();
    let expected_from = [
        format!("FROM {NODE_IMAGE} AS builder"),
        format!("FROM {NODE_IMAGE}"),
    ];
    if from
        != expected_from
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err(PolicyError::new(format!(
            "Dockerfile base image is not digest-pinned exactly: {from:?}"
        )));
    }

    for required in [
        "COPY package.json package-lock.json ./",
        "COPY --from=builder /app/package.json /app/package-lock.json ./",
        "ENV NODE_ENV=\"production\"",
        "ENV COPILOT_CLI_PATH=\"/app/node_modules/.bin/copilot\"",
    ] {
        if !statements.iter().any(|statement| statement == required) {
            return Err(PolicyError::new(format!(
                "Dockerfile does not couple exact package roots: {required}"
            )));
        }
    }
    for required in [
        "npm ci --ignore-scripts --no-audit --no-fund",
        "npm rebuild --foreground-scripts isolated-vm@7.0.0 koffi@3.1.2",
    ] {
        if !statements
            .iter()
            .filter(|statement| statement.starts_with("RUN "))
            .any(|statement| statement.contains(required))
        {
            return Err(PolicyError::new(format!(
                "Dockerfile install-script allowlist changed: missing {required}"
            )));
        }
    }
    for (forbidden, diagnostic) in [
        ("npm install", "npm install is forbidden"),
        ("npx ", "npx network fallback is forbidden"),
        ("package-lock.json*", "optional package lock copy is forbidden"),
        ("gh.io/copilot-install", "remote Copilot installer is forbidden"),
    ] {
        if statements
            .iter()
            .any(|statement| statement.contains(forbidden))
        {
            return Err(PolicyError::new(diagnostic));
        }
    }
    Ok(())
}

fn validate_runtime_source_policy(root: &SafeRoot) -> PolicyResult<()> {
    let config = root.read_text("src/config.ts", DEFAULT_FILE_LIMIT)?;
    for required in [
        "if (AUTO_UPDATE) {",
        "AUTO_UPDATE is unsupported: update package.json and package-lock.json through review",
        "const WHATSAPP_APP_SECRET = parseOptionalNonEmptyEnv(",
        "!WHATSAPP_APP_SECRET",
        "ENABLE_WHATSAPP=true requires WHATSAPP_VERIFY_TOKEN, WHATSAPP_ACCESS_TOKEN, WHATSAPP_PHONE_NUMBER_ID, and WHATSAPP_APP_SECRET",
    ] {
        if !config.contains(required) {
            return Err(PolicyError::new(format!(
                "AUTO_UPDATE=true must fail configuration: missing {required}"
            )));
        }
    }

    let executor = root.read_text("src/engine/toolExecutor.ts", DEFAULT_FILE_LIMIT)?;
    for required in [
        "reducedIsolationOptIn = process.env[\"GTA_CLAW_ALLOW_REDUCED_ISOLATION\"]",
        "nodeEnvironment !== \"development\"",
        "reducedIsolationOptIn !== \"true\"",
        "isolated-vm is required; reduced node:vm isolation requires NODE_ENV=development and GTA_CLAW_ALLOW_REDUCED_ISOLATION=true",
    ] {
        if !executor.contains(required) {
            return Err(PolicyError::new(format!(
                "reduced node:vm isolation must require exact development opt-in: missing {required}"
            )));
        }
    }

    let updater = root.read_text("src/updater/sdkUpdater.ts", DEFAULT_FILE_LIMIT)?;
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
        return Err(PolicyError::new(
            "mutable runtime update logic is forbidden",
        ));
    }
    Ok(())
}

fn validate_environment_mapping_policy(root: &SafeRoot) -> PolicyResult<()> {
    let compatibility =
        root.read_bytes("compat/legacy/config/env-mapping.json", DEFAULT_FILE_LIMIT)?;
    let packaged =
        root.read_bytes("crates/claw-config/data/env-mapping.json", DEFAULT_FILE_LIMIT)?;
    if compatibility != packaged {
        return Err(PolicyError::new(
            "workspace and packaged environment mappings must have identical bytes",
        ));
    }
    let document: JsonValue = serde_json::from_slice(&compatibility)
        .map_err(|cause| error("parse environment mapping policy", cause))?;
    let document = json_object(&document, "environment mapping policy")?;
    require_json_string(
        document,
        "source_revision",
        LEGACY_SOURCE_REVISION,
        "environment mapping policy",
    )?;
    let mappings = document
        .get("mappings")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| PolicyError::new("environment mapping policy mappings must be an array"))?;
    let auto_update = mappings
        .iter()
        .filter_map(JsonValue::as_object)
        .filter(|mapping| {
            mapping.get("legacy_env").and_then(JsonValue::as_str) == Some("AUTO_UPDATE")
        })
        .collect::<Vec<_>>();
    if auto_update.len() != 1 {
        return Err(PolicyError::new(
            "environment mapping policy must define AUTO_UPDATE exactly once",
        ));
    }
    let auto_update = auto_update[0];
    for (key, expected) in [
        ("target_json5_key", "updates.enabled"),
        ("conversion", "Accept only exact lowercase true or false."),
        (
            "validation",
            "Boolean; true is rejected because dependency updates are review-only.",
        ),
        (
            "known_legacy_quirk",
            "The compatibility runtime preserves read-only update checks; AUTO_UPDATE=true fails instead of invoking npm or curl.",
        ),
    ] {
        require_json_string(auto_update, key, expected, "AUTO_UPDATE mapping")?;
    }
    if auto_update.get("default").and_then(JsonValue::as_bool) != Some(false) {
        return Err(PolicyError::new(
            "AUTO_UPDATE mapping default must remain false",
        ));
    }
    let app_secret = mappings
        .iter()
        .filter_map(JsonValue::as_object)
        .filter(|mapping| {
            mapping.get("legacy_env").and_then(JsonValue::as_str)
                == Some("WHATSAPP_APP_SECRET")
        })
        .collect::<Vec<_>>();
    if app_secret.len() != 1 {
        return Err(PolicyError::new(
            "environment mapping policy must define WHATSAPP_APP_SECRET exactly once",
        ));
    }
    let app_secret = app_secret[0];
    for (key, expected) in [
        ("scope", "runtime"),
        ("target_json5_key", "channels.whatsapp.app_secret"),
        (
            "conversion",
            "Trim; empty becomes absent. Store as a secret reference.",
        ),
        ("validation", "Nonempty when WhatsApp is enabled."),
        ("required_when", "channels.whatsapp.enabled is true"),
    ] {
        require_json_string(app_secret, key, expected, "WHATSAPP_APP_SECRET mapping")?;
    }
    if app_secret.get("secret").and_then(JsonValue::as_bool) != Some(true)
        || !app_secret.get("default").is_some_and(JsonValue::is_null)
    {
        return Err(PolicyError::new(
            "WHATSAPP_APP_SECRET mapping must be a null-default secret reference",
        ));
    }
    let example = root.read_text(".env.example", DEFAULT_FILE_LIMIT)?;
    for required in [
        "Dependency updates are review-only; AUTO_UPDATE=true is rejected at startup.",
        "Reduced node:vm isolation is development-only and requires both values explicitly.",
        "# NODE_ENV=development",
        "# GTA_CLAW_ALLOW_REDUCED_ISOLATION=false",
    ] {
        if !example.contains(required) {
            return Err(PolicyError::new(format!(
                "environment example does not document fail-closed runtime policy: {required}"
            )));
        }
    }
    Ok(())
}

fn workflow_steps(workflow: &YamlValue) -> PolicyResult<Vec<&YamlValue>> {
    let jobs = yaml_get(workflow, "jobs")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new("workflow jobs must be a mapping"))?;
    let mut steps = Vec::new();
    for job in jobs.values() {
        let job_steps = yaml_get(job, "steps")
            .and_then(YamlValue::as_sequence)
            .ok_or_else(|| PolicyError::new("workflow job steps must be a sequence"))?;
        steps.extend(job_steps);
    }
    Ok(steps)
}

fn workflow_job<'a>(workflow: &'a YamlValue, name: &str) -> PolicyResult<&'a YamlValue> {
    yaml_get(workflow, "jobs")
        .and_then(yaml_mapping)
        .and_then(|jobs| jobs.get(yaml_key(name)))
        .ok_or_else(|| PolicyError::new(format!("workflow job is missing: {name}")))
}

fn workflow_job_steps<'a>(
    workflow: &'a YamlValue,
    job_name: &str,
) -> PolicyResult<Vec<&'a YamlValue>> {
    let job = workflow_job(workflow, job_name)?;
    yaml_get(job, "steps")
        .and_then(YamlValue::as_sequence)
        .map(|steps| steps.iter().collect())
        .ok_or_else(|| PolicyError::new(format!("workflow job has no steps: {job_name}")))
}

fn workflow_step<'a>(steps: &[&'a YamlValue], name: &str) -> PolicyResult<&'a YamlValue> {
    let matches = steps
        .iter()
        .copied()
        .filter(|step| yaml_string(yaml_get(step, "name")) == Some(name))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(PolicyError::new(format!(
            "workflow must contain exactly one {name:?} step"
        )));
    }
    Ok(matches[0])
}

fn validate_deny_targets(
    root: &SafeRoot,
    path: &str,
    expected: &[&str],
) -> PolicyResult<()> {
    let document: TomlValue = toml::from_str(&root.read_text(path, DEFAULT_FILE_LIMIT)?)
        .map_err(|cause| error(&format!("parse {path} target policy"), cause))?;
    let graph = document
        .get("graph")
        .and_then(TomlValue::as_table)
        .ok_or_else(|| PolicyError::new(format!("{path} must define [graph]")))?;
    if graph.get("all-features").and_then(TomlValue::as_bool) != Some(true) {
        return Err(PolicyError::new(format!(
            "{path} must evaluate each shipped target with all features"
        )));
    }
    let targets = graph
        .get("targets")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| PolicyError::new(format!("{path} graph targets must be an array")))?;
    let actual = targets
        .iter()
        .map(|target| {
            target
                .as_table()
                .filter(|target| target.len() == 1)
                .and_then(|target| target.get("triple"))
                .and_then(TomlValue::as_str)
                .ok_or_else(|| {
                    PolicyError::new(format!(
                        "{path} graph target must be exactly one triple"
                    ))
                })
        })
        .collect::<PolicyResult<Vec<_>>>()?;
    if actual != expected {
        return Err(PolicyError::new(format!(
            "{path} shipped target set changed: expected {expected:?}, found {actual:?}"
        )));
    }
    Ok(())
}

fn validate_desktop_target_workflow(root: &SafeRoot) -> PolicyResult<()> {
    let build = root.read_text(
        "desktop/apps/gta-claw-desktop/build.rs",
        DEFAULT_FILE_LIMIT,
    )?;
    for required in [
        "fn cargo_target_os() -> String",
        "std::env::var(\"CARGO_CFG_TARGET_OS\")",
        "\"windows\" => \"fluent\"",
        "\"macos\" => \"cupertino\"",
        "requires a Windows or macOS build host",
    ] {
        if !build.contains(required) {
            return Err(PolicyError::new(format!(
                "desktop build script is not target-OS aware: {required}"
            )));
        }
    }
    for forbidden in [
        "std::env::var(\"HOST\")",
        "std::env::var(\"TARGET\")",
        "host != target",
        "matching host and target triples",
    ] {
        if build.contains(forbidden) {
            return Err(PolicyError::new(format!(
                "desktop build script blocks supported cross-architecture targets: {forbidden}"
            )));
        }
    }

    let workflow: YamlValue =
        serde_yaml_ng::from_str(&root.read_text(RUST_WORKFLOW, DEFAULT_FILE_LIMIT)?)
            .map_err(|cause| error("parse Rust workflow target coverage", cause))?;
    let steps = workflow_steps(&workflow)?;
    let tree = workflow_step(&steps, "Assert shipped desktop trees exclude Skia")?;
    let tree_run = yaml_string(yaml_get(tree, "run"))
        .ok_or_else(|| PolicyError::new("desktop shipped-target tree step has no run script"))?;
    for target in [
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
    ] {
        if !tree_run.contains(target) {
            return Err(PolicyError::new(format!(
                "desktop shipped-target tree coverage is missing {target}"
            )));
        }
    }
    for required in [
        "cargo tree --manifest-path desktop/Cargo.toml --locked --all-features",
        "--target \"$target\"",
        "i-slint-renderer-skia|skia-bindings|skia-safe",
    ] {
        if !tree_run.contains(required) {
            return Err(PolicyError::new(format!(
                "desktop shipped-target tree enforcement changed: {required}"
            )));
        }
    }
    let arm64 = workflow_step(&steps, "Check Windows ARM64 desktop target at MSRV")?;
    if yaml_string(yaml_get(arm64, "if")) != Some("runner.os == 'Windows'")
        || yaml_string(yaml_get(arm64, "shell")) != Some("pwsh")
    {
        return Err(PolicyError::new(
            "Windows ARM64 desktop MSRV check must run only under PowerShell on Windows",
        ));
    }
    let arm64_run = yaml_string(yaml_get(arm64, "run"))
        .ok_or_else(|| PolicyError::new("Windows ARM64 desktop MSRV check has no run script"))?;
    for required in [
        "rustup target add --toolchain 1.94.0 aarch64-pc-windows-msvc",
        "cargo +1.94.0 check --manifest-path desktop/Cargo.toml",
        "--package gta-claw-desktop --all-targets",
        "--target aarch64-pc-windows-msvc --locked",
    ] {
        if !arm64_run.contains(required) {
            return Err(PolicyError::new(format!(
                "desktop Windows ARM64 MSRV coverage changed: {required}"
            )));
        }
    }
    let linux = workflow_step(&steps, "Assert desktop build rejects Linux")?;
    let linux_run = yaml_string(yaml_get(linux, "run"))
        .ok_or_else(|| PolicyError::new("desktop Linux rejection step has no run script"))?;
    if !linux_run.contains("requires a Windows or macOS build host")
        || linux_run.contains("matching host and target triples")
    {
        return Err(PolicyError::new(
            "desktop Linux rejection must preserve target-OS-aware diagnostics",
        ));
    }
    Ok(())
}

fn validate_mobile_target_workflow(
    root: &SafeRoot,
    path: &str,
    platform: &str,
    label: &str,
    package_runner: &str,
    install_step: &str,
    targets: &[&str],
    target_step: &str,
    target_command: &str,
) -> PolicyResult<()> {
    let workflow: YamlValue =
        serde_yaml_ng::from_str(&root.read_text(path, DEFAULT_FILE_LIMIT)?)
            .map_err(|cause| error(&format!("parse {path} target coverage"), cause))?;
    let policy = workflow_job(&workflow, "policy")?;
    if yaml_string(yaml_get(policy, "runs-on")) != Some("ubuntu-24.04") {
        return Err(PolicyError::new(format!(
            "{path} dependency policy must run separately on Ubuntu 24.04"
        )));
    }
    let policy_steps = workflow_job_steps(&workflow, "policy")?;
    let prerequisites =
        workflow_step(&policy_steps, "Install pinned Linux host renderer prerequisites")?;
    let prerequisites_run = yaml_string(yaml_get(prerequisites, "run"))
        .ok_or_else(|| PolicyError::new(format!("{path} host prerequisites have no run script")))?;
    for required in [
        "sudo apt-get update",
        "sudo apt-get install --no-install-recommends -y",
        "libfontconfig-dev=2.15.0-1.1ubuntu2",
        "pkgconf=1.8.1-2build1",
    ] {
        if !prerequisites_run.contains(required) {
            return Err(PolicyError::new(format!(
                "{path} Linux host prerequisite pin changed: {required}"
            )));
        }
    }
    let host_graph_name = format!("Check {label} Linux host graph at MSRV");
    let host_graph = workflow_step(&policy_steps, &host_graph_name)?;
    let host_graph_run = yaml_string(yaml_get(host_graph, "run"))
        .ok_or_else(|| PolicyError::new(format!("{path} Linux host graph has no run script")))?;
    let expected_host_check = format!(
        "cargo +1.94.0 check --manifest-path {platform}/Cargo.toml --workspace --all-targets --locked"
    );
    if !host_graph_run.contains("rustup toolchain install 1.94.0 --profile minimal")
        || !host_graph_run.contains(&expected_host_check)
    {
        return Err(PolicyError::new(format!(
            "{path} Linux host MSRV coverage changed"
        )));
    }
    let host_policy_name = format!("Check {label} Linux host dependency policy");
    let host_policy = workflow_step(&policy_steps, &host_policy_name)?;
    let host_policy_run = yaml_string(yaml_get(host_policy, "run"))
        .ok_or_else(|| PolicyError::new(format!("{path} Linux host policy has no run script")))?;
    let expected_host_policy = format!(
        "cargo deny --manifest-path {platform}/Cargo.toml --config {platform}/deny.toml \
         --locked --all-features --target x86_64-unknown-linux-gnu check"
    );
    if normalized_command(host_policy_run) != expected_host_policy {
        return Err(PolicyError::new(format!(
            "{path} Linux host dependency-policy target changed"
        )));
    }
    let shipped_policy_name = format!("Check {label} dependency policy");
    let shipped_policy = workflow_step(&policy_steps, &shipped_policy_name)?;
    let shipped_policy_run = yaml_string(yaml_get(shipped_policy, "run"))
        .ok_or_else(|| PolicyError::new(format!("{path} shipped policy has no run script")))?;
    let expected_shipped_policy = format!(
        "cargo deny --manifest-path {platform}/Cargo.toml --config {platform}/deny.toml \
         --locked --all-features check"
    );
    if normalized_command(shipped_policy_run) != expected_shipped_policy {
        return Err(PolicyError::new(format!(
            "{path} shipped-target dependency policy command changed"
        )));
    }
    let package = workflow_job(&workflow, "package")?;
    if yaml_string(yaml_get(package, "runs-on")) != Some(package_runner) {
        return Err(PolicyError::new(format!(
            "{path} shipped-target package job runner changed"
        )));
    }
    let package_steps = workflow_job_steps(&workflow, "package")?;
    let install = workflow_step(&package_steps, install_step)?;
    let install_run = yaml_string(yaml_get(install, "run"))
        .ok_or_else(|| PolicyError::new(format!("{path} target installation has no run script")))?;
    for expected_install in [
        format!("rustup target add {}", targets.join(" ")),
        "rustup toolchain install 1.94.0 --profile minimal".to_owned(),
        format!(
            "rustup target add --toolchain 1.94.0 {}",
            targets.join(" ")
        ),
    ] {
        if !install_run.contains(&expected_install) {
            return Err(PolicyError::new(format!(
                "{path} installed target set changed: missing {expected_install:?}"
            )));
        }
    }
    let check = workflow_step(&package_steps, target_step)?;
    if yaml_string(yaml_get(check, "run")).map(normalized_command)
        != Some(target_command.to_owned())
    {
        return Err(PolicyError::new(format!(
            "{path} shipped-target check command changed"
        )));
    }
    let check_env = yaml_get(check, "env")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new(format!("{path} shipped-target check env is missing")))?;
    if yaml_string(check_env.get(yaml_key("RUSTUP_TOOLCHAIN"))) != Some("1.94.0") {
        return Err(PolicyError::new(format!(
            "{path} shipped-target check must use Rust 1.94.0"
        )));
    }
    Ok(())
}

fn validate_candidate_target_coverage(root: &SafeRoot) -> PolicyResult<()> {
    validate_deny_targets(
        root,
        "desktop/deny.toml",
        &[
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        ],
    )?;
    validate_deny_targets(
        root,
        "android/deny.toml",
        &["aarch64-linux-android", "x86_64-linux-android"],
    )?;
    validate_deny_targets(
        root,
        "ios/deny.toml",
        &["aarch64-apple-ios", "aarch64-apple-ios-sim"],
    )?;
    validate_desktop_target_workflow(root)?;
    validate_mobile_target_workflow(
        root,
        ".github/workflows/android-packaging.yml",
        "android",
        "Android",
        "ubuntu-latest",
        "Install Rust Android targets",
        &["aarch64-linux-android", "x86_64-linux-android"],
        "Check all declared Android targets at MSRV",
        "./android/scripts/check-targets.sh",
    )?;
    validate_mobile_target_workflow(
        root,
        ".github/workflows/ios-packaging.yml",
        "ios",
        "iOS",
        "macos-15",
        "Install Rust iOS targets",
        &["aarch64-apple-ios", "aarch64-apple-ios-sim"],
        "Check device and simulator targets at MSRV",
        "./ios/scripts/check-targets.sh",
    )?;
    Ok(())
}

fn validate_python_requirements(root: &SafeRoot) -> PolicyResult<()> {
    let requirements =
        root.read_text("compat/legacy/scripts/requirements.txt", DEFAULT_FILE_LIMIT)?;
    let mut parsed = BTreeMap::new();
    let mut current: Option<(String, String, usize)> = None;
    for line in requirements.lines().filter(|line| !line.trim().is_empty()) {
        if line.starts_with(char::is_whitespace) {
            let hash = line
                .trim()
                .strip_suffix('\\')
                .unwrap_or(line.trim())
                .trim()
                .strip_prefix("--hash=sha256:")
                .filter(|hash| {
                    hash.len() == 64
                        && hash
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or_else(|| {
                    PolicyError::new(format!(
                        "Python requirement hash is not a lowercase SHA-256: {line:?}"
                    ))
                })?;
            let Some((_, _, count)) = current.as_mut() else {
                return Err(PolicyError::new(
                    "Python requirement hash has no preceding requirement",
                ));
            };
            let _ = hash;
            *count = count
                .checked_add(1)
                .ok_or_else(|| PolicyError::new("Python requirement hash count overflow"))?;
            continue;
        }
        if let Some((name, version, hashes)) = current.take() {
            if hashes == 0 || parsed.insert(name.clone(), version).is_some() {
                return Err(PolicyError::new(format!(
                    "Python requirement entry has no unique SHA-256 binding: {name}"
                )));
            }
        }
        let requirement = line
            .strip_suffix('\\')
            .unwrap_or(line)
            .trim()
            .split_once("==")
            .filter(|(name, version)| !name.is_empty() && !version.is_empty())
            .ok_or_else(|| PolicyError::new(format!("Python requirement is not exact: {line}")))?;
        current = Some((requirement.0.to_owned(), requirement.1.to_owned(), 0));
    }
    if let Some((name, version, hashes)) = current {
        if hashes == 0 || parsed.insert(name.clone(), version).is_some() {
            return Err(PolicyError::new(format!(
                "Python requirement entry has no unique SHA-256 binding: {name}"
            )));
        }
    }
    let expected = EXACT_PYTHON_REQUIREMENTS.into_iter().collect::<BTreeMap<_, _>>();
    let actual = parsed
        .iter()
        .map(|(name, version)| (name.as_str(), version.as_str()))
        .collect::<BTreeMap<_, _>>();
    if actual != expected {
        return Err(PolicyError::new(format!(
            "Python requirement inventory changed: expected {expected:?}, found {actual:?}"
        )));
    }
    Ok(())
}

fn validate_python_source_revisions(root: &SafeRoot) -> PolicyResult<()> {
    if LEGACY_SOURCE_REVISION.len() != 40
        || !LEGACY_SOURCE_REVISION
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(PolicyError::new(
            "protected legacy source revision is not an exact lowercase 40-hex commit SHA",
        ));
    }
    for path in LEGACY_REVISION_DOCUMENTS {
        let document = parse_json(root, path)?;
        let document = json_object(&document, path)?;
        require_json_string(
            document,
            "source_revision",
            LEGACY_SOURCE_REVISION,
            path,
        )?;
    }
    Ok(())
}

fn validate_python_workflow(root: &SafeRoot) -> PolicyResult<()> {
    let text = root.read_text(RUST_WORKFLOW, DEFAULT_FILE_LIMIT)?;
    let workflow: YamlValue = serde_yaml_ng::from_str(&text)
        .map_err(|cause| error("parse Rust workflow for Python policy", cause))?;
    let steps = workflow_steps(&workflow)?;
    let setup = workflow_step(&steps, "Set up pinned Python")?;
    if yaml_string(yaml_get(setup, "uses")) != Some(SETUP_PYTHON_ACTION)
        || yaml_get(setup, "with")
            .and_then(yaml_mapping)
            .and_then(|with| yaml_string(with.get(yaml_key("python-version"))))
            != Some("3.13.5")
    {
        return Err(PolicyError::new(
            "setup-python action or interpreter is not pinned",
        ));
    }
    let validation = workflow_step(&steps, "Validate locked Python compatibility policy")?;
    let run = yaml_string(yaml_get(validation, "run"))
        .ok_or_else(|| PolicyError::new("Python policy validation step has no run script"))?;
    for required in [
        "python3 -c 'import json; print(json.load(open(\"compat/legacy/contract.json\", encoding=\"utf-8\"))[\"source_revision\"])'",
        "[[ \"$source_revision\" =~ ^[0-9a-f]{40}$ ]]",
        "git fetch --no-tags --depth=1 origin \"$source_revision\"",
        "test \"$(git rev-parse FETCH_HEAD)\" = \"$source_revision\"",
        "git cat-file -e \"${source_revision}^{commit}\"",
        "python3 -m pip install",
        "--disable-pip-version-check",
        "--only-binary=:all:",
        "--require-hashes",
        "--requirement compat/legacy/scripts/requirements.txt",
        "python3 -m pip check",
        "python3 compat/legacy/scripts/validate.py",
    ] {
        if !run.contains(required) {
            let diagnostic = if required == "--require-hashes" {
                "pip install does not require hashes"
            } else {
                "Python workflow invocation is not exact"
            };
            return Err(PolicyError::new(format!("{diagnostic}: {required}")));
        }
    }
    if run.contains("python3 -m pip install --upgrade")
        || run.contains("python3 -m pip install -U")
    {
        return Err(PolicyError::new(
            "mutable pip upgrade is forbidden",
        ));
    }

    let triggers = yaml_get(&workflow, "on")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new("Rust workflow triggers must be a mapping"))?;
    for event in ["push", "pull_request"] {
        let paths = triggers
            .get(yaml_key(event))
            .and_then(yaml_mapping)
            .and_then(|event| event.get(yaml_key("paths")))
            .and_then(YamlValue::as_sequence)
            .ok_or_else(|| PolicyError::new(format!("Rust workflow {event} paths are missing")))?
            .iter()
            .map(|path| {
                yaml_string(Some(path)).ok_or_else(|| {
                    PolicyError::new(format!("Rust workflow {event} path is not a string"))
                })
            })
            .collect::<PolicyResult<BTreeSet<_>>>()?;
        for required in [
            ".env.example",
            "compat/**",
            "src/**",
            "test/**",
            "Dockerfile",
            "package-lock.json",
            "package.json",
            "tsconfig.json",
        ] {
            if !paths.contains(required) {
                return Err(PolicyError::new(format!(
                    "Rust workflow {event} paths do not cover compatibility input {required}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_docker_workflow(root: &SafeRoot) -> PolicyResult<()> {
    let text = root.read_text(DOCKER_WORKFLOW, DEFAULT_FILE_LIMIT)?;
    let workflow: YamlValue = serde_yaml_ng::from_str(&text)
        .map_err(|cause| error("parse Docker publish workflow", cause))?;
    let triggers = yaml_get(&workflow, "on")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new("Docker publish workflow has no on mapping"))?;
    if !triggers.contains_key(yaml_key("pull_request")) {
        return Err(PolicyError::new(
            "Docker secret-free pull request build is missing",
        ));
    }
    let steps = workflow_steps(&workflow)?;
    let uses = steps
        .iter()
        .filter_map(|step| yaml_string(yaml_get(step, "uses")))
        .collect::<Vec<_>>();
    for pin in DOCKER_WORKFLOW_ACTION_PINS {
        if uses.iter().filter(|action| **action == pin).count() != 1 {
            return Err(PolicyError::new(format!(
                "Docker workflow action pin changed: {pin}"
            )));
        }
    }
    if uses
        .iter()
        .filter(|action| action.starts_with("docker/"))
        .count()
        != 3
        || uses
            .iter()
            .any(|action| action.starts_with("docker/build-push-action@"))
    {
        return Err(PolicyError::new("Docker workflow action set changed"));
    }

    let build = workflow_step(&steps, "Build image once")?;
    let build_run = yaml_string(yaml_get(build, "run"))
        .ok_or_else(|| PolicyError::new("Docker build step has no run script"))?;
    if build_run.matches("docker buildx build \\").count() != 1 {
        return Err(PolicyError::new(
            "Docker publish workflow must build exactly once",
        ));
    }
    let validate = workflow_step(&steps, "Validate exact built image")?;
    let validate_run = yaml_string(yaml_get(validate, "run"))
        .ok_or_else(|| PolicyError::new("Docker validation step has no run script"))?;
    for required in [
        "test \"$(docker image inspect --format '{{.Id}}' \"$IMAGE_TAG\")\" = \"$EXPECTED_IMAGE_ID\"",
        "await access(\"/app/package-lock.json\", constants.R_OK);",
        "await access(process.env.COPILOT_CLI_PATH, constants.X_OK);",
        "selectIsolationMode(false, \"production\")",
    ] {
        if !validate_run.contains(required) {
            return Err(PolicyError::new(format!(
                "Docker build/validate/push coupling changed: {required}"
            )));
        }
    }
    let push = workflow_step(&steps, "Push the validated image digest")?;
    if yaml_string(yaml_get(push, "if")) != Some("github.event_name != 'pull_request'") {
        return Err(PolicyError::new(
            "Docker push step must remain disabled for pull requests",
        ));
    }
    let push_run = yaml_string(yaml_get(push, "run"))
        .ok_or_else(|| PolicyError::new("Docker push step has no run script"))?;
    for required in [
        "for (i = 1; i <= NF; i++) if ($i ~ /^sha256:/) print $i",
        "test \"$digest\" = \"$pushed_digest\"",
    ] {
        if !push_run.contains(required) {
            let diagnostic = if required.starts_with("for (i = 1") {
                "Docker publish digest parser changed"
            } else {
                "Docker build/validate/push coupling changed"
            };
            return Err(PolicyError::new(format!("{diagnostic}: {required}")));
        }
    }
    Ok(())
}

fn validate_candidate_legacy_supply_chain(root: &SafeRoot) -> PolicyResult<()> {
    validate_node_package_policy(root)?;
    validate_dockerfile_policy(root)?;
    validate_runtime_source_policy(root)?;
    validate_environment_mapping_policy(root)?;
    validate_python_requirements(root)?;
    validate_python_source_revisions(root)?;
    validate_python_workflow(root)?;
    validate_docker_workflow(root)?;
    for (path, digest) in REVIEWED_POLICY_INPUTS {
        require_reviewed_digest(root, path, digest)?;
    }
    Ok(())
}

fn normalized_command(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_policy_execution_workflows(root: &SafeRoot) -> PolicyResult<()> {
    let workflow_text = root.read_text(UPSTREAM_WORKFLOW, DEFAULT_FILE_LIMIT)?;
    let workflow: YamlValue = serde_yaml_ng::from_str(&workflow_text)
        .map_err(|cause| error("parse upstream repository-policy workflow", cause))?;
    if yaml_get(&workflow, "env").is_some() || yaml_get(&workflow, "defaults").is_some() {
        return Err(PolicyError::new(
            "upstream repository-policy workflow must not override global execution state",
        ));
    }
    let triggers = yaml_get(&workflow, "on")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new("upstream repository-policy workflow has no on mapping"))?;
    let pull_request = triggers.get(yaml_key("pull_request")).ok_or_else(|| {
        PolicyError::new("upstream repository-policy workflow must run on every pull request")
    })?;
    if !matches!(pull_request, YamlValue::Null)
        && yaml_mapping(pull_request).is_none_or(|mapping| !mapping.is_empty())
    {
        return Err(PolicyError::new(
            "upstream repository-policy pull_request trigger must not use filters",
        ));
    }
    let permissions = yaml_get(&workflow, "permissions")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new("upstream repository-policy permissions are missing"))?;
    if permissions.len() != 1 || yaml_string(permissions.get(yaml_key("contents"))) != Some("read")
    {
        return Err(PolicyError::new(
            "upstream repository-policy permissions must be exactly contents: read",
        ));
    }
    let jobs = yaml_get(&workflow, "jobs")
        .and_then(yaml_mapping)
        .ok_or_else(|| PolicyError::new("upstream repository-policy jobs are missing"))?;
    let mut policy_jobs = 0_usize;
    for job in jobs.values() {
        let Some(steps) = yaml_get(job, "steps").and_then(YamlValue::as_sequence) else {
            continue;
        };
        let policy_positions = steps
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                yaml_string(yaml_get(step, "run")).is_some_and(|run| {
                normalized_command(run)
                    == "cargo test --locked --package claw-repo-policy --test repository_policy"
                })
                .then_some(index)
            })
            .collect::<Vec<_>>();
        if policy_positions.is_empty() {
            continue;
        }
        let job = yaml_mapping(job)
            .ok_or_else(|| PolicyError::new("repository-policy job is not a mapping"))?;
        let job_keys = job
            .keys()
            .filter_map(YamlValue::as_str)
            .collect::<BTreeSet<_>>();
        let timeout = job
            .get(yaml_key("timeout-minutes"))
            .and_then(YamlValue::as_u64);
        if policy_positions != [1]
            || job.len() != 4
            || job_keys != BTreeSet::from(["name", "runs-on", "steps", "timeout-minutes"])
            || yaml_string(job.get(yaml_key("runs-on"))) != Some("windows-latest")
            || timeout.is_none_or(|timeout| !(1..=45).contains(&timeout))
            || steps.len() < 2
        {
            return Err(PolicyError::new(
                "repository-policy test job shape or execution order changed",
            ));
        }
        let checkout = yaml_mapping(&steps[0])
            .ok_or_else(|| PolicyError::new("repository-policy checkout is not a mapping"))?;
        let checkout_with = checkout
            .get(yaml_key("with"))
            .and_then(yaml_mapping)
            .ok_or_else(|| PolicyError::new("repository-policy checkout inputs are missing"))?;
        if checkout.len() != 3
            || checkout
                .keys()
                .filter_map(YamlValue::as_str)
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(["name", "uses", "with"])
            || yaml_string(checkout.get(yaml_key("name"))) != Some("Checkout GTA Claw")
            || yaml_string(checkout.get(yaml_key("uses")))
                != Some("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
            || checkout_with.len() != 1
            || checkout_with
                .get(yaml_key("persist-credentials"))
                .and_then(YamlValue::as_bool)
                != Some(false)
        {
            return Err(PolicyError::new(
                "repository-policy test must start from the exact isolated checkout",
            ));
        }
        let policy_step = yaml_mapping(&steps[1])
            .ok_or_else(|| PolicyError::new("repository-policy test step is not a mapping"))?;
        if policy_step.len() != 2
            || policy_step
                .keys()
                .filter_map(YamlValue::as_str)
                .collect::<BTreeSet<_>>()
                != BTreeSet::from(["name", "run"])
            || yaml_string(policy_step.get(yaml_key("name"))) != Some(POLICY_TEST_STEP_NAME)
        {
            return Err(PolicyError::new(
                "repository-policy test step or blocking semantics changed",
            ));
        }
        policy_jobs = policy_jobs
            .checked_add(1)
            .ok_or_else(|| PolicyError::new("repository-policy job count overflow"))?;
    }
    if policy_jobs != 1 {
        return Err(PolicyError::new(
            "always-on repository-policy workflow must contain exactly one policy job",
        ));
    }

    let rust = root.read_text(RUST_WORKFLOW, DEFAULT_FILE_LIMIT)?;
    if !rust
        .lines()
        .any(|line| line.trim() == "run: cargo test --workspace --all-targets --locked")
    {
        return Err(PolicyError::new(
            "Headless workspace tests no longer execute claw-repo-policy",
        ));
    }
    Ok(())
}

fn validate_policy_crate(root: &SafeRoot, files: &[String]) -> PolicyResult<()> {
    let actual = files
        .iter()
        .filter(|path| path.starts_with(&format!("{POLICY_CRATE}/")))
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = [POLICY_MANIFEST, POLICY_LIBRARY, POLICY_TEST]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(PolicyError::new(format!(
            "claw-repo-policy file inventory changed: expected {expected:?}, found {actual:?}"
        )));
    }
    validate_policy_manifest(root)?;
    validate_policy_source(root)?;
    validate_policy_execution_workflows(root)?;
    if !root.exists(ALLOWED_SHELL_FIXTURE)? {
        return Err(PolicyError::new(
            "the exact inert adversarial shell fixture is missing",
        ));
    }
    Ok(())
}

fn policy_crate_is_present(files: &[String]) -> bool {
    files
        .iter()
        .any(|path| path.starts_with(&format!("{POLICY_CRATE}/")))
}

/// Enforces monotonic legacy-artifact and workflow reduction across one Final base-to-head pair.
pub fn validate_repository_policy_transition(
    trusted: &SafeRoot,
    candidate: &SafeRoot,
) -> PolicyResult<()> {
    let trusted_files = repository_files(trusted)?;
    let candidate_files = repository_files(candidate)?;
    validate_reviewed_legacy_tests(trusted, &trusted_files)?;
    validate_reviewed_legacy_tests(candidate, &candidate_files)?;
    let trusted_artifacts = legacy_artifacts(&trusted_files);
    let candidate_artifacts = legacy_artifacts(&candidate_files);
    require_artifacts_within_ceiling(&trusted_artifacts, "protected base")?;
    require_artifacts_within_ceiling(&candidate_artifacts, "candidate")?;
    require_candidate_subset(&trusted_artifacts, &candidate_artifacts)?;

    let trusted_workflow_violations = workflow_violations(trusted, &trusted_files)?;
    let candidate_workflow_violations = workflow_violations(candidate, &candidate_files)?;
    let trusted_active = policy_crate_is_present(&trusted_files);
    let candidate_active = policy_crate_is_present(&candidate_files);
    if trusted_active && !candidate_active {
        return Err(PolicyError::new(
            "candidate removed the base-owned claw-repo-policy crate",
        ));
    }
    if trusted_active {
        validate_policy_crate(trusted, &trusted_files)?;
    }
    if candidate_active {
        validate_policy_crate(candidate, &candidate_files)?;
        if !candidate_workflow_violations.is_empty() {
            return Err(PolicyError::new(format!(
                "active claw-repo-policy requires zero Node workflow/action violations: {:?}",
                candidate_workflow_violations.keys().collect::<Vec<_>>()
            )));
        }
    } else {
        require_violation_subset(&trusted_workflow_violations, &candidate_workflow_violations)?;
    }
    validate_candidate_target_coverage(candidate)?;
    validate_candidate_legacy_supply_chain(candidate)?;
    Ok(())
}
