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
const ALLOWED_INERT_WORKFLOW_LINES: &[(&str, &str)] = &[
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
    assert_eq!(
        LEGACY_RUNTIME_INVENTORY
            .iter()
            .filter(|path| path.ends_with(".ts") || path.ends_with(".tsx"))
            .count(),
        18,
        "the binding legacy TypeScript ceiling changed without an explicit ratchet update"
    );
    for required_root in [
        "Dockerfile",
        "package-lock.json",
        "package.json",
        "tsconfig.json",
    ] {
        assert!(
            LEGACY_RUNTIME_INVENTORY.contains(&required_root),
            "legacy build root is missing from the explicit inventory: {required_root}"
        );
    }
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
            allowed.starts_with(".github/fixtures/security-tools/") && allowed.ends_with(".sh"),
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
        } else if file_type.is_dir() {
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

fn scan_policy_document(path: &str, document: &str, violations: &mut Vec<String>) {
    for (line_index, line) in document.lines().enumerate() {
        let trimmed = line.trim();
        if ALLOWED_INERT_WORKFLOW_LINES
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
