//! Content policy for the admitted `ios-packaging.yml` workflow.
//!
//! `ios-packaging.yml` is an admitted, optional workflow path (`ADMITTED_WORKFLOWS` in
//! `workflows.rs`): it may be absent, and today it is absent from every checkout this trust root
//! validates — no `ios/` workspace exists on `main`, and closed PR #110, which drafted a shell
//! under `ios/`, is audit evidence only and is neither reopened nor mutated by this change. **A
//! file at this path is not itself proof of Skia exposure.** Live PR #138 already admits
//! `.github/workflows/ios-packaging.yml`, but it packages `apps/gta-claw-ios` — a different,
//! Skia-free application, proven Skia-free by that PR's own CI (a `cargo tree` assertion with a
//! positive control, so an empty resolved dependency tree cannot vacuously pass) — and never
//! fetches a Skia archive at all. This module's checks therefore apply only to the steps of an
//! admitted `ios-packaging.yml` that actually target the iOS Skia workspace
//! ([`targets_ios_skia_workspace`]): the workspace or app manifest `MOBILE_PLATFORMS` declares for
//! iOS, its exact app package name, or an exact `working-directory: ios`. A workflow admitted at
//! this path with no such step — like PR #138's — has nothing here for this trust chain to
//! protect and is accepted outright; the moment any step does target that workspace, every
//! prebuilt Skia archive it could fetch must be resolved through the trusted CLI resolver
//! (`resolve-build-artifact-pin`, backed by `PINNED_BUILD_ARTIFACTS`), never a URL or digest typed
//! directly into the YAML, fetched with a fail-closed download to a path derived from the
//! resolved URL's own basename (never a hardcoded literal), verified locally, and only then handed
//! to `cargo` through the supported `SKIA_BINARIES_URL=file://...` override — an absolute path,
//! since `skia-bindings` reads everything after the `file://` prefix as a literal path — with
//! `FORCE_SKIA_BINARIES_DOWNLOAD` set and the resulting build log checked for the exact evidence
//! that the forced download-and-unpack path actually ran, not merely declared.
//!
//! ## What this check proves, and what it does not
//!
//! This is a **static content check** over the workflow YAML text and structure. It proves the
//! workflow *says* the right things: the right resolver invocations, the right fail-closed curl
//! flags, the right environment variables wired to the right cargo steps, in the right order. It
//! does not execute the workflow, does not simulate GitHub Actions expression evaluation, and does
//! not perform shell data-flow analysis. Several deliberate, bounded conventions make that
//! tractable, and are the limits of what this module can see:
//!
//! - Cross-target substitution is detected through **fixed environment variable names**
//!   ([`SKIA_ARCHIVE_IOS_DEVICE_VAR`] / [`SKIA_ARCHIVE_IOS_SIM_VAR`]) that the workflow must
//!   publish through `$GITHUB_ENV` after each resolve-and-verify step, and reference through the
//!   standard `${{ env.NAME }}` expression syntax in a later step's `env:` mapping. A workflow that
//!   smuggled the verified path through some other channel (a file, a step output, string
//!   concatenation) would not be recognized, and is rejected exactly as if the override were
//!   entirely missing — the same fail-closed posture as the prefix-collision fix this module reuses
//!   (`exact_flag_token` below plays the same role for CLI flags that
//!   `longest_admitted_target_in_url` plays for pin URLs in `policy.rs`).
//! - A "Skia-resolving cargo step" is identified by a bounded, explicit rule
//!   ([`is_skia_resolving_cargo_step`]): a `cargo` token followed within two tokens by
//!   `check`/`clippy`/`build`/`test`/`run` on the same line. It does not prove which crates a given
//!   invocation actually compiles — which is exactly why it is only ever applied after
//!   [`targets_ios_skia_workspace`] has already narrowed to steps naming the iOS Skia workspace by
//!   exact manifest path, package name, or working directory; applied unconditionally, this rule
//!   alone would also match PR #138's `cargo build --package gta-claw-ios`, an unrelated,
//!   already-audited, Skia-free build.
//! - Token scanning is whitespace-based, per line, and quote-trimming only; it is not a shell
//!   parser. A flag value split across a line continuation, or built by shell substitution, is out
//!   of scope, exactly as the README already documents for the URL/target matching this module's
//!   `exact_flag_token` mirrors. The build-log evidence check is the same kind of bounded textual
//!   proxy: it confirms the workflow's own script *contains* the exact `skia-bindings` log lines
//!   and a check for the failure line, not that a shell interpreter's negation logic is correct.
//!
//! Digest mismatches, 404s, and "wrong local archive" substitutions are **not** static content
//! properties of the YAML; they are runtime facts about what a `curl` and a local file actually
//! contain, and are covered by `resolve_build_artifact_pin`/`verify_local_build_artifact` in
//! `policy.rs` and their own tests instead.

use std::collections::{BTreeMap, BTreeSet};

use serde_yaml_ng::Value as YamlValue;

use crate::policy::{
    ios_app_manifest_path, ios_app_package_name, ios_skia_targets, ios_workspace_directory,
    ios_workspace_manifest_path, skia_bindings_package_name, skia_bindings_pin_version,
};
use crate::workflows::{get, mapping, string};
use crate::{PolicyError, PolicyResult};

/// Fixed environment variable name publishing the verified local iOS device archive path.
///
/// Fixed rather than caller-chosen so cross-target substitution and "mutable name" fallbacks
/// (reusing one variable name for both targets, so a later assignment silently overwrites an
/// earlier one) are structurally impossible to satisfy this check: the device and simulator
/// archives can only ever be referenced by these two distinct, non-overlapping names.
pub const SKIA_ARCHIVE_IOS_DEVICE_VAR: &str = "SKIA_ARCHIVE_IOS_DEVICE";
/// Fixed environment variable name publishing the verified local iOS simulator archive path.
pub const SKIA_ARCHIVE_IOS_SIM_VAR: &str = "SKIA_ARCHIVE_IOS_SIM";
/// The environment variable `skia-bindings`' build script reads for a prebuilt archive location.
const SKIA_BINARIES_URL_VAR: &str = "SKIA_BINARIES_URL";
/// The environment variable forcing `skia-bindings` to use the pinned prebuilt path.
const FORCE_SKIA_BINARIES_DOWNLOAD_VAR: &str = "FORCE_SKIA_BINARIES_DOWNLOAD";
/// The trusted CLI subcommand that resolves one reviewed build-artifact pin.
const RESOLVER_SUBCOMMAND: &str = "resolve-build-artifact-pin";
/// Cargo subcommands capable of invoking a build script and therefore able to resolve Skia.
const SKIA_RESOLVING_CARGO_SUBCOMMANDS: [&str; 5] = ["check", "clippy", "build", "test", "run"];
/// A trigger `paths:` filter that includes this workflow must include the trusted pin table.
const TRUSTED_ROOT_TRIGGER_PATH: &str = ".github/trusted/**";

/// Literal build-script log line `skia-bindings` 0.99.0 prints only when it actually attempts its
/// own download-and-install path
/// (`build_support/binary_cache/download.rs::try_prepare_download`, confirmed against the
/// published source at that tag).
const SKIA_DOWNLOAD_ATTEMPTED_LOG: &str = "TRYING TO DOWNLOAD AND INSTALL SKIA BINARIES";
/// Literal build-script log line printed only after the archive is fetched and unpacked
/// (`download_and_unpack`) — i.e. after a complete, successful download.
const SKIA_UNPACK_LOG: &str = "UNPACKING ARCHIVE INTO";
/// Literal build-script log line printed on any download-or-unpack failure. An admitted workflow
/// must check its own captured log for this line's *absence*; `Compiling skia-bindings` alone
/// proves nothing, since a stale build directory or a silent fallback source build can print that
/// line too.
const SKIA_DOWNLOAD_FAILED_LOG: &str = "DOWNLOAD AND INSTALL FAILED";

/// Immutable per-job context threaded through the step-level checks below.
struct StepContext<'a> {
    path: &'a str,
    job_id: &'a str,
    device: &'static str,
    sim: &'static str,
}

/// One workflow step's shell command text, effective (workflow + job + step) environment, and
/// declared `working-directory`, if any.
struct ParsedStep<'a> {
    run: Option<&'a str>,
    env: BTreeMap<String, String>,
    working_directory: Option<&'a str>,
}

fn scalar_text(value: &YamlValue) -> Option<String> {
    match value {
        YamlValue::String(text) => Some(text.clone()),
        YamlValue::Bool(flag) => Some(flag.to_string()),
        YamlValue::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Flattens a YAML `env:` mapping into plain strings, dropping any non-scalar entry.
fn env_map(value: Option<&YamlValue>) -> BTreeMap<String, String> {
    let Some(entries) = value.and_then(mapping) else {
        return BTreeMap::new();
    };
    entries
        .iter()
        .filter_map(|(key, value)| Some((string(Some(key))?.to_owned(), scalar_text(value)?)))
        .collect()
}

fn tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split_ascii_whitespace()
}

/// Returns whether `text` contains `token` as one exact whitespace-delimited token, anywhere.
fn contains_word_token(text: &str, token: &str) -> bool {
    tokens(text).any(|candidate| candidate == token)
}

fn trim_matching_quotes(token: &str) -> &str {
    let bytes = token.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            return &token[1..token.len() - 1];
        }
    }
    token
}

/// Returns whether `text` invokes `flag` with exactly `value`, as `--flag value` or
/// `--flag=value`, with at most one layer of matching quotes trimmed from the value.
///
/// Exact-token equality only — never `contains`/prefix matching — for the same reason
/// `longest_admitted_target_in_url` in `policy.rs` cannot use `contains`: `aarch64-apple-ios` is a
/// proper prefix of `aarch64-apple-ios-sim`, so a naive substring check on `--target` values would
/// let a simulator invocation satisfy a device check or vice versa.
fn exact_flag_token(text: &str, flag: &str, value: &str) -> bool {
    let mut iter = tokens(text).peekable();
    while let Some(token) = iter.next() {
        if token == flag {
            if let Some(&next) = iter.peek()
                && trim_matching_quotes(next) == value
            {
                return true;
            }
            continue;
        }
        if let Some(rest) = token.strip_prefix(flag)
            && let Some(equals_value) = rest.strip_prefix('=')
            && trim_matching_quotes(equals_value) == value
        {
            return true;
        }
    }
    false
}

/// Returns whether `token` looks like a `curl` fail-closed flag: `--fail`, `--fail-with-body`, or
/// any short-option cluster (a single dash followed only by letters) containing `f`, which covers
/// combined forms such as `-f`, `-fL`, `-sSfL`.
fn is_curl_fail_flag(token: &str) -> bool {
    if token == "--fail" || token == "--fail-with-body" {
        return true;
    }
    match token.strip_prefix('-') {
        Some(rest) if !rest.is_empty() && !rest.starts_with('-') => {
            rest.chars().all(|ch| ch.is_ascii_alphabetic()) && rest.contains('f')
        }
        _ => false,
    }
}

/// Returns whether some line of `run` both invokes `curl` and carries a fail-closed flag.
///
/// Scoped per line (not the whole multi-line `run:` block) so an unrelated command's flags on a
/// different line are never mistaken for `curl`'s own; a `curl` invocation whose flags are split
/// across a shell line continuation is out of scope, consistent with this module's other
/// whitespace/per-line token scanning.
fn has_fail_closed_curl(run: &str) -> bool {
    run.lines().any(|line| {
        let mut saw_curl = false;
        let mut saw_fail_flag = false;
        for token in tokens(line) {
            if token == "curl" {
                saw_curl = true;
            }
            if is_curl_fail_flag(token) {
                saw_fail_flag = true;
            }
        }
        saw_curl && saw_fail_flag
    })
}

/// Returns the value token following a standalone `-o`/`--output` flag on the line of `run` that
/// invokes `curl`, if any.
///
/// Bounded and textual like the rest of this module: a combined short-option cluster such as
/// `-fSLo file` is out of scope, exactly as `is_curl_fail_flag`'s own doc comment already notes
/// combined clusters are recognized for fail-closed flags but not decomposed for their values.
fn curl_output_token(run: &str) -> Option<&str> {
    run.lines().find_map(|line| {
        if !contains_word_token(line, "curl") {
            return None;
        }
        let mut iter = tokens(line).peekable();
        while let Some(token) = iter.next() {
            if token == "-o" || token == "--output" {
                return iter.peek().map(|next| trim_matching_quotes(next));
            }
        }
        None
    })
}

/// Returns whether `token` looks like a value written directly into the workflow YAML, rather
/// than a shell variable reference or command substitution (`$name`, `${name}`, `$(...)`).
///
/// The curl output filename must always be the latter: derived from the same resolver-returned
/// URL that names the archive, never a name chosen ahead of time, so a target/key mismatch between
/// a hardcoded local filename and the archive actually fetched cannot occur.
fn is_hardcoded_literal(token: &str) -> bool {
    !token.starts_with('$')
}

fn is_identifier_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

/// Returns the assigned value text for `run`'s exact publication of `var` via `$GITHUB_ENV`, if
/// any: the substring after `var=`, on a line that mentions `$GITHUB_ENV`, up to the next
/// unescaped double quote or whitespace. `None` if `run` never exactly publishes `var` this way.
///
/// The assignment is not itself a suffix of a longer identifier (so `FOO_VAR=` is never mistaken
/// for a match on `VAR`) — the one property [`publishes_archive_var`] and
/// [`publishes_absolute_archive_var`] both need, so they share this lookup rather than
/// duplicating it.
fn archive_var_assignment<'a>(run: &'a str, var: &str) -> Option<&'a str> {
    let needle = format!("{var}=");
    for line in run.lines() {
        if !line.contains("GITHUB_ENV") {
            continue;
        }
        let bytes = line.as_bytes();
        let mut search_from = 0usize;
        while let Some(relative) = line[search_from..].find(needle.as_str()) {
            let start = search_from + relative;
            if start == 0 || !is_identifier_byte(bytes[start - 1]) {
                let value_start = start + needle.len();
                let rest = &line[value_start..];
                let end = rest
                    .find(|ch: char| ch == '"' || ch.is_ascii_whitespace())
                    .unwrap_or(rest.len());
                return Some(&rest[..end]);
            }
            search_from = start + 1;
        }
    }
    None
}

/// Returns whether `run` publishes `var` via `$GITHUB_ENV` at all (see
/// [`archive_var_assignment`]).
fn publishes_archive_var(run: &str, var: &str) -> bool {
    archive_var_assignment(run, var).is_some()
}

/// Returns whether `run` publishes `var` via `$GITHUB_ENV` as a visibly absolute path: starting
/// with `/`, or one of the shell forms that always expand to an absolute path in a GitHub Actions
/// job (`$(pwd)/`, `$PWD/`, `${PWD}/`, `$GITHUB_WORKSPACE/`, `${GITHUB_WORKSPACE}/`).
///
/// `skia-bindings` reads everything after a `file://` prefix as a literal path with no further
/// parsing (confirmed against its `download` implementation: a plain `strip_prefix("file://")`
/// followed by `fs::read`) — a *relative* path is technically readable by the crate this way, but
/// is silently working-directory-dependent; this policy requires the unambiguous absolute form
/// instead.
fn publishes_absolute_archive_var(run: &str, var: &str) -> bool {
    const ABSOLUTE_PREFIXES: [&str; 6] = [
        "/",
        "$(pwd)/",
        "$PWD/",
        "${PWD}/",
        "$GITHUB_WORKSPACE/",
        "${GITHUB_WORKSPACE}/",
    ];
    archive_var_assignment(run, var).is_some_and(|value| {
        ABSOLUTE_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
    })
}

/// Strips all ASCII whitespace, so `${{ env.X }}` and `${{env.X}}` compare equal.
fn normalize_expression(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect()
}

fn expected_file_url(var: &str) -> String {
    normalize_expression(&format!("file://${{{{ env.{var} }}}}"))
}

/// Distinguishes the iOS device and simulator targets `MOBILE_PLATFORMS` declares by name, without
/// hardcoding either literal target string here.
fn device_and_sim_targets() -> PolicyResult<(&'static str, &'static str)> {
    let targets = ios_skia_targets();
    let sim = targets
        .iter()
        .copied()
        .find(|target| target.ends_with("-sim"));
    let device = targets
        .iter()
        .copied()
        .find(|target| !target.ends_with("-sim"));
    match (device, sim) {
        (Some(device), Some(sim)) if targets.len() == 2 => Ok((device, sim)),
        _ => Err(PolicyError::new(
            "iOS platform must declare exactly two Skia targets, one device and one simulator, \
             to check its packaging workflow",
        )),
    }
}

/// Rejects a hardcoded pin URL or a bare SHA-256-shaped token appearing anywhere in the raw
/// workflow text, including comments (comments are invisible to the parsed YAML, but a literal
/// leaked into one is exactly as much a hardcoded duplicate as one in a `run:` string).
fn reject_literal_pin_leaks(text: &str, path: &str) -> PolicyResult<()> {
    if text.contains("skia-binaries/releases/download/") {
        return Err(PolicyError::new(format!(
            "{path} embeds a Skia release download URL literally; resolve it through \
             `{RESOLVER_SUBCOMMAND}` instead"
        )));
    }
    if contains_bare_hex_run_at_least(text, 64) {
        return Err(PolicyError::new(format!(
            "{path} embeds what looks like a bare SHA-256 digest literally; resolve it through \
             `{RESOLVER_SUBCOMMAND}` instead"
        )));
    }
    Ok(())
}

/// Returns whether `text` contains a maximal alphanumeric run, entirely hex digits, of at least
/// `min_len` characters — the shape of an accidentally hardcoded SHA-256 hex digest.
fn contains_bare_hex_run_at_least(text: &str, min_len: usize) -> bool {
    let mut run_len = 0usize;
    let mut run_is_hex = true;
    for ch in text.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_alphanumeric() {
            if run_len == 0 {
                run_is_hex = true;
            }
            run_is_hex &= ch.is_ascii_hexdigit();
            run_len += 1;
        } else {
            if run_is_hex && run_len >= min_len {
                return true;
            }
            run_len = 0;
        }
    }
    false
}

/// Returns whether `run` contains a `cargo` invocation of a Skia-resolving subcommand
/// (`check`/`clippy`/`build`/`test`/`run`) on some line, allowing up to one intervening token such
/// as a `+toolchain` selector.
///
/// Deliberately over-inclusive on its own — it does not look at which crate or workspace is being
/// built — because it is never applied to a step without first calling
/// [`targets_ios_skia_workspace`] on it: matching a bare cargo-subcommand shape against every step
/// in a workflow would also flag closed/live PR #138's `cargo build --package gta-claw-ios`, a
/// wholly unrelated, already-audited, Skia-free build at the same path this module admits.
fn is_skia_resolving_cargo_step(run: &str) -> bool {
    run.lines().any(|line| {
        let words = tokens(line).collect::<Vec<_>>();
        words.iter().enumerate().any(|(index, token)| {
            *token == "cargo"
                && words[index + 1..]
                    .iter()
                    .take(2)
                    .any(|candidate| SKIA_RESOLVING_CARGO_SUBCOMMANDS.contains(candidate))
        })
    })
}

/// Returns whether `step` targets the iOS Skia workspace `MOBILE_PLATFORMS` declares: an exact
/// `working-directory: ios`, or a `run:` invocation naming the exact workspace manifest, exact app
/// manifest, or exact app package.
///
/// Exact matching only — never `contains`/prefix matching — for the same reason
/// `longest_admitted_target_in_url` in `policy.rs` and `exact_flag_token` below are exact: the iOS
/// app package `gta-claw-ios-shell` is not a substring-safe discriminator against an unrelated app
/// such as `gta-claw-ios` (no `-shell` suffix) — `"gta-claw-ios"` is a proper prefix of
/// `"gta-claw-ios-shell"`, so a `contains` check would let one satisfy a match meant for the
/// other. A step naming none of these is not building the iOS Skia workspace, no matter which
/// Skia-resolving cargo subcommand it runs; most concretely, this is what correctly exempts
/// closed/live PR #138's `apps/gta-claw-ios` steps, proven Skia-free by that PR's own CI.
fn targets_ios_skia_workspace(step: &ParsedStep<'_>) -> bool {
    if step
        .working_directory
        .is_some_and(|value| value == ios_workspace_directory())
    {
        return true;
    }
    let Some(run) = step.run else {
        return false;
    };
    exact_flag_token(run, "--manifest-path", ios_workspace_manifest_path())
        || exact_flag_token(run, "--manifest-path", ios_app_manifest_path())
        || exact_flag_token(run, "--package", ios_app_package_name())
}

/// Resolves the exact admitted iOS target a resolver invocation names, requiring the exact
/// reviewed package and version alongside it.
fn resolver_invocation_target(
    run: &str,
    device: &'static str,
    sim: &'static str,
) -> PolicyResult<&'static str> {
    let matches = [device, sim]
        .into_iter()
        .filter(|target| exact_flag_token(run, "--target", target))
        .collect::<Vec<_>>();
    let &[target] = matches.as_slice() else {
        return Err(PolicyError::new(format!(
            "resolver invocation must name exactly one admitted iOS target, found {}: {matches:?}",
            matches.len()
        )));
    };
    if !exact_flag_token(run, "--package", skia_bindings_package_name())
        || !exact_flag_token(run, "--version", skia_bindings_pin_version())
    {
        return Err(PolicyError::new(format!(
            "resolver invocation for target {target} does not name the exact reviewed package \
             {} and version {}",
            skia_bindings_package_name(),
            skia_bindings_pin_version()
        )));
    }
    Ok(target)
}

/// Validates one step that invokes the trusted resolver: it must fetch with a fail-closed `curl`
/// to a filename derived from the resolved URL (never a hardcoded literal), verify that exact
/// local archive, and publish its verified absolute path under the fixed variable name for the
/// target it resolved.
fn validate_resolve_and_verify_step(
    ctx: &StepContext<'_>,
    index: usize,
    run: &str,
) -> PolicyResult<&'static str> {
    let target = resolver_invocation_target(run, ctx.device, ctx.sim).map_err(|cause| {
        PolicyError::new(format!(
            "{}: job {} step {index}: {cause}",
            ctx.path, ctx.job_id
        ))
    })?;
    if !has_fail_closed_curl(run) {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} fetches the {target} archive without a fail-closed curl \
             flag (e.g. -f/--fail), so a 404 or redirect would not fail the step",
            ctx.path, ctx.job_id
        )));
    }
    let Some(curl_output) = curl_output_token(run) else {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} fetches the {target} archive without a curl -o/--output \
             filename to verify",
            ctx.path, ctx.job_id
        )));
    };
    if is_hardcoded_literal(curl_output) {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} writes the {target} archive to a hardcoded filename \
             ({curl_output:?}) instead of one derived from the resolved URL, risking a \
             target/key mismatch between the local file and the archive actually fetched",
            ctx.path, ctx.job_id
        )));
    }
    if !exact_flag_token(run, "--verify-local", curl_output) {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} resolves the {target} pin without --verify-local naming \
             the exact fetched archive ({curl_output:?})",
            ctx.path, ctx.job_id
        )));
    }
    let expected_var = if target == ctx.sim {
        SKIA_ARCHIVE_IOS_SIM_VAR
    } else {
        SKIA_ARCHIVE_IOS_DEVICE_VAR
    };
    if !publishes_archive_var(run, expected_var) {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} verifies the {target} archive but never publishes \
             {expected_var} via $GITHUB_ENV",
            ctx.path, ctx.job_id
        )));
    }
    if !publishes_absolute_archive_var(run, expected_var) {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} publishes {expected_var} as a path that is not visibly \
             absolute (expected one of /, $(pwd)/, $PWD/, ${{PWD}}/, $GITHUB_WORKSPACE/, or \
             ${{GITHUB_WORKSPACE}}/); skia-bindings treats a file:// override as a literal path \
             with no further parsing, so a relative path would be silently working-directory \
             dependent",
            ctx.path, ctx.job_id
        )));
    }
    Ok(target)
}

/// Validates one Skia-resolving cargo step's effective environment: it must force the pinned
/// download path, point it at the verified local archive for exactly the target this step names
/// (or, for a step naming no explicit target, either verified archive), and that archive's
/// resolve-and-verify step must already have run earlier in the same job.
fn validate_skia_injection_env(
    ctx: &StepContext<'_>,
    index: usize,
    run: &str,
    env: &BTreeMap<String, String>,
    resolved_targets: &BTreeMap<&'static str, usize>,
) -> PolicyResult<()> {
    let force_truthy = env
        .get(FORCE_SKIA_BINARIES_DOWNLOAD_VAR)
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    if !force_truthy {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} runs a Skia-resolving cargo command without \
             {FORCE_SKIA_BINARIES_DOWNLOAD_VAR} set to a truthy value",
            ctx.path, ctx.job_id
        )));
    }

    let names_sim = exact_flag_token(run, "--target", ctx.sim);
    let names_device = exact_flag_token(run, "--target", ctx.device);
    let candidate_vars: &[&str] = if names_sim {
        &[SKIA_ARCHIVE_IOS_SIM_VAR]
    } else if names_device {
        &[SKIA_ARCHIVE_IOS_DEVICE_VAR]
    } else {
        // A host-target step (no explicit --target aimed at either admitted iOS target): no
        // specific pin applies to an unspecified host triple, so either established, verified
        // archive is accepted, as long as one actually is.
        &[SKIA_ARCHIVE_IOS_DEVICE_VAR, SKIA_ARCHIVE_IOS_SIM_VAR]
    };

    let url = env
        .get(SKIA_BINARIES_URL_VAR)
        .map(|value| normalize_expression(value));
    let referenced_var = candidate_vars
        .iter()
        .find(|var| url.as_deref() == Some(expected_file_url(var).as_str()));
    let Some(&referenced_var) = referenced_var else {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} does not set {SKIA_BINARIES_URL_VAR} to the verified local \
             archive for this step's target (expected one of {candidate_vars:?} via \
             file://${{{{ env.NAME }}}})",
            ctx.path, ctx.job_id
        )));
    };

    let resolved_target = if referenced_var == SKIA_ARCHIVE_IOS_SIM_VAR {
        ctx.sim
    } else {
        ctx.device
    };
    let resolved_index = resolved_targets.get(resolved_target).ok_or_else(|| {
        PolicyError::new(format!(
            "{}: job {} step {index} references {referenced_var} but no earlier step resolves \
             and verifies a pin for {resolved_target}",
            ctx.path, ctx.job_id
        ))
    })?;
    if *resolved_index >= index {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} references {referenced_var} before step {resolved_index}, \
             which resolves and verifies it, has run",
            ctx.path, ctx.job_id
        )));
    }
    Ok(())
}

/// Returns whether `run` requests cargo's "very verbose" build-script output level: `-vv` in one
/// token, or the same total count of `v`s split across separate `-v`/`--verbose`/`-vN` tokens.
///
/// This is the only verbosity that makes a successful `cargo build`/`check`/`clippy`/`test`/`run`
/// print a build script's own `println!` output at all (confirmed against current Cargo behavior:
/// plain `-v`/`--verbose` alone suppresses it on success) — without it, the log-marker evidence
/// [`skia_download_path_is_verified_in_log`] requires could never appear even from a fully honest,
/// compliant workflow.
fn requests_double_verbose(run: &str) -> bool {
    let mut verbose_count = 0usize;
    for token in tokens(run) {
        let contribution = match token {
            "-v" | "--verbose" => 1,
            _ => match token.strip_prefix('-') {
                Some(rest) if !rest.is_empty() && rest.chars().all(|ch| ch == 'v') => rest.len(),
                _ => 0,
            },
        };
        verbose_count += contribution;
        if verbose_count >= 2 {
            return true;
        }
    }
    false
}

/// Returns whether `run` both requests `-vv` build output ([`requests_double_verbose`]) and pipes
/// it through `tee`, so a later check in the job can actually grep the captured log rather than
/// the output having gone only to the ephemeral job console.
fn captures_verbose_build_log(run: &str) -> bool {
    requests_double_verbose(run) && contains_word_token(run, "tee")
}

/// Returns whether, scanning forward from `steps[from_index..]` inclusive, some step's `run` text
/// contains all three literal `skia-bindings` build-script log lines this policy requires as
/// evidence the forced download-and-unpack path actually ran:
/// [`SKIA_DOWNLOAD_ATTEMPTED_LOG`], [`SKIA_UNPACK_LOG`], and [`SKIA_DOWNLOAD_FAILED_LOG`] (the
/// last one so the workflow's own script demonstrably checks for, rather than ignores, that
/// failure line). Scanning forward from the Skia-resolving cargo step itself, rather than
/// requiring all three in one exact line, allows the same `run: |` block or a later step in the
/// job to perform the actual grep/assert.
///
/// A successful `Compiling skia-bindings` line proves nothing on its own — a stale build cache or
/// a silent fallback source build (see this module's own doc comment on
/// `FORCE_SKIA_BINARIES_DOWNLOAD`) can print that line too — so this check requires the specific
/// download/unpack evidence instead.
fn skia_download_path_is_verified_in_log(steps: &[ParsedStep<'_>], from_index: usize) -> bool {
    let mut saw_attempted = false;
    let mut saw_unpacked = false;
    let mut saw_failure_check = false;
    for step in &steps[from_index..] {
        let Some(run) = step.run else { continue };
        saw_attempted |= run.contains(SKIA_DOWNLOAD_ATTEMPTED_LOG);
        saw_unpacked |= run.contains(SKIA_UNPACK_LOG);
        saw_failure_check |= run.contains(SKIA_DOWNLOAD_FAILED_LOG);
    }
    saw_attempted && saw_unpacked && saw_failure_check
}

fn parse_steps<'a>(job: &'a YamlValue, job_env: &BTreeMap<String, String>) -> Vec<ParsedStep<'a>> {
    let steps = match get(job, "steps") {
        Some(YamlValue::Sequence(steps)) => steps.as_slice(),
        _ => &[],
    };
    steps
        .iter()
        .map(|step| {
            let mut env = job_env.clone();
            env.extend(env_map(get(step, "env")));
            let run = match get(step, "run") {
                Some(YamlValue::String(run)) => Some(run.as_str()),
                _ => None,
            };
            let working_directory = string(get(step, "working-directory"));
            ParsedStep {
                run,
                env,
                working_directory,
            }
        })
        .collect()
}

/// Validates one job's Skia trust chain, returning the set of targets it resolves and verifies,
/// and whether any step in it actually targets the iOS Skia workspace with a Skia-resolving cargo
/// command ([`targets_ios_skia_workspace`]).
fn validate_job_skia_injection(
    path: &str,
    job_id: &str,
    job: &YamlValue,
    workflow_env: &BTreeMap<String, String>,
    device: &'static str,
    sim: &'static str,
) -> PolicyResult<(BTreeSet<&'static str>, bool)> {
    let mut job_env = workflow_env.clone();
    job_env.extend(env_map(get(job, "env")));
    let steps = parse_steps(job, &job_env);
    let ctx = StepContext {
        path,
        job_id,
        device,
        sim,
    };

    let mut resolved_targets: BTreeMap<&'static str, usize> = BTreeMap::new();
    for (index, step) in steps.iter().enumerate() {
        let Some(run) = step.run else { continue };
        if !contains_word_token(run, RESOLVER_SUBCOMMAND) {
            continue;
        }
        let target = validate_resolve_and_verify_step(&ctx, index, run)?;
        resolved_targets.insert(target, index);
    }

    let mut saw_ios_skia_step = false;
    for (index, step) in steps.iter().enumerate() {
        let Some(run) = step.run else { continue };
        // Both conditions are required: a bare Skia-resolving cargo shape alone would also match
        // closed/live PR #138's `cargo build --package gta-claw-ios`, an unrelated, already-audited,
        // Skia-free build admitted at this same workflow path (see this module's doc comment).
        if !targets_ios_skia_workspace(step) || !is_skia_resolving_cargo_step(run) {
            continue;
        }
        saw_ios_skia_step = true;
        validate_skia_injection_env(&ctx, index, run, &step.env, &resolved_targets)?;
        if !captures_verbose_build_log(run) {
            return Err(PolicyError::new(format!(
                "{path}: job {job_id} step {index} runs a Skia-resolving cargo command without \
                 capturing its build output at cargo's -vv verbosity through tee; plain -v \
                 suppresses a build script's own log output on a successful build, so this is \
                 needed to ever prove the forced Skia download actually ran"
            )));
        }
        if !skia_download_path_is_verified_in_log(&steps, index) {
            return Err(PolicyError::new(format!(
                "{path}: job {job_id} step {index} never checks a captured build log for \
                 evidence the forced Skia download actually ran ({SKIA_DOWNLOAD_ATTEMPTED_LOG:?} \
                 and {SKIA_UNPACK_LOG:?}) and did not fail ({SKIA_DOWNLOAD_FAILED_LOG:?}); a \
                 successful `Compiling skia-bindings` line alone does not prove this, since a \
                 stale cache or a silent fallback source build can print that too"
            )));
        }
    }

    Ok((resolved_targets.into_keys().collect(), saw_ios_skia_step))
}

/// Validates that, for every trigger event under `on:` that narrows itself with a `paths:` allow
/// list, that list includes the trusted policy root ([`TRUSTED_ROOT_TRIGGER_PATH`]) — so a change
/// to `PINNED_BUILD_ARTIFACTS` or the resolver itself always re-runs a workflow that consumes
/// them. An event with no `paths:` filter at all is already unrestricted and therefore compliant;
/// only a narrowed list that omits the trusted root is rejected. `paths-ignore:` deny lists are
/// out of scope of this bounded check.
fn validate_trigger_paths_include_trusted_root(
    path: &str,
    workflow: &YamlValue,
) -> PolicyResult<()> {
    let Some(triggers) = get(workflow, "on").and_then(mapping) else {
        return Ok(());
    };
    for (event_key, event_value) in triggers {
        let event_name = string(Some(event_key)).unwrap_or("<non-string trigger>");
        let Some(YamlValue::Sequence(paths)) = get(event_value, "paths") else {
            continue;
        };
        let includes_trusted_root = paths
            .iter()
            .any(|entry| string(Some(entry)) == Some(TRUSTED_ROOT_TRIGGER_PATH));
        if !includes_trusted_root {
            return Err(PolicyError::new(format!(
                "{path}: trigger {event_name} narrows to a paths: allow list that omits \
                 {TRUSTED_ROOT_TRIGGER_PATH}, so a change to the trusted pin table or resolver \
                 would not re-run this workflow"
            )));
        }
    }
    Ok(())
}

/// Validates that an admitted `ios-packaging.yml` workflow resolves, verifies, and injects both
/// reviewed Skia build-artifact pins before any step that could otherwise fetch `skia-bindings`
/// unverified.
///
/// A file at this admitted path is not itself proof of Skia exposure (live PR #138 already admits
/// one while packaging a Skia-free `apps/gta-claw-ios`, see this module's doc comment): every
/// check below protects the iOS Skia trust chain specifically, so none of them apply unless some
/// step in the file actually engages that chain — a real resolver invocation, or a step naming the
/// iOS Skia workspace with a Skia-resolving cargo command. A file with neither has nothing here to
/// protect and is accepted outright.
///
/// `text` is the raw workflow source (used only to reject literal pin leaks, including ones inside
/// comments); `workflow` is the same document already parsed as YAML.
pub fn validate_ios_packaging_workflow_skia_injection(
    path: &str,
    text: &str,
    workflow: &YamlValue,
) -> PolicyResult<()> {
    reject_literal_pin_leaks(text, path)?;
    let (device, sim) = device_and_sim_targets()?;
    let workflow_env = env_map(get(workflow, "env"));
    let jobs = mapping(
        get(workflow, "jobs")
            .ok_or_else(|| PolicyError::new(format!("{path}: workflow has no jobs mapping")))?,
    )
    .ok_or_else(|| PolicyError::new(format!("{path}: workflow jobs are not a mapping")))?;

    let mut resolved_anywhere: BTreeSet<&'static str> = BTreeSet::new();
    let mut saw_ios_skia_step_anywhere = false;
    for (job_key, job) in jobs {
        let job_id = string(Some(job_key)).unwrap_or("<non-string job id>");
        let (resolved_in_job, saw_ios_skia_step) =
            validate_job_skia_injection(path, job_id, job, &workflow_env, device, sim)?;
        resolved_anywhere.extend(resolved_in_job);
        saw_ios_skia_step_anywhere |= saw_ios_skia_step;
    }

    let engages_ios_skia_trust_chain = saw_ios_skia_step_anywhere || !resolved_anywhere.is_empty();
    if !engages_ios_skia_trust_chain {
        return Ok(());
    }

    for target in [device, sim] {
        if !resolved_anywhere.contains(target) {
            return Err(PolicyError::new(format!(
                "{path} never resolves and verifies a reviewed build-artifact pin for target \
                 {target}"
            )));
        }
    }
    validate_trigger_paths_include_trusted_root(path, workflow)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ParsedStep, SKIA_ARCHIVE_IOS_DEVICE_VAR, SKIA_ARCHIVE_IOS_SIM_VAR,
        contains_bare_hex_run_at_least, curl_output_token, exact_flag_token, has_fail_closed_curl,
        is_curl_fail_flag, is_hardcoded_literal, is_skia_resolving_cargo_step,
        publishes_absolute_archive_var, publishes_archive_var, requests_double_verbose,
        targets_ios_skia_workspace,
    };

    #[test]
    fn exact_flag_token_rejects_prefix_collisions() {
        assert!(exact_flag_token(
            "resolver --target aarch64-apple-ios-sim --package skia-bindings",
            "--target",
            "aarch64-apple-ios-sim"
        ));
        assert!(!exact_flag_token(
            "resolver --target aarch64-apple-ios-sim --package skia-bindings",
            "--target",
            "aarch64-apple-ios"
        ));
        assert!(exact_flag_token(
            "resolver --target=aarch64-apple-ios --package skia-bindings",
            "--target",
            "aarch64-apple-ios"
        ));
        assert!(!exact_flag_token(
            "resolver --target=aarch64-apple-ios-sim",
            "--target",
            "aarch64-apple-ios"
        ));
    }

    #[test]
    fn curl_fail_flag_recognizes_combined_short_options() {
        for flag in ["-f", "-fL", "-sSfL", "-Lf", "--fail", "--fail-with-body"] {
            assert!(is_curl_fail_flag(flag), "must recognize {flag}");
        }
        for flag in ["-L", "-sS", "--location", "-o"] {
            assert!(!is_curl_fail_flag(flag), "must not recognize {flag}");
        }
    }

    #[test]
    fn fail_closed_curl_is_scoped_to_its_own_line() {
        assert!(has_fail_closed_curl(
            "curl -fL -o out.tar.gz https://example.invalid"
        ));
        assert!(!has_fail_closed_curl(
            "curl -L -o out.tar.gz https://example.invalid\nsome-other-tool -f\n"
        ));
    }

    #[test]
    fn bare_hex_run_detection_requires_the_minimum_length() {
        assert!(contains_bare_hex_run_at_least(
            "digest 15e20f3265dfddd658f9ef0d0e30d50a73afccb88787812f65fb5e6cf4ec55c8 end",
            64
        ));
        assert!(!contains_bare_hex_run_at_least("short abc123 token", 64));
        assert!(!contains_bare_hex_run_at_least(
            "not-hex-because-of-a-g abcdefg1abcdefg1abcdefg1abcdefg1abcdefg1abcdefg1abcdefg1abcdefg1",
            64
        ));
    }

    #[test]
    fn archive_publication_requires_github_env_and_exact_name() {
        assert!(publishes_archive_var(
            "echo \"SKIA_ARCHIVE_IOS_DEVICE=$path\" >> \"$GITHUB_ENV\"",
            SKIA_ARCHIVE_IOS_DEVICE_VAR
        ));
        assert!(!publishes_archive_var(
            "echo \"SKIA_ARCHIVE_IOS_DEVICE=$path\" >> \"$GITHUB_ENV\"",
            SKIA_ARCHIVE_IOS_SIM_VAR
        ));
        assert!(!publishes_archive_var(
            "echo \"MY_SKIA_ARCHIVE_IOS_DEVICE=$path\" >> \"$GITHUB_ENV\"",
            SKIA_ARCHIVE_IOS_DEVICE_VAR
        ));
        assert!(!publishes_archive_var(
            "SKIA_ARCHIVE_IOS_DEVICE=$path",
            SKIA_ARCHIVE_IOS_DEVICE_VAR
        ));
    }

    #[test]
    fn skia_resolving_cargo_step_matches_bounded_subcommands() {
        assert!(is_skia_resolving_cargo_step(
            "cargo clippy --manifest-path ios/Cargo.toml --target aarch64-apple-ios"
        ));
        assert!(is_skia_resolving_cargo_step(
            "cargo +1.94.0 build --manifest-path ios/Cargo.toml"
        ));
        assert!(!is_skia_resolving_cargo_step(
            "cargo fmt --manifest-path ios/Cargo.toml"
        ));
        // The token scan is a bounded, line-wide match rather than a shell parser (see the module
        // doc comment): it deliberately treats any line where a `cargo` token is followed within
        // two tokens by a Skia-resolving subcommand as a Skia-resolving step, even if `cargo` is
        // not the first word. That over-inclusion is intentionally fail-closed — a false positive
        // only asks an unrelated line for an override it doesn't need, whereas a false negative
        // would let a real invocation slip past this check entirely.
        assert!(is_skia_resolving_cargo_step(
            "echo cargo check is not actually invoked here"
        ));
    }

    #[test]
    fn absolute_archive_publication_accepts_only_visibly_absolute_forms() {
        for value in [
            "/abs/device.tar.gz",
            "$(pwd)/device.tar.gz",
            "$PWD/device.tar.gz",
            "${PWD}/device.tar.gz",
            "$GITHUB_WORKSPACE/device.tar.gz",
            "${GITHUB_WORKSPACE}/device.tar.gz",
        ] {
            let run = format!("echo \"SKIA_ARCHIVE_IOS_DEVICE={value}\" >> \"$GITHUB_ENV\"");
            assert!(
                publishes_absolute_archive_var(&run, SKIA_ARCHIVE_IOS_DEVICE_VAR),
                "must accept {value:?} as absolute"
            );
        }
        for value in ["device.tar.gz", "./device.tar.gz", "../device.tar.gz"] {
            let run = format!("echo \"SKIA_ARCHIVE_IOS_DEVICE={value}\" >> \"$GITHUB_ENV\"");
            assert!(
                !publishes_absolute_archive_var(&run, SKIA_ARCHIVE_IOS_DEVICE_VAR),
                "must reject {value:?} as not visibly absolute"
            );
        }
    }

    #[test]
    fn curl_output_token_extracts_the_fetched_filename_only_from_the_curl_line() {
        assert_eq!(
            curl_output_token("curl -fL -sS -o \"$archive_file\" \"$url\""),
            Some("$archive_file")
        );
        assert_eq!(
            curl_output_token("curl -fL --output device.tar.gz \"$url\""),
            Some("device.tar.gz")
        );
        assert_eq!(
            curl_output_token("echo -o not-a-curl-line\ncurl -fL \"$url\""),
            None
        );
    }

    #[test]
    fn hardcoded_literal_detection_requires_a_shell_variable_reference() {
        for token in ["device.tar.gz", "archive.tar.gz"] {
            assert!(is_hardcoded_literal(token), "must flag {token:?} literal");
        }
        for token in ["$archive_file", "${archive_file}", "$(basename \"$url\")"] {
            assert!(
                !is_hardcoded_literal(token),
                "must not flag {token:?} literal"
            );
        }
    }

    #[test]
    fn double_verbose_detection_accepts_split_or_combined_forms() {
        assert!(requests_double_verbose("cargo build --target x -vv"));
        assert!(requests_double_verbose("cargo build -v --target x -v"));
        assert!(requests_double_verbose(
            "cargo build --verbose --target x --verbose"
        ));
        assert!(!requests_double_verbose("cargo build --target x -v"));
        assert!(!requests_double_verbose("cargo build --target x"));
    }

    #[test]
    fn targets_ios_skia_workspace_uses_exact_not_prefix_matching() {
        let step_for =
            |run: Option<&'static str>, working_directory: Option<&'static str>| ParsedStep {
                run,
                env: BTreeMap::new(),
                working_directory,
            };
        assert!(targets_ios_skia_workspace(&step_for(
            Some("cargo build --manifest-path ios/Cargo.toml --target aarch64-apple-ios"),
            None
        )));
        assert!(targets_ios_skia_workspace(&step_for(
            Some("cargo build --package gta-claw-ios-shell"),
            None
        )));
        assert!(targets_ios_skia_workspace(&step_for(
            Some("cargo build --target aarch64-apple-ios"),
            Some("ios")
        )));
        // The unrelated, Skia-free `gta-claw-ios` app (no `-shell` suffix, live PR #138) must never
        // match by prefix against the admitted `gta-claw-ios-shell` package name.
        assert!(!targets_ios_skia_workspace(&step_for(
            Some("cargo build --locked --package gta-claw-ios --target aarch64-apple-ios"),
            None
        )));
        assert!(!targets_ios_skia_workspace(&step_for(
            Some("cargo build --manifest-path apps/gta-claw-ios/Cargo.toml"),
            None
        )));
        assert!(!targets_ios_skia_workspace(&step_for(None, None)));
    }
}
