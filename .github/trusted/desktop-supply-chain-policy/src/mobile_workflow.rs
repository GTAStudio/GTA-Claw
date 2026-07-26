//! Content policy for the admitted `ios-packaging.yml` workflow.
//!
//! `ios-packaging.yml` is an admitted, optional workflow path (`ADMITTED_WORKFLOWS` in
//! `workflows.rs`): it may be absent, and today it is absent from every checkout this trust root
//! validates — no `ios/` workspace or `ios-packaging.yml` exists on `main`, and closed PR #110,
//! which drafted a shell under `ios/`, is audit evidence only and is neither reopened nor mutated
//! by this change. This module exists so that if and when a future change admits the file, it is
//! accepted only if its Skia trust chain matches the one reviewed here: every prebuilt Skia archive
//! it could fetch is resolved through the trusted CLI resolver (`resolve-build-artifact-pin`,
//! backed by `PINNED_BUILD_ARTIFACTS`), never a URL or digest typed directly into the YAML, fetched
//! with a fail-closed download, verified locally, and only then handed to `cargo` through the
//! supported `SKIA_BINARIES_URL=file://...` override with `FORCE_SKIA_BINARIES_DOWNLOAD` set — so
//! `skia-bindings`' own unverified network fetch never runs.
//!
//! ## What this check proves, and what it does not
//!
//! This is a **static content check** over the workflow YAML text and structure. It proves the
//! workflow *says* the right things: the right resolver invocations, the right fail-closed curl
//! flags, the right environment variables wired to the right cargo steps, in the right order. It
//! does not execute the workflow, does not simulate GitHub Actions expression evaluation, and does
//! not perform shell data-flow analysis. Three deliberate, bounded conventions make that tractable,
//! and are the limits of what this module can see:
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
//!   invocation actually compiles.
//! - Token scanning is whitespace-based, per line, and quote-trimming only; it is not a shell
//!   parser. A flag value split across a line continuation, or built by shell substitution, is out
//!   of scope, exactly as the README already documents for the URL/target matching this module's
//!   `exact_flag_token` mirrors.
//!
//! Digest mismatches, 404s, and "wrong local archive" substitutions are **not** static content
//! properties of the YAML; they are runtime facts about what a `curl` and a local file actually
//! contain, and are covered by `resolve_build_artifact_pin`/`verify_local_build_artifact` in
//! `policy.rs` and their own tests instead.

use std::collections::{BTreeMap, BTreeSet};

use serde_yaml_ng::Value as YamlValue;

use crate::policy::{ios_skia_targets, skia_bindings_package_name, skia_bindings_pin_version};
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

/// Immutable per-job context threaded through the step-level checks below.
struct StepContext<'a> {
    path: &'a str,
    job_id: &'a str,
    device: &'static str,
    sim: &'static str,
}

/// One workflow step's shell command text and effective (workflow + job + step) environment.
struct ParsedStep<'a> {
    run: Option<&'a str>,
    env: BTreeMap<String, String>,
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

fn is_identifier_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

/// Returns whether some line of `run` both mentions `$GITHUB_ENV` and assigns exactly `var=`,
/// where the assignment is not itself a suffix of a longer identifier (so `FOO_VAR=` is never
/// mistaken for a match on `VAR`).
fn publishes_archive_var(run: &str, var: &str) -> bool {
    let needle = format!("{var}=");
    run.lines().any(|line| {
        if !line.contains("GITHUB_ENV") {
            return false;
        }
        let bytes = line.as_bytes();
        let mut search_from = 0usize;
        while let Some(relative) = line[search_from..].find(needle.as_str()) {
            let start = search_from + relative;
            if start == 0 || !is_identifier_byte(bytes[start - 1]) {
                return true;
            }
            search_from = start + 1;
        }
        false
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

/// Validates one step that invokes the trusted resolver: it must fetch with a fail-closed `curl`,
/// verify the local archive, and publish the verified path under the fixed variable name for the
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
    if !contains_word_token(run, "--verify-local") {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} resolves the {target} pin without --verify-local",
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
            ParsedStep { run, env }
        })
        .collect()
}

/// Validates one job's Skia trust chain, returning the set of targets it resolves and verifies.
fn validate_job_skia_injection(
    path: &str,
    job_id: &str,
    job: &YamlValue,
    workflow_env: &BTreeMap<String, String>,
    device: &'static str,
    sim: &'static str,
) -> PolicyResult<BTreeSet<&'static str>> {
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

    for (index, step) in steps.iter().enumerate() {
        let Some(run) = step.run else { continue };
        if !is_skia_resolving_cargo_step(run) {
            continue;
        }
        validate_skia_injection_env(&ctx, index, run, &step.env, &resolved_targets)?;
    }

    Ok(resolved_targets.into_keys().collect())
}

/// Validates that an admitted `ios-packaging.yml` workflow resolves, verifies, and injects both
/// reviewed Skia build-artifact pins before any step that could otherwise fetch `skia-bindings`
/// unverified.
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
    for (job_key, job) in jobs {
        let job_id = string(Some(job_key)).unwrap_or("<non-string job id>");
        let resolved_in_job =
            validate_job_skia_injection(path, job_id, job, &workflow_env, device, sim)?;
        resolved_anywhere.extend(resolved_in_job);
    }

    for target in [device, sim] {
        if !resolved_anywhere.contains(target) {
            return Err(PolicyError::new(format!(
                "{path} never resolves and verifies a reviewed build-artifact pin for target \
                 {target}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        SKIA_ARCHIVE_IOS_DEVICE_VAR, SKIA_ARCHIVE_IOS_SIM_VAR, contains_bare_hex_run_at_least,
        exact_flag_token, has_fail_closed_curl, is_curl_fail_flag, is_skia_resolving_cargo_step,
        publishes_archive_var,
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
}
