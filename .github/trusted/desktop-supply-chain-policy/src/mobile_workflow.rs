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
//! ## Logs are corroboration, not the primary proof
//!
//! The primary proof this chain is safe is the sequence above: a trusted-table resolve, a
//! fail-closed prefetch, a local SHA-256 verification, a `file://` injection of that exact
//! verified path, `FORCE_SKIA_BINARIES_DOWNLOAD` forcing the download-only code path, and the
//! step's own process exit status. The captured build log is secondary corroboration layered on
//! top of that chain, and is only trustworthy once three further conditions hold, because a real
//! GitHub Actions log retains ANSI color escape codes interleaved with cargo's own text (for
//! example, a "Compiling" token immediately followed by a color-reset escape code and only then
//! `skia-bindings`). A raw, colorized log can split one of this module's literal markers across an
//! escape code, so a naive substring grep for it can silently find nothing even though the marker
//! text is fully present in the log — turning an absence-check meant to catch a real failure into
//! a vacuous pass instead. An admitted workflow must therefore also: disable color at the source
//! (`CARGO_TERM_COLOR=never` or `--color never`, [`requests_color_never`]); strip any ANSI escape
//! codes from the captured log before grepping it ([`ANSI_CSI_STRIP_PATTERN`]); and prove that
//! capture-and-strip pipeline can find *something* with a verified-nonzero positive control — a
//! `grep -c` count actually compared against zero, not merely computed and discarded
//! ([`has_verified_positive_control`]) — before its absence-check on the failure line means
//! anything at all. A zero or unchecked count invalidates the whole measurement and must be
//! treated as failure, never silently passed.
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
//!   The color-never, ANSI-strip, and positive-control evidence above are the same kind of
//!   bounded literal/token presence check, not shell execution or real log inspection either —
//!   they raise the bar on what the workflow's own script must visibly do, they do not run it.
//!
//! Digest mismatches, 404s, and "wrong local archive" substitutions are **not** static content
//! properties of the YAML; they are runtime facts about what a `curl` and a local file actually
//! contain, and are covered by `resolve_build_artifact_pin`/`verify_local_build_artifact` in
//! `policy.rs` and their own tests instead.
//!
//! ## A normal build's console output is not build-script evidence
//!
//! Measured against real `skia-bindings` 0.99.0 behavior: a plain `cargo build` genuinely prints
//! nothing from a build script's own `println!` calls even on a fresh, uncached run — only
//! `cargo build -vv` (or a build failure) echoes that output to the console at all, exactly what
//! [`captures_verbose_build_log`] already requires. Cargo, however, writes a build script's
//! complete captured stdout to `target/<...>/build/<pkgname>-<hash>/output` on **every** build
//! script invocation, unconditionally, regardless of verbosity — a strictly more reliable evidence
//! source than a piped console log, immune to both a plain build's suppressed echo and any
//! pipe/`tee` exit-status concern (below). Two further conditions make that file trustworthy as
//! *this run's* evidence rather than some earlier, possibly-unverified run's leftover: an admitted
//! workflow must delete any stale prior copy of that directory before the build meant to recreate
//! it ([`cleans_stale_build_script_output`] — the hash suffix cannot be checked literally, so
//! deleting the whole directory beforehand is what makes anything found there afterward
//! unambiguous), and it must then read that exact file and assert it names both the literal
//! [`SKIA_UNPACK_LOG`] line and the specific injected pinned `file://` URL via
//! [`SKIA_DOWNLOAD_FROM_LOG`] ([`asserts_from_pinned_url_in_output`]) — not merely that *some*
//! download happened, but that it was *this* verified archive, not a stale cache, the other
//! target's archive, or the crate's own unverified default resolution silently taking over
//! ([`skia_download_receipt_is_verified_via_output_file`]). This check is additional to, not a
//! replacement for, the piped-console-log evidence above.
//!
//! ## The step's own exit status is only trustworthy if nothing can mask it
//!
//! This module's stated primary proof rests on trusting a step's reported exit status. Two checks
//! exist solely to keep that trust well-founded. First, a resolve-and-verify step or a
//! Skia-resolving cargo step marked `continue-on-error: true` would let GitHub Actions report the
//! *job* as successful even if that exact step failed, so this policy rejects either step outright
//! for carrying it. Second, because [`captures_verbose_build_log`] already requires piping a
//! Skia-resolving cargo step's output through `tee` to capture it, that pipeline's own reported
//! exit status becomes `tee`'s (almost always zero) rather than `cargo`'s real one unless the
//! shell is told `pipefail` ([`protects_pipeline_exit_status`]) — otherwise a real, forced-download
//! failure inside `build.rs` (which `panic!`s on a verified failure, confirmed against the
//! published source) could be silently swallowed by the pipe itself, even though the workflow's own
//! doc comment and this module both already treat the step's exit status as the primary proof.

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
/// The cargo/env knob controlling ANSI color output in build logs.
const CARGO_TERM_COLOR_VAR: &str = "CARGO_TERM_COLOR";
/// The only value of [`CARGO_TERM_COLOR_VAR`] (or a `--color` flag) this policy accepts as
/// disabling color output.
const COLOR_NEVER_VALUE: &str = "never";
/// The literal ANSI CSI (Control Sequence Introducer) escape prefix, spelled the way an author
/// types it inside a `sed`/`perl` pattern: `\x1b\[`. A raw GitHub Actions log retains real escape
/// sequences interleaved with cargo's own output, which can split one of this module's required
/// literal markers across the escape code so a naive substring grep on the unstripped log finds
/// nothing even when the marker text is fully present. Bounded textual detection of this exact
/// pattern in some forward-scanned step's `run` text is evidence the workflow strips escape codes
/// from its captured log before grepping it, rather than grepping the raw log directly.
const ANSI_CSI_STRIP_PATTERN: &str = r"\x1b\[";
/// Literal shell idioms proving a count was compared against zero: `-gt 0`/`-ne 0` (POSIX
/// `test`/`[`) or `!= 0` (arithmetic `(( ))`/`[[ ]]`) — any one of the ways an author might spell
/// "and it is not zero".
const NONZERO_COMPARISONS: [&str; 3] = ["-gt 0", "-ne 0", "!= 0"];
/// Literal build-script log line `skia-bindings` 0.99.0 prints immediately after
/// [`SKIA_DOWNLOAD_ATTEMPTED_LOG`], naming the exact URL the download actually used (confirmed
/// against the published source: `println!("  FROM: {url}");`, distinct from the unrelated
/// `DOWNLOADING:` line the crate's own separate git-submodule fallback path prints). This is what
/// [`asserts_from_pinned_url_in_output`] requires alongside the exact injected pinned `file://`
/// expression: not merely that *some* download was attempted, but that it named this specific
/// verified archive.
const SKIA_DOWNLOAD_FROM_LOG: &str = "FROM:";
/// The shell option proving a piped pipeline's exit status is not silently replaced by the last
/// command in the pipe (almost always `tee`, exit code 0) — `set -o pipefail`, or a combined
/// `set -eo pipefail`/`set -euo pipefail`.
const PIPEFAIL_TOKEN: &str = "pipefail";
/// The literal trailing path segment of Cargo's own build-script output-capture file — always
/// named exactly `output`, with no extension — that [`reads_build_script_output_file`] requires
/// alongside [`build_script_output_dir_hint`].
const BUILD_SCRIPT_OUTPUT_FILE_HINT: &str = "/output";

/// Immutable per-job context threaded through the step-level checks below.
struct StepContext<'a> {
    path: &'a str,
    job_id: &'a str,
    device: &'static str,
    sim: &'static str,
}

/// One workflow step's shell command text, effective (workflow + job + step) environment,
/// declared `working-directory`, if any, and whether it carries `continue-on-error: true`.
struct ParsedStep<'a> {
    run: Option<&'a str>,
    env: BTreeMap<String, String>,
    working_directory: Option<&'a str>,
    continue_on_error: bool,
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

/// Validates one step that invokes the trusted resolver: it must not carry
/// `continue-on-error: true` (which would let the job succeed even if this exact step's resolve,
/// fetch, or verify failed), must fetch with a fail-closed `curl` to a filename derived from the
/// resolved URL (never a hardcoded literal), verify that exact local archive, and publish its
/// verified absolute path under the fixed variable name for the target it resolved.
fn validate_resolve_and_verify_step(
    ctx: &StepContext<'_>,
    index: usize,
    run: &str,
    continue_on_error: bool,
) -> PolicyResult<&'static str> {
    if continue_on_error {
        return Err(PolicyError::new(format!(
            "{}: job {} step {index} resolves a build-artifact pin with continue-on-error: \
             true, so a failed resolve, fetch, or local verification would not fail the job",
            ctx.path, ctx.job_id
        )));
    }
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

/// Returns the fixed archive-variable name(s) applicable to a Skia-resolving cargo step: the
/// single variable for the exact target it names via `--target`, or both if it names neither (a
/// host-target invocation, to which either verified archive may apply). Shared by
/// [`validate_skia_injection_env`] and [`skia_download_receipt_is_verified_via_output_file`] so
/// both agree on exactly which archive(s) a given step's evidence must name.
fn candidate_archive_vars(run: &str, ctx: &StepContext<'_>) -> &'static [&'static str] {
    let names_sim = exact_flag_token(run, "--target", ctx.sim);
    let names_device = exact_flag_token(run, "--target", ctx.device);
    if names_sim {
        &[SKIA_ARCHIVE_IOS_SIM_VAR]
    } else if names_device {
        &[SKIA_ARCHIVE_IOS_DEVICE_VAR]
    } else {
        // A host-target step (no explicit --target aimed at either admitted iOS target): no
        // specific pin applies to an unspecified host triple, so either established, verified
        // archive is accepted, as long as one actually is.
        &[SKIA_ARCHIVE_IOS_DEVICE_VAR, SKIA_ARCHIVE_IOS_SIM_VAR]
    }
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

    let candidate_vars = candidate_archive_vars(run, ctx);

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

/// Returns whether `env` (already merged workflow+job+step, see [`ParsedStep`]) or `run` disables
/// cargo's ANSI color output: [`CARGO_TERM_COLOR_VAR`] set to [`COLOR_NEVER_VALUE`]
/// (case-insensitive), or an exact `--color never`/`--color=never` flag on the invocation itself
/// ([`exact_flag_token`]).
///
/// This is the first and strongest defense against the ANSI-escape concern
/// [`ANSI_CSI_STRIP_PATTERN`]'s doc comment describes: a color code cargo never emits in the first
/// place can never split a literal log marker, regardless of whether a later stripping step is
/// also present, or is itself correct.
fn requests_color_never(run: &str, env: &BTreeMap<String, String>) -> bool {
    env.get(CARGO_TERM_COLOR_VAR)
        .is_some_and(|value| value.eq_ignore_ascii_case(COLOR_NEVER_VALUE))
        || exact_flag_token(run, "--color", COLOR_NEVER_VALUE)
}

/// Returns whether `token` is a grep count-mode short-option cluster: a single dash followed only
/// by letters, at least one of which is `c` — covering `-c` as well as combined clusters such as
/// `-Ec`, consistent with [`is_curl_fail_flag`]'s own documented scope of recognizing but not
/// decomposing combined short-option clusters.
fn is_grep_count_flag(token: &str) -> bool {
    match token.strip_prefix('-') {
        Some(rest) if !rest.is_empty() && !rest.starts_with('-') => {
            rest.chars().all(|ch| ch.is_ascii_alphabetic()) && rest.contains('c')
        }
        _ => false,
    }
}

/// Returns whether `run` proves a "positive control": a `grep` count-mode invocation
/// ([`is_grep_count_flag`]) together with evidence that count was actually compared against zero
/// ([`NONZERO_COMPARISONS`]), not merely computed and ignored.
///
/// `grep`'s own exit code and a printed count look identical whether a pattern matched many
/// times, once, or the capture pipeline is entirely broken (wrong file, truncated log, stripping
/// that ate everything) unless something then checks the count is nonzero. Requiring a
/// verified-nonzero count on some known-present marker is the closest bounded textual proxy for
/// "this workflow's own capture-and-check pipeline can find something on this exact log", so a
/// zero or unchecked count cannot be silently treated as a passing measurement.
fn has_verified_positive_control(run: &str) -> bool {
    let has_grep_count = contains_word_token(run, "grep") && tokens(run).any(is_grep_count_flag);
    has_grep_count
        && NONZERO_COMPARISONS
            .iter()
            .any(|pattern| run.contains(pattern))
}

/// Returns whether, scanning forward from `steps[from_index..]` inclusive, some step's `run` text
/// contains all three literal `skia-bindings` build-script log lines this policy requires as
/// evidence the forced download-and-unpack path actually ran —
/// [`SKIA_DOWNLOAD_ATTEMPTED_LOG`], [`SKIA_UNPACK_LOG`], and [`SKIA_DOWNLOAD_FAILED_LOG`] (the
/// last one so the workflow's own script demonstrably checks for, rather than ignores, that
/// failure line) — **and** the two conditions that make trusting those three checks sound in the
/// first place: literal evidence the log was stripped of ANSI escape codes before any of them ran
/// ([`ANSI_CSI_STRIP_PATTERN`]), and a verified-nonzero positive control proving the
/// capture-and-strip pipeline can find something at all ([`has_verified_positive_control`]).
/// Scanning forward from the Skia-resolving cargo step itself, rather than requiring everything in
/// one exact line, allows the same `run: |` block or a later step in the job to perform the actual
/// grep/assert.
///
/// A successful `Compiling skia-bindings` line proves nothing on its own — a stale build cache or
/// a silent fallback source build (see this module's own doc comment on
/// `FORCE_SKIA_BINARIES_DOWNLOAD`) can print that line too — so this check requires the specific
/// download/unpack evidence instead. Nor does a raw, unstripped grep against a colorized log:
/// escape codes between tokens can make it silently find nothing even when the marker text is
/// fully present, so a naive absence-check on [`SKIA_DOWNLOAD_FAILED_LOG`] could vacuously pass.
fn skia_download_path_is_verified_in_log(steps: &[ParsedStep<'_>], from_index: usize) -> bool {
    let mut saw_attempted = false;
    let mut saw_unpacked = false;
    let mut saw_failure_check = false;
    let mut saw_ansi_stripped = false;
    let mut saw_positive_control = false;
    for step in &steps[from_index..] {
        let Some(run) = step.run else { continue };
        saw_attempted |= run.contains(SKIA_DOWNLOAD_ATTEMPTED_LOG);
        saw_unpacked |= run.contains(SKIA_UNPACK_LOG);
        saw_failure_check |= run.contains(SKIA_DOWNLOAD_FAILED_LOG);
        saw_ansi_stripped |= run.contains(ANSI_CSI_STRIP_PATTERN);
        saw_positive_control |= has_verified_positive_control(run);
    }
    saw_attempted && saw_unpacked && saw_failure_check && saw_ansi_stripped && saw_positive_control
}

/// Returns whether `run` protects a piped exit status with a `pipefail` shell option
/// ([`PIPEFAIL_TOKEN`]: `set -o pipefail`, or a combined `set -eo pipefail`/`set -euo pipefail`) —
/// the only reason redirecting a Skia-resolving cargo step's own exit code through `| tee <log>`
/// (already required by [`captures_verbose_build_log`]) does not silently replace it with `tee`'s
/// own, almost always zero, exit code. Without this, a real `build.rs` failure from a rejected
/// forced download could leave the step reporting success anyway, making that success meaningless
/// as proof of anything — directly undermining this module's own stated primary proof (see the
/// module doc comment) that the step's own exit status is trustworthy.
fn protects_pipeline_exit_status(run: &str) -> bool {
    contains_word_token(run, PIPEFAIL_TOKEN)
}

/// Computes the fixed, non-hash-suffixed fragment of Cargo's own build-script output-capture
/// directory for the exact reviewed `skia-bindings` package — `build/<package-name>-` — derived
/// from [`skia_bindings_package_name`] rather than hardcoded, consistent with this module's use of
/// that same accessor everywhere else a literal package name would otherwise appear. The trailing
/// hash segment Cargo appends is inherently unpredictable statically, so this hint is deliberately
/// only the fixed prefix, not a full path.
fn build_script_output_dir_hint() -> String {
    format!("build/{}-", skia_bindings_package_name())
}

/// Returns whether `run` deletes any prior build-script output directory for this package before
/// its own cargo invocation runs: an `rm` token together with `hint`
/// ([`build_script_output_dir_hint`]). This is the freshness proof
/// [`skia_download_receipt_is_verified_via_output_file`] requires: Cargo names this directory with
/// an unpredictable hash suffix that cannot be checked literally, so deleting it beforehand is what
/// makes any file found there afterward unambiguously written by *this* run, rather than a cached
/// leftover from some earlier, unrelated, possibly-unverified build.
fn cleans_stale_build_script_output(run: &str, hint: &str) -> bool {
    contains_word_token(run, "rm") && run.contains(hint)
}

/// Returns whether `run` reads Cargo's own captured build-script output file — text naming both
/// `hint` ([`build_script_output_dir_hint`]) and [`BUILD_SCRIPT_OUTPUT_FILE_HINT`] — rather than
/// relying solely on the piped console log. Cargo writes this file unconditionally on every
/// build-script invocation, regardless of `-v`/`-vv` verbosity (only the *console echo* of its
/// contents needs `-vv`, or a build failure), so it is a strictly more reliable evidence source
/// than a piped log for proving a normal, successful build actually ran the forced download path.
fn reads_build_script_output_file(run: &str, hint: &str) -> bool {
    run.contains(hint) && run.contains(BUILD_SCRIPT_OUTPUT_FILE_HINT)
}

/// Returns whether `run` asserts, against literal text naming both [`SKIA_DOWNLOAD_FROM_LOG`] and
/// the exact `file://${{ env.VAR }}` expression this job's resolve-and-verify step publishes
/// ([`expected_file_url`]), that the specific URL `skia-bindings` actually attempted this run was
/// the verified local archive — not a stale cache entry, the other target's archive, or the
/// crate's own unverified default resolution silently taking over. Whitespace-normalized
/// ([`normalize_expression`]) on both sides, the same way [`validate_skia_injection_env`] compares
/// an injected `SKIA_BINARIES_URL` value, so `${{ env.X }}` and `${{env.X}}` are equivalent.
fn asserts_from_pinned_url_in_output(run: &str, var: &str) -> bool {
    run.contains(SKIA_DOWNLOAD_FROM_LOG)
        && normalize_expression(run).contains(&expected_file_url(var))
}

/// Returns whether, for the Skia-resolving cargo step at `build_index`, this job proves — through
/// Cargo's own unconditionally-written build-script output file rather than the piped console log
/// — that *this run's* forced download actually fetched the exact verified local archive for one
/// of `candidate_vars`: some step at or before `build_index` deletes any stale prior output
/// directory ([`cleans_stale_build_script_output`], the freshness proof, allowed in the same step
/// since a `run: |` block naturally cleans immediately before the build it precedes), and some
/// step at or after `build_index` both reads that file ([`reads_build_script_output_file`]) and
/// asserts it contains [`SKIA_UNPACK_LOG`] and the exact pinned URL for one of `candidate_vars`
/// ([`asserts_from_pinned_url_in_output`]).
fn skia_download_receipt_is_verified_via_output_file(
    steps: &[ParsedStep<'_>],
    build_index: usize,
    candidate_vars: &'static [&'static str],
) -> bool {
    let hint = build_script_output_dir_hint();
    let cleaned = steps[..=build_index].iter().any(|step| {
        step.run
            .is_some_and(|run| cleans_stale_build_script_output(run, &hint))
    });
    if !cleaned {
        return false;
    }
    steps[build_index..].iter().any(|step| {
        step.run.is_some_and(|run| {
            reads_build_script_output_file(run, &hint)
                && run.contains(SKIA_UNPACK_LOG)
                && candidate_vars
                    .iter()
                    .any(|var| asserts_from_pinned_url_in_output(run, var))
        })
    })
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
            let continue_on_error = get(step, "continue-on-error")
                .and_then(scalar_text)
                .is_some_and(|value| value.eq_ignore_ascii_case("true"));
            ParsedStep {
                run,
                env,
                working_directory,
                continue_on_error,
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
        let target = validate_resolve_and_verify_step(&ctx, index, run, step.continue_on_error)?;
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
        if step.continue_on_error {
            return Err(PolicyError::new(format!(
                "{path}: job {job_id} step {index} runs a Skia-resolving cargo command with \
                 continue-on-error: true, so a forced-download verification failure raised \
                 inside build.rs would not fail the job, defeating this module's own primary \
                 proof that the step's exit status is trustworthy"
            )));
        }
        validate_skia_injection_env(&ctx, index, run, &step.env, &resolved_targets)?;
        if !captures_verbose_build_log(run) {
            return Err(PolicyError::new(format!(
                "{path}: job {job_id} step {index} runs a Skia-resolving cargo command without \
                 capturing its build output at cargo's -vv verbosity through tee; plain -v \
                 suppresses a build script's own log output on a successful build, so this is \
                 needed to ever prove the forced Skia download actually ran"
            )));
        }
        if !protects_pipeline_exit_status(run) {
            return Err(PolicyError::new(format!(
                "{path}: job {job_id} step {index} pipes its -vv build output through tee \
                 without a `pipefail` shell option (e.g. `set -o pipefail`); without it, a real \
                 build.rs failure from a rejected forced download would be masked by tee's own \
                 near-always-zero exit status, making this step's reported success meaningless \
                 as proof of anything"
            )));
        }
        if !requests_color_never(run, &step.env) {
            return Err(PolicyError::new(format!(
                "{path}: job {job_id} step {index} runs a Skia-resolving cargo command without \
                 disabling ANSI color output ({CARGO_TERM_COLOR_VAR}={COLOR_NEVER_VALUE:?} or \
                 --color {COLOR_NEVER_VALUE}); a colorized log can interleave escape codes with \
                 the literal build-script markers this policy requires, letting a later absence \
                 check on {SKIA_DOWNLOAD_FAILED_LOG:?} silently pass even when that text is \
                 fully present in the raw log"
            )));
        }
        if !skia_download_path_is_verified_in_log(&steps, index) {
            return Err(PolicyError::new(format!(
                "{path}: job {job_id} step {index} never checks a captured build log for \
                 evidence the forced Skia download actually ran ({SKIA_DOWNLOAD_ATTEMPTED_LOG:?} \
                 and {SKIA_UNPACK_LOG:?}), did not fail ({SKIA_DOWNLOAD_FAILED_LOG:?}), that the \
                 log was stripped of ANSI escape codes before grepping it (a literal \
                 {ANSI_CSI_STRIP_PATTERN:?} pattern), and a verified-nonzero positive control \
                 proving that capture-and-strip pipeline can find something at all (a `grep -c` \
                 count actually compared against zero); a successful `Compiling skia-bindings` \
                 line alone does not prove this, since a stale cache or a silent fallback source \
                 build can print that too, and a raw grep against an unstripped colorized log can \
                 silently find nothing even when the marker text is fully present"
            )));
        }
        let candidate_vars = candidate_archive_vars(run, &ctx);
        if !skia_download_receipt_is_verified_via_output_file(&steps, index, candidate_vars) {
            let hint = build_script_output_dir_hint();
            return Err(PolicyError::new(format!(
                "{path}: job {job_id} step {index} never proves, by reading Cargo's own \
                 captured build-script output file ({hint}*{BUILD_SCRIPT_OUTPUT_FILE_HINT}, \
                 written unconditionally on every build-script invocation regardless of \
                 verbosity) rather than relying solely on the piped console log, that this \
                 run's forced download actually used the verified pinned archive: some step at \
                 or before this one must delete any stale prior output directory for this \
                 package first (the freshness proof — a cached leftover from an earlier, \
                 possibly-unverified run would otherwise look identical), and some step at or \
                 after this one must then assert that file contains both \
                 {SKIA_DOWNLOAD_FROM_LOG:?} naming the exact injected pinned file:// URL and \
                 {SKIA_UNPACK_LOG:?}"
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
        asserts_from_pinned_url_in_output, build_script_output_dir_hint,
        cleans_stale_build_script_output, contains_bare_hex_run_at_least, curl_output_token,
        exact_flag_token, has_fail_closed_curl, is_curl_fail_flag, is_hardcoded_literal,
        is_skia_resolving_cargo_step, protects_pipeline_exit_status,
        publishes_absolute_archive_var, publishes_archive_var, reads_build_script_output_file,
        requests_double_verbose, targets_ios_skia_workspace,
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
                continue_on_error: false,
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

    #[test]
    fn pipeline_exit_status_protection_requires_the_pipefail_token() {
        assert!(protects_pipeline_exit_status(
            "set -o pipefail\ncargo build -vv 2>&1 | tee out.log"
        ));
        assert!(protects_pipeline_exit_status(
            "set -euo pipefail\ncargo build -vv 2>&1 | tee out.log"
        ));
        assert!(!protects_pipeline_exit_status(
            "set -eu\ncargo build -vv 2>&1 | tee out.log"
        ));
        assert!(!protects_pipeline_exit_status(
            "cargo build -vv 2>&1 | tee out.log"
        ));
    }

    #[test]
    fn build_script_output_dir_hint_is_derived_from_the_reviewed_package_name() {
        assert_eq!(build_script_output_dir_hint(), "build/skia-bindings-");
    }

    #[test]
    fn stale_output_cleaning_requires_an_rm_token_and_the_directory_hint() {
        let hint = build_script_output_dir_hint();
        assert!(cleans_stale_build_script_output(
            "rm -rf target/*/build/skia-bindings-*",
            &hint
        ));
        // `rm` must be a standalone token, not embedded in a longer word such as `confirm`.
        assert!(!cleans_stale_build_script_output(
            "confirm target/*/build/skia-bindings-* exists",
            &hint
        ));
        assert!(!cleans_stale_build_script_output(
            "rm -rf target/*/build/some-other-crate-*",
            &hint
        ));
    }

    #[test]
    fn output_file_reading_requires_both_the_directory_hint_and_the_output_suffix() {
        let hint = build_script_output_dir_hint();
        assert!(reads_build_script_output_file(
            "cat target/*/build/skia-bindings-*/output",
            &hint
        ));
        assert!(!reads_build_script_output_file(
            "cat target/*/build/skia-bindings-*/stderr",
            &hint
        ));
        assert!(!reads_build_script_output_file(
            "cat target/*/build/some-other-crate-*/output",
            &hint
        ));
    }

    #[test]
    fn from_url_assertion_requires_both_the_from_marker_and_the_exact_pinned_expression() {
        assert!(asserts_from_pinned_url_in_output(
            "grep -q \"FROM: file://${{ env.SKIA_ARCHIVE_IOS_DEVICE }}\" \"$output_file\"",
            SKIA_ARCHIVE_IOS_DEVICE_VAR
        ));
        // Whitespace-insensitive inside the `${{ }}` expression, consistent with
        // `expected_file_url`/`normalize_expression` elsewhere in this module.
        assert!(asserts_from_pinned_url_in_output(
            "grep -q \"FROM: file://${{env.SKIA_ARCHIVE_IOS_DEVICE}}\" \"$output_file\"",
            SKIA_ARCHIVE_IOS_DEVICE_VAR
        ));
        // The other target's expression must not satisfy this target's assertion.
        assert!(!asserts_from_pinned_url_in_output(
            "grep -q \"FROM: file://${{ env.SKIA_ARCHIVE_IOS_SIM }}\" \"$output_file\"",
            SKIA_ARCHIVE_IOS_DEVICE_VAR
        ));
        // The exact pinned expression without the FROM: marker proves nothing either.
        assert!(!asserts_from_pinned_url_in_output(
            "grep -q \"file://${{ env.SKIA_ARCHIVE_IOS_DEVICE }}\" \"$output_file\"",
            SKIA_ARCHIVE_IOS_DEVICE_VAR
        ));
    }
}
