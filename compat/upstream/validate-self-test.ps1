<#
.SYNOPSIS
    Adversarial self-test for compat/upstream/validate.ps1.

.DESCRIPTION
    Copies the real contract into throwaway directories, plants one genuine
    violation per case, and asserts the specific rejection reason. Cases marked
    regenerate_digests first run the validator in -WriteLedgerDigests mode inside
    the copy, so every forgery case models an attacker who already re-blessed the
    ledger digests. One case is positive: an honest transition backed by real
    Rust tests in this working tree must pass.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$SourceRoot = $PSScriptRoot
$RepositoryRoot = (Resolve-Path -LiteralPath (Split-Path -Parent (Split-Path -Parent $SourceRoot))).ProviderPath
$PowerShellExecutable = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$ValidatorTimeoutMilliseconds = 300000

# Real, existing acceptance evidence in this working tree, used to build the
# honest transition and to isolate exactly one defect in each forgery case.
$RealTestPath = "crates/claw-security/tests/frozen_gateway_registry.rs"
$RealTestName = "rust_registries_equal_the_frozen_inventory_in_both_directions"
$RealSourcePath = "crates/claw-security/src/authorization.rs"
$RealSourceSymbol = "CURRENT_PROTOCOL_VERSION"
$RealFixturePath = "crates/claw-config/data/env-mapping.json"
$RealWorkflowPath = ".github/workflows/rust.yml"
$RealWorkflowCheck = "msrv"
$RustFileWithoutTests = "crates/claw-config/src/error.rs"

# A throwaway repository root used only by the cases that probe what counts as an
# ENABLED Rust test. The real tree has no #[ignore]d, cfg-gated or commented-out
# test to cite, so those forgeries are staged in a synthetic tree instead of
# adding files outside compat/upstream.
#
# Both throwaway trees live under a work root that defaults to the system temp
# directory. That directory is NOT private to this run: on Windows, Storage Sense
# deletes %TEMP% content under disk pressure, and this repository's development
# and CI machines run many concurrent cargo builds that create exactly that
# pressure. Allow relocating the work root so a run can be made hermetic.
$SelfTestWorkRoot = if ([string]::IsNullOrEmpty($env:GTA_CLAW_SELFTEST_WORK_ROOT)) {
    [System.IO.Path]::GetTempPath()
} else {
    $env:GTA_CLAW_SELFTEST_WORK_ROOT
}
if (-not (Test-Path -LiteralPath $SelfTestWorkRoot)) {
    New-Item -ItemType Directory -Path $SelfTestWorkRoot -Force | Out-Null
}
$SyntheticRoot = Join-Path $SelfTestWorkRoot (
    "gta-claw-upstream-validator-synthetic-" + [Guid]::NewGuid().ToString("N")
)
$SyntheticTestName = "parity_is_proven_here"

function New-SyntheticRepositoryRoot {
    param([string]$Root)
    $files = [ordered]@{
        "Cargo.toml" = ("[workspace]`nmembers = [`n" +
            "  `"crates/synthetic`",`n" +
            "  `"crates/decoy`",`n" +
            "  `"crates/nonrunning`",`n" +
            "  `"globbed/*`",`n" +
            "]`nexclude = [`"vendored`"]`n")
        "crates/synthetic/Cargo.toml" = "[package]`nname = `"synthetic`"`n"
        "crates/synthetic/tests/enabled.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/tests/async_enabled.rs" =
            "#[tokio::test]`nasync fn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/tests/ignored.rs" =
            "#[test]`n#[ignore]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/tests/cfg_gated.rs" =
            "#[test]`n#[cfg(target_os = `"none`")]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/tests/line_commented.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`n`n`n`n`n`n`n// #[test]`n// fn $SyntheticTestName() {}`n"
        "crates/synthetic/tests/block_commented.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`n`n`n`n`n`n`n/* #[test]`nfn $SyntheticTestName() {} */`n"
        "crates/synthetic/tests/plain_fn.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`n`n`n`n`n`n`nfn $SyntheticTestName() {}`n"
        "crates/synthetic/tests/string_literal.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`n`n`n`n`n`n`nconst CLAIM: &str = `"fn $SyntheticTestName`";`n"
        # The cases below exercise the item-tree walker rather than the lexer.
        # Each one is a forgery that a line-window matcher would have accepted.
        "crates/synthetic/tests/detached_attribute.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`nfn $SyntheticTestName() {}`n"
        "crates/synthetic/tests/nested_module.rs" =
            "mod real_module {`n    #[test]`n    fn $SyntheticTestName() {`n        assert!(true);`n    }`n}`n"
        "crates/synthetic/tests/cfg_test_module.rs" =
            "#[cfg(test)]`nmod tests {`n    #[test]`n    fn $SyntheticTestName() {`n        assert!(true);`n    }`n}`n"
        "crates/synthetic/tests/disabled_module.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`n#[cfg(any())]`nmod tests {`n    #[test]`n    fn $SyntheticTestName() {}`n}`n"
        "crates/synthetic/tests/inner_disabled_module.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`nmod tests {`n    #![cfg(any())]`n    #[test]`n    fn $SyntheticTestName() {}`n}`n"
        "crates/synthetic/tests/raw_string_literal.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`nconst CLAIM: &str = r#`"#[test] fn $SyntheticTestName() {}`"#;`n"
        "crates/synthetic/tests/impl_block.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`nstruct Proof;`nimpl Proof {`n    #[test]`n    fn $SyntheticTestName() {}`n}`n"
        "crates/synthetic/tests/doc_comment.rs" =
            "#[test]`nfn unrelated_but_real() {}`n`n/// #[test]`n/// fn $SyntheticTestName() {}`nfn documented() {}`n"
        # Written with CRLF on purpose. Carriage return is ASCII whitespace to the
        # tokenizer, so a CRLF checkout on Windows and an LF checkout on Linux must
        # reach the same verdict for the same file.
        "crates/synthetic/tests/crlf_enabled.rs" =
            "#[test]`r`nfn $SyntheticTestName() {`r`n    assert!(true);`r`n}`r`n"
        # The files below all contain a genuinely enabled #[test] that the oracle
        # accepts. What separates them is whether any cargo test target actually
        # compiles the file, which is the only thing that decides whether the test
        # can ever run.
        "crates/synthetic/src/lib.rs" =
            ("mod wired;`nmod nested;`n#[path = `"relocated.rs`"]`nmod aliased;`nmod carrier;`n" +
             "pub(crate) mod restricted;`nmod inline_host;`nmod twinned;`n")
        "crates/synthetic/src/wired.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/src/relocated.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/src/nested/mod.rs" =
            "mod deep;`n#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/src/nested/deep.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # carrier.rs is a non-mod-rs file, so its module directory
        # (src/carrier/) and the directory holding it (src/) are different. Every
        # #[path] below sits at the top level of the file, where Rust resolves it
        # against the directory holding the file. Each real target has a decoy
        # planted where a resolver using the module directory instead would look,
        # so a rule that gets this wrong both rejects the real file and blesses a
        # file cargo never compiles.
        "crates/synthetic/src/carrier.rs" =
            ("#[path = `"sibling.rs`"]`nmod one;`n" +
             "#[path = `"modular/mod.rs`"]`nmod two;`n" +
             "#[path = r`"rawsib.rs`"]`nmod three;`n")
        "crates/synthetic/src/sibling.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/src/carrier/sibling.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # A #[path] naming a mod.rs makes that module mod-rs, so its children
        # resolve beside it. modular/mod/child.rs is where a resolver that
        # stripped only the .rs would look, and nothing compiles it.
        "crates/synthetic/src/modular/mod.rs" =
            "mod child;`n"
        "crates/synthetic/src/modular/child.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/src/modular/mod/child.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # #[path = r"..."] is a raw string. A reader that tokenises raw strings as
        # opaque literals cannot see the attribute at all and resolves the
        # declaration by module name instead, which lands on carrier/three.rs.
        "crates/synthetic/src/rawsib.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/src/carrier/three.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # A #[path] on an INLINE module renames the directory its children live
        # in. cargo compiles blessed/proof.rs here; a reader that treats the
        # inline block as a plain name segment looks under inline_host/scope/
        # instead, so a decoy is planted there.
        "crates/synthetic/src/inline_host.rs" =
            ("#[path = `"blessed`"]`nmod scope {`n    mod proof;`n}`n" +
             "mod holder {`n    #[path = `"renamed`"]`n    mod deeper {`n        mod nestleaf;`n    }`n}`n")
        "crates/synthetic/src/blessed/proof.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/src/inline_host/scope/proof.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # A path on a NESTED inline module is relative to the enclosing module
        # directory, not to the directory holding the file. Verified against
        # cargo: it compiles inline_host/holder/renamed/nestleaf.rs.
        "crates/synthetic/src/inline_host/holder/renamed/nestleaf.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/src/inline_host/holder/deeper/nestleaf.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # 'mod twinned;' is answered by BOTH files below. rustc rejects that with
        # E0761 and compiles neither, so both must fail closed. They are the only
        # fixture files deliberately left unbuildable.
        "crates/synthetic/src/twinned.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/src/twinned/mod.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # Declared with a restricted visibility. The token walk has to step over
        # the whole (crate) group before it can see the mod keyword; stopping
        # short leaves an ordinary module looking like an orphan.
        "crates/synthetic/src/restricted.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # Never named by any mod declaration anywhere in the crate. cargo builds
        # nothing from it, so the test inside it never runs.
        "crates/synthetic/src/orphan.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # A build script is compiled, but cargo test does not run its tests.
        "crates/synthetic/build.rs" =
            "fn main() {}`n#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # Outside every Cargo package.
        "loose/outside.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/data/fixture.json" = "{}`n"
        # The cited test exists only inside a macro token tree. cargo expands
        # stringify! to a string literal, so no test named $SyntheticTestName is
        # ever compiled or run. The {} before the attribute is deliberate: it is
        # what made an earlier port stop at the first brace and resume INSIDE the
        # token tree, which made the forged item visible.
        "crates/synthetic/tests/macro_forged.rs" =
            "const _FORGED: &str = stringify!({} #[test] fn $SyntheticTestName() {});`n"
        # The accepting direction for the same rule: an item-position macro must
        # not swallow the real test that follows it.
        "crates/synthetic/tests/macro_then_real.rs" =
            "::std::thread_local! { static V: u32 = 1; }`n`n#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # A function-level #[cfg(test)] genuinely does run under cargo test, so
        # it must be accepted. Pinning this stops the cfg rule from being
        # tightened back into a false-rejection engine.
        "crates/synthetic/tests/cfg_test_fn.rs" =
            "#[cfg(test)]`n#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # A second crate whose manifest names an orphan under a dependency table
        # rather than a target section. cargo builds nothing from it.
        "crates/decoy/Cargo.toml" =
            "[package]`nname = `"decoy`"`n`n[dependencies.other]`npath = `"src/blessed.rs`"`n"
        "crates/decoy/src/lib.rs" = "`n"
        "crates/decoy/src/blessed.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # bench and example targets default to test = false, so cargo test
        # compiles them but never runs a #[test] inside one. Measured against
        # cargo metadata rather than recalled.
        "crates/synthetic/benches/bench.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/synthetic/examples/demo.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # The accepting direction for the same rule: a bin target under src/bin
        # does run its tests, so it must stay citable.
        "crates/synthetic/src/bin/cli.rs" =
            "fn main() {}`n#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # A crate that switches off every route by which cargo test would reach
        # its files: auto-discovery of tests/, an explicit bin with test = false,
        # and an explicit test target whose own main() replaces the libtest
        # harness so its #[test] items are inert.
        "crates/nonrunning/Cargo.toml" =
            ("[package]`nname = `"nonrunning`"`nautotests = false`n`n" +
             "[[bin]]`nname = `"notest`"`npath = `"src/bin/notest.rs`"`ntest = false`n`n" +
             "[[test]]`nname = `"noharness`"`npath = `"tests/noharness.rs`"`nharness = false`n")
        "crates/nonrunning/src/lib.rs" = "`n"
        "crates/nonrunning/src/bin/notest.rs" =
            "fn main() {}`n#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/nonrunning/tests/noharness.rs" =
            "fn main() {}`n#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        "crates/nonrunning/tests/autodiscovered.rs" =
            "#[test]`nfn $SyntheticTestName() {`n    assert!(true);`n}`n"
        # Workspace membership. Reachability proves cargo would compile a file
        # within its package; it says nothing about whether anything builds the
        # package. Each of these four is a real cargo outcome, measured against
        # cargo itself rather than recalled.
        # Not listed in members and not excluded: cargo test --workspace never
        # touches it, so its #[test] items never run.
        "crates/orphanpkg/Cargo.toml" = "[package]`nname = `"orphanpkg`"`n"
        "crates/orphanpkg/src/lib.rs" =
            "#[cfg(test)]`nmod tests {`n    #[test]`n    fn $SyntheticTestName() {`n        assert!(true);`n    }`n}`n"
        # Named in the workspace exclude list -- a deliberate, reviewed statement
        # that this directory is not part of the build.
        "vendored/Cargo.toml" = "[package]`nname = `"vendored`"`n"
        "vendored/src/lib.rs" =
            "#[cfg(test)]`nmod tests {`n    #[test]`n    fn $SyntheticTestName() {`n        assert!(true);`n    }`n}`n"
        # The accepting direction, twice, because a membership rule that only
        # pins its rejections becomes a false-rejection engine on the next edit.
        # A glob member must expand.
        "globbed/member/Cargo.toml" = "[package]`nname = `"globbed-member`"`n"
        "globbed/member/src/lib.rs" =
            "#[cfg(test)]`nmod tests {`n    #[test]`n    fn $SyntheticTestName() {`n        assert!(true);`n    }`n}`n"
        # A manifest carrying its own [workspace] table is a separate build root
        # and cargo builds it on its own terms. The real tree has two.
        "standalone/Cargo.toml" = "[package]`nname = `"standalone`"`n`n[workspace]`n"
        "standalone/src/lib.rs" =
            "#[cfg(test)]`nmod tests {`n    #[test]`n    fn $SyntheticTestName() {`n        assert!(true);`n    }`n}`n"
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $separator = [string][System.IO.Path]::DirectorySeparatorChar
    foreach ($relative in $files.Keys) {
        $absolute = Join-Path $Root ($relative.Replace("/", $separator))
        $directory = Split-Path -Parent $absolute
        if (-not (Test-Path -LiteralPath $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        [System.IO.File]::WriteAllText($absolute, [string]$files[$relative], $encoding)
    }
}

New-SyntheticRepositoryRoot $SyntheticRoot

# Sentinels spanning every subtree the synthetic cases cite. The fixture is built
# once at startup and no case ever modifies it, so a missing file can only mean
# the tree was deleted or truncated underneath the run. Checked immediately after
# construction AND before every case, because the observed failure mode is
# disappearance mid-run rather than a failed create.
$SyntheticRootSentinels = @(
    "Cargo.toml",
    "crates/synthetic/Cargo.toml",
    "crates/synthetic/tests/enabled.rs",
    "crates/synthetic/tests/ignored.rs",
    "crates/orphanpkg/Cargo.toml",
    "vendored/Cargo.toml",
    "globbed/member/Cargo.toml",
    "standalone/Cargo.toml"
)

function Assert-SelfTestFixtureIntact {
    param([string]$Stage)
    $separator = [string][System.IO.Path]::DirectorySeparatorChar
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($relative in $SyntheticRootSentinels) {
        $absolute = Join-Path $SyntheticRoot ($relative.Replace("/", $separator))
        if (-not (Test-Path -LiteralPath $absolute)) {
            $missing.Add($relative)
        }
    }
    if ($missing.Count -eq 0) {
        return
    }
    # Deliberately not phrased as a rule violation. A run that reports this has
    # measured nothing about the validator, and saying so plainly is the whole
    # point: the previous behaviour was a cascade of per-case "not a GTA-Claw
    # tree" errors that read exactly like a semantic regression.
    throw (("validator self-test fixture is INCOMPLETE at {0}: {1} of {2} sentinel " +
        "files are missing under '{3}' (first missing: {4}). This is an " +
        "ENVIRONMENT failure, not a validator regression -- the fixture is built " +
        "once at startup and never modified by any case, so missing files mean " +
        "the directory was removed underneath this run. On Windows, Storage Sense " +
        "deletes %TEMP% content under disk pressure, which concurrent cargo builds " +
        "readily create. Re-run with GTA_CLAW_SELFTEST_WORK_ROOT set to a " +
        "directory outside the temp cleaner's reach.") -f
        $Stage, $missing.Count, $SyntheticRootSentinels.Count, $SyntheticRoot, $missing[0])
}

Assert-SelfTestFixtureIntact "construction"

function Read-Json {
    param([string]$Path)
    # ReadAllText rather than Get-Content -Raw: Windows PowerShell 5.1 decodes a
    # BOM-less file with the system ANSI codepage, PowerShell Core as UTF-8.
    return (ConvertFrom-Json ([System.IO.File]::ReadAllText($Path)))
}

function Write-Json {
    param(
        [string]$Path,
        [object]$Value
    )
    # Set-Content -Encoding UTF8 emits a BOM on Windows PowerShell and none on
    # PowerShell Core; write the bytes directly so both hosts produce the same
    # file for the same case.
    $text = ($Value | ConvertTo-Json -Depth 50)
    [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

function Test-OrdinalStringEqual {
    param(
        [AllowNull()]
        [string]$Left,
        [AllowNull()]
        [string]$Right
    )
    return [StringComparer]::Ordinal.Equals($Left, $Right)
}

function ConvertTo-PowerShellLiteral {
    param([string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Invoke-Validator {
    param(
        [string]$CaseRoot,
        [string]$RepositoryRootOverride,
        [switch]$WriteLedgerDigests
    )
    # The child is started through System.Diagnostics.Process rather than the
    # PowerShell call operator for three reasons:
    #   * the raw failure text is captured verbatim, instead of PowerShell's
    #     wrapped ErrorRecord rendering, which hard-wraps long messages mid-word
    #     and would defeat exact rejection-reason matching;
    #   * standard input is redirected and closed immediately (and -InputFormat
    #     None is passed) so the child can never block waiting on an inherited,
    #     never-closed pipe;
    #   * both output streams are drained asynchronously, so neither can deadlock
    #     on a full pipe buffer.
    # The command text deliberately contains no double quote characters, which
    # keeps the single Windows argument quoting below exact.
    $repositoryRoot = if ([string]::IsNullOrEmpty($RepositoryRootOverride)) {
        $RepositoryRoot
    } else {
        $RepositoryRootOverride
    }
    $invocation = "& {0} -RepositoryRoot {1}" -f
        (ConvertTo-PowerShellLiteral (Join-Path $CaseRoot "validate.ps1")),
        (ConvertTo-PowerShellLiteral $repositoryRoot)
    if ($WriteLedgerDigests) {
        $invocation += " -WriteLedgerDigests"
    }
    $command = '$ErrorActionPreference = ''Stop''; try { ' + $invocation +
        ' } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }'
    if ($command.Contains('"')) {
        throw "Invoke-Validator built a command containing a double quote, which would break argument quoting."
    }

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $PowerShellExecutable
    $startInfo.Arguments = "-NoLogo -NoProfile -NonInteractive -InputFormat None " +
        "-ExecutionPolicy Bypass -Command `"$command`""
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = $RepositoryRoot
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    [void]$process.Start()
    $process.StandardInput.Close()
    $standardOutput = $process.StandardOutput.ReadToEndAsync()
    $standardError = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($ValidatorTimeoutMilliseconds)) {
        try { $process.Kill() } catch { }
        throw "Validator run under '$CaseRoot' did not finish within $ValidatorTimeoutMilliseconds ms."
    }
    [void]$standardOutput.Wait($ValidatorTimeoutMilliseconds)
    [void]$standardError.Wait($ValidatorTimeoutMilliseconds)
    $exitCode = $process.ExitCode
    $text = ($standardOutput.Result + "`n" + $standardError.Result)
    $process.Dispose()

    return [pscustomobject]@{
        exit_code = $exitCode
        output = ($text -replace "`r`n", "`n")
    }
}

function Get-FirstLedger {
    param([string]$CaseRoot)
    return Read-Json (Join-Path $CaseRoot "ledgers/gateway-core.json")
}

function Save-FirstLedger {
    param(
        [string]$CaseRoot,
        [object]$Ledger
    )
    Write-Json (Join-Path $CaseRoot "ledgers/gateway-core.json") $Ledger
}

function New-Artifact {
    param(
        [string]$Path,
        [string]$Test
    )
    return [pscustomobject][ordered]@{
        path = $Path
        test = $Test
    }
}

function New-Pointer {
    param(
        [string]$Path,
        [string]$Note
    )
    return [pscustomobject][ordered]@{
        path = $Path
        note = $Note
    }
}

function Set-FeatureTransition {
    param(
        [object]$Feature,
        [string]$Status,
        [string]$EvidenceStatus,
        [object[]]$Artifacts,
        [object[]]$Pointers,
        [switch]$KeepBaselineDifference
    )
    $Feature.status = $Status
    $Feature.acceptance_evidence.status = $EvidenceStatus
    $Feature.acceptance_evidence.artifacts = @($Artifacts)
    if ($null -ne $Pointers -and $Pointers.Count -gt 0) {
        $Feature | Add-Member -NotePropertyName "implementation_pointers" -NotePropertyValue @($Pointers) -Force
    }
    if (-not $KeepBaselineDifference) {
        $Feature.known_differences = @("Rust parity proven by the cited acceptance evidence.")
    }
}

function Set-ManifestStatusTotals {
    param(
        [string]$CaseRoot,
        [int]$Unimplemented,
        [int]$Partial,
        [int]$Implemented
    )
    $path = Join-Path $CaseRoot "manifest.json"
    $manifest = Read-Json $path
    $manifest.evidence_policy.status_totals.unimplemented = $Unimplemented
    $manifest.evidence_policy.status_totals.partial = $Partial
    $manifest.evidence_policy.status_totals.implemented = $Implemented
    Write-Json $path $manifest
}

function Reset-MutableLedgerTransitions {
    param([string]$CaseRoot)
    $baselineDifference =
        "No npm-free Rust implementation or acceptance evidence exists in this repository at this baseline."
    $ledgerPaths = @(
        "ledgers/gateway-core.json",
        "ledgers/official-integration.json",
        "ledgers/official-client-interop.json"
    )
    foreach ($relativePath in $ledgerPaths) {
        $path = Join-Path $CaseRoot $relativePath
        $ledger = Read-Json $path
        foreach ($feature in @($ledger.features)) {
            $feature.status = "unimplemented"
            $feature.acceptance_evidence.status = "missing"
            $feature.acceptance_evidence.artifacts = @()
            $feature.known_differences = @($baselineDifference)
            $feature.PSObject.Properties.Remove("implementation_pointers")
        }
        Write-Json $path $ledger
    }
    Set-ManifestStatusTotals $CaseRoot 47 0 0
}

# Applies a syntactically well-formed "implemented" claim to the first row of the
# gateway-core ledger, differing from the honest claim only by the planted defect.
function Set-ForgedTransition {
    param(
        [string]$CaseRoot,
        [object[]]$Artifacts,
        [object[]]$Pointers,
        [string]$EvidenceStatus = "accepted",
        [switch]$KeepBaselineDifference
    )
    $ledger = Get-FirstLedger $CaseRoot
    Set-FeatureTransition `
        -Feature $ledger.features[0] `
        -Status "implemented" `
        -EvidenceStatus $EvidenceStatus `
        -Artifacts $Artifacts `
        -Pointers $Pointers `
        -KeepBaselineDifference:$KeepBaselineDifference
    Save-FirstLedger $CaseRoot $ledger
    Set-ManifestStatusTotals $CaseRoot 46 0 1
}

$validResult = Invoke-Validator $SourceRoot
if ($validResult.exit_code -ne 0) {
    throw "validator self-test baseline failed: $($validResult.output)"
}

$cases = @(
    [ordered]@{
        name = "honest-transition-passes"
        expect_success = $true
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot -Artifacts @(
                (New-Artifact $RealTestPath $RealTestName)
            ) -Pointers @(
                (New-Pointer $RealSourcePath "Rust implementation of the protocol version constant."),
                (New-Pointer $RealWorkflowPath "Workflow that runs the cited test.")
            )
        }
    },
    [ordered]@{
        name = "partial-honest-transition-passes"
        expect_success = $true
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            Set-FeatureTransition `
                -Feature $ledger.features[0] `
                -Status "partial" `
                -EvidenceStatus "partial" `
                -Artifacts @(
                    (New-Artifact $RealTestPath $RealTestName)
                ) `
                -Pointers @(
                    (New-Pointer $RealSourcePath "Registration is done; behaviour is not.")
                )
            Save-FirstLedger $caseRoot $ledger
            Set-ManifestStatusTotals $caseRoot 46 1 0
        }
    },
    [ordered]@{
        name = "partial-without-artifacts"
        expected_message = "status 'partial' requires at least one acceptance evidence artifact"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            Set-FeatureTransition `
                -Feature $ledger.features[0] `
                -Status "partial" `
                -EvidenceStatus "partial" `
                -Artifacts @()
            Save-FirstLedger $caseRoot $ledger
            Set-ManifestStatusTotals $caseRoot 46 1 0
        }
    },
    [ordered]@{
        name = "partial-claiming-accepted-evidence"
        expected_message = "status 'partial' requires acceptance_evidence.status 'partial', got 'accepted'"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            Set-FeatureTransition `
                -Feature $ledger.features[0] `
                -Status "partial" `
                -EvidenceStatus "accepted" `
                -Artifacts @((New-Artifact $RealTestPath $RealTestName))
            Save-FirstLedger $caseRoot $ledger
            Set-ManifestStatusTotals $caseRoot 46 1 0
        }
    },
    [ordered]@{
        name = "partial-keeps-baseline-known-difference"
        expected_message = "status 'partial' must not keep the baseline no-implementation known_differences placeholder"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            Set-FeatureTransition `
                -Feature $ledger.features[0] `
                -Status "partial" `
                -EvidenceStatus "partial" `
                -Artifacts @((New-Artifact $RealTestPath $RealTestName)) `
                -KeepBaselineDifference
            Save-FirstLedger $caseRoot $ledger
            Set-ManifestStatusTotals $caseRoot 46 1 0
        }
    },
    [ordered]@{
        name = "partial-not-declared-in-manifest-totals"
        expected_message = "status_totals"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            Set-FeatureTransition `
                -Feature $ledger.features[0] `
                -Status "partial" `
                -EvidenceStatus "partial" `
                -Artifacts @((New-Artifact $RealTestPath $RealTestName))
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "synthetic-enabled-test-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/enabled.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "synthetic-async-enabled-test-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/async_enabled.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "synthetic-nested-module-test-passes-when-cited-exactly"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/nested_module.rs" "real_module::$SyntheticTestName")
            )
        }
    },
    [ordered]@{
        name = "synthetic-cfg-test-module-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/cfg_test_module.rs" "tests::$SyntheticTestName")
            )
        }
    },
    [ordered]@{
        name = "synthetic-crlf-source-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/crlf_enabled.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-detached-test-attribute"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # An unrelated #[test] earlier in the file must not bless a following
            # ordinary function. A line-window matcher accepted this.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/detached_attribute.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-unqualified-nested-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # The test exists but lives in a module; a bare citation does not
            # identify it, so the module path is part of the proof obligation.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/nested_module.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-fabricated-module-path"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/nested_module.rs" "fabricated_module::$SyntheticTestName")
            )
        }
    },
    [ordered]@{
        name = "implemented-with-cfg-disabled-module-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/disabled_module.rs" "tests::$SyntheticTestName")
            )
        }
    },
    [ordered]@{
        name = "implemented-with-inner-attribute-disabled-module-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # #![cfg(any())] disables the whole enclosing scope transitively.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/inner_disabled_module.rs" "tests::$SyntheticTestName")
            )
        }
    },
    [ordered]@{
        name = "implemented-with-raw-string-literal-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/raw_string_literal.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-test-inside-impl-block"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/impl_block.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-doc-comment-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/doc_comment.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "oracle-corpus-expectation-flipped"
        expected_message = "enabled-test oracle drift on case"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # The shared corpus is the drift detector between the two trust roots.
            # Flipping an expectation is how a re-port that silently changed
            # behaviour would look, so it must be rejected by name.
            $corpusPath = Join-Path $caseRoot "enabled-test-oracle.json"
            $corpus = Read-Json $corpusPath
            $corpus.cases[0].expected = -not $corpus.cases[0].expected
            Write-Json $corpusPath $corpus
        }
    },
    [ordered]@{
        name = "oracle-corpus-case-deleted"
        expected_message = "enabled-test-oracle must contain exactly"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $corpusPath = Join-Path $caseRoot "enabled-test-oracle.json"
            $corpus = Read-Json $corpusPath
            $corpus.cases = @($corpus.cases | Select-Object -Skip 1)
            Write-Json $corpusPath $corpus
        }
    },
    [ordered]@{
        name = "reachability-corpus-case-deleted"
        expected_message = "reachability-corpus must contain exactly"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # The shared reachability corpus is the only instrument that compares
            # the two resolvers on constructs the real tree does not contain.
            # Deleting a case is how a disagreement would be hidden.
            $corpusPath = Join-Path $caseRoot "reachability-corpus.json"
            $corpus = Read-Json $corpusPath
            $corpus.cases = @($corpus.cases | Select-Object -Skip 1)
            Write-Json $corpusPath $corpus
        }
    },
    [ordered]@{
        name = "reachability-corpus-expectation-flipped"
        expected_message = "accepting cases; found"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # Flipping an accepting case to rejecting is how a resolver that
            # started refusing legitimate evidence would be papered over. The
            # accepting/rejecting split is pinned so the false-rejection
            # direction cannot be quietly relaxed.
            $corpusPath = Join-Path $caseRoot "reachability-corpus.json"
            $corpus = Read-Json $corpusPath
            foreach ($case in $corpus.cases) {
                if ($case.expect -eq "accept") {
                    $case.expect = "reject"
                    break
                }
            }
            Write-Json $corpusPath $corpus
        }
    },
    [ordered]@{
        name = "reachability-corpus-cites-undefined-file"
        expected_message = "which the case does not define"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # A case that cites a path it never defines would assert a verdict
            # about a file the fixture never contained - and on a replayer that
            # materializes into a real checkout, about a file that already exists
            # there. Same fabricated-citation defence as the ledger itself.
            $corpusPath = Join-Path $caseRoot "reachability-corpus.json"
            $corpus = Read-Json $corpusPath
            $corpus.cases[0].cite = "crates/claw-migrate/tests/providers.rs"
            Write-Json $corpusPath $corpus
        }
    },
    [ordered]@{
        name = "reachability-corpus-path-escapes-fixture-root"
        expected_message = "must not contain a dot segment"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # A dot segment in a fixture key lets any harness that materializes
            # this corpus write outside its fixture root.
            $corpusPath = Join-Path $caseRoot "reachability-corpus.json"
            $corpus = Read-Json $corpusPath
            $files = [ordered]@{}
            foreach ($property in $corpus.cases[0].files.PSObject.Properties) {
                $files["../" + $property.Name] = $property.Value
            }
            $corpus.cases[0].files = [pscustomobject]$files
            $corpus.cases[0].cite = "../" + $corpus.cases[0].cite
            Write-Json $corpusPath $corpus
        }
    },
    [ordered]@{
        name = "reachability-corpus-removed"
        expected_message = "fixed artifact topology mismatch; missing=[reachability-corpus.json]"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Remove-Item -LiteralPath (Join-Path $caseRoot "reachability-corpus.json") -Force
        }
    },
    [ordered]@{
        name = "reachability-corpus-case-renamed"
        expected_message = "reachability-corpus digest mismatch"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # Renaming preserves the count and the accept/reject split, so only
            # the frozen digest catches it.
            $corpusPath = Join-Path $caseRoot "reachability-corpus.json"
            $corpus = Read-Json $corpusPath
            $corpus.cases[0].name = "renamed-case"
            Write-Json $corpusPath $corpus
        }
    },
    [ordered]@{
        name = "frozen-acceptance-bar-weakened"
        expected_message = "frozen feature text changed"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # The claimant rewrites the row's own statement of what parity means,
            # then re-blesses the ledger digest through the documented command.
            # acceptance_evidence.required is contract text, not a mutable field:
            # a party that could edit it would be setting the bar it is judged
            # against. Only the frozen projection digest catches this, and
            # -WriteLedgerDigests cannot reach that constant.
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].acceptance_evidence.required = "Any test at all exists."
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "frozen-feature-title-rewritten"
        expected_message = "frozen feature text changed"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].title = "Something easier to claim"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "frozen-upstream-source-narrowed"
        expected_message = "frozen feature text changed"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # Shrinking the upstream surface a row is measured against is the same
            # forgery as weakening its required text, one level down.
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].upstream_source.paths = @("docs")
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "frozen-feature-tier-downgraded"
        expected_message = "frozen feature text changed"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].tier = "tier_3"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "oracle-corpus-case-renamed"
        expected_message = "enabled-test-oracle digest mismatch"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # Every case still classifies correctly and the counts still hold, so
            # only the frozen digest catches this. -WriteLedgerDigests cannot
            # regenerate it.
            $corpusPath = Join-Path $caseRoot "enabled-test-oracle.json"
            $corpus = Read-Json $corpusPath
            $corpus.cases[0].name = "renamed-behind-your-back"
            Write-Json $corpusPath $corpus
        }
    },
    [ordered]@{
        name = "oracle-corpus-normative-owner-rewritten"
        expected_message = "must record claw-conformance declares_enabled_test as normative"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            # Ownership direction is part of the contract: this script may never
            # declare itself the normative implementation.
            $corpusPath = Join-Path $caseRoot "enabled-test-oracle.json"
            $corpus = Read-Json $corpusPath
            $corpus.normative_implementation.path = "compat/upstream/validate.ps1"
            $corpus.normative_implementation.function = "Test-DeclaresEnabledRustTest"
            Write-Json $corpusPath $corpus
        }
    },
    [ordered]@{
        name = "oracle-corpus-removed"
        expected_message = "fixed artifact topology mismatch"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Remove-Item -LiteralPath (Join-Path $caseRoot "enabled-test-oracle.json") -Force
        }
    },
    [ordered]@{
        name = "implemented-with-ignored-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/ignored.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-orphan-source-file"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # The cited test is real and enabled; the oracle accepts it. Nothing
            # in the crate declares mod orphan, so cargo compiles the file into
            # nothing and the test never runs. This is the disclosed vector.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/orphan.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-build-script-test"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # cargo test does not run tests declared in a build script.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/build.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-file-outside-any-crate"
        expected_message = "is not inside a Cargo package"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "loose/outside.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-mod-wired-source-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # Reachability must not reject honest evidence. A unit test in a
            # src/ module that lib.rs declares is legitimate and common.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/wired.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-path-attribute-module-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # Reached only through #[path = "relocated.rs"]. A resolver that
            # ignored the attribute would reject this honest citation.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/relocated.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-transitive-mod-chain-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # lib.rs -> nested/mod.rs -> nested/deep.rs. Both the mod.rs form and
            # the transitive hop must resolve.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/nested/deep.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-path-attribute-sibling-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # src/carrier.rs is non-mod-rs and carries #[path = "sibling.rs"] at
            # its top level, which Rust resolves against src/, not src/carrier/.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/sibling.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-path-attribute-module-directory-decoy"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # The decoy sits at src/carrier/sibling.rs, where a resolver that
            # based a top-level #[path] on the module directory would look. No
            # mod declaration names it, so cargo never compiles it.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/carrier/sibling.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-path-attribute-mod-rs-child-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # #[path = "modular/mod.rs"] makes that module mod-rs, so its own
            # mod child; resolves to modular/child.rs beside it.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/modular/child.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-path-attribute-mod-rs-child-decoy"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # modular/mod/child.rs is where a resolver that turned the path target
            # into a directory by stripping .rs would look for that module's
            # children. Nothing compiles it.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/modular/mod/child.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-inline-path-attribute-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # #[path = "blessed"] on the inline 'mod scope { }' renames the
            # directory its children resolve in, so 'mod proof;' inside the block
            # is src/blessed/proof.rs. This pins the accepting direction: a rule
            # that simply dropped inline path support would reject honest
            # evidence here rather than merely bless the decoy below.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/blessed/proof.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-inline-path-attribute-decoy"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # src/inline_host/scope/proof.rs is where a reader that carried the
            # inline module's NAME instead of its #[path] would look. cargo never
            # compiles it.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/inline_host/scope/proof.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-nested-inline-path-attribute-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # #[path = "renamed"] on an inline module nested inside another
            # inline module resolves against the ENCLOSING module directory
            # (inline_host/holder/), not against the directory holding the file.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/inline_host/holder/renamed/nestleaf.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-nested-inline-path-attribute-decoy"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # Where a reader that ignored the nested path attribute would look.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/inline_host/holder/deeper/nestleaf.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-ambiguous-module-file-side"
        expected_message = "E0761: file for module found at both paths"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # src/twinned.rs and src/twinned/mod.rs both answer 'mod twinned;'.
            # rustc refuses the crate outright, so neither file is ever compiled
            # and neither can carry acceptance evidence.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/twinned.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-ambiguous-module-directory-side"
        expected_message = "E0761: file for module found at both paths"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # The other side of the same ambiguity. Both must fail, and both must
            # fail for the ambiguity rather than for the generic unreachable
            # message, or the report sends the reader to rewire a module that is
            # already wired twice.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/twinned/mod.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-raw-string-path-attribute-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # #[path = r"rawsib.rs"] is a raw string literal and names a real file.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/rawsib.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-unreadable-path-attribute-fallback-decoy"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # carrier/three.rs is what mod three; would resolve to if the raw
            # string in its #[path] were invisible. A path attribute the reader
            # cannot resolve must resolve to nothing rather than fall back to the
            # module name, or an unreadable attribute becomes a blessing.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/carrier/three.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-restricted-visibility-module-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # pub(crate) mod restricted; is an ordinary module declaration. A walk
            # that cannot step over the visibility group never sees the mod
            # keyword and rejects a file cargo plainly compiles.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/restricted.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-manifest-dependency-path-orphan"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # crates/decoy/Cargo.toml names src/blessed.rs, but under
            # [dependencies.other], not a target section. Treating any path= in a
            # manifest as a target root would let one manifest line bless an
            # orphan without wiring it into the crate.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/decoy/src/blessed.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-bench-target-test"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # A bench target defaults to test = false. cargo test compiles the
            # file and never runs the #[test] inside it, so citing one is a claim
            # backed by code that never executes -- and it needs no manifest edit
            # at all, only a file in benches/.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/benches/bench.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-example-target-test"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # Same rule as benches/: example targets default to test = false.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/examples/demo.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-src-bin-target-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # The accepting direction: a bin target under src/bin DOES run its
            # tests. Dropping benches/ and examples/ from the root set must not
            # take src/bin/ with them.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/src/bin/cli.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-test-false-bin-target"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # An explicit [[bin]] with test = false, whose path also sits under
            # src/bin/. Auto-discovery must not resurrect the target the manifest
            # disabled: this is the fix for the fix, and it fails without the
            # explicit-path precedence rule.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/nonrunning/src/bin/notest.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-harness-false-test-target"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # harness = false replaces libtest with the target's own main(), so
            # every #[test] item in the file is inert. cargo metadata cannot
            # express this -- it still reports test = true -- so this rule is
            # deliberately stricter than a metadata-only root set.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/nonrunning/tests/noharness.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-autotests-disabled-target"
        expected_message = "is not reached by any cargo test target"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # autotests = false switches off discovery of tests/*.rs entirely, so
            # the file is never built into a target.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/nonrunning/tests/autodiscovered.rs" $SyntheticTestName)
            )
        }
    },    [ordered]@{
        name = "implemented-citing-non-member-package"
        expected_message = "belongs to a Cargo package that nothing builds"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # crates/orphanpkg is a well-formed package whose src/lib.rs is a
            # target root and whose test is a genuine enabled #[test]. Every
            # file-level rule passes. It is simply not in the workspace members
            # list, so cargo test at the repository root never builds it and the
            # test never runs. Two new files and no unusual construct anywhere:
            # the cheapest forgery in the pipeline until membership is checked.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/orphanpkg/src/lib.rs" "tests::$SyntheticTestName")
            )
        }
    },    [ordered]@{
        name = "implemented-citing-workspace-excluded-package"
        expected_message = "exclude list"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # Sharper than merely unlisted: the workspace manifest names this
            # directory in exclude, which is an explicit reviewed statement that
            # it is not part of the build.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "vendored/src/lib.rs" "tests::$SyntheticTestName")
            )
        }
    },    [ordered]@{
        name = "implemented-citing-glob-member-package-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # The accepting direction. members entries may be globs, and a rule
            # that compared them literally would reject every crate in a
            # repository that uses `crates/*` -- a false-rejection engine with a
            # green self-test.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "globbed/member/src/lib.rs" "tests::$SyntheticTestName")
            )
        }
    },    [ordered]@{
        name = "implemented-citing-self-rooted-workspace-package-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # A manifest carrying its own [workspace] table is a separate build
            # root that cargo builds on its own terms, and this repository has
            # two of them. Pinned in the accepting direction because it is the
            # documented residual of this rule: a static check cannot tell which
            # workspaces CI invokes, so tightening here would be a guess that
            # falsely rejects real evidence.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "standalone/src/lib.rs" "tests::$SyntheticTestName")
            )
        }
    },    [ordered]@{
        name = "implemented-with-cfg-gated-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/cfg_gated.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-citing-macro-token-tree-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # The whole forgery, end to end: the file is a real cargo test
            # target, the path exists, the citation is well formed, and the text
            # "#[test] fn <name>" is genuinely present. It is inside a macro
            # token tree, so cargo never compiles a test by that name. This is
            # the ledger-level form of the corpus case, and it is the one that
            # proves the oracle re-port protects the ledger and not just itself.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/macro_forged.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-citing-macro-then-real-test-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # A tightening rule needs its false-positive cases pinned as much as
            # its true-positive ones. An item-position macro invocation before
            # the test must not hide it.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/macro_then_real.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-citing-cfg-test-function-passes"
        expect_success = $true
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            # #[cfg(test)] #[test] fn runs under cargo test, so refusing it would
            # reject honest evidence. An earlier port did refuse it.
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/cfg_test_fn.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-line-commented-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/line_commented.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-block-commented-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/block_commented.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-plain-function-not-a-test"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/plain_fn.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-test-name-in-string-literal"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/string_literal.rs" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "non-rust-file-cited-as-evidence"
        expected_message = "must be a Rust source file containing the cited test"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/synthetic/tests/enabled.rs" $SyntheticTestName),
                (New-Artifact "crates/synthetic/data/fixture.json" $SyntheticTestName)
            )
        }
    },
    [ordered]@{
        name = "pointer-with-nonexistent-path"
        expected_message = "cites implementation pointer path 'crates/synthetic/src/imaginary.rs' that does not exist in the working tree"
        regenerate_digests = $true
        repository_root = $SyntheticRoot
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot -Artifacts @(
                (New-Artifact "crates/synthetic/tests/enabled.rs" $SyntheticTestName)
            ) -Pointers @(
                (New-Pointer "crates/synthetic/src/imaginary.rs" "Claimed implementation.")
            )
        }
    },
    [ordered]@{
        name = "pointer-with-typescript-path"
        expected_message = "is a legacy TypeScript/JavaScript file and is never Rust acceptance evidence"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot -Artifacts @(
                (New-Artifact $RealTestPath $RealTestName)
            ) -Pointers @(
                (New-Pointer "src/server.ts" "Legacy implementation.")
            )
        }
    },
    [ordered]@{
        name = "unimplemented-with-implementation-pointer"
        expected_message = "is unimplemented and must not record implementation pointers"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0] | Add-Member -NotePropertyName "implementation_pointers" -NotePropertyValue @(
                (New-Pointer $RealSourcePath "Started work.")
            ) -Force
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "implementation-pointers-are-not-acceptance-evidence"
        expected_message = "requires at least one acceptance evidence artifact naming an enabled Rust test"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot -Artifacts @() -Pointers @(
                (New-Pointer $RealSourcePath "The whole implementation lives here, honest."),
                (New-Pointer $RealWorkflowPath "And CI runs it.")
            )
        }
    },
    [ordered]@{
        name = "implemented-without-artifacts"
        expected_message = "requires at least one acceptance evidence artifact"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @()
        }
    },
    [ordered]@{
        name = "implemented-with-nonexistent-path"
        expected_message = "cites acceptance evidence path 'crates/claw-security/tests/fabricated_parity.rs' that does not exist in the working tree"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "crates/claw-security/tests/fabricated_parity.rs" $RealTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-case-folded-path"
        expected_message = "does not exist in the working tree"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "Crates/claw-security/tests/frozen_gateway_registry.rs" $RealTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-typescript-artifact"
        expected_message = "is a legacy TypeScript/JavaScript file and is never Rust acceptance evidence"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact "src/server.ts" $RealTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-javascript-artifact"
        expected_message = "is a legacy TypeScript/JavaScript file and is never Rust acceptance evidence"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName),
                (New-Artifact "compat/legacy/scripts/verify.mjs" $RealTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-legacy-tree-artifact"
        expected_message = "lives in a legacy JavaScript/TypeScript tree and is never Rust acceptance evidence"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName),
                (New-Artifact "compat/legacy/contract.json" $RealTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-self-referential-artifact"
        expected_message = "is self-referential compatibility contract data, not acceptance evidence"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName),
                (New-Artifact "compat/upstream/inventories/gateway-protocol.json" $RealTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-fabricated-test-name"
        expected_message = "cites test 'proves_total_parity' that is not declared as an enabled #[test] in"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath "proves_total_parity")
            )
        }
    },
    [ordered]@{
        name = "implemented-with-source-symbol-instead-of-test"
        expected_message = "does not match JSON Schema pattern"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName),
                (New-Artifact $RealSourcePath $RealSourceSymbol)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-source-file-and-lowercase-symbol"
        expected_message = "cites test 'current_protocol_version' that is not declared as an enabled #[test] in"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName),
                (New-Artifact $RealSourcePath "current_protocol_version")
            )
        }
    },
    [ordered]@{
        name = "implemented-with-untested-rust-file"
        expected_message = "is not declared as an enabled #[test]"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RustFileWithoutTests $RealTestName)
            )
        }
    },
    [ordered]@{
        name = "implemented-with-fixture-as-evidence"
        expected_message = "must be a Rust source file containing the cited test"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName),
                (New-Artifact $RealFixturePath "never_run_anywhere")
            )
        }
    },
    [ordered]@{
        name = "implemented-with-workflow-as-evidence"
        expected_message = "must be a Rust source file containing the cited test"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName),
                (New-Artifact $RealWorkflowPath $RealWorkflowCheck)
            )
        }
    },
    [ordered]@{
        name = "artifact-missing-test-field"
        expected_message = "missing required properties [test]"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            Set-FeatureTransition `
                -Feature $ledger.features[0] `
                -Status "implemented" `
                -EvidenceStatus "accepted" `
                -Artifacts @((New-Artifact $RealTestPath $RealTestName))
            $ledger.features[0].acceptance_evidence.artifacts = @(
                [pscustomobject][ordered]@{ path = $RealTestPath }
            )
            Save-FirstLedger $caseRoot $ledger
            Set-ManifestStatusTotals $caseRoot 46 0 1
        }
    },
    [ordered]@{
        name = "implemented-with-untyped-string-artifact"
        expected_message = "must have JSON Schema type object"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            Set-FeatureTransition `
                -Feature $ledger.features[0] `
                -Status "implemented" `
                -EvidenceStatus "accepted" `
                -Artifacts @()
            $ledger.features[0].acceptance_evidence.artifacts = @("crates/claw-security/tests/frozen_gateway_registry.rs")
            Save-FirstLedger $caseRoot $ledger
            Set-ManifestStatusTotals $caseRoot 46 0 1
        }
    },
    [ordered]@{
        name = "implemented-with-mismatched-evidence-status"
        expected_message = "requires acceptance_evidence.status 'accepted', got 'partial'"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName)
            ) -EvidenceStatus "partial"
        }
    },
    [ordered]@{
        name = "implemented-keeps-baseline-known-difference"
        expected_message = "must not keep the baseline no-implementation known_differences placeholder"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName)
            ) -KeepBaselineDifference
        }
    },
    [ordered]@{
        name = "implemented-with-duplicated-artifact"
        expected_message = "violates JSON Schema uniqueItems"
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot @(
                (New-Artifact $RealTestPath $RealTestName),
                (New-Artifact $RealTestPath $RealTestName)
            )
        }
    },
    [ordered]@{
        name = "unimplemented-with-artifacts"
        expected_message = "must start unimplemented with an empty evidence placeholder"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].acceptance_evidence.artifacts = @(
                (New-Artifact $RealTestPath $RealTestName)
            )
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "unimplemented-drops-baseline-known-difference"
        expected_message = "is unimplemented and must keep the frozen baseline known_differences placeholder"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].known_differences = @("Quietly reworded to imply progress.")
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "retired-status-value"
        expected_message = "is not in its JSON Schema enum"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].status = "not_applicable"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "status-totals-not-updated"
        expected_message = "status_totals count 'unimplemented' must be '46'"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            Set-FeatureTransition `
                -Feature $ledger.features[0] `
                -Status "implemented" `
                -EvidenceStatus "accepted" `
                -Artifacts @((New-Artifact $RealTestPath $RealTestName))
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "mutated-last-verified-sha"
        expected_message = "last_verified_sha mismatch"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].last_verified_sha = "0000000000000000000000000000000000000000"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "mutated-ledger-baseline-sha"
        expected_message = "fixed ledger metadata mismatch"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.baseline_sha = "0000000000000000000000000000000000000000"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "duplicated-feature-id"
        expected_message = "duplicate feature_id"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[1].feature_id = $ledger.features[0].feature_id
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "mutated-ledger-row-count"
        expected_message = "ledgers/gateway-core.json must contain exactly 16 features"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features = @($ledger.features | Select-Object -First 15)
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "tampered-ledger-with-stale-digest"
        expected_message = "canonical feature/source evidence fingerprint mismatch"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].title = ([string]$ledger.features[0].title) + " (quietly retitled)"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "forged-ledger-digest-entry"
        expected_message = "canonical feature/source evidence fingerprint mismatch"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "ledger-digests.sha256"
            $text = [System.IO.File]::ReadAllText($path)
            $text = [regex]::Replace($text, "[0-9a-f]{64}", ("0" * 64), 1)
            [System.IO.File]::WriteAllText($path, $text)
        }
    },
    [ordered]@{
        name = "noncanonical-ledger-digest-file"
        expected_message = "is not in canonical form; regenerate it with validate.ps1 -WriteLedgerDigests"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "ledger-digests.sha256"
            $lines = [System.IO.File]::ReadAllText($path).Replace("`r`n", "`n").TrimEnd("`n").Split("`n")
            $comments = @($lines | Where-Object { $_.StartsWith("#", [System.StringComparison]::Ordinal) })
            [string[]]$entries = @(
                $lines | Where-Object { -not $_.StartsWith("#", [System.StringComparison]::Ordinal) }
            )
            [Array]::Sort($entries, [StringComparer]::Ordinal)
            [Array]::Reverse($entries)
            $reordered = $comments + $entries
            [System.IO.File]::WriteAllText($path, (($reordered -join "`n") + "`n"),
                (New-Object System.Text.UTF8Encoding($false)))
        }
    },
    [ordered]@{
        name = "missing-ledger-digest-file"
        expected_message = "missing=[ledger-digests.sha256]"
        mutate = {
            param($caseRoot)
            Remove-Item -LiteralPath (Join-Path $caseRoot "ledger-digests.sha256") -Force
        }
    },
    # --- Cross-platform determinism -------------------------------------------
    # These three pin the defect that made a byte-identical validate.ps1 pass
    # under Windows PowerShell 5.1 and fail under PowerShell Core on Linux.
    [ordered]@{
        # .gitattributes is frozen and has no rule for *.sha256, so this file
        # checks out CRLF on Windows and LF on Linux. Reading it must not care.
        name = "ledger-digest-file-with-crlf-line-endings"
        expect_success = $true
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "ledger-digests.sha256"
            $text = [System.IO.File]::ReadAllText($path).Replace("`r`n", "`n").Replace("`n", "`r`n")
            [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
        }
    },
    [ordered]@{
        # Every digest is structural, taken over parsed JSON re-encoded
        # canonically, so no digest may depend on how git checked the file out.
        # Rewriting every digest-bearing class of file with CRLF must still pass.
        name = "contract-digests-ignore-crlf-checkout"
        expect_success = $true
        mutate = {
            param($caseRoot)
            $encoding = New-Object System.Text.UTF8Encoding($false)
            $targets = @(
                "ledgers/gateway-core.json",
                "ledgers/official-integration.json",
                "ledgers/official-client-interop.json",
                "inventories/clients.json",
                "feature-ledger.schema.json",
                "baseline.json",
                "manifest.json",
                # git checks these out with CRLF on Windows and LF on Linux. Their
                # digests are structural and every newline inside a case source is
                # a \n escape, so both checkouts must reach the same digest and
                # the same 120 oracle verdicts and 32 reachability verdicts.
                "enabled-test-oracle.json",
                "reachability-corpus.json"
            )
            foreach ($target in $targets) {
                $path = Join-Path $caseRoot $target
                $text = [System.IO.File]::ReadAllText($path).Replace("`r`n", "`n").Replace("`n", "`r`n")
                [System.IO.File]::WriteAllText($path, $text, $encoding)
            }
        }
    },
    [ordered]@{
        # Simulates the regression itself rather than the assertion about it: the
        # canonical encoder is downgraded to a culture-sensitive key sort, which
        # is what makes ICU on Linux and NLS on Windows disagree. The pinned
        # vectors must catch it before any contract file is read.
        name = "culture-sensitive-key-sort-is-rejected"
        expected_message = "host portability invariant violated (object members are ordered ordinally)"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "validate.ps1"
            $text = [System.IO.File]::ReadAllText($path)
            $original = '[Array]::Sort($names, [StringComparer]::Ordinal)'
            $downgraded = '[Array]::Sort($names, [StringComparer]::InvariantCulture)'
            if (-not $text.Contains($original)) {
                throw "culture-sensitive-key-sort-is-rejected could not find the ordinal key sort to downgrade."
            }
            $text = $text.Replace($original, $downgraded)
            [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
        }
    },
    [ordered]@{
        name = "changed-inventory-survives-digest-regeneration"
        expected_message = "inventories/clients.json canonical identity/source evidence fingerprint mismatch"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "inventories/clients.json"
            $inventory = Read-Json $path
            $inventory.items[0].source_path = "apps/fabricated/client.rs"
            Write-Json $path $inventory
        }
    },
    [ordered]@{
        name = "changed-schema-survives-digest-regeneration"
        expected_message = "feature ledger schema is not the frozen Draft 2020-12 contract"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "feature-ledger.schema.json"
            $schema = Read-Json $path
            $schema.'$defs'.feature_status.enum = @("unimplemented", "partial", "implemented", "not_applicable")
            Write-Json $path $schema
        }
    },
    [ordered]@{
        name = "changed-baseline-survives-digest-regeneration"
        expected_message = "baseline upstream provenance mismatch"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "baseline.json"
            $baseline = Read-Json $path
            $baseline.upstream.commit_sha = "0000000000000000000000000000000000000000"
            Write-Json $path $baseline
        }
    },
    [ordered]@{
        name = "fixed-topology"
        expected_message = "fixed artifact topology mismatch"
        mutate = {
            param($caseRoot)
            Remove-Item -LiteralPath (Join-Path $caseRoot "ledgers/gateway-core.json") -Force
        }
    },
    [ordered]@{
        name = "smuggled-extra-artifact"
        expected_message = "fixed artifact topology mismatch"
        mutate = {
            param($caseRoot)
            Set-Content -LiteralPath (Join-Path $caseRoot "waiver.txt") -Value "parity approved" -Encoding UTF8
        }
    },
    [ordered]@{
        name = "manifest-bypass"
        expected_message = "manifest inventory declaration drift for inventories/skills.json"
        mutate = {
            param($caseRoot)
            $skillsPath = Join-Path $caseRoot "inventories/skills.json"
            $skills = Read-Json $skillsPath
            $skills.items = @($skills.items | Select-Object -First 50)
            $skills.counts.total = 50
            $skills.counts.bundled = 50
            Write-Json $skillsPath $skills

            $manifestPath = Join-Path $caseRoot "manifest.json"
            $manifest = Read-Json $manifestPath
            ($manifest.inventories | Where-Object {
                Test-OrdinalStringEqual ([string]$_.path) "inventories/skills.json"
            }).expected_items = 50
            $manifest.canonical_counts.bundled_skills = 50
            $manifest.canonical_counts.inventory_rows = 716
            Write-Json $manifestPath $manifest
        }
    },
    [ordered]@{
        name = "manifest-evidence-policy-downgrade"
        expected_message = "manifest evidence policy mismatch"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "manifest.json"
            $manifest = Read-Json $path
            $manifest.evidence_policy.legacy_typescript_is_not_rust_acceptance_evidence = $false
            Write-Json $path $manifest
        }
    },
    [ordered]@{
        name = "manifest-artifact-field-widening"
        expected_message = "manifest evidence lifecycle policy mismatch"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "manifest.json"
            $manifest = Read-Json $path
            $manifest.evidence_policy.artifact_fields = @("path", "test", "kind")
            Write-Json $path $manifest
        }
    },
    [ordered]@{
        name = "manifest-test-requirement-downgrade"
        expected_message = "manifest evidence lifecycle policy mismatch"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "manifest.json"
            $manifest = Read-Json $path
            $manifest.evidence_policy.every_artifact_names_an_enabled_rust_test = $false
            Write-Json $path $manifest
        }
    },
    [ordered]@{
        name = "manifest-pointer-promotion-to-evidence"
        expected_message = "manifest evidence lifecycle policy mismatch"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "manifest.json"
            $manifest = Read-Json $path
            $manifest.evidence_policy.implementation_pointers_are_not_acceptance_evidence = $false
            Write-Json $path $manifest
        }
    },
    [ordered]@{
        name = "manifest-ledger-path-ordinal"
        expected_message = "manifest must declare ledger ledgers/gateway-core.json exactly once"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "manifest.json"
            $manifest = Read-Json $path
            $manifest.ledgers[0].path = ([string]$manifest.ledgers[0].path) + [char]0x00AD
            Write-Json $path $manifest
        }
    },
    [ordered]@{
        name = "manifest-inventory-path-ordinal"
        expected_message = "manifest must declare inventory inventories/plugins.json exactly once"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "manifest.json"
            $manifest = Read-Json $path
            $manifest.inventories[0].path = ([string]$manifest.inventories[0].path) + [char]0x00AD
            Write-Json $path $manifest
        }
    },
    [ordered]@{
        name = "fixed-row-total"
        expected_message = "inventories/skills.json must contain exactly 51 rows"
        mutate = {
            param($caseRoot)
            $skillsPath = Join-Path $caseRoot "inventories/skills.json"
            $skills = Read-Json $skillsPath
            $skills.items = @($skills.items | Select-Object -First 50)
            $skills.counts.total = 50
            $skills.counts.bundled = 50
            Write-Json $skillsPath $skills
        }
    },
    [ordered]@{
        name = "declared-subtotal"
        expected_message = "inventories/plugins.json count 'total' must be '137'"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "inventories/plugins.json"
            $inventory = Read-Json $path
            $inventory.counts.total = 999
            Write-Json $path $inventory
        }
    },
    [ordered]@{
        name = "natural-identity"
        expected_message = "duplicate natural identity"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "inventories/providers.json"
            $inventory = Read-Json $path
            $inventory.items[1].id = $inventory.items[0].id
            Write-Json $path $inventory
        }
    },
    [ordered]@{
        name = "evidence-source-path-tamper"
        expected_message = "canonical identity/source"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "inventories/http-sse-endpoints.json"
            $inventory = Read-Json $path
            $inventory.items[0].source_path = "src/fabricated.ts"
            Write-Json $path $inventory
        }
    },
    [ordered]@{
        name = "evidence-path-boundary-regrouping"
        expected_message = "canonical feature/source evidence fingerprint mismatch"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $feature = @($ledger.features | Where-Object {
                @($_.upstream_source.paths).Count -gt 1
            } | Select-Object -First 1)[0]
            $feature.upstream_source.paths = @((@($feature.upstream_source.paths) -join ","))
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "evidence-valid-url-tamper"
        expected_message = "canonical feature/source evidence fingerprint mismatch"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].upstream_source |
                Add-Member -NotePropertyName "official_url" -NotePropertyValue "https://example.invalid/fabricated"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-required"
        expected_message = "missing required properties [domain]"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].PSObject.Properties.Remove("domain")
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-const"
        expected_message = "does not match its JSON Schema const"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.schema_version = 2
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-pattern"
        expected_message = "does not match JSON Schema pattern"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].feature_id = "INVALID ID"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-enum"
        expected_message = "is not in its JSON Schema enum"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].tier = "tier_9"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-additional-properties"
        expected_message = "contains JSON Schema additional properties [unexpected]"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0] | Add-Member -NotePropertyName "unexpected" -NotePropertyValue $true
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "artifact-additional-properties"
        expected_message = "contains JSON Schema additional properties [waiver]"
        mutate = {
            param($caseRoot)
            $artifact = New-Artifact $RealTestPath $RealTestName
            $artifact | Add-Member -NotePropertyName "waiver" -NotePropertyValue "approved"
            Set-ForgedTransition $caseRoot @($artifact)
        }
    },
    [ordered]@{
        name = "pointer-additional-properties"
        expected_message = "contains JSON Schema additional properties [test]"
        mutate = {
            param($caseRoot)
            $pointer = New-Pointer $RealSourcePath "Implementation."
            $pointer | Add-Member -NotePropertyName "test" -NotePropertyValue $RealTestName
            Set-ForgedTransition $caseRoot `
                -Artifacts @((New-Artifact $RealTestPath $RealTestName)) `
                -Pointers @($pointer)
        }
    },
    [ordered]@{
        name = "duplicated-implementation-pointer"
        expected_message = "violates JSON Schema uniqueItems"
        regenerate_digests = $true
        mutate = {
            param($caseRoot)
            Set-ForgedTransition $caseRoot `
                -Artifacts @((New-Artifact $RealTestPath $RealTestName)) `
                -Pointers @(
                    (New-Pointer $RealSourcePath "Implementation."),
                    (New-Pointer $RealSourcePath "Implementation.")
                )
        }
    },
    [ordered]@{
        name = "schema-property-name-casing"
        expected_message = "missing required properties [feature_id]"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $value = $ledger.features[0].feature_id
            $ledger.features[0].PSObject.Properties.Remove("feature_id")
            $ledger.features[0] | Add-Member -NotePropertyName "FEATURE_ID" -NotePropertyValue $value
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-title-key-casing"
        expected_message = "missing required properties [title]"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $value = $ledger.features[0].title
            $ledger.features[0].PSObject.Properties.Remove("title")
            $ledger.features[0] | Add-Member -NotePropertyName "Title" -NotePropertyValue $value
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-property-name-ordinal"
        expected_message = "missing required properties [title]"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $value = $ledger.features[0].title
            $ledger.features[0].PSObject.Properties.Remove("title")
            $ledger.features[0] |
                Add-Member -NotePropertyName ("title" + [char]0x00AD) -NotePropertyValue $value
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-pattern-casing"
        expected_message = "does not match JSON Schema pattern"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].feature_id = ([string]$ledger.features[0].feature_id).ToUpperInvariant()
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-enum-ordinal"
        expected_message = "is not in its JSON Schema enum"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].tier = "tier" + [char]0x00AD + "_1"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-unique-items"
        expected_message = "violates JSON Schema uniqueItems"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].upstream_source.paths = @("docs/gateway/protocol.md", "docs/gateway/protocol.md")
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-nested-required"
        expected_message = "missing required properties [paths]"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].upstream_source.PSObject.Properties.Remove("paths")
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-min-items"
        expected_message = "has fewer than JSON Schema minItems 1"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].known_differences = @()
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-min-length"
        expected_message = "is shorter than JSON Schema minLength 1"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].title = ""
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-format"
        expected_message = "is not an absolute URI"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].upstream_source |
                Add-Member -NotePropertyName "official_url" -NotePropertyValue "not a uri"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "schema-windows-path-is-not-uri"
        expected_message = "is not an absolute URI"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].upstream_source |
                Add-Member -NotePropertyName "official_url" -NotePropertyValue "C:\not-a-uri"
            Save-FirstLedger $caseRoot $ledger
        }
    },
    [ordered]@{
        name = "inventory-enum-casing"
        expected_message = "has invalid client kind"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "inventories/clients.json"
            $inventory = Read-Json $path
            $inventory.items[0].kind = ([string]$inventory.items[0].kind).ToUpperInvariant()
            Write-Json $path $inventory
        }
    },
    [ordered]@{
        name = "inventory-property-name-ordinal"
        expected_message = "contains unsupported fields [source_path"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "inventories/clients.json"
            $inventory = Read-Json $path
            $inventory.items[0] |
                Add-Member -NotePropertyName ("source_path" + [char]0x00AD) -NotePropertyValue "src/ordinal"
            Write-Json $path $inventory
        }
    },
    [ordered]@{
        name = "inventory-kind-dispatch-ordinal"
        expected_message = "gateway-protocol item has invalid kind"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "inventories/gateway-protocol.json"
            $inventory = Read-Json $path
            $item = @($inventory.items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.kind) "method"
            } | Select-Object -First 1)[0]
            $item.kind = ([string]$item.kind) + [char]0x00AD
            Write-Json $path $inventory
        }
    },
    [ordered]@{
        name = "provider-unique-count-ordinal"
        expected_message = "canonical identity/source evidence fingerprint mismatch"
        mutate = {
            param($caseRoot)
            $path = Join-Path $caseRoot "inventories/providers.json"
            $inventory = Read-Json $path
            $ordinalAlias = ([string]$inventory.items[0].id) + [char]0x00AD
            $inventory.items[1].id = $ordinalAlias
            $inventory.items[1].record_id = "provider:$ordinalAlias"
            Write-Json $path $inventory
        }
    },
    [ordered]@{
        name = "schema-type"
        expected_message = "$.features must have JSON Schema type array"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features = "not-an-array"
            Save-FirstLedger $caseRoot $ledger
        }
    }
)

$temporaryRoot = Join-Path $SelfTestWorkRoot (
    "gta-claw-upstream-validator-self-test-" + [Guid]::NewGuid().ToString("N")
)
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
$caseTemplateRoot = Join-Path $temporaryRoot "neutral-case-template"
New-Item -ItemType Directory -Path $caseTemplateRoot | Out-Null
Copy-Item -Path (Join-Path $SourceRoot "*") -Destination $caseTemplateRoot -Recurse -Force
Reset-MutableLedgerTransitions $caseTemplateRoot
$templateResult = Invoke-Validator $caseTemplateRoot -WriteLedgerDigests
if ($templateResult.exit_code -ne 0) {
    throw "validator self-test neutral template failed: $($templateResult.output)"
}

$passed = New-Object System.Collections.Generic.List[string]
$failures = New-Object System.Collections.Generic.List[string]
$negativeCases = 0
$positiveCases = 1
try {
    foreach ($case in $cases) {
        # Re-checked every iteration: a fixture that evaporates part-way through
        # would otherwise turn every remaining case into a confusing precondition
        # error that looks like a rule regression.
        Assert-SelfTestFixtureIntact ("case '" + $case.name + "'")
        if (-not (Test-Path -LiteralPath $temporaryRoot)) {
            throw (("validator self-test work root '{0}' disappeared before case " +
                "'{1}'. This is an ENVIRONMENT failure, not a validator " +
                "regression; see the fixture-integrity note above.") -f
                $temporaryRoot, $case.name)
        }
        $caseRoot = Join-Path $temporaryRoot $case.name
        New-Item -ItemType Directory -Path $caseRoot | Out-Null
        Copy-Item -Path (Join-Path $caseTemplateRoot "*") -Destination $caseRoot -Recurse -Force
        & $case.mutate $caseRoot
        $caseRepositoryRoot = ""
        if ($case.Contains("repository_root")) {
            $caseRepositoryRoot = [string]$case.repository_root
        }
        if ($case.Contains("regenerate_digests") -and $case.regenerate_digests) {
            # Model an attacker who already re-blessed the mutable ledger digests.
            Invoke-Validator $caseRoot -RepositoryRootOverride $caseRepositoryRoot -WriteLedgerDigests | Out-Null
        }

        $result = Invoke-Validator $caseRoot -RepositoryRootOverride $caseRepositoryRoot
        # Every case is evaluated even after one fails, so a single regression
        # cannot hide the status of the cases behind it.
        $failure = ""
        if ($case.Contains("expect_success") -and $case.expect_success) {
            $positiveCases += 1
            if ($result.exit_code -ne 0) {
                $failure = "positive case unexpectedly failed: $($result.output)"
            }
        } else {
            $negativeCases += 1
            if ($result.exit_code -eq 0) {
                $failure = "negative tamper case unexpectedly passed"
            } else {
                $normalizedOutput = [regex]::Replace($result.output, "\s+", " ")
                $normalizedExpected = [regex]::Replace([string]$case.expected_message, "\s+", " ")
                if ($normalizedOutput.IndexOf($normalizedExpected, [StringComparison]::Ordinal) -lt 0) {
                    $failure = ("failed for the wrong reason; expected '{0}' in: {1}" -f
                        $normalizedExpected, $normalizedOutput)
                }
            }
        }
        if ($failure.Length -eq 0) {
            $passed.Add([string]$case.name)
            [Console]::Error.WriteLine("  ok   $($case.name)")
        } else {
            $failures.Add(("{0}: {1}" -f $case.name, $failure))
            [Console]::Error.WriteLine("  FAIL $($case.name)")
        }
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $SyntheticRoot) {
        Remove-Item -LiteralPath $SyntheticRoot -Recurse -Force
    }
}

if ($failures.Count -gt 0) {
    throw ("validator self-test: {0} of {1} cases failed:{2}{3}" -f
        $failures.Count, $cases.Count, [Environment]::NewLine, ($failures -join [Environment]::NewLine))
}

[ordered]@{
    status = "ok"
    positive_baseline = $true
    positive_cases = $positiveCases
    negative_cases = $negativeCases
    cases = @($passed)
} | ConvertTo-Json -Depth 4
