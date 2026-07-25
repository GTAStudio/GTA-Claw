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
$SyntheticRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "gta-claw-upstream-validator-synthetic-" + [Guid]::NewGuid().ToString("N")
)
$SyntheticTestName = "parity_is_proven_here"

function New-SyntheticRepositoryRoot {
    param([string]$Root)
    $files = [ordered]@{
        "Cargo.toml" = "[workspace]`nmembers = [`"crates/synthetic`"]`n"
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
        "crates/synthetic/data/fixture.json" = "{}`n"
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
    },
    [ordered]@{
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
        expected_message = "contains no Rust test attribute"
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
                "manifest.json"
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

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "gta-claw-upstream-validator-self-test-" + [Guid]::NewGuid().ToString("N")
)
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

$passed = New-Object System.Collections.Generic.List[string]
$failures = New-Object System.Collections.Generic.List[string]
$negativeCases = 0
$positiveCases = 1
try {
    foreach ($case in $cases) {
        $caseRoot = Join-Path $temporaryRoot $case.name
        New-Item -ItemType Directory -Path $caseRoot | Out-Null
        Copy-Item -Path (Join-Path $SourceRoot "*") -Destination $caseRoot -Recurse -Force
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
