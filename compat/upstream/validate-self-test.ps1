[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$SourceRoot = $PSScriptRoot
$PowerShellExecutable = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

function Read-Json {
    param([string]$Path)
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Write-Json {
    param(
        [string]$Path,
        [object]$Value
    )
    $Value | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Invoke-Validator {
    param([string]$CaseRoot)
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(
            & $PowerShellExecutable `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File (Join-Path $CaseRoot "validate.ps1") 2>&1
        )
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [pscustomobject]@{
        exit_code = $exitCode
        output = ($output | Out-String)
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

$validResult = Invoke-Validator $SourceRoot
if ($validResult.exit_code -ne 0) {
    throw "validator self-test baseline failed: $($validResult.output)"
}

$cases = @(
    [ordered]@{
        name = "fixed-topology"
        expected_message = "fixed JSON topology mismatch"
        mutate = {
            param($caseRoot)
            Remove-Item -LiteralPath (Join-Path $caseRoot "ledgers/gateway-core.json") -Force
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
            ($manifest.inventories | Where-Object { $_.path -eq "inventories/skills.json" }).expected_items = 50
            $manifest.canonical_counts.bundled_skills = 50
            $manifest.canonical_counts.inventory_rows = 716
            Write-Json $manifestPath $manifest
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
        name = "fixed-ledger-row-total"
        expected_message = "ledgers/gateway-core.json must contain exactly 16 features"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features = @($ledger.features | Select-Object -First 15)
            Save-FirstLedger $caseRoot $ledger
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
        name = "source-evidence"
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
        name = "acceptance-evidence"
        expected_message = "must start unimplemented with an empty evidence placeholder"
        mutate = {
            param($caseRoot)
            $ledger = Get-FirstLedger $caseRoot
            $ledger.features[0].acceptance_evidence.artifacts = @("unverified-result.txt")
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
try {
    foreach ($case in $cases) {
        $caseRoot = Join-Path $temporaryRoot $case.name
        New-Item -ItemType Directory -Path $caseRoot | Out-Null
        Copy-Item -Path (Join-Path $SourceRoot "*") -Destination $caseRoot -Recurse -Force
        & $case.mutate $caseRoot

        $result = Invoke-Validator $caseRoot
        if ($result.exit_code -eq 0) {
            throw "negative tamper case '$($case.name)' unexpectedly passed"
        }
        $normalizedOutput = [regex]::Replace($result.output, "\s+", " ")
        $normalizedExpected = [regex]::Replace([string]$case.expected_message, "\s+", " ")
        if (-not $normalizedOutput.Contains($normalizedExpected)) {
            throw "negative tamper case '$($case.name)' failed for the wrong reason: $($result.output)"
        }
        $passed.Add([string]$case.name)
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

[ordered]@{
    status = "ok"
    positive_baseline = $true
    negative_cases = $passed.Count
    cases = @($passed)
} | ConvertTo-Json -Depth 4
