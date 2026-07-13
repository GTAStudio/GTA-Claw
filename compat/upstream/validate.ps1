[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$ExpectedSha = "b43e832fcc8000ed7287c7accc54e381db607f85"
$AllowedClassifications = @(
    "gateway_core",
    "official_integration",
    "official_client_interop"
)
$AllowedTiers = @("tier_1", "tier_2", "tier_3")
$AllowedProfiles = @("core_gateway", "client_interop", "platform_integration")
$AllowedStatuses = @("unimplemented", "partial", "implemented", "blocked", "not_applicable")
$RequiredFeatureFields = @(
    "feature_id",
    "title",
    "domain",
    "tier",
    "profile",
    "classification",
    "upstream_source",
    "status",
    "acceptance_evidence",
    "last_verified_sha",
    "known_differences"
)

function Fail {
    param([string]$Message)
    throw "compat/upstream validation failed: $Message"
}

function Read-Json {
    param([string]$Path)
    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        Fail "invalid JSON in $Path`: $($_.Exception.Message)"
    }
}

$jsonFiles = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter "*.json" | Sort-Object FullName)
if ($jsonFiles.Count -eq 0) {
    Fail "no JSON artifacts found"
}
foreach ($jsonFile in $jsonFiles) {
    $null = Read-Json $jsonFile.FullName
}

$baseline = Read-Json (Join-Path $Root "baseline.json")
if ($baseline.upstream.commit_sha -ne $ExpectedSha) {
    Fail "baseline SHA must be $ExpectedSha"
}
if ($baseline.upstream.package_version -ne "2026.7.2") {
    Fail "package version must be 2026.7.2"
}
if ($baseline.stable_release.tag -ne "v2026.6.11") {
    Fail "stable release must be v2026.6.11"
}
if ($baseline.gateway_protocol.current -ne 4 -or
    $baseline.gateway_protocol.minimum_general_client -ne 4 -or
    $baseline.gateway_protocol.minimum_authenticated_node -ne 3 -or
    $baseline.gateway_protocol.minimum_probe -ne 3) {
    Fail "Gateway protocol levels must be current=4, general=4, node=3, probe=3"
}

$schema = Read-Json (Join-Path $Root "feature-ledger.schema.json")
$schemaFeatureRequired = @($schema.'$defs'.feature.required)
foreach ($field in $RequiredFeatureFields) {
    if ($schemaFeatureRequired -notcontains $field) {
        Fail "feature schema does not require $field"
    }
}

$manifest = Read-Json (Join-Path $Root "manifest.json")
if ($manifest.baseline_sha -ne $ExpectedSha) {
    Fail "manifest baseline SHA mismatch"
}

$featureIds = New-Object System.Collections.Generic.HashSet[string]
$featureCount = 0
$missingEvidenceCount = 0
foreach ($ledgerEntry in $manifest.ledgers) {
    $ledgerPath = Join-Path $Root ([string]$ledgerEntry.path)
    if (-not (Test-Path -LiteralPath $ledgerPath -PathType Leaf)) {
        Fail "missing ledger $($ledgerEntry.path)"
    }
    $ledger = Read-Json $ledgerPath
    if ($ledger.baseline_sha -ne $ExpectedSha) {
        Fail "$($ledgerEntry.path) baseline SHA mismatch"
    }
    if ($AllowedClassifications -notcontains [string]$ledger.classification) {
        Fail "$($ledgerEntry.path) has unclassified ledger"
    }
    if ([string]$ledger.classification -ne [string]$ledgerEntry.classification) {
        Fail "$($ledgerEntry.path) manifest classification mismatch"
    }
    if (@($ledger.features).Count -ne [int]$ledgerEntry.expected_features) {
        Fail "$($ledgerEntry.path) feature count mismatch"
    }

    foreach ($feature in $ledger.features) {
        $featureCount += 1
        foreach ($field in $RequiredFeatureFields) {
            if ($feature.PSObject.Properties.Name -notcontains $field) {
                Fail "$($ledgerEntry.path) feature is missing $field"
            }
        }
        if (-not $featureIds.Add([string]$feature.feature_id)) {
            Fail "duplicate feature_id $($feature.feature_id)"
        }
        if ($AllowedClassifications -notcontains [string]$feature.classification) {
            Fail "$($feature.feature_id) is unclassified"
        }
        if ($AllowedTiers -notcontains [string]$feature.tier) {
            Fail "$($feature.feature_id) has invalid tier $($feature.tier)"
        }
        if ($AllowedProfiles -notcontains [string]$feature.profile) {
            Fail "$($feature.feature_id) has invalid profile $($feature.profile)"
        }
        if ($AllowedStatuses -notcontains [string]$feature.status) {
            Fail "$($feature.feature_id) has invalid status $($feature.status)"
        }
        if ($manifest.evidence_policy.initial_status -eq "unimplemented" -and
            [string]$feature.status -ne "unimplemented") {
            Fail "$($feature.feature_id) must start unimplemented until Rust acceptance evidence exists"
        }
        if ([string]$feature.classification -ne [string]$ledger.classification) {
            Fail "$($feature.feature_id) classification does not match its ledger"
        }
        if ([string]$feature.last_verified_sha -ne $ExpectedSha) {
            Fail "$($feature.feature_id) last_verified_sha mismatch"
        }
        if ([string]::IsNullOrWhiteSpace([string]$feature.feature_id) -or
            [string]::IsNullOrWhiteSpace([string]$feature.domain) -or
            [string]::IsNullOrWhiteSpace([string]$feature.tier) -or
            [string]::IsNullOrWhiteSpace([string]$feature.profile)) {
            Fail "$($feature.feature_id) has an empty required classification field"
        }
        if (@($feature.upstream_source.paths).Count -eq 0) {
            Fail "$($feature.feature_id) has no upstream source path"
        }
        if (@($feature.known_differences).Count -eq 0) {
            Fail "$($feature.feature_id) has no known-differences entry"
        }
        if ([string]::IsNullOrWhiteSpace([string]$feature.acceptance_evidence.required)) {
            Fail "$($feature.feature_id) has no acceptance-evidence requirement"
        }
        if ($feature.acceptance_evidence.status -eq "missing") {
            $missingEvidenceCount += 1
            if (@($feature.acceptance_evidence.artifacts).Count -ne 0) {
                Fail "$($feature.feature_id) missing evidence must use an empty artifact placeholder"
            }
        } elseif ($manifest.evidence_policy.acceptance_evidence_state -eq "missing") {
            Fail "$($feature.feature_id) must start with a missing evidence placeholder"
        }
    }
}

$recordIds = New-Object System.Collections.Generic.HashSet[string]
$inventoryCounts = @{}
foreach ($inventoryEntry in $manifest.inventories) {
    $inventoryPath = Join-Path $Root ([string]$inventoryEntry.path)
    if (-not (Test-Path -LiteralPath $inventoryPath -PathType Leaf)) {
        Fail "missing inventory $($inventoryEntry.path)"
    }
    $inventory = Read-Json $inventoryPath
    if ($inventory.baseline_sha -ne $ExpectedSha) {
        Fail "$($inventoryEntry.path) baseline SHA mismatch"
    }
    $items = @($inventory.items)
    if ($items.Count -ne [int]$inventoryEntry.expected_items) {
        Fail "$($inventoryEntry.path) item count mismatch"
    }
    $inventoryCounts[[string]$inventory.inventory_id] = $items.Count
    foreach ($item in $items) {
        if ([string]::IsNullOrWhiteSpace([string]$item.record_id) -or
            [string]::IsNullOrWhiteSpace([string]$item.id) -or
            [string]::IsNullOrWhiteSpace([string]$item.source_path)) {
            Fail "$($inventoryEntry.path) contains an item with missing id or source"
        }
        if (-not $recordIds.Add([string]$item.record_id)) {
            Fail "duplicate inventory record_id $($item.record_id)"
        }
        if ($AllowedClassifications -notcontains [string]$item.classification) {
            Fail "$($item.record_id) is unclassified"
        }
    }
}

$plugins = Read-Json (Join-Path $Root "inventories/plugins.json")
$pluginItems = @($plugins.items)
$corePlugins = @($pluginItems | Where-Object { $_.delivery_class -eq "core" }).Count
$externalPlugins = @($pluginItems | Where-Object { $_.delivery_class -eq "official_external" }).Count
$qaPlugins = @($pluginItems | Where-Object { $_.delivery_class -eq "source_only_qa" }).Count
$skills = Read-Json (Join-Path $Root "inventories/skills.json")
$protocol = Read-Json (Join-Path $Root "inventories/gateway-protocol.json")

if ($corePlugins -ne 64) {
    Fail "canonical core plugin count must be 64, got $corePlugins"
}
if ($externalPlugins -ne 70) {
    Fail "canonical official external plugin count must be 70, got $externalPlugins"
}
if ($qaPlugins -ne 3) {
    Fail "canonical source-only QA plugin count must be 3, got $qaPlugins"
}
if (@($skills.items).Count -ne 51) {
    Fail "canonical bundled skill count must be 51, got $(@($skills.items).Count)"
}
if ([int]$protocol.counts.methods -ne 278 -or [int]$protocol.counts.events -ne 33) {
    Fail "Gateway protocol inventory must contain 278 methods and 33 events"
}
if ([int]$inventoryCounts["config-domains"] -ne 47) {
    Fail "top-level configuration domain count must be 47"
}
if ([int]$inventoryCounts["providers"] -ne 78) {
    Fail "provider count must be 78"
}
if ([int]$inventoryCounts["channels"] -ne 29) {
    Fail "channel count must be 29"
}

$summary = [ordered]@{
    status = "ok"
    baseline_sha = $ExpectedSha
    json_files = $jsonFiles.Count
    ledgers = @($manifest.ledgers).Count
    feature_rows = $featureCount
    missing_acceptance_evidence = $missingEvidenceCount
    inventory_rows = $recordIds.Count
    canonical_counts = [ordered]@{
        core_plugins = $corePlugins
        official_external_plugins = $externalPlugins
        source_only_qa_plugins = $qaPlugins
        bundled_skills = @($skills.items).Count
        gateway_methods = [int]$protocol.counts.methods
        gateway_events = [int]$protocol.counts.events
        config_domains = [int]$inventoryCounts["config-domains"]
        providers = [int]$inventoryCounts["providers"]
        channels = [int]$inventoryCounts["channels"]
    }
}

$summary | ConvertTo-Json -Depth 6
