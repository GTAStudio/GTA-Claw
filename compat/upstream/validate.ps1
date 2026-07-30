<#
.SYNOPSIS
    Validates the frozen OpenClaw upstream compatibility contract under compat/upstream.

.DESCRIPTION
    Enforces the frozen baseline (upstream provenance, inventories, canonical counts)
    and the audited feature-ledger lifecycle. A feature row may be unimplemented,
    partial or implemented; anything other than unimplemented must cite typed
    acceptance evidence whose paths exist in the working tree and whose named test,
    symbol or job actually appears inside the cited file.

.PARAMETER WriteLedgerDigests
    Runs every check except the stored ledger digest comparison, then rewrites
    compat/upstream/ledger-digests.sha256 from the current ledgers and prints the
    digests for review. This is the ONLY supported way to change ledger digests.
    It never touches inventory digests, the schema digest or baseline.json.

.PARAMETER WriteStatusTotals
    Declares the lifecycle totals in the form
    "unimplemented=<n>,partial=<n>,implemented=<n>". This switch is accepted only
    with -WriteLedgerDigests. The declaration must already match the ledger rows,
    and both reviewed files are written only after every validation rule passes.

.PARAMETER ReplayEvidenceSweep
    Re-runs the shipped reachability rule over every tracked .rs file, rewrites
    compat/upstream/evidence-reachability-sweep.tsv, and prints the new digest and
    the differential from the previous record. This writer is mutually exclusive
    with the ledger transition writer.

.PARAMETER RepositoryRoot
    Repository working tree used to resolve acceptance-evidence paths. Defaults to
    the parent of compat/. The validator self-test passes the real tree explicitly
    because it runs mutated copies of this contract from a temporary directory.

.EXAMPLE
    powershell -NoProfile -File compat/upstream/validate.ps1

.EXAMPLE
    powershell -NoProfile -File compat/upstream/validate.ps1 -WriteLedgerDigests

.EXAMPLE
    powershell -NoProfile -File compat/upstream/validate.ps1 `
        -WriteLedgerDigests -WriteStatusTotals "unimplemented=3,partial=10,implemented=34"

.EXAMPLE
    powershell -NoProfile -File compat/upstream/validate.ps1 -ReplayEvidenceSweep
#>
[CmdletBinding()]
param(
    [switch]$WriteLedgerDigests,
    [string]$WriteStatusTotals,
    [switch]$ReplayEvidenceSweep,
    [string]$RepositoryRoot
)

$ErrorActionPreference = "Stop"
$WriteStatusTotalsRequested = -not [string]::IsNullOrWhiteSpace($WriteStatusTotals)
if ($WriteStatusTotalsRequested -and -not $WriteLedgerDigests) {
    throw "-WriteStatusTotals requires -WriteLedgerDigests so ledger digests and manifest totals move in one reviewed command"
}
if ($ReplayEvidenceSweep -and ($WriteLedgerDigests -or $WriteStatusTotalsRequested)) {
    throw ("validator writer modes are mutually exclusive and are rejected before any artifact write; " +
        "select either -ReplayEvidenceSweep or the ledger transition writer")
}
$WriterModeRequested = $WriteLedgerDigests -or $WriteStatusTotalsRequested -or $ReplayEvidenceSweep
if ($WriterModeRequested) {
    foreach ($name in @("CI", "GITHUB_ACTIONS", "TF_BUILD", "BUILDKITE")) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($value) -and
            -not [string]::Equals($value, "false", [StringComparison]::OrdinalIgnoreCase) -and
            -not [string]::Equals($value, "no", [StringComparison]::OrdinalIgnoreCase) -and
            -not [string]::Equals($value, "0", [StringComparison]::Ordinal)) {
            throw "validator writer modes are forbidden in CI; '$name' is set"
        }
    }
}

$Root = $PSScriptRoot
$ExpectedSha = "b43e832fcc8000ed7287c7accc54e381db607f85"
$ExpectedSchemaDigest = "5fd454c7a1012e78410178bc44c02dc3201f46eed94d62c5dc811f441e8de396"

# Frozen like the inventories and the schema: the shared enabled-test corpus is a
# contract artifact, NOT a regenerable one. -WriteLedgerDigests cannot reach this
# constant, so weakening a case to let a forged citation through requires a
# reviewed edit to this script.
$ExpectedOracleCorpusDigest = "e8853b665f2d09e2d526dee5349b56223b249817df5872e408fc7a5d0b182c25"
$ExpectedOracleCorpusCases = 120
$ExpectedOracleCorpusTrue = 46
# The shared reachability corpus is frozen on exactly the same terms. Its
# expectations were produced by running cargo and rustc against each fixture, so
# cargo and rustc arbitrate reachability and neither resolver may edit a case to
# match itself. No writer mode can reach these constants.
$ExpectedReachabilityCorpusDigest = "70aec3e02f3885970ec37d61421fdc34ea932e591842d6a1669adf0e1f4880dd"
$ExpectedReachabilityCorpusCases = 32
$ExpectedReachabilityCorpusAccepting = 15
# The anti-forgery self-test is a trust-root artifact, not a convenience script.
# Nothing in CI executes it today, and validate.ps1 previously only checked that
# the file EXISTED: replacing all 113,996 bytes with "exit 0" left both this
# script and the gutted self-test exiting 0, so the instrument that proves every
# rejection rule still bites could be removed without any check noticing.
#
# The digest is taken over LF-normalised text on purpose. *.ps1 is NOT covered by
# .gitattributes and core.autocrlf rewrites these bytes per platform, so a raw
# byte digest would pass on a Windows checkout and fail under pwsh on Linux CI.
# Frozen exactly like the schema and corpus digests: -WriteLedgerDigests cannot
# reach this constant, so re-blessing a hollowed-out self-test takes a reviewed
# edit to this line.
$ExpectedSelfTestDigest = "20b26f2e52009b44d90d2c83a9d392248b3495d5e4b7a1dd3d673073a4d76add"
# README.md is the normative specification for these rules. Pinning its
# LF-normalised text makes a prose change a reviewed trust-root edit instead of a
# silent change to the instructions future rule owners follow.
$ExpectedReadmeDigest = "f9f5926890bb080fecea8ee616cdb7eaca9dd8cd00dcfead9e5865a4c2990dcc"
$LedgerDigestFileName = "ledger-digests.sha256"
$EvidenceSweepFileName = "evidence-reachability-sweep.tsv"
$EvidenceSweepExpectedFiles = 0
$EvidenceSweepExpectedAccepted = 0
$EvidenceSweepExpectedRejected = 0
$EvidenceSweepPreamble = @(
    "# GTA-Claw acceptance-evidence reachability sweep.",
    "# Every tracked .rs file, judged by the reachability rule shipped in validate.ps1.",
    "# This is a cross-check record only: it grants no evidence permission.",
    "# Regenerate ONLY through the reviewed command, never by hand:",
    "#   powershell -NoProfile -File compat/upstream/validate.ps1 -ReplayEvidenceSweep"
)
$EvidenceSweepGeneratedByLine = "# generated-by: validate.ps1 -ReplayEvidenceSweep"
$ExpectedEvidenceSweepDigest = "0000000000000000000000000000000000000000000000000000000000000000"
$LedgerDigestHeader = @(
    "# GTA-Claw frozen upstream compatibility ledger digests.",
    "# Only the three mutable ledgers are covered here; inventory digests, the feature",
    "# schema digest and baseline.json stay hardcoded in validate.ps1 and are frozen.",
    "# Regenerate ONLY through the reviewed command, never by hand:",
    "#   powershell -NoProfile -File compat/upstream/validate.ps1 -WriteLedgerDigests",
    "# Format: <sha256>  <ledger path>"
)
$AllowedFeatureStatuses = @("unimplemented", "partial", "implemented")
$BaselineKnownDifference =
    "No npm-free Rust implementation or acceptance evidence exists in this repository at this baseline."
$ArtifactFields = @("path", "test")
$LegacyScriptExtensions = @(".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
$LegacyPathPrefixes = @(
    "src/",
    "compat/legacy/",
    "node_modules/",
    "_upstream/",
    "packages/"
)
$SelfReferentialPathPrefixes = @("compat/upstream/")
$AllowedClassifications = @(
    "gateway_core",
    "official_integration",
    "official_client_interop"
)
$AllowedOperatorScopes = @(
    "dynamic",
    "node",
    "operator.admin",
    "operator.approvals",
    "operator.pairing",
    "operator.read",
    "operator.talk.secrets",
    "operator.write"
)

$ExpectedJsonPaths = @(
    "baseline.json",
    "enabled-test-oracle.json",
    "feature-ledger.schema.json",
    "manifest.json",
    "reachability-corpus.json",
    "inventories/channels.json",
    "inventories/clients.json",
    "inventories/config-domains.json",
    "inventories/gateway-protocol.json",
    "inventories/http-sse-endpoints.json",
    "inventories/migrations.json",
    "inventories/plugins.json",
    "inventories/providers.json",
    "inventories/release-deployment.json",
    "inventories/skills.json",
    "ledgers/gateway-core.json",
    "ledgers/official-client-interop.json",
    "ledgers/official-integration.json"
)

$ExpectedNonJsonPaths = @(
    "README.md",
    "evidence-reachability-sweep.tsv",
    "ledger-digests.sha256",
    "validate-self-test.ps1",
    "validate.ps1"
)

$LedgerSpecs = @(
    [ordered]@{
        path = "ledgers/gateway-core.json"
        ledger_id = "gateway-core"
        classification = "gateway_core"
        expected_features = 16
        frozen_digest = "1ed1326f8f0d1ed97e417e01ec2f9942222cb79376297c23f7eb14c4d7924c29"
    },
    [ordered]@{
        path = "ledgers/official-integration.json"
        ledger_id = "official-integration"
        classification = "official_integration"
        expected_features = 13
        frozen_digest = "0ccabe72545c332c52120c569059a6bee9fd737f3cdc2c496445c91e7fd9308f"
    },
    [ordered]@{
        path = "ledgers/official-client-interop.json"
        ledger_id = "official-client-interop"
        classification = "official_client_interop"
        expected_features = 18
        frozen_digest = "9d6886795df7d7c4fa327a679ec9f925dc16065cb30df4e35e1d44617607dbe8"
    }
)

$InventorySpecs = [ordered]@{
    "plugins" = [ordered]@{
        path = "inventories/plugins.json"
        classification = "official_integration"
        expected_items = 137
        natural_key_fields = @("delivery_class", "id")
        required_fields = @("record_id", "id", "classification", "source_path", "package_name", "delivery_class")
        allowed_fields = @("record_id", "id", "classification", "source_path", "package_name", "delivery_class")
        canonical_fields = @("record_id", "id", "classification", "source_path", "package_name", "delivery_class")
        digest = "abc4d4b787fedf403b3e4c0b32b6a79fc275eeb0f17c805052111581602f9cf4"
    }
    "skills" = [ordered]@{
        path = "inventories/skills.json"
        classification = "official_integration"
        expected_items = 51
        natural_key_fields = @("id")
        required_fields = @("record_id", "id", "classification", "source_path", "license")
        allowed_fields = @("record_id", "id", "classification", "source_path", "license")
        canonical_fields = @("record_id", "id", "classification", "source_path", "license")
        digest = "32190e03ec446183457fba09857b0bb744b70ad46963ccbbed8ac434aad3c3cb"
    }
    "gateway-protocol" = [ordered]@{
        path = "inventories/gateway-protocol.json"
        classification = "gateway_core"
        expected_items = 320
        natural_key_fields = @("kind", "id")
        required_fields = @("record_id", "id", "classification", "source_path", "kind")
        allowed_fields = @("record_id", "id", "classification", "source_path", "kind", "scope", "advertised", "protocol_class")
        canonical_fields = @("record_id", "id", "classification", "source_path", "kind", "scope", "advertised", "protocol_class")
        digest = "69c16fe2d025241e21e6c1dd1a92c7586af5cbcb26f02771b3a16b5f09cff9c9"
    }
    "config-domains" = [ordered]@{
        path = "inventories/config-domains.json"
        classification = "gateway_core"
        expected_items = 47
        natural_key_fields = @("id")
        required_fields = @("record_id", "id", "classification", "source_path")
        allowed_fields = @("record_id", "id", "classification", "source_path")
        canonical_fields = @("record_id", "id", "classification", "source_path")
        digest = "eaf225655042192ca83f83a4b6f61e88de1ad2e06a4c3121bfc4ef3b07b4001b"
    }
    "providers" = [ordered]@{
        path = "inventories/providers.json"
        classification = "official_integration"
        expected_items = 78
        natural_key_fields = @("id")
        required_fields = @("record_id", "id", "classification", "source_path", "plugin_id")
        allowed_fields = @("record_id", "id", "classification", "source_path", "plugin_id")
        canonical_fields = @("record_id", "id", "classification", "source_path", "plugin_id")
        digest = "97101869f0fbb0e73e78812f50f40876cf02fd1e1c3590a04a64f42dcce8eaec"
    }
    "channels" = [ordered]@{
        path = "inventories/channels.json"
        classification = "official_integration"
        expected_items = 29
        natural_key_fields = @("id")
        required_fields = @("record_id", "id", "classification", "source_path", "provenance")
        allowed_fields = @("record_id", "id", "classification", "source_path", "plugin_id", "package_name", "catalog_package", "catalog_source_path", "provenance")
        canonical_fields = @("record_id", "id", "classification", "source_path", "plugin_id", "package_name", "catalog_package", "catalog_source_path", "provenance")
        digest = "9004c28b17a1b5bcd4bb274078c50fa5c5890bf9d0f550c32f2462f3e8e19d50"
    }
    "http-sse-endpoints" = [ordered]@{
        path = "inventories/http-sse-endpoints.json"
        classification = "mixed"
        expected_items = 18
        natural_key_fields = @("method", "path")
        required_fields = @("record_id", "id", "classification", "source_path", "method", "path", "streaming")
        allowed_fields = @("record_id", "id", "classification", "source_path", "method", "path", "streaming")
        canonical_fields = @("record_id", "id", "classification", "source_path", "method", "path", "streaming")
        digest = "b58c884627ef580c0b1f41d861711daf122c990f7926303c46e680a7463b2f16"
    }
    "clients" = [ordered]@{
        path = "inventories/clients.json"
        classification = "official_client_interop"
        expected_items = 10
        natural_key_fields = @("kind", "id")
        required_fields = @("record_id", "id", "classification", "source_path", "kind")
        allowed_fields = @("record_id", "id", "classification", "source_path", "kind")
        canonical_fields = @("record_id", "id", "classification", "source_path", "kind")
        digest = "251782ee9aaac756595287a76c689af611a082123f6deb66160c2d8e776e98f1"
    }
    "migrations" = [ordered]@{
        path = "inventories/migrations.json"
        classification = "official_client_interop"
        expected_items = 3
        natural_key_fields = @("kind", "id")
        required_fields = @("record_id", "id", "classification", "source_path", "package_path", "kind")
        allowed_fields = @("record_id", "id", "classification", "source_path", "package_path", "kind")
        canonical_fields = @("record_id", "id", "classification", "source_path", "package_path", "kind")
        digest = "8a8da66bc4d3d6d6e728b8e5b052358ee4c4c0c99093d3f8244712ae86b4d2fb"
    }
    "release-deployment" = [ordered]@{
        path = "inventories/release-deployment.json"
        classification = "official_integration"
        expected_items = 24
        natural_key_fields = @("kind", "id")
        required_fields = @("record_id", "id", "classification", "source_path", "kind")
        allowed_fields = @("record_id", "id", "classification", "source_path", "kind")
        canonical_fields = @("record_id", "id", "classification", "source_path", "kind")
        digest = "b65ed03dd4e285593855043a5adb0ed79b5fdc6854cb464f339a5ee3799ae945"
    }
}

$ExpectedCanonicalCounts = [ordered]@{
    artifact_json_files = 18
    ledgers = 3
    feature_rows = 47
    inventory_files = 10
    inventory_rows = 717
    core_plugins = 64
    official_external_plugins = 70
    source_only_qa_plugins = 3
    bundled_skills = 51
    gateway_methods = 278
    gateway_advertised_methods = 258
    gateway_events = 33
    gateway_roles = 3
    gateway_scopes = 6
    config_domains = 47
    providers = 78
    channels = 29
    http_sse_endpoints = 18
    client_surfaces = 10
    migration_providers = 3
    release_deployment_surfaces = 24
}

function Fail {
    param([string]$Message)
    throw "compat/upstream validation failed: $Message"
}

function Read-Json {
    param([string]$Path)
    try {
        # Deliberately not Get-Content -Raw: Windows PowerShell 5.1 decodes a
        # BOM-less file with the system ANSI codepage while PowerShell Core
        # decodes it as UTF-8, so the same bytes would parse differently on the
        # two platforms. ReadAllText is UTF-8 with BOM detection everywhere.
        return (ConvertFrom-Json ([System.IO.File]::ReadAllText($Path)))
    } catch {
        Fail "invalid JSON in $Path`: $($_.Exception.Message)"
    }
}

function Get-PropertyNames {
    param([object]$Value)
    if ($Value -is [System.Collections.IDictionary]) {
        return @($Value.Keys | ForEach-Object { [string]$_ })
    }
    if ($null -eq $Value) {
        return @()
    }
    return @($Value.PSObject.Properties.Name)
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

function Test-OrdinalContains {
    param(
        [string[]]$Values,
        [string]$Expected
    )
    foreach ($value in $Values) {
        if (Test-OrdinalStringEqual $value $Expected) {
            return $true
        }
    }
    return $false
}

function Has-Property {
    param(
        [object]$Value,
        [string]$Name
    )
    return Test-OrdinalContains (Get-PropertyNames $Value) $Name
}

function Get-PropertyValue {
    param(
        [object]$Value,
        [string]$Name
    )
    $found = $false
    $result = $null
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            if (Test-OrdinalStringEqual ([string]$key) $Name) {
                $result = $Value[$key]
                $found = $true
                break
            }
        }
    } elseif ($null -ne $Value) {
        foreach ($property in $Value.PSObject.Properties) {
            if (Test-OrdinalStringEqual $property.Name $Name) {
                $result = $property.Value
                $found = $true
                break
            }
        }
    }
    if (-not $found) {
        return $null
    }
    if ($result -is [System.Array]) {
        return (, $result)
    }
    return $result
}

function Assert-ExactPropertySet {
    param(
        [object]$Value,
        [string[]]$Expected,
        [string]$Context
    )
    $actual = @(Get-PropertyNames $Value)
    $missing = @($Expected | Where-Object { -not (Test-OrdinalContains $actual $_) })
    $unexpected = @($actual | Where-Object { -not (Test-OrdinalContains $Expected $_) })
    if ($missing.Count -gt 0 -or $unexpected.Count -gt 0) {
        Fail "$Context property mismatch; missing=[$($missing -join ',')], unexpected=[$($unexpected -join ',')]"
    }
}

function Assert-RequiredProperties {
    param(
        [object]$Value,
        [string[]]$Required,
        [string]$Context
    )
    $actual = @(Get-PropertyNames $Value)
    $missing = @($Required | Where-Object { -not (Test-OrdinalContains $actual $_) })
    if ($missing.Count -gt 0) {
        Fail "$Context missing required properties [$($missing -join ',')]"
    }
}

function Get-Sha256Text {
    param([string]$Text)
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) |
            ForEach-Object { $_.ToString("x2") }) -join "")
    } finally {
        $algorithm.Dispose()
    }
}

function Get-ObjectDigest {
    param([object]$Value)
    return Get-Sha256Text (ConvertTo-CanonicalJson $Value)
}

# --- Cross-platform determinism -------------------------------------------
#
# Windows PowerShell 5.1 and PowerShell Core disagree about JSON in two ways
# that silently corrupt a trust root:
#
#   1. ConvertFrom-Json in PowerShell Core coerces ISO-8601-looking strings into
#      [datetime], and [string] then renders them with the current culture. The
#      same document therefore yields "2026-07-13T03:29:58Z" on Windows and
#      "07/13/2026 03:29:58" on Linux.
#   2. ConvertTo-Json in Windows PowerShell escapes < > & ' as \uXXXX because it
#      uses JavaScriptSerializer; PowerShell Core emits them raw. Any digest
#      taken over its output is therefore platform dependent.
#
# Everything canonical below is hand-encoded so neither difference can reach a
# digest or a comparison. Assert-PortabilityInvariants pins the behaviour.

$ContractTimestampFormat = "yyyy-MM-ddTHH:mm:ssZ"

function ConvertTo-ContractString {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) {
        return ""
    }
    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToUniversalTime().ToString(
            $ContractTimestampFormat, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.DateTimeOffset]) {
        return ([System.DateTimeOffset]$Value).ToUniversalTime().ToString(
            $ContractTimestampFormat, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [System.IFormattable]) {
        return ([System.IFormattable]$Value).ToString(
            $null, [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return [string]$Value
}

function ConvertTo-CanonicalJsonString {
    param([string]$Value)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $code = [int]$character
        if ($character -eq '"') {
            [void]$builder.Append('\"')
        } elseif ($character -eq '\') {
            [void]$builder.Append('\\')
        } elseif ($code -eq 8) {
            [void]$builder.Append('\b')
        } elseif ($code -eq 9) {
            [void]$builder.Append('\t')
        } elseif ($code -eq 10) {
            [void]$builder.Append('\n')
        } elseif ($code -eq 12) {
            [void]$builder.Append('\f')
        } elseif ($code -eq 13) {
            [void]$builder.Append('\r')
        } elseif ($code -lt 32) {
            [void]$builder.Append('\u' + $code.ToString(
                "x4", [System.Globalization.CultureInfo]::InvariantCulture))
        } else {
            [void]$builder.Append($character)
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-CanonicalJsonScalar {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) {
        return "null"
    }
    if ($Value -is [bool]) {
        if ($Value) { return "true" }
        return "false"
    }
    if ($Value -is [datetime] -or $Value -is [System.DateTimeOffset]) {
        return ConvertTo-CanonicalJsonString (ConvertTo-ContractString $Value)
    }
    if ($Value -is [string] -or $Value -is [char]) {
        return ConvertTo-CanonicalJsonString ([string]$Value)
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or
        $Value -is [uint16] -or $Value -is [int] -or $Value -is [uint32] -or
        $Value -is [long] -or $Value -is [uint64] -or $Value -is [bigint]) {
        return ConvertTo-ContractString $Value
    }
    if ($Value -is [decimal] -or $Value -is [double] -or $Value -is [single]) {
        return ([System.IFormattable]$Value).ToString(
            "R", [System.Globalization.CultureInfo]::InvariantCulture)
    }
    Fail "canonical JSON encountered an unsupported scalar of type $($Value.GetType().FullName)"
}

function ConvertTo-CanonicalJson {
    param(
        [AllowNull()]
        [object]$Value
    )
    if ($null -eq $Value) {
        return "null"
    }
    if ($Value -is [System.Array]) {
        [string[]]$elements = @($Value | ForEach-Object { ConvertTo-CanonicalJson $_ })
        return "[" + ($elements -join ",") + "]"
    }
    if (Test-JsonObject $Value) {
        [string[]]$names = @(Get-PropertyNames $Value)
        [Array]::Sort($names, [StringComparer]::Ordinal)
        [string[]]$members = @(
            $names | ForEach-Object {
                $encodedName = ConvertTo-CanonicalJsonString $_
                $encodedValue = ConvertTo-CanonicalJson (Get-PropertyValue $Value $_)
                "${encodedName}:${encodedValue}"
            }
        )
        return "{" + ($members -join ",") + "}"
    }
    return ConvertTo-CanonicalJsonScalar $Value
}

function Get-CanonicalArrayDigest {
    param([object[]]$Items)
    [string[]]$elements = @($Items | ForEach-Object { ConvertTo-CanonicalJson $_ })
    [Array]::Sort($elements, [StringComparer]::Ordinal)
    return Get-Sha256Text ("[" + ($elements -join ",") + "]")
}

# Pins every behaviour that has to be identical under Windows PowerShell 5.1 and
# PowerShell Core on Linux and macOS. This runs on every invocation, in both
# verify and write mode, before any contract file is read, so a host whose
# globalisation or JSON behaviour differs fails loudly here instead of silently
# computing a different digest. Each vector below corresponds to a real observed
# divergence between the two engines.
function Assert-PortabilityInvariants {
    $expectations = @(
        # JSON string escaping. Windows PowerShell's ConvertTo-Json emits
        # \u003c \u003e \u0026 \u0027 for these; PowerShell Core emits them raw.
        @{ actual = (ConvertTo-CanonicalJsonString "a<b"); expected = '"a<b"'; case = "less-than is not escaped" },
        @{ actual = (ConvertTo-CanonicalJsonString "a>b"); expected = '"a>b"'; case = "greater-than is not escaped" },
        @{ actual = (ConvertTo-CanonicalJsonString "a&b"); expected = '"a&b"'; case = "ampersand is not escaped" },
        @{ actual = (ConvertTo-CanonicalJsonString "a'b"); expected = '"a''b"'; case = "apostrophe is not escaped" },
        @{ actual = (ConvertTo-CanonicalJsonString "a/b"); expected = '"a/b"'; case = "solidus is not escaped" },
        @{ actual = (ConvertTo-CanonicalJsonString ("caf" + [char]0x00E9)); expected = ('"caf' + [char]0x00E9 + '"'); case = "non-ASCII is emitted literally" },
        @{ actual = (ConvertTo-CanonicalJsonString "a`"b\c"); expected = '"a\"b\\c"'; case = "quote and backslash are escaped" },
        @{ actual = (ConvertTo-CanonicalJsonString "a`tb`nc`rd"); expected = '"a\tb\nc\rd"'; case = "control characters use short escapes" },
        @{ actual = (ConvertTo-CanonicalJsonString ([string][char]1)); expected = '"\u0001"'; case = "other control characters use \u escapes" },
        # Scalar rendering must never pick up the ambient culture.
        @{ actual = (ConvertTo-CanonicalJsonScalar $true); expected = "true"; case = "booleans render as JSON literals" },
        @{ actual = (ConvertTo-CanonicalJsonScalar 47); expected = "47"; case = "integers render invariantly" },
        @{ actual = (ConvertTo-CanonicalJsonScalar $null); expected = "null"; case = "null renders as null" },
        # Windows PowerShell parses JSON integers as Int32, PowerShell Core as
        # Int64, so integer recognition must not be tied to one concrete type.
        @{
            actual = [string](Test-JsonInteger ((ConvertFrom-Json '{"n":47}').n))
            expected = "True"
            case = "parsed JSON integers are recognised regardless of width"
        },
        @{
            actual = (ConvertTo-CanonicalJsonScalar ((ConvertFrom-Json '{"n":47}').n))
            expected = "47"
            case = "parsed JSON integers canonicalise identically"
        },
        # PowerShell Core's ConvertFrom-Json turns this string into [datetime];
        # Windows PowerShell leaves it a [string]. Both must canonicalise the same.
        @{
            actual = (ConvertTo-CanonicalJson (ConvertFrom-Json '{"b":"2026-07-13T03:29:58Z","a":1}'))
            expected = '{"a":1,"b":"2026-07-13T03:29:58Z"}'
            case = "ISO-8601 strings survive JSON round-tripping unchanged"
        },
        @{
            actual = (ConvertTo-ContractString ((ConvertFrom-Json '{"t":"2026-07-13T03:29:58Z"}').t))
            expected = "2026-07-13T03:29:58Z"
            case = "ISO-8601 strings compare as their original text"
        },
        # Object member order is ordinal, not linguistic; ICU and NLS disagree
        # about culture-sensitive ordering of punctuation and case.
        @{
            actual = (ConvertTo-CanonicalJson (ConvertFrom-Json '{"b":1,"C":2,"a_b":3,"aD":4,"_a":5}'))
            expected = '{"C":2,"_a":5,"aD":4,"a_b":3,"b":1}'
            case = "object members are ordered ordinally"
        },
        # Digests must not depend on how git checked the file out.
        @{
            actual = (Get-Sha256Text ("x`r`ny`r`n".Replace("`r`n", "`n")))
            expected = (Get-Sha256Text "x`ny`n")
            case = "CRLF and LF hash identically after normalisation"
        },
        # The comparison primitives the whole validator is built on.
        @{ actual = [string](Test-OrdinalStringEqual "abc" "ABC"); expected = "False"; case = "ordinal equality is case sensitive" },
        @{ actual = [string](Test-OrdinalStringEqual "abc" ("abc" + [char]0x00AD)); expected = "False"; case = "ordinal equality is not linguistic" },
        @{ actual = [string](Test-OrdinalContains @("abc") "ABC"); expected = "False"; case = "ordinal membership is case sensitive" },
        @{ actual = [string]("a`r`nb".IndexOf("`n", [System.StringComparison]::Ordinal)); expected = "2"; case = "ordinal IndexOf finds a lone newline inside CRLF" }
    )
    foreach ($expectation in $expectations) {
        if (-not (Test-OrdinalStringEqual ([string]$expectation.actual) ([string]$expectation.expected))) {
            Fail ("host portability invariant violated ({0}): expected '{1}', got '{2}'; this host does not compute contract digests the same way as a conforming host, refusing to validate" -f
                $expectation.case, $expectation.expected, $expectation.actual)
        }
    }
}

function Get-InventoryDigest {
    param(
        [object[]]$Items,
        [string[]]$Fields
    )
    [object[]]$canonicalRows = @(
        $Items | ForEach-Object {
            $row = $_
            $canonicalRow = [ordered]@{}
            foreach ($field in $Fields) {
                if (Has-Property $row $field) {
                    $canonicalRow[$field] = Get-PropertyValue $row $field
                }
            }
            [pscustomobject]$canonicalRow
        }
    )
    return Get-CanonicalArrayDigest $canonicalRows
}

function Get-FeatureDigest {
    param([object[]]$Features)
    return Get-CanonicalArrayDigest $Features
}

# The mutable surface of a feature row. Everything else is frozen contract text.
#
# acceptance_evidence.required is deliberately NOT mutable. It is the row's own
# statement of what parity means, so a claimant that could rewrite it would be
# setting the bar it is judged against. Making the ledger digests regenerable
# (which transitions require) exposed every descriptive field to exactly that
# edit, because the file digest is the only thing that had been holding them.
# Get-LedgerFrozenDigest closes it: the projection below is pinned by a constant
# in $LedgerSpecs that -WriteLedgerDigests cannot reach, and it is verified in
# BOTH modes, so the regeneration command cannot launder a descriptive edit
# either.
$MutableFeatureFields = @("status", "implementation_pointers", "known_differences")
$MutableEvidenceFields = @("status", "artifacts")

function Test-NameInSet {
    param(
        [string]$Name,
        [string[]]$Set
    )
    foreach ($candidate in $Set) {
        if (Test-OrdinalStringEqual $Name $candidate) {
            return $true
        }
    }
    return $false
}

function Get-FrozenFeatureProjection {
    param([object]$Feature)
    $projection = [ordered]@{}
    foreach ($name in (Get-PropertyNames $Feature)) {
        if (Test-NameInSet $name $MutableFeatureFields) {
            continue
        }
        $value = Get-PropertyValue $Feature $name
        if ((Test-OrdinalStringEqual $name "acceptance_evidence") -and (Test-JsonObject $value)) {
            $frozenEvidence = [ordered]@{}
            foreach ($evidenceName in (Get-PropertyNames $value)) {
                if (-not (Test-NameInSet $evidenceName $MutableEvidenceFields)) {
                    $frozenEvidence[$evidenceName] = Get-PropertyValue $value $evidenceName
                }
            }
            $projection[$name] = [pscustomobject]$frozenEvidence
            continue
        }
        $projection[$name] = $value
    }
    return [pscustomobject]$projection
}

function Get-LedgerFrozenDigest {
    param([object[]]$Features)
    return Get-CanonicalArrayDigest @($Features | ForEach-Object { Get-FrozenFeatureProjection $_ })
}

function Test-JsonValueEqual {
    param(
        [object]$Left,
        [object]$Right
    )
    return Test-OrdinalStringEqual (ConvertTo-CanonicalJson $Left) (ConvertTo-CanonicalJson $Right)
}

function Test-JsonObject {
    param([object]$Value)
    return $null -ne $Value -and
        -not ($Value -is [string]) -and
        -not ($Value -is [System.Array]) -and
        ($Value -is [pscustomobject] -or $Value -is [System.Collections.IDictionary])
}

# Windows PowerShell parses JSON integers as Int32 and PowerShell Core as Int64,
# so no caller may test against one concrete numeric type.
function Test-JsonInteger {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [bool]) {
        return $false
    }
    return ($Value -is [byte]) -or ($Value -is [sbyte]) -or ($Value -is [int16]) -or
        ($Value -is [uint16]) -or ($Value -is [int32]) -or ($Value -is [uint32]) -or
        ($Value -is [int64]) -or ($Value -is [uint64])
}

function Resolve-LocalSchemaReference {
    param(
        [string]$Reference,
        [object]$RootSchema
    )
    if (-not $Reference.StartsWith("#/", [StringComparison]::Ordinal)) {
        Fail "unsupported non-local JSON Schema reference $Reference"
    }
    $current = $RootSchema
    foreach ($rawSegment in $Reference.Substring(2).Split("/")) {
        $segment = $rawSegment.Replace("~1", "/").Replace("~0", "~")
        if (-not (Has-Property $current $segment)) {
            Fail "unresolvable JSON Schema reference $Reference"
        }
        $current = Get-PropertyValue $current $segment
    }
    return $current
}

function Assert-JsonSchema {
    param(
        [AllowNull()]
        [object]$Instance,
        [object]$SchemaNode,
        [object]$RootSchema,
        [string]$Path
    )

    if (Has-Property $SchemaNode '$ref') {
        $resolved = Resolve-LocalSchemaReference ([string](Get-PropertyValue $SchemaNode '$ref')) $RootSchema
        Assert-JsonSchema $Instance $resolved $RootSchema $Path
        return
    }

    if (Has-Property $SchemaNode "type") {
        $expectedType = [string](Get-PropertyValue $SchemaNode "type")
        if (Test-OrdinalStringEqual $expectedType "object") {
            $typeMatches = Test-JsonObject $Instance
        } elseif (Test-OrdinalStringEqual $expectedType "array") {
            $typeMatches = $Instance -is [System.Array]
        } elseif (Test-OrdinalStringEqual $expectedType "string") {
            $typeMatches = $Instance -is [string]
        } elseif (Test-OrdinalStringEqual $expectedType "boolean") {
            $typeMatches = $Instance -is [bool]
        } elseif (Test-OrdinalStringEqual $expectedType "integer") {
            $typeMatches = ($Instance -is [byte]) -or ($Instance -is [int16]) -or
                ($Instance -is [int32]) -or ($Instance -is [int64])
        } elseif (Test-OrdinalStringEqual $expectedType "number") {
            $typeMatches = ($Instance -is [byte]) -or ($Instance -is [int16]) -or
                ($Instance -is [int32]) -or ($Instance -is [int64]) -or
                ($Instance -is [single]) -or ($Instance -is [double]) -or
                ($Instance -is [decimal])
        } elseif (Test-OrdinalStringEqual $expectedType "null") {
            $typeMatches = $null -eq $Instance
        } else {
            Fail "$Path uses unsupported JSON Schema type $expectedType"
        }
        if (-not $typeMatches) {
            $actualType = if ($null -eq $Instance) { "null" } else { $Instance.GetType().FullName }
            Fail "$Path must have JSON Schema type $expectedType (actual $actualType)"
        }
    }

    if (Has-Property $SchemaNode "const") {
        $constant = Get-PropertyValue $SchemaNode "const"
        if (-not (Test-JsonValueEqual $Instance $constant)) {
            Fail "$Path does not match its JSON Schema const"
        }
    }

    if (Has-Property $SchemaNode "enum") {
        $matchesEnum = $false
        $enumValues = Get-PropertyValue $SchemaNode "enum"
        foreach ($candidate in $enumValues) {
            if (Test-JsonValueEqual $Instance $candidate) {
                $matchesEnum = $true
                break
            }
        }
        if (-not $matchesEnum) {
            Fail "$Path is not in its JSON Schema enum"
        }
    }

    if ($Instance -is [string]) {
        if (Has-Property $SchemaNode "minLength") {
            $minimumLength = [int](Get-PropertyValue $SchemaNode "minLength")
            if ($Instance.Length -lt $minimumLength) {
                Fail "$Path is shorter than JSON Schema minLength $minimumLength"
            }
        }
        if (Has-Property $SchemaNode "pattern") {
            $pattern = [string](Get-PropertyValue $SchemaNode "pattern")
            if (-not ($Instance -cmatch $pattern)) {
                Fail "$Path does not match JSON Schema pattern $pattern"
            }
        }
        if (Test-OrdinalStringEqual ([string](Get-PropertyValue $SchemaNode "format")) "uri") {
            $uri = $null
            if ($Instance -cnotmatch "^[A-Za-z][A-Za-z0-9+.-]*:[^\s\\]*$" -or
                -not [Uri]::IsWellFormedUriString($Instance, [UriKind]::Absolute) -or
                -not [Uri]::TryCreate($Instance, [UriKind]::Absolute, [ref]$uri)) {
                Fail "$Path is not an absolute URI"
            }
        }
    }

    if (Test-JsonObject $Instance) {
        if (Has-Property $SchemaNode "required") {
            [string[]]$requiredProperties = Get-PropertyValue $SchemaNode "required"
            Assert-RequiredProperties $Instance $requiredProperties $Path
        }
        $propertySchemas = Get-PropertyValue $SchemaNode "properties"
        if ((Get-PropertyValue $SchemaNode "additionalProperties") -eq $false) {
            $allowed = if ($null -eq $propertySchemas) { @() } else { @(Get-PropertyNames $propertySchemas) }
            $unexpected = @(
                (Get-PropertyNames $Instance) |
                    Where-Object { -not (Test-OrdinalContains $allowed $_) }
            )
            if ($unexpected.Count -gt 0) {
                Fail "$Path contains JSON Schema additional properties [$($unexpected -join ',')]"
            }
        }
        if ($null -ne $propertySchemas) {
            foreach ($propertyName in Get-PropertyNames $propertySchemas) {
                if (Has-Property $Instance $propertyName) {
                    $propertyInstance = Get-PropertyValue $Instance $propertyName
                    $propertySchema = Get-PropertyValue $propertySchemas $propertyName
                    Assert-JsonSchema `
                        -Instance $propertyInstance `
                        -SchemaNode $propertySchema `
                        -RootSchema $RootSchema `
                        -Path "$Path.$propertyName"
                }
            }
        }
    }

    if ($Instance -is [System.Array]) {
        $items = @($Instance)
        if (Has-Property $SchemaNode "minItems") {
            $minimumItems = [int](Get-PropertyValue $SchemaNode "minItems")
            if ($items.Count -lt $minimumItems) {
                Fail "$Path has fewer than JSON Schema minItems $minimumItems"
            }
        }
        if ((Get-PropertyValue $SchemaNode "uniqueItems") -eq $true) {
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($item in $items) {
                $identity = ConvertTo-CanonicalJson $item
                if (-not $seen.Add($identity)) {
                    Fail "$Path violates JSON Schema uniqueItems"
                }
            }
        }
        if (Has-Property $SchemaNode "items") {
            $itemSchema = Get-PropertyValue $SchemaNode "items"
            for ($index = 0; $index -lt $items.Count; $index += 1) {
                Assert-JsonSchema $items[$index] $itemSchema $RootSchema "$Path[$index]"
            }
        }
    }
}

function Assert-RelativeSourcePath {
    param(
        [string]$Path,
        [string]$Context
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not ($Path -cmatch '^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$')) {
        Fail "$Context has invalid upstream-relative source path '$Path'"
    }
}

function Resolve-RepositoryRoot {
    param([AllowNull()][string]$Requested)
    if ([string]::IsNullOrWhiteSpace($Requested)) {
        $candidate = Split-Path -Parent (Split-Path -Parent $Root)
    } else {
        $candidate = $Requested
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
        Fail "repository root '$candidate' does not exist; acceptance evidence cannot be verified"
    }
    $resolved = (Resolve-Path -LiteralPath $candidate).ProviderPath
    foreach ($marker in @("Cargo.toml", "crates")) {
        if (-not (Test-Path -LiteralPath (Join-Path $resolved $marker))) {
            Fail "repository root '$resolved' is not a GTA-Claw working tree (missing $marker)"
        }
    }
    return $resolved
}

$script:DirectoryEntryCache = @{}
$script:RepositoryFileTextCache = @{}
$script:CrateReachabilityCache = @{}

function Get-DirectoryEntryNames {
    param([string]$AbsoluteDirectory)
    if ($script:DirectoryEntryCache.ContainsKey($AbsoluteDirectory)) {
        return $script:DirectoryEntryCache[$AbsoluteDirectory]
    }
    [string[]]$names = @()
    if (Test-Path -LiteralPath $AbsoluteDirectory -PathType Container) {
        $names = @(Get-ChildItem -LiteralPath $AbsoluteDirectory -Force | ForEach-Object { [string]$_.Name })
    }
    $script:DirectoryEntryCache[$AbsoluteDirectory] = $names
    return $names
}

function Resolve-RepositoryFilePath {
    param([string]$RelativePath)
    $current = $script:RepositoryRootFull
    foreach ($segment in $RelativePath.Split("/")) {
        if (-not (Test-OrdinalContains (Get-DirectoryEntryNames $current) $segment)) {
            return $null
        }
        $current = Join-Path $current $segment
        # A reparse point (symlink or junction) can resolve outside the repository,
        # which the Rust parity harness rejects through canonicalisation. Refuse it
        # here too so the two trust roots cannot disagree about the same citation.
        $entry = Get-Item -LiteralPath $current -Force -ErrorAction SilentlyContinue
        if ($null -eq $entry) {
            return $null
        }
        if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $null
        }
    }
    if (-not (Test-Path -LiteralPath $current -PathType Leaf)) {
        return $null
    }
    return $current
}

function Get-RepositoryFileText {
    param([string]$AbsolutePath)
    if ($script:RepositoryFileTextCache.ContainsKey($AbsolutePath)) {
        return $script:RepositoryFileTextCache[$AbsolutePath]
    }
    $text = [System.IO.File]::ReadAllText($AbsolutePath)
    $script:RepositoryFileTextCache[$AbsolutePath] = $text
    return $text
}

function Test-PathHasExtension {
    param(
        [string]$RelativePath,
        [string[]]$Extensions
    )
    $lowered = $RelativePath.ToLowerInvariant()
    foreach ($extension in $Extensions) {
        if ($lowered.EndsWith($extension, [StringComparison]::Ordinal)) {
            return $true
        }
    }
    return $false
}

function Test-PathHasPrefix {
    param(
        [string]$RelativePath,
        [string[]]$Prefixes
    )
    foreach ($prefix in $Prefixes) {
        if ($RelativePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Assert-EvidencePathShape {
    param(
        [string]$RelativePath,
        [string]$Context
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or
        -not ($RelativePath -cmatch '\A[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\z')) {
        Fail "$Context acceptance evidence path '$RelativePath' must be a repository-relative forward-slash path"
    }
    foreach ($segment in $RelativePath.Split("/")) {
        if ((Test-OrdinalStringEqual $segment ".") -or (Test-OrdinalStringEqual $segment "..")) {
            Fail "$Context acceptance evidence path '$RelativePath' must not contain relative segments"
        }
    }
    if (Test-PathHasExtension $RelativePath $LegacyScriptExtensions) {
        Fail "$Context acceptance evidence path '$RelativePath' is a legacy TypeScript/JavaScript file and is never Rust acceptance evidence"
    }
    if (Test-PathHasPrefix $RelativePath $LegacyPathPrefixes) {
        Fail "$Context acceptance evidence path '$RelativePath' lives in a legacy JavaScript/TypeScript tree and is never Rust acceptance evidence"
    }
    if (Test-PathHasPrefix $RelativePath $SelfReferentialPathPrefixes) {
        Fail "$Context acceptance evidence path '$RelativePath' is self-referential compatibility contract data, not acceptance evidence"
    }
}

# ---------------------------------------------------------------------------
# Enabled-test oracle.
#
# This is the PowerShell implementation of the shared enabled-test rule.
# declares_enabled_test / rust_tokens / declares_in_items in
# crates/claw-conformance/src/claims.rs map to Test-DeclaresEnabledRustTest /
# Get-RustTokens / Test-RustDeclaresInItems here. Neither implementation may
# change the rule alone.
# Agreement is not asserted by hand: enabled-test-oracle.json is a shared,
# frozen fixture corpus that both implementations must classify identically, and
# Assert-EnabledTestOracle below replays every case on every run.
#
# The oracle is a tokenizer plus an item-tree walker, not a line matcher. It
# operates on UTF-8 BYTES because the Rust original indexes bytes. Comments,
# strings, byte strings, raw strings and char literals are discarded BEFORE any
# matching, so Rust-shaped text inside a comment or a string literal can never
# be cited as evidence. A #[test] attribute must attach to the CITED function
# itself, and the in-file module path must match exactly.
# ---------------------------------------------------------------------------

function Get-RustBlockCommentEnd {
    param([byte[]]$Bytes, [int]$Index)
    # Nesting aware: /* is checked before */ so a nested comment cannot end early.
    $length = $Bytes.Length
    $depth = 0
    $index = $Index
    while ($index -lt $length) {
        if (($index + 2) -le $length -and $Bytes[$index] -eq 47 -and $Bytes[$index + 1] -eq 42) {
            $depth += 1
            $index += 2
        } elseif (($index + 2) -le $length -and $Bytes[$index] -eq 42 -and $Bytes[$index + 1] -eq 47) {
            $depth -= 1
            $index += 2
            if ($depth -eq 0) {
                return $index
            }
        } else {
            $index += 1
        }
    }
    return $index
}

function Get-RustRawStringEnd {
    param([byte[]]$Bytes, [int]$Index)
    # Handles r"..", r#".."#, br".." and br#".."#. Returns -1 (Rust None) when the
    # prefix is not a raw string, and the end of input when it is unterminated.
    $length = $Bytes.Length
    $cursor = $Index
    if ($cursor -lt $length -and $Bytes[$cursor] -eq 98) {
        $cursor += 1
    }
    if ($cursor -ge $length -or $Bytes[$cursor] -ne 114) {
        return -1
    }
    $cursor += 1
    $hashes = 0
    while (($cursor + $hashes) -lt $length -and $Bytes[$cursor + $hashes] -eq 35) {
        $hashes += 1
    }
    $cursor += $hashes
    if ($cursor -ge $length -or $Bytes[$cursor] -ne 34) {
        return -1
    }
    $cursor += 1
    while ($cursor -lt $length) {
        if ($Bytes[$cursor] -eq 34) {
            $suffixEnd = $cursor + 1 + $hashes
            if ($suffixEnd -le $length) {
                $allHashes = $true
                for ($probe = $cursor + 1; $probe -lt $suffixEnd; $probe += 1) {
                    if ($Bytes[$probe] -ne 35) {
                        $allHashes = $false
                        break
                    }
                }
                if ($allHashes) {
                    return $suffixEnd
                }
            }
        }
        $cursor += 1
    }
    return $length
}

function Get-RustQuotedEnd {
    param([byte[]]$Bytes, [int]$Quote)
    $length = $Bytes.Length
    $cursor = $Quote + 1
    while ($cursor -lt $length) {
        if ($Bytes[$cursor] -eq 92) {
            $cursor = [Math]::Min($cursor + 2, $length)
        } elseif ($Bytes[$cursor] -eq 34) {
            return $cursor + 1
        } else {
            $cursor += 1
        }
    }
    return $cursor
}

function Get-RustCharLiteralEnd {
    param([byte[]]$Bytes, [int]$Quote)
    # Returns -1 (Rust None) when the quote is not a char literal, which is how a
    # lifetime such as &'a str stays a lifetime instead of opening a literal.
    $length = $Bytes.Length
    $cursor = $Quote + 1
    if ($cursor -lt $length -and $Bytes[$cursor] -eq 92) {
        $cursor += 2
    } else {
        $cursor += 1
    }
    if ($cursor -lt $length -and $Bytes[$cursor] -eq 39) {
        return $cursor + 1
    }
    return -1
}

function Get-RustTokens {
    param([string]$Source, [switch]$WithStrings)
    # Token encoding: identifiers become "i:<name>", punctuation is its own text,
    # :: becomes "::", every string/char literal becomes "lit" and every other
    # byte becomes "oth". Identifiers carry an "i:" prefix, so no identifier can
    # collide with a punctuation marker even though identifiers may now contain
    # non-ASCII characters.
    #
    # "lit" and "oth" are load bearing, not cosmetic. The Rust tokenizer
    # emits a token for every unrecognised byte, so a stray byte in front of an
    # attribute makes the following item part of the item that stray byte opened
    # and the test stops being visible. Dropping those bytes silently, as an
    # earlier port did, accepted sources the Rust implementation rejects.
    #
    # -WithStrings exposes the Rust tokenizer's StringLiteral and Equals variants
    # as "s:<value>" and "=" so the shared reachability rule can read a
    # #[path = "..."] attribute. The enabled-test consumer uses the opaque
    # "lit"/"oth" form because it does not need those values.
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Source)
    $length = $bytes.Length
    $tokens = New-Object System.Collections.Generic.List[string]
    $index = 0
    while ($index -lt $length) {
        $byte = $bytes[$index]
        # A UTF-8 BOM is skipped outright. It has to be skipped before the
        # identifier branch, because that branch now starts an identifier on any
        # non-ASCII byte and would otherwise turn a leading BOM into one.
        if (($index + 3) -le $length -and $byte -eq 239 -and $bytes[$index + 1] -eq 187 -and $bytes[$index + 2] -eq 191) {
            $index += 3
            continue
        }
        # Rust is_ascii_whitespace: space, tab, newline, form feed, carriage
        # return. Carriage return being whitespace is what makes the oracle
        # produce identical tokens for CRLF and LF checkouts.
        if ($byte -eq 32 -or $byte -eq 9 -or $byte -eq 10 -or $byte -eq 12 -or $byte -eq 13) {
            $index += 1
            continue
        }
        if (($index + 2) -le $length -and $byte -eq 47 -and $bytes[$index + 1] -eq 47) {
            $index += 2
            while ($index -lt $length -and $bytes[$index] -ne 10) {
                $index += 1
            }
            continue
        }
        if (($index + 2) -le $length -and $byte -eq 47 -and $bytes[$index + 1] -eq 42) {
            $index = Get-RustBlockCommentEnd $bytes $index
            continue
        }
        $rawEnd = Get-RustRawStringEnd $bytes $index
        if ($rawEnd -ge 0) {
            if ($WithStrings) {
                # A raw string carries a value like any other string literal, and
                # #[path = r"..."] is legal Rust. Tokenising it as an opaque
                # literal made the attribute invisible, so the declaration was
                # resolved by module name and a file cargo never compiles was
                # blessed instead. Raw strings have no escapes, so the bytes
                # between the quotes are the value.
                $prefix = $index
                if ($bytes[$prefix] -eq 98) { $prefix += 1 }
                $prefix += 1
                $hashCount = 0
                while (($prefix + $hashCount) -lt $length -and $bytes[$prefix + $hashCount] -eq 35) {
                    $hashCount += 1
                }
                $contentStart = $prefix + $hashCount + 1
                $contentLength = $rawEnd - $hashCount - 1 - $contentStart
                if ($contentLength -ge 0 -and ($contentStart + $contentLength) -le $length) {
                    [void]$tokens.Add("s:" + [System.Text.Encoding]::UTF8.GetString($bytes, $contentStart, $contentLength))
                } else {
                    [void]$tokens.Add("lit")
                }
            } else {
                [void]$tokens.Add("lit")
            }
            $index = $rawEnd
            continue
        }
        if ($byte -eq 34 -or ($byte -eq 98 -and ($index + 1) -lt $length -and $bytes[$index + 1] -eq 34)) {
            $quote = if ($byte -eq 34) { $index } else { $index + 1 }
            $quotedEnd = Get-RustQuotedEnd $bytes $quote
            if ($WithStrings) {
                $inner = $quotedEnd - $quote - 2
                if ($inner -ge 0) {
                    [void]$tokens.Add("s:" + [System.Text.Encoding]::UTF8.GetString($bytes, $quote + 1, $inner))
                } else {
                    [void]$tokens.Add("lit")
                }
            } else {
                [void]$tokens.Add("lit")
            }
            $index = $quotedEnd
            continue
        }
        if ($byte -eq 39) {
            [void]$tokens.Add("lit")
            $charEnd = Get-RustCharLiteralEnd $bytes $index
            if ($charEnd -ge 0) {
                $index = $charEnd
            } else {
                $index += 1
            }
            continue
        }
        # Identifier start: ASCII letter, underscore, or any non-ASCII byte.
        # Walking non-ASCII a byte at a time is equivalent to the Rust
        # implementation's char::len_utf8 step, because every continuation byte
        # of a multi-byte character is itself >= 0x80 and is consumed here too.
        if (($byte -ge 65 -and $byte -le 90) -or ($byte -ge 97 -and $byte -le 122) -or $byte -eq 95 -or $byte -ge 128) {
            $start = $index
            $index += 1
            while ($index -lt $length) {
                $next = $bytes[$index]
                if (($next -ge 48 -and $next -le 57) -or ($next -ge 65 -and $next -le 90) -or
                    ($next -ge 97 -and $next -le 122) -or $next -eq 95 -or $next -ge 128) {
                    $index += 1
                } else {
                    break
                }
            }
            [void]$tokens.Add("i:" + [System.Text.Encoding]::UTF8.GetString($bytes, $start, $index - $start))
            continue
        }
        if ($byte -eq 35) { [void]$tokens.Add("#") }
        elseif ($byte -eq 33) { [void]$tokens.Add("!") }
        elseif ($byte -eq 91) { [void]$tokens.Add("[") }
        elseif ($byte -eq 93) { [void]$tokens.Add("]") }
        elseif ($byte -eq 123) { [void]$tokens.Add("{") }
        elseif ($byte -eq 125) { [void]$tokens.Add("}") }
        elseif ($byte -eq 40) { [void]$tokens.Add("(") }
        elseif ($byte -eq 41) { [void]$tokens.Add(")") }
        elseif ($byte -eq 59) { [void]$tokens.Add(";") }
        elseif ($byte -eq 58 -and ($index + 1) -lt $length -and $bytes[$index + 1] -eq 58) {
            [void]$tokens.Add("::")
            $index += 1
        }
        elseif ($byte -eq 61 -and $WithStrings) { [void]$tokens.Add("=") }
        else { [void]$tokens.Add("oth") }
        $index += 1
    }
    return ,$tokens.ToArray()
}

function Get-RustMatchingDelimiter {
    param([string[]]$Tokens, [int]$Open, [int]$End)
    # A typed stack, not a depth counter. Mismatched delimiters return -1 so the
    # caller fails closed. An earlier port counted only the opening delimiter's
    # own kind and ignored the others, which accepted "{ ( }" as balanced; the
    # Rust implementation rejects it, and macro scanning makes that reachable.
    if ($Open -lt 0) {
        return -1
    }
    $expected = New-Object System.Collections.Generic.List[string]
    $limit = [Math]::Min($End, $Tokens.Length)
    for ($index = $Open; $index -lt $limit; $index += 1) {
        $token = $Tokens[$index]
        $closing = $null
        if (Test-OrdinalStringEqual $token "[") { $closing = "]" }
        elseif (Test-OrdinalStringEqual $token "{") { $closing = "}" }
        elseif (Test-OrdinalStringEqual $token "(") { $closing = ")" }
        if ($null -ne $closing) {
            [void]$expected.Add($closing)
            continue
        }
        if ((Test-OrdinalStringEqual $token "]") -or (Test-OrdinalStringEqual $token "}") -or
            (Test-OrdinalStringEqual $token ")")) {
            if ($expected.Count -eq 0) {
                return -1
            }
            $top = $expected[$expected.Count - 1]
            $expected.RemoveAt($expected.Count - 1)
            if (-not (Test-OrdinalStringEqual $top $token)) {
                return -1
            }
            if ($expected.Count -eq 0) {
                return $index
            }
        }
    }
    return -1
}

function Get-RustMacroInvocationEnd {
    param([string[]]$Tokens, [int]$Index, [int]$End)
    # <name> ! <delimited token tree>, returning the index just past the closing
    # delimiter, or -1 when this is not a macro invocation at all.
    if ($Index -lt 0 -or $Index -ge $Tokens.Length) {
        return -1
    }
    if (-not $Tokens[$Index].StartsWith("i:", [StringComparison]::Ordinal)) {
        return -1
    }
    if (($Index + 1) -ge $Tokens.Length -or -not (Test-OrdinalStringEqual $Tokens[$Index + 1] "!")) {
        return -1
    }
    $open = $Index + 2
    # macro_rules! <name> { ... } carries the macro's own name before the body.
    if ((Test-OrdinalStringEqual $Tokens[$Index] "i:macro_rules") -and
        $open -lt $Tokens.Length -and $Tokens[$open].StartsWith("i:", [StringComparison]::Ordinal)) {
        $open += 1
    }
    if ($open -ge $Tokens.Length) {
        return -1
    }
    $delimiter = $Tokens[$open]
    if (-not ((Test-OrdinalStringEqual $delimiter "[") -or (Test-OrdinalStringEqual $delimiter "{") -or
            (Test-OrdinalStringEqual $delimiter "("))) {
        return -1
    }
    $close = Get-RustMatchingDelimiter $Tokens $open $End
    if ($close -lt 0) {
        return -1
    }
    return $close + 1
}

function Test-RustMacroItemPrefix {
    param([string[]]$Tokens, [int]$Start, [int]$MacroName)
    # True when everything from the start of the item up to and including the
    # macro name is a bare path, so the macro invocation IS the item rather than
    # sitting inside one. A leading :: is allowed, which is what keeps a real
    # test following ::std::thread_local! { ... } visible.
    $start = $Start
    if ($start -lt 0 -or $MacroName -ge $Tokens.Length -or $start -gt $MacroName) {
        return $false
    }
    if (Test-OrdinalStringEqual $Tokens[$start] "::") {
        $start += 1
    }
    if ($start -gt $MacroName) {
        return $false
    }
    for ($offset = 0; ($start + $offset) -le $MacroName; $offset += 1) {
        $token = $Tokens[$start + $offset]
        if (($offset % 2) -eq 0) {
            if (-not $token.StartsWith("i:", [StringComparison]::Ordinal)) {
                return $false
            }
        } elseif (-not (Test-OrdinalStringEqual $token "::")) {
            return $false
        }
    }
    return $true
}

function Get-RustAttributes {
    param([string[]]$Tokens, [int]$Index, [int]$End)
    $attributes = New-Object System.Collections.Generic.List[object]
    $index = $Index
    while ($index -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$index] "#")) {
        $inner = (($index + 1) -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$index + 1] "!"))
        $bracket = $index + $(if ($inner) { 2 } else { 1 })
        if ($bracket -ge $Tokens.Length -or -not (Test-OrdinalStringEqual $Tokens[$bracket] "[")) {
            break
        }
        $close = Get-RustMatchingDelimiter $Tokens $bracket $End
        if ($close -lt 0) {
            $close = $End
        }
        $path = New-Object System.Collections.Generic.List[string]
        $cursor = $bracket + 1
        if ($cursor -lt $Tokens.Length -and $Tokens[$cursor].StartsWith("i:", [StringComparison]::Ordinal)) {
            [void]$path.Add($Tokens[$cursor].Substring(2))
            $cursor += 1
            while ($cursor -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$cursor] "::")) {
                if (($cursor + 1) -ge $Tokens.Length -or
                    -not $Tokens[$cursor + 1].StartsWith("i:", [StringComparison]::Ordinal)) {
                    break
                }
                [void]$path.Add($Tokens[$cursor + 1].Substring(2))
                $cursor += 2
            }
        }
        $bodyStart = $bracket + 1
        $bodyCount = [Math]::Max(0, [Math]::Min($close, $Tokens.Length) - $bodyStart)
        [string[]]$body = @()
        if ($bodyCount -gt 0) {
            $body = $Tokens[$bodyStart..($bodyStart + $bodyCount - 1)]
        }
        [void]$attributes.Add([ordered]@{
            inner = $inner
            path = $path.ToArray()
            tokens = $body
        })
        $index = $close + 1
    }
    return [ordered]@{ attributes = $attributes.ToArray(); next = $index }
}

function Test-RustAttributeEnablesTests {
    param([object]$Attribute)
    # One rule, shared by function attributes and by enclosing-scope attributes.
    # An attribute with no path is inert. #[ignore] and #[cfg_attr(..)] always
    # disqualify. A #[cfg(..)] disqualifies unless it is exactly cfg ( test ),
    # so #[cfg(test)] is honoured but #[cfg(test = "disabled")], #[cfg(feature =
    # "x")] and #[cfg(any())] are not.
    [string[]]$path = $Attribute.path
    if ($path.Length -eq 0) {
        return $true
    }
    $first = $path[0]
    if ((Test-OrdinalStringEqual $first "ignore") -or (Test-OrdinalStringEqual $first "cfg_attr")) {
        return $false
    }
    if (-not (Test-OrdinalStringEqual $first "cfg")) {
        return $true
    }
    [string[]]$body = $Attribute.tokens
    if ($body.Length -ne 4) {
        return $false
    }
    return ((Test-OrdinalStringEqual $body[0] "i:cfg") -and
        (Test-OrdinalStringEqual $body[1] "(") -and
        (Test-OrdinalStringEqual $body[2] "i:test") -and
        (Test-OrdinalStringEqual $body[3] ")"))
}

function Test-RustAttributesDeclareEnabledTest {
    param([object[]]$Attributes)
    # has_test && every attribute enables tests. The trailing path segment is
    # matched for has_test so that both #[test] and #[tokio::test] count.
    $hasTest = $false
    foreach ($attribute in $Attributes) {
        [string[]]$path = $attribute.path
        if ($path.Length -gt 0 -and (Test-OrdinalStringEqual $path[$path.Length - 1] "test")) {
            $hasTest = $true
        }
    }
    if (-not $hasTest) {
        return $false
    }
    foreach ($attribute in $Attributes) {
        if (-not (Test-RustAttributeEnablesTests $attribute)) {
            return $false
        }
    }
    return $true
}

function Test-RustModuleAttributesEnableTests {
    param([object[]]$Attributes)
    # Enclosing modules and file/module inner attributes are held to the same
    # per-attribute rule, with no has_test requirement.
    foreach ($attribute in $Attributes) {
        if (-not (Test-RustAttributeEnablesTests $attribute)) {
            return $false
        }
    }
    return $true
}

function Test-RustTestIdentityMatches {
    param([string[]]$Modules, [string]$Function, [string[]]$Target)
    # Exact in-file module identity: a nested test must be cited with its real
    # module path, so neither a fabricated module nor a bare name can match it.
    if ($Target.Length -ne ($Modules.Length + 1)) {
        return $false
    }
    for ($index = 0; $index -lt $Modules.Length; $index += 1) {
        if (-not (Test-OrdinalStringEqual $Modules[$index] $Target[$index])) {
            return $false
        }
    }
    return (Test-OrdinalStringEqual $Target[$Target.Length - 1] $Function)
}

function Get-RustSkipVisibility {
    param([string[]]$Tokens, [int]$Index, [int]$End)
    $index = $Index
    if ($index -ge $Tokens.Length -or -not (Test-OrdinalStringEqual $Tokens[$index] "i:pub")) {
        return $index
    }
    $index += 1
    if ($index -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$index] "(")) {
        $close = Get-RustMatchingDelimiter $Tokens $index $End
        if ($close -lt 0) {
            $close = $End
        }
        $index = $close + 1
    }
    return $index
}

function Get-RustSkipItem {
    param([string[]]$Tokens, [int]$Index, [int]$End)
    # Walks to the end of one item. Macro invocations are consumed whole, which
    # is what stops a #[test] fn spelled inside stringify!(..), a discarding
    # macro body or a macro_rules! definition from being read as a real test.
    # A malformed macro invocation returns End, so scanning stops rather than
    # resuming in the middle of a token tree.
    $itemStart = $Index
    $index = $Index
    $limit = [Math]::Min($End, $Tokens.Length)
    while ($index -lt $limit) {
        if ($Tokens[$index].StartsWith("i:", [StringComparison]::Ordinal) -and
            ($index + 1) -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$index + 1] "!")) {
            $afterMacro = Get-RustMacroInvocationEnd $Tokens $index $End
            if ($afterMacro -lt 0) {
                return $End
            }
            $macroIsItem = Test-RustMacroItemPrefix $Tokens $itemStart $index
            $index = $afterMacro
            if ($macroIsItem) {
                if ($index -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$index] ";")) {
                    $index += 1
                }
                return $index
            }
            continue
        }
        $token = $Tokens[$index]
        if (Test-OrdinalStringEqual $token ";") {
            return $index + 1
        }
        if (Test-OrdinalStringEqual $token "{") {
            $close = Get-RustMatchingDelimiter $Tokens $index $End
            if ($close -lt 0) {
                $close = $End
            }
            return $close + 1
        }
        $index += 1
    }
    return $End
}

$RustItemModifiers = @{ "i:async" = $true; "i:const" = $true; "i:default" = $true; "i:unsafe" = $true }

function Get-RustSkipItemModifiers {
    param([string[]]$Tokens, [int]$Index)
    # async / const / default / unsafe advance one token; extern additionally
    # consumes its ABI string literal, so extern "C" fn does not read as an item
    # whose name is the literal.
    $index = $Index
    while ($index -lt $Tokens.Length) {
        if (Test-OrdinalStringEqual $Tokens[$index] "i:extern") {
            $index += 1
            if ($index -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$index] "lit")) {
                $index += 1
            }
            continue
        }
        if ($RustItemModifiers.ContainsKey($Tokens[$index])) {
            $index += 1
            continue
        }
        break
    }
    return $index
}

function Test-RustDeclaresInItems {
    param(
        [string[]]$Tokens,
        [int]$Start,
        [int]$End,
        [string[]]$Modules,
        [string[]]$Target
    )
    $index = $Start
    while ($index -lt $End) {
        $itemStart = $index
        $parsed = Get-RustAttributes $Tokens $index $End
        $outer = New-Object System.Collections.Generic.List[object]
        $inner = New-Object System.Collections.Generic.List[object]
        foreach ($attribute in $parsed.attributes) {
            if ($attribute.inner) { [void]$inner.Add($attribute) } else { [void]$outer.Add($attribute) }
        }
        # An inner attribute such as #![cfg(any())] disables the entire enclosing
        # scope, so it is checked before anything in that scope is considered.
        if (-not (Test-RustModuleAttributesEnableTests $inner.ToArray())) {
            return $false
        }
        $index = $parsed.next
        if ($index -ge $End) {
            break
        }
        $index = Get-RustSkipVisibility $Tokens $index $End
        $index = Get-RustSkipItemModifiers $Tokens $index
        $keyword = if ($index -lt $Tokens.Length) { $Tokens[$index] } else { $null }
        $nameToken = if (($index + 1) -lt $Tokens.Length) { $Tokens[$index + 1] } else { $null }
        $isIdentPair = ($null -ne $keyword -and $null -ne $nameToken -and
            $keyword.StartsWith("i:", [StringComparison]::Ordinal) -and
            $nameToken.StartsWith("i:", [StringComparison]::Ordinal))
        if ($isIdentPair -and (Test-OrdinalStringEqual $keyword "i:mod")) {
            $name = $nameToken.Substring(2)
            if (($index + 2) -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$index + 2] "{")) {
                $open = $index + 2
                $close = Get-RustMatchingDelimiter $Tokens $open $End
                if ($close -lt 0) {
                    $close = $End
                }
                if (Test-RustModuleAttributesEnableTests $outer.ToArray()) {
                    [string[]]$nested = @($Modules) + @($name)
                    if (Test-RustDeclaresInItems $Tokens ($open + 1) $close $nested $Target) {
                        return $true
                    }
                }
                $index = $close + 1
            } else {
                $index = Get-RustSkipItem $Tokens $index $End
            }
        } elseif ($isIdentPair -and (Test-OrdinalStringEqual $keyword "i:fn")) {
            $name = $nameToken.Substring(2)
            if ((Test-RustTestIdentityMatches $Modules $name $Target) -and
                (Test-RustAttributesDeclareEnabledTest $outer.ToArray())) {
                return $true
            }
            $index = Get-RustSkipItem $Tokens ($index + 2) $End
        } else {
            $index = Get-RustSkipItem $Tokens $index $End
        }
        if ($index -le $itemStart) {
            $index = $itemStart + 1
        }
    }
    return $false
}

function Test-DeclaresEnabledRustTest {
    param(
        [string]$Source,
        [string]$TestName
    )
    [string[]]$target = $TestName.Split(@("::"), [System.StringSplitOptions]::None)
    [string[]]$tokens = Get-RustTokens $Source
    return (Test-RustDeclaresInItems $tokens 0 $tokens.Length @() $target)
}

function Assert-EnabledTestOracle {
    param([object]$Corpus)
    # Replays the shared fixture corpus on every run. The Rust and PowerShell
    # implementations are independently owned; the frozen corpus is the common
    # contract and both implementations must classify every case identically.
    Assert-ExactPropertySet $Corpus @(
        "schema_version", "purpose", "normative_implementation",
        "follower_implementation", "expected_is_authoritative_from", "cases"
    ) "enabled-test-oracle"
    if ($Corpus.schema_version -ne 1) {
        Fail "enabled-test-oracle schema_version must be 1"
    }
    Assert-ExactPropertySet $Corpus.normative_implementation @("path", "function", "ported_at_commit") "enabled-test-oracle.normative_implementation"
    Assert-ExactPropertySet $Corpus.follower_implementation @("path", "function") "enabled-test-oracle.follower_implementation"
    if (-not (Test-OrdinalStringEqual ([string]$Corpus.normative_implementation.path) "crates/claw-conformance/src/claims.rs") -or
        -not (Test-OrdinalStringEqual ([string]$Corpus.normative_implementation.function) "declares_enabled_test") -or
        -not (Test-OrdinalStringEqual ([string]$Corpus.follower_implementation.path) "compat/upstream/validate.ps1") -or
        -not (Test-OrdinalStringEqual ([string]$Corpus.follower_implementation.function) "Test-DeclaresEnabledRustTest")) {
        Fail "enabled-test-oracle frozen provenance must name claw-conformance declares_enabled_test and validate.ps1 Test-DeclaresEnabledRustTest"
    }
    $cases = @($Corpus.cases)
    # The case count and the true/false split are pinned so that a case cannot be
    # deleted or flipped to hide a disagreement.
    if ($cases.Count -ne $ExpectedOracleCorpusCases) {
        Fail ("enabled-test-oracle must contain exactly {0} cases; found {1}" -f $ExpectedOracleCorpusCases, $cases.Count)
    }
    $names = @{}
    $trueCases = 0
    foreach ($case in $cases) {
        Assert-ExactPropertySet $case @("name", "source", "test", "expected") "enabled-test-oracle case"
        $name = [string]$case.name
        if ([string]::IsNullOrWhiteSpace($name)) {
            Fail "enabled-test-oracle case name must not be empty"
        }
        if ($names.ContainsKey($name)) {
            Fail "enabled-test-oracle case name '$name' is duplicated"
        }
        $names[$name] = $true
        if ($case.expected -isnot [bool]) {
            Fail "enabled-test-oracle case '$name' expected must be a boolean"
        }
        if ($case.expected) {
            $trueCases += 1
        }
        $actual = Test-DeclaresEnabledRustTest ([string]$case.source) ([string]$case.test)
        if ($actual -ne $case.expected) {
            Fail (("enabled-test oracle drift on case '{0}': the shared corpus records {1} but this port returned {2}. " +
                "the frozen expected result is authoritative; reconcile both implementations before changing this corpus.") -f
                $name, $case.expected, $actual)
        }
    }
    if ($trueCases -ne $ExpectedOracleCorpusTrue) {
        Fail ("enabled-test-oracle must record exactly {0} accepting cases; found {1}" -f $ExpectedOracleCorpusTrue, $trueCases)
    }
    $digest = Get-ObjectDigest $Corpus
    if (-not (Test-OrdinalStringEqual $digest $ExpectedOracleCorpusDigest)) {
        Fail ("enabled-test-oracle digest mismatch; expected {0}, found {1}" -f $ExpectedOracleCorpusDigest, $digest)
    }
}

function Assert-ReachabilityCorpusPath {
    param(
        [string]$Path,
        [string]$Context
    )
    Assert-RelativeSourcePath $Path $Context
    # Assert-RelativeSourcePath's character class admits "." and ".." as whole
    # segments. A corpus key containing a dot segment would let any harness that
    # materializes these fixtures write outside the fixture root, so reject them
    # here rather than trusting every future replayer to notice.
    foreach ($segment in $Path.Split("/")) {
        if ((Test-OrdinalStringEqual $segment ".") -or (Test-OrdinalStringEqual $segment "..")) {
            Fail "$Context '$Path' must not contain a dot segment"
        }
    }
}

# Every accepted canonical case, including future additions, must be registered
# here. The registry and corpus are exact sets: adding a case appends its name;
# removing or renaming one requires an explicit deletion from this never-remove
# list rather than hiding inside the count and digest updates every honest
# addition already requires.
$CanonicalReachabilityCaseNames = @(
    "ambiguity-directory-side",
    "ambiguity-file-side",
    "compiled-file-outside-any-package",
    "cross-package-also-own-package-accept",
    "cross-package-only-reject",
    "inline-path-mod-rs-accept",
    "inline-path-mod-rs-decoy",
    "inline-path-non-mod-rs-accept",
    "inline-path-non-mod-rs-module-dir-decoy",
    "inline-path-plain-child-accept",
    "nested-inline-path-accept",
    "nested-inline-path-file-dir-decoy",
    "peer1-explicit-bin-test-false-reject",
    "peer2-top-level-path-sibling",
    "peer2-top-level-path-sibling-decoy",
    "peer3-path-mod-rs-child",
    "peer3-path-mod-rs-child-decoy",
    "peer4-inline-path-propagates",
    "peer4-inline-path-propagates-decoy",
    "peer5-raw-string-path",
    "peer6-ambiguity-directory-side",
    "peer6-ambiguity-file-side",
    "peer7-excluded-workspace-root",
    "peer7-standalone-own-workspace-table-accept",
    "peer7-unbuildable-orphan-package-reject",
    "peer8-default-bench-reject",
    "peer8-default-example-reject",
    "peer8-enabled-integration-test-accept",
    "peer8-harness-false-target-reject",
    "peer8-src-bin-target-accept",
    "unambiguous-file-accept",
    "unambiguous-mod-rs-accept"
)

function Assert-ReachabilityCorpus {
    param([object]$Corpus)
    # Structural and digest pin only. This function deliberately does NOT
    # materialize the fixtures and replay them in-process: the resolver memoizes
    # per-crate compiled-file sets in script-scoped caches, and seeding those
    # caches from attacker-supplied fixture trees during a real validation run
    # would be a forgery vector, not a convenience. Behavioural replay belongs in
    # validate-self-test.ps1, where every case runs in an isolated child process
    # against its own repository root.
    Assert-ExactPropertySet $Corpus @(
        "schema_version", "purpose", "rule", "arbiter", "implementations", "cases"
    ) "reachability-corpus"
    if ($Corpus.schema_version -ne 1) {
        Fail "reachability-corpus schema_version must be 1"
    }
    $implementations = @($Corpus.implementations)
    if ($implementations.Count -ne 2) {
        Fail "reachability-corpus must record exactly the two resolvers it compares"
    }
    foreach ($implementation in $implementations) {
        Assert-ExactPropertySet $implementation @("path", "entry_point") "reachability-corpus.implementations"
    }
    if (-not (Test-OrdinalStringEqual ([string]$implementations[0].path) "crates/claw-conformance/src/claims.rs") -or
        -not (Test-OrdinalStringEqual ([string]$implementations[1].path) "compat/upstream/validate.ps1")) {
        Fail "reachability-corpus must name claw-conformance and validate.ps1 as the two compared resolvers"
    }
    $cases = @($Corpus.cases)
    $names = @{}
    $accepting = 0
    foreach ($case in $cases) {
        Assert-ExactPropertySet $case @("name", "files", "cite", "expect", "why") "reachability-corpus case"
        $name = [string]$case.name
        if ([string]::IsNullOrWhiteSpace($name)) {
            Fail "reachability-corpus case name must not be empty"
        }
        if ($names.ContainsKey($name)) {
            Fail "reachability-corpus case name '$name' is duplicated"
        }
        $names[$name] = $true
        $expect = [string]$case.expect
        if (-not (Test-OrdinalStringEqual $expect "accept") -and -not (Test-OrdinalStringEqual $expect "reject")) {
            Fail "reachability-corpus case '$name' expect must be 'accept' or 'reject'"
        }
        if (Test-OrdinalStringEqual $expect "accept") {
            $accepting += 1
        }
        if ([string]::IsNullOrWhiteSpace([string]$case.why)) {
            Fail "reachability-corpus case '$name' must record why the toolchain produces this verdict"
        }
        $fileNames = @($case.files.PSObject.Properties.Name)
        if ($fileNames.Count -lt 2) {
            Fail "reachability-corpus case '$name' must define a manifest and at least one source"
        }
        $hasManifest = $false
        foreach ($fileName in $fileNames) {
            Assert-ReachabilityCorpusPath $fileName ("reachability-corpus case '$name' file")
            if ($fileName.EndsWith("Cargo.toml", [System.StringComparison]::Ordinal)) {
                $hasManifest = $true
            }
        }
        if (-not $hasManifest) {
            Fail "reachability-corpus case '$name' must define at least one Cargo.toml"
        }
        # A case may only cite a file it actually defines. Without this a corpus
        # case could cite a path that exists in the real repository and quietly
        # assert a verdict about something the fixture never contained.
        $cite = [string]$case.cite
        Assert-ReachabilityCorpusPath $cite ("reachability-corpus case '$name' cite")
        if (-not $cite.EndsWith(".rs", [System.StringComparison]::Ordinal)) {
            Fail "reachability-corpus case '$name' must cite a .rs source"
        }
        $citeIsDefined = $false
        foreach ($fileName in $fileNames) {
            if (Test-OrdinalStringEqual $fileName $cite) {
                $citeIsDefined = $true
            }
        }
        if (-not $citeIsDefined) {
            Fail "reachability-corpus case '$name' cites '$cite', which the case does not define"
        }
    }
    $canonicalNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($canonicalName in $CanonicalReachabilityCaseNames) {
        if (-not $canonicalNames.Add([string]$canonicalName)) {
            Fail "canonical reachability case registry repeats '$canonicalName'"
        }
    }
    $missingCanonical = @()
    foreach ($canonicalName in $CanonicalReachabilityCaseNames) {
        if (-not $names.ContainsKey($canonicalName)) {
            $missingCanonical += $canonicalName
        }
    }
    if ($missingCanonical.Count -gt 0) {
        [Array]::Sort($missingCanonical, [StringComparer]::Ordinal)
        Fail ("reachability-corpus must not drop canonical cases; missing=[{0}]" -f ($missingCanonical -join ", "))
    }
    $unregistered = @()
    foreach ($name in $names.Keys) {
        if (-not $canonicalNames.Contains([string]$name)) {
            $unregistered += [string]$name
        }
    }
    if ($unregistered.Count -gt 0) {
        [Array]::Sort($unregistered, [StringComparer]::Ordinal)
        Fail ("new reachability-corpus cases must be appended to `$CanonicalReachabilityCaseNames; unregistered=[{0}]" -f
            ($unregistered -join ", "))
    }
    if ($cases.Count -ne $ExpectedReachabilityCorpusCases -or
        $CanonicalReachabilityCaseNames.Count -ne $ExpectedReachabilityCorpusCases) {
        Fail ("reachability-corpus and canonical registry must both contain exactly {0} cases; found corpus={1}, registry={2}" -f
            $ExpectedReachabilityCorpusCases, $cases.Count, $CanonicalReachabilityCaseNames.Count)
    }
    if ($accepting -ne $ExpectedReachabilityCorpusAccepting) {
        Fail ("reachability-corpus must record exactly {0} accepting cases; found {1}" -f $ExpectedReachabilityCorpusAccepting, $accepting)
    }
    $digest = Get-ObjectDigest $Corpus
    if (-not (Test-OrdinalStringEqual $digest $ExpectedReachabilityCorpusDigest)) {
        Fail ("reachability-corpus digest mismatch; expected {0}, found {1}" -f $ExpectedReachabilityCorpusDigest, $digest)
    }
}

function Assert-RustTestSymbol {
    param(
        [string]$Text,
        [string]$Symbol,
        [string]$RelativePath,
        [string]$Context
    )
    if (-not (Test-DeclaresEnabledRustTest $Text $Symbol)) {
        Fail "$Context cites test '$Symbol' that is not declared as an enabled #[test] in '$RelativePath'"
    }
}

# ---------------------------------------------------------------------------
# Cargo target reachability.
#
# Shared with crates/claw-conformance. Rust orchestrates target discovery through
# CargoTestTargets::load and membership through
# CargoTestTargets::contains_compiled_source; this script combines
# Test-CratePackageIsBuilt, Get-CrateTargetRootFiles and
# Get-CrateCompiledFileSet inside Assert-EvidenceFileIsCompiled. Rust's
# rust_module_references_from_tokens / reachable_rust_sources map to
# Get-RustModuleReferences / Get-CrateCompiledFileSet here.
#
# One current fail-closed extension is PowerShell-only:
# non-empty required-features target declarations are refused here, while the
# Rust loader still trusts cargo metadata's target.test flag. The shared corpus
# has no required-features case, so it does not arbitrate that gap; see README.md.
#
# A structurally perfect, enabled #[test] in a .rs file that no Cargo target
# compiles never runs. An author could add crates/foo/src/orphan.rs, never
# reference it from any mod, and cite a test inside it: the oracle would accept
# it, cargo test would never execute it, and the parity claim would be pure
# fiction. This rule closes that by requiring the cited file to be part of some
# target that cargo test actually builds.
#
# The reachable set is built from the auto-discovered target roots of the owning
# crate and then followed through mod declarations, honouring #[path = "..."].
# build.rs is deliberately NOT a root: cargo test does not run tests in a build
# script, so a #[test] there never executes either.
#
# Scope, stated honestly: this catches files that nothing references. It does
# not evaluate cfg predicates, so a module behind #[cfg(never)] still counts as
# referenced. Reachability is deliberately permissive wherever a false rejection
# would block honest evidence, because the disclosed vector is the unreferenced
# file, not the unreachable-under-all-configurations one.
# ---------------------------------------------------------------------------

function Join-RepositoryRelativePath {
    param([string]$Base, [string]$Relative)
    $parts = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrEmpty($Base)) {
        foreach ($part in $Base.Split("/")) {
            if (-not [string]::IsNullOrEmpty($part)) { [void]$parts.Add($part) }
        }
    }
    foreach ($part in $Relative.Split("/")) {
        if ([string]::IsNullOrEmpty($part) -or (Test-OrdinalStringEqual $part ".")) { continue }
        if (Test-OrdinalStringEqual $part "..") {
            if ($parts.Count -eq 0) { return $null }
            $parts.RemoveAt($parts.Count - 1)
            continue
        }
        [void]$parts.Add($part)
    }
    return ($parts -join "/")
}

function Get-RustModReferencesInRange {
    param([string[]]$Tokens, [int]$Start, [int]$End, [object[]]$Segments, [object]$Sink)
    $index = $Start
    while ($index -lt $End) {
        $attributeResult = Get-RustAttributes $Tokens $index $End
        $outer = @($attributeResult.attributes | Where-Object { -not $_.inner })
        $index = [int]$attributeResult.next
        if ($index -ge $End) { break }
        $itemStart = $index
        $index = Get-RustSkipVisibility $Tokens $index $End
        $index = Get-RustSkipItemModifiers $Tokens $index
        $matched = $false
        if ($index -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$index] "i:mod") -and
            ($index + 1) -lt $Tokens.Length -and $Tokens[$index + 1].StartsWith("i:", [StringComparison]::Ordinal)) {
            $name = $Tokens[$index + 1].Substring(2)
            $after = $index + 2
            # A path attribute governs an inline 'mod name { }' exactly as it
            # governs 'mod name;', so it has to be read before the two forms are
            # told apart rather than inside the semicolon branch only.
            $pathAttribute = $null
            $hasPathAttribute = $false
            foreach ($attribute in $outer) {
                if ($attribute.path.Length -eq 1 -and (Test-OrdinalStringEqual $attribute.path[0] "path")) {
                    $hasPathAttribute = $true
                    foreach ($token in $attribute.tokens) {
                        if ($token.StartsWith("s:", [StringComparison]::Ordinal)) {
                            $pathAttribute = $token.Substring(2)
                            break
                        }
                    }
                }
            }
            if ($after -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$after] "{")) {
                $close = Get-RustMatchingDelimiter $Tokens $after $End
                if ($close -lt 0) { $close = $End }
                $segment = [ordered]@{ name = $name; path = $pathAttribute; hasPath = $hasPathAttribute }
                Get-RustModReferencesInRange $Tokens ($after + 1) ([Math]::Min($close, $End)) ($Segments + @($segment)) $Sink
                $index = $close + 1
                $matched = $true
            } elseif ($after -lt $Tokens.Length -and (Test-OrdinalStringEqual $Tokens[$after] ";")) {
                [void]$Sink.Add([ordered]@{
                    segments = $Segments
                    name = $name
                    path = $pathAttribute
                    hasPath = $hasPathAttribute
                })
                $index = $after + 1
                $matched = $true
            }
        }
        if (-not $matched) {
            $index = Get-RustSkipItem $Tokens $index $End
        }
        if ($index -le $itemStart) { $index = $itemStart + 1 }
    }
}

function Get-RustModuleReferences {
    param([string]$Source)
    $tokens = Get-RustTokens $Source -WithStrings
    $sink = New-Object System.Collections.Generic.List[object]
    Get-RustModReferencesInRange $tokens 0 $tokens.Length @() $sink
    return ,$sink.ToArray()
}

function Get-CrateDirectoryForPath {
    param([string]$RelativePath)
    # Nearest ancestor holding a Cargo.toml that declares a [package]. A virtual
    # workspace manifest owns no sources and must not be treated as a crate.
    $segments = @($RelativePath.Split("/"))
    for ($i = $segments.Length - 1; $i -ge 0; $i -= 1) {
        $candidate = ($segments[0..([Math]::Max(0, $i - 1))] -join "/")
        if ($i -eq 0) { $candidate = "" }
        $manifest = Join-RepositoryRelativePath $candidate "Cargo.toml"
        $absolute = Resolve-RepositoryFilePath $manifest
        if ($null -ne $absolute) {
            $text = Get-RepositoryFileText $absolute
            if ($text -cmatch '(?m)^\s*\[package\]\s*$') {
                return [ordered]@{ directory = $candidate; manifest = $manifest; text = $text }
            }
        }
    }
    return $null
}

function Convert-CargoGlobToRegex {
    param([string]$Pattern)
    # cargo accepts glob patterns in workspace member and exclude lists. `*` and
    # `?` do not cross a directory separator; `**` does.
    $placeholder = [string][char]1
    $escaped = [regex]::Escape($Pattern)
    $escaped = $escaped.Replace('\*\*', $placeholder)
    $escaped = $escaped.Replace('\*', '[^/]*')
    $escaped = $escaped.Replace('\?', '[^/]')
    $escaped = $escaped.Replace($placeholder, '.*')
    return ('\A' + $escaped + '\z')
}

function Get-CargoWorkspaceSpec {
    param([string]$ManifestText)
    # `members` and `exclude` read from the [workspace] table itself. The
    # sub-tables [workspace.package], [workspace.dependencies] and
    # [workspace.lints.*] are deliberately NOT the workspace table: reading an
    # array of paths out of one of those would let an author claim membership in
    # a place cargo never consults, which is the same mistake as honouring a
    # bare `path =` under [dependencies.<name>] as a target.
    $inWorkspace = $false
    $hasWorkspace = $false
    $collecting = $null
    $members = New-Object System.Collections.Generic.List[string]
    $exclude = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($ManifestText -split "`n")) {
        $trimmed = $line.Trim()
        $header = [regex]::Match($trimmed, '\A\[\[?([A-Za-z0-9_.-]+)\]?\]\z')
        if ($header.Success) {
            $inWorkspace = (Test-OrdinalStringEqual $header.Groups[1].Value "workspace")
            if ($inWorkspace) { $hasWorkspace = $true }
            $collecting = $null
            continue
        }
        if (-not $inWorkspace) { continue }
        if ($null -eq $collecting) {
            $open = [regex]::Match($trimmed, '\A(members|exclude)\s*=\s*\[')
            if (-not $open.Success) { continue }
            $collecting = $open.Groups[1].Value
            $trimmed = $trimmed.Substring($open.Length)
        }
        # A plain assignment, never $(if ...): a subexpression writes to the
        # pipeline, and PowerShell enumerates a List there, so $sink would
        # become a detached array copy and every Add would be lost.
        $sink = $exclude
        if (Test-OrdinalStringEqual $collecting "members") { $sink = $members }
        foreach ($match in [regex]::Matches($trimmed, '"([^"]*)"')) {
            $value = $match.Groups[1].Value.Trim().TrimEnd("/")
            if (-not [string]::IsNullOrEmpty($value)) { [void]$sink.Add($value) }
        }
        if ($trimmed.Contains("]")) { $collecting = $null }
    }
    return [ordered]@{
        workspace = $hasWorkspace
        members = $members.ToArray()
        exclude = $exclude.ToArray()
    }
}

function Test-CargoPatternCoversPath {
    param([string]$Pattern, [string]$RelativeDirectory)
    # An exclude entry removes the named directory and everything beneath it, so
    # the pattern is tested against the directory and each of its ancestors.
    $expression = Convert-CargoGlobToRegex $Pattern
    $segments = @($RelativeDirectory.Split("/") | Where-Object { -not [string]::IsNullOrEmpty($_) })
    for ($i = 0; $i -lt $segments.Length; $i += 1) {
        $prefix = ($segments[0..$i] -join "/")
        if ([regex]::IsMatch($prefix, $expression)) { return $true }
    }
    return $false
}

function Test-CratePackageIsBuilt {
    param([string]$CrateDirectory, [string]$ManifestText)
    # Reachability from a target root proves cargo would compile a file WITHIN
    # its package. It says nothing about whether anything builds that package.
    # A package that no workspace lists is never built by `cargo test` at the
    # repository root, so a #[test] inside it never runs, and citing it is a
    # claim about code the repository does not execute. Adding one is a two-file
    # change that needs no unusual Rust and no manifest trickery, which makes it
    # the cheapest forgery available if membership is not checked.
    if ((Get-CargoWorkspaceSpec $ManifestText).workspace) {
        return [ordered]@{ built = $true; workspace = $CrateDirectory; reason = "root" }
    }
    $segments = @($CrateDirectory.Split("/") | Where-Object { -not [string]::IsNullOrEmpty($_) })
    for ($i = $segments.Length - 1; $i -ge 0; $i -= 1) {
        $directory = $(if ($i -eq 0) { "" } else { ($segments[0..($i - 1)] -join "/") })
        $manifest = Join-RepositoryRelativePath $directory "Cargo.toml"
        $absolute = Resolve-RepositoryFilePath $manifest
        if ($null -eq $absolute) { continue }
        $spec = Get-CargoWorkspaceSpec (Get-RepositoryFileText $absolute)
        if (-not $spec.workspace) { continue }
        # cargo stops at the FIRST [workspace] ancestor and that manifest alone
        # decides membership, so neither does this.
        $relative = $(if ([string]::IsNullOrEmpty($directory)) {
            $CrateDirectory
        } else {
            $CrateDirectory.Substring($directory.Length + 1)
        })
        foreach ($pattern in $spec.exclude) {
            if (Test-CargoPatternCoversPath $pattern $relative) {
                return [ordered]@{ built = $false; workspace = $directory; reason = "excluded" }
            }
        }
        foreach ($pattern in $spec.members) {
            if ([regex]::IsMatch($relative, (Convert-CargoGlobToRegex $pattern))) {
                return [ordered]@{ built = $true; workspace = $directory; reason = "member" }
            }
        }
        return [ordered]@{ built = $false; workspace = $directory; reason = "unlisted" }
    }
    return [ordered]@{ built = $true; workspace = $null; reason = "standalone" }
}

function Add-TomlArrayFragment {
    param(
        [string]$Text,
        [System.Collections.IDictionary]$State
    )
    # Minimal TOML array scanner for required-features. It is deliberately not a
    # feature resolver: it answers only whether the declared array is empty, while
    # respecting comments, quoted strings and arrays split across lines.
    for ($index = 0; $index -lt $Text.Length; $index += 1) {
        $character = $Text[$index]
        if ($State["in_basic"]) {
            if ($State["escaped"]) {
                $State["escaped"] = $false
            } elseif ($character -eq [char]92) {
                $State["escaped"] = $true
            } elseif ($character -eq [char]34) {
                $State["in_basic"] = $false
            }
            continue
        }
        if ($State["in_literal"]) {
            if ($character -eq [char]39) {
                $State["in_literal"] = $false
            }
            continue
        }
        if ($character -eq [char]35) {
            break
        }
        if ($character -eq [char]34) {
            if ($State["depth"] -gt 0) { $State["has_entry"] = $true }
            $State["in_basic"] = $true
            continue
        }
        if ($character -eq [char]39) {
            if ($State["depth"] -gt 0) { $State["has_entry"] = $true }
            $State["in_literal"] = $true
            continue
        }
        if ($character -eq [char]91) {
            if ($State["started"] -and $State["depth"] -gt 0) {
                $State["has_entry"] = $true
            }
            $State["started"] = $true
            $State["depth"] += 1
            continue
        }
        if ($character -eq [char]93) {
            if (-not $State["started"] -or $State["depth"] -le 0) {
                $State["invalid"] = $true
                $State["complete"] = $true
                break
            }
            $State["depth"] -= 1
            if ($State["depth"] -eq 0) {
                $State["complete"] = $true
                break
            }
            continue
        }
        if ($State["depth"] -gt 0 -and
            $character -ne [char]44 -and
            -not [char]::IsWhiteSpace($character)) {
            $State["has_entry"] = $true
        }
    }
}

function Get-CargoManifestTargetSections {
    param([string]$ManifestText)
    # Every [lib] / [[bin]] / [[test]] / [[bench]] / [[example]] block, with the
    # four keys that decide whether `cargo test` runs #[test] items in the
    # named file. Keys are read per block: a bare `path = "..."` also appears
    # under [dependencies.<name>], and honouring that would let an author bless
    # an orphan file by adding one line to a manifest instead of wiring the file
    # into the crate.
    $sections = New-Object System.Collections.Generic.List[object]
    $current = $null
    $requiredFeaturesState = $null
    $packageFlags = @{}
    $inPackage = $false
    foreach ($line in ($ManifestText -split "`n")) {
        $trimmed = $line.Trim()
        if ($null -ne $requiredFeaturesState) {
            Add-TomlArrayFragment $trimmed $requiredFeaturesState
            if ($requiredFeaturesState["complete"]) {
                $current.requiredFeatures =
                    $requiredFeaturesState["has_entry"] -or $requiredFeaturesState["invalid"]
                $requiredFeaturesState = $null
            }
            continue
        }
        $header = [regex]::Match($trimmed, '\A\[\[?([A-Za-z0-9_.-]+)\]?\]\z')
        if ($header.Success) {
            $kind = $header.Groups[1].Value
            $inPackage = (Test-OrdinalStringEqual $kind "package")
            if (Test-OrdinalContains @("lib", "bin", "test", "bench", "example") $kind) {
                $current = [ordered]@{
                    kind = $kind
                    path = $null
                    test = $null
                    harness = $null
                    requiredFeatures = $null
                }
                [void]$sections.Add($current)
            } else {
                $current = $null
            }
            continue
        }
        if ($inPackage) {
            $auto = [regex]::Match($trimmed, '\A(autobins|autotests|autobenches|autoexamples)\s*=\s*(true|false)\z')
            if ($auto.Success) { $packageFlags[$auto.Groups[1].Value] = (Test-OrdinalStringEqual $auto.Groups[2].Value "true") }
            continue
        }
        if ($null -eq $current) { continue }
        $declared = [regex]::Match($trimmed, '\Apath\s*=\s*"([^"]+)"\z')
        if ($declared.Success) { $current.path = $declared.Groups[1].Value; continue }
        $flag = [regex]::Match($trimmed, '\A(test|harness)\s*=\s*(true|false)\z')
        if ($flag.Success) { $current[$flag.Groups[1].Value] = (Test-OrdinalStringEqual $flag.Groups[2].Value "true") }
        $required = [regex]::Match($trimmed, '\Arequired-features\s*=\s*(.*)\z')
        if ($required.Success) {
            # Incomplete or malformed syntax remains fail-closed ($true).
            $current.requiredFeatures = $true
            $requiredFeaturesState = [ordered]@{
                started = $false
                depth = 0
                in_basic = $false
                in_literal = $false
                escaped = $false
                has_entry = $false
                invalid = $false
                complete = $false
            }
            Add-TomlArrayFragment $required.Groups[1].Value $requiredFeaturesState
            if ($requiredFeaturesState["complete"]) {
                $current.requiredFeatures =
                    $requiredFeaturesState["has_entry"] -or $requiredFeaturesState["invalid"]
                $requiredFeaturesState = $null
            }
        }
    }
    return [ordered]@{ sections = $sections.ToArray(); package = $packageFlags }
}

function Test-CargoSectionRunsTests {
    param([object]$Section)
    # cargo's per-kind defaults, measured against `cargo metadata` rather than
    # recalled: lib, bin and test targets are run by `cargo test`; bench and
    # example targets are NOT (they report test = false), so a #[test] inside
    # one never executes. An explicit `test = ...` overrides the default.
    # `harness = false` replaces the libtest harness with the target's own
    # main(), which makes every #[test] item in it inert, so it can never be
    # acceptance evidence whatever `test` says.
    if ($Section.harness -eq $false) { return $false }
    # A non-empty required-features declaration makes a plain cargo test skip the
    # target entirely. Presence is read, never resolved, because reproducing
    # Cargo's feature graph here would create a new way to bless a target Cargo
    # did not build. This outranks an explicit test = true. An empty array is not
    # a gate and remains accepted.
    if ($Section.requiredFeatures -eq $true) { return $false }
    if ($null -ne $Section.test) { return [bool]$Section.test }
    return (Test-OrdinalContains @("lib", "bin", "test") ([string]$Section.kind))
}

function Get-CrateTargetRootFiles {
    param([string]$CrateDirectory, [string]$ManifestText)
    $roots = New-Object System.Collections.Generic.List[object]
    $manifest = Get-CargoManifestTargetSections $ManifestText
    # A file named by an explicit target section is governed by that section
    # alone. cargo matches an explicit target to the auto-discovered file it
    # replaces, so re-adding it through auto-discovery would resurrect exactly
    # the target the manifest disabled -- an explicit `test = false` bin whose
    # path sits under src/bin/ would otherwise still be treated as a root.
    $explicitPaths = @{}
    $explicitKinds = @{}
    foreach ($section in $manifest.sections) {
        if ($null -eq $section.path) { continue }
        $explicitKinds[[string]$section.kind] = $true
        $declared = Join-RepositoryRelativePath $CrateDirectory ([string]$section.path)
        if ($null -ne $declared) { $explicitPaths[$declared] = $true }
    }
    # An explicit [lib] path replaces src/lib.rs rather than adding to it: cargo
    # builds the named file and never looks at src/lib.rs.
    foreach ($entry in @("src/lib.rs", "src/main.rs")) {
        if ($entry -eq "src/lib.rs" -and $explicitKinds.ContainsKey("lib")) { continue }
        $candidate = Join-RepositoryRelativePath $CrateDirectory $entry
        if ($explicitPaths.ContainsKey($candidate)) { continue }
        if ($null -ne (Resolve-RepositoryFilePath $candidate)) {
            [void]$roots.Add([ordered]@{ file = $candidate; directory = (Join-RepositoryRelativePath $CrateDirectory "src") })
        }
    }
    # Auto-discovered target directories that `cargo test` actually runs.
    # benches/ and examples/ are deliberately absent: their targets default to
    # test = false, so a #[test] in one is compiled but never run, and treating
    # them as roots would accept evidence that can never execute.
    $autoDirectories = [ordered]@{ "tests" = "autotests"; "src/bin" = "autobins" }
    foreach ($directory in $autoDirectories.Keys) {
        if ($manifest.package[$autoDirectories[$directory]] -eq $false) { continue }
        $relative = Join-RepositoryRelativePath $CrateDirectory $directory
        $absolute = $script:RepositoryRootFull
        foreach ($segment in $relative.Split("/")) {
            if (-not [string]::IsNullOrEmpty($segment)) { $absolute = Join-Path $absolute $segment }
        }
        foreach ($name in (Get-DirectoryEntryNames $absolute)) {
            $child = Join-RepositoryRelativePath $relative $name
            if ($name.EndsWith(".rs", [StringComparison]::Ordinal)) {
                if ($explicitPaths.ContainsKey($child)) { continue }
                if ($null -ne (Resolve-RepositoryFilePath $child)) {
                    [void]$roots.Add([ordered]@{ file = $child; directory = $relative })
                }
                continue
            }
            $nested = Join-RepositoryRelativePath $child "main.rs"
            if ($explicitPaths.ContainsKey($nested)) { continue }
            if ($null -ne (Resolve-RepositoryFilePath $nested)) {
                [void]$roots.Add([ordered]@{ file = $nested; directory = $child })
            }
        }
    }
    foreach ($section in $manifest.sections) {
        if ($null -eq $section.path) { continue }
        if (-not (Test-CargoSectionRunsTests $section)) { continue }
        $candidate = Join-RepositoryRelativePath $CrateDirectory ([string]$section.path)
        if ($null -ne $candidate -and $null -ne (Resolve-RepositoryFilePath $candidate)) {
            [void]$roots.Add([ordered]@{ file = $candidate; directory = ($candidate -replace '/[^/]+\z', '') })
        }
    }
    return ,$roots.ToArray()
}

function Get-AmbiguousModuleKey {
    # Ambiguity markers share the reachable-set hashtable, so they need a prefix
    # no repository-relative path can ever produce. This is a function rather
    # than a variable so that any harness which lifts the reachability rule out
    # of this file fails loudly instead of silently keying on the bare path.
    param([string]$Path)
    return ("!ambiguous-module:" + $Path)
}

function Get-CrateCompiledFileSet {
    param([string]$CrateDirectory, [string]$ManifestText)
    if ($script:CrateReachabilityCache.ContainsKey($CrateDirectory)) {
        return $script:CrateReachabilityCache[$CrateDirectory]
    }
    $reachable = @{}
    $queue = New-Object System.Collections.Generic.Queue[object]
    foreach ($root in (Get-CrateTargetRootFiles $CrateDirectory $ManifestText)) {
        if (-not $reachable.ContainsKey($root.file)) {
            $reachable[$root.file] = $true
            $queue.Enqueue($root)
        }
    }
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $absolute = Resolve-RepositoryFilePath $current.file
        if ($null -eq $absolute) { continue }
        foreach ($reference in (Get-RustModuleReferences (Get-RepositoryFileText $absolute))) {
            $scope = $current.directory
            $fileDirectory = Join-RepositoryRelativePath $current.file ".."
            # A path attribute on an INLINE module renames the directory its
            # children live in, so the enclosing scopes cannot be a list of plain
            # module names. Cargo compiles
            #   #[path = "actual"] mod outer { #[path = "proof.rs"] mod proof; }
            # as actual/proof.rs and never as outer/proof.rs, and it resolves a
            # top-level inline path against the directory holding the source file
            # exactly as it does for 'mod name;'.
            $scopeFailed = $false
            $depth = 0
            foreach ($segment in $reference.segments) {
                if ($segment.hasPath) {
                    if ($null -eq $segment.path) { $scopeFailed = $true; break }
                    if ($depth -eq 0) { $base = $fileDirectory } else { $base = $scope }
                    if ($null -eq $base) { $scopeFailed = $true; break }
                    $scope = Join-RepositoryRelativePath $base $segment.path
                } else {
                    $scope = Join-RepositoryRelativePath $scope $segment.name
                }
                if ($null -eq $scope) { $scopeFailed = $true; break }
                $depth = $depth + 1
            }
            if ($scopeFailed) { continue }
            if ($null -eq $scope) { continue }
            $candidates = @()
            $childDirectory = $null
            if ($reference.hasPath) {
                # A path attribute this reader cannot resolve to a string value
                # resolves to nothing at all. Falling back to name-based lookup
                # would bless '<scope>/<name>.rs' -- a file cargo never compiles
                # -- on the strength of an attribute that points somewhere else.
                if ($null -eq $reference.path) { continue }
                # Outside an inline module block a path attribute is relative to
                # the directory holding the source file, not to the module
                # directory. The two coincide for mod-rs files (crate roots and
                # mod.rs) and differ for every other file, so resolving against
                # the module directory both missed the real target and blessed a
                # same-named file one directory deeper.
                $base = $scope
                if (@($reference.segments).Count -eq 0) {
                    $base = $fileDirectory
                }
                if ($null -eq $base) { continue }
                $target = Join-RepositoryRelativePath $base $reference.path
                if ($null -ne $target) {
                    $candidates = @($target)
                    # A path naming a mod.rs makes that module mod-rs, so its own
                    # children live beside it rather than under a 'mod/' directory
                    # named after the file.
                    if ($target -cmatch '(?:\A|/)mod\.rs\z') {
                        $childDirectory = Join-RepositoryRelativePath $target ".."
                    } else {
                        $childDirectory = ($target -replace '\.rs\z', '')
                    }
                }
            } else {
                $fileCandidate = Join-RepositoryRelativePath $scope ($reference.name + ".rs")
                $directoryCandidate = Join-RepositoryRelativePath $scope ($reference.name + "/mod.rs")
                $fileExists = ($null -ne $fileCandidate) -and ($null -ne (Resolve-RepositoryFilePath $fileCandidate))
                $directoryExists = ($null -ne $directoryCandidate) -and ($null -ne (Resolve-RepositoryFilePath $directoryCandidate))
                if ($fileExists -and $directoryExists) {
                    # rustc refuses this outright (E0761: file for module found at
                    # both paths) and compiles NEITHER file, so blessing either
                    # one would cite a test out of a crate that does not build.
                    # Fail closed and remember both sides so the citation gets the
                    # specific reason instead of a misleading 'not wired in'.
                    $reachable[(Get-AmbiguousModuleKey $fileCandidate)] = $directoryCandidate
                    $reachable[(Get-AmbiguousModuleKey $directoryCandidate)] = $fileCandidate
                    continue
                }
                $candidates = @($fileCandidate, $directoryCandidate)
                $childDirectory = Join-RepositoryRelativePath $scope $reference.name
            }
            foreach ($candidate in $candidates) {
                if ($null -eq $candidate -or $reachable.ContainsKey($candidate)) { continue }
                if ($null -eq (Resolve-RepositoryFilePath $candidate)) { continue }
                $reachable[$candidate] = $true
                $queue.Enqueue([ordered]@{ file = $candidate; directory = $childDirectory })
            }
        }
    }
    $script:CrateReachabilityCache[$CrateDirectory] = $reachable
    return $reachable
}

function Assert-EvidenceFileIsCompiled {
    param([string]$RelativePath, [string]$Context)
    $crate = Get-CrateDirectoryForPath $RelativePath
    if ($null -eq $crate) {
        Fail ("$Context acceptance evidence '$RelativePath' is not inside a Cargo package, " +
            "so no cargo test target compiles it and the cited test can never run")
    }
    $membership = Test-CratePackageIsBuilt ([string]$crate.directory) ([string]$crate.text)
    if (-not $membership.built) {
        $workspaceLabel = $(if ([string]::IsNullOrEmpty([string]$membership.workspace)) {
            "the repository root workspace"
        } else {
            "the workspace at " + [string]$membership.workspace
        })
        $why = $(if (Test-OrdinalStringEqual ([string]$membership.reason) "excluded") {
            "its package is in that workspace's exclude list"
        } else {
            "its package is not in that workspace's members list"
        })
        Fail ("$Context acceptance evidence '$RelativePath' belongs to a Cargo package that nothing builds: " +
            "$why, so cargo test never compiles or runs it and the cited test proves nothing about the " +
            "shipped product. Reachability from a target root only establishes that cargo would compile the " +
            "file WITHIN its package. Add the package to $workspaceLabel, or cite a test in a package that " +
            "is already built.")
    }
    $reachable = Get-CrateCompiledFileSet ([string]$crate.directory) ([string]$crate.text)
    $ambiguityKey = Get-AmbiguousModuleKey $RelativePath
    if ($reachable.ContainsKey($ambiguityKey)) {
        Fail ("$Context acceptance evidence '$RelativePath' and '" + [string]$reachable[$ambiguityKey] + "' both " +
            "answer the same 'mod' declaration. rustc rejects that ambiguity outright (E0761: file for module " +
            "found at both paths) and compiles NEITHER file, so the crate does not build and the cited test can " +
            "never run. Delete or rename one of the two files, then cite the survivor.")
    }
    if (-not $reachable.ContainsKey($RelativePath)) {
        $crateLabel = $(if ([string]::IsNullOrEmpty([string]$crate.directory)) { "the repository root crate" } else { [string]$crate.directory })
        Fail ("$Context acceptance evidence '$RelativePath' is not reached by any cargo test target of $crateLabel. " +
            "It is not an auto-discovered target under tests/ or src/bin/, is not a manifest target that cargo test " +
            "runs, and no mod chain from that crate's roots declares it, so the cited test is never compiled or run. " +
            "Note that benches/ and examples/ targets default to test = false and never run #[test] items. " +
            "Wire the file into the crate, or cite a test in a file that is.")
    }
}

function Get-RepositoryRustFiles {
    # The sweep universe is git's tracked list, not a filesystem walk that
    # reimplements ignore rules and can silently admit untracked sources.
    $root = [string]$script:RepositoryRootFull
    $tracked = @(& git -C $root -c core.quotepath=off ls-files -- "*.rs" 2>$null)
    if ($LASTEXITCODE -ne 0) {
        Fail "-ReplayEvidenceSweep could not list tracked Rust files with git"
    }
    $results = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $tracked) {
        $relative = [string]$entry
        if ([string]::IsNullOrEmpty($relative)) { continue }
        if ($relative.StartsWith("compat/legacy/", [StringComparison]::Ordinal)) { continue }
        $results.Add($relative)
    }
    $results.Sort([System.StringComparer]::Ordinal)
    return ,$results.ToArray()
}

function Get-EvidenceFileReachability {
    param([string]$RelativePath)
    $resolved = Resolve-RepositoryFilePath $RelativePath
    if ($null -eq $resolved) {
        return [pscustomobject]@{
            verdict = "missing"
            reason = "the path is absent, non-ordinal, not a regular file, or traverses a reparse point"
        }
    }
    try {
        Assert-EvidenceFileIsCompiled $RelativePath "sweep"
        return [pscustomobject]@{
            verdict = "accept"
            reason = "the shipped reachability rule accepts the existing repository file"
        }
    } catch {
        return [pscustomobject]@{
            verdict = "reject"
            reason = [string]$_.Exception.Message
        }
    }
}

function Get-EvidenceSweepRecord {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Fail "$EvidenceSweepFileName is missing"
    }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and
        $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Fail "$EvidenceSweepFileName must be BOM-less UTF-8"
    }
    try {
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $rawText = $strictUtf8.GetString($bytes)
    } catch {
        Fail "$EvidenceSweepFileName must be valid BOM-less UTF-8"
    }
    if ([regex]::IsMatch($rawText, "`r(?!`n)")) {
        Fail "$EvidenceSweepFileName contains a bare CR; use uniform LF or uniform CRLF"
    }
    $hasCrlf = $rawText.Contains("`r`n")
    if ($hasCrlf -and $rawText.Replace("`r`n", "").Contains("`n")) {
        Fail "$EvidenceSweepFileName mixes LF and CRLF"
    }
    $text = $rawText.Replace("`r`n", "`n")
    if (-not $text.EndsWith("`n", [StringComparison]::Ordinal) -or
        $text.EndsWith("`n`n", [StringComparison]::Ordinal)) {
        Fail "$EvidenceSweepFileName must end with exactly one newline"
    }
    $lines = @($text.Substring(0, $text.Length - 1) -split "`n")
    $fixedHeaderLines = $EvidenceSweepPreamble.Count + 4
    if ($lines.Count -lt $fixedHeaderLines) {
        Fail "$EvidenceSweepFileName is truncated before its complete canonical header"
    }
    for ($index = 0; $index -lt $EvidenceSweepPreamble.Count; $index += 1) {
        $expected = [string]$EvidenceSweepPreamble[$index]
        if (-not (Test-OrdinalStringEqual ([string]$lines[$index]) $expected)) {
            Fail ("$EvidenceSweepFileName canonical header line {0} must be exactly '{1}', got '{2}'" -f
                ($index + 1), $expected, [string]$lines[$index])
        }
    }
    $generatedIndex = $EvidenceSweepPreamble.Count
    if (-not (Test-OrdinalStringEqual ([string]$lines[$generatedIndex]) $EvidenceSweepGeneratedByLine)) {
        Fail ("$EvidenceSweepFileName generated-by line must be exactly '{0}', got '{1}'" -f
            $EvidenceSweepGeneratedByLine, [string]$lines[$generatedIndex])
    }
    $baseCommitIndex = $generatedIndex + 1
    $baseCommitMatch = [regex]::Match(
        [string]$lines[$baseCommitIndex],
        '\A# base-commit: ([0-9a-f]{40})\z'
    )
    if (-not $baseCommitMatch.Success) {
        Fail ("$EvidenceSweepFileName canonical header line {0} must be " +
            "'# base-commit: <40 lowercase hex characters>'" -f ($baseCommitIndex + 1))
    }
    $sweptAtIndex = $baseCommitIndex + 1
    $sweptAtMatch = [regex]::Match(
        [string]$lines[$sweptAtIndex],
        '\A# swept-at: ([0-9]{4}-[0-9]{2}-[0-9]{2})\z'
    )
    if (-not $sweptAtMatch.Success) {
        Fail ("$EvidenceSweepFileName canonical header line {0} must be " +
            "'# swept-at: <ISO yyyy-MM-dd date>'" -f ($sweptAtIndex + 1))
    }
    $parsedDate = [datetime]::MinValue
    if (-not [datetime]::TryParseExact(
            $sweptAtMatch.Groups[1].Value,
            "yyyy-MM-dd",
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None,
            [ref]$parsedDate
        )) {
        Fail "$EvidenceSweepFileName swept-at value is not a real ISO yyyy-MM-dd date"
    }
    $totalsIndex = $sweptAtIndex + 1
    $totalsMatch = [regex]::Match(
        [string]$lines[$totalsIndex],
        '\A# totals: files=([0-9]+) accept=([0-9]+) reject=([0-9]+)\z'
    )
    if (-not $totalsMatch.Success) {
        Fail ("$EvidenceSweepFileName canonical header line {0} must be " +
            "'# totals: files=<n> accept=<n> reject=<n>'" -f ($totalsIndex + 1))
    }
    $rows = New-Object System.Collections.Generic.List[object]
    $previous = $null
    $accepted = 0
    $rejected = 0
    for ($index = $fixedHeaderLines; $index -lt $lines.Count; $index += 1) {
        $line = [string]$lines[$index]
        $tab = $line.IndexOf("`t", [StringComparison]::Ordinal)
        if ($tab -lt 0 -or
            $line.IndexOf("`t", $tab + 1, [StringComparison]::Ordinal) -ge 0) {
            Fail ("$EvidenceSweepFileName row {0} must contain exactly two fields separated by one TAB: '{1}'" -f
                ($index + 1), $line)
        }
        $verdict = $line.Substring(0, $tab)
        $path = $line.Substring($tab + 1)
        if (-not (Test-OrdinalStringEqual $verdict "accept") -and
            -not (Test-OrdinalStringEqual $verdict "reject")) {
            Fail "$EvidenceSweepFileName row $($index + 1) verdict must be exactly 'accept' or 'reject'"
        }
        if (-not $path.EndsWith(".rs", [StringComparison]::Ordinal)) {
            Fail "$EvidenceSweepFileName row path '$path' is not a .rs file"
        }
        Assert-EvidencePathShape $path "$EvidenceSweepFileName row"
        if ($null -ne $previous -and [string]::CompareOrdinal($path, $previous) -le 0) {
            Fail "$EvidenceSweepFileName rows must be strictly ascending by path; '$path' follows '$previous'"
        }
        $previous = $path
        if ($verdict -eq "accept") { $accepted += 1 } else { $rejected += 1 }
        $rows.Add([pscustomobject]@{ verdict = $verdict; path = $path })
    }
    $expectedTotals = "files={0} accept={1} reject={2}" -f $rows.Count, $accepted, $rejected
    $declaredTotals = [string]$lines[$totalsIndex].Substring("# totals: ".Length)
    if (-not (Test-OrdinalStringEqual $declaredTotals $expectedTotals)) {
        Fail ("$EvidenceSweepFileName totals line disagrees with its rows; header says '{0}', rows are '{1}'" -f
            $declaredTotals, $expectedTotals)
    }
    return [ordered]@{
        rows = $rows.ToArray()
        accepted = $accepted
        rejected = $rejected
        base_commit = $baseCommitMatch.Groups[1].Value
        swept_at = $sweptAtMatch.Groups[1].Value
    }
}

function Assert-EvidenceArtifact {
    param(
        [object]$Artifact,
        [string]$Context
    )
    # Every acceptance evidence artifact is a proof obligation: an existing file
    # plus the name of an ENABLED #[test] inside it. There is deliberately no
    # weaker artifact shape. A source file, a fixture, a workflow or a test file
    # with no test name proves nothing on its own and would not satisfy the Rust
    # parity harness either, so such pointers belong in the separate,
    # explicitly non-evidential implementation_pointers field.
    Assert-ExactPropertySet $Artifact @("path", "test") $Context
    $relativePath = [string](Get-PropertyValue $Artifact "path")
    $test = [string](Get-PropertyValue $Artifact "test")
    Assert-EvidencePathShape $relativePath $Context
    $absolutePath = Resolve-RepositoryFilePath $relativePath
    if ($null -eq $absolutePath) {
        Fail "$Context cites acceptance evidence path '$relativePath' that does not exist in the working tree"
    }
    if (-not (Test-PathHasExtension $relativePath @(".rs"))) {
        Fail "$Context acceptance evidence '$relativePath' must be a Rust source file containing the cited test"
    }
    if (-not ($test -cmatch '\A[a-z_][A-Za-z0-9_]*(?:::[a-z_][A-Za-z0-9_]*)*\z')) {
        Fail "$Context acceptance evidence test '$test' must be a Rust test path"
    }
    $text = Get-RepositoryFileText $absolutePath
    # The full module-qualified path is handed to the oracle, not just the last
    # segment: in-file module identity is part of the citation, so a test nested
    # in a module cannot be cited by a bare name or under a fabricated module.
    # There is deliberately no cheaper pre-check in front of the oracle; a second,
    # weaker rule would be a place for the two trust roots to disagree.
    Assert-RustTestSymbol $text $test $relativePath $Context
    # A structurally enabled test in a file no cargo target compiles never runs.
    Assert-EvidenceFileIsCompiled $relativePath $Context
}

function Assert-ImplementationPointer {
    param(
        [object]$Pointer,
        [string]$Context
    )
    # Never acceptance evidence. Still validated, so a pointer cannot be used to
    # smuggle a fabricated or legacy-JavaScript path into the ledger.
    Assert-ExactPropertySet $Pointer @("path", "note") $Context
    $relativePath = [string](Get-PropertyValue $Pointer "path")
    $note = [string](Get-PropertyValue $Pointer "note")
    Assert-EvidencePathShape $relativePath $Context
    if ($null -eq (Resolve-RepositoryFilePath $relativePath)) {
        Fail "$Context cites implementation pointer path '$relativePath' that does not exist in the working tree"
    }
    if ([string]::IsNullOrWhiteSpace($note)) {
        Fail "$Context implementation pointer must explain what the path contributes"
    }
}

function Assert-FeatureLifecycle {
    param(
        [object]$Feature,
        [string]$Context
    )
    $status = [string]$Feature.status
    $evidence = $Feature.acceptance_evidence
    $evidenceStatus = [string]$evidence.status
    $artifacts = @($evidence.artifacts)
    $differences = @($Feature.known_differences)
    $pointers = @()
    if (Has-Property $Feature "implementation_pointers") {
        $pointers = @($Feature.implementation_pointers)
    }

    if (-not (Test-OrdinalContains $AllowedFeatureStatuses $status)) {
        Fail "$Context has unsupported lifecycle status '$status'"
    }

    if (Test-OrdinalStringEqual $status "unimplemented") {
        if (-not (Test-OrdinalStringEqual $evidenceStatus "missing") -or $artifacts.Count -ne 0) {
            Fail "$Context must start unimplemented with an empty evidence placeholder"
        }
        if ($pointers.Count -ne 0) {
            Fail "$Context is unimplemented and must not record implementation pointers"
        }
        if ($differences.Count -ne 1 -or
            -not (Test-OrdinalStringEqual ([string]$differences[0]) $BaselineKnownDifference)) {
            Fail "$Context is unimplemented and must keep the frozen baseline known_differences placeholder"
        }
        return
    }

    $expectedEvidenceStatus = if (Test-OrdinalStringEqual $status "implemented") { "accepted" } else { "partial" }
    if (-not (Test-OrdinalStringEqual $evidenceStatus $expectedEvidenceStatus)) {
        Fail "$Context status '$status' requires acceptance_evidence.status '$expectedEvidenceStatus', got '$evidenceStatus'"
    }
    if ($artifacts.Count -eq 0) {
        Fail "$Context status '$status' requires at least one acceptance evidence artifact naming an enabled Rust test"
    }
    foreach ($difference in $differences) {
        if (Test-OrdinalStringEqual ([string]$difference) $BaselineKnownDifference) {
            Fail "$Context status '$status' must not keep the baseline no-implementation known_differences placeholder"
        }
    }

    $identities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($index = 0; $index -lt $artifacts.Count; $index += 1) {
        $artifact = $artifacts[$index]
        if (-not (Test-JsonObject $artifact)) {
            Fail "$Context acceptance evidence artifact $index must be a typed object"
        }
        if (-not $identities.Add((ConvertTo-CanonicalJson $artifact))) {
            Fail "$Context repeats the same acceptance evidence artifact"
        }
        Assert-EvidenceArtifact $artifact "$Context.acceptance_evidence.artifacts[$index]"
    }

    $pointerIdentities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($index = 0; $index -lt $pointers.Count; $index += 1) {
        $pointer = $pointers[$index]
        if (-not (Test-JsonObject $pointer)) {
            Fail "$Context implementation pointer $index must be a typed object"
        }
        if (-not $pointerIdentities.Add((ConvertTo-CanonicalJson $pointer))) {
            Fail "$Context repeats the same implementation pointer"
        }
        Assert-ImplementationPointer $pointer "$Context.implementation_pointers[$index]"
    }
}

function Format-LedgerDigestFile {
    param([System.Collections.IDictionary]$DigestsByPath)
    [string[]]$lines = @($LedgerDigestHeader)
    foreach ($spec in $LedgerSpecs) {
        $lines += ("{0}  {1}" -f [string]$DigestsByPath[[string]$spec.path], [string]$spec.path)
    }
    return (($lines -join "`n") + "`n")
}

function Read-LedgerDigestFile {
    param([string]$AbsolutePath)
    if (-not (Test-Path -LiteralPath $AbsolutePath -PathType Leaf)) {
        Fail "$LedgerDigestFileName is missing; regenerate it with validate.ps1 -WriteLedgerDigests"
    }
    $text = [System.IO.File]::ReadAllText($AbsolutePath).Replace("`r`n", "`n")
    $digests = [ordered]@{}
    foreach ($line in $text.Split("`n")) {
        if ($line.Length -eq 0 -or $line.StartsWith("#", [StringComparison]::Ordinal)) {
            continue
        }
        if (-not ($line -cmatch '\A([0-9a-f]{64})  ([A-Za-z0-9._/-]+)\z')) {
            Fail "$LedgerDigestFileName contains a malformed entry; regenerate it with validate.ps1 -WriteLedgerDigests"
        }
        $entryPath = $Matches[2]
        if ($digests.Contains($entryPath)) {
            Fail "$LedgerDigestFileName declares '$entryPath' more than once"
        }
        $digests[$entryPath] = $Matches[1]
    }
    foreach ($spec in $LedgerSpecs) {
        if (-not $digests.Contains([string]$spec.path)) {
            Fail "$LedgerDigestFileName does not declare a digest for $($spec.path)"
        }
    }
    if ($digests.Count -ne $LedgerSpecs.Count) {
        Fail "$LedgerDigestFileName must declare exactly $($LedgerSpecs.Count) ledger digests"
    }
    if (-not (Test-OrdinalStringEqual $text (Format-LedgerDigestFile $digests))) {
        Fail "$LedgerDigestFileName is not in canonical form; regenerate it with validate.ps1 -WriteLedgerDigests"
    }
    return $digests
}

function Write-LedgerDigestFile {
    param(
        [string]$AbsolutePath,
        [System.Collections.IDictionary]$DigestsByPath
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($AbsolutePath, (Format-LedgerDigestFile $DigestsByPath), $encoding)
}

function ConvertTo-DeclaredStatusTotals {
    param([string]$Declaration)
    $declared = [ordered]@{}
    foreach ($part in ([string]$Declaration -split ",")) {
        $trimmed = $part.Trim()
        if ($trimmed.Length -eq 0) {
            Fail "-WriteStatusTotals contains an empty declaration"
        }
        $match = [regex]::Match($trimmed, '\A(?<key>[a-z]+)=(?<value>0|[1-9][0-9]*)\z')
        if (-not $match.Success) {
            Fail ("-WriteStatusTotals must be " +
                "'unimplemented=<n>,partial=<n>,implemented=<n>'; got '$trimmed'")
        }
        $key = $match.Groups["key"].Value
        if ($declared.Contains($key)) {
            Fail "-WriteStatusTotals declares '$key' more than once"
        }
        $parsed = 0
        if (-not [int]::TryParse(
                $match.Groups["value"].Value,
                [System.Globalization.NumberStyles]::None,
                [System.Globalization.CultureInfo]::InvariantCulture,
                [ref]$parsed
            )) {
            Fail "-WriteStatusTotals value for '$key' is outside the supported integer range"
        }
        $declared[$key] = $parsed
    }
    foreach ($status in $AllowedFeatureStatuses) {
        if (-not $declared.Contains($status)) {
            Fail "-WriteStatusTotals must declare every status; '$status' is missing"
        }
    }
    foreach ($key in @($declared.Keys)) {
        if ($AllowedFeatureStatuses -notcontains $key) {
            Fail "-WriteStatusTotals declares unknown status '$key'"
        }
    }
    return $declared
}

function Get-UpdatedManifestStatusTotalsBytes {
    param(
        [string]$AbsolutePath,
        [System.Collections.IDictionary]$Totals
    )
    # Decode and re-encode explicitly so the writer preserves the input BOM state
    # as well as every byte outside the three integer tokens. ReadAllText hides a
    # UTF-8 BOM, which makes string round-trip comparisons unsuitable here.
    $source = [System.IO.File]::ReadAllBytes($AbsolutePath)
    $hasBom = $source.Length -ge 3 -and
        $source[0] -eq 0xEF -and $source[1] -eq 0xBB -and $source[2] -eq 0xBF
    $offset = $(if ($hasBom) { 3 } else { 0 })
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    try {
        $raw = $strictUtf8.GetString($source, $offset, $source.Length - $offset)
    } catch {
        Fail "manifest.json must be valid UTF-8"
    }
    $marker = '"status_totals"'
    $markerIndex = $raw.IndexOf($marker, [System.StringComparison]::Ordinal)
    if ($markerIndex -lt 0 -or
        $raw.IndexOf($marker, $markerIndex + $marker.Length, [System.StringComparison]::Ordinal) -ge 0) {
        Fail "manifest.json must contain exactly one status_totals object"
    }
    $open = $raw.IndexOf("{", $markerIndex, [System.StringComparison]::Ordinal)
    $close = $raw.IndexOf("}", [Math]::Max($open, 0), [System.StringComparison]::Ordinal)
    if ($open -lt 0 -or $close -lt 0) {
        Fail "manifest.json status_totals object is not well formed"
    }
    $block = $raw.Substring($open, $close - $open + 1)
    foreach ($status in $AllowedFeatureStatuses) {
        $pattern = '("' + [regex]::Escape($status) + '"\s*:\s*)\d+'
        if ([regex]::Matches($block, $pattern).Count -ne 1) {
            Fail "manifest.json status_totals must name '$status' exactly once"
        }
        $block = [regex]::Replace($block, $pattern, ('${1}' + [string]$Totals[$status]))
    }
    $updated = $raw.Substring(0, $open) + $block + $raw.Substring($close + 1)
    [byte[]]$encoded = $strictUtf8.GetBytes($updated)
    if (-not $hasBom) {
        return ,$encoded
    }
    [byte[]]$withBom = New-Object byte[] ($encoded.Length + 3)
    $withBom[0] = 0xEF
    $withBom[1] = 0xBB
    $withBom[2] = 0xBF
    [Array]::Copy($encoded, 0, $withBom, 3, $encoded.Length)
    return ,$withBom
}

function Write-BytesAtomically {
    param(
        [string]$AbsolutePath,
        [byte[]]$Bytes
    )
    $directory = [System.IO.Path]::GetDirectoryName($AbsolutePath)
    $temporaryPath = Join-Path $directory (
        "." + [System.IO.Path]::GetFileName($AbsolutePath) + "." +
        [System.IO.Path]::GetRandomFileName() + ".tmp"
    )
    try {
        [System.IO.File]::WriteAllBytes($temporaryPath, $Bytes)
        if ([System.IO.File]::Exists($AbsolutePath)) {
            [System.IO.File]::Replace($temporaryPath, $AbsolutePath, $null)
        } else {
            [System.IO.File]::Move($temporaryPath, $AbsolutePath)
        }
    } finally {
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
    }
}

function Write-ReviewedStatusTransition {
    param(
        [string]$ManifestPath,
        [byte[]]$ManifestBytes,
        [string]$DigestPath,
        [byte[]]$DigestBytes
    )
    # Stage both byte sequences before touching either reviewed file. If the
    # second atomic replacement fails, restore the first from its exact original
    # bytes so the composite operation leaves no half-transition or temp residue.
    $manifestExisted = [System.IO.File]::Exists($ManifestPath)
    $digestExisted = [System.IO.File]::Exists($DigestPath)
    $originalManifest = if ($manifestExisted) {
        [System.IO.File]::ReadAllBytes($ManifestPath)
    } else {
        $null
    }
    $originalDigest = if ($digestExisted) {
        [System.IO.File]::ReadAllBytes($DigestPath)
    } else {
        $null
    }
    try {
        Write-BytesAtomically $DigestPath $DigestBytes
        Write-BytesAtomically $ManifestPath $ManifestBytes
    } catch {
        $transitionFailure = $_
        try {
            if ($manifestExisted) {
                Write-BytesAtomically $ManifestPath $originalManifest
            } elseif ([System.IO.File]::Exists($ManifestPath)) {
                [System.IO.File]::Delete($ManifestPath)
            }
            if ($digestExisted) {
                Write-BytesAtomically $DigestPath $originalDigest
            } elseif ([System.IO.File]::Exists($DigestPath)) {
                [System.IO.File]::Delete($DigestPath)
            }
        } catch {
            Fail ("composite status transition failed and rollback also failed: transition='{0}'; rollback='{1}'" -f
                $transitionFailure.Exception.Message, $_.Exception.Message)
        }
        throw $transitionFailure
    }
}

function Assert-ExactCounts {
    param(
        [object]$Declared,
        [System.Collections.IDictionary]$Derived,
        [string]$Context
    )
    Assert-ExactPropertySet $Declared @($Derived.Keys) "$Context.counts"
    foreach ($key in $Derived.Keys) {
        if (-not (Test-JsonValueEqual (Get-PropertyValue $Declared $key) $Derived[$key])) {
            Fail "$Context count '$key' must be '$($Derived[$key])'"
        }
    }
}

function Get-ExpectedRecordId {
    param(
        [string]$InventoryId,
        [object]$Item
    )
    if (Test-OrdinalStringEqual $InventoryId "plugins") {
        $prefix = "plugin"
    } elseif (Test-OrdinalStringEqual $InventoryId "skills") {
        $prefix = "skill"
    } elseif (Test-OrdinalStringEqual $InventoryId "gateway-protocol") {
        $kind = [string]$Item.kind
        if (Test-OrdinalStringEqual $kind "method") {
            $prefix = "gateway_method"
        } elseif (Test-OrdinalStringEqual $kind "event") {
            $prefix = "gateway_event"
        } elseif (Test-OrdinalStringEqual $kind "role") {
            $prefix = "gateway_role"
        } elseif (Test-OrdinalStringEqual $kind "scope") {
            $prefix = "gateway_scope"
        } else {
            Fail "gateway-protocol item has invalid kind '$kind'"
        }
    } elseif (Test-OrdinalStringEqual $InventoryId "config-domains") {
        $prefix = "config_domain"
    } elseif (Test-OrdinalStringEqual $InventoryId "providers") {
        $prefix = "provider"
    } elseif (Test-OrdinalStringEqual $InventoryId "channels") {
        $prefix = "channel"
    } elseif (Test-OrdinalStringEqual $InventoryId "http-sse-endpoints") {
        $prefix = "http"
    } elseif (Test-OrdinalStringEqual $InventoryId "clients") {
        $prefix = "client"
    } elseif (Test-OrdinalStringEqual $InventoryId "migrations") {
        $prefix = "migration"
    } elseif (Test-OrdinalStringEqual $InventoryId "release-deployment") {
        $prefix = "release_surface"
    } else {
        Fail "unknown inventory $InventoryId"
    }
    return "${prefix}:$($Item.id)"
}

function Assert-InventoryItemContract {
    param(
        [string]$InventoryId,
        [object]$Item,
        [string]$Context
    )
    if (-not (Test-OrdinalStringEqual ([string]$Item.record_id) (Get-ExpectedRecordId $InventoryId $Item))) {
        Fail "$Context record_id does not match its natural id"
    }
    Assert-RelativeSourcePath ([string]$Item.source_path) "$Context.source_path"
    foreach ($optionalPath in @("catalog_source_path", "package_path")) {
        if (Has-Property $Item $optionalPath) {
            Assert-RelativeSourcePath ([string](Get-PropertyValue $Item $optionalPath)) "$Context.$optionalPath"
        }
    }

    if (Test-OrdinalStringEqual $InventoryId "plugins") {
        if (-not (Test-OrdinalContains @("core", "official_external", "source_only_qa") ([string]$Item.delivery_class))) {
            Fail "$Context has invalid delivery_class"
        }
    } elseif (Test-OrdinalStringEqual $InventoryId "skills") {
        if (-not (Test-OrdinalContains @("MIT", "Apache-2.0") ([string]$Item.license))) {
            Fail "$Context has invalid license"
        }
        if ((Test-OrdinalStringEqual ([string]$Item.id) "skill-creator") -ne
            (Test-OrdinalStringEqual ([string]$Item.license) "Apache-2.0")) {
            Fail "$Context has stale skill license evidence"
        }
    } elseif (Test-OrdinalStringEqual $InventoryId "gateway-protocol") {
        $base = @("record_id", "id", "classification", "source_path", "kind")
        $kind = [string]$Item.kind
        if (Test-OrdinalStringEqual $kind "method") {
            Assert-ExactPropertySet $Item ($base + @("scope", "advertised")) $Context
            if (-not (Test-OrdinalContains $AllowedOperatorScopes ([string]$Item.scope)) -or
                -not ($Item.advertised -is [bool])) {
                Fail "$Context has invalid method scope or advertised flag"
            }
        } elseif (Test-OrdinalStringEqual $kind "event") {
            Assert-ExactPropertySet $Item $base $Context
        } elseif (Test-OrdinalStringEqual $kind "role") {
            Assert-ExactPropertySet $Item ($base + @("protocol_class")) $Context
            if (-not (Test-OrdinalContains @("gateway", "closed_worker") ([string]$Item.protocol_class))) {
                Fail "$Context has invalid role protocol_class"
            }
        } elseif (Test-OrdinalStringEqual $kind "scope") {
            Assert-ExactPropertySet $Item $base $Context
        } else {
            Fail "$Context has invalid protocol kind"
        }
    } elseif (Test-OrdinalStringEqual $InventoryId "channels") {
        if (-not (Test-OrdinalContains @("source_manifest", "official_catalog_only") ([string]$Item.provenance))) {
            Fail "$Context has invalid provenance"
        }
        if ((Test-OrdinalStringEqual ([string]$Item.provenance) "source_manifest") -and
            -not (Has-Property $Item "plugin_id")) {
            Fail "$Context source manifest row requires plugin_id"
        }
        if ((Test-OrdinalStringEqual ([string]$Item.provenance) "official_catalog_only") -and
            -not (Has-Property $Item "package_name")) {
            Fail "$Context catalog-only row requires package_name"
        }
    } elseif (Test-OrdinalStringEqual $InventoryId "http-sse-endpoints") {
        if (-not (Test-OrdinalContains @("GET", "POST") ([string]$Item.method)) -or
            -not (Test-OrdinalContains @("none", "optional_sse", "long_poll", "streamable_http") ([string]$Item.streaming)) -or
            -not ([string]$Item.path).StartsWith("/", [StringComparison]::Ordinal)) {
            Fail "$Context has invalid HTTP method, path, or streaming kind"
        }
    } elseif (Test-OrdinalStringEqual $InventoryId "clients") {
        $allowedKinds = @(
            "browser_extension", "headless_node", "native_app", "native_helper",
            "native_sidecar", "terminal_app", "terminal_client", "web_app"
        )
        if (-not (Test-OrdinalContains $allowedKinds ([string]$Item.kind))) {
            Fail "$Context has invalid client kind"
        }
    } elseif (Test-OrdinalStringEqual $InventoryId "migrations") {
        if (-not (Test-OrdinalStringEqual ([string]$Item.kind) "migration_provider")) {
            Fail "$Context has invalid migration kind"
        }
    } elseif (Test-OrdinalStringEqual $InventoryId "release-deployment") {
        if (-not (Test-OrdinalContains @("release", "installation", "deployment") ([string]$Item.kind))) {
            Fail "$Context has invalid release/deployment kind"
        }
    }
}

function Get-DerivedInventoryCounts {
    param(
        [string]$InventoryId,
        [object[]]$Items
    )
    if (Test-OrdinalStringEqual $InventoryId "plugins") {
        return [ordered]@{
            total = $Items.Count
            core = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.delivery_class) "core"
            }).Count
            official_external = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.delivery_class) "official_external"
            }).Count
            source_only_qa = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.delivery_class) "source_only_qa"
            }).Count
        }
    }
    if (Test-OrdinalStringEqual $InventoryId "skills") {
        return [ordered]@{ total = $Items.Count; bundled = $Items.Count }
    }
    if (Test-OrdinalStringEqual $InventoryId "gateway-protocol") {
        $methods = @($Items | Where-Object {
            Test-OrdinalStringEqual ([string]$_.kind) "method"
        })
        return [ordered]@{
            total = $Items.Count
            methods = $methods.Count
            advertised_methods = @($methods | Where-Object { $_.advertised -eq $true }).Count
            events = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.kind) "event"
            }).Count
            roles = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.kind) "role"
            }).Count
            scopes = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.kind) "scope"
            }).Count
            dynamic_plugin_methods = "runtime-dependent"
        }
    }
    if (Test-OrdinalStringEqual $InventoryId "config-domains") {
        return [ordered]@{ total = $Items.Count }
    }
    if (Test-OrdinalStringEqual $InventoryId "providers") {
        $uniqueIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($item in $Items) {
            [void]$uniqueIds.Add([string]$item.id)
        }
        return [ordered]@{
            total = $Items.Count
            unique = $uniqueIds.Count
        }
    }
    if (Test-OrdinalStringEqual $InventoryId "channels") {
        return [ordered]@{
            total = $Items.Count
            source_manifest = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.provenance) "source_manifest"
            }).Count
            official_catalog_only = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.provenance) "official_catalog_only"
            }).Count
        }
    }
    if (Test-OrdinalStringEqual $InventoryId "http-sse-endpoints") {
        return [ordered]@{
            total = $Items.Count
            optional_sse = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.streaming) "optional_sse"
            }).Count
            long_poll = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.streaming) "long_poll"
            }).Count
            streamable_http = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.streaming) "streamable_http"
            }).Count
        }
    }
    if (Test-OrdinalStringEqual $InventoryId "clients") {
        return [ordered]@{ total = $Items.Count }
    }
    if (Test-OrdinalStringEqual $InventoryId "migrations") {
        return [ordered]@{ total = $Items.Count }
    }
    if (Test-OrdinalStringEqual $InventoryId "release-deployment") {
        return [ordered]@{
            total = $Items.Count
            release = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.kind) "release"
            }).Count
            installation = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.kind) "installation"
            }).Count
            deployment = @($Items | Where-Object {
                Test-OrdinalStringEqual ([string]$_.kind) "deployment"
            }).Count
        }
    }
    Fail "unknown inventory $InventoryId"
}

function Assert-ManifestDeclarations {
    param([object]$Manifest)
    Assert-ExactPropertySet $Manifest @(
        "schema_version",
        "artifact_set",
        "baseline_sha",
        "baseline_path",
        "feature_schema_path",
        "validation_script",
        "validation_self_test",
        "ledgers",
        "inventories",
        "canonical_counts",
        "evidence_policy"
    ) "manifest"
    if ($Manifest.schema_version -ne 1 -or
        -not (Test-OrdinalStringEqual ([string]$Manifest.artifact_set) "openclaw-upstream-compatibility-baseline") -or
        -not (Test-OrdinalStringEqual ([string]$Manifest.baseline_sha) $ExpectedSha) -or
        -not (Test-OrdinalStringEqual ([string]$Manifest.baseline_path) "baseline.json") -or
        -not (Test-OrdinalStringEqual ([string]$Manifest.feature_schema_path) "feature-ledger.schema.json") -or
        -not (Test-OrdinalStringEqual ([string]$Manifest.validation_script) "validate.ps1") -or
        -not (Test-OrdinalStringEqual ([string]$Manifest.validation_self_test) "validate-self-test.ps1")) {
        Fail "manifest fixed metadata mismatch"
    }

    $ledgerDeclarations = @($Manifest.ledgers)
    if ($ledgerDeclarations.Count -ne $LedgerSpecs.Count) {
        Fail "manifest must declare exactly 3 ledgers"
    }
    foreach ($spec in $LedgerSpecs) {
        $matches = @($ledgerDeclarations | Where-Object {
            Test-OrdinalStringEqual ([string]$_.path) ([string]$spec.path)
        })
        if ($matches.Count -ne 1) {
            Fail "manifest must declare ledger $($spec.path) exactly once"
        }
        Assert-ExactPropertySet $matches[0] @("path", "classification", "expected_features") "manifest.$($spec.path)"
        if (-not (Test-OrdinalStringEqual ([string]$matches[0].classification) ([string]$spec.classification)) -or
            [int]$matches[0].expected_features -ne [int]$spec.expected_features) {
            Fail "manifest ledger declaration drift for $($spec.path)"
        }
    }

    $inventoryDeclarations = @($Manifest.inventories)
    if ($inventoryDeclarations.Count -ne $InventorySpecs.Count) {
        Fail "manifest must declare exactly 10 inventories"
    }
    foreach ($inventoryId in $InventorySpecs.Keys) {
        $spec = $InventorySpecs[$inventoryId]
        $matches = @($inventoryDeclarations | Where-Object {
            Test-OrdinalStringEqual ([string]$_.path) ([string]$spec.path)
        })
        if ($matches.Count -ne 1) {
            Fail "manifest must declare inventory $($spec.path) exactly once"
        }
        Assert-ExactPropertySet $matches[0] @("path", "expected_items") "manifest.$($spec.path)"
        if ([int]$matches[0].expected_items -ne [int]$spec.expected_items) {
            Fail "manifest inventory declaration drift for $($spec.path)"
        }
    }

    Assert-ExactCounts $Manifest.canonical_counts $ExpectedCanonicalCounts "manifest"
    Assert-ExactPropertySet $Manifest.evidence_policy @(
        "initial_status",
        "acceptance_evidence_state",
        "legacy_typescript_is_not_rust_acceptance_evidence",
        "allowed_statuses",
        "artifact_fields",
        "every_artifact_names_an_enabled_rust_test",
        "implementation_pointers_are_not_acceptance_evidence",
        "status_totals"
    ) "manifest.evidence_policy"
    if (-not (Test-OrdinalStringEqual ([string]$Manifest.evidence_policy.initial_status) "unimplemented") -or
        -not (Test-OrdinalStringEqual ([string]$Manifest.evidence_policy.acceptance_evidence_state) "missing") -or
        $Manifest.evidence_policy.legacy_typescript_is_not_rust_acceptance_evidence -ne $true) {
        Fail "manifest evidence policy mismatch"
    }
    if (-not (Test-JsonValueEqual $Manifest.evidence_policy.allowed_statuses $AllowedFeatureStatuses) -or
        -not (Test-JsonValueEqual $Manifest.evidence_policy.artifact_fields $ArtifactFields) -or
        $Manifest.evidence_policy.every_artifact_names_an_enabled_rust_test -ne $true -or
        $Manifest.evidence_policy.implementation_pointers_are_not_acceptance_evidence -ne $true) {
        Fail "manifest evidence lifecycle policy mismatch"
    }
    Assert-ExactPropertySet $Manifest.evidence_policy.status_totals $AllowedFeatureStatuses "manifest.evidence_policy.status_totals"
    foreach ($status in $AllowedFeatureStatuses) {
        $declaredTotal = Get-PropertyValue $Manifest.evidence_policy.status_totals $status
        # PowerShell Core parses JSON integers as Int64 while Windows PowerShell
        # produces Int32, so never test against a single concrete numeric type.
        if (-not (Test-JsonInteger $declaredTotal) -or [long]$declaredTotal -lt 0) {
            Fail "manifest.evidence_policy.status_totals.$status must be a non-negative integer"
        }
    }
}

$script:RepositoryRootFull = Resolve-RepositoryRoot $RepositoryRoot
$declaredStatusTotals = $null
if ($WriteStatusTotalsRequested) {
    $declaredStatusTotals = ConvertTo-DeclaredStatusTotals $WriteStatusTotals
}

# Runs before any contract file is read, in both verify and write mode, so a host
# whose globalisation or JSON behaviour differs from a conforming host fails
# loudly instead of silently computing a different digest.
Assert-PortabilityInvariants

$actualFilePaths = @(
    Get-ChildItem -LiteralPath $Root -Recurse -File -Force | ForEach-Object {
        $relative = $_.FullName.Substring($Root.Length)
        while ($relative.StartsWith("\", [StringComparison]::Ordinal) -or
            $relative.StartsWith("/", [StringComparison]::Ordinal)) {
            $relative = $relative.Substring(1)
        }
        $relative.Replace("\", "/")
    }
)
$actualJsonPaths = @($actualFilePaths | Where-Object { $_.EndsWith(".json", [StringComparison]::Ordinal) })
$expectedFilePaths = @($ExpectedJsonPaths + $ExpectedNonJsonPaths)
if ($WriteLedgerDigests -and
    -not (Test-Path -LiteralPath (Join-Path $Root $LedgerDigestFileName) -PathType Leaf)) {
    $expectedFilePaths = @(
        $expectedFilePaths | Where-Object { -not (Test-OrdinalStringEqual $_ $LedgerDigestFileName) }
    )
}
if ($ReplayEvidenceSweep -and
    -not (Test-Path -LiteralPath (Join-Path $Root $EvidenceSweepFileName) -PathType Leaf)) {
    $expectedFilePaths = @(
        $expectedFilePaths | Where-Object { -not (Test-OrdinalStringEqual $_ $EvidenceSweepFileName) }
    )
}
$missingFiles = @($expectedFilePaths | Where-Object { -not (Test-OrdinalContains $actualFilePaths $_) })
$unexpectedFiles = @($actualFilePaths | Where-Object { -not (Test-OrdinalContains $expectedFilePaths $_) })
if ($actualFilePaths.Count -ne $expectedFilePaths.Count -or
    $missingFiles.Count -gt 0 -or
    $unexpectedFiles.Count -gt 0) {
    Fail "fixed artifact topology mismatch; missing=[$($missingFiles -join ',')], unexpected=[$($unexpectedFiles -join ',')]"
}
$missingJsonFiles = @($ExpectedJsonPaths | Where-Object { -not (Test-OrdinalContains $actualJsonPaths $_) })
$unexpectedJsonFiles = @($actualJsonPaths | Where-Object { -not (Test-OrdinalContains $ExpectedJsonPaths $_) })
if ($actualJsonPaths.Count -ne 18 -or
    $missingJsonFiles.Count -gt 0 -or
    $unexpectedJsonFiles.Count -gt 0) {
    Fail ("fixed JSON topology mismatch; expected 18 JSON artifacts, found {0}; missing=[{1}], unexpected=[{2}]" -f
        $actualJsonPaths.Count, ($missingJsonFiles -join ','), ($unexpectedJsonFiles -join ','))
}

# The self-test is the only thing that proves the rules below actually reject a
# forgery, and nothing in CI runs it. Verify the instrument is intact before its
# verdicts are relied on. Placed after the topology check so a MISSING self-test
# is still reported as a topology failure rather than a digest mismatch, and the
# comparison is over LF-normalised text so the answer is identical on Windows and
# on Linux CI.
$selfTestPath = Join-Path $Root "validate-self-test.ps1"
$selfTestText = [System.IO.File]::ReadAllText($selfTestPath) -replace "`r`n", "`n"
$selfTestDigest = Get-Sha256Text $selfTestText
if (-not (Test-OrdinalStringEqual $selfTestDigest $ExpectedSelfTestDigest)) {
    Fail ("validate-self-test.ps1 digest mismatch; expected {0}, found {1}. The anti-forgery self-test is a frozen trust-root artifact; regenerating it is a reviewed edit to `$ExpectedSelfTestDigest, never an automatic step." -f
        $ExpectedSelfTestDigest, $selfTestDigest)
}

$readmePath = Join-Path $Root "README.md"
$readmeText = [System.IO.File]::ReadAllText($readmePath) -replace "`r`n", "`n"
$readmeDigest = Get-Sha256Text $readmeText
if (-not (Test-OrdinalStringEqual $readmeDigest $ExpectedReadmeDigest)) {
    Fail ("README.md digest mismatch; expected {0}, found {1}. README.md is the normative specification " +
        "and must be re-pinned in the same reviewed commit." -f $ExpectedReadmeDigest, $readmeDigest)
}

$documents = @{}
foreach ($relativePath in $ExpectedJsonPaths) {
    $documents[$relativePath] = Read-Json (Join-Path $Root $relativePath)
}

# Prove both enabled-test implementations still agree with the frozen oracle
# before any evidence is judged. A drifted implementation must never get the
# chance to accept or reject a parity claim.
Assert-EnabledTestOracle $documents["enabled-test-oracle.json"]
Assert-ReachabilityCorpus $documents["reachability-corpus.json"]

$baseline = $documents["baseline.json"]
Assert-ExactPropertySet $baseline @("schema_version", "upstream", "stable_release", "gateway_protocol", "licensing") "baseline"
Assert-ExactPropertySet $baseline.upstream @(
    "repository", "repository_url", "branch", "commit_sha", "tree_sha", "parent_sha",
    "commit_timestamp", "commit_url", "commit_signature_verified", "package_name",
    "package_version", "package_manifest_path"
) "baseline.upstream"
if ($baseline.schema_version -ne 1 -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.repository) "openclaw/openclaw") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.repository_url) "https://github.com/openclaw/openclaw") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.branch) "main") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.commit_sha) $ExpectedSha) -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.tree_sha) "ba3177d3dd666b702d59c4daab74f62a9f7a84fb") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.parent_sha) "a674ce5e0d1ab0774546086fa7b2730516eca176") -or
    -not (Test-OrdinalStringEqual (ConvertTo-ContractString $baseline.upstream.commit_timestamp) "2026-07-13T03:29:58Z") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.commit_url) "https://github.com/openclaw/openclaw/commit/b43e832fcc8000ed7287c7accc54e381db607f85") -or
    $baseline.upstream.commit_signature_verified -ne $true -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.package_name) "openclaw") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.package_version) "2026.7.2") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.package_manifest_path) "package.json")) {
    Fail "baseline upstream provenance mismatch"
}
Assert-ExactPropertySet $baseline.stable_release @(
    "tag", "name", "tag_object_sha", "commit_sha", "published_at", "release_url"
) "baseline.stable_release"
if (-not (Test-OrdinalStringEqual ([string]$baseline.stable_release.tag) "v2026.6.11") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.stable_release.name) "openclaw 2026.6.11") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.stable_release.tag_object_sha) "08d1bbad1bd6ee5700082e1c0f65f63f07600d1f") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.stable_release.commit_sha) "e085fa1a3ffd32d0ea6917e1e6fb4ecbffbb77d2") -or
    -not (Test-OrdinalStringEqual (ConvertTo-ContractString $baseline.stable_release.published_at) "2026-06-30T16:06:39Z") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.stable_release.release_url) "https://github.com/openclaw/openclaw/releases/tag/v2026.6.11")) {
    Fail "stable release provenance mismatch"
}
Assert-ExactPropertySet $baseline.gateway_protocol @(
    "current", "minimum_general_client", "minimum_authenticated_node", "minimum_probe",
    "compatibility_window", "source_path", "documentation_path"
) "baseline.gateway_protocol"
if ($baseline.gateway_protocol.current -ne 4 -or
    $baseline.gateway_protocol.minimum_general_client -ne 4 -or
    $baseline.gateway_protocol.minimum_authenticated_node -ne 3 -or
    $baseline.gateway_protocol.minimum_probe -ne 3 -or
    -not (Test-OrdinalStringEqual ([string]$baseline.gateway_protocol.compatibility_window) "Authenticated role=node and client.mode=node clients may use v3 (N-1); general clients require v4.") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.gateway_protocol.source_path) "packages/gateway-protocol/src/version.ts") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.gateway_protocol.documentation_path) "docs/gateway/protocol.md")) {
    Fail "Gateway protocol baseline mismatch"
}
Assert-ExactPropertySet $baseline.licensing @(
    "repository_license", "repository_license_path", "repository_copyright",
    "third_party_notices_path", "exceptions", "content_policy"
) "baseline.licensing"
if (-not (Test-OrdinalStringEqual ([string]$baseline.licensing.repository_license) "MIT") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.licensing.repository_license_path) "LICENSE") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.licensing.repository_copyright) "Copyright (c) 2026 OpenClaw Foundation") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.licensing.third_party_notices_path) "THIRD_PARTY_NOTICES.md") -or
    @($baseline.licensing.exceptions).Count -ne 1 -or
    -not (Test-OrdinalStringEqual ([string]$baseline.licensing.exceptions[0].path) "skills/skill-creator/license.txt") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.licensing.exceptions[0].license) "Apache-2.0") -or
    -not (Test-OrdinalStringEqual ([string]$baseline.licensing.content_policy) "Contracts, identifiers, paths, metadata, and evidence references only; no upstream implementation code is copied.")) {
    Fail "baseline licensing metadata mismatch"
}
Assert-ExactPropertySet $baseline.licensing.exceptions[0] @("path", "license") "baseline.licensing.exceptions[0]"

$schema = $documents["feature-ledger.schema.json"]
if (-not (Test-OrdinalStringEqual ([string]$schema.'$schema') "https://json-schema.org/draft/2020-12/schema") -or
    -not (Test-OrdinalStringEqual ([string]$schema.'$id') "https://github.com/GTAStudio/GTA-Claw/compat/upstream/feature-ledger.schema.json") -or
    -not (Test-OrdinalStringEqual (Get-ObjectDigest $schema) $ExpectedSchemaDigest)) {
    Fail ("feature ledger schema is not the frozen Draft 2020-12 contract (expected digest {0}, computed {1})" -f
        $ExpectedSchemaDigest, (Get-ObjectDigest $schema))
}

$manifestPath = Join-Path $Root "manifest.json"
$manifest = $documents["manifest.json"]
Assert-ManifestDeclarations $manifest

$ledgerDigestPath = Join-Path $Root $LedgerDigestFileName
$computedLedgerDigests = [ordered]@{}
$computedFrozenDigests = [ordered]@{}
foreach ($spec in $LedgerSpecs) {
    $ledger = $documents[$spec.path]
    Assert-JsonSchema $ledger $schema $schema '$'
    if (-not (Test-OrdinalStringEqual ([string]$ledger.ledger_id) ([string]$spec.ledger_id)) -or
        -not (Test-OrdinalStringEqual ([string]$ledger.classification) ([string]$spec.classification)) -or
        -not (Test-OrdinalStringEqual ([string]$ledger.baseline_sha) $ExpectedSha)) {
        Fail "$($spec.path) fixed ledger metadata mismatch"
    }
    $features = @($ledger.features)
    if ($features.Count -ne [int]$spec.expected_features) {
        Fail "$($spec.path) must contain exactly $($spec.expected_features) features"
    }
    # Computed here but asserted after the per-feature checks and the stored
    # digest comparison, so a mutation those catch keeps its own specific
    # rejection reason. This check is the residual: it exists for descriptive
    # edits that nothing else covers.
    $computedFrozenDigests[[string]$spec.path] = Get-LedgerFrozenDigest $features
    $computedLedgerDigests[[string]$spec.path] = Get-FeatureDigest $features
}

if ($WriteLedgerDigests -and -not $WriteStatusTotalsRequested) {
    # Preserve the existing standalone anti-forgery workflow: the reviewed
    # mutable ledger fields are re-blessed before their semantic checks run.
    # Composite status transitions defer both reviewed writes until all checks
    # pass, so a rejected declaration leaves neither file changed.
    Write-LedgerDigestFile $ledgerDigestPath $computedLedgerDigests
} elseif (-not $WriteStatusTotalsRequested) {
    $storedLedgerDigests = Read-LedgerDigestFile $ledgerDigestPath
    foreach ($spec in $LedgerSpecs) {
        if (-not (Test-OrdinalStringEqual `
                    ([string]$computedLedgerDigests[[string]$spec.path]) `
                    ([string]$storedLedgerDigests[[string]$spec.path]))) {
            Fail "$($spec.path) canonical feature/source evidence fingerprint mismatch"
        }
    }
}

$featureIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$featureCount = 0
$statusTotals = [ordered]@{}
foreach ($status in $AllowedFeatureStatuses) {
    $statusTotals[$status] = 0
}
foreach ($spec in $LedgerSpecs) {
    $ledger = $documents[$spec.path]
    foreach ($feature in @($ledger.features)) {
        $featureCount += 1
        if (-not $featureIds.Add([string]$feature.feature_id)) {
            Fail "duplicate feature_id '$($feature.feature_id)'"
        }
        if (-not (Test-OrdinalStringEqual ([string]$feature.classification) ([string]$ledger.classification))) {
            Fail "$($feature.feature_id) classification does not match its ledger"
        }
        Assert-FeatureLifecycle $feature ([string]$feature.feature_id)
        if (-not (Test-OrdinalStringEqual ([string]$feature.last_verified_sha) $ExpectedSha)) {
            Fail "$($feature.feature_id) last_verified_sha mismatch"
        }
        $statusTotals[[string]$feature.status] += 1
    }
}
if ($LedgerSpecs.Count -ne 3 -or $featureCount -ne 47) {
    Fail "fixed ledger totals must be 3 ledgers and 47 features"
}
# Runs in write mode too, so a command cannot complete after frozen ledger text
# was edited. Standalone -WriteLedgerDigests intentionally writes its reviewed
# digest file first; the composite status transition defers both writes until
# this and every later semantic check have passed.
foreach ($spec in $LedgerSpecs) {
    if (-not (Test-OrdinalStringEqual `
                ([string]$computedFrozenDigests[[string]$spec.path]) `
                ([string]$spec.frozen_digest))) {
        Fail ("$($spec.path) frozen feature text changed; only status, " +
            "acceptance_evidence.status, acceptance_evidence.artifacts, " +
            "implementation_pointers and known_differences may change")
    }
}
if ($WriteStatusTotalsRequested) {
    foreach ($status in $AllowedFeatureStatuses) {
        if ($statusTotals[$status] -ne $declaredStatusTotals[$status]) {
            Fail ("-WriteStatusTotals declaration disagrees with validated ledger rows: " +
                "{0} declared {1}, computed {2}" -f
                $status, $declaredStatusTotals[$status], $statusTotals[$status])
        }
    }
} else {
    Assert-ExactCounts $manifest.evidence_policy.status_totals $statusTotals "manifest.evidence_policy.status_totals"
}
$missingEvidenceCount = $statusTotals["unimplemented"]

$globalRecordIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$inventoryRowCount = 0
$derivedByInventory = [ordered]@{}
foreach ($inventoryId in $InventorySpecs.Keys) {
    $spec = $InventorySpecs[$inventoryId]
    $inventory = $documents[$spec.path]
    Assert-ExactPropertySet $inventory @(
        "schema_version", "inventory_id", "classification", "baseline_sha", "counts", "items"
    ) $spec.path
    if ($inventory.schema_version -ne 1 -or
        -not (Test-OrdinalStringEqual ([string]$inventory.inventory_id) ([string]$inventoryId)) -or
        -not (Test-OrdinalStringEqual ([string]$inventory.classification) ([string]$spec.classification)) -or
        -not (Test-OrdinalStringEqual ([string]$inventory.baseline_sha) $ExpectedSha)) {
        Fail "$($spec.path) fixed inventory metadata mismatch"
    }
    if (-not ($inventory.items -is [System.Array])) {
        Fail "$($spec.path).items must be an array"
    }
    $items = @($inventory.items)
    if ($items.Count -ne [int]$spec.expected_items) {
        Fail "$($spec.path) must contain exactly $($spec.expected_items) rows"
    }

    $naturalIdentities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    for ($index = 0; $index -lt $items.Count; $index += 1) {
        $item = $items[$index]
        $context = "$($spec.path).items[$index]"
        Assert-RequiredProperties $item @($spec.required_fields) $context
        $unexpectedFields = @(
            (Get-PropertyNames $item) |
                Where-Object { -not (Test-OrdinalContains @($spec.allowed_fields) $_) }
        )
        if ($unexpectedFields.Count -gt 0) {
            Fail "$context contains unsupported fields [$($unexpectedFields -join ',')]"
        }
        foreach ($field in @("record_id", "id", "classification", "source_path")) {
            if ([string]::IsNullOrWhiteSpace([string](Get-PropertyValue $item $field))) {
                Fail "$context has empty required field $field"
            }
        }
        if (-not (Test-OrdinalContains $AllowedClassifications ([string]$item.classification))) {
            Fail "$context is unclassified"
        }
        if (-not (Test-OrdinalStringEqual ([string]$inventoryId) "http-sse-endpoints") -and
            -not (Test-OrdinalStringEqual ([string]$item.classification) ([string]$spec.classification))) {
            Fail "$context classification differs from its inventory"
        }
        if (-not $globalRecordIds.Add([string]$item.record_id)) {
            Fail "duplicate global inventory record_id $($item.record_id)"
        }
        $naturalIdentityFields = [ordered]@{}
        foreach ($field in @($spec.natural_key_fields)) {
            $naturalIdentityFields[$field] = Get-PropertyValue $item $field
        }
        $naturalIdentity = ConvertTo-CanonicalJson ([pscustomobject]$naturalIdentityFields)
        if (-not $naturalIdentities.Add($naturalIdentity)) {
            Fail "$($spec.path) duplicate natural identity '$naturalIdentity'"
        }
        Assert-InventoryItemContract $inventoryId $item $context
        $inventoryRowCount += 1
    }

    $derivedCounts = Get-DerivedInventoryCounts $inventoryId $items
    Assert-ExactCounts $inventory.counts $derivedCounts $spec.path
    if (-not (Test-OrdinalStringEqual (Get-InventoryDigest $items @($spec.canonical_fields)) ([string]$spec.digest))) {
        Fail "$($spec.path) canonical identity/source evidence fingerprint mismatch"
    }
    $derivedByInventory[$inventoryId] = $derivedCounts
}
if ($InventorySpecs.Count -ne 10 -or $inventoryRowCount -ne 717 -or $globalRecordIds.Count -ne 717) {
    Fail "fixed inventory totals must be 10 files and 717 globally unique rows"
}

$derivedCanonicalCounts = [ordered]@{
    artifact_json_files = $actualJsonPaths.Count
    ledgers = $LedgerSpecs.Count
    feature_rows = $featureCount
    inventory_files = $InventorySpecs.Count
    inventory_rows = $inventoryRowCount
    core_plugins = $derivedByInventory["plugins"].core
    official_external_plugins = $derivedByInventory["plugins"].official_external
    source_only_qa_plugins = $derivedByInventory["plugins"].source_only_qa
    bundled_skills = $derivedByInventory["skills"].bundled
    gateway_methods = $derivedByInventory["gateway-protocol"].methods
    gateway_advertised_methods = $derivedByInventory["gateway-protocol"].advertised_methods
    gateway_events = $derivedByInventory["gateway-protocol"].events
    gateway_roles = $derivedByInventory["gateway-protocol"].roles
    gateway_scopes = $derivedByInventory["gateway-protocol"].scopes
    config_domains = $derivedByInventory["config-domains"].total
    providers = $derivedByInventory["providers"].total
    channels = $derivedByInventory["channels"].total
    http_sse_endpoints = $derivedByInventory["http-sse-endpoints"].total
    client_surfaces = $derivedByInventory["clients"].total
    migration_providers = $derivedByInventory["migrations"].total
    release_deployment_surfaces = $derivedByInventory["release-deployment"].total
}
foreach ($key in $ExpectedCanonicalCounts.Keys) {
    if ($derivedCanonicalCounts[$key] -ne $ExpectedCanonicalCounts[$key]) {
        Fail "derived canonical count $key must be $($ExpectedCanonicalCounts[$key]), got $($derivedCanonicalCounts[$key])"
    }
}

# This record is a cross-check of the shipped reachability rule, never an input
# to an evidence decision. Ordinary validation re-evaluates every dated row;
# replay explicitly rebuilds the record from git's tracked Rust universe.
$evidenceSweepPath = Join-Path $Root $EvidenceSweepFileName
$sweepRecord = $null
$sweepRowsRechecked = 0
if ($ReplayEvidenceSweep) {
    # A malformed previous record must remain repairable by the one reviewed
    # writer mode rather than requiring a hand-authored replacement.
    if (Test-Path -LiteralPath $evidenceSweepPath -PathType Leaf) {
        try {
            $sweepRecord = Get-EvidenceSweepRecord $evidenceSweepPath
        } catch {
            Write-Host ("  previous $EvidenceSweepFileName does not parse and is being replaced: " +
                $_.Exception.Message)
            $sweepRecord = $null
        }
    }
} else {
    $sweepText = [System.IO.File]::ReadAllText($evidenceSweepPath).Replace("`r`n", "`n")
    $sweepDigest = Get-Sha256Text $sweepText
    if (-not (Test-OrdinalStringEqual $sweepDigest $ExpectedEvidenceSweepDigest)) {
        Fail (("{0} digest mismatch; expected {1}, found {2}. Regenerate only with " +
            "validate.ps1 -ReplayEvidenceSweep, then review and pin the new digest.") -f
            $EvidenceSweepFileName, $ExpectedEvidenceSweepDigest, $sweepDigest)
    }
    $sweepRecord = Get-EvidenceSweepRecord $evidenceSweepPath
    if (-not (Test-OrdinalStringEqual ([string]$sweepRecord.base_commit) $ExpectedEvidenceSweepBaseCommit) -or
        -not (Test-OrdinalStringEqual ([string]$sweepRecord.swept_at) $ExpectedEvidenceSweepSweptAt)) {
        Fail ("$EvidenceSweepFileName metadata must remain pinned to base {0} at {1}" -f
            $ExpectedEvidenceSweepBaseCommit, $ExpectedEvidenceSweepSweptAt)
    }
    $semanticMismatches = New-Object System.Collections.Generic.List[string]
    foreach ($row in $sweepRecord.rows) {
        $live = Get-EvidenceFileReachability ([string]$row.path)
        if (Test-OrdinalStringEqual ([string]$live.verdict) "missing") {
            $semanticMismatches.Add(("{0} semantic mismatch for '{1}': record says '{2}', but {3}." -f
                    $EvidenceSweepFileName, [string]$row.path, [string]$row.verdict, [string]$live.reason))
        } elseif (-not (Test-OrdinalStringEqual ([string]$row.verdict) ([string]$live.verdict))) {
            $semanticMismatches.Add((("{0} semantic mismatch for '{1}': record says '{2}', " +
                        "shipped reachability rule says '{3}'. Reason: {4}") -f
                    $EvidenceSweepFileName,
                    [string]$row.path,
                    [string]$row.verdict,
                    [string]$live.verdict,
                    [string]$live.reason))
        }
        $sweepRowsRechecked += 1
    }
    if ($semanticMismatches.Count -gt 0) {
        Fail ($semanticMismatches.ToArray() -join [Environment]::NewLine)
    }
    if ($sweepRecord.rows.Count -ne $EvidenceSweepExpectedFiles -or
        $sweepRecord.accepted -ne $EvidenceSweepExpectedAccepted -or
        $sweepRecord.rejected -ne $EvidenceSweepExpectedRejected) {
        Fail (("{0} semantic verdicts agree, but the reviewed record must contain exactly " +
                "{1} files / {2} accept / {3} reject; found {4} / {5} / {6}") -f
            $EvidenceSweepFileName,
            $EvidenceSweepExpectedFiles,
            $EvidenceSweepExpectedAccepted,
            $EvidenceSweepExpectedRejected,
            $sweepRecord.rows.Count,
            $sweepRecord.accepted,
            $sweepRecord.rejected)
    }
}

if ($ReplayEvidenceSweep) {
    $sweepBaseCommit = $null
    try {
        $sweepBaseCommit = (& git -C $script:RepositoryRootFull rev-parse HEAD 2>$null | Out-String).Trim()
    } catch {
        $sweepBaseCommit = $null
    }
    if (-not [regex]::IsMatch([string]$sweepBaseCommit, '\A[0-9a-f]{40}\z')) {
        Fail ("-ReplayEvidenceSweep could not read the current commit from git; " +
            "run it inside the repository worktree")
    }
    # The rows come from the working tree, so base-commit is truthful only while
    # every tracked or untracked Rust path matches HEAD.
    $dirtyRustPaths = @(
        & git -C $script:RepositoryRootFull status --porcelain -- "*.rs" 2>$null |
            ForEach-Object { ([string]$_).Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($dirtyRustPaths.Count -gt 0) {
        Fail ((("-ReplayEvidenceSweep will not date a record it cannot honestly date: {0} Rust " +
                    "path(s) differ from HEAD, so base-commit {1} would be false. Differing: {2}") -f
                $dirtyRustPaths.Count, $sweepBaseCommit, ($dirtyRustPaths -join "; ")))
    }
    $sweepDate = [datetime]::UtcNow.ToString(
        "yyyy-MM-dd",
        [System.Globalization.CultureInfo]::InvariantCulture
    )
    $sweptFiles = Get-RepositoryRustFiles
    $sweptRows = New-Object System.Collections.Generic.List[object]
    foreach ($file in $sweptFiles) {
        $live = Get-EvidenceFileReachability $file
        if (Test-OrdinalStringEqual ([string]$live.verdict) "missing") {
            Fail "-ReplayEvidenceSweep listed tracked Rust path '$file', but $($live.reason)"
        }
        $sweptRows.Add([pscustomobject]@{ verdict = [string]$live.verdict; path = $file })
    }
    $previousByPath = @{}
    if ($null -ne $sweepRecord) {
        foreach ($row in $sweepRecord.rows) { $previousByPath[$row.path] = $row.verdict }
    }
    $currentByPath = @{}
    foreach ($row in $sweptRows) { $currentByPath[$row.path] = $row.verdict }
    $changed = @($sweptRows | Where-Object {
            $previousByPath.ContainsKey($_.path) -and $previousByPath[$_.path] -ne $_.verdict
        })
    $added = @($sweptRows | Where-Object { -not $previousByPath.ContainsKey($_.path) })
    $removed = New-Object System.Collections.Generic.List[string]
    foreach ($path in $previousByPath.Keys) {
        if (-not $currentByPath.ContainsKey($path)) { $removed.Add([string]$path) }
    }
    $removed.Sort([System.StringComparer]::Ordinal)
    $acceptedCount = @($sweptRows | Where-Object { $_.verdict -eq "accept" }).Count
    $rejectedCount = @($sweptRows | Where-Object { $_.verdict -eq "reject" }).Count
    $sweepLines = New-Object System.Collections.Generic.List[string]
    foreach ($line in $EvidenceSweepPreamble) { $sweepLines.Add([string]$line) }
    $sweepLines.Add($EvidenceSweepGeneratedByLine)
    $sweepLines.Add("# base-commit: $sweepBaseCommit")
    $sweepLines.Add("# swept-at: $sweepDate")
    $sweepLines.Add(("# totals: files={0} accept={1} reject={2}" -f
            $sweptRows.Count, $acceptedCount, $rejectedCount))
    foreach ($row in $sweptRows) {
        $sweepLines.Add(("{0}`t{1}" -f $row.verdict, $row.path))
    }
    $sweepEncoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText(
        $evidenceSweepPath,
        (($sweepLines -join "`n") + "`n"),
        $sweepEncoding
    )
    $sweepRecord = Get-EvidenceSweepRecord $evidenceSweepPath
    Write-Host ("Recorded {0} swept files in {1} ({2} accept / {3} reject); " +
        "review every line before committing." -f
        $sweptRows.Count, $EvidenceSweepFileName, $acceptedCount, $rejectedCount)
    Write-Host "  pin these reviewed values in validate.ps1:"
    Write-Host ("    base commit: {0}" -f $sweepBaseCommit)
    Write-Host ("    swept at:    {0}" -f $sweepDate)
    Write-Host ("    digest:      {0}" -f
        (Get-Sha256Text ([System.IO.File]::ReadAllText($evidenceSweepPath).Replace("`r`n", "`n")))
    )
    Write-Host ("  verdict changes since the previous record: {0}" -f $changed.Count)
    foreach ($row in $changed) {
        Write-Host ("    CHANGED {0}: {1} -> {2}" -f
            $row.path, $previousByPath[$row.path], $row.verdict)
    }
    Write-Host ("  files added since the previous record: {0}" -f $added.Count)
    foreach ($row in $added) {
        Write-Host ("    ADDED   {0} ({1})" -f $row.path, $row.verdict)
    }
    Write-Host ("  files removed since the previous record: {0}" -f $removed.Count)
    foreach ($path in $removed) { Write-Host ("    REMOVED {0}" -f $path) }
    Write-Host "  refusals in the refreshed record:"
    foreach ($row in $sweptRows) {
        if ($row.verdict -eq "reject") {
            Write-Host ("    REJECT  {0}" -f $row.path)
        }
    }
}

if ($WriteStatusTotalsRequested) {
    # All contract and sweep checks have passed. Build both replacements before
    # touching disk, then publish them as one rollback-protected transition.
    $updatedManifestBytes = Get-UpdatedManifestStatusTotalsBytes $manifestPath $statusTotals
    $digestEncoding = New-Object System.Text.UTF8Encoding($false)
    [byte[]]$updatedDigestBytes = $digestEncoding.GetBytes(
        (Format-LedgerDigestFile $computedLedgerDigests)
    )
    Write-ReviewedStatusTransition `
        $manifestPath $updatedManifestBytes $ledgerDigestPath $updatedDigestBytes
}

if ($WriteLedgerDigests) {
    Write-Host "Recorded ledger digests in $LedgerDigestFileName; review every line before committing:"
    foreach ($spec in $LedgerSpecs) {
        Write-Host ("  {0}  {1}" -f [string]$computedLedgerDigests[[string]$spec.path], [string]$spec.path)
    }
}
if ($WriteStatusTotalsRequested) {
    Write-Host "Recorded manifest.evidence_policy.status_totals; review the transition:"
    foreach ($status in $AllowedFeatureStatuses) {
        Write-Host ("  {0,-15} {1}" -f $status, $statusTotals[$status])
    }
    foreach ($spec in $LedgerSpecs) {
        foreach ($feature in @($documents[$spec.path].features)) {
            if (-not (Test-OrdinalStringEqual ([string]$feature.status) "unimplemented")) {
                Write-Host ("  {0,-15} {1}" -f
                    [string]$feature.status, [string]$feature.feature_id)
            }
        }
    }
}

$writeModes = @()
if ($WriteLedgerDigests) { $writeModes += "write-ledger-digests" }
if ($WriteStatusTotalsRequested) { $writeModes += "write-status-totals" }
if ($ReplayEvidenceSweep) { $writeModes += "replay-evidence-sweep" }

[ordered]@{
    status = "ok"
    mode = if ($writeModes.Count -eq 0) { "verify" } else { $writeModes -join "+" }
    baseline_sha = $ExpectedSha
    repository_root = $script:RepositoryRootFull
    artifact_json_files = $actualJsonPaths.Count
    ledgers = $LedgerSpecs.Count
    feature_rows = $featureCount
    feature_status_totals = $statusTotals
    missing_acceptance_evidence = $missingEvidenceCount
    ledger_digests = $computedLedgerDigests
    evidence_sweep_files = $(if ($null -eq $sweepRecord) { 0 } else { $sweepRecord.rows.Count })
    evidence_sweep_rows_rechecked = $sweepRowsRechecked
    evidence_sweep_rows_absent = 0
    inventory_files = $InventorySpecs.Count
    inventory_rows = $inventoryRowCount
    canonical_counts = $derivedCanonicalCounts
    inventory_subtotals = $derivedByInventory
} | ConvertTo-Json -Depth 8
