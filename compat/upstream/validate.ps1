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

.PARAMETER RepositoryRoot
    Repository working tree used to resolve acceptance-evidence paths. Defaults to
    the parent of compat/. The validator self-test passes the real tree explicitly
    because it runs mutated copies of this contract from a temporary directory.

.EXAMPLE
    powershell -NoProfile -File compat/upstream/validate.ps1

.EXAMPLE
    powershell -NoProfile -File compat/upstream/validate.ps1 -WriteLedgerDigests
#>
[CmdletBinding()]
param(
    [switch]$WriteLedgerDigests,
    [string]$RepositoryRoot
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$ExpectedSha = "b43e832fcc8000ed7287c7accc54e381db607f85"
$ExpectedSchemaDigest = "32f04a7b53fa0968cc427bc6acb2cf9755d4a92dc130a0ebb8d574682dd4b052"
$LedgerDigestFileName = "ledger-digests.sha256"
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
$AllowedArtifactKinds = @("rust_test", "rust_source", "rust_fixture", "ci_check")
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
    "feature-ledger.schema.json",
    "manifest.json",
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
    },
    [ordered]@{
        path = "ledgers/official-integration.json"
        ledger_id = "official-integration"
        classification = "official_integration"
        expected_features = 13
    },
    [ordered]@{
        path = "ledgers/official-client-interop.json"
        ledger_id = "official-client-interop"
        classification = "official_client_interop"
        expected_features = 18
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
    artifact_json_files = 16
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
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
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
    $json = ConvertTo-Json -InputObject $Value -Compress -Depth 50
    return Get-Sha256Text $json
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
                $encodedName = ConvertTo-Json -InputObject $_ -Compress
                $encodedValue = ConvertTo-CanonicalJson (Get-PropertyValue $Value $_)
                "${encodedName}:${encodedValue}"
            }
        )
        return "{" + ($members -join ",") + "}"
    }
    return ConvertTo-Json -InputObject $Value -Compress
}

function Get-CanonicalArrayDigest {
    param([object[]]$Items)
    [string[]]$elements = @($Items | ForEach-Object { ConvertTo-CanonicalJson $_ })
    [Array]::Sort($elements, [StringComparer]::Ordinal)
    return Get-Sha256Text ("[" + ($elements -join ",") + "]")
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

function Assert-RustTestSymbol {
    param(
        [string]$Text,
        [string]$Symbol,
        [string]$RelativePath,
        [string]$Context
    )
    if ($Text -cnotmatch ('\bfn\s+' + [regex]::Escape($Symbol) + '\s*[(<]')) {
        Fail "$Context cites test '$Symbol' that does not exist in '$RelativePath'"
    }
}

function Assert-EvidenceArtifact {
    param(
        [object]$Artifact,
        [string]$Context,
        [System.Collections.Generic.List[string]]$RustTestTexts
    )
    Assert-ExactPropertySet $Artifact @("kind", "path", "check") $Context
    $kind = [string](Get-PropertyValue $Artifact "kind")
    $relativePath = [string](Get-PropertyValue $Artifact "path")
    $check = [string](Get-PropertyValue $Artifact "check")
    if (-not (Test-OrdinalContains $AllowedArtifactKinds $kind)) {
        Fail "$Context has unsupported acceptance evidence kind '$kind'"
    }
    Assert-EvidencePathShape $relativePath $Context
    $absolutePath = Resolve-RepositoryFilePath $relativePath
    if ($null -eq $absolutePath) {
        Fail "$Context cites acceptance evidence path '$relativePath' that does not exist in the working tree"
    }
    $text = Get-RepositoryFileText $absolutePath

    if (Test-OrdinalStringEqual $kind "rust_test") {
        if (-not (Test-PathHasExtension $relativePath @(".rs"))) {
            Fail "$Context rust_test acceptance evidence '$relativePath' must be a Rust source file"
        }
        if (-not ($check -cmatch '\A[a-z_][A-Za-z0-9_]*(?:::[a-z_][A-Za-z0-9_]*)*\z')) {
            Fail "$Context rust_test check '$check' must be a Rust test path"
        }
        if ($text -cnotmatch '#\s*\[\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*::\s*)*test') {
            Fail "$Context rust_test acceptance evidence '$relativePath' contains no Rust test attribute"
        }
        $symbol = @($check.Split(":") | Where-Object { $_.Length -gt 0 })[-1]
        Assert-RustTestSymbol $text $symbol $relativePath $Context
        return
    }

    if (Test-OrdinalStringEqual $kind "rust_source") {
        if (-not (Test-PathHasExtension $relativePath @(".rs"))) {
            Fail "$Context rust_source acceptance evidence '$relativePath' must be a Rust source file"
        }
        if (-not ($check -cmatch '\A[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*\z')) {
            Fail "$Context rust_source check '$check' must be a Rust symbol path"
        }
        $symbol = @($check.Split(":") | Where-Object { $_.Length -gt 0 })[-1]
        $declaration = '\b(?:fn|struct|enum|trait|union|type|const|static|mod|impl)[ \t]+(?:[A-Za-z0-9_:<>,&'' \t]*[ \t])?' +
            [regex]::Escape($symbol) + '\b'
        if ($text -cnotmatch $declaration) {
            Fail "$Context cites symbol '$symbol' that is not declared in '$relativePath'"
        }
        return
    }

    if (Test-OrdinalStringEqual $kind "rust_fixture") {
        if (Test-PathHasExtension $relativePath @(".rs")) {
            Fail "$Context rust_fixture acceptance evidence '$relativePath' must be fixture data, not Rust source"
        }
        if (-not ($check -cmatch '\A[a-z_][A-Za-z0-9_]*(?:::[a-z_][A-Za-z0-9_]*)*\z')) {
            Fail "$Context rust_fixture check '$check' must name the Rust test that consumes the fixture"
        }
        $symbol = @($check.Split(":") | Where-Object { $_.Length -gt 0 })[-1]
        $consumed = $false
        foreach ($testText in $RustTestTexts) {
            if ($testText -cmatch ('\bfn\s+' + [regex]::Escape($symbol) + '\s*[(<]')) {
                $consumed = $true
                break
            }
        }
        if (-not $consumed) {
            Fail "$Context rust_fixture cites test '$symbol' that is not one of the rust_test artifacts of this row"
        }
        return
    }

    if (-not $relativePath.StartsWith(".github/workflows/", [StringComparison]::Ordinal) -or
        -not (Test-PathHasExtension $relativePath @(".yml", ".yaml"))) {
        Fail "$Context ci_check acceptance evidence '$relativePath' must be a workflow under .github/workflows"
    }
    if (-not ($check -cmatch '\A[A-Za-z0-9][A-Za-z0-9 ._/-]*\z')) {
        Fail "$Context ci_check check '$check' must be a workflow job key or step name"
    }
    $escapedCheck = [regex]::Escape($check)
    if ($text -cnotmatch ('(?m)^\s*(?:name:\s*["'']?' + $escapedCheck + '["'']?\s*$|' + $escapedCheck + ':\s*$)')) {
        Fail "$Context cites workflow check '$check' that does not exist in '$relativePath'"
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

    if (-not (Test-OrdinalContains $AllowedFeatureStatuses $status)) {
        Fail "$Context has unsupported lifecycle status '$status'"
    }

    if (Test-OrdinalStringEqual $status "unimplemented") {
        if (-not (Test-OrdinalStringEqual $evidenceStatus "missing") -or $artifacts.Count -ne 0) {
            Fail "$Context must start unimplemented with an empty evidence placeholder"
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
        Fail "$Context status '$status' requires at least one acceptance evidence artifact"
    }
    foreach ($difference in $differences) {
        if (Test-OrdinalStringEqual ([string]$difference) $BaselineKnownDifference) {
            Fail "$Context status '$status' must not keep the baseline no-implementation known_differences placeholder"
        }
    }

    $identities = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $rustTestTexts = New-Object System.Collections.Generic.List[string]
    for ($index = 0; $index -lt $artifacts.Count; $index += 1) {
        $artifact = $artifacts[$index]
        if (-not (Test-JsonObject $artifact)) {
            Fail "$Context acceptance evidence artifact $index must be a typed object"
        }
        if (-not $identities.Add((ConvertTo-CanonicalJson $artifact))) {
            Fail "$Context repeats the same acceptance evidence artifact"
        }
        if (Test-OrdinalStringEqual ([string](Get-PropertyValue $artifact "kind")) "rust_test") {
            $relativePath = [string](Get-PropertyValue $artifact "path")
            Assert-EvidencePathShape $relativePath "$Context.acceptance_evidence.artifacts[$index]"
            $absolutePath = Resolve-RepositoryFilePath $relativePath
            if ($null -ne $absolutePath) {
                $rustTestTexts.Add((Get-RepositoryFileText $absolutePath))
            }
        }
    }
    for ($index = 0; $index -lt $artifacts.Count; $index += 1) {
        Assert-EvidenceArtifact $artifacts[$index] "$Context.acceptance_evidence.artifacts[$index]" $rustTestTexts
    }
    if ($rustTestTexts.Count -eq 0) {
        Fail "$Context status '$status' requires at least one rust_test acceptance evidence artifact"
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
        "artifact_kinds",
        "proof_artifact_kind",
        "status_totals"
    ) "manifest.evidence_policy"
    if (-not (Test-OrdinalStringEqual ([string]$Manifest.evidence_policy.initial_status) "unimplemented") -or
        -not (Test-OrdinalStringEqual ([string]$Manifest.evidence_policy.acceptance_evidence_state) "missing") -or
        $Manifest.evidence_policy.legacy_typescript_is_not_rust_acceptance_evidence -ne $true) {
        Fail "manifest evidence policy mismatch"
    }
    if (-not (Test-JsonValueEqual $Manifest.evidence_policy.allowed_statuses $AllowedFeatureStatuses) -or
        -not (Test-JsonValueEqual $Manifest.evidence_policy.artifact_kinds $AllowedArtifactKinds) -or
        -not (Test-OrdinalStringEqual ([string]$Manifest.evidence_policy.proof_artifact_kind) "rust_test")) {
        Fail "manifest evidence lifecycle policy mismatch"
    }
    Assert-ExactPropertySet $Manifest.evidence_policy.status_totals $AllowedFeatureStatuses "manifest.evidence_policy.status_totals"
    foreach ($status in $AllowedFeatureStatuses) {
        $declaredTotal = Get-PropertyValue $Manifest.evidence_policy.status_totals $status
        if (-not ($declaredTotal -is [int]) -or [int]$declaredTotal -lt 0) {
            Fail "manifest.evidence_policy.status_totals.$status must be a non-negative integer"
        }
    }
}

$script:RepositoryRootFull = Resolve-RepositoryRoot $RepositoryRoot

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
$missingFiles = @($expectedFilePaths | Where-Object { -not (Test-OrdinalContains $actualFilePaths $_) })
$unexpectedFiles = @($actualFilePaths | Where-Object { -not (Test-OrdinalContains $expectedFilePaths $_) })
if ($actualFilePaths.Count -ne $expectedFilePaths.Count -or
    $missingFiles.Count -gt 0 -or
    $unexpectedFiles.Count -gt 0) {
    Fail "fixed artifact topology mismatch; missing=[$($missingFiles -join ',')], unexpected=[$($unexpectedFiles -join ',')]"
}
$missingJsonFiles = @($ExpectedJsonPaths | Where-Object { -not (Test-OrdinalContains $actualJsonPaths $_) })
$unexpectedJsonFiles = @($actualJsonPaths | Where-Object { -not (Test-OrdinalContains $ExpectedJsonPaths $_) })
if ($actualJsonPaths.Count -ne 16 -or
    $missingJsonFiles.Count -gt 0 -or
    $unexpectedJsonFiles.Count -gt 0) {
    Fail "fixed JSON topology mismatch; missing=[$($missingJsonFiles -join ',')], unexpected=[$($unexpectedJsonFiles -join ',')]"
}

$documents = @{}
foreach ($relativePath in $ExpectedJsonPaths) {
    $documents[$relativePath] = Read-Json (Join-Path $Root $relativePath)
}

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
    -not (Test-OrdinalStringEqual ([string]$baseline.upstream.commit_timestamp) "2026-07-13T03:29:58Z") -or
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
    -not (Test-OrdinalStringEqual ([string]$baseline.stable_release.published_at) "2026-06-30T16:06:39Z") -or
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
    Fail "feature ledger schema is not the frozen Draft 2020-12 contract"
}

$manifest = $documents["manifest.json"]
Assert-ManifestDeclarations $manifest

$ledgerDigestPath = Join-Path $Root $LedgerDigestFileName
$computedLedgerDigests = [ordered]@{}
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
    $computedLedgerDigests[[string]$spec.path] = Get-FeatureDigest $features
}

if ($WriteLedgerDigests) {
    Write-LedgerDigestFile $ledgerDigestPath $computedLedgerDigests
} else {
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
Assert-ExactCounts $manifest.evidence_policy.status_totals $statusTotals "manifest.evidence_policy.status_totals"
$missingEvidenceCount = $statusTotals["unimplemented"]

$globalRecordIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$inventoryRowCount = 0
$derivedByInventory = @{}
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

if ($WriteLedgerDigests) {
    Write-Host "Recorded ledger digests in $LedgerDigestFileName; review every line before committing:"
    foreach ($spec in $LedgerSpecs) {
        Write-Host ("  {0}  {1}" -f [string]$computedLedgerDigests[[string]$spec.path], [string]$spec.path)
    }
}

[ordered]@{
    status = "ok"
    mode = if ($WriteLedgerDigests) { "write-ledger-digests" } else { "verify" }
    baseline_sha = $ExpectedSha
    repository_root = $script:RepositoryRootFull
    artifact_json_files = $actualJsonPaths.Count
    ledgers = $LedgerSpecs.Count
    feature_rows = $featureCount
    feature_status_totals = $statusTotals
    missing_acceptance_evidence = $missingEvidenceCount
    ledger_digests = $computedLedgerDigests
    inventory_files = $InventorySpecs.Count
    inventory_rows = $inventoryRowCount
    canonical_counts = $derivedCanonicalCounts
    inventory_subtotals = $derivedByInventory
} | ConvertTo-Json -Depth 8
