[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$ExpectedSha = "b43e832fcc8000ed7287c7accc54e381db607f85"
$ExpectedSchemaDigest = "ce2399751e5f990bcf5074435a6e3159e1a5bce2266402c3d1665da1971e9a44"
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

$LedgerSpecs = @(
    [ordered]@{
        path = "ledgers/gateway-core.json"
        ledger_id = "gateway-core"
        classification = "gateway_core"
        expected_features = 16
        digest = "c2812699bb69e3460249dab1b5333172ea5303a0308a24251ff57dbe64fd4bc7"
    },
    [ordered]@{
        path = "ledgers/official-integration.json"
        ledger_id = "official-integration"
        classification = "official_integration"
        expected_features = 13
        digest = "08babe914a79ff7425c8e45555962a6ecf9a6a6d068c51dba2de91eee14f4de1"
    },
    [ordered]@{
        path = "ledgers/official-client-interop.json"
        ledger_id = "official-client-interop"
        classification = "official_client_interop"
        expected_features = 18
        digest = "523ae2e4eb83e06d779d0813bc2328691ba2d6a924573b40374088a7baa4b39d"
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
        digest = "800a64620e10f354fe49ca56bb091ce757d098eb9dbe980e50ffadc1fff823ca"
    }
    "skills" = [ordered]@{
        path = "inventories/skills.json"
        classification = "official_integration"
        expected_items = 51
        natural_key_fields = @("id")
        required_fields = @("record_id", "id", "classification", "source_path", "license")
        allowed_fields = @("record_id", "id", "classification", "source_path", "license")
        canonical_fields = @("record_id", "id", "classification", "source_path", "license")
        digest = "aee321c19126ce19004499b0f3628445d732886e24852cd0d0e3d1e5d5bc9a14"
    }
    "gateway-protocol" = [ordered]@{
        path = "inventories/gateway-protocol.json"
        classification = "gateway_core"
        expected_items = 320
        natural_key_fields = @("kind", "id")
        required_fields = @("record_id", "id", "classification", "source_path", "kind")
        allowed_fields = @("record_id", "id", "classification", "source_path", "kind", "scope", "advertised", "protocol_class")
        canonical_fields = @("record_id", "id", "classification", "source_path", "kind", "scope", "advertised", "protocol_class")
        digest = "90417a3abc9c98bf482fd4f45540d45b131f67d431304cf0c9fac700326c2e02"
    }
    "config-domains" = [ordered]@{
        path = "inventories/config-domains.json"
        classification = "gateway_core"
        expected_items = 47
        natural_key_fields = @("id")
        required_fields = @("record_id", "id", "classification", "source_path")
        allowed_fields = @("record_id", "id", "classification", "source_path")
        canonical_fields = @("record_id", "id", "classification", "source_path")
        digest = "fa49ef6ea826a8eb86fbb61e7dcca6cdfd321a45845819d887c76f855883c278"
    }
    "providers" = [ordered]@{
        path = "inventories/providers.json"
        classification = "official_integration"
        expected_items = 78
        natural_key_fields = @("id")
        required_fields = @("record_id", "id", "classification", "source_path", "plugin_id")
        allowed_fields = @("record_id", "id", "classification", "source_path", "plugin_id")
        canonical_fields = @("record_id", "id", "classification", "source_path", "plugin_id")
        digest = "47bf1b81f068f26b1a49b207c0c988d08fcdcb8f0a10b5be098a6cc9dc8735de"
    }
    "channels" = [ordered]@{
        path = "inventories/channels.json"
        classification = "official_integration"
        expected_items = 29
        natural_key_fields = @("id")
        required_fields = @("record_id", "id", "classification", "source_path", "provenance")
        allowed_fields = @("record_id", "id", "classification", "source_path", "plugin_id", "package_name", "catalog_package", "catalog_source_path", "provenance")
        canonical_fields = @("record_id", "id", "classification", "source_path", "plugin_id", "package_name", "catalog_package", "catalog_source_path", "provenance")
        digest = "e1c1d482c347b3523e9d787c677cfe376c7cd7ae461e7b6a026e93f1578b111a"
    }
    "http-sse-endpoints" = [ordered]@{
        path = "inventories/http-sse-endpoints.json"
        classification = "mixed"
        expected_items = 18
        natural_key_fields = @("method", "path")
        required_fields = @("record_id", "id", "classification", "source_path", "method", "path", "streaming")
        allowed_fields = @("record_id", "id", "classification", "source_path", "method", "path", "streaming")
        canonical_fields = @("record_id", "id", "classification", "source_path", "method", "path", "streaming")
        digest = "48a5718dc84e709f95bebf39309962fd62a1b475e64c988f825e5a7d33776707"
    }
    "clients" = [ordered]@{
        path = "inventories/clients.json"
        classification = "official_client_interop"
        expected_items = 10
        natural_key_fields = @("kind", "id")
        required_fields = @("record_id", "id", "classification", "source_path", "kind")
        allowed_fields = @("record_id", "id", "classification", "source_path", "kind")
        canonical_fields = @("record_id", "id", "classification", "source_path", "kind")
        digest = "f9685499874467491ded7572013c45c76e37434eb0df55169ee333dc98ad26f7"
    }
    "migrations" = [ordered]@{
        path = "inventories/migrations.json"
        classification = "official_client_interop"
        expected_items = 3
        natural_key_fields = @("kind", "id")
        required_fields = @("record_id", "id", "classification", "source_path", "package_path", "kind")
        allowed_fields = @("record_id", "id", "classification", "source_path", "package_path", "kind")
        canonical_fields = @("record_id", "id", "classification", "source_path", "package_path", "kind")
        digest = "c6033ec9f3f2709f1ca11474e5c48c27a49f65835ac6bf46ddb89850a6f82dbd"
    }
    "release-deployment" = [ordered]@{
        path = "inventories/release-deployment.json"
        classification = "official_integration"
        expected_items = 24
        natural_key_fields = @("kind", "id")
        required_fields = @("record_id", "id", "classification", "source_path", "kind")
        allowed_fields = @("record_id", "id", "classification", "source_path", "kind")
        canonical_fields = @("record_id", "id", "classification", "source_path", "kind")
        digest = "4e1e0b1a5f3dfa5e5f95c2917cc60aa5b704ddda3813ac3cb0d07157b7da7cd9"
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

function Has-Property {
    param(
        [object]$Value,
        [string]$Name
    )
    return (Get-PropertyNames $Value) -contains $Name
}

function Get-PropertyValue {
    param(
        [object]$Value,
        [string]$Name
    )
    if ($Value -is [System.Collections.IDictionary]) {
        $result = $Value[$Name]
    } else {
        $property = $Value.PSObject.Properties[$Name]
        if ($null -eq $property) {
            $result = $null
        } else {
            $result = $property.Value
        }
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
    $missing = @($Expected | Where-Object { $actual -notcontains $_ })
    $unexpected = @($actual | Where-Object { $Expected -notcontains $_ })
    if ($missing.Count -gt 0 -or $unexpected.Count -gt 0) {
        Fail "$Context property mismatch; missing=[$($missing -join ',')], unexpected=[$($unexpected -join ',')]"
    }
    Assert-ExactProperties $entry[0] @("path", "classification", "expected_features") @("path", "classification", "expected_features") "manifest ledger '$($contract.Path)'"
}
foreach ($contract in $InventoryContracts) {
    $entry = @($manifest.inventories | Where-Object { $_.path -ceq $contract.Path })
    if ($entry.Count -ne 1 -or [int]$entry[0].expected_items -ne $contract.Items) {
        Fail "manifest inventory contract mismatch for '$($contract.Path)'"
    }
    Assert-ExactProperties $entry[0] @("path", "expected_items") @("path", "expected_items") "manifest inventory '$($contract.Path)'"
}
$expectedCanonicalCounts = [ordered]@{
    core_plugins = 64
    official_external_plugins = 70
    source_only_qa_plugins = 3
    bundled_skills = 51
    gateway_methods = 278
    gateway_events = 33
    config_domains = 47
    providers = 78
    channels = 29
}
Assert-HashtableEquals $manifest.canonical_counts $expectedCanonicalCounts "manifest.canonical_counts"
Assert-ExactProperties $manifest.evidence_policy @("initial_status", "acceptance_evidence_state", "legacy_typescript_is_not_rust_acceptance_evidence") @("initial_status", "acceptance_evidence_state", "legacy_typescript_is_not_rust_acceptance_evidence") "manifest.evidence_policy"
if ($manifest.evidence_policy.initial_status -cne "unimplemented" -or
    $manifest.evidence_policy.acceptance_evidence_state -cne "missing" -or
    $manifest.evidence_policy.legacy_typescript_is_not_rust_acceptance_evidence -ne $true) {
    Fail "manifest evidence policy mismatch"
}

function Assert-RequiredProperties {
    param(
        [object]$Value,
        [string[]]$Required,
        [string]$Context
    )
    $actual = @(Get-PropertyNames $Value)
    $missing = @($Required | Where-Object { $actual -notcontains $_ })
    if ($missing.Count -gt 0) {
        Fail "$Context missing required properties [$($missing -join ',')]"
    }
}

function Convert-ScalarText {
    param([object]$Value)
    if ($null -eq $Value) {
        return ""
    }
    if ($Value -is [bool]) {
        return $Value.ToString().ToLowerInvariant()
    }
    return [string]$Value
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

function Get-InventoryDigest {
    param(
        [object[]]$Items,
        [string[]]$Fields
    )
    [string[]]$lines = @(
        $Items | ForEach-Object {
            $row = $_
            (($Fields | ForEach-Object {
                "$_=$(Convert-ScalarText (Get-PropertyValue $row $_))"
            }) -join [char]31)
        }
    )
    [Array]::Sort($lines, [StringComparer]::Ordinal)
    return Get-Sha256Text ($lines -join "`n")
}

function Get-FeatureDigest {
    param([object[]]$Features)
    [string[]]$lines = @(
        $Features | ForEach-Object {
            @(
                [string]$_.feature_id,
                [string]$_.title,
                [string]$_.domain,
                [string]$_.tier,
                [string]$_.profile,
                [string]$_.classification,
                [string]$_.upstream_source.repository,
                (@($_.upstream_source.paths) -join ","),
                [string]$_.status,
                [string]$_.acceptance_evidence.status,
                [string]$_.acceptance_evidence.required,
                (@($_.known_differences) -join ",")
            ) -join [char]31
        }
    )
    [Array]::Sort($lines, [StringComparer]::Ordinal)
    return Get-Sha256Text ($lines -join "`n")
}

function Test-JsonValueEqual {
    param(
        [object]$Left,
        [object]$Right
    )
    return (ConvertTo-Json -InputObject $Left -Compress -Depth 50) -ceq
        (ConvertTo-Json -InputObject $Right -Compress -Depth 50)
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
    if (-not $Reference.StartsWith("#/")) {
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
        $typeMatches = switch ($expectedType) {
            "object" { Test-JsonObject $Instance; break }
            "array" { $Instance -is [System.Array]; break }
            "string" { $Instance -is [string]; break }
            "boolean" { $Instance -is [bool]; break }
            "integer" {
                ($Instance -is [byte]) -or ($Instance -is [int16]) -or
                ($Instance -is [int32]) -or ($Instance -is [int64]); break
            }
            "number" {
                ($Instance -is [byte]) -or ($Instance -is [int16]) -or
                ($Instance -is [int32]) -or ($Instance -is [int64]) -or
                ($Instance -is [single]) -or ($Instance -is [double]) -or
                ($Instance -is [decimal]); break
            }
            "null" { $null -eq $Instance; break }
            default { Fail "$Path uses unsupported JSON Schema type $expectedType" }
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
            if ($Instance -notmatch $pattern) {
                Fail "$Path does not match JSON Schema pattern $pattern"
            }
        }
        if ((Get-PropertyValue $SchemaNode "format") -eq "uri") {
            $uri = $null
            if (-not [Uri]::TryCreate($Instance, [UriKind]::Absolute, [ref]$uri)) {
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
            $unexpected = @((Get-PropertyNames $Instance) | Where-Object { $allowed -notcontains $_ })
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
            $seen = New-Object System.Collections.Generic.HashSet[string]
            foreach ($item in $items) {
                $identity = ConvertTo-Json -InputObject $item -Compress -Depth 50
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
        $Path -notmatch '^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$') {
        Fail "$Context has invalid upstream-relative source path '$Path'"
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
    $prefix = switch ($InventoryId) {
        "plugins" { "plugin"; break }
        "skills" { "skill"; break }
        "gateway-protocol" {
            switch ([string]$Item.kind) {
                "method" { "gateway_method"; break }
                "event" { "gateway_event"; break }
                "role" { "gateway_role"; break }
                "scope" { "gateway_scope"; break }
                default { Fail "gateway-protocol item has invalid kind '$($Item.kind)'" }
            }
            break
        }
        "config-domains" { "config_domain"; break }
        "providers" { "provider"; break }
        "channels" { "channel"; break }
        "http-sse-endpoints" { "http"; break }
        "clients" { "client"; break }
        "migrations" { "migration"; break }
        "release-deployment" { "release_surface"; break }
        default { Fail "unknown inventory $InventoryId" }
    }
    return "${prefix}:$($Item.id)"
}

function Assert-InventoryItemContract {
    param(
        [string]$InventoryId,
        [object]$Item,
        [string]$Context
    )
    if ([string]$Item.record_id -ne (Get-ExpectedRecordId $InventoryId $Item)) {
        Fail "$Context record_id does not match its natural id"
    }
    Assert-RelativeSourcePath ([string]$Item.source_path) "$Context.source_path"
    foreach ($optionalPath in @("catalog_source_path", "package_path")) {
        if (Has-Property $Item $optionalPath) {
            Assert-RelativeSourcePath ([string](Get-PropertyValue $Item $optionalPath)) "$Context.$optionalPath"
        }
    }

    switch ($InventoryId) {
        "plugins" {
            if (@("core", "official_external", "source_only_qa") -notcontains [string]$Item.delivery_class) {
                Fail "$Context has invalid delivery_class"
            }
        }
        "skills" {
            if (@("MIT", "Apache-2.0") -notcontains [string]$Item.license) {
                Fail "$Context has invalid license"
            }
            if (($Item.id -eq "skill-creator") -ne ($Item.license -eq "Apache-2.0")) {
                Fail "$Context has stale skill license evidence"
            }
        }
        "gateway-protocol" {
            $base = @("record_id", "id", "classification", "source_path", "kind")
            switch ([string]$Item.kind) {
                "method" {
                    Assert-ExactPropertySet $Item ($base + @("scope", "advertised")) $Context
                    if ($AllowedOperatorScopes -notcontains [string]$Item.scope -or
                        -not ($Item.advertised -is [bool])) {
                        Fail "$Context has invalid method scope or advertised flag"
                    }
                }
                "event" {
                    Assert-ExactPropertySet $Item $base $Context
                }
                "role" {
                    Assert-ExactPropertySet $Item ($base + @("protocol_class")) $Context
                    if (@("gateway", "closed_worker") -notcontains [string]$Item.protocol_class) {
                        Fail "$Context has invalid role protocol_class"
                    }
                }
                "scope" {
                    Assert-ExactPropertySet $Item $base $Context
                }
                default {
                    Fail "$Context has invalid protocol kind"
                }
            }
        }
        "channels" {
            if (@("source_manifest", "official_catalog_only") -notcontains [string]$Item.provenance) {
                Fail "$Context has invalid provenance"
            }
            if ($Item.provenance -eq "source_manifest" -and -not (Has-Property $Item "plugin_id")) {
                Fail "$Context source manifest row requires plugin_id"
            }
            if ($Item.provenance -eq "official_catalog_only" -and -not (Has-Property $Item "package_name")) {
                Fail "$Context catalog-only row requires package_name"
            }
        }
        "http-sse-endpoints" {
            if (@("GET", "POST") -notcontains [string]$Item.method -or
                @("none", "optional_sse", "long_poll", "streamable_http") -notcontains [string]$Item.streaming -or
                -not ([string]$Item.path).StartsWith("/")) {
                Fail "$Context has invalid HTTP method, path, or streaming kind"
            }
        }
        "clients" {
            $allowedKinds = @(
                "browser_extension", "headless_node", "native_app", "native_helper",
                "native_sidecar", "terminal_app", "terminal_client", "web_app"
            )
            if ($allowedKinds -notcontains [string]$Item.kind) {
                Fail "$Context has invalid client kind"
            }
        }
        "migrations" {
            if ($Item.kind -ne "migration_provider") {
                Fail "$Context has invalid migration kind"
            }
        }
        "release-deployment" {
            if (@("release", "installation", "deployment") -notcontains [string]$Item.kind) {
                Fail "$Context has invalid release/deployment kind"
            }
        }
    }
}

function Get-DerivedInventoryCounts {
    param(
        [string]$InventoryId,
        [object[]]$Items
    )
    switch ($InventoryId) {
        "plugins" {
            return [ordered]@{
                total = $Items.Count
                core = @($Items | Where-Object { $_.delivery_class -eq "core" }).Count
                official_external = @($Items | Where-Object { $_.delivery_class -eq "official_external" }).Count
                source_only_qa = @($Items | Where-Object { $_.delivery_class -eq "source_only_qa" }).Count
            }
        }
        "skills" {
            return [ordered]@{ total = $Items.Count; bundled = $Items.Count }
        }
        "gateway-protocol" {
            $methods = @($Items | Where-Object { $_.kind -eq "method" })
            return [ordered]@{
                total = $Items.Count
                methods = $methods.Count
                advertised_methods = @($methods | Where-Object { $_.advertised -eq $true }).Count
                events = @($Items | Where-Object { $_.kind -eq "event" }).Count
                roles = @($Items | Where-Object { $_.kind -eq "role" }).Count
                scopes = @($Items | Where-Object { $_.kind -eq "scope" }).Count
                dynamic_plugin_methods = "runtime-dependent"
            }
        }
        "config-domains" {
            return [ordered]@{ total = $Items.Count }
        }
        "providers" {
            return [ordered]@{
                total = $Items.Count
                unique = @($Items.id | Sort-Object -Unique).Count
            }
        }
        "channels" {
            return [ordered]@{
                total = $Items.Count
                source_manifest = @($Items | Where-Object { $_.provenance -eq "source_manifest" }).Count
                official_catalog_only = @($Items | Where-Object { $_.provenance -eq "official_catalog_only" }).Count
            }
        }
        "http-sse-endpoints" {
            return [ordered]@{
                total = $Items.Count
                optional_sse = @($Items | Where-Object { $_.streaming -eq "optional_sse" }).Count
                long_poll = @($Items | Where-Object { $_.streaming -eq "long_poll" }).Count
                streamable_http = @($Items | Where-Object { $_.streaming -eq "streamable_http" }).Count
            }
        }
        "clients" {
            return [ordered]@{ total = $Items.Count }
        }
        "migrations" {
            return [ordered]@{ total = $Items.Count }
        }
        "release-deployment" {
            return [ordered]@{
                total = $Items.Count
                release = @($Items | Where-Object { $_.kind -eq "release" }).Count
                installation = @($Items | Where-Object { $_.kind -eq "installation" }).Count
                deployment = @($Items | Where-Object { $_.kind -eq "deployment" }).Count
            }
        }
        default {
            Fail "unknown inventory $InventoryId"
        }
    }
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
        $Manifest.artifact_set -ne "openclaw-upstream-compatibility-baseline" -or
        $Manifest.baseline_sha -ne $ExpectedSha -or
        $Manifest.baseline_path -ne "baseline.json" -or
        $Manifest.feature_schema_path -ne "feature-ledger.schema.json" -or
        $Manifest.validation_script -ne "validate.ps1" -or
        $Manifest.validation_self_test -ne "validate-self-test.ps1") {
        Fail "manifest fixed metadata mismatch"
    }

    $ledgerDeclarations = @($Manifest.ledgers)
    if ($ledgerDeclarations.Count -ne $LedgerSpecs.Count) {
        Fail "manifest must declare exactly 3 ledgers"
    }
    foreach ($spec in $LedgerSpecs) {
        $matches = @($ledgerDeclarations | Where-Object { $_.path -eq $spec.path })
        if ($matches.Count -ne 1) {
            Fail "manifest must declare ledger $($spec.path) exactly once"
        }
        Assert-ExactPropertySet $matches[0] @("path", "classification", "expected_features") "manifest.$($spec.path)"
        if ($matches[0].classification -ne $spec.classification -or
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
        $matches = @($inventoryDeclarations | Where-Object { $_.path -eq $spec.path })
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
        "legacy_typescript_is_not_rust_acceptance_evidence"
    ) "manifest.evidence_policy"
    if ($Manifest.evidence_policy.initial_status -ne "unimplemented" -or
        $Manifest.evidence_policy.acceptance_evidence_state -ne "missing" -or
        $Manifest.evidence_policy.legacy_typescript_is_not_rust_acceptance_evidence -ne $true) {
        Fail "manifest evidence policy mismatch"
    }
}

$actualJsonPaths = @(
    Get-ChildItem -LiteralPath $Root -Recurse -File -Filter "*.json" | ForEach-Object {
        $relative = $_.FullName.Substring($Root.Length)
        while ($relative.StartsWith("\") -or $relative.StartsWith("/")) {
            $relative = $relative.Substring(1)
        }
        $relative.Replace("\", "/")
    }
)
$missingJsonFiles = @($ExpectedJsonPaths | Where-Object { $actualJsonPaths -notcontains $_ })
$unexpectedJsonFiles = @($actualJsonPaths | Where-Object { $ExpectedJsonPaths -notcontains $_ })
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
    $baseline.upstream.repository -ne "openclaw/openclaw" -or
    $baseline.upstream.repository_url -ne "https://github.com/openclaw/openclaw" -or
    $baseline.upstream.branch -ne "main" -or
    $baseline.upstream.commit_sha -ne $ExpectedSha -or
    $baseline.upstream.tree_sha -ne "ba3177d3dd666b702d59c4daab74f62a9f7a84fb" -or
    $baseline.upstream.parent_sha -ne "a674ce5e0d1ab0774546086fa7b2730516eca176" -or
    $baseline.upstream.commit_timestamp -ne "2026-07-13T03:29:58Z" -or
    $baseline.upstream.commit_url -ne "https://github.com/openclaw/openclaw/commit/b43e832fcc8000ed7287c7accc54e381db607f85" -or
    $baseline.upstream.commit_signature_verified -ne $true -or
    $baseline.upstream.package_name -ne "openclaw" -or
    $baseline.upstream.package_version -ne "2026.7.2" -or
    $baseline.upstream.package_manifest_path -ne "package.json") {
    Fail "baseline upstream provenance mismatch"
}
Assert-ExactPropertySet $baseline.stable_release @(
    "tag", "name", "tag_object_sha", "commit_sha", "published_at", "release_url"
) "baseline.stable_release"
if ($baseline.stable_release.tag -ne "v2026.6.11" -or
    $baseline.stable_release.name -ne "openclaw 2026.6.11" -or
    $baseline.stable_release.tag_object_sha -ne "08d1bbad1bd6ee5700082e1c0f65f63f07600d1f" -or
    $baseline.stable_release.commit_sha -ne "e085fa1a3ffd32d0ea6917e1e6fb4ecbffbb77d2" -or
    $baseline.stable_release.published_at -ne "2026-06-30T16:06:39Z" -or
    $baseline.stable_release.release_url -ne "https://github.com/openclaw/openclaw/releases/tag/v2026.6.11") {
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
    $baseline.gateway_protocol.compatibility_window -ne "Authenticated role=node and client.mode=node clients may use v3 (N-1); general clients require v4." -or
    $baseline.gateway_protocol.source_path -ne "packages/gateway-protocol/src/version.ts" -or
    $baseline.gateway_protocol.documentation_path -ne "docs/gateway/protocol.md") {
    Fail "Gateway protocol baseline mismatch"
}
Assert-ExactPropertySet $baseline.licensing @(
    "repository_license", "repository_license_path", "repository_copyright",
    "third_party_notices_path", "exceptions", "content_policy"
) "baseline.licensing"
if ($baseline.licensing.repository_license -ne "MIT" -or
    $baseline.licensing.repository_license_path -ne "LICENSE" -or
    $baseline.licensing.repository_copyright -ne "Copyright (c) 2026 OpenClaw Foundation" -or
    $baseline.licensing.third_party_notices_path -ne "THIRD_PARTY_NOTICES.md" -or
    @($baseline.licensing.exceptions).Count -ne 1 -or
    $baseline.licensing.exceptions[0].path -ne "skills/skill-creator/license.txt" -or
    $baseline.licensing.exceptions[0].license -ne "Apache-2.0" -or
    $baseline.licensing.content_policy -ne "Contracts, identifiers, paths, metadata, and evidence references only; no upstream implementation code is copied.") {
    Fail "baseline licensing metadata mismatch"
}
Assert-ExactPropertySet $baseline.licensing.exceptions[0] @("path", "license") "baseline.licensing.exceptions[0]"

$schema = $documents["feature-ledger.schema.json"]
if ($schema.'$schema' -ne "https://json-schema.org/draft/2020-12/schema" -or
    $schema.'$id' -ne "https://github.com/GTAStudio/GTA-Claw/compat/upstream/feature-ledger.schema.json" -or
    (Get-ObjectDigest $schema) -ne $ExpectedSchemaDigest) {
    Fail "feature ledger schema is not the frozen Draft 2020-12 contract"
}

$manifest = $documents["manifest.json"]
Assert-ManifestDeclarations $manifest

$featureIds = New-Object System.Collections.Generic.HashSet[string]
$featureCount = 0
$missingEvidenceCount = 0
foreach ($spec in $LedgerSpecs) {
    $ledger = $documents[$spec.path]
    Assert-JsonSchema $ledger $schema $schema '$'
    if ($ledger.ledger_id -ne $spec.ledger_id -or
        $ledger.classification -ne $spec.classification -or
        $ledger.baseline_sha -ne $ExpectedSha) {
        Fail "$($spec.path) fixed ledger metadata mismatch"
    }
    $features = @($ledger.features)
    if ($features.Count -ne [int]$spec.expected_features) {
        Fail "$($spec.path) must contain exactly $($spec.expected_features) features"
    }
    if ((Get-FeatureDigest $features) -ne $spec.digest) {
        Fail "$($spec.path) canonical feature/source evidence fingerprint mismatch"
    }
    foreach ($feature in $features) {
        $featureCount += 1
        if (-not $featureIds.Add([string]$feature.feature_id)) {
            Fail "duplicate feature_id '$($feature.feature_id)'"
        }
        if ($feature.classification -ne $ledger.classification) {
            Fail "$($feature.feature_id) classification does not match its ledger"
        }
        if ($feature.status -ne "unimplemented" -or
            $feature.acceptance_evidence.status -ne "missing" -or
            @($feature.acceptance_evidence.artifacts).Count -ne 0) {
            Fail "$($feature.feature_id) must start unimplemented with an empty evidence placeholder"
        }
        if ($feature.last_verified_sha -ne $ExpectedSha) {
            Fail "$($feature.feature_id) last_verified_sha mismatch"
        }
        $missingEvidenceCount += 1
    }
}
if ($LedgerSpecs.Count -ne 3 -or $featureCount -ne 47 -or $missingEvidenceCount -ne 47) {
    Fail "fixed ledger totals must be 3 ledgers, 47 features, and 47 missing evidence placeholders"
}

$globalRecordIds = New-Object System.Collections.Generic.HashSet[string]
$inventoryRowCount = 0
$derivedByInventory = @{}
foreach ($inventoryId in $InventorySpecs.Keys) {
    $spec = $InventorySpecs[$inventoryId]
    $inventory = $documents[$spec.path]
    Assert-ExactPropertySet $inventory @(
        "schema_version", "inventory_id", "classification", "baseline_sha", "counts", "items"
    ) $spec.path
    if ($inventory.schema_version -ne 1 -or
        $inventory.inventory_id -ne $inventoryId -or
        $inventory.classification -ne $spec.classification -or
        $inventory.baseline_sha -ne $ExpectedSha) {
        Fail "$($spec.path) fixed inventory metadata mismatch"
    }
    if (-not ($inventory.items -is [System.Array])) {
        Fail "$($spec.path).items must be an array"
    }
    $items = @($inventory.items)
    if ($items.Count -ne [int]$spec.expected_items) {
        Fail "$($spec.path) must contain exactly $($spec.expected_items) rows"
    }

    $naturalIdentities = New-Object System.Collections.Generic.HashSet[string]
    for ($index = 0; $index -lt $items.Count; $index += 1) {
        $item = $items[$index]
        $context = "$($spec.path).items[$index]"
        Assert-RequiredProperties $item @($spec.required_fields) $context
        $unexpectedFields = @((Get-PropertyNames $item) | Where-Object { @($spec.allowed_fields) -notcontains $_ })
        if ($unexpectedFields.Count -gt 0) {
            Fail "$context contains unsupported fields [$($unexpectedFields -join ',')]"
        }
        foreach ($field in @("record_id", "id", "classification", "source_path")) {
            if ([string]::IsNullOrWhiteSpace([string](Get-PropertyValue $item $field))) {
                Fail "$context has empty required field $field"
            }
        }
        if ($AllowedClassifications -notcontains [string]$item.classification) {
            Fail "$context is unclassified"
        }
        if ($inventoryId -ne "http-sse-endpoints" -and $item.classification -ne $spec.classification) {
            Fail "$context classification differs from its inventory"
        }
        if (-not $globalRecordIds.Add([string]$item.record_id)) {
            Fail "duplicate global inventory record_id $($item.record_id)"
        }
        $naturalIdentity = (@($spec.natural_key_fields) | ForEach-Object {
            "$_=$(Convert-ScalarText (Get-PropertyValue $item $_))"
        }) -join [char]31
        if (-not $naturalIdentities.Add($naturalIdentity)) {
            Fail "$($spec.path) duplicate natural identity '$naturalIdentity'"
        }
        Assert-InventoryItemContract $inventoryId $item $context
        $inventoryRowCount += 1
    }

    if ((Get-InventoryDigest $items @($spec.canonical_fields)) -ne $spec.digest) {
        Fail "$($spec.path) canonical identity/source evidence fingerprint mismatch"
    }
    $derivedCounts = Get-DerivedInventoryCounts $inventoryId $items
    Assert-ExactCounts $inventory.counts $derivedCounts $spec.path
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
    $derivedCounts = Get-InventoryDerivedCounts $contract.InventoryId $items
    Assert-HashtableEquals ([pscustomobject]$derivedCounts) $contract.Counts "$($contract.Path).derived_counts"
    Assert-HashtableEquals $inventory.counts $derivedCounts "$($contract.Path).counts"
    $derivedByInventory[$contract.InventoryId] = $derivedCounts
}
if ($inventoryTotal -ne 717 -or $recordIds.Count -ne 717) {
    Fail "fixed inventory total must be 717 unique rows, got $inventoryTotal rows and $($recordIds.Count) record IDs"
}

[ordered]@{
    status = "ok"
    baseline_sha = $ExpectedSha
    artifact_json_files = $actualJsonPaths.Count
    ledgers = $LedgerSpecs.Count
    feature_rows = $featureCount
    missing_acceptance_evidence = $missingEvidenceCount
    inventory_files = $InventorySpecs.Count
    inventory_rows = $inventoryRowCount
    canonical_counts = $derivedCanonicalCounts
    inventory_subtotals = $derivedByInventory
} | ConvertTo-Json -Depth 8
