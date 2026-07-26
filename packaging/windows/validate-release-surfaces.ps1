[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
$inventoryPath = Join-Path $repoRoot 'compat\upstream\inventories\release-deployment.json'
$implementationPath = Join-Path $scriptRoot 'release-surfaces.json'

$inventory = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
$implementation = Get-Content -LiteralPath $implementationPath -Raw | ConvertFrom-Json

if ($inventory.inventory_id -ne 'release-deployment' -or $inventory.counts.total -ne 24) {
    throw 'Frozen release-deployment inventory identity or count changed.'
}
if ($implementation.schema -ne 1 -or $implementation.platform -ne 'windows') {
    throw 'Windows release surface declaration is invalid.'
}

$applicable = @($inventory.items |
    Where-Object { $_.id -in @('github-release', 'installer') -or $_.id.StartsWith('windows-') } |
    ForEach-Object { $_.id } |
    Sort-Object)
$implemented = @($implementation.implemented | Sort-Object)

if (($applicable -join "`n") -ne ($implemented -join "`n")) {
    throw "Windows release surfaces differ from the frozen inventory.`nExpected: $($applicable -join ', ')`nImplemented: $($implemented -join ', ')"
}
if ($implementation.native_replacements.'windows-node' -notmatch 'npm-free Rust') {
    throw 'The windows-node surface must document its npm-free Rust replacement.'
}

Write-Host "Windows frozen release surfaces match exactly: $($implemented -join ', ')."
