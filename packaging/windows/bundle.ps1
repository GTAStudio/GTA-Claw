[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$X64Msix,
    [Parameter(Mandatory)][string]$Arm64Msix,
    [switch]$ReleaseMode,
    [string]$Publisher = 'CN=GTAStudio Windows Signing Placeholder',
    [string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
Import-Module (Join-Path $scriptRoot 'WindowsPackaging.psm1') -Force
Import-Module (Join-Path $scriptRoot 'SupplyChain.psm1') -Force

if ($ReleaseMode -and $Publisher -eq 'CN=GTAStudio Windows Signing Placeholder') {
    throw 'Release MSIXBundle assembly requires the production certificate subject via -Publisher.'
}
if (-not $ReleaseMode -and $Publisher -ne 'CN=GTAStudio Windows Signing Placeholder') {
    throw 'A production publisher is accepted only in release mode.'
}

$ownedRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot 'out'))
Assert-NoReparsePathComponents -Root $repoRoot -Path $ownedRoot
[System.IO.Directory]::CreateDirectory($ownedRoot) | Out-Null
Assert-NoReparsePathComponents -Root $repoRoot -Path $ownedRoot
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $ownedRoot 'bundle'
}
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
Assert-ChildPath -Parent $ownedRoot -Child $OutputRoot | Out-Null
Assert-NoReparsePathComponents -Root $ownedRoot -Path $OutputRoot
$publishedOutputRoot = $OutputRoot

Initialize-MsvcEnvironment x64 | Out-Null
$makeAppx = Find-WindowsSdkTool 'makeappx.exe'
$version = Get-CanonicalVersion $repoRoot
Assert-RustToolchain $repoRoot
$innerSignature = 'unsigned'
if ($ReleaseMode) {
    $innerSignature = 'signed'
}

$inputs = @(
    [pscustomobject]@{ Path = (Assert-PlainFile $X64Msix); Architecture = 'x64' },
    [pscustomobject]@{ Path = (Assert-PlainFile $Arm64Msix); Architecture = 'arm64' }
)
$outputTransaction = Start-OwnedDirectoryTransaction `
    -OwnedRoot $ownedRoot `
    -Destination $publishedOutputRoot
$OutputRoot = $outputTransaction.WorkPath
try {
$inspectionRoot = Join-Path $OutputRoot '.inspection'
foreach ($input in $inputs) {
    Test-MsixPackage `
        -PackagePath $input.Path `
        -MakeAppxPath $makeAppx `
        -InspectionRoot (Join-Path $inspectionRoot $input.Architecture) `
        -Version $version.Msix `
        -Architecture $input.Architecture `
        -ExpectedPublisher $Publisher `
        -SignatureMode $innerSignature `
        -ReleaseStatus $(if ($ReleaseMode) { 'release-candidate' } else { 'non-release' })
}

$bundleInput = Join-Path $OutputRoot '.bundle-input'
[System.IO.Directory]::CreateDirectory($bundleInput) | Out-Null
foreach ($input in $inputs) {
    Copy-PlainFile `
        -Source $input.Path `
        -Destination (Join-Path $bundleInput "gta-claw-desktop-$($version.Cargo)-windows-$($input.Architecture).msix")
}

$qualifier = 'unsigned-non-release'
if ($ReleaseMode) {
    $qualifier = 'release-candidate-unsigned'
}
$bundle = Join-Path $OutputRoot "gta-claw-desktop-$($version.Cargo)-windows-x64_arm64-$qualifier.msixbundle"
Invoke-CheckedCommand -FilePath $makeAppx -Arguments @(
    'bundle', '/d', $bundleInput, '/p', $bundle, '/bv', $version.Msix, '/o'
)
Set-NormalizedZipTimestamps $bundle
Test-MsixBundle `
    -PackagePath $bundle `
    -MakeAppxPath $makeAppx `
    -InspectionRoot (Join-Path $inspectionRoot 'bundle') `
    -Version $version.Msix `
    -ExpectedPublisher $Publisher `
    -SignatureMode unsigned `
    -InnerSignatureMode $innerSignature `
    -InnerReleaseStatus $(if ($ReleaseMode) { 'release-candidate' } else { 'non-release' })

Remove-OwnedDirectory -OwnedRoot $OutputRoot -Path $bundleInput
Remove-OwnedDirectory -OwnedRoot $OutputRoot -Path $inspectionRoot
Write-ArtifactHash $bundle | Out-Null
New-ArtifactSupplyChain `
    -RepoRoot $repoRoot `
    -ArtifactPath $bundle `
    -ComponentSet desktop `
    -RustTarget @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc') `
    -ProvenanceTargets @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc') | Out-Null
Write-ArtifactSetChecksums $OutputRoot | Out-Null
Test-ArtifactSetChecksums $OutputRoot

$inventory = [ordered]@{
    schema = 1
    status = $(if ($ReleaseMode) { 'release-candidate-unsigned' } else { 'unsigned-non-release' })
    cargo_version = $version.Cargo
    msix_version = $version.Msix
    architectures = @('x64', 'arm64')
    publisher = $Publisher
    artifact = [System.IO.Path]::GetFileName($bundle)
}
Write-Utf8File -Path (Join-Path $OutputRoot 'artifacts.json') -Content (($inventory | ConvertTo-Json -Depth 5) + "`n")
    Complete-OwnedDirectoryTransaction $outputTransaction
} catch {
    Undo-OwnedDirectoryTransaction $outputTransaction
    throw
}
Write-Host "Created and inspected MSIXBundle '$(Join-Path $publishedOutputRoot ([System.IO.Path]::GetFileName($bundle)))'."
