[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture,

    [Parameter(Mandatory)]
    [string]$StageDirectory,

    [string]$WixPath,

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
Import-Module (Join-Path $scriptRoot 'WindowsPackaging.psm1') -Force

$arch = Get-Architecture $Architecture
$version = Get-CanonicalVersion $repoRoot
$stage = [System.IO.Path]::GetFullPath($StageDirectory)
Assert-NoReparsePoints $stage
Test-HashManifest $stage
Assert-PayloadSafety -Root $stage -ExpectedExecutables @(
    'gta-claw-desktop.exe', 'gta-claw-cli.exe', 'gta-claw-daemon.exe'
)
foreach ($name in @('gta-claw-desktop.exe', 'gta-claw-cli.exe', 'gta-claw-daemon.exe')) {
    Assert-PeArchitecture -Path (Join-Path $stage $name) -ExpectedMachine $arch.PeMachine
}

$source = Join-Path $scriptRoot 'wix\GtaClaw.wxs'
Test-WixSource $source
if ([string]::IsNullOrWhiteSpace($WixPath)) {
    $command = Get-Command wix -ErrorAction Stop
    $WixPath = $command.Source
}
Assert-PlainFile $WixPath | Out-Null

$ownedRoot = Join-Path $scriptRoot 'out'
Assert-NoReparsePathComponents -Root $repoRoot -Path $ownedRoot
[System.IO.Directory]::CreateDirectory($ownedRoot) | Out-Null
Assert-NoReparsePathComponents -Root $repoRoot -Path $ownedRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputDirectory = Join-Path $ownedRoot $arch.Name
    Assert-NoReparsePathComponents -Root $ownedRoot -Path $outputDirectory
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
    Assert-NoReparsePathComponents -Root $ownedRoot -Path $outputDirectory
    $OutputPath = Join-Path $outputDirectory "gta-claw-$($version.Cargo)-windows-$($arch.Name)-unsigned-non-release.msi"
} else {
    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    Assert-ChildPath -Parent $ownedRoot -Child $OutputPath | Out-Null
    Assert-NoReparsePathComponents -Root $ownedRoot -Path $OutputPath
}
if (Test-Path -LiteralPath $OutputPath) {
    Remove-Item -LiteralPath $OutputPath -Force
}

$productNamespace = [Guid]'DAD72B88-4094-5FD5-9494-D8C54C8DFE7D'
$productCode = New-UuidV5 -Namespace $productNamespace -Name "$($arch.Name):$($version.Msi)"
$componentNamespace = [Guid]'725599B6-B7E4-5A10-A600-FC1E40B62EAE'
$componentIds = @('License', 'NonRelease', 'HashManifest', 'Desktop', 'Cli', 'Daemon')
$componentDefines = @()
foreach ($componentId in $componentIds) {
    $guid = New-UuidV5 -Namespace $componentNamespace -Name "$($arch.Name):$componentId"
    $componentDefines += @('-d', "$($componentId)ComponentGuid=$($guid.ToString().ToUpperInvariant())")
}
$wixArguments = @(
    'build',
    '-arch', $arch.Name,
    '-d', "StageDir=$stage",
    '-d', "ProductVersion=$($version.Msi)",
    '-d', "ProductCode=$($productCode.ToString().ToUpperInvariant())",
    '-d', "UpgradeCode=$($arch.UpgradeCode)",
    '-o', $OutputPath
) + $componentDefines + @($source)
Invoke-CheckedCommand -FilePath $WixPath -Arguments $wixArguments
Assert-PlainFile $OutputPath | Out-Null
Write-ArtifactHash $OutputPath | Out-Null
Write-Host "Created unsigned non-release MSI prototype '$OutputPath'."
