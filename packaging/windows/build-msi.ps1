[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture,

    [Parameter(Mandatory)]
    [string]$StageDirectory,

    [string]$WixPath,

    [string]$OutputPath,

    [switch]$ReleaseMode
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
$releaseStatus = [System.IO.File]::ReadAllText((Join-Path $stage 'RELEASE-STATUS.txt'))
if ($ReleaseMode -and $releaseStatus -notmatch 'RELEASE CANDIDATE') {
    throw 'Release MSI staging lacks an explicit release-candidate marker.'
}
if (-not $ReleaseMode -and $releaseStatus -notmatch 'UNSIGNED NON-RELEASE') {
    throw 'Unsigned MSI staging lacks an explicit non-release marker.'
}
foreach ($name in @('gta-claw-desktop.exe', 'gta-claw-cli.exe', 'gta-claw-daemon.exe')) {
    $binary = Join-Path $stage $name
    if ($name -ne 'gta-claw-desktop.exe') {
        $binary = Join-Path $stage "headless\$name"
    }
    Assert-PeArchitecture -Path $binary -ExpectedMachine $arch.PeMachine
}
Set-NormalizedTreeTimestamp $stage

$source = Join-Path $scriptRoot 'wix\GtaClaw.wxs'
Test-WixSource $source
if ([string]::IsNullOrWhiteSpace($WixPath)) {
    if (-not [string]::IsNullOrWhiteSpace($env:GTA_CLAW_WIX)) {
        $WixPath = $env:GTA_CLAW_WIX
    }
}
if ([string]::IsNullOrWhiteSpace($WixPath)) {
    $command = Get-Command wix.exe -ErrorAction Stop
    $WixPath = $command.Source
}
Assert-PlainFile $WixPath | Out-Null
if ($null -eq (Get-Command dumpbin.exe -ErrorAction SilentlyContinue)) {
    Initialize-MsvcEnvironment $Architecture | Out-Null
}

$ownedRoot = Join-Path $scriptRoot 'out'
Assert-NoReparsePathComponents -Root $repoRoot -Path $ownedRoot
[System.IO.Directory]::CreateDirectory($ownedRoot) | Out-Null
Assert-NoReparsePathComponents -Root $repoRoot -Path $ownedRoot
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputDirectory = Join-Path $ownedRoot $arch.Name
    Assert-NoReparsePathComponents -Root $ownedRoot -Path $outputDirectory
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
    Assert-NoReparsePathComponents -Root $ownedRoot -Path $outputDirectory
    $qualifier = 'unsigned-non-release'
    if ($ReleaseMode) {
        $qualifier = 'release-candidate-unsigned'
    }
    $OutputPath = Join-Path $outputDirectory "gta-claw-$($version.Cargo)-windows-$($arch.Name)-$qualifier.msi"
} else {
    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    Assert-ChildPath -Parent $ownedRoot -Child $OutputPath | Out-Null
    Assert-NoReparsePathComponents -Root $ownedRoot -Path $OutputPath
}
$publishedOutputPath = $OutputPath
$outputDirectory = Split-Path -Parent $publishedOutputPath
$temporaryOutputPath = Join-Path $outputDirectory (
    ".{0}.packaging-new.msi" -f [System.IO.Path]::GetFileNameWithoutExtension($publishedOutputPath)
)
$temporaryWixPdb = [System.IO.Path]::ChangeExtension($temporaryOutputPath, '.wixpdb')
$temporaryHashPath = "$temporaryOutputPath.sha256"
Assert-ChildPath -Parent $ownedRoot -Child $temporaryOutputPath | Out-Null
foreach ($stalePath in @($temporaryOutputPath, $temporaryWixPdb, $temporaryHashPath)) {
    if (Test-Path -LiteralPath $stalePath) {
        Remove-Item -LiteralPath $stalePath -Force
    }
}
$OutputPath = $temporaryOutputPath

$productNamespace = [Guid]'DAD72B88-4094-5FD5-9494-D8C54C8DFE7D'
$productCode = New-UuidV5 -Namespace $productNamespace -Name "$($arch.Name):$($version.Msi)"
$packageNamespace = [Guid]'30E765FA-E804-5919-987E-C06725F6F25B'
$packageCode = New-UuidV5 -Namespace $packageNamespace -Name "$($arch.Name):$($version.Msi)"
$componentNamespace = [Guid]'725599B6-B7E4-5A10-A600-FC1E40B62EAE'
$componentIds = @('License', 'ReleaseStatus', 'HashManifest', 'Desktop', 'Cli', 'Daemon')
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
$inspectionRoot = Join-Path $outputDirectory '.msi-inspection'
try {
Invoke-CheckedCommand -FilePath $WixPath -Arguments $wixArguments
Assert-PlainFile $OutputPath | Out-Null
$installer = New-Object -ComObject WindowsInstaller.Installer
$summary = $installer.GetType().InvokeMember(
    'SummaryInformation',
    [System.Reflection.BindingFlags]::GetProperty,
    $null,
    $installer,
    @($OutputPath, 3)
)
$fixedTimestamp = [DateTime]::SpecifyKind(
    [DateTime]::ParseExact('2000-01-01T00:00:00', 'yyyy-MM-ddTHH:mm:ss', $null),
    [DateTimeKind]::Unspecified
)
foreach ($property in @(12, 13)) {
    $summary.GetType().InvokeMember(
        'Property',
        [System.Reflection.BindingFlags]::SetProperty,
        $null,
        $summary,
        @($property, $fixedTimestamp)
    ) | Out-Null
}
$summary.GetType().InvokeMember(
    'Property',
    [System.Reflection.BindingFlags]::SetProperty,
    $null,
    $summary,
    @(9, $packageCode.ToString('B').ToUpperInvariant())
) | Out-Null
$summary.GetType().InvokeMember(
    'Persist',
    [System.Reflection.BindingFlags]::InvokeMethod,
    $null,
    $summary,
    $null
) | Out-Null
$summary = $null
[GC]::Collect()
[GC]::WaitForPendingFinalizers()
Set-NormalizedMsiStorageTimestamps $OutputPath
$wixPdb = $temporaryWixPdb
if (Test-Path -LiteralPath $wixPdb -PathType Leaf) {
    Remove-Item -LiteralPath $wixPdb -Force
}
Test-MsiPackage `
    -PackagePath $OutputPath `
    -InspectionRoot $inspectionRoot `
    -Architecture $Architecture `
    -SignatureMode unsigned `
    -ReleaseStatus $(if ($ReleaseMode) { 'release-candidate' } else { 'non-release' })
Write-ArtifactHash `
    -Path $temporaryOutputPath `
    -HashPath $temporaryHashPath `
    -ArtifactName ([System.IO.Path]::GetFileName($publishedOutputPath)) | Out-Null
Test-ArtifactHash `
    -Path $temporaryOutputPath `
    -HashPath $temporaryHashPath `
    -ArtifactName ([System.IO.Path]::GetFileName($publishedOutputPath))
} catch {
    foreach ($temporaryPath in @($temporaryOutputPath, $temporaryWixPdb, $temporaryHashPath)) {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
    throw
} finally {
    if (Test-Path -LiteralPath $inspectionRoot) {
        Remove-OwnedDirectory -OwnedRoot $outputDirectory -Path $inspectionRoot
    }
}

Publish-OwnedArtifactPair `
    -OwnedRoot $ownedRoot `
    -StagedArtifact $temporaryOutputPath `
    -StagedHash $temporaryHashPath `
    -DestinationArtifact $publishedOutputPath
Write-Host "Created and inspected unsigned MSI '$publishedOutputPath'."
