[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture,

    [string]$OutputRoot,

    [switch]$SkipBuild,

    [string]$DesktopExecutable,

    [string]$CliExecutable,

    [string]$DaemonExecutable,

    [switch]$SkipMsix,

    [switch]$SkipMsi,

    [switch]$ReleaseMode,

    [string]$Publisher = 'CN=GTAStudio Windows Signing Placeholder',

    [string]$WixPath,

    [string]$BuildRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
Import-Module (Join-Path $scriptRoot 'WindowsPackaging.psm1') -Force
Import-Module (Join-Path $scriptRoot 'SupplyChain.psm1') -Force

if ($ReleaseMode -and $Publisher -eq 'CN=GTAStudio Windows Signing Placeholder') {
    throw 'Release mode requires the exact subject of the provisioned signing certificate via -Publisher.'
}
if (-not $ReleaseMode -and $Publisher -ne 'CN=GTAStudio Windows Signing Placeholder') {
    throw 'A production publisher is accepted only in explicit release mode.'
}

$ownedRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot 'out'))
Assert-NoReparsePathComponents -Root $repoRoot -Path $ownedRoot
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = $ownedRoot
} else {
    $OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
    if (-not $OutputRoot.Equals($ownedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Assert-ChildPath -Parent $ownedRoot -Child $OutputRoot | Out-Null
    }
}
[System.IO.Directory]::CreateDirectory($ownedRoot) | Out-Null
Assert-NoReparsePathComponents -Root $repoRoot -Path $ownedRoot
Assert-NoReparsePathComponents -Root $ownedRoot -Path $OutputRoot
[System.IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
Assert-NoReparsePathComponents -Root $ownedRoot -Path $OutputRoot

$arch = Get-Architecture $Architecture
$version = Get-CanonicalVersion $repoRoot
$archRoot = Join-Path $OutputRoot $arch.Name
Remove-OwnedDirectory -OwnedRoot $OutputRoot -Path $archRoot
[System.IO.Directory]::CreateDirectory($archRoot) | Out-Null

$license = Join-Path $scriptRoot 'LICENSE.txt'
$assetSpec = Join-Path $scriptRoot 'assets\logo-spec.json'
$manifestTemplate = Join-Path $scriptRoot 'AppxManifest.template.xml'
$wixSource = Join-Path $scriptRoot 'wix\GtaClaw.wxs'
Assert-PlainFile $license | Out-Null
Assert-PlainFile $assetSpec | Out-Null
Assert-PlainFile $manifestTemplate | Out-Null
Test-WixSource $wixSource
Assert-HeadlessGraph -RepoRoot $repoRoot -TargetTriple $arch.RustTarget

$workRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '.work'))
[System.IO.Directory]::CreateDirectory($workRoot) | Out-Null
Assert-NoReparsePathComponents -Root $scriptRoot -Path $workRoot
if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
    if (-not [string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        $BuildRoot = Join-Path $env:CARGO_TARGET_DIR "windows-packaging\$($arch.RustTarget)"
    } else {
        $BuildRoot = Join-Path $workRoot "build\$($arch.RustTarget)"
    }
}
$buildRoot = [System.IO.Path]::GetFullPath($BuildRoot)
if (-not $SkipBuild) {
    [System.IO.Directory]::CreateDirectory($buildRoot) | Out-Null
    Initialize-MsvcEnvironment $arch.Name | Out-Null
    $cargo = (Get-Command cargo -ErrorAction Stop).Source
    $priorTargetDir = $env:CARGO_TARGET_DIR
    $priorEncodedRustflags = $env:CARGO_ENCODED_RUSTFLAGS
    try {
        $rustflags = @(
            "-Ctarget-feature=+crt-static",
            "--remap-path-prefix=$repoRoot=.",
            '-Dwarnings'
        )
        $env:CARGO_ENCODED_RUSTFLAGS = $rustflags -join [char]0x1F
        $headlessTargetDir = Join-Path $buildRoot 'headless'
        $env:CARGO_TARGET_DIR = $headlessTargetDir
        Invoke-CheckedCommand -FilePath $cargo -Arguments @(
            'build',
            '--manifest-path', (Join-Path $repoRoot 'Cargo.toml'),
            '--locked',
            '--offline',
            '--release',
            '--target', $arch.RustTarget,
            '--package', 'gta-claw-cli',
            '--package', 'gta-claw-daemon'
        )
        $desktopTargetDir = Join-Path $buildRoot 'desktop'
        $env:CARGO_TARGET_DIR = $desktopTargetDir
        Invoke-CheckedCommand -FilePath $cargo -Arguments @(
            'build',
            '--manifest-path', (Join-Path $repoRoot 'desktop\Cargo.toml'),
            '--locked',
            '--offline',
            '--release',
            '--target', $arch.RustTarget,
            '--package', 'gta-claw-desktop'
        )
    } finally {
        $env:CARGO_TARGET_DIR = $priorTargetDir
        $env:CARGO_ENCODED_RUSTFLAGS = $priorEncodedRustflags
    }
    $DesktopExecutable = Join-Path $buildRoot "desktop\$($arch.RustTarget)\release\gta-claw-desktop.exe"
    $CliExecutable = Join-Path $buildRoot "headless\$($arch.RustTarget)\release\gta-claw-cli.exe"
    $DaemonExecutable = Join-Path $buildRoot "headless\$($arch.RustTarget)\release\gta-claw-daemon.exe"
} elseif ([string]::IsNullOrWhiteSpace($DesktopExecutable) -or
    [string]::IsNullOrWhiteSpace($CliExecutable) -or
    [string]::IsNullOrWhiteSpace($DaemonExecutable)) {
    throw '-SkipBuild requires -DesktopExecutable, -CliExecutable, and -DaemonExecutable.'
}

$executables = @{
    Desktop = Assert-PlainFile $DesktopExecutable
    Cli = Assert-PlainFile $CliExecutable
    Daemon = Assert-PlainFile $DaemonExecutable
}
foreach ($path in $executables.Values) {
    Assert-PeArchitecture -Path $path -ExpectedMachine $arch.PeMachine
}
if ($null -eq (Get-Command dumpbin.exe -ErrorAction SilentlyContinue)) {
    Initialize-MsvcEnvironment $arch.Name | Out-Null
}

$releaseStatusText = @"
UNSIGNED NON-RELEASE VALIDATION ARTIFACT

This payload is not signed, not trusted for deployment, and must not be
published as a release.
"@
if ($ReleaseMode) {
    $releaseStatusText = @"
RELEASE CANDIDATE - AUTHENTICODE SIGNATURE REQUIRED

This payload uses the production package identity but is not a release until
sign.ps1 creates and verifies a signed, timestamped output.
"@
}

$layoutRoot = Join-Path $archRoot 'layouts'
$desktopPortable = Join-Path $layoutRoot 'portable-desktop'
$headlessPortable = Join-Path $layoutRoot 'portable-headless'
$msixLayout = Join-Path $layoutRoot 'msix'
$msiLayout = Join-Path $layoutRoot 'msi'
foreach ($directory in @($desktopPortable, $headlessPortable, $msixLayout, $msiLayout)) {
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
}

Copy-PlainFile -Source $executables.Desktop -Destination (Join-Path $desktopPortable 'gta-claw-desktop.exe')
Copy-PlainFile -Source $license -Destination (Join-Path $desktopPortable 'LICENSE.txt')
if ($ReleaseMode) {
    Write-Utf8File -Path (Join-Path $desktopPortable 'RELEASE-STATUS.txt') -Content @"
RELEASE PORTABLE ARTIFACT

Portable ZIP archives do not carry Authenticode package signatures. Verify
SHA256SUMS, SPDX SBOM, and provenance before distribution.
"@
} else {
    Write-Utf8File -Path (Join-Path $desktopPortable 'RELEASE-STATUS.txt') -Content $releaseStatusText
}
New-HashManifest $desktopPortable | Out-Null
Test-HashManifest $desktopPortable
Assert-PayloadSafety -Root $desktopPortable -ExpectedExecutables @('gta-claw-desktop.exe')

Copy-PlainFile -Source $executables.Cli -Destination (Join-Path $headlessPortable 'gta-claw-cli.exe')
Copy-PlainFile -Source $executables.Daemon -Destination (Join-Path $headlessPortable 'gta-claw-daemon.exe')
Copy-PlainFile -Source $license -Destination (Join-Path $headlessPortable 'LICENSE.txt')
if ($ReleaseMode) {
    Write-Utf8File -Path (Join-Path $headlessPortable 'RELEASE-STATUS.txt') -Content @"
RELEASE PORTABLE ARTIFACT

Portable ZIP archives do not carry Authenticode package signatures. Verify
SHA256SUMS, SPDX SBOM, and provenance before distribution.
"@
} else {
    Write-Utf8File -Path (Join-Path $headlessPortable 'RELEASE-STATUS.txt') -Content $releaseStatusText
}
New-HashManifest $headlessPortable | Out-Null
Test-HashManifest $headlessPortable
Assert-PayloadSafety -Root $headlessPortable -ExpectedExecutables @('gta-claw-cli.exe', 'gta-claw-daemon.exe')

$zipQualifier = 'portable-unsigned-non-release'
if ($ReleaseMode) {
    $zipQualifier = 'portable-release'
}
$desktopZip = Join-Path $archRoot "gta-claw-desktop-$($version.Cargo)-windows-$($arch.Name)-$zipQualifier.zip"
$headlessZip = Join-Path $archRoot "gta-claw-headless-$($version.Cargo)-windows-$($arch.Name)-$zipQualifier.zip"
New-DeterministicZip -Root $desktopPortable -Destination $desktopZip | Out-Null
New-DeterministicZip -Root $headlessPortable -Destination $headlessZip | Out-Null
Write-ArtifactHash $desktopZip | Out-Null
Write-ArtifactHash $headlessZip | Out-Null
$zipInspection = Join-Path $archRoot 'work\zip-inspection'
$portableStatus = 'non-release'
if ($ReleaseMode) {
    $portableStatus = 'release'
}
Test-ZipPackage `
    -PackagePath $desktopZip `
    -InspectionRoot (Join-Path $zipInspection 'desktop') `
    -Architecture $Architecture `
    -ComponentSet desktop `
    -ReleaseStatus $portableStatus
Test-ZipPackage `
    -PackagePath $headlessZip `
    -InspectionRoot (Join-Path $zipInspection 'headless') `
    -Architecture $Architecture `
    -ComponentSet headless `
    -ReleaseStatus $portableStatus

Copy-PlainFile -Source $executables.Desktop -Destination (Join-Path $msixLayout 'gta-claw-desktop.exe')
Copy-PlainFile -Source $license -Destination (Join-Path $msixLayout 'LICENSE.txt')
Write-Utf8File -Path (Join-Path $msixLayout 'RELEASE-STATUS.txt') -Content $releaseStatusText
$assetsDirectory = Join-Path $msixLayout 'Assets'
New-VisualAssets -SpecPath $assetSpec -OutputDirectory $assetsDirectory
New-AppxManifest `
    -TemplatePath $manifestTemplate `
    -OutputPath (Join-Path $msixLayout 'AppxManifest.xml') `
    -MsixVersion $version.Msix `
    -Architecture $arch.Msix `
    -Publisher $Publisher
New-HashManifest $msixLayout | Out-Null
Test-HashManifest $msixLayout
Test-AppxManifest `
    -Path (Join-Path $msixLayout 'AppxManifest.xml') `
    -Version $version.Msix `
    -Architecture $arch.Msix `
    -ExpectedPublisher $Publisher
Assert-PayloadSafety -Root $msixLayout -ExpectedExecutables @('gta-claw-desktop.exe')

Copy-PlainFile -Source $executables.Desktop -Destination (Join-Path $msiLayout 'gta-claw-desktop.exe')
Copy-PlainFile -Source $executables.Cli -Destination (Join-Path $msiLayout 'headless\gta-claw-cli.exe')
Copy-PlainFile -Source $executables.Daemon -Destination (Join-Path $msiLayout 'headless\gta-claw-daemon.exe')
Copy-PlainFile -Source $license -Destination (Join-Path $msiLayout 'LICENSE.txt')
Write-Utf8File -Path (Join-Path $msiLayout 'RELEASE-STATUS.txt') -Content $releaseStatusText
New-HashManifest $msiLayout | Out-Null
Test-HashManifest $msiLayout
Assert-PayloadSafety -Root $msiLayout -ExpectedExecutables @(
    'gta-claw-desktop.exe', 'gta-claw-cli.exe', 'gta-claw-daemon.exe'
)
Set-NormalizedTreeTimestamp $msixLayout
Set-NormalizedTreeTimestamp $msiLayout

$makeAppx = $null
$msixPackage = $null
if (-not $SkipMsix) {
    $makeAppx = Find-WindowsSdkTool 'makeappx.exe'
    $msixQualifier = 'unsigned-non-release'
    if ($ReleaseMode) {
        $msixQualifier = 'release-candidate-unsigned'
    }
    $msixPackage = Join-Path $archRoot "gta-claw-desktop-$($version.Cargo)-windows-$($arch.Name)-$msixQualifier.msix"
    Invoke-CheckedCommand -FilePath $makeAppx -Arguments @(
        'pack', '/h', 'SHA256', '/d', $msixLayout, '/p', $msixPackage, '/o'
    )
    Set-NormalizedZipTimestamps $msixPackage
    $inspectionRoot = Join-Path $archRoot 'work\msix-inspection'
    [System.IO.Directory]::CreateDirectory((Split-Path -Parent $inspectionRoot)) | Out-Null
    Test-MsixPackage `
        -PackagePath $msixPackage `
        -MakeAppxPath $makeAppx `
        -InspectionRoot $inspectionRoot `
        -Version $version.Msix `
        -Architecture $arch.Msix `
        -ExpectedPublisher $Publisher `
        -SignatureMode unsigned `
        -ReleaseStatus $(if ($ReleaseMode) { 'release-candidate' } else { 'non-release' })
    Write-ArtifactHash $msixPackage | Out-Null
}

$msiPackage = $null
if (-not $SkipMsi) {
    $msiQualifier = 'unsigned-non-release'
    if ($ReleaseMode) {
        $msiQualifier = 'release-candidate-unsigned'
    }
    $msiPackage = Join-Path $archRoot "gta-claw-$($version.Cargo)-windows-$($arch.Name)-$msiQualifier.msi"
    $msiArguments = @{
        Architecture = $Architecture
        StageDirectory = $msiLayout
        OutputPath = $msiPackage
        ReleaseMode = $ReleaseMode
    }
    if (-not [string]::IsNullOrWhiteSpace($WixPath)) {
        $msiArguments.WixPath = $WixPath
    }
    & (Join-Path $scriptRoot 'build-msi.ps1') @msiArguments
}

New-ArtifactSupplyChain `
    -RepoRoot $repoRoot `
    -ArtifactPath $desktopZip `
    -ComponentSet desktop `
    -RustTarget $arch.RustTarget | Out-Null
New-ArtifactSupplyChain `
    -RepoRoot $repoRoot `
    -ArtifactPath $headlessZip `
    -ComponentSet headless `
    -RustTarget $arch.RustTarget | Out-Null
if ($null -ne $msixPackage) {
    New-ArtifactSupplyChain `
        -RepoRoot $repoRoot `
        -ArtifactPath $msixPackage `
        -ComponentSet desktop `
        -RustTarget $arch.RustTarget | Out-Null
}
if ($null -ne $msiPackage) {
    New-ArtifactSupplyChain `
        -RepoRoot $repoRoot `
        -ArtifactPath $msiPackage `
        -ComponentSet combined `
        -RustTarget $arch.RustTarget | Out-Null
}
Write-ArtifactSetChecksums $archRoot | Out-Null
Test-ArtifactSetChecksums $archRoot
if (Test-Path -LiteralPath (Join-Path $archRoot 'work')) {
    Remove-OwnedDirectory -OwnedRoot $archRoot -Path (Join-Path $archRoot 'work')
}

$toolVersion = $null
if ($null -ne $makeAppx) {
    $toolVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($makeAppx).FileVersion
}
$inventory = [ordered]@{
    schema = 1
    status = $(if ($ReleaseMode) { 'release-candidate-unsigned' } else { 'unsigned-non-release' })
    cargo_version = $version.Cargo
    msix_version = $version.Msix
    msi_version = $version.Msi
    architecture = $arch.Name
    rust_target = $arch.RustTarget
    pe_machine = ('0x{0:X4}' -f $arch.PeMachine)
    package_identity = 'GTAStudio.GTAClaw'
    publisher = $Publisher
    makeappx_version = $toolVersion
    artifacts = @(
        [System.IO.Path]::GetFileName($desktopZip),
        [System.IO.Path]::GetFileName($headlessZip)
    )
    deferred = @('store-publication', 'app-installer-feed', 'service-installation')
}
if ($null -ne $msixPackage) {
    $inventory.artifacts += [System.IO.Path]::GetFileName($msixPackage)
}
if ($null -ne $msiPackage) {
    $inventory.artifacts += [System.IO.Path]::GetFileName($msiPackage)
}
Write-Utf8File -Path (Join-Path $archRoot 'artifacts.json') -Content (($inventory | ConvertTo-Json -Depth 5) + "`n")

Write-Host "Created inspected Windows packaging outputs in '$archRoot' with status '$($inventory.status)'."
