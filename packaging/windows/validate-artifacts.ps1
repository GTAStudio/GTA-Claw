[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactDirectory,
    [string]$Publisher = 'CN=GTAStudio Windows Signing Placeholder',
    [ValidatePattern('^SHA256SUMS(?:-[a-z]+)?$')][string]$ChecksumName = 'SHA256SUMS'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$scriptRoot = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $scriptRoot 'WindowsPackaging.psm1') -Force
Import-Module (Join-Path $scriptRoot 'SupplyChain.psm1') -Force

$root = [System.IO.Path]::GetFullPath($ArtifactDirectory)
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "Published artifact directory is missing: $root"
}
Assert-NoReparsePoints $root
Initialize-MsvcEnvironment x64 | Out-Null
$makeAppx = Find-WindowsSdkTool 'makeappx.exe'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
$version = Get-CanonicalVersion $repoRoot
$inspection = Join-Path $root '.published-inspection'
if (Test-Path -LiteralPath $inspection) {
    Remove-OwnedDirectory -OwnedRoot $root -Path $inspection
}
[System.IO.Directory]::CreateDirectory($inspection) | Out-Null

try {
    $artifacts = @(Get-ChildItem -LiteralPath $root -File |
        Where-Object { $_.Extension.ToLowerInvariant() -in @('.zip', '.msix', '.msixbundle', '.msi') } |
        Sort-Object Name)
    if ($artifacts.Count -eq 0) {
        throw "No published Windows artifacts found in '$root'."
    }
    $actualArtifactNames = @($artifacts | Select-Object -ExpandProperty Name | Sort-Object)
    $releaseSet = @($artifacts | Where-Object {
        $_.Name -match 'portable-release|-signed\.'
    }).Count -ne 0
    $bundleSet = @($artifacts | Where-Object { $_.Extension -eq '.msixbundle' }).Count -ne 0
    if ($bundleSet -and $artifacts.Count -eq 1 -and -not $releaseSet) {
        $expectedArtifactNames = @(
            "gta-claw-desktop-$($version.Cargo)-windows-x64_arm64-unsigned-non-release.msixbundle"
        )
    } elseif ($releaseSet) {
        $expectedArtifactNames = @(
            "gta-claw-$($version.Cargo)-windows-x64-signed.msi",
            "gta-claw-desktop-$($version.Cargo)-windows-arm64-portable-release.zip",
            "gta-claw-desktop-$($version.Cargo)-windows-arm64-signed.msix",
            "gta-claw-desktop-$($version.Cargo)-windows-x64-portable-release.zip",
            "gta-claw-desktop-$($version.Cargo)-windows-x64-signed.msix",
            "gta-claw-desktop-$($version.Cargo)-windows-x64_arm64-signed.msixbundle",
            "gta-claw-headless-$($version.Cargo)-windows-arm64-portable-release.zip",
            "gta-claw-headless-$($version.Cargo)-windows-x64-portable-release.zip"
        ) | Sort-Object
    } else {
        $packageArchitecture = 'x64'
        if (@($artifacts | Where-Object { $_.Name -match 'windows-arm64' }).Count -ne 0) {
            $packageArchitecture = 'arm64'
        }
        $expectedArtifactNames = @(
            "gta-claw-$($version.Cargo)-windows-$packageArchitecture-unsigned-non-release.msi",
            "gta-claw-desktop-$($version.Cargo)-windows-$packageArchitecture-portable-unsigned-non-release.zip",
            "gta-claw-desktop-$($version.Cargo)-windows-$packageArchitecture-unsigned-non-release.msix",
            "gta-claw-headless-$($version.Cargo)-windows-$packageArchitecture-portable-unsigned-non-release.zip"
        ) | Sort-Object
    }
    if (($actualArtifactNames -join "`n") -cne ($expectedArtifactNames -join "`n")) {
        throw "Published Windows artifact set differs from its exact delivery profile."
    }
    $allowedFiles = @{}
    $allowedFiles[$ChecksumName] = $true
    foreach ($artifact in $artifacts) {
        $name = $artifact.Name
        $allowedFiles[$name] = $true
        $allowedFiles["$name.spdx.json"] = $true
        $allowedFiles["$name.provenance.json"] = $true
        if (Test-Path -LiteralPath "$($artifact.FullName).sha256" -PathType Leaf) {
            $allowedFiles["$name.sha256"] = $true
        }
        $signatureMode = 'unsigned'
        if ($name -match '-signed\.') {
            $signatureMode = 'signed'
        }
        $architecture = 'x64'
        if ($name -match 'windows-arm64') {
            $architecture = 'arm64'
        }

        if ($artifact.Extension -eq '.zip') {
            $componentSet = 'desktop'
            if ($name -match 'headless') {
                $componentSet = 'headless'
            }
            $releaseStatus = 'non-release'
            if ($name -match 'portable-release') {
                $releaseStatus = 'release'
            }
            Test-ZipPackage `
                -PackagePath $artifact.FullName `
                -InspectionRoot (Join-Path $inspection $artifact.BaseName) `
                -Architecture $architecture `
                -ComponentSet $componentSet `
                -ReleaseStatus $releaseStatus
        } elseif ($artifact.Extension -eq '.msix') {
            $releaseStatus = 'release-candidate'
            if ($name -match 'unsigned-non-release') {
                $releaseStatus = 'non-release'
            }
            Test-MsixPackage `
                -PackagePath $artifact.FullName `
                -MakeAppxPath $makeAppx `
                -InspectionRoot (Join-Path $inspection $artifact.BaseName) `
                -Version $version.Msix `
                -Architecture $architecture `
                -ExpectedPublisher $Publisher `
                -SignatureMode $signatureMode `
                -ReleaseStatus $releaseStatus
        } elseif ($artifact.Extension -eq '.msixbundle') {
            $bundleProfile = Get-MsixBundleValidationProfile $name
            Test-MsixBundle `
                -PackagePath $artifact.FullName `
                -MakeAppxPath $makeAppx `
                -InspectionRoot (Join-Path $inspection $artifact.BaseName) `
                -Version $version.Msix `
                -ExpectedPublisher $Publisher `
                -SignatureMode $bundleProfile.SignatureMode `
                -InnerSignatureMode $bundleProfile.InnerSignatureMode `
                -InnerReleaseStatus $bundleProfile.InnerReleaseStatus
        } else {
            $releaseStatus = 'release-candidate'
            if ($name -match 'unsigned-non-release') {
                $releaseStatus = 'non-release'
            }
            Test-MsiPackage `
                -PackagePath $artifact.FullName `
                -InspectionRoot (Join-Path $inspection $artifact.BaseName) `
                -Architecture $architecture `
                -SignatureMode $signatureMode `
                -ReleaseStatus $releaseStatus
        }
        Test-ArtifactSupplyChain $artifact.FullName
    }
    if (Test-Path -LiteralPath (Join-Path $root 'artifacts.json') -PathType Leaf) {
        $allowedFiles['artifacts.json'] = $true
    }
    foreach ($file in Get-ChildItem -LiteralPath $root -File) {
        if (-not $allowedFiles.ContainsKey($file.Name)) {
            throw "Unexpected published Windows file: $($file.Name)"
        }
    }
    Test-ArtifactSetChecksums -Directory $root -ManifestName $ChecksumName
} finally {
    if (Test-Path -LiteralPath $inspection) {
        Remove-OwnedDirectory -OwnedRoot $root -Path $inspection
    }
}

Write-Host "Validated $($artifacts.Count) published Windows artifact(s) from '$root'."
