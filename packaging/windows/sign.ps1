[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackagePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f ]{40,59}$')]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory)]
    [ValidatePattern('^https://')]
    [string]$TimestampUrl,

    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$CertificateStore = 'CurrentUser',

    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
Import-Module (Join-Path $scriptRoot 'WindowsPackaging.psm1') -Force

$source = Assert-PlainFile $PackagePath
$sourceDirectory = Split-Path -Parent $source
Assert-NoReparsePathComponents -Root $sourceDirectory -Path $source
$extension = [System.IO.Path]::GetExtension($source).ToLowerInvariant()
if ($extension -notin @('.zip', '.msix', '.msixbundle', '.msi')) {
    throw 'The signing gate accepts only validated portable ZIP, MSIX, MSIXBundle, and MSI release candidates.'
}
if ([System.IO.Path]::GetFileName($source) -notmatch '-release-candidate-unsigned\.') {
    throw 'Input package must be explicitly labeled release-candidate-unsigned.'
}

$thumbprint = $CertificateThumbprint.Replace(' ', '').ToUpperInvariant()
if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
    throw 'Certificate thumbprint must contain exactly 40 hexadecimal characters.'
}
$certificatePath = "Cert:\$CertificateStore\My\$thumbprint"
if (-not (Test-Path -LiteralPath $certificatePath -PathType Leaf)) {
    throw "Signing certificate was not found in $CertificateStore\My."
}
$certificate = Get-Item -LiteralPath $certificatePath
if (-not $certificate.HasPrivateKey) {
    throw 'Signing certificate has no accessible private key or hardware-backed provider.'
}
if ($certificate.NotAfter -le [DateTime]::UtcNow) {
    throw 'Signing certificate is expired.'
}
$codeSigningEku = @($certificate.EnhancedKeyUsageList |
    Where-Object { $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3' })
if ($codeSigningEku.Count -ne 1) {
    throw 'Signing certificate does not assert the code-signing enhanced key usage.'
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $signedName = [System.IO.Path]::GetFileName($source).
        Replace('-release-candidate-unsigned', '-signed')
    $OutputPath = Join-Path $sourceDirectory $signedName
} else {
    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    Assert-ChildPath -Parent $sourceDirectory -Child $OutputPath | Out-Null
}
if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to overwrite signed output '$OutputPath'."
}
$outputFiles = @(
    $OutputPath,
    "$OutputPath.sha256",
    "$OutputPath.spdx.json",
    "$OutputPath.provenance.json"
)
foreach ($path in $outputFiles) {
    if (Test-Path -LiteralPath $path) {
        throw "Refusing to overwrite signed output or companion '$path'."
    }
}
$checksumPath = Join-Path $sourceDirectory 'SHA256SUMS'
$originalChecksumBytes = $null
if (Test-Path -LiteralPath $checksumPath -PathType Leaf) {
    $originalChecksumBytes = [System.IO.File]::ReadAllBytes($checksumPath)
}

$version = Get-CanonicalVersion $repoRoot
$architecture = 'x64'
if ([System.IO.Path]::GetFileName($source) -match 'windows-arm64') {
    $architecture = 'arm64'
}
$publisher = $certificate.Subject
$inspectionRoot = Join-Path $sourceDirectory '.sign-inspection'
Initialize-MsvcEnvironment x64 | Out-Null
$signTool = Find-WindowsSdkTool 'signtool.exe'
$storeArguments = @('/sha1', $thumbprint, '/s', 'My')
if ($CertificateStore -eq 'LocalMachine') {
    $storeArguments += '/sm'
}

function Add-VerifiedSignature {
    param([Parameter(Mandatory)][string]$Path)
    Invoke-CheckedCommand -FilePath $signTool -Arguments (@(
        'sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $TimestampUrl
    ) + $storeArguments + @($Path))
    Invoke-CheckedCommand -FilePath $signTool -Arguments @('verify', '/pa', '/all', $Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Signature verification failed with status '$($signature.Status)': $Path"
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw "Release signature has no verified timestamp certificate: $Path"
    }
}

try {
    if ($extension -eq '.zip') {
        $componentSet = $(if ([System.IO.Path]::GetFileName($source) -match 'headless') {
            'headless'
        } else {
            'desktop'
        })
        $payloadRoot = Join-Path $inspectionRoot 'unsigned-zip'
        Test-ZipPackage `
            -PackagePath $source `
            -InspectionRoot $payloadRoot `
            -Architecture $architecture `
            -ComponentSet $componentSet `
            -ReleaseStatus release `
            -SignatureMode unsigned
        $expectedExecutables = @('gta-claw-desktop.exe')
        if ($componentSet -eq 'headless') {
            $expectedExecutables = @('gta-claw-cli.exe', 'gta-claw-daemon.exe')
        }
        foreach ($name in $expectedExecutables) {
            Add-VerifiedSignature (Join-Path $payloadRoot $name)
        }
        Remove-Item -LiteralPath (Join-Path $payloadRoot 'SHA256SUMS.txt') -Force
        New-HashManifest $payloadRoot | Out-Null
        Test-HashManifest $payloadRoot
        New-DeterministicZip -Root $payloadRoot -Destination $OutputPath | Out-Null
        Test-ZipPackage `
            -PackagePath $OutputPath `
            -InspectionRoot (Join-Path $inspectionRoot 'signed-zip') `
            -Architecture $architecture `
            -ComponentSet $componentSet `
            -ReleaseStatus release `
            -SignatureMode signed
    } else {
        $makeAppx = $null
        if ($extension -in @('.msix', '.msixbundle')) {
            $makeAppx = Find-WindowsSdkTool 'makeappx.exe'
        }
        if ($extension -eq '.msix') {
            Test-MsixPackage `
                -PackagePath $source `
                -MakeAppxPath $makeAppx `
                -InspectionRoot (Join-Path $inspectionRoot 'unsigned-msix') `
                -Version $version.Msix `
                -Architecture $architecture `
                -ExpectedPublisher $publisher `
                -SignatureMode unsigned `
                -ReleaseStatus release-candidate
        } elseif ($extension -eq '.msixbundle') {
            Test-MsixBundle `
                -PackagePath $source `
                -MakeAppxPath $makeAppx `
                -InspectionRoot (Join-Path $inspectionRoot 'unsigned-bundle') `
                -Version $version.Msix `
                -ExpectedPublisher $publisher `
                -SignatureMode unsigned `
                -InnerSignatureMode signed `
                -InnerReleaseStatus release-candidate
        } else {
            Test-MsiPackage `
                -PackagePath $source `
                -InspectionRoot (Join-Path $inspectionRoot 'unsigned-msi') `
                -Architecture $architecture `
                -SignatureMode unsigned `
                -ReleaseStatus release-candidate
        }
        Copy-Item -LiteralPath $source -Destination $OutputPath
        Add-VerifiedSignature $OutputPath
    }

    if ($extension -eq '.msix') {
        Test-MsixPackage `
            -PackagePath $OutputPath `
            -MakeAppxPath $makeAppx `
            -InspectionRoot (Join-Path $inspectionRoot 'signed-msix') `
            -Version $version.Msix `
            -Architecture $architecture `
            -ExpectedPublisher $publisher `
            -SignatureMode signed `
            -ReleaseStatus release-candidate
    } elseif ($extension -eq '.msixbundle') {
        Test-MsixBundle `
            -PackagePath $OutputPath `
            -MakeAppxPath $makeAppx `
            -InspectionRoot (Join-Path $inspectionRoot 'signed-bundle') `
            -Version $version.Msix `
            -ExpectedPublisher $publisher `
            -SignatureMode signed `
            -InnerSignatureMode signed `
            -InnerReleaseStatus release-candidate
    } elseif ($extension -eq '.msi') {
        Test-MsiPackage `
            -PackagePath $OutputPath `
            -InspectionRoot (Join-Path $inspectionRoot 'signed-msi') `
            -Architecture $architecture `
            -SignatureMode signed `
            -ReleaseStatus release-candidate
    }
    Write-ArtifactHash $OutputPath | Out-Null
    Test-ArtifactHash $OutputPath
} catch {
    foreach ($path in $outputFiles) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }
    if ($null -ne $originalChecksumBytes) {
        [System.IO.File]::WriteAllBytes($checksumPath, $originalChecksumBytes)
    } elseif (Test-Path -LiteralPath $checksumPath) {
        Remove-Item -LiteralPath $checksumPath -Force
    }
    throw
} finally {
    if (Test-Path -LiteralPath $inspectionRoot) {
        Remove-OwnedDirectory -OwnedRoot $sourceDirectory -Path $inspectionRoot
    }
}

Write-Host "Created signed, timestamped, and verified release candidate '$OutputPath'."
