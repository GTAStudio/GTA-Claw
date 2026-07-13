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
if ($extension -ne '.msix') {
    throw 'This gate signs only attested MSIX outputs; MSI signing is deferred until MSI database validation exists.'
}
if ([System.IO.Path]::GetFileName($source) -notmatch 'unsigned|non-release') {
    throw 'Input package must be explicitly labeled unsigned or non-release.'
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

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $signedName = [System.IO.Path]::GetFileName($source).
        Replace('-unsigned', '-signed').
        Replace('-non-release', '-signed')
    $OutputPath = Join-Path $sourceDirectory $signedName
} else {
    $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    Assert-ChildPath -Parent $sourceDirectory -Child $OutputPath | Out-Null
}
if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to overwrite signed output '$OutputPath'."
}

$msixVersion = $null
$msixArchitecture = $null
$publisher = $null
$makeAppx = Find-WindowsSdkTool 'makeappx.exe'
$inspectionRoot = Join-Path $sourceDirectory '.sign-inspection-unsigned'
Remove-OwnedDirectory -OwnedRoot $sourceDirectory -Path $inspectionRoot
[System.IO.Directory]::CreateDirectory($inspectionRoot) | Out-Null
try {
    Invoke-CheckedCommand -FilePath $makeAppx -Arguments @(
        'unpack', '/p', $source, '/d', $inspectionRoot, '/o'
    )
    [xml]$manifest = Get-Content -LiteralPath (Join-Path $inspectionRoot 'AppxManifest.xml') -Raw
    $publisher = [string]$manifest.Package.Identity.Publisher
    $msixVersion = [string]$manifest.Package.Identity.Version
    $msixArchitecture = [string]$manifest.Package.Identity.ProcessorArchitecture
    if ($publisher -ne $certificate.Subject) {
        throw "MSIX publisher does not match the selected certificate subject."
    }
} finally {
    if (Test-Path -LiteralPath $inspectionRoot) {
        Remove-OwnedDirectory -OwnedRoot $sourceDirectory -Path $inspectionRoot
    }
}

Copy-Item -LiteralPath $source -Destination $OutputPath
$signTool = Find-WindowsSdkTool 'signtool.exe'
$storeArguments = @('/sha1', $thumbprint, '/s', 'My')
if ($CertificateStore -eq 'LocalMachine') {
    $storeArguments += '/sm'
}
try {
    Invoke-CheckedCommand -FilePath $signTool -Arguments (@(
        'sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $TimestampUrl
    ) + $storeArguments + @($OutputPath))
    Invoke-CheckedCommand -FilePath $signTool -Arguments @('verify', '/pa', '/all', $OutputPath)
    $signature = Get-AuthenticodeSignature -LiteralPath $OutputPath
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Signature verification failed with status '$($signature.Status)'."
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw 'Release signature has no verified timestamp certificate.'
    }
    $signedInspection = Join-Path $sourceDirectory '.sign-inspection-signed'
    [System.IO.Directory]::CreateDirectory($signedInspection) | Out-Null
    try {
        Test-MsixPackage `
            -PackagePath $OutputPath `
            -MakeAppxPath $makeAppx `
            -InspectionRoot $signedInspection `
            -Version $msixVersion `
            -Architecture $msixArchitecture `
            -ExpectedPublisher $publisher
    } finally {
        if (Test-Path -LiteralPath $signedInspection) {
            Remove-OwnedDirectory -OwnedRoot $sourceDirectory -Path $signedInspection
        }
    }
    Write-ArtifactHash $OutputPath | Out-Null
} catch {
    if (Test-Path -LiteralPath $OutputPath) {
        Remove-Item -LiteralPath $OutputPath -Force
    }
    throw
}

Write-Host "Created signed, timestamped, and verified release candidate '$OutputPath'."
