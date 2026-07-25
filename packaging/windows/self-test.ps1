[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$scriptRoot = Split-Path -Parent $PSCommandPath
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..\..'))
Import-Module (Join-Path $scriptRoot 'WindowsPackaging.psm1') -Force
Import-Module (Join-Path $scriptRoot 'SupplyChain.psm1') -Force

$ownedRoot = Join-Path $scriptRoot '.work\self-tests'
[System.IO.Directory]::CreateDirectory($ownedRoot) | Out-Null
$testRoot = Join-Path $ownedRoot ("self-test-" + [Guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($testRoot) | Out-Null
$passed = 0

function Assert-Throws {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        & $Action
    } catch {
        $script:passed++
        return
    }
    throw "Expected failure was not raised: $Name"
}

try {
    Assert-Throws { Convert-WindowsVersion '1.2.3-beta.1' } 'invalid prerelease version'
    Assert-Throws { Convert-WindowsVersion '256.0.0' } 'MSI major overflow'
    Assert-Throws { Assert-RelativePackagePath '..\escape.exe' } 'path traversal'
    Assert-Throws { Assert-RelativePackagePath 'C:\escape.exe' } 'rooted package path'
    Assert-Throws { Assert-PlainFile (Join-Path $testRoot 'missing.exe') } 'missing required file'

    $missingSdk = Join-Path $testRoot 'empty-sdk'
    [System.IO.Directory]::CreateDirectory($missingSdk) | Out-Null
    Assert-Throws { Find-WindowsSdkTool -ToolName 'makeappx.exe' -SdkBinRoot $missingSdk } 'missing SDK tool'

    $hashRoot = Join-Path $testRoot 'hash'
    [System.IO.Directory]::CreateDirectory($hashRoot) | Out-Null
    Write-Utf8File -Path (Join-Path $hashRoot 'payload.txt') -Content 'before'
    New-HashManifest $hashRoot | Out-Null
    Write-Utf8File -Path (Join-Path $hashRoot 'payload.txt') -Content 'after'
    Assert-Throws { Test-HashManifest $hashRoot } 'hash mismatch'

    $artifactSet = Join-Path $testRoot 'artifact-set'
    [System.IO.Directory]::CreateDirectory($artifactSet) | Out-Null
    Write-Utf8File -Path (Join-Path $artifactSet 'artifact.bin') -Content 'published'
    Write-ArtifactSetChecksums $artifactSet | Out-Null
    Test-ArtifactSetChecksums $artifactSet
    $passed++
    Write-Utf8File -Path (Join-Path $artifactSet 'unexpected.bin') -Content 'not listed'
    Assert-Throws {
        Test-ArtifactSetChecksums $artifactSet
    } 'incomplete artifact checksum coverage'

    $junctionTarget = Join-Path $testRoot 'junction-target'
    $junctionRoot = Join-Path $testRoot 'junction-root'
    [System.IO.Directory]::CreateDirectory($junctionTarget) | Out-Null
    [System.IO.Directory]::CreateDirectory($junctionRoot) | Out-Null
    $junction = Join-Path $junctionRoot 'linked'
    New-Item -ItemType Junction -Path $junction -Target $junctionTarget | Out-Null
    Assert-Throws { Assert-NoReparsePoints $junctionRoot } 'reparse point'
    $outsideVictim = Join-Path $junctionTarget 'victim'
    [System.IO.Directory]::CreateDirectory($outsideVictim) | Out-Null
    Assert-Throws {
        Remove-OwnedDirectory -OwnedRoot $junctionRoot -Path (Join-Path $junction 'victim')
    } 'ancestor junction deletion escape'
    if (-not (Test-Path -LiteralPath $outsideVictim -PathType Container)) {
        throw 'Ancestor junction test deleted content outside the owned root.'
    }

    foreach ($architecture in @('x64', 'arm64')) {
        $version = Convert-WindowsVersion '1.2.3'
        $manifestPath = Join-Path $testRoot "AppxManifest-$architecture.xml"
        New-AppxManifest `
            -TemplatePath (Join-Path $scriptRoot 'AppxManifest.template.xml') `
            -OutputPath $manifestPath `
            -MsixVersion $version.Msix `
            -Architecture $architecture `
            -Publisher 'CN=GTAStudio Windows Signing Placeholder'
        Test-AppxManifest -Path $manifestPath -Version $version.Msix -Architecture $architecture
        $passed++
    }

    $aliasedManifest = Join-Path $testRoot 'AppxManifest-aliased-extension.xml'
    $aliasedContent = [System.IO.File]::ReadAllText((Join-Path $testRoot 'AppxManifest-x64.xml')).
        Replace('IgnorableNamespaces="uap uap10 rescap"', 'xmlns:x="http://schemas.microsoft.com/appx/manifest/uap/windows10" IgnorableNamespaces="uap uap10 rescap x"').
        Replace('</Application>', '<x:Extension Category="windows.fake" /></Application>')
    Write-Utf8File -Path $aliasedManifest -Content $aliasedContent
    Assert-Throws {
        Test-AppxManifest -Path $aliasedManifest -Version '1.2.3.0' -Architecture x64
    } 'namespace-aliased manifest extension'

    $zipRoot = Join-Path $testRoot 'zip'
    [System.IO.Directory]::CreateDirectory((Join-Path $zipRoot 'nested')) | Out-Null
    Write-Utf8File -Path (Join-Path $zipRoot 'a.txt') -Content "alpha`n"
    Write-Utf8File -Path (Join-Path $zipRoot 'nested\b.txt') -Content "beta`n"
    $zipOne = Join-Path $testRoot 'one.zip'
    $zipTwo = Join-Path $testRoot 'two.zip'
    New-DeterministicZip -Root $zipRoot -Destination $zipOne | Out-Null
    New-DeterministicZip -Root $zipRoot -Destination $zipTwo | Out-Null
    if ((Get-FileHash $zipOne -Algorithm SHA256).Hash -ne (Get-FileHash $zipTwo -Algorithm SHA256).Hash) {
        throw 'Deterministic ZIP rerun produced different bytes.'
    }
    $passed++

    $assetOne = Join-Path $testRoot 'assets-one'
    $assetTwo = Join-Path $testRoot 'assets-two'
    New-VisualAssets -SpecPath (Join-Path $scriptRoot 'assets\logo-spec.json') -OutputDirectory $assetOne
    New-VisualAssets -SpecPath (Join-Path $scriptRoot 'assets\logo-spec.json') -OutputDirectory $assetTwo
    foreach ($name in @('Square44x44Logo.png', 'StoreLogo.png', 'Square150x150Logo.png')) {
        if ((Get-FileHash (Join-Path $assetOne $name) -Algorithm SHA256).Hash -ne
            (Get-FileHash (Join-Path $assetTwo $name) -Algorithm SHA256).Hash) {
            throw "Visual asset '$name' is not deterministic."
        }
    }
    $passed++

    Test-WixSource (Join-Path $scriptRoot 'wix\GtaClaw.wxs')
    $passed++

    $fakeCargoRoot = Join-Path $testRoot 'fake-cargo'
    [System.IO.Directory]::CreateDirectory($fakeCargoRoot) | Out-Null
    $fakeCargo = Join-Path $fakeCargoRoot 'cargo.cmd'
    $cargoArguments = Join-Path $fakeCargoRoot 'arguments.txt'
    Write-Utf8File -Path $fakeCargo -Content @"
@echo off
echo %* > "%GTA_CLAW_TEST_CARGO_ARGUMENTS%"
echo gta-claw-cli v0.1.0
"@
    $priorPath = $env:PATH
    $priorCargoArguments = $env:GTA_CLAW_TEST_CARGO_ARGUMENTS
    try {
        $env:PATH = "$fakeCargoRoot;$priorPath"
        $env:GTA_CLAW_TEST_CARGO_ARGUMENTS = $cargoArguments
        $target = 'x86_64-pc-windows-msvc'
        Assert-HeadlessGraph -RepoRoot $repoRoot -TargetTriple $target
        $arguments = [System.IO.File]::ReadAllText($cargoArguments)
        if ($arguments -notmatch "(^|\s)--target\s+$([regex]::Escape($target))(\s|$)") {
            throw "Headless Cargo graph proof omitted target '$target': $arguments"
        }
        $passed++
    } finally {
        $env:PATH = $priorPath
        $env:GTA_CLAW_TEST_CARGO_ARGUMENTS = $priorCargoArguments
    }

    Assert-Throws {
        & (Join-Path $scriptRoot 'package.ps1') -Architecture x64 -ReleaseMode
    } 'release without signing'

    $fakeMsi = Join-Path $testRoot 'fake-release-candidate-unsigned.msi'
    Write-Utf8File -Path $fakeMsi -Content 'not an installer'
    Assert-Throws {
        & (Join-Path $scriptRoot 'sign.ps1') `
            -PackagePath $fakeMsi `
            -CertificateThumbprint ('0' * 40) `
            -TimestampUrl 'https://timestamp.invalid'
    } 'MSI signing without a provisioned certificate'

    & (Join-Path $scriptRoot 'validate-release-surfaces.ps1')
    $passed++

    if ($passed -ne 21) {
        throw "Expected 21 self-tests, completed $passed."
    }
    Write-Host "Windows packaging self-tests passed: $passed."
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
