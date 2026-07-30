[CmdletBinding()]
param([switch]$PortableOnly)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$isWindowsHost = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT

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
    Assert-RustToolchain $repoRoot
    $passed++
    $wrongRustRoot = Join-Path $testRoot 'wrong-rust'
    [System.IO.Directory]::CreateDirectory($wrongRustRoot) | Out-Null
    Write-Utf8File -Path (Join-Path $wrongRustRoot 'rust-toolchain.toml') -Content @"
[toolchain]
channel = "1.96.0"
"@
    Assert-Throws { Get-PinnedRustVersion $wrongRustRoot } 'wrong repository Rust pin'
    $fakeRustc = Join-Path $testRoot 'rustc.ps1'
    $fakeCargo = Join-Path $testRoot 'cargo.ps1'
    Write-Utf8File -Path $fakeRustc -Content "'rustc 1.96.0 (fixture)'`n"
    Write-Utf8File -Path $fakeCargo -Content "'cargo 1.97.1 (fixture)'`n"
    Assert-Throws {
        Assert-RustToolchain `
            -RepoRoot $repoRoot `
            -RustcPath $fakeRustc `
            -CargoPath $fakeCargo
    } 'active Rust compiler version mismatch'

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
    Write-ArtifactHash (Join-Path $artifactSet 'artifact.bin') | Out-Null
    Test-ArtifactHash (Join-Path $artifactSet 'artifact.bin')
    $passed++
    Write-Utf8File -Path (Join-Path $artifactSet 'artifact.bin.sha256') -Content (
        ('0' * 64) + "  artifact.bin`n"
    )
    Assert-Throws {
        Test-ArtifactHash (Join-Path $artifactSet 'artifact.bin')
    } 'per-artifact published-byte hash mismatch'
    Write-ArtifactHash (Join-Path $artifactSet 'artifact.bin') | Out-Null
    $missingHashArtifact = Join-Path $artifactSet 'missing-hash.bin'
    Write-Utf8File -Path $missingHashArtifact -Content 'published without companion'
    Assert-Throws {
        Test-ArtifactHash $missingHashArtifact
    } 'missing per-artifact SHA-256 companion'
    Remove-Item -LiteralPath $missingHashArtifact -Force
    Write-ArtifactSetChecksums $artifactSet | Out-Null
    Test-ArtifactSetChecksums $artifactSet
    if ((Get-Content (Join-Path $artifactSet 'SHA256SUMS') -Raw) -notmatch
        '(?m)^[0-9a-f]{64}  artifact\.bin\.sha256$') {
        throw 'Artifact-set checksum manifest omits the per-artifact .sha256 companion.'
    }
    $passed++
    Write-Utf8File -Path (Join-Path $artifactSet 'unexpected.bin') -Content 'not listed'
    Assert-Throws {
        Test-ArtifactSetChecksums $artifactSet
    } 'incomplete artifact checksum coverage'

    $supplyArtifact = Join-Path $testRoot 'supply.bin'
    Write-Utf8File -Path $supplyArtifact -Content 'attested bytes'
    $supplyHash = (Get-FileHash $supplyArtifact -Algorithm SHA256).Hash.ToLowerInvariant()
    $supplySha1 = (Get-FileHash $supplyArtifact -Algorithm SHA1).Hash.ToLowerInvariant()
    $supplyName = [System.IO.Path]::GetFileName($supplyArtifact)
    $sbom = [ordered]@{
        spdxVersion = 'SPDX-2.3'
        documentDescribes = @('SPDXRef-Artifact')
        packages = @([ordered]@{ name = 'fixture' })
        files = @([ordered]@{
            fileName = "./$supplyName"
            SPDXID = 'SPDXRef-Artifact'
            checksums = @(
                [ordered]@{ algorithm = 'SHA1'; checksumValue = $supplySha1 },
                [ordered]@{ algorithm = 'SHA256'; checksumValue = $supplyHash }
            )
        })
    }
    $provenance = [ordered]@{
        _type = 'https://in-toto.io/Statement/v1'
        predicateType = 'https://slsa.dev/provenance/v1'
        subject = @([ordered]@{
            name = $supplyName
            digest = [ordered]@{ sha256 = $supplyHash }
        })
    }
    Write-Utf8File -Path "$supplyArtifact.spdx.json" -Content (($sbom | ConvertTo-Json -Depth 8) + "`n")
    Write-Utf8File -Path "$supplyArtifact.provenance.json" -Content (($provenance | ConvertTo-Json -Depth 8) + "`n")
    Test-ArtifactSupplyChain $supplyArtifact
    if (@($sbom.files[0].checksums | Where-Object algorithm -eq 'SHA1').Count -ne 1 -or
        @($sbom.files[0].checksums | Where-Object algorithm -eq 'SHA256').Count -ne 1) {
        throw 'SPDX file checksums must contain exactly SHA1 and SHA256.'
    }
    $passed++
    $sbom.files[0].checksums[0].checksumValue = '0' * 40
    Write-Utf8File -Path "$supplyArtifact.spdx.json" -Content (($sbom | ConvertTo-Json -Depth 8) + "`n")
    Assert-Throws {
        Test-ArtifactSupplyChain $supplyArtifact
    } 'SBOM checksum algorithm substitution'

    $transactionRoot = Join-Path $testRoot 'transactions'
    $transactionDestination = Join-Path $transactionRoot 'published'
    [System.IO.Directory]::CreateDirectory($transactionDestination) | Out-Null
    Write-Utf8File -Path (Join-Path $transactionDestination 'old.txt') -Content 'old'
    $transaction = Start-OwnedDirectoryTransaction `
        -OwnedRoot $transactionRoot `
        -Destination $transactionDestination
    Write-Utf8File -Path (Join-Path $transaction.WorkPath 'new.txt') -Content 'new'
    Undo-OwnedDirectoryTransaction $transaction
    if (-not (Test-Path -LiteralPath (Join-Path $transactionDestination 'old.txt') -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $transactionDestination 'new.txt'))) {
        throw 'Packaging transaction rollback did not preserve the prior output.'
    }
    $passed++
    $transaction = Start-OwnedDirectoryTransaction `
        -OwnedRoot $transactionRoot `
        -Destination $transactionDestination
    Write-Utf8File -Path (Join-Path $transaction.WorkPath 'new.txt') -Content 'new'
    $cleanupWarnings = @(Complete-OwnedDirectoryTransaction `
        -Transaction $transaction `
        -BackupCleanupAction { throw 'simulated backup cleanup failure' } 3>&1)
    if (-not (Test-Path -LiteralPath (Join-Path $transactionDestination 'new.txt') -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $transactionDestination 'old.txt')) -or
        -not (Test-Path -LiteralPath $transaction.BackupPath -PathType Container) -or
        $cleanupWarnings.Count -ne 1) {
        throw 'Packaging transaction did not remain committed after backup cleanup failed.'
    }
    $recoveryTransaction = Start-OwnedDirectoryTransaction `
        -OwnedRoot $transactionRoot `
        -Destination $transactionDestination
    Undo-OwnedDirectoryTransaction $recoveryTransaction
    if (Test-Path -LiteralPath $transaction.BackupPath) {
        throw 'The next packaging transaction did not clean the stale post-commit backup.'
    }
    $passed++

    $pairRoot = Join-Path $testRoot 'artifact-pair'
    [System.IO.Directory]::CreateDirectory($pairRoot) | Out-Null
    $publishedMsi = Join-Path $pairRoot 'package.msi'
    Write-Utf8File -Path $publishedMsi -Content 'old msi'
    Write-ArtifactHash $publishedMsi | Out-Null
    $stagedMsi = Join-Path $pairRoot '.package.packaging-new.msi'
    $stagedMsiHash = "$stagedMsi.sha256"
    Write-Utf8File -Path $stagedMsi -Content 'new msi'
    Write-ArtifactHash `
        -Path $stagedMsi `
        -HashPath $stagedMsiHash `
        -ArtifactName 'package.msi' | Out-Null
    Assert-Throws {
        Publish-OwnedArtifactPair `
            -OwnedRoot $pairRoot `
            -StagedArtifact $stagedMsi `
            -StagedHash $stagedMsiHash `
            -DestinationArtifact $publishedMsi `
            -HashPublishAction { throw 'simulated checksum publication failure' }
    } 'MSI checksum publication failure rollback'
    if ([System.IO.File]::ReadAllText($publishedMsi) -ne 'old msi') {
        throw 'MSI pair rollback did not restore the previous installer bytes.'
    }
    Test-ArtifactHash $publishedMsi
    foreach ($path in @(
        "$publishedMsi.packaging-previous",
        "$publishedMsi.sha256.packaging-previous",
        $stagedMsi,
        $stagedMsiHash
    )) {
        if (Test-Path -LiteralPath $path) {
            throw "MSI pair rollback left transaction material behind: $path"
        }
    }
    $firstPublicationPhases = @(
        'prepared',
        'artifact-publish-renamed',
        'artifact-published',
        'hash-publish-renamed',
        'hash-published',
        'committed',
        'artifact-backup-removed',
        'hash-backup-removed'
    )
    $replacementPhases = @(
        'prepared',
        'artifact-backup-renamed',
        'artifact-backed-up',
        'hash-backup-renamed',
        'hash-backed-up',
        'artifact-publish-renamed',
        'artifact-published',
        'hash-publish-renamed',
        'hash-published',
        'committed',
        'artifact-backup-deleted',
        'artifact-backup-removed',
        'hash-backup-deleted',
        'hash-backup-removed'
    )
    foreach ($profile in @(
        [pscustomobject]@{ Name = 'first'; HasPrior = $false; Phases = $firstPublicationPhases },
        [pscustomobject]@{ Name = 'replacement'; HasPrior = $true; Phases = $replacementPhases }
    )) {
        foreach ($phase in $profile.Phases) {
            $phaseRoot = Join-Path $testRoot "pair-$($profile.Name)-$phase"
            [System.IO.Directory]::CreateDirectory($phaseRoot) | Out-Null
            $phaseArtifact = Join-Path $phaseRoot 'package.msi'
            if ($profile.HasPrior) {
                Write-Utf8File -Path $phaseArtifact -Content 'known-good old msi'
                Write-ArtifactHash $phaseArtifact | Out-Null
            }
            $phaseStaged = Join-Path $phaseRoot '.package.packaging-new.msi'
            $phaseStagedHash = "$phaseStaged.sha256"
            Write-Utf8File -Path $phaseStaged -Content 'validated new msi'
            Write-ArtifactHash `
                -Path $phaseStaged `
                -HashPath $phaseStagedHash `
                -ArtifactName 'package.msi' | Out-Null
            Publish-OwnedArtifactPair `
                -OwnedRoot $phaseRoot `
                -StagedArtifact $phaseStaged `
                -StagedHash $phaseStagedHash `
                -DestinationArtifact $phaseArtifact `
                -StopAfterPhase $phase
            Repair-OwnedArtifactPairTransaction `
                -OwnedRoot $phaseRoot `
                -DestinationArtifact $phaseArtifact

            $newPairCommitted = $phase -in @(
                'hash-publish-renamed',
                'hash-published',
                'committed',
                'artifact-backup-deleted',
                'artifact-backup-removed',
                'hash-backup-deleted',
                'hash-backup-removed'
            )
            if ($profile.HasPrior -and $phase -notin @(
                'committed',
                'artifact-backup-deleted',
                'artifact-backup-removed',
                'hash-backup-deleted',
                'hash-backup-removed'
            )) {
                $newPairCommitted = $false
            }
            if ($newPairCommitted) {
                Test-ArtifactHash $phaseArtifact
                if ([System.IO.File]::ReadAllText($phaseArtifact) -ne 'validated new msi') {
                    throw "Crash recovery at '$($profile.Name)/$phase' did not retain the committed new pair."
                }
            } elseif ($profile.HasPrior) {
                Test-ArtifactHash $phaseArtifact
                if ([System.IO.File]::ReadAllText($phaseArtifact) -ne 'known-good old msi') {
                    throw "Crash recovery at '$($profile.Name)/$phase' did not restore the prior pair."
                }
            } elseif ((Test-Path -LiteralPath $phaseArtifact) -or
                (Test-Path -LiteralPath "$phaseArtifact.sha256")) {
                throw "Crash recovery at '$($profile.Name)/$phase' retained an incomplete first publication."
            }
            foreach ($debris in @(
                "$phaseArtifact.packaging-previous",
                "$phaseArtifact.sha256.packaging-previous",
                "$phaseArtifact.packaging-transaction.json",
                $phaseStaged,
                $phaseStagedHash
            )) {
                if (Test-Path -LiteralPath $debris) {
                    throw "Crash recovery at '$($profile.Name)/$phase' left debris '$debris'."
                }
            }
            $passed++
        }
    }

    foreach ($cleanupOperation in @(
        'remove-artifact-backup',
        'write-artifact-backup-removed-phase',
        'remove-hash-backup',
        'write-hash-backup-removed-phase',
        'remove-phase-journal',
        'remove-staged-artifact',
        'remove-staged-hash'
    )) {
        $cleanupRoot = Join-Path $testRoot "pair-cleanup-$cleanupOperation"
        [System.IO.Directory]::CreateDirectory($cleanupRoot) | Out-Null
        $cleanupArtifact = Join-Path $cleanupRoot 'package.msi'
        Write-Utf8File -Path $cleanupArtifact -Content 'known-good old msi'
        Write-ArtifactHash $cleanupArtifact | Out-Null
        $cleanupStaged = Join-Path $cleanupRoot '.package.packaging-new.msi'
        $cleanupStagedHash = "$cleanupStaged.sha256"
        Write-Utf8File -Path $cleanupStaged -Content 'committed new msi'
        Write-ArtifactHash `
            -Path $cleanupStaged `
            -HashPath $cleanupStagedHash `
            -ArtifactName 'package.msi' | Out-Null

        $cleanupWarnings = @(Publish-OwnedArtifactPair `
            -OwnedRoot $cleanupRoot `
            -StagedArtifact $cleanupStaged `
            -StagedHash $cleanupStagedHash `
            -DestinationArtifact $cleanupArtifact `
            -PostCommitCleanupAction {
                param($operation)
                if ($operation -eq $cleanupOperation) {
                    if ($operation -eq 'remove-staged-artifact') {
                        Write-Utf8File -Path $cleanupStaged -Content 'simulated staged artifact debris'
                    }
                    if ($operation -eq 'remove-staged-hash') {
                        Write-Utf8File -Path $cleanupStagedHash -Content 'simulated staged hash debris'
                    }
                    throw "simulated $operation failure"
                }
            } 3>&1)
        Test-ArtifactHash $cleanupArtifact
        if ([System.IO.File]::ReadAllText($cleanupArtifact) -ne 'committed new msi' -or
            $cleanupWarnings.Count -ne 1) {
            throw "Post-commit '$cleanupOperation' failure changed successful publication semantics."
        }

        Repair-OwnedArtifactPairTransaction `
            -OwnedRoot $cleanupRoot `
            -DestinationArtifact $cleanupArtifact
        Test-ArtifactHash $cleanupArtifact
        if ([System.IO.File]::ReadAllText($cleanupArtifact) -ne 'committed new msi') {
            throw "Next-run repair after '$cleanupOperation' did not retain the committed pair."
        }
        foreach ($debris in @(
            "$cleanupArtifact.packaging-previous",
            "$cleanupArtifact.sha256.packaging-previous",
            "$cleanupArtifact.packaging-transaction.json",
            $cleanupStaged,
            $cleanupStagedHash
        )) {
            if (Test-Path -LiteralPath $debris) {
                throw "Next-run repair after '$cleanupOperation' left debris '$debris'."
            }
        }
        $passed++
    }

    if ($PortableOnly -or -not $isWindowsHost) {
        if ($passed -ne 49) {
            throw "Expected 49 portable self-tests, completed $passed."
        }
        if ($PortableOnly) {
            Write-Host "Portable Windows packaging self-tests passed: $passed."
        } else {
            Write-Host "Portable Windows packaging self-tests passed: $passed (Windows-native tests skipped on non-Windows host)."
        }
        return
    }

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

    $unsignedBundleProfile = Get-MsixBundleValidationProfile `
        'gta-claw-desktop-1.2.3-windows-x64_arm64-unsigned-non-release.msixbundle'
    $signedBundleProfile = Get-MsixBundleValidationProfile `
        'gta-claw-desktop-1.2.3-windows-x64_arm64-signed.msixbundle'
    if ($unsignedBundleProfile.SignatureMode -ne 'unsigned' -or
        $unsignedBundleProfile.InnerSignatureMode -ne 'unsigned' -or
        $unsignedBundleProfile.InnerReleaseStatus -ne 'non-release' -or
        $signedBundleProfile.SignatureMode -ne 'signed' -or
        $signedBundleProfile.InnerSignatureMode -ne 'signed' -or
        $signedBundleProfile.InnerReleaseStatus -ne 'release-candidate') {
        throw 'MSIXBundle publication status classification is invalid.'
    }
    $passed++
    Assert-Throws {
        Get-MsixBundleValidationProfile `
            'gta-claw-desktop-1.2.3-windows-x64_arm64-release-candidate-unsigned.msixbundle'
    } 'unpublished MSIXBundle status'

    $workflow = [System.IO.File]::ReadAllText(
        (Join-Path $repoRoot '.github\workflows\windows-packaging.yml')
    )
    foreach ($fetch in @(
        'cargo fetch --manifest-path Cargo.toml --locked',
        'cargo fetch --manifest-path desktop\Cargo.toml --locked'
    )) {
        $matches = [regex]::Matches(
            $workflow,
            "(?m)^\s*$([regex]::Escape($fetch))\s*$"
        )
        if ($matches.Count -ne 3) {
            throw "Expected complete locked dependency acquisition in package, bundle, and release jobs: $fetch"
        }
    }
    $passed++

    $buildIndex = $workflow.IndexOf('name: Build and freeze reviewed production-identity candidates offline')
    $packageImportIndex = $workflow.IndexOf('name: Import protected package signing identity')
    $packageRemoveIndex = $workflow.IndexOf('name: Remove package signing identity before bundle assembly')
    $bundleIndex = $workflow.IndexOf('name: Assemble signed-inner bundle without signing identity')
    $bundleImportIndex = $workflow.IndexOf('name: Import protected bundle signing identity')
    $bundleRemoveIndex = $workflow.IndexOf('name: Remove bundle signing identity before supply-chain assembly')
    $assemblyIndex = $workflow.IndexOf('name: Assemble and validate exact release publication bytes')
    $uploadIndex = $workflow.IndexOf('name: Upload signed Windows release')
    $finalCleanupIndex = $workflow.IndexOf('name: Always remove signing identity')
    $finalizeIndex = $workflow.IndexOf('finalize-release:')
    if ($buildIndex -lt 0 -or
        -not ($buildIndex -lt $packageImportIndex -and
              $packageImportIndex -lt $packageRemoveIndex -and
              $packageRemoveIndex -lt $bundleIndex -and
              $bundleIndex -lt $bundleImportIndex -and
              $bundleImportIndex -lt $bundleRemoveIndex -and
              $bundleRemoveIndex -lt $assemblyIndex -and
              $assemblyIndex -lt $uploadIndex -and
              $uploadIndex -lt $finalCleanupIndex -and
              $finalCleanupIndex -lt $finalizeIndex)) {
        throw 'Protected Windows build/sign/bundle/supply-chain phase order is unsafe.'
    }
    $packageCertificateWindow = $workflow.Substring(
        $packageImportIndex,
        $packageRemoveIndex - $packageImportIndex
    )
    $bundleCertificateWindow = $workflow.Substring(
        $bundleImportIndex,
        $bundleRemoveIndex - $bundleImportIndex
    )
    $packageCleanupWindow = $workflow.Substring(
        $packageRemoveIndex,
        $bundleIndex - $packageRemoveIndex
    )
    $bundleCleanupWindow = $workflow.Substring(
        $bundleRemoveIndex,
        $assemblyIndex - $bundleRemoveIndex
    )
    $finalCleanupWindow = $workflow.Substring(
        $finalCleanupIndex,
        $finalizeIndex - $finalCleanupIndex
    )
    foreach ($window in @($packageCertificateWindow, $bundleCertificateWindow)) {
        if ($window -match '(?im)^\s*(cargo|rustc)\b' -or
            $window -match 'package\.ps1' -or
            $window -match 'bundle\.ps1' -or
            $window -match 'New-ArtifactSupplyChain') {
            throw 'Certificate-active Windows phase executes build or supply-chain code.'
        }
    }
        $cleanupContracts = @(
            @{
                Name = 'package import failure'
                Text = $packageCertificateWindow
                Deletes = 1
                Verifications = 2
            },
            @{
                Name = 'package normal cleanup'
                Text = $packageCleanupWindow
                Deletes = 1
                Verifications = 2
            },
            @{
                Name = 'bundle import failure'
                Text = $bundleCertificateWindow
                Deletes = 1
                Verifications = 2
            },
            @{
                Name = 'bundle normal cleanup'
                Text = $bundleCleanupWindow
                Deletes = 1
                Verifications = 2
            },
            @{
                Name = 'final cleanup'
                Text = $finalCleanupWindow
                Deletes = 1
                Verifications = 2
            }
        )
        foreach ($contract in $cleanupContracts) {
            $deleteCount = [regex]::Matches($contract.Text, '-DeleteKey').Count
            $verificationCount = [regex]::Matches(
                $contract.Text,
                'Test-Path -LiteralPath \$certificatePath'
            ).Count
            if ($deleteCount -ne $contract.Deletes -or
                $verificationCount -ne $contract.Verifications -or
                $contract.Text -notmatch '\$cleanupFailures' -or
                $contract.Text -match 'Cert:.*SilentlyContinue') {
                throw "Windows $($contract.Name) does not delete and verify every private key."
            }
        }
        foreach ($cleanupWindow in @($packageCleanupWindow, $bundleCleanupWindow, $finalCleanupWindow)) {
            if ($cleanupWindow -notmatch 'if: always\(\)') {
                throw 'Windows normal/final signing cleanup is not unconditional.'
            }
        }
        if ([regex]::Matches($workflow, '-DeleteKey').Count -ne 5 -or
            [regex]::Matches($workflow, 'cleanup-thumbprints=').Count -ne 2 -or
            [regex]::Matches($workflow, 'Get-PfxData -FilePath \$pfx -Password \$secure').Count -ne 2 -or
            [regex]::Matches($workflow, '\$null = @\(Import-PfxCertificate').Count -ne 2 -or
            [regex]::Matches($workflow, 'Protected .* PFX must import exactly one matching private-key signer').Count -ne 2) {
            throw 'Windows signing identity cleanup does not fail closed and delete private keys.'
        }
        foreach ($certificateWindow in @($packageCertificateWindow, $bundleCertificateWindow)) {
            $derivationIndex = $certificateWindow.IndexOf(
                '$pfxThumbprints = @($pfxCertificates |'
            )
            $cleanupBindingIndex = $certificateWindow.IndexOf(
                '$cleanupThumbprints = $pfxThumbprints'
            )
            $retentionIndex = $certificateWindow.IndexOf('cleanup-thumbprints=')
            $cardinalityIndex = $certificateWindow.IndexOf('$signingCertificates.Count -ne 1')
            $signerOutputIndex = $certificateWindow.IndexOf('"thumbprint=$($certificate.Thumbprint)"')
            $postImportTryIndex = $certificateWindow.IndexOf('try {', $cleanupBindingIndex)
            $cleanupCatchIndex = $certificateWindow.IndexOf('$postImportError = $_')
            $cleanupCallIndex = $certificateWindow.LastIndexOf('Remove-ImportedCertificates')
            $cleanupLoopIndex = $certificateWindow.IndexOf(
                'foreach ($thumbprint in @($Thumbprints | Sort-Object -Unique))'
            )
            $cleanupAggregateIndex = $certificateWindow.IndexOf(
                'if ($cleanupFailures.Count -gt 0)'
            )
            if ($derivationIndex -lt 0 -or
                $cleanupBindingIndex -le $derivationIndex -or
                $postImportTryIndex -le $cleanupBindingIndex -or
                $retentionIndex -le $postImportTryIndex -or
                $cardinalityIndex -lt 0 -or
                $retentionIndex -ge $cardinalityIndex -or
                $signerOutputIndex -le $cardinalityIndex -or
                $cleanupCatchIndex -le $signerOutputIndex -or
                $cleanupCallIndex -le $cleanupCatchIndex -or
                $cleanupLoopIndex -lt 0 -or
                $cleanupAggregateIndex -le $cleanupLoopIndex -or
                [regex]::Matches($certificateWindow, 'Remove-ImportedCertificates').Count -ne 3 -or
                $certificateWindow -notmatch '\$pfxData\.EndEntityCertificates' -or
                $certificateWindow -notmatch '\$pfxData\.OtherCertificates' -or
                $certificateWindow -notmatch 'ForEach-Object \{ \$_\.Thumbprint \}' -or
                $certificateWindow -notmatch 'Sort-Object -Unique' -or
                $certificateWindow -notmatch 'collides with an existing certificate' -or
                $certificateWindow -notmatch 'throw \$postImportError') {
                throw 'Windows import does not retain and exhaustively clean the full certificate set.'
            }
            $packageCleanupReference =
                '${{ steps.package-signing.outputs.cleanup-thumbprints }}'
            $bundleCleanupReference =
                '${{ steps.bundle-signing.outputs.cleanup-thumbprints }}'
            if (-not $packageCleanupWindow.Contains($packageCleanupReference) -or
                -not $bundleCleanupWindow.Contains($bundleCleanupReference) -or
                -not $finalCleanupWindow.Contains($packageCleanupReference) -or
                -not $finalCleanupWindow.Contains($bundleCleanupReference)) {
                throw 'Windows cleanup phases do not consume every retained certificate set.'
            }
            foreach ($cleanupWindow in @(
                $packageCleanupWindow,
                $bundleCleanupWindow,
                $finalCleanupWindow
            )) {
                $cleanupLoopIndex = $cleanupWindow.IndexOf('foreach ($thumbprint in $thumbprints)')
                $cleanupAggregateIndex = $cleanupWindow.IndexOf('if ($cleanupFailures.Count -gt 0)')
                if ($cleanupLoopIndex -lt 0 -or
                    $cleanupAggregateIndex -le $cleanupLoopIndex) {
                    throw 'Windows cleanup can fail before attempting every retained certificate.'
                }
                $cleanupLoopBody = $cleanupWindow.Substring(
                    $cleanupLoopIndex,
                    $cleanupAggregateIndex - $cleanupLoopIndex
                )
                if ($cleanupLoopBody -match '(?m)^\s*throw\b') {
                    throw 'Windows cleanup throws before processing the complete retained set.'
                }
            }
        }
        $packageSignerReference =
            '-CertificateThumbprint ''${{ steps.package-signing.outputs.thumbprint }}'''
        $bundleSignerReference =
            '-CertificateThumbprint ''${{ steps.bundle-signing.outputs.thumbprint }}'''
        if (-not $packageCertificateWindow.Contains($packageSignerReference) -or
            -not $bundleCertificateWindow.Contains($bundleSignerReference) -or
            [regex]::Matches($workflow, '-CertificateThumbprint').Count -ne 2 -or
            [regex]::Matches($workflow, [regex]::Escape($packageSignerReference)).Count -ne 1 -or
            [regex]::Matches($workflow, [regex]::Escape($bundleSignerReference)).Count -ne 1) {
            throw 'Windows sign steps do not consume their validated single-certificate outputs.'
        }
    $signSource = [System.IO.File]::ReadAllText((Join-Path $scriptRoot 'sign.ps1'))
    if ($signSource -match '(?im)^\s*(cargo|rustc)\b' -or
        $signSource -match 'Assert-RustToolchain' -or
        $signSource -match 'New-ArtifactSupplyChain' -or
        $signSource -match 'package\.ps1' -or
        $signSource -match 'bundle\.ps1') {
        throw 'sign.ps1 is not constrained to reviewed package signing and validation.'
    }
    $assemblyWindow = $workflow.Substring($assemblyIndex, $uploadIndex - $assemblyIndex)
    if ($workflow -notmatch 'SIGNING_INPUT_MANIFEST' -or
        $workflow -notmatch 'BUNDLE_SIGNING_SHA256' -or
        $workflow -notmatch 'release_commit must equal the immutable workflow commit' -or
        $workflow -notmatch 'Remote annotated release tag changed before signing' -or
        $workflow -notmatch 'Remote annotated release tag changed before bundle signing' -or
        $workflow -notmatch 'Expected eight signed Windows release artifacts' -or
        $assemblyWindow -notmatch 'portable-signed') {
        throw 'Protected Windows reviewed-byte or signed-only release contract is incomplete.'
    }
    if ($signSource -notmatch "'\.zip'" -or
        $signSource -notmatch 'Add-VerifiedSignature' -or
        $signSource -notmatch 'New-DeterministicZip') {
        throw 'Portable executable signing is not confined to the reviewed sign-only helper.'
    }
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
        foreach ($target in @('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')) {
            Assert-HeadlessGraph -RepoRoot $repoRoot -TargetTriple $target
            $arguments = [System.IO.File]::ReadAllText($cargoArguments)
            if ($arguments -notmatch "(^|\s)--target\s+$([regex]::Escape($target))(\s|$)") {
                throw "Headless Cargo graph proof omitted target '$target': $arguments"
            }
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

    if ($passed -ne 65) {
        throw "Expected 65 self-tests, completed $passed."
    }
    Write-Host "Windows packaging self-tests passed: $passed."
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
