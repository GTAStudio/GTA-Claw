Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-CargoPackages {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][ValidateSet('desktop', 'headless', 'combined')][string]$ComponentSet,
        [Parameter(Mandatory)][string[]]$RustTarget
    )

    $manifests = @()
    if ($ComponentSet -in @('headless', 'combined')) {
        $manifests += Join-Path $RepoRoot 'Cargo.toml'
    }
    if ($ComponentSet -in @('desktop', 'combined')) {
        $manifests += Join-Path $RepoRoot 'desktop\Cargo.toml'
    }

    $cargo = (Get-Command cargo -ErrorAction Stop).Source
    $packages = @{}
    foreach ($target in $RustTarget) {
        foreach ($manifest in $manifests) {
            $json = & $cargo metadata `
                --manifest-path $manifest `
                --locked `
                --offline `
                --format-version 1 `
                --filter-platform $target
            if ($LASTEXITCODE -ne 0) {
                throw "cargo metadata failed while generating the artifact SBOM for '$manifest' and '$target'."
            }
            $metadata = $json | ConvertFrom-Json
            foreach ($package in $metadata.packages) {
                $key = "$($package.name)@$($package.version)"
                if (-not $packages.ContainsKey($key)) {
                    $packages[$key] = $package
                }
            }
        }
    }
    return @($packages.Values | Sort-Object name, version)
}

function Get-SourceRevision {
    param([Parameter(Mandatory)][string]$RepoRoot)

    if ($env:GITHUB_SHA -match '^[0-9a-f]{40}$') {
        return $env:GITHUB_SHA
    }
    $git = (Get-Command git -ErrorAction Stop).Source
    $revision = (& $git -C $RepoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{40}$') {
        throw 'Unable to resolve a full source revision for provenance.'
    }
    return $revision
}

function ConvertTo-SpdxId {
    param([Parameter(Mandatory)][string]$Value)

    $safe = [regex]::Replace($Value, '[^A-Za-z0-9.-]', '-')
    return "SPDXRef-Package-$safe"
}

function New-ArtifactSupplyChain {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$ArtifactPath,
        [Parameter(Mandatory)][ValidateSet('desktop', 'headless', 'combined')][string]$ComponentSet,
        [Parameter(Mandatory)][string[]]$RustTarget,
        [string[]]$ProvenanceTargets = @($RustTarget)
    )

    $artifact = Assert-PlainFile $ArtifactPath
    $artifactName = [System.IO.Path]::GetFileName($artifact)
    $artifactHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    $revision = Get-SourceRevision $RepoRoot
    $packages = Get-CargoPackages -RepoRoot $RepoRoot -ComponentSet $ComponentSet -RustTarget $RustTarget

    $spdxPackages = @()
    foreach ($package in $packages) {
        $license = 'NOASSERTION'
        if (-not [string]::IsNullOrWhiteSpace([string]$package.license)) {
            $license = [string]$package.license
        }
        $spdxPackages += [ordered]@{
            name = [string]$package.name
            SPDXID = ConvertTo-SpdxId "$($package.name)-$($package.version)"
            versionInfo = [string]$package.version
            downloadLocation = 'NOASSERTION'
            filesAnalyzed = $false
            licenseConcluded = 'NOASSERTION'
            licenseDeclared = $license
            copyrightText = 'NOASSERTION'
            externalRefs = @(
                [ordered]@{
                    referenceCategory = 'PACKAGE-MANAGER'
                    referenceType = 'purl'
                    referenceLocator = "pkg:cargo/$($package.name)@$($package.version)"
                }
            )
        }
    }

    $spdx = [ordered]@{
        spdxVersion = 'SPDX-2.3'
        dataLicense = 'CC0-1.0'
        SPDXID = 'SPDXRef-DOCUMENT'
        name = "$artifactName SBOM"
        documentNamespace = "https://github.com/GTAStudio/GTA-Claw/releases/sbom/$artifactHash"
        creationInfo = [ordered]@{
            created = '2000-01-01T00:00:00Z'
            creators = @('Tool: GTA-Claw-WindowsPackaging')
        }
        documentDescribes = @('SPDXRef-Artifact')
        packages = $spdxPackages
        files = @(
            [ordered]@{
                fileName = "./$artifactName"
                SPDXID = 'SPDXRef-Artifact'
                checksums = @(
                    [ordered]@{
                        algorithm = 'SHA256'
                        checksumValue = $artifactHash
                    }
                )
                licenseConcluded = 'NOASSERTION'
                copyrightText = 'NOASSERTION'
            }
        )
    }
    $sbomPath = "$artifact.spdx.json"
    Write-Utf8File -Path $sbomPath -Content (($spdx | ConvertTo-Json -Depth 10 -Compress) + "`n")

    $lockSubjects = @()
    foreach ($lockPath in @((Join-Path $RepoRoot 'Cargo.lock'), (Join-Path $RepoRoot 'desktop\Cargo.lock'))) {
        if ($ComponentSet -eq 'desktop' -and $lockPath -eq (Join-Path $RepoRoot 'Cargo.lock')) {
            continue
        }
        if ($ComponentSet -eq 'headless' -and $lockPath -eq (Join-Path $RepoRoot 'desktop\Cargo.lock')) {
            continue
        }
        $lockUri = 'Cargo.lock'
        if ($lockPath -eq (Join-Path $RepoRoot 'desktop\Cargo.lock')) {
            $lockUri = 'desktop/Cargo.lock'
        }
        $lockSubjects += [ordered]@{
            uri = $lockUri
            digest = [ordered]@{
                sha256 = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    }

    $provenance = [ordered]@{
        _type = 'https://in-toto.io/Statement/v1'
        subject = @(
            [ordered]@{
                name = $artifactName
                digest = [ordered]@{ sha256 = $artifactHash }
            }
        )
        predicateType = 'https://slsa.dev/provenance/v1'
        predicate = [ordered]@{
            buildDefinition = [ordered]@{
                buildType = 'https://github.com/GTAStudio/GTA-Claw/packaging/windows/v1'
                externalParameters = [ordered]@{
                    componentSet = $ComponentSet
                    profile = 'release'
                    rustTargets = @($ProvenanceTargets)
                    offline = $true
                }
                internalParameters = [ordered]@{}
                resolvedDependencies = $lockSubjects
            }
            runDetails = [ordered]@{
                builder = [ordered]@{
                    id = 'https://github.com/GTAStudio/GTA-Claw/.github/workflows/windows-packaging.yml'
                }
                metadata = [ordered]@{
                    invocationId = $revision
                }
            }
        }
    }
    $provenancePath = "$artifact.provenance.json"
    Write-Utf8File -Path $provenancePath -Content (($provenance | ConvertTo-Json -Depth 10 -Compress) + "`n")

    Test-ArtifactSupplyChain -ArtifactPath $artifact | Out-Null
    return [pscustomobject]@{
        Sbom = $sbomPath
        Provenance = $provenancePath
    }
}

function Test-ArtifactSupplyChain {
    param([Parameter(Mandatory)][string]$ArtifactPath)

    $artifact = Assert-PlainFile $ArtifactPath
    $artifactHash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    $artifactName = [System.IO.Path]::GetFileName($artifact)
    $sbomPath = Assert-PlainFile "$artifact.spdx.json"
    $provenancePath = Assert-PlainFile "$artifact.provenance.json"

    $sbom = Get-Content -LiteralPath $sbomPath -Raw | ConvertFrom-Json
    if ($sbom.spdxVersion -ne 'SPDX-2.3' -or
        @($sbom.files).Count -ne 1 -or
        $sbom.files[0].fileName -ne "./$artifactName" -or
        $sbom.files[0].checksums[0].checksumValue -ne $artifactHash -or
        @($sbom.packages).Count -eq 0) {
        throw "SPDX SBOM does not attest the published artifact bytes: $artifact"
    }

    $provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
    if ($provenance._type -ne 'https://in-toto.io/Statement/v1' -or
        $provenance.predicateType -ne 'https://slsa.dev/provenance/v1' -or
        @($provenance.subject).Count -ne 1 -or
        $provenance.subject[0].name -ne $artifactName -or
        $provenance.subject[0].digest.sha256 -ne $artifactHash) {
        throw "Provenance does not attest the published artifact bytes: $artifact"
    }
}

function Write-ArtifactSetChecksums {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [ValidatePattern('^SHA256SUMS(?:-[a-z]+)?$')][string]$ManifestName = 'SHA256SUMS'
    )

    if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
        throw "Artifact directory is missing: $Directory"
    }
    $manifest = Join-Path $Directory $ManifestName
    $lines = Get-ChildItem -LiteralPath $Directory -File |
        Where-Object { $_.FullName -ne $manifest -and $_.Name -ne 'artifacts.json' -and $_.Extension -ne '.sha256' } |
        Sort-Object Name |
        ForEach-Object {
            "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $($_.Name)"
        }
    if (-not $lines) {
        throw "No published artifacts found in '$Directory'."
    }
    Write-Utf8File -Path $manifest -Content (($lines -join "`n") + "`n")
    return $manifest
}

function Test-ArtifactSetChecksums {
    param(
        [Parameter(Mandatory)][string]$Directory,
        [ValidatePattern('^SHA256SUMS(?:-[a-z]+)?$')][string]$ManifestName = 'SHA256SUMS'
    )

    $manifest = Assert-PlainFile (Join-Path $Directory $ManifestName)
    $seen = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($manifest)) {
        if ($line -notmatch '^([0-9a-f]{64})  ([^\\/]+)$') {
            throw "Invalid published SHA256SUMS entry: $line"
        }
        $name = $Matches[2]
        if ($seen.ContainsKey($name)) {
            throw "Duplicate published SHA256SUMS entry: $name"
        }
        $seen[$name] = $true
        $path = Assert-PlainFile (Join-Path $Directory $name)
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $Matches[1]) {
            throw "Published SHA-256 mismatch for '$name'."
        }
    }
    $expected = @(Get-ChildItem -LiteralPath $Directory -File |
        Where-Object {
            $_.Name -ne $ManifestName -and
            $_.Name -ne 'artifacts.json' -and
            $_.Extension -ne '.sha256'
        })
    if ($seen.Count -ne $expected.Count) {
        throw "Published SHA256SUMS coverage differs from the artifact directory."
    }
    foreach ($file in $expected) {
        if (-not $seen.ContainsKey($file.Name)) {
            throw "Published SHA256SUMS omits '$($file.Name)'."
        }
    }
}

Export-ModuleMember -Function @(
    'New-ArtifactSupplyChain',
    'Test-ArtifactSetChecksums',
    'Test-ArtifactSupplyChain',
    'Write-ArtifactSetChecksums'
)
