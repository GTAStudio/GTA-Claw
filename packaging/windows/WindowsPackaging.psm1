Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NormalizedFullPath {
    param([Parameter(Mandatory)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory)][string]$Parent,
        [Parameter(Mandatory)][string]$Child
    )
    $parentPath = Get-NormalizedFullPath $Parent
    $childPath = Get-NormalizedFullPath $Child
    $prefix = $parentPath + [System.IO.Path]::DirectorySeparatorChar
    if (-not $childPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$childPath' is outside owned root '$parentPath'."
    }
    return $childPath
}

function Assert-NoReparsePathComponents {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path
    )
    $rootPath = Get-NormalizedFullPath $Root
    $pathValue = Get-NormalizedFullPath $Path
    if (-not $pathValue.Equals($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        Assert-ChildPath -Parent $rootPath -Child $pathValue | Out-Null
    }
    $current = $rootPath
    $paths = @($current)
    if (-not $pathValue.Equals($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        $relative = $pathValue.Substring($rootPath.Length).TrimStart(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        )
        foreach ($segment in ($relative -split '[\\/]')) {
            $current = Join-Path $current $segment
            $paths += $current
        }
    }
    foreach ($candidate in $paths) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            break
        }
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point in owned path is forbidden: $candidate"
        }
    }
}

function Assert-RelativePackagePath {
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or [System.IO.Path]::IsPathRooted($Path) -or $Path.Contains(':')) {
        throw "Package path '$Path' must be relative."
    }
    $segments = $Path -split '[\\/]'
    if ($segments.Count -eq 0 -or ($segments | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' })) {
        throw "Package path '$Path' contains an invalid or traversing segment."
    }
    return ($segments -join '\')
}

function Assert-PlainFile {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse points are forbidden in package inputs: $Path"
    }
    return $item.FullName
}

function Assert-NoReparsePoints {
    param([Parameter(Mandatory)][string]$Root)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "Required directory is missing: $Root"
    }
    $items = @((Get-Item -LiteralPath $Root -Force)) + @(Get-ChildItem -LiteralPath $Root -Force -Recurse)
    foreach ($item in $items) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse points are forbidden in staged payloads: $($item.FullName)"
        }
    }
}

function Remove-OwnedDirectory {
    param(
        [Parameter(Mandatory)][string]$OwnedRoot,
        [Parameter(Mandatory)][string]$Path
    )
    $safePath = Assert-ChildPath -Parent $OwnedRoot -Child $Path
    Assert-NoReparsePathComponents -Root $OwnedRoot -Path $safePath
    if (Test-Path -LiteralPath $safePath) {
        Remove-Item -LiteralPath $safePath -Recurse -Force
    }
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Get-CanonicalVersion {
    param([Parameter(Mandatory)][string]$RepoRoot)
    $rootManifest = Join-Path $RepoRoot 'Cargo.toml'
    $desktopManifest = Join-Path $RepoRoot 'desktop\Cargo.toml'
    Assert-PlainFile $rootManifest | Out-Null
    Assert-PlainFile $desktopManifest | Out-Null

    function Read-WorkspaceVersion([string]$ManifestPath) {
        $section = ''
        foreach ($line in [System.IO.File]::ReadAllLines($ManifestPath)) {
            if ($line -match '^\s*\[([^\]]+)\]\s*$') {
                $section = $Matches[1]
                continue
            }
            if ($section -eq 'workspace.package' -and $line -match '^\s*version\s*=\s*"([^"]+)"\s*$') {
                return $Matches[1]
            }
        }
        throw "Missing [workspace.package].version in $ManifestPath"
    }

    $version = Read-WorkspaceVersion $rootManifest
    $desktopVersion = Read-WorkspaceVersion $desktopManifest
    if ($desktopVersion -ne $version) {
        throw "Desktop version '$desktopVersion' differs from canonical root Cargo version '$version'."
    }
    return Convert-WindowsVersion $version
}

function Convert-WindowsVersion {
    param([Parameter(Mandatory)][string]$Version)
    if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw "Cargo version '$Version' must be plain major.minor.patch; prerelease and build metadata are not packageable."
    }
    [uint32]$major = $Matches[1]
    [uint32]$minor = $Matches[2]
    [uint32]$patch = $Matches[3]
    if ($major -gt 255) {
        throw "Cargo major version '$major' exceeds the MSI limit of 255."
    }
    if ($minor -gt 65535 -or $patch -gt 65535) {
        throw "Cargo minor and patch versions must not exceed 65535."
    }
    return [pscustomobject]@{
        Cargo = $Version
        Msix = "$major.$minor.$patch.0"
        Msi = "$major.$minor.$patch"
    }
}

function Get-Architecture {
    param([Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Name)
    if ($Name -eq 'x64') {
        return [pscustomobject]@{
            Name = 'x64'
            RustTarget = 'x86_64-pc-windows-msvc'
            Msix = 'x64'
            PeMachine = [uint16]0x8664
            UpgradeCode = 'B14FD1CA-ED7E-59B7-81CF-5D0D9B6D7090'
        }
    }
    return [pscustomobject]@{
        Name = 'arm64'
        RustTarget = 'aarch64-pc-windows-msvc'
        Msix = 'arm64'
        PeMachine = [uint16]0xAA64
        UpgradeCode = '589E56FD-45DD-5AB7-BB59-E02D949119A7'
    }
}

function Assert-PeArchitecture {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][uint16]$ExpectedMachine
    )
    Assert-PlainFile $Path | Out-Null
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            throw "'$Path' is not a PE executable."
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 6)) {
            throw "'$Path' has an invalid PE header offset."
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "'$Path' has no PE signature."
        }
        $actual = $reader.ReadUInt16()
        if ($actual -ne $ExpectedMachine) {
            throw ("PE machine mismatch for '{0}': expected 0x{1:X4}, found 0x{2:X4}." -f $Path, $ExpectedMachine, $actual)
        }
    } finally {
        $stream.Dispose()
    }
}

function Find-WindowsSdkTool {
    param(
        [Parameter(Mandatory)][ValidateSet('makeappx.exe', 'signtool.exe')][string]$ToolName,
        [string]$SdkBinRoot
    )
    if ([string]::IsNullOrWhiteSpace($SdkBinRoot) -and -not [string]::IsNullOrWhiteSpace($env:GTA_CLAW_WINDOWS_SDK_BIN)) {
        $SdkBinRoot = $env:GTA_CLAW_WINDOWS_SDK_BIN
    }
    if (-not [string]::IsNullOrWhiteSpace($SdkBinRoot)) {
        $candidate = Join-Path $SdkBinRoot $ToolName
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Assert-PlainFile $candidate)
        }
        throw "Required Windows SDK tool '$ToolName' was not found in '$SdkBinRoot'."
    }

    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (-not (Test-Path -LiteralPath $kitsRoot -PathType Container)) {
        throw "Windows SDK bin root was not found: $kitsRoot"
    }
    $candidates = Get-ChildItem -LiteralPath $kitsRoot -Directory |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName "x64\$ToolName" } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    if (-not $candidates) {
        throw "Required Windows SDK tool '$ToolName' was not found below '$kitsRoot'."
    }
    return (Assert-PlainFile ($candidates | Select-Object -First 1))
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    Assert-PlainFile $FilePath | Out-Null
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "'$FilePath' failed with exit code $LASTEXITCODE."
    }
}

function Initialize-MsvcEnvironment {
    param([Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture)
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    Assert-PlainFile $vswhere | Out-Null
    $component = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
    if ($Architecture -eq 'arm64') {
        $component = 'Microsoft.VisualStudio.Component.VC.Tools.ARM64'
    }
    $installationPaths = @(& $vswhere -latest -products '*' -requires $component -property installationPath)
    $vswhereExitCode = $LASTEXITCODE
    $installationPath = $installationPaths | Select-Object -First 1
    if ($vswhereExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($installationPath)) {
        throw "Visual Studio MSVC tools for '$Architecture' are not installed."
    }
    $developerCommand = Join-Path $installationPath 'Common7\Tools\VsDevCmd.bat'
    Assert-PlainFile $developerCommand | Out-Null
    $vswhereDirectory = Split-Path -Parent $vswhere
    $command = 'set "PATH={0};%PATH%" && call "{1}" -no_logo -arch={2} -host_arch=x64 >nul && set' -f (
        $vswhereDirectory,
        $developerCommand,
        $Architecture
    )
    $environment = & $env:ComSpec /d /s /c $command
    if ($LASTEXITCODE -ne 0) {
        throw "VsDevCmd failed to initialize the '$Architecture' compiler environment."
    }
    foreach ($line in $environment) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            $name = $line.Substring(0, $separator)
            $value = $line.Substring($separator + 1)
            Set-Item -Path "Env:$name" -Value $value
        }
    }
    $linker = (Get-Command link.exe -ErrorAction Stop).Source
    $expectedSegment = '\Hostx64\x64\'
    if ($Architecture -eq 'arm64') {
        $expectedSegment = '\Hostx64\arm64\'
    }
    if ($linker.IndexOf($expectedSegment, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "VsDevCmd selected unexpected linker '$linker' for '$Architecture'."
    }
    return $linker
}

function Copy-PlainFile {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )
    Assert-PlainFile $Source | Out-Null
    $parent = Split-Path -Parent $Destination
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    Assert-PlainFile $Destination | Out-Null
}

function Set-NormalizedTreeTimestamp {
    param([Parameter(Mandatory)][string]$Root)
    Assert-NoReparsePoints $Root
    $timestamp = [DateTime]::SpecifyKind(
        [DateTime]::ParseExact('2000-01-01T00:00:00', 'yyyy-MM-ddTHH:mm:ss', $null),
        [DateTimeKind]::Utc
    )
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force -Recurse) + @(Get-Item -LiteralPath $Root -Force)) {
        $item.LastWriteTimeUtc = $timestamp
    }
}

function Set-NormalizedZipTimestamps {
    param([Parameter(Mandatory)][string]$Path)
    $package = Assert-PlainFile $Path
    $bytes = [System.IO.File]::ReadAllBytes($package)
    $eocd = $bytes.Length - 22
    $minimum = [Math]::Max(0, $bytes.Length - 65557)
    while ($eocd -ge $minimum -and [BitConverter]::ToUInt32($bytes, $eocd) -ne 0x06054B50) {
        $eocd--
    }
    if ($eocd -lt $minimum) {
        throw "ZIP end-of-central-directory record is missing: $package"
    }
    $entryCount = [int64][BitConverter]::ToUInt16($bytes, $eocd + 10)
    $centralOffset = [int64][BitConverter]::ToUInt32($bytes, $eocd + 16)
    if ($entryCount -eq 65535 -or $centralOffset -eq [uint32]::MaxValue) {
        $locator = $eocd - 20
        if ($locator -lt 0 -or [BitConverter]::ToUInt32($bytes, $locator) -ne 0x07064B50) {
            throw "ZIP64 locator is missing: $package"
        }
        $zip64 = [int][BitConverter]::ToUInt64($bytes, $locator + 8)
        if ([BitConverter]::ToUInt32($bytes, $zip64) -ne 0x06064B50) {
            throw "ZIP64 end-of-central-directory record is missing: $package"
        }
        $entryCount = [int64][BitConverter]::ToUInt64($bytes, $zip64 + 32)
        $centralOffset = [int64][BitConverter]::ToUInt64($bytes, $zip64 + 48)
    }
    if ($entryCount -le 0 -or $entryCount -gt 100000 -or
        $centralOffset -lt 0 -or $centralOffset -ge $bytes.Length) {
        throw "ZIP central-directory metadata is invalid: $package"
    }

    $fixedDate = [uint16]0x2821
    $offset = [int]$centralOffset
    for ($entry = 0; $entry -lt $entryCount; $entry++) {
        if ([BitConverter]::ToUInt32($bytes, $offset) -ne 0x02014B50) {
            throw "ZIP central-directory entry is invalid: $package"
        }
        $nameLength = [BitConverter]::ToUInt16($bytes, $offset + 28)
        $extraLength = [BitConverter]::ToUInt16($bytes, $offset + 30)
        $commentLength = [BitConverter]::ToUInt16($bytes, $offset + 32)
        $local32 = [BitConverter]::ToUInt32($bytes, $offset + 42)
        $localOffset = [int64]$local32
        $extraOffset = $offset + 46 + $nameLength
        $extraEnd = $extraOffset + $extraLength
        while ($extraOffset -lt $extraEnd) {
            if ($extraOffset + 4 -gt $extraEnd) {
                throw "ZIP extra field is truncated: $package"
            }
            $extraId = [BitConverter]::ToUInt16($bytes, $extraOffset)
            $extraSize = [BitConverter]::ToUInt16($bytes, $extraOffset + 2)
            if ($extraOffset + 4 + $extraSize -gt $extraEnd) {
                throw "ZIP extra field length is invalid: $package"
            }
            if ($extraId -eq 1) {
                $cursor = $extraOffset + 4
                if ([BitConverter]::ToUInt32($bytes, $offset + 24) -eq [uint32]::MaxValue) {
                    $cursor += 8
                }
                if ([BitConverter]::ToUInt32($bytes, $offset + 20) -eq [uint32]::MaxValue) {
                    $cursor += 8
                }
                if ($local32 -eq [uint32]::MaxValue) {
                    if ($cursor + 8 -gt $extraOffset + 4 + $extraSize) {
                        throw "ZIP64 local-header offset is missing: $package"
                    }
                    $localOffset = [int64][BitConverter]::ToUInt64($bytes, $cursor)
                }
            }
            $extraOffset += 4 + $extraSize
        }
        if ($localOffset -lt 0 -or $localOffset + 14 -gt $bytes.Length -or
            [BitConverter]::ToUInt32($bytes, [int]$localOffset) -ne 0x04034B50) {
            throw "ZIP local-file header is invalid: $package"
        }
        [Array]::Copy([BitConverter]::GetBytes([uint16]0), 0, $bytes, $offset + 12, 2)
        [Array]::Copy([BitConverter]::GetBytes($fixedDate), 0, $bytes, $offset + 14, 2)
        [Array]::Copy([BitConverter]::GetBytes([uint16]0), 0, $bytes, [int]$localOffset + 10, 2)
        [Array]::Copy([BitConverter]::GetBytes($fixedDate), 0, $bytes, [int]$localOffset + 12, 2)
        $offset += 46 + $nameLength + $extraLength + $commentLength
    }
    [System.IO.File]::WriteAllBytes($package, $bytes)
}

function Set-NormalizedMsiStorageTimestamps {
    param([Parameter(Mandatory)][string]$Path)
    $package = Assert-PlainFile $Path
    $bytes = [System.IO.File]::ReadAllBytes($package)
    $magic = [byte[]](0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1)
    for ($index = 0; $index -lt $magic.Length; $index++) {
        if ($bytes[$index] -ne $magic[$index]) {
            throw "MSI is not a compound file: $package"
        }
    }
    $sectorSize = 1 -shl [BitConverter]::ToUInt16($bytes, 30)
    if ($sectorSize -notin @(512, 4096)) {
        throw "MSI compound-file sector size is invalid: $sectorSize"
    }
    $fatCount = [BitConverter]::ToUInt32($bytes, 44)
    $directorySector = [BitConverter]::ToUInt32($bytes, 48)
    $freeSector = [uint32]::MaxValue
    $endOfChain = [uint32]4294967294
    $difat = @()
    for ($index = 0; $index -lt 109; $index++) {
        $sector = [BitConverter]::ToUInt32($bytes, 76 + (4 * $index))
        if ($sector -ne $freeSector) {
            $difat += $sector
        }
    }
    $nextDifat = [BitConverter]::ToUInt32($bytes, 68)
    $difatCount = [BitConverter]::ToUInt32($bytes, 72)
    for ($difatIndex = 0; $difatIndex -lt $difatCount; $difatIndex++) {
        $difatOffset = ([int64]$nextDifat + 1) * $sectorSize
        if ($difatOffset -lt 0 -or $difatOffset + $sectorSize -gt $bytes.Length) {
            throw "MSI DIFAT sector is invalid: $package"
        }
        for ($index = 0; $index -lt (($sectorSize / 4) - 1); $index++) {
            $sector = [BitConverter]::ToUInt32($bytes, [int]($difatOffset + (4 * $index)))
            if ($sector -ne $freeSector) {
                $difat += $sector
            }
        }
        $nextDifat = [BitConverter]::ToUInt32($bytes, [int]($difatOffset + $sectorSize - 4))
    }
    if ($difat.Count -ne $fatCount) {
        throw "MSI FAT sector count is invalid: $package"
    }
    $fat = New-Object 'System.Collections.Generic.List[uint32]'
    foreach ($sector in $difat) {
        $fatOffset = ([int64]$sector + 1) * $sectorSize
        if ($fatOffset -lt 0 -or $fatOffset + $sectorSize -gt $bytes.Length) {
            throw "MSI FAT sector is invalid: $package"
        }
        for ($index = 0; $index -lt ($sectorSize / 4); $index++) {
            $fat.Add([BitConverter]::ToUInt32($bytes, [int]($fatOffset + (4 * $index))))
        }
    }
    $visited = @{}
    while ($directorySector -ne $endOfChain) {
        if ($directorySector -ge $fat.Count -or $visited.ContainsKey($directorySector)) {
            throw "MSI directory chain is invalid: $package"
        }
        $visited[$directorySector] = $true
        $directoryOffset = ([int64]$directorySector + 1) * $sectorSize
        if ($directoryOffset -lt 0 -or $directoryOffset + $sectorSize -gt $bytes.Length) {
            throw "MSI directory sector is invalid: $package"
        }
        for ($entryOffset = 0; $entryOffset -lt $sectorSize; $entryOffset += 128) {
            if ($bytes[[int]($directoryOffset + $entryOffset + 66)] -ne 0) {
                for ($timestampOffset = 100; $timestampOffset -lt 116; $timestampOffset++) {
                    $bytes[[int]($directoryOffset + $entryOffset + $timestampOffset)] = 0
                }
            }
        }
        $directorySector = $fat[[int]$directorySector]
    }
    [System.IO.File]::WriteAllBytes($package, $bytes)
}

function Get-RelativePayloadPath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Path
    )
    $rootPath = Get-NormalizedFullPath $Root
    $pathValue = Assert-ChildPath -Parent $rootPath -Child $Path
    $rootUri = New-Object System.Uri(($rootPath + [System.IO.Path]::DirectorySeparatorChar))
    $pathUri = New-Object System.Uri($pathValue)
    return [System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString()).Replace('/', '\')
}

function New-HashManifest {
    param([Parameter(Mandatory)][string]$Root)
    Assert-NoReparsePoints $Root
    $manifest = Join-Path $Root 'SHA256SUMS.txt'
    $lines = Get-ChildItem -LiteralPath $Root -File -Recurse |
        Where-Object { $_.FullName -ne $manifest } |
        ForEach-Object {
            $relative = Get-RelativePayloadPath -Root $Root -Path $_.FullName
            [pscustomobject]@{
                Relative = $relative
                Line = "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)  $relative"
            }
        } |
        Sort-Object Relative |
        Select-Object -ExpandProperty Line
    if (-not $lines) {
        throw "Cannot create a hash manifest for an empty payload: $Root"
    }
    Write-Utf8File -Path $manifest -Content (($lines -join "`n") + "`n")
    return $manifest
}

function Test-HashManifest {
    param(
        [Parameter(Mandatory)][string]$Root,
        [string[]]$IgnoreAdditionalFiles = @()
    )
    Assert-NoReparsePoints $Root
    $manifest = Assert-PlainFile (Join-Path $Root 'SHA256SUMS.txt')
    $seen = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($manifest)) {
        if ($line -notmatch '^([0-9A-F]{64})  (.+)$') {
            throw "Invalid SHA256SUMS entry: $line"
        }
        $relative = Assert-RelativePackagePath $Matches[2]
        if ($seen.ContainsKey($relative)) {
            throw "Duplicate SHA256SUMS entry: $relative"
        }
        $seen[$relative] = $true
        $path = Assert-ChildPath -Parent $Root -Child (Join-Path $Root $relative)
        Assert-PlainFile $path | Out-Null
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        if ($actual -ne $Matches[1]) {
            throw "SHA-256 mismatch for '$relative'."
        }
    }
    $payloadFiles = Get-ChildItem -LiteralPath $Root -File -Recurse |
        Where-Object { $_.FullName -ne $manifest }
    $ignored = @{}
    foreach ($name in $IgnoreAdditionalFiles) {
        $ignored[$name.ToLowerInvariant()] = $true
    }
    foreach ($file in $payloadFiles) {
        $relative = Get-RelativePayloadPath -Root $Root -Path $file.FullName
        if (-not $seen.ContainsKey($relative) -and -not $ignored.ContainsKey($file.Name.ToLowerInvariant())) {
            throw "SHA256SUMS.txt does not cover '$relative'."
        }
    }
}

function Assert-PayloadSafety {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$ExpectedExecutables,
        [string[]]$AdditionalAllowedFiles = @()
    )
    Assert-NoReparsePoints $Root
    $expected = @{}
    foreach ($name in $ExpectedExecutables) {
        $expected[$name.ToLowerInvariant()] = $true
    }
    $allowed = @{
        'license.txt' = $true
        'non-release.txt' = $true
        'release-status.txt' = $true
        'sha256sums.txt' = $true
        'appxmanifest.xml' = $true
        'square44x44logo.png' = $true
        'square150x150logo.png' = $true
        'storelogo.png' = $true
    }
    foreach ($name in $AdditionalAllowedFiles) {
        $allowed[$name.ToLowerInvariant()] = $true
    }
    foreach ($file in Get-ChildItem -LiteralPath $Root -File -Recurse) {
        $name = $file.Name.ToLowerInvariant()
        $extension = $file.Extension.ToLowerInvariant()
        if ($name -match '^(node|npm|npx|pnpm|bun)(\.|$)' -or
            $name -eq 'package.json' -or
            $extension -in @('.js', '.mjs', '.cjs', '.node', '.npmrc')) {
            throw "JavaScript/Node runtime material is forbidden in Windows payloads: $($file.FullName)"
        }
        if ($extension -eq '.dll') {
            throw "Unexpected DLL in Windows payload: $($file.FullName)"
        }
        if ($extension -eq '.exe' -and -not $expected.ContainsKey($name)) {
            throw "Unexpected executable in Windows payload: $($file.FullName)"
        }
        if ($extension -ne '.exe' -and -not $allowed.ContainsKey($name)) {
            throw "Unexpected payload file: $($file.FullName)"
        }
    }
    foreach ($name in $ExpectedExecutables) {
        $matches = @(Get-ChildItem -LiteralPath $Root -File -Recurse | Where-Object { $_.Name -ieq $name })
        if ($matches.Count -ne 1) {
            throw "Expected exactly one '$name' in '$Root'; found $($matches.Count)."
        }
    }
}

function Assert-BinaryDoesNotContainAscii {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Forbidden
    )
    $bytes = [System.IO.File]::ReadAllBytes((Assert-PlainFile $Path))
    $text = [System.Text.Encoding]::ASCII.GetString($bytes).ToLowerInvariant()
    foreach ($needle in $Forbidden) {
        if ($text.Contains($needle.ToLowerInvariant())) {
            throw "Published binary '$Path' contains forbidden marker '$needle'."
        }
    }
}

function Test-PeDependencies {
    param([Parameter(Mandatory)][string]$Path)

    Assert-PlainFile $Path | Out-Null
    $dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($null -eq $dumpbin) {
        throw 'dumpbin.exe is required to validate published PE dependency allowlists.'
    }
    $output = & $dumpbin.Source /nologo /dependents $Path
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin could not inspect dependencies for '$Path'."
    }
    $allowed = @(
        'ADVAPI32.dll', 'bcrypt.dll', 'bcryptprimitives.dll', 'cfgmgr32.dll',
        'COMCTL32.dll', 'COMDLG32.dll', 'CRYPT32.dll', 'D2D1.dll', 'd3d11.dll',
        'combase.dll',
        'DWrite.dll', 'dxgi.dll', 'dwmapi.dll', 'GDI32.dll', 'IMM32.dll',
        'IPHLPAPI.DLL', 'KERNEL32.dll', 'MSIMG32.dll', 'ncrypt.dll',
        'NETAPI32.dll', 'normaliz.dll', 'NTDLL.dll', 'ole32.dll', 'OLEAUT32.dll',
        'OPENGL32.dll', 'POWRPROF.dll', 'PROPSYS.dll', 'RPCRT4.dll',
        'secur32.dll', 'SETUPAPI.dll', 'SHELL32.dll', 'SHLWAPI.dll',
        'UIAutomationCore.dll', 'USER32.dll', 'USERENV.dll', 'UxTheme.dll', 'VERSION.dll',
        'WINHTTP.dll', 'WINMM.dll', 'WINSPOOL.DRV', 'WS2_32.dll', 'WTSAPI32.dll',
        'WindowsCodecs.dll'
    )
    $allowedSet = @{}
    foreach ($name in $allowed) {
        $allowedSet[$name.ToLowerInvariant()] = $true
    }
    $dependencies = @($output |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^[A-Za-z0-9_.-]+\.(dll|drv)$' })
    if ($dependencies.Count -eq 0) {
        throw "No PE imports were discovered in '$Path'."
    }
    foreach ($dependency in $dependencies) {
        $normalized = $dependency.ToLowerInvariant()
        if (-not $allowedSet.ContainsKey($normalized) -and
            -not $normalized.StartsWith('api-ms-win-') -and
            -not $normalized.StartsWith('ext-ms-win-')) {
            throw "Unexpected PE dependency '$dependency' in '$Path'."
        }
    }
}

function New-DeterministicZip {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Destination
    )
    Assert-NoReparsePoints $Root
    Add-Type -AssemblyName System.IO.Compression
    $destinationPath = Get-NormalizedFullPath $Destination
    $parent = Split-Path -Parent $destinationPath
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    if (Test-Path -LiteralPath $destinationPath) {
        Remove-Item -LiteralPath $destinationPath -Force
    }
    $stream = [System.IO.File]::Open($destinationPath, [System.IO.FileMode]::CreateNew)
    try {
        $archive = New-Object System.IO.Compression.ZipArchive(
            $stream,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $false
        )
        try {
            $files = Get-ChildItem -LiteralPath $Root -File -Recurse |
                ForEach-Object {
                    [pscustomobject]@{
                        File = $_
                        Relative = (Get-RelativePayloadPath -Root $Root -Path $_.FullName).Replace('\', '/')
                    }
                } |
                Sort-Object Relative
            foreach ($entryFile in $files) {
                $entry = $archive.CreateEntry(
                    $entryFile.Relative,
                    [System.IO.Compression.CompressionLevel]::NoCompression
                )
                $entry.LastWriteTime = [System.DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)
                $input = [System.IO.File]::OpenRead($entryFile.File.FullName)
                $output = $entry.Open()
                try {
                    $input.CopyTo($output)
                } finally {
                    $output.Dispose()
                    $input.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    return $destinationPath
}

function Write-ArtifactHash {
    param([Parameter(Mandatory)][string]$Path)
    Assert-PlainFile $Path | Out-Null
    $hashPath = "$Path.sha256"
    $line = "$((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash)  $([System.IO.Path]::GetFileName($Path))`n"
    Write-Utf8File -Path $hashPath -Content $line
    return $hashPath
}

function New-VisualAssets {
    param(
        [Parameter(Mandatory)][string]$SpecPath,
        [Parameter(Mandatory)][string]$OutputDirectory
    )
    Assert-PlainFile $SpecPath | Out-Null
    $spec = Get-Content -LiteralPath $SpecPath -Raw | ConvertFrom-Json
    if ($spec.schema -ne 1 -or
        $spec.background -notmatch '^#[0-9A-Fa-f]{6}$' -or
        $spec.foreground -notmatch '^#[0-9A-Fa-f]{6}$') {
        throw "Invalid visual asset source specification: $SpecPath"
    }
    Add-Type -AssemblyName System.Drawing
    [System.IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
    $assets = @(
        @{ Name = 'Square44x44Logo.png'; Size = 44 },
        @{ Name = 'StoreLogo.png'; Size = 50 },
        @{ Name = 'Square150x150Logo.png'; Size = 150 }
    )
    foreach ($asset in $assets) {
        $size = [int]$asset.Size
        $bitmap = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        try {
            $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
            $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::None
            $graphics.Clear([System.Drawing.ColorTranslator]::FromHtml([string]$spec.background))
            $brush = New-Object System.Drawing.SolidBrush(
                [System.Drawing.ColorTranslator]::FromHtml([string]$spec.foreground)
            )
            try {
                $inset = [int][Math]::Round($size * ([double]$spec.mark.outerInsetPercent / 100))
                $bar = [Math]::Max(2, [int][Math]::Round($size * ([double]$spec.mark.barWidthPercent / 100)))
                $gap = [Math]::Max(1, [int][Math]::Round($size * ([double]$spec.mark.gapPercent / 100)))
                $height = $size - (2 * $inset)
                $graphics.FillRectangle($brush, $inset, $inset, $bar, $height)
                $graphics.FillRectangle($brush, $inset, $inset, $height, $bar)
                $graphics.FillRectangle($brush, $inset, $size - $inset - $bar, $height, $bar)
                $rightX = $size - $inset - $bar
                $graphics.FillRectangle($brush, $rightX, $inset, $bar, [int][Math]::Floor(($height - $gap) / 2))
                $graphics.FillRectangle($brush, $rightX, $inset + [int][Math]::Ceiling(($height + $gap) / 2), $bar, [int][Math]::Floor(($height - $gap) / 2))
            } finally {
                $brush.Dispose()
            }
            $path = Join-Path $OutputDirectory $asset.Name
            $bitmap.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
        } finally {
            $graphics.Dispose()
            $bitmap.Dispose()
        }
    }
}

function New-AppxManifest {
    param(
        [Parameter(Mandatory)][string]$TemplatePath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$MsixVersion,
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
        [Parameter(Mandatory)][string]$Publisher
    )
    Assert-PlainFile $TemplatePath | Out-Null
    Convert-WindowsVersion (($MsixVersion -split '\.')[0..2] -join '.') | Out-Null
    if ($MsixVersion -notmatch '^\d+\.\d+\.\d+\.0$') {
        throw "Invalid MSIX version '$MsixVersion'."
    }
    $content = [System.IO.File]::ReadAllText($TemplatePath)
    if ($Publisher -notmatch '^CN=[^<>&"]+$') {
        throw "Invalid MSIX publisher distinguished name '$Publisher'."
    }
    $escapedPublisher = [System.Security.SecurityElement]::Escape($Publisher)
    $content = $content.
        Replace('{{MSIX_VERSION}}', $MsixVersion).
        Replace('{{MSIX_ARCHITECTURE}}', $Architecture).
        Replace('{{MSIX_PUBLISHER}}', $escapedPublisher)
    if ($content.Contains('{{')) {
        throw "Unresolved AppxManifest template token."
    }
    Write-Utf8File -Path $OutputPath -Content $content
}

function Test-AppxManifest {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
        [string]$ExpectedPublisher = 'CN=GTAStudio Windows Signing Placeholder'
    )
    Assert-PlainFile $Path | Out-Null
    [xml]$xml = Get-Content -LiteralPath $Path -Raw
    $manager = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $manager.AddNamespace('f', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $manager.AddNamespace('uap', 'http://schemas.microsoft.com/appx/manifest/uap/windows10')
    $identity = $xml.SelectSingleNode('/f:Package/f:Identity', $manager)
    if ($null -eq $identity -or
        $identity.Name -ne 'GTAStudio.GTAClaw' -or
        $identity.Publisher -ne $ExpectedPublisher -or
        $identity.Version -ne $Version -or
        $identity.ProcessorArchitecture -ne $Architecture) {
        throw "AppxManifest identity does not match the requested package."
    }
    $applications = @($xml.SelectNodes('/f:Package/f:Applications/f:Application', $manager))
    if ($applications.Count -ne 1 -or $applications[0].Executable -ne 'gta-claw-desktop.exe') {
        throw "AppxManifest executable mapping is invalid."
    }
    $capabilities = @($xml.SelectNodes('/f:Package/f:Capabilities/*', $manager))
    if ($capabilities.Count -ne 1 -or $capabilities[0].Name -ne 'runFullTrust') {
        throw "AppxManifest must declare only runFullTrust."
    }
    if (@($xml.SelectNodes('//*[local-name()="Extension"]')).Count -ne 0) {
        throw "AppxManifest unexpectedly declares an association or extension."
    }
}

function Test-MsixPackage {
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$MakeAppxPath,
        [Parameter(Mandatory)][string]$InspectionRoot,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
        [string]$ExpectedPublisher = 'CN=GTAStudio Windows Signing Placeholder',
        [ValidateSet('unsigned', 'signed')][string]$SignatureMode = 'unsigned',
        [Parameter(Mandatory)][ValidateSet('non-release', 'release-candidate')][string]$ReleaseStatus
    )
    Assert-PlainFile $PackagePath | Out-Null
    Remove-OwnedDirectory -OwnedRoot (Split-Path -Parent $InspectionRoot) -Path $InspectionRoot
    [System.IO.Directory]::CreateDirectory($InspectionRoot) | Out-Null
    Invoke-CheckedCommand -FilePath $MakeAppxPath -Arguments @(
        'unpack', '/p', $PackagePath, '/d', $InspectionRoot, '/o'
    )
    Test-AppxManifest `
        -Path (Join-Path $InspectionRoot 'AppxManifest.xml') `
        -Version $Version `
        -Architecture $Architecture `
        -ExpectedPublisher $ExpectedPublisher
    Test-HashManifest -Root $InspectionRoot -IgnoreAdditionalFiles @(
        'AppxBlockMap.xml', 'AppxSignature.p7x', '[Content_Types].xml', 'CodeIntegrity.cat'
    )
    Assert-PayloadSafety -Root $InspectionRoot -ExpectedExecutables @('gta-claw-desktop.exe') -AdditionalAllowedFiles @(
        'AppxBlockMap.xml', 'AppxSignature.p7x', '[Content_Types].xml', 'CodeIntegrity.cat'
    )
    $binary = Join-Path $InspectionRoot 'gta-claw-desktop.exe'
    $status = [System.IO.File]::ReadAllText((Join-Path $InspectionRoot 'RELEASE-STATUS.txt'))
    if ($ReleaseStatus -eq 'non-release' -and $status -notmatch 'UNSIGNED NON-RELEASE') {
        throw 'Unsigned MSIX lacks an explicit non-release marker.'
    }
    if ($ReleaseStatus -eq 'release-candidate' -and $status -notmatch 'RELEASE CANDIDATE') {
        throw 'Release MSIX lacks an explicit release-candidate marker.'
    }
    Assert-PeArchitecture -Path $binary -ExpectedMachine (Get-Architecture $Architecture).PeMachine
    Test-PeDependencies $binary
    Test-PackageSignature -Path $PackagePath -Mode $SignatureMode
}

function Test-PackageSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('unsigned', 'signed')][string]$Mode
    )
    Assert-PlainFile $Path | Out-Null
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($Mode -eq 'unsigned') {
        if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned) {
            throw "Artifact claims unsigned status but signature state is '$($signature.Status)': $Path"
        }
        return
    }
    $signTool = Find-WindowsSdkTool 'signtool.exe'
    Invoke-CheckedCommand -FilePath $signTool -Arguments @('verify', '/pa', '/all', $Path)
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Signed artifact failed Authenticode verification: $Path ($($signature.Status))."
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw "Signed artifact has no verified timestamp certificate: $Path"
    }
}

function Test-ZipPackage {
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$InspectionRoot,
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
        [Parameter(Mandatory)][ValidateSet('desktop', 'headless')][string]$ComponentSet,
        [Parameter(Mandatory)][ValidateSet('non-release', 'release')][string]$ReleaseStatus
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Assert-PlainFile $PackagePath | Out-Null
    Remove-OwnedDirectory -OwnedRoot (Split-Path -Parent $InspectionRoot) -Path $InspectionRoot
    [System.IO.Directory]::CreateDirectory($InspectionRoot) | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($PackagePath, $InspectionRoot)
    Assert-NoReparsePoints $InspectionRoot
    $expected = @('gta-claw-desktop.exe')
    if ($ComponentSet -eq 'headless') {
        $expected = @('gta-claw-cli.exe', 'gta-claw-daemon.exe')
    }
    Assert-PayloadSafety -Root $InspectionRoot -ExpectedExecutables $expected
    Test-HashManifest $InspectionRoot
    $status = [System.IO.File]::ReadAllText((Join-Path $InspectionRoot 'RELEASE-STATUS.txt'))
    if ($ReleaseStatus -eq 'non-release' -and $status -notmatch 'UNSIGNED NON-RELEASE') {
        throw 'Unsigned portable archive lacks an explicit non-release marker.'
    }
    if ($ReleaseStatus -eq 'release' -and $status -notmatch 'RELEASE PORTABLE ARTIFACT') {
        throw 'Release portable archive lacks its release status marker.'
    }
    $machine = (Get-Architecture $Architecture).PeMachine
    foreach ($name in $expected) {
        $binary = Join-Path $InspectionRoot $name
        Assert-PeArchitecture -Path $binary -ExpectedMachine $machine
        Test-PeDependencies $binary
        if ($ComponentSet -eq 'headless') {
            Assert-BinaryDoesNotContainAscii -Path $binary -Forbidden @(
                'slint', 'i-slint', 'node_modules', 'package.json', 'javascript'
            )
        }
    }
}

function Invoke-MsiQuery {
    param(
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][string]$Sql,
        [Parameter(Mandatory)][int]$Columns
    )
    $view = $Database.GetType().InvokeMember(
        'OpenView',
        [System.Reflection.BindingFlags]::InvokeMethod,
        $null,
        $Database,
        @($Sql)
    )
    $view.GetType().InvokeMember(
        'Execute',
        [System.Reflection.BindingFlags]::InvokeMethod,
        $null,
        $view,
        $null
    ) | Out-Null
    $rows = @()
    while ($true) {
        $record = $view.GetType().InvokeMember(
            'Fetch',
            [System.Reflection.BindingFlags]::InvokeMethod,
            $null,
            $view,
            $null
        )
        if ($null -eq $record) {
            break
        }
        $row = @()
        for ($column = 1; $column -le $Columns; $column++) {
            $row += $record.GetType().InvokeMember(
                "StringData",
                [System.Reflection.BindingFlags]::GetProperty,
                $null,
                $record,
                @($column)
            )
        }
        $rows += ,$row
    }
    $view.GetType().InvokeMember(
        'Close',
        [System.Reflection.BindingFlags]::InvokeMethod,
        $null,
        $view,
        $null
    ) | Out-Null
    return $rows
}

function Test-MsiPackage {
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$InspectionRoot,
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
        [Parameter(Mandatory)][ValidateSet('unsigned', 'signed')][string]$SignatureMode,
        [Parameter(Mandatory)][ValidateSet('non-release', 'release-candidate')][string]$ReleaseStatus
    )
    $package = Assert-PlainFile $PackagePath
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.GetType().InvokeMember(
        'OpenDatabase',
        [System.Reflection.BindingFlags]::InvokeMethod,
        $null,
        $installer,
        @($package, 0)
    )
    $features = @(Invoke-MsiQuery -Database $database -Sql 'SELECT `Feature` FROM `Feature`' -Columns 1 |
        ForEach-Object { $_[0] } |
        Sort-Object)
    foreach ($required in @('GTAClaw', 'Gui', 'Headless')) {
        if ($required -notin $features) {
            throw "Published MSI is missing feature '$required'."
        }
        $properties = @{}
        foreach ($row in @(Invoke-MsiQuery -Database $database -Sql 'SELECT `Property`, `Value` FROM `Property`' -Columns 2)) {
            $properties[$row[0]] = $row[1]
        }
        $version = Get-CanonicalVersion ([System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')))
        $arch = Get-Architecture $Architecture
        $productNamespace = [Guid]'DAD72B88-4094-5FD5-9494-D8C54C8DFE7D'
        $productGuid = New-UuidV5 -Namespace $productNamespace -Name "$($arch.Name):$($version.Msi)"
        $expectedProductCode = $productGuid.ToString('B').ToUpperInvariant()
        $packageNamespace = [Guid]'30E765FA-E804-5919-987E-C06725F6F25B'
        $packageGuid = New-UuidV5 -Namespace $packageNamespace -Name "$($arch.Name):$($version.Msi)"
        $expectedPackageCode = $packageGuid.ToString('B').ToUpperInvariant()
        if ($properties.ProductName -ne 'GTA Claw' -or
            $properties.Manufacturer -ne 'GTAStudio' -or
            $properties.ProductVersion -ne $version.Msi -or
            $properties.ProductCode.ToUpperInvariant() -ne $expectedProductCode -or
            $properties.UpgradeCode.ToUpperInvariant() -ne "{$($arch.UpgradeCode)}") {
            throw 'Published MSI product identity differs from the deterministic release identity.'
        }
        $summary = $database.GetType().InvokeMember(
            'SummaryInformation',
            [System.Reflection.BindingFlags]::GetProperty,
            $null,
            $database,
            $null
        )
        $template = $summary.GetType().InvokeMember(
            'Property',
            [System.Reflection.BindingFlags]::GetProperty,
            $null,
            $summary,
            @(7)
        )
        $packageCode = [string]$summary.GetType().InvokeMember(
            'Property',
            [System.Reflection.BindingFlags]::GetProperty,
            $null,
            $summary,
            @(9)
        )
        $expectedTemplate = "$(if ($Architecture -eq 'x64') { 'x64' } else { 'Arm64' });1033"
        if ($template -ne $expectedTemplate -or $packageCode.ToUpperInvariant() -ne $expectedPackageCode) {
            throw 'Published MSI package identity or platform metadata is invalid.'
        }
    }
    $tables = @(Invoke-MsiQuery -Database $database -Sql 'SELECT `Name` FROM `_Tables`' -Columns 1 |
        ForEach-Object { $_[0] })
    if ('CustomAction' -in $tables) {
        $customActions = @(Invoke-MsiQuery -Database $database -Sql 'SELECT `Action` FROM `CustomAction`' -Columns 1)
        if ($customActions.Count -ne 0) {
            throw "Published MSI contains forbidden custom actions: $($customActions -join ', ')"
        }
    }
    $files = @(Invoke-MsiQuery -Database $database -Sql 'SELECT `FileName` FROM `File`' -Columns 1 |
        ForEach-Object { (($_[0] -split '\|')[-1]).ToLowerInvariant() } |
        Sort-Object)
    $expectedFiles = @(
        'gta-claw-cli.exe', 'gta-claw-daemon.exe', 'gta-claw-desktop.exe',
        'license.txt', 'release-status.txt', 'sha256sums.txt'
    ) | Sort-Object
    if (($files -join "`n") -ne ($expectedFiles -join "`n")) {
        throw "Published MSI file table differs from the allowlist: $($files -join ', ')"
    }

    $logRoot = $env:TEMP
    if ([string]::IsNullOrWhiteSpace($logRoot)) {
        $logRoot = [System.IO.Path]::GetTempPath()
    }
    [System.IO.Directory]::CreateDirectory($logRoot) | Out-Null
    $safeRoot = Join-Path $logRoot ("gta-claw-msi-" + [Guid]::NewGuid().ToString('N'))
    $safePackage = Join-Path $safeRoot 'package.msi'
    $actualInspection = Join-Path $safeRoot 'payload'
    $log = Join-Path $safeRoot 'extract.log'
    [System.IO.Directory]::CreateDirectory($actualInspection) | Out-Null
    Copy-Item -LiteralPath $package -Destination $safePackage
    if ((Get-FileHash $safePackage -Algorithm SHA256).Hash -ne
        (Get-FileHash $package -Algorithm SHA256).Hash) {
        throw 'MSI trusted-path copy differs from the published bytes.'
    }
    try {
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList @(
        '/a', "`"$safePackage`"", '/qn', "TARGETDIR=`"$actualInspection`"", '/l*v', "`"$log`""
    ) -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "MSI administrative extraction failed with exit code $($process.ExitCode); see '$log'."
    }
    Assert-NoReparsePoints $actualInspection
    $installRoot = Join-Path $actualInspection 'PFiles64\GTAStudio\GTA Claw'
    if (-not (Test-Path -LiteralPath $installRoot -PathType Container)) {
        throw 'Published MSI does not install below the expected Program Files path.'
    }
    $payloadFiles = @(Get-ChildItem -LiteralPath $installRoot -File -Recurse)
    $allNonMsiFiles = @(Get-ChildItem -LiteralPath $actualInspection -File -Recurse |
        Where-Object { $_.Extension -ne '.msi' })
    if ($allNonMsiFiles.Count -ne $payloadFiles.Count) {
        throw 'Published MSI administrative extraction contains files outside its install root.'
    }
    $expectedPaths = @(
        'gta-claw-desktop.exe', 'headless\gta-claw-cli.exe', 'headless\gta-claw-daemon.exe',
        'LICENSE.txt', 'RELEASE-STATUS.txt', 'SHA256SUMS.txt'
    ) | Sort-Object
    $actualPaths = @($payloadFiles | ForEach-Object {
        Get-RelativePayloadPath -Root $installRoot -Path $_.FullName
    } | Sort-Object)
    if (($actualPaths -join "`n") -cne ($expectedPaths -join "`n")) {
        throw "Published MSI extraction differs from the path allowlist: $($actualPaths -join ', ')"
    }
    Test-HashManifest -Root $installRoot
    $status = [System.IO.File]::ReadAllText((Join-Path $installRoot 'RELEASE-STATUS.txt'))
    if ($ReleaseStatus -eq 'non-release' -and $status -notmatch 'UNSIGNED NON-RELEASE') {
        throw 'Unsigned MSI lacks an explicit non-release marker.'
    }
    if ($ReleaseStatus -eq 'release-candidate' -and $status -notmatch 'RELEASE CANDIDATE') {
        throw 'Release MSI lacks an explicit release-candidate marker.'
    }
    $machine = (Get-Architecture $Architecture).PeMachine
    foreach ($name in @('gta-claw-desktop.exe', 'gta-claw-cli.exe', 'gta-claw-daemon.exe')) {
        $binary = ($payloadFiles | Where-Object { $_.Name -ieq $name }).FullName
        Assert-PeArchitecture -Path $binary -ExpectedMachine $machine
        Test-PeDependencies $binary
        if ($name -ne 'gta-claw-desktop.exe') {
            Assert-BinaryDoesNotContainAscii -Path $binary -Forbidden @(
                'slint', 'i-slint', 'node_modules', 'package.json', 'javascript'
            )
        }
    }
    } finally {
        if (Test-Path -LiteralPath $safeRoot) {
            Remove-Item -LiteralPath $safeRoot -Recurse -Force
        }
    }
    Test-PackageSignature -Path $package -Mode $SignatureMode
}

function Test-MsixBundle {
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [Parameter(Mandatory)][string]$MakeAppxPath,
        [Parameter(Mandatory)][string]$InspectionRoot,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$ExpectedPublisher,
        [Parameter(Mandatory)][ValidateSet('unsigned', 'signed')][string]$SignatureMode,
        [ValidateSet('unsigned', 'signed')][string]$InnerSignatureMode = $SignatureMode,
        [Parameter(Mandatory)][ValidateSet('non-release', 'release-candidate')][string]$InnerReleaseStatus
    )
    Assert-PlainFile $PackagePath | Out-Null
    Remove-OwnedDirectory -OwnedRoot (Split-Path -Parent $InspectionRoot) -Path $InspectionRoot
    [System.IO.Directory]::CreateDirectory($InspectionRoot) | Out-Null
    Invoke-CheckedCommand -FilePath $MakeAppxPath -Arguments @(
        'unbundle', '/p', $PackagePath, '/d', $InspectionRoot, '/o'
    )
    $packages = @(Get-ChildItem -LiteralPath $InspectionRoot -File -Filter '*.msix' | Sort-Object Name)
    if ($packages.Count -ne 2) {
        throw "MSIXBundle must contain exactly x64 and arm64 packages; found $($packages.Count)."
    }
    $bundleManifest = Join-Path $InspectionRoot 'AppxMetadata\AppxBundleManifest.xml'
    Assert-PlainFile $bundleManifest | Out-Null
    [xml]$bundleXml = Get-Content -LiteralPath $bundleManifest -Raw
    $identity = $bundleXml.SelectSingleNode('/*[local-name()="Bundle"]/*[local-name()="Identity"]')
    $manifestPackages = @($bundleXml.SelectNodes(
        '/*[local-name()="Bundle"]/*[local-name()="Packages"]/*[local-name()="Package"]'
    ))
    if ($null -eq $identity -or
        $identity.Name -ne 'GTAStudio.GTAClaw' -or
        $identity.Publisher -ne $ExpectedPublisher -or
        $identity.Version -ne $Version -or
        $manifestPackages.Count -ne 2) {
        throw 'MSIXBundle outer identity is invalid.'
    }
    $manifestArchitectures = @($manifestPackages | ForEach-Object { $_.Architecture } | Sort-Object)
    if (($manifestArchitectures -join ',') -ne 'arm64,x64') {
        throw 'MSIXBundle outer manifest does not map exactly x64 and arm64.'
    }
    foreach ($manifestPackage in $manifestPackages) {
        if ($manifestPackage.Type -ne 'application' -or
            $manifestPackage.Version -ne $Version -or
            [System.IO.Path]::GetFileName($manifestPackage.FileName) -ne $manifestPackage.FileName -or
            @($packages | Where-Object { $_.Name -ceq $manifestPackage.FileName }).Count -ne 1) {
            throw 'MSIXBundle outer package mapping is invalid.'
        }
    }
    foreach ($architecture in @('x64', 'arm64')) {
        $candidate = @($packages | Where-Object { $_.Name -match "-$architecture-" -or $_.Name -match "-$architecture\." })
        if ($candidate.Count -ne 1) {
            throw "MSIXBundle contains no unique '$architecture' package."
        }
        $packageInspection = Join-Path $InspectionRoot "inspect-$architecture"
        Test-MsixPackage `
            -PackagePath $candidate[0].FullName `
            -MakeAppxPath $MakeAppxPath `
            -InspectionRoot $packageInspection `
            -Version $Version `
            -Architecture $architecture `
            -ExpectedPublisher $ExpectedPublisher `
            -SignatureMode $InnerSignatureMode `
            -ReleaseStatus $InnerReleaseStatus
        Remove-OwnedDirectory -OwnedRoot $InspectionRoot -Path $packageInspection
    }
    Test-PackageSignature -Path $PackagePath -Mode $SignatureMode
}

function Assert-HeadlessGraph {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)]
        [ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')]
        [string]$TargetTriple
    )
    $cargo = (Get-Command cargo -ErrorAction Stop).Source
    $tree = & $cargo tree `
        --manifest-path (Join-Path $RepoRoot 'Cargo.toml') `
        --target $TargetTriple `
        --locked `
        --offline `
        --prefix none `
        --format '{p}'
    if ($LASTEXITCODE -ne 0) {
        throw "cargo tree failed for the headless workspace target '$TargetTriple'."
    }
    $forbidden = @($tree | Where-Object {
        $_ -match '^(slint|slint-build|i-slint[-A-Za-z0-9]*)\s+v'
    })
    if ($forbidden.Count -ne 0) {
        throw "Headless Cargo graph for '$TargetTriple' contains Slint packages: $($forbidden -join ', ')"
    }
}

function New-UuidV5 {
    param(
        [Parameter(Mandatory)][Guid]$Namespace,
        [Parameter(Mandatory)][string]$Name
    )
    $namespaceBytes = $Namespace.ToByteArray()
    [Array]::Reverse($namespaceBytes, 0, 4)
    [Array]::Reverse($namespaceBytes, 4, 2)
    [Array]::Reverse($namespaceBytes, 6, 2)
    $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($Name)
    $input = New-Object byte[] ($namespaceBytes.Length + $nameBytes.Length)
    [Array]::Copy($namespaceBytes, 0, $input, 0, $namespaceBytes.Length)
    [Array]::Copy($nameBytes, 0, $input, $namespaceBytes.Length, $nameBytes.Length)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $hash = $sha1.ComputeHash($input)
    } finally {
        $sha1.Dispose()
    }
    $bytes = New-Object byte[] 16
    [Array]::Copy($hash, $bytes, 16)
    $bytes[6] = ($bytes[6] -band 0x0F) -bor 0x50
    $bytes[8] = ($bytes[8] -band 0x3F) -bor 0x80
    [Array]::Reverse($bytes, 0, 4)
    [Array]::Reverse($bytes, 4, 2)
    [Array]::Reverse($bytes, 6, 2)
    return New-Object Guid (,$bytes)
}

function Test-WixSource {
    param([Parameter(Mandatory)][string]$Path)
    Assert-PlainFile $Path | Out-Null
    [xml]$xml = Get-Content -LiteralPath $Path -Raw
    if ($xml.DocumentElement.NamespaceURI -ne 'http://wixtoolset.org/schemas/v4/wxs') {
        throw "WiX source does not use the v4 schema namespace."
    }
    $manager = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $manager.AddNamespace('w', 'http://wixtoolset.org/schemas/v4/wxs')
    $package = $xml.SelectSingleNode('/w:Wix/w:Package', $manager)
    if ($null -eq $package -or $package.Scope -ne 'perMachine') {
        throw "WiX package must be explicitly per-machine."
    }
    foreach ($feature in @('Gui', 'Headless')) {
        if ($null -eq $xml.SelectSingleNode("//w:Feature[@Id='$feature']", $manager)) {
            throw "WiX source is missing '$feature' selection."
        }
    }
    if ($null -ne $xml.SelectSingleNode('//w:CustomAction | //w:ServiceInstall | //w:ServiceControl', $manager)) {
        throw "WiX package must not contain custom actions or service registration."
    }
}

Export-ModuleMember -Function @(
    'Assert-ChildPath',
    'Assert-HeadlessGraph',
    'Assert-BinaryDoesNotContainAscii',
    'Assert-NoReparsePoints',
    'Assert-NoReparsePathComponents',
    'Assert-PayloadSafety',
    'Assert-PeArchitecture',
    'Assert-PlainFile',
    'Assert-RelativePackagePath',
    'Convert-WindowsVersion',
    'Copy-PlainFile',
    'Find-WindowsSdkTool',
    'Get-Architecture',
    'Get-CanonicalVersion',
    'Initialize-MsvcEnvironment',
    'Invoke-CheckedCommand',
    'New-AppxManifest',
    'New-DeterministicZip',
    'New-HashManifest',
    'New-UuidV5',
    'New-VisualAssets',
    'Remove-OwnedDirectory',
    'Set-NormalizedTreeTimestamp',
    'Set-NormalizedMsiStorageTimestamps',
    'Set-NormalizedZipTimestamps',
    'Test-AppxManifest',
    'Test-MsiPackage',
    'Test-HashManifest',
    'Test-MsixBundle',
    'Test-MsixPackage',
    'Test-PackageSignature',
    'Test-PeDependencies',
    'Test-WixSource',
    'Test-ZipPackage',
    'Write-ArtifactHash',
    'Write-Utf8File'
)
