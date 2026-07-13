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
    $installationPath = (& $vswhere -latest -products '*' -requires $component -property installationPath |
        Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installationPath)) {
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
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture
    )
    Assert-PlainFile $TemplatePath | Out-Null
    Convert-WindowsVersion (($MsixVersion -split '\.')[0..2] -join '.') | Out-Null
    if ($MsixVersion -notmatch '^\d+\.\d+\.\d+\.0$') {
        throw "Invalid MSIX version '$MsixVersion'."
    }
    $content = [System.IO.File]::ReadAllText($TemplatePath)
    $content = $content.Replace('{{MSIX_VERSION}}', $MsixVersion).Replace('{{MSIX_ARCHITECTURE}}', $Architecture)
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
        [string]$ExpectedPublisher = 'CN=GTAStudio Windows Signing Placeholder'
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
}

function Assert-HeadlessGraph {
    param([Parameter(Mandatory)][string]$RepoRoot)
    $cargo = (Get-Command cargo -ErrorAction Stop).Source
    $json = & $cargo metadata --manifest-path (Join-Path $RepoRoot 'Cargo.toml') --locked --format-version 1
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed for the headless workspace."
    }
    $metadata = $json | ConvertFrom-Json
    $forbidden = @($metadata.packages | Where-Object {
        $_.name -eq 'slint' -or $_.name -eq 'slint-build' -or $_.name.StartsWith('i-slint')
    })
    if ($forbidden.Count -ne 0) {
        throw "Headless Cargo graph contains Slint packages: $($forbidden.name -join ', ')"
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
        throw "WiX prototype must not contain custom actions or service registration."
    }
}

Export-ModuleMember -Function @(
    'Assert-ChildPath',
    'Assert-HeadlessGraph',
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
    'Test-AppxManifest',
    'Test-HashManifest',
    'Test-MsixPackage',
    'Test-WixSource',
    'Write-ArtifactHash',
    'Write-Utf8File'
)
