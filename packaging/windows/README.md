# Windows packaging prototype

This directory owns the P04b Windows-only packaging surface. It does not publish releases, install services, register protocols/file types, or modify the Rust/Slint application behavior.

## Proven deliverables

`package.ps1` builds both Cargo workspaces with `--locked` and creates architecture-specific, **unsigned/non-release** artifacts:

| Architecture | Rust target | PE machine | MSIX value | Executables |
| --- | --- | --- | --- | --- |
| x64 | `x86_64-pc-windows-msvc` | `0x8664` | `x64` | `gta-claw-desktop.exe`, `gta-claw-cli.exe`, `gta-claw-daemon.exe` |
| arm64 | `aarch64-pc-windows-msvc` | `0xAA64` | `arm64` | `gta-claw-desktop.exe`, `gta-claw-cli.exe`, `gta-claw-daemon.exe` |

Outputs under `packaging/windows/out/<architecture>/` are:

- `gta-claw-desktop-<version>-windows-<architecture>-portable-non-release.zip`: GUI only.
- `gta-claw-headless-<version>-windows-<architecture>-portable-non-release.zip`: CLI and daemon only; the root Cargo graph is checked to contain no Slint crates.
- `gta-claw-desktop-<version>-windows-<architecture>-unsigned.msix`: GUI-only full-trust MSIX, created and unpack-inspected with Windows SDK `MakeAppx.exe`.
- `layouts/msix/`: validated MSIX input layout.
- `layouts/msi/`: exact input layout for the deferred WiX v4 MSI gate.
- adjacent `.sha256` files for each archive/package.

Every layout contains `SHA256SUMS.txt` for every other payload file. ZIP entry names and timestamps are normalized; rerunning packaging over unchanged executables produces identical ZIP bytes. Cargo remains the single version source: `[workspace.package].version` in root `Cargo.toml`; the desktop workspace must match it. MSIX maps `major.minor.patch` to `major.minor.patch.0`; MSI uses `major.minor.patch`. Prerelease/build metadata is rejected because neither Windows package identity can preserve SemVer ordering without an additional release-version source. MSI limits are enforced (`major <= 255`, `minor/patch <= 65535`); MSIX fields are limited to `65535`.

```powershell
pwsh -NoProfile -File packaging\windows\package.ps1 -Architecture x64
pwsh -NoProfile -File packaging\windows\package.ps1 -Architecture arm64
pwsh -NoProfile -File packaging\windows\self-test.ps1
```

Pass `-SkipBuild` plus all three explicit executable paths to package an already-built target. `-SkipMsix` is only for portable/layout validation on hosts without the Windows SDK. Normal packaging fails when required executables, license, asset specification, or `MakeAppx.exe` are absent.

Build mode uses the installed Visual Studio `vswhere.exe` and `VsDevCmd.bat` to select the x64-hosted MSVC linker for the requested target. arm64 packaging fails clearly when the optional MSVC ARM64 component is absent; the workflow always compile-checks arm64 and creates arm64 package artifacts only when that official component is available.

## MSIX identity and capabilities

`AppxManifest.template.xml` uses stable prototype identity `GTAStudio.GTAClaw` and publisher placeholder `CN=GTAStudio Windows Signing Placeholder`. The publisher **must** be replaced with the final certificate subject or Partner Center identity before release signing. The only declared capability is restricted `runFullTrust`, required by Microsoft for a packaged classic desktop executable. There are no invented network/device capabilities, protocol handlers, file associations, startup tasks, aliases, or services. Visual PNGs are generated deterministically from the reviewed `assets/logo-spec.json`; generated files are never committed.

The minimum OS is Windows 10 2004 (`10.0.19041.0`) because the manifest uses `uap10:RuntimeBehavior="packagedClassicApp"` and `uap10:TrustLevel="mediumIL"`. Package integrity enforcement is enabled. Unsigned MSIX is validation-only and cannot be treated as deployable release media.

## WiX v4 MSI gate

`wix/GtaClaw.wxs` is a source prototype for one per-machine MSI with independently selectable `Gui` and `Headless` features (`ADDLOCAL=Gui`, `ADDLOCAL=Headless`, or both). It installs to `%ProgramFiles%\GTAStudio\GTA Claw`; headless tools install below `headless\`. Uninstall is MSI component-driven. No service registration or custom action exists because the current daemon is a foreground process, not a Windows service.

Component GUIDs are stable UUIDv5 values derived from a committed namespace, architecture, and component ID; this prevents x64/arm64 component collisions. ProductCode is likewise a stable UUIDv5 of architecture plus MSI version, while upgrade families are architecture-specific:

| Architecture | UpgradeCode |
| --- | --- |
| x64 | `{B14FD1CA-ED7E-59B7-81CF-5D0D9B6D7090}` |
| arm64 | `{589E56FD-45DD-5AB7-BB59-E02D949119A7}` |

`build-msi.ps1` derives a deterministic UUIDv5 ProductCode from architecture plus MSI version and runs official WiX v4 `wix build`. A release gate must install a pinned WiX v4 toolchain from an approved trusted source, run the compiler (the schema authority), install/upgrade/repair/uninstall the resulting MSI in disposable x64 and arm64 Windows environments, then sign and verify it. Current CI intentionally performs structural source validation and stages MSI inputs but does **not** claim an MSI build because WiX v4 is not preinstalled on GitHub-hosted Windows runners.

## Signing and publication gate

Signing is separate and fail-closed:

```powershell
pwsh -NoProfile -File packaging\windows\sign.ps1 `
  -PackagePath packaging\windows\out\x64\gta-claw-desktop-0.1.0-windows-x64-unsigned.msix `
  -CertificateThumbprint $env:GTA_CLAW_SIGNING_THUMBPRINT `
  -TimestampUrl https://<approved-rfc3161-service>
```

The script signs only attested MSIX outputs and accepts only a certificate already provisioned in the Windows certificate store (including hardware-backed providers). It never accepts/prints a private key or password, requires HTTPS RFC3161 timestamping, verifies the manifest publisher equals the certificate subject, invokes Windows SDK `SignTool`, verifies Authenticode and timestamp certificates, and re-inspects MSIX identity/contents. Azure Artifact Signing is also suitable but requires its official client/dlib integration and is deferred to the release environment. MSI signing remains blocked until the release gate validates MSI database tables, features, files, and absence of custom actions.

Microsoft Store reservation, Partner Center identity replacement, App Installer feed/publication, trusted signing credentials, final certificate/timestamp policy, MSI signing, clean-machine deployment tests, and Windows service installation are explicitly deferred. CI uploads ephemeral artifacts named `unsigned-non-release-*` only.

## Source references

- Microsoft Learn: [manual desktop MSIX components](https://learn.microsoft.com/windows/msix/desktop/desktop-to-uwp-manual-conversion), [MakeAppx](https://learn.microsoft.com/windows/msix/package/create-app-package-with-makeappx-tool), [SignTool package signing](https://learn.microsoft.com/windows/msix/package/sign-app-package-using-signtool), and [MSIX signing/timestamping](https://learn.microsoft.com/windows/msix/package/signing-package-overview).
- FireGiant WiX v4: [WiX toolset documentation](https://docs.firegiant.com/wix/) and official `wix build` compiler.
- Rust: [`*-pc-windows-msvc` platform support](https://doc.rust-lang.org/rustc/platform-support/windows-msvc.html). Both selected targets are Tier 1 with host tools.
- Slint 1.17.1: [deployment guidance](https://releases.slint.dev/1.17.1/docs/slint/guide/development/advanced/deploying/). The current feature set embeds Slint in the GUI executable; no Slint DLL is staged.
