# Windows release packaging

This directory builds the native Rust GUI and headless deliverables for Windows
10/11 x64 and Windows 11 arm64. Product payloads contain no JavaScript, Node.js,
package-manager runtime, or Slint dependency in the headless Cargo graph.

## Outputs

`package.ps1` builds with both committed lockfiles, Cargo offline mode, static
MSVC CRT linkage, normalized source paths, and the Cargo workspace version as
the only version source. For each architecture it emits:

- deterministic desktop and headless portable ZIP archives;
- a full-trust desktop MSIX with identity `GTAStudio.GTAClaw`;
- a WiX v6 per-machine MSI with selectable `Gui` and `Headless` features;
- an SPDX 2.3 SBOM and SLSA/in-toto provenance statement for every artifact;
- complete `SHA256SUMS` manifests over every artifact and supply-chain
  companion (`SHA256SUMS-windows` in a GitHub Release).

Protected release portable ZIPs contain only individually Authenticode-signed,
timestamped executables plus their license, status, and internal checksum
manifest. The fixed release profile contains signed x64 and arm64 desktop and
headless ZIPs, the signed x64 MSI, signed x64 and arm64 MSIX packages, and the
signed x64+arm64 MSIXBundle, with a `.sha256`, SPDX, and provenance companion
for each.

`bundle.ps1` validates the x64 and arm64 MSIX bytes before creating an
x64+arm64 MSIXBundle. Unsigned outputs include `unsigned-non-release` in their
names and contain an explicit non-release marker. Release mode requires the
exact signing-certificate subject and produces only
`release-candidate-unsigned` packages until `sign.ps1` succeeds.

```powershell
$env:CARGO_TARGET_DIR = 'D:\cargo-target'
$env:GTA_CLAW_WIX = 'D:\tools\wix.exe'
.\packaging\windows\package.ps1 -Architecture x64
.\packaging\windows\package.ps1 -Architecture arm64
.\packaging\windows\bundle.ps1 `
  -X64Msix .\packaging\windows\out\x64\*-windows-x64-unsigned-non-release.msix `
  -Arm64Msix .\packaging\windows\out\arm64\*-windows-arm64-unsigned-non-release.msix
```

The package scripts perform no network access. Provision Rust targets, locked
Cargo sources, the Windows SDK, both MSVC architecture components, and the
pinned WiX CLI before invoking them. This separates online acquisition from an
offline-capable reproducible build. Packaging fails before Cargo starts unless
the active `rustc` and `cargo` both match the repository's exact Rust 1.97.1
pin. Completed output directories are replaced transactionally: a failed
package or bundle run removes its partial work and preserves the previous
validated output.

## Install, upgrade, repair, and remove

The MSI is per-machine and therefore requires elevation. Its default install
includes both features; unattended deployment can select either feature:

```powershell
msiexec /i .\gta-claw-<version>-windows-x64-signed.msi /qn
msiexec /i .\gta-claw-<version>-windows-x64-signed.msi /qn ADDLOCAL=GTAClaw,Gui
msiexec /i .\gta-claw-<version>-windows-x64-signed.msi /qn ADDLOCAL=GTAClaw,Headless
msiexec /fa .\gta-claw-<version>-windows-x64-signed.msi /qn
msiexec /x .\gta-claw-<version>-windows-x64-signed.msi /qn
```

A newer MSI of the same architecture performs a rollback-safe major upgrade,
migrates the selected features, and removes the older product. Downgrades are
rejected; rerunning the same-version package enters standard MSI maintenance
rather than a major upgrade. Modify, Repair, and Remove entries remain
available in Windows Apps settings, and no installed component is permanent.
x64 and arm64 use distinct upgrade identities and cannot replace one another.
MSIX install, update, rollback, and removal remain managed by Windows package
deployment.

## Published-byte validation

`validate-artifacts.ps1` opens the emitted bytes rather than trusting staging:

- ZIPs are extracted and checked against exact executable/file allowlists.
- MSIX packages are unpacked with `MakeAppx`, then their manifest, package
  identity, architecture, hashes, payload, PE imports, and signature state are
  checked.
- MSIXBundle packages are unbundled and both contained MSIX packages are
  revalidated.
- MSI tables are queried through Windows Installer, custom actions are
  forbidden, and an administrative extraction verifies the actual compressed
  payload.
- Headless executables are checked for architecture, system-DLL imports, and
  Slint/JavaScript markers. `cargo tree --offline` separately proves that the
  entire headless dependency graph contains no Slint crate.
- SBOM and provenance subjects must hash the exact published bytes, and the
  per-artifact and directory checksum manifests must verify.

## Signing

`sign.ps1` accepts only `release-candidate-unsigned` portable ZIP, MSIX,
MSIXBundle, or MSI inputs. It requires a non-expired code-signing certificate
with an accessible private key, an HTTPS RFC3161 timestamp endpoint, and (for
MSIX) an exact publisher-subject match. For ZIPs it validates and extracts the
reviewed archive, signs and timestamps every allowlisted executable, rebuilds
the internal checksum manifest and deterministic container, then reopens and
verifies every executable member. Missing credentials are fatal; unsigned
executables or packages can never pass signed validation.

The workflow exercises unsigned x64 and arm64 packaging on every relevant
change. An explicit protected `windows-release` dispatch builds and hashes all
production-identity candidates before importing a certificate. Certificate
windows execute signing only: package signing is followed by immediate identity
removal, bundle assembly runs without a private key, and a second short-lived
identity signs only the reviewed bundle. After both identities are removed, the
workflow generates and officially validates SPDX plus provenance for the final
signed bytes, validates the exact publication directory, and uploads it.
