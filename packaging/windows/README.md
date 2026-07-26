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
offline-capable reproducible build.

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
  directory checksum manifest must verify.

## Signing

`sign.ps1` accepts only `release-candidate-unsigned` MSIX, MSIXBundle, or MSI
packages. It requires a non-expired code-signing certificate with an accessible
private key, an HTTPS RFC3161 timestamp endpoint, and (for MSIX) an exact
publisher-subject match. It signs a copy, verifies Authenticode and the
timestamp, reopens the signed package bytes, and regenerates SBOM, provenance,
and checksums for the changed bytes. Missing credentials are fatal; unsigned
packages can never pass signed validation.

The workflow exercises unsigned x64 and arm64 packaging on every relevant
change. An explicit protected `windows-release` dispatch imports a temporary
certificate, signs x64 MSI plus both MSIX packages and the MSIXBundle, validates
the final publication directory, uploads it, and removes the certificate.
