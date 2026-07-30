# macOS release packaging

This directory builds GTA Claw for macOS 14 or newer using Cargo and
Apple/Xcode tooling only. It produces a native Slint application and separate
headless Rust archives without JavaScript, Node.js, or Slint in the headless
dependency graph. Packaging requires the repository-pinned Rust 1.97.1
toolchain and fails before fetching or building when another toolchain is
active.

## Architecture and artifact matrix

The workflow ships arm64 binaries built on `macos-15`. Its Intel macOS row is
retained as host-native workspace test coverage, not as a release producer.
Release outputs are:

- an arm64 `GTA Claw.app` preserved in an `.app.zip`;
- a Developer ID signed and Apple-notarized DMG;
- a Developer ID Installer signed and Apple-notarized PKG;
- arm64 CLI and daemon archives;
- an SPDX 2.3 SBOM and SLSA/in-toto provenance statement for every artifact;
- one complete `SHA256SUMS` manifest over the exact publication bytes.

Each CLI and daemon archive also carries its individual `.sha256` checksum.
The protected release handoff binds those archives and their checksum, SPDX,
and provenance companions before any signing secret is available.

The GUI app has bundle identifier `com.gtastudio.gta-claw`, minimum system
version 14.0, a source-generated icon, the committed empty entitlement set, and
the hardened runtime.

```sh
rustup target add aarch64-apple-darwin
cargo fetch --manifest-path Cargo.toml --locked
cargo fetch --manifest-path desktop/Cargo.toml --locked

GTA_CLAW_OFFLINE=1 ./packaging/macos/build.sh native
./packaging/macos/package.sh prototype \
  "target/macos-package/apps/arm64/GTA Claw.app"
```

`package.sh` and `validate-artifacts.sh` share one fail-closed distribution
profile. Omitting their optional archive-label and expected-architecture
arguments selects `arm64`; any retired universal2 or Intel distribution profile
is rejected.

`GTA_CLAW_OFFLINE=1` requires all Rust targets and locked dependencies to be
present and then forbids Cargo network access. Run the locked `cargo fetch`
commands above before invoking `build.sh` offline on a clean machine. Without
offline mode, `build.sh` acquires both complete locked workspaces before its
offline graph proof. Paths, tar ownership, gzip headers, source paths, and
staged timestamps are normalized. Signed timestamps, notarization tickets, DMG
filesystem metadata, and PKG metadata are issued by Apple tools and are
therefore checksum-recorded rather than falsely claimed to be byte-identical
across signing times or Xcode versions.

## Published-byte validation

`validate-artifacts.sh` validates emitted files rather than staging:

- CLI archives are path-checked, extracted, hash-verified, architecture-checked,
  dependency-allowlisted, and scanned for Slint and JavaScript markers.
- App ZIPs are link/path-checked and extracted before full bundle validation.
- DMGs are verified, mounted read-only, checked against the root allowlist, and
  their embedded app is revalidated.
- PKGs are expanded in full, installer scripts are forbidden, payload paths are
  inspected, and the embedded app is revalidated.
- Release mode requires Developer ID authority, secure timestamps, hardened
  runtime, Installer identity, accepted notarization staples, and Gatekeeper
  assessment. Prototype mode rejects claims of release signatures.
- Every SBOM and provenance statement must hash its exact artifact, and
  `SHA256SUMS` must verify the complete publication directory.

## Signing and notarization

`sign.sh release` requires a real `Developer ID Application` identity and signs
nested code before the app with hardened runtime and a secure timestamp.
`notarize.sh` accepts only an explicit keychain profile or complete App Store
Connect API credentials, waits for exact `Accepted` status, staples, and
validates the ticket. `package.sh release` requires both Application and
Installer identities, signs and notarizes the DMG and PKG, creates the app ZIP,
generates supply-chain companions, and runs published-byte validation.

Missing credentials fail the protected release. Normal pull requests still
produce clearly labeled unsigned/ad-hoc prototype artifacts and never claim a
signature or notarization result.

## Install, upgrade, and remove

Drag `GTA Claw.app` from the DMG to `/Applications`, or install the PKG with
Installer. The PKG is non-relocatable and uses macOS Installer's `upgrade`
bundle action: a first install creates `/Applications/GTA Claw.app`, while a
reinstall, upgrade, or downgrade atomically replaces the existing bundle and
removes stale files from the old bundle. It does not install scripts or modify
shell profiles.

There is no uninstaller and removing the app does not remove user-created
data. To remove only the installed application and forget its Installer
receipt:

```sh
sudo rm -rf "/Applications/GTA Claw.app"
sudo pkgutil --forget com.gtastudio.gta-claw.pkg.component
```

Packaging is transactional: artifacts are fully assembled and validated under
`target/macos-package/staging` before the validated distribution directory
replaces the previous one. A failed package or validation run leaves the last
validated `target/macos-package/distribution` intact. The desktop Cargo package
inventory is resolved once per packaging transaction and reused for each
artifact's deterministic SBOM. Renaming the validated directory into place is
the publication commit point. If deleting the previous directory then fails,
packaging succeeds with an explicit warning and may retain
`distribution.rollback`; the next publication removes any stale backup before
replacing the committed distribution.
