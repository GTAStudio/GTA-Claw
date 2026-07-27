# GTA Claw iOS shell

This independent Cargo workspace adds a Slint 1.17.1 iPhone/iPad shell over the
existing `gta-claw-ios` core. A bounded Tokio controller owns one Gateway client,
drains its event queue, releases the core attempt guard on every completion path,
and sends deduplicated, redaction-safe snapshots to Slint's event loop.

The UI responds to compact and regular widths, keeps fields inside a
touch-pannable `ScrollView`, follows runtime safe-area and virtual-keyboard
insets, uses 44pt-or-larger controls, and labels every input and action for
assistive technologies.

## Verified Skia prebuilt inputs

Slint's iOS Winit backend necessarily resolves `skia-bindings` 0.99.0.
`scripts/fetch-skia.sh` accepts only the two arm64 archives selected by the
resolved `gl,jpeg,metal,pdf,textlayout` feature set. Their SHA-256 values come
from the official `rust-skia/skia-binaries` 0.99.0 GitHub release asset
metadata:

```sh
gh api repos/rust-skia/skia-binaries/releases/tags/0.99.0 \
  --jq '.assets[] | select(.name | test("aarch64-apple-ios.*gl-jpegd-jpege-metal-pdf-textlayout")) | [.name, .digest] | @tsv'
```

The script verifies the archive before exposing a `file://` URL through
`SKIA_BINARIES_URL`. The direct `skia-safe/no-compile` feature prevents a
fallback source build and its additional downloads.

## Build

Host checks do not require Xcode:

```sh
./ios/scripts/check.sh
```

Device and simulator checks require full Xcode:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
./ios/scripts/check-targets.sh
```

Install the pinned XcodeGen 2.46.0 release, then create an unsigned archive:

```sh
./ios/scripts/package.sh
```

CI uploads only the unsigned `.xcarchive`. Distribution signing, provisioning,
export, and App Store upload require an Apple Developer identity and remain
outside repository automation.

## Limits

- No Bonjour discovery, pairing, push notifications, background refresh,
  Keychain persistence, or Secure Enclave integration is implemented.
- iOS may suspend the Tokio workers in the background; this shell does not claim
  background connectivity. Reconnect after returning if the session is stale.
- `NSLocalNetworkUsageDescription` covers an explicitly entered local Gateway.
  No Bonjour service is declared because no discovery backend ships.
- A simulator build cannot validate local-network privacy, radio transitions,
  accessibility services, signing, or a real Gateway handshake. Those require a
  physical device and valid provisioning.
