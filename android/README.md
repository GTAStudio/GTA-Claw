# GTA Claw Android shell

This independent Cargo workspace adds the Slint 1.17.1 NativeActivity shell that
the headless root workspace cannot contain. It uses the existing
`gta-claw-android` controller, keeps all Gateway work on its bounded Tokio
runtime, and sends deduplicated snapshots back to Slint's event loop.

The UI responds to phone and tablet widths, keeps form fields inside a
touch-pannable `ScrollView`, respects Slint safe-area insets, uses 48px-or-larger
touch targets, and declares accessibility labels for every input and action.

## Local checks

```sh
./android/scripts/check.sh
rustup target add aarch64-linux-android x86_64-linux-android
ANDROID_NDK_HOME=/path/to/ndk ./android/scripts/check-targets.sh
```

Install the pinned stable cargo-apk release before packaging:

```sh
cargo install cargo-apk --version 0.10.0 --locked
./android/scripts/package.sh aarch64-linux-android
```

Upstream marks cargo-apk 0.10.0 deprecated in favor of xbuild, while Slint's
1.17.1 Android guide also records xbuild's stable 0.2.0 release as outdated and
recommends an unversioned Git install. This workspace deliberately chooses the
latest stable cargo-apk release rather than making a Git branch part of the
packaging trust path.

The resulting prototype APK uses cargo-apk's local signing behavior. It is not a
Play Store release artifact.

## Limits

- Minimum Android API is 26, as required by Slint's Android backend.
- Slint 1.17.1's Android backend requires Skia even when the software renderer
  feature is not selected. Device arm64 and emulator x86_64 use only
  digest-verified 0.99.0 release assets, with `no-compile` preventing fallback
  downloads. The release publishes no matching armv7 archive, so this shell
  does not claim armeabi-v7a support.
- The app has no discovery, pairing, background reconnect, push delivery, or
  Android Keystore persistence. Pausing the activity disconnects; reconnect is
  manual after resume.
- `usesCleartextTraffic` is enabled only because the existing core supports an
  explicit remote `ws://` opt-in. The UI warns before that transport can be used.
- CI can prove compilation and APK assembly. Radio changes, process death,
  accessibility services, keyboard behavior, and a real Gateway handshake still
  require an emulator or physical device.
