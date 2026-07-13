# macOS packaging prototype

This directory is the isolated P04c prototype for packaging the native Rust/Slint desktop app and the two headless Rust executables. It targets macOS 14.0 or newer and uses only Cargo plus tools shipped with macOS/Xcode. It does not invoke or embed Node.js, npm, Bun, pnpm, or a JavaScript runtime.

## Outputs and guarantees

`build.sh` uses both committed Cargo lockfiles with `--locked`, sets `MACOSX_DEPLOYMENT_TARGET=14.0` for every slice, and supports native, `arm64`, `x86_64`, and `universal2` builds. Universal assembly compares each slice's dylibs, rpaths, and deployment metadata before `lipo`, then verifies the result contains exactly `arm64` and `x86_64`. A cross-built slice is a build validation only; runtime validation is claimed only by the matching native GitHub runner.

The app has the canonical `Contents/MacOS` and `Contents/Resources` layout. `Contents/Frameworks` is created only if a future explicitly declared non-system dependency requires it. With Slint 1.17.1's selected `backend-winit` and `renderer-femtovg` features, no non-system dylib is expected: `dependencies.allowlist` permits Apple system frameworks and `/usr/lib` only, and validation rejects undeclared dylibs, unsafe rpaths, symlinks, or absolute build paths.

The source icon is `icon/render.swift`; Xcode's Swift, `sips`, and `iconutil` reproducibly render the committed source into `GTAClaw.icns`. Generated icons, apps, archives, DMGs, PKGs, certificates, screenshots, and secrets stay under ignored `target/` paths and are never committed.

```sh
# Native app and separate CLI/daemon tar.gz archives
./packaging/macos/build.sh native

# Both slices plus a universal2 app
./packaging/macos/build.sh universal2

# Unsigned prototype DMG and PKG from the validated universal app
./packaging/macos/package.sh prototype \
  "target/macos-package/apps/universal2/GTA Claw.app"

# Built-in self-tests
./packaging/macos/self-test.sh
```

Each staging tree receives a sorted SHA-256 manifest, and each emitted artifact receives a checksum. Inputs, paths, permissions, archive timestamps, gzip headers, and tar ownership (`root:wheel`) are normalized. Apple container tools may encode tool-version-specific filesystem metadata, so the prototype proves deterministic staged content and records the exact final artifact checksum; it does not claim DMG/PKG byte identity across different Xcode or macOS versions.

## Signing and notarization contract

CI validation uses an ad-hoc signature with the source-controlled empty entitlement set. Release mode is fail-closed:

1. `sign.sh release APP` requires a valid `Developer ID Application` identity already available in the selected temporary keychain, signs nested code inside-out, applies hardened runtime and a secure timestamp, and verifies the designated requirement, signature, and entitlements.
2. `notarize.sh` requires either a `notarytool` keychain profile or App Store Connect API credentials, submits with `--wait`, requires exact `Accepted` status, staples the app/DMG/PKG, and validates the ticket.
3. `package.sh release APP` requires both a Developer ID Application and a distinct `Developer ID Installer` identity. It signs the UDZO DMG and uses `pkgbuild` plus `productbuild` for a flat PKG with no installer scripts.
4. The workflow's protected `macos-release` environment imports certificates and stores notarization credentials only in an ephemeral keychain. One trap removes the keychain, profiles, API key, and certificate files on success, failure, or cancellation. The prototype release job validates artifacts but intentionally does not publish or upload release artifacts.

No `--deep` signing shortcut is used. Frameworks and dylibs, when present and declared, are signed before the outer app. Missing identity, timestamp, hardened runtime, matching entitlement, accepted notarization, staple, or validation is fatal.

## Prototype boundaries

Real Developer ID certificates, App Store Connect credentials, release publication, custom DMG appearance, and clean-machine installation testing are deployment work. The current daemon does not implement a complete macOS service lifecycle, so this prototype deliberately adds no launchd plist, privileged helper, installer script, or automatic service registration. Headless tar archives are native command-line artifacts, not notarized release deliverables. App Store sandboxing and Mac App Store submission are also out of scope.

The implementation follows Apple's current guidance for [bundle structure](https://developer.apple.com/library/archive/documentation/CoreFoundation/Conceptual/CFBundles/BundleArchitectures/BundleArchitectures.html), [universal binaries](https://developer.apple.com/documentation/apple-silicon/building-a-universal-macos-binary), [distribution signing](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac), [packaging](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution), [hardened runtime and notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution), and `notarytool` migration in [TN3147](https://developer.apple.com/documentation/technotes/tn3147-migrating-to-the-latest-notarization-tool). Slint 1.17.1 provides the Rust build integration and native winit/femtovg backend used here, but no complete Apple signing/notarization pipeline; this repository therefore owns and validates that distribution layer explicitly.
