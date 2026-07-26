# `ios/` — the Slint iOS shell workspace

This is an **excluded** Cargo workspace, like `desktop/`. It is not a member of
the repository root workspace and is not built by `cargo build --workspace` at
the root. The reason is in `ios/Cargo.toml` next to the code that depends on it,
because the person who breaks this will be reading the manifest, not this file.

```
ios/Cargo.toml                          excluded workspace root
ios/apps/gta-claw-ios-shell/            the Slint binary
ios/Cargo.lock                          640 packages
```

The UI-independent client core lives at `apps/gta-claw-ios/` and *is* a root
workspace member, so its tests run on Linux and Windows CI hosts that can never
build for iOS. The shell here depends on it by path.

## Building

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo build --manifest-path ios/Cargo.toml --locked \
  --target aarch64-apple-ios --bin gta-claw-ios-shell
```

Producing a runnable `.app` needs Xcode: this binary is the payload that an
Xcode run script copies in, alongside `lipo`, `dsymutil` and `codesign`. That
project is **not** in this repository.

## What has actually been proven, and by whom

Everything below is a statement about a specific machine, not about the product.

| Claim | Status |
| --- | --- |
| Compiles for the host target | **Verified**, Windows x86_64, rustc 1.97.0 |
| `clippy -D warnings`, `fmt --check` clean | **Verified**, Windows x86_64 and macOS arm64 |
| Compiles for `aarch64-apple-ios` | **Verified in CI**, macos-15-arm64, Xcode 16.4 |
| Compiles for `aarch64-apple-ios-sim` | **Verified in CI**, macos-15-arm64, Xcode 16.4 |
| Links with the Apple linker | **Verified in CI** — `Mach-O 64-bit executable arm64` |
| Runs on a simulator | **Never done** |
| Runs on a device | **Never done** |
| Completes a Gateway v4 handshake from iOS | **Never done** |

The first five rows became true when `.github/workflows/ios-packaging.yml` first ran:
both `cargo build --target aarch64-apple-ios` and `--target aarch64-apple-ios-sim`
succeeded, and `file` reported `Mach-O 64-bit executable arm64` for each. That
exercised `skia-bindings`, the five `objc2` crates and the real Apple linker.

**A green build is still not a working app.** Nothing above launches the binary.
The bottom three rows are the ones that would tell you it works, and they remain
untested.

A host-target `cargo check` is **not** an iOS build proof. It runs no Apple
toolchain, no `xcrun`, no SDK, no target `clang` and no linker, so nothing that
compiles C, assembly or Objective-C is exercised by it — which on this
dependency graph means `skia-bindings` and the five `objc2` crates.

## Known limitations

* **Slint 1.17.1 has no iOS backend feature.** Android has two first-class ones
  (`backend-android-activity-05` and `-06`) and a dedicated backend crate; iOS
  has neither and no occurrence of the string `ios` in the `slint` crate's
  index entry. iOS goes through `backend-winit` plus `renderer-skia`, where
  `i-slint-backend-winit` carries five non-optional `cfg(target_os = "ios")`
  dependencies (`block2`, `objc2`, `objc2-foundation`, `objc2-quartz-core`,
  `objc2-ui-kit`). iOS support is real, but it is materially less mature than
  Android's in the pinned version.
* **Safe-area, virtual-keyboard and lifecycle behaviour are unverified.** These
  were asserted in the original brief. Nothing here has measured them, and they
  must not be repeated as facts on the strength of this crate.
* **Skia is unavoidable on iOS.** Slint offers no femtovg or software renderer
  fallback there, so a `skia-bindings` failure is a total failure of the
  platform rather than a degraded mode.
* **The workspace cannot pass the trusted policy validator yet.** It fails at
  exactly one check, `require_build_artifact_pins`, because
  `PINNED_BUILD_ARTIFACTS` in `.github/trusted/**` is empty. That table is
  byte-frozen and cannot be edited from this branch.

## Lints

`unsafe_code` is `deny`, not `forbid`, matching `desktop/`. `forbid` cannot be
relaxed by an inner `allow`, and Slint's generated item-tree macros locally
allow their own unsafe. No `unsafe` is written in this workspace's own source;
all UIKit interop lives inside Slint.

## Dependencies are declared unconditionally, on purpose

`desktop/` scopes its GUI dependencies under a `cfg(...)` target table. This
workspace deliberately does not. Scoping them to `target_os = "ios"` would mean
the shell's own source is compiled on no machine anyone can currently reach, so
a type error would first surface on an iOS build that nobody can run. Declaring
them unconditionally lets the whole shell compile on Windows, Linux and macOS.

There is a second reason for `slint-build`: Cargo evaluates
`[target.'cfg(...)'.build-dependencies]` against the **target**, not the host,
so a `cfg(target_os = "ios")` build dependency would disappear exactly when
cross-compiling from macOS to iOS.
