# `ios/` — ARCHIVED, NOT SHIPPED

> **This workspace is not part of the product.** Mobile ships without a GUI for
> this release, and the ruling applies identically to iOS and Android. This
> branch is kept as an archive so the work can be revived rather than redone.
> It was never merged to `main`.
>
> **Do not treat a green build here as a shipping decision.** The decision was
> made explicitly, on four grounds: the product requirement names Windows and
> macOS as the GUI platforms and mobile was an addition; the trust-root pin
> table needed to admit Skia is empty and not editable from a feature branch;
> `ios/**` matches none of `rust.yml`'s path filters and the repository has no
> required status checks, so an `ios/`-only PR runs zero Rust validation and
> merges green; and CI can prove this compiles and links but cannot prove it
> runs, so a defect in behaviour would surface at release rather than in review.
>
> **The fourth ground is narrower than "CI cannot build it".** CI *did* build
> it — see the table below. What CI cannot do is launch it. And per Apple's
> TN3179 the simulator *"doesn't support local network privacy"*, so even a
> simulator job could never validate the discovery path. That ceiling is a
> property of the platform, not of this code.

## Exact state at archival

| | |
| --- | --- |
| Branch | `aizhihuxiao-ios-slint-shell` |
| Commits | `bde439a` (shell), `49e1fd2` (reachability boundary entry) |
| Base | `main` at `988c6d64b6ec61adbfb7f04d39b83155e025de6c` |
| Closed PR | #110 |
| Rust | 1.97.0 pinned, MSRV 1.94.0 |
| Slint | 1.17.1 (must equal `desktop/Cargo.lock`; the trust root cross-checks) |
| `skia-bindings` | 0.99.0 |
| Lock | 640 packages |
| Targets | `aarch64-apple-ios`, `aarch64-apple-ios-sim` |

### The two Skia pin rows, if this is ever revived

Obtained independently — `curl` from the published release URL into a clean
empty directory, SHA-256 computed there, **never** from a build output or
cache. Both targets share release tag `0.99.0`. Recorded here so the
acquisition does not have to be repeated.

| package | version | target | bytes | SHA-256 |
| --- | --- | --- | --- | --- |
| `skia-bindings` | `0.99.0` | `aarch64-apple-ios` | 15024772 | `15e20f3265dfddd658f9ef0d0e30d50a73afccb88787812f65fb5e6cf4ec55c8` |
| `skia-bindings` | `0.99.0` | `aarch64-apple-ios-sim` | 15063260 | `ade5b153818d9b7b81240f106df148a9c4b92fb3aba566f942a713b93914e11e` |

Reviving this also requires fixing `url.contains(target)` at `policy.rs:1435`:
`aarch64-apple-ios` is a proper prefix of `aarch64-apple-ios-sim`, so the
simulator archive satisfies the device row. Measured, not inferred — the table
accepted exactly that pairing.

---

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
