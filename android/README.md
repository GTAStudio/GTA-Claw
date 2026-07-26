# ARCHIVE — not shipped, not on `main`, not built by CI

**This branch preserves work that is deliberately not part of the product.** It
exists on `android-slint-ui-archive` only. Do not merge it, do not open a pull
request from it, and do not treat anything below as a validated capability.

**The decision it records.** Mobile ships **without a GUI** for this release.
That was decided explicitly rather than discovered at release: the product
requirement names Windows and macOS as the GUI platforms, nothing in this
repository can validate a mobile GUI, and a tree that no CI job builds would
merge green while being unvalidated by construction. The shipped Android client
is the UI-independent core at `apps/gta-claw-android` on `main`.

## Provenance, and why this branch exists at all

This tree was recovered from commit `871a983b87e04acaabfc708bacddee6c87dae320`
("Add the Slint Android client crate", 2026-07-25), which was **reachable from
no branch, tag or remote ref**. It survived only as a dangling object in one
worktree's object store and would have been destroyed by the next `git gc`.
Every file was verified byte-identical to that commit with `git hash-object`
before being committed here.

The eight files that had been kept outside the repository as a hand-copied
archive were also byte-identical to it — and that archive was **missing
`src/lib.rs`**, the file containing the `android_main` entry point. The
out-of-tree copy was therefore not restorable; this branch is.

## What was changed during recovery

Relocated from `apps/gta-claw-android/` to top-level `android/`, mirroring
`desktop/`. That path is occupied on `main` by the shipped no-GUI crate, and it
is the location this UI is intended to occupy if the trust root ever admits it.
The five path dependencies were rewritten from `../../crates/` to `../crates/`
to match the new depth. **Nothing else was modified.**

## Toolchain this was built against

| Component | Version |
| --- | --- |
| Rust | 1.97.0 pinned (`rust-toolchain.toml`), MSRV 1.94.0 |
| Slint | 1.17.1 |
| Android NDK | 30.0.14904198, API level 24 |
| Host | Windows 11 x86_64 |

## What was verified here, and what it does not prove

On 2026-07-26, at the relocated path and against the **current** `crates/claw-*`
on `main` at `988c6d64b6ec`:

```
cargo check --locked --target aarch64-linux-android   # exit 0
cargo check --locked --target x86_64-linux-android    # exit 0
```

So the archive still resolves and type-checks against today's core crates — it
is not a snapshot that has already rotted. **That is the whole of the claim.**
It is a type-check: it does not link a `.so`, does not build or sign an APK, and
proves nothing about whether the application starts, whether the Slint event
loop runs, whether safe-area or IME handling behave, or how any of it survives
Android's process lifecycle. **Nothing in this tree has ever been executed on an
Android device or emulator.** No such device exists on the machine that produced
these results, and no CI job builds this branch — every workflow's `push:`
trigger is restricted to `branches: [main]`, which was verified rather than
assumed.

## ⚠ Three source files here are STALE — do not resurrect them blindly

`src/onboarding.rs`, `src/session.rs` and `src/controller.rs` are a 2026-07-25
snapshot of the client core. **The maintained versions are on `main` at
`apps/gta-claw-android/` and have since gained fixes this copy does not have:**

- **PR #71** (merged `333d58941d17356f609224bc413ce7bb9f45bf12`) — exhaustive
  mapping of all 29 `ConnectErrorDetailCode` variants to remedies that can
  actually work. The copy in this archive still collapses them into a single
  "check the token" message, which is a fabricated remedy for Tailscale,
  pairing and rate-limit failures.
- **PR #76** (merged `662adbb300c8a366dc1e796932c11479dac4a54e`) — binds the
  requested scope set to the frozen `claw-clients` contract via
  `validate_gateway_profile`, so the client cannot silently widen its privileges.

**Only the UI layer here is irreplaceable**: `ui/*.slint`, `build.rs`,
`src/ui_adapter.rs`, the `android_main` entry point in `src/lib.rs`, and the
Slint dependency wiring in `Cargo.toml`. If this UI is ever revived, port those
onto the current core rather than restoring this tree wholesale.

## Why it is not on `main`

Measured against the trust root by running its own validator, not by reading it.
`validate_root_workspace` requires `workspace.exclude` to byte-equal
`["desktop"]`; `ALLOWED_LOCKS` is exactly three paths and does not admit an
Android `Cargo.lock`; the manifest inventory is a closed set; and
`is_forbidden_gui` bans `slint`, `slint-build` and any `i-slint*` prefix across
`[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, **every**
`[target.'cfg(...)'.*]` table, the `package = "..."` rename field, and every
package name in the root `Cargo.lock`. A root member also inherits
`unsafe_code = "forbid"` exactly, under which the `android_main` entry point is
unrepresentable. **There is no placement for a Slint crate in this repository
today except `desktop/`, which is itself byte-frozen.**

Admitting `slint` to a root member would also add 560 packages and 26 duplicated
crates to the **root** lock, forcing roughly 17 skips into a byte-frozen
`deny.toml` whose holes would then stop protecting the daemon as well.

---

*Everything below is the crate's original README as written on 2026-07-25, kept
for the historical record. One statement in it has been corrected in place,
because leaving a false claim about the build is the defect this project spent a
week removing.*

---

# gta-claw-android

The native Android client for GTA Claw: a Slint UI over the shared
`claw-gateway-client` transport, packaged as a `cdylib` that `android-activity`
loads through `NativeActivity`.

## Why this is its own workspace

**Corrected 2026-07-26:** this crate declares its own `[workspace]`, but it is
**not** listed in the repository root's `exclude` and never was — that was the
plan at the time of writing, and the trusted validator refuses it. Root
`Cargo.toml` on `main` byte-equals `exclude = ["desktop"]`. The crate is
invisible to the root workspace here only because root `members` is an explicit
list that does not name it.

Slint's Android backend brings Skia, the
`android-activity` glue and a font stack whose transitive graph contains 17
crates at more than one version. The root `deny.toml` sets
`multiple-versions = "deny"` and is byte-frozen by the base-owned security
policy, so an Android member crate in the root workspace could not be made to
pass without editing a file this session must not touch. Isolating the graph
keeps the root policy intact and gives Android its own auditable
[`deny.toml`](deny.toml).

## Layout

| Path | Compiled for | Contents |
| --- | --- | --- |
| `src/onboarding.rs` | all targets | Input policy, redaction, connection state machine, snapshot rendering |
| `src/session.rs` | all targets | Attempt ownership (RAII), `GatewayClientConfig` construction |
| `src/controller.rs` | all targets | Tokio runtime owning one `GatewayClient`; composition against `claw-application` |
| `src/ui_adapter.rs` | `target_os = "android"` | Slint event loop and property marshalling |
| `src/lib.rs` | all targets | Module wiring; `android_main` on Android only |
| `ui/` | `target_os = "android"` | Slint markup, compiled by `build.rs` |

Only `ui_adapter.rs` and the `.slint` files are Android-only. Everything that
decides anything compiles and is unit-tested on the development host, so the
behaviour that matters does not need a device in the loop.

## `unsafe_code` is `deny`, not `forbid`

The workspace root sets `unsafe_code = "forbid"`. This crate sets `deny`, for
one declaration:

```rust
#[expect(unsafe_code, reason = "android-activity resolves the unmangled `android_main` symbol by name")]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) { ... }
```

`android-activity` resolves `android_main` by name at load time, so the symbol
cannot be mangled, and `#[unsafe(no_mangle)]` trips the `unsafe_code` lint —
verified by removing the attribute and observing
`error: usage of an `unsafe` attribute ... requested on the command line with
-D unsafe-code`. `forbid` cannot be locally overridden, so the entry point is
unrepresentable under it. The function body performs no unsafe operation and
there is no other `unsafe` in the crate. `desktop/Cargo.toml` makes the same
`deny` choice for the same reason. `expect` rather than `allow`: if a future
Slint release stops requiring the unmangled symbol, the unfulfilled expectation
becomes a warning and `-D warnings` withdraws the exemption automatically.

## Building

Requires the Android NDK. Set the compiler, archiver and linker for the target
you want; the values below are for NDK r30 on a Windows host.

```powershell
$bin = "$env:LOCALAPPDATA\Android\Sdk\ndk\<version>\toolchains\llvm\prebuilt\windows-x86_64\bin"
$env:ANDROID_NDK_ROOT = Split-Path (Split-Path (Split-Path $bin))
$env:CC_aarch64_linux_android  = "$bin\aarch64-linux-android24-clang.cmd"
$env:CXX_aarch64_linux_android = "$bin\aarch64-linux-android24-clang++.cmd"
$env:AR_aarch64_linux_android  = "$bin\llvm-ar.exe"
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "$bin\aarch64-linux-android24-clang.cmd"

cargo build --target aarch64-linux-android --lib
```

The result is `target/aarch64-linux-android/debug/libgta_claw_android.so`,
exporting both `android_main` and `ANativeActivity_onCreate`.

### ABI support

| ABI | Status |
| --- | --- |
| `aarch64-linux-android` | Builds and links. |
| `x86_64-linux-android` | Builds and links (emulator). |
| `armv7-linux-androideabi` | **Does not build from a clean cache.** |

32-bit ARM fails in `skia-bindings`, not in this crate:
`rust-skia/skia-binaries` release `0.99.0` publishes prebuilt archives for
`aarch64-linux-android`, `i686-linux-android` and `x86_64-linux-android` only.
With no armv7 asset the build script falls back to compiling Skia from source,
which needs `python3`, `ninja` and the `ANDROID_NDK` variable, and takes on the
order of an hour. Supporting armv7 means either accepting a from-source Skia
build or waiting for an upstream armv7 binary release; it is not a change to
this crate.

## Packaging

There is no APK build here, and no CI job builds this crate. The repository's
workflow allowlist is an exact eight-file set that admits no Android workflow,
and adding one is out of scope for this crate by instruction. `cargo apk` would
be the natural next step:

```
cargo install cargo-apk
cargo apk run --target aarch64-linux-android --lib
```

That has not been exercised, and no APK has been built, signed or installed on
a device or emulator.

## Credentials

Nothing is persisted. The endpoint and token live in the Slint text fields and
in one `ConnectRequest`; the token is moved into the transport's credential
type and dropped when the attempt ends. There is no keystore integration, no
biometric gate and no file on disk. `onboarding::CREDENTIAL_NOTICE` says this in
the UI so the absence is stated rather than assumed, and
`AppWindow::clear-token-input()` is documented as clearing the *field*, not the
IME's own preedit buffer — which only the platform can drop.

Every type that can carry the endpoint or the token has a hand-written `Debug`
that redacts both, including the URL path (a path can carry a token as easily as
a query string can). Tests assert the redaction rather than trusting it.

## Testing

```powershell
cargo test --all-targets            # host
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny --locked --target aarch64-linux-android --config deny.toml check
```

34 host unit tests cover input policy, redaction, the state machine's
generation guard, attempt-slot release on future drop, and the plaintext opt-in
reaching the transport configuration.
