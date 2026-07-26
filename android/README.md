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
is the location this UI is intended to occupy. The trust root has since
admitted `android/` as a workspace path, though not in this tree's shape —
see "Correction: a placement now exists" below.
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
unrepresentable.

Admitting `slint` to a root member would also add 560 packages and 26 duplicated
crates to the **root** lock, forcing roughly 17 skips into a byte-frozen
`deny.toml` whose holes would then stop protecting the daemon as well.

### Correction: a placement now exists, and this tree does not fit it

An earlier revision of this file ended the section above with "there is no
placement for a Slint crate in this repository today except `desktop/`".
**That was true when written and is now false.** PR #72 landed on `main`
at `988c6d64b6ec` and admits two top-level sibling workspaces, `android/`
and `ios/`, alongside `desktop/`. The claim is corrected here rather than
deleted, because a reader who finds this branch needs to know the barrier
moved.

The placement is bounded, not a prefix rule, and **this tree does not
satisfy it.** The list below was produced by building the trust root's own
validator from `main` and running it against this branch, taking each
rejection in turn — not by reading the policy source:

1. `REJECTED: unexpected deny/audit policy file: android/deny.toml`
   A mobile `deny.toml` is rejected outright. Nothing executes it, because
   `android-packaging.yml` is an admitted path that does not exist, and the
   trust root's stated reasoning is that a policy file nothing runs is worse
   than none because it reads as protection. The `deny.toml` in this archive
   is therefore a file that must be **deleted, not ported**, and it should
   return only in the same change that lands the workflow running it.
2. `REJECTED: android workspace is incomplete: present ["android/Cargo.toml",
   "android/Cargo.lock"], missing ["android/apps/gta-claw-android-shell/Cargo.toml"]`
   A platform is a complete unit. This crate sits directly at `android/`;
   the admitted shape puts the sole app member at
   `android/apps/gta-claw-android-shell/`, and the package must be named
   `gta-claw-android-shell` — deliberately distinct from the root
   `gta-claw-android` client core so a shell can path-depend on its core
   without a name collision.
3. `REJECTED: android/Cargo.toml top-level schema changed`
   After relocating the member, the workspace manifest is still rejected.
   `validate_mobile_workspace` requires top-level keys to be exactly
   `profile` and `workspace`, and `[workspace]` keys to be exactly
   `dependencies`, `lints`, `members`, `package`, `resolver`. This archive's
   manifest is a combined workspace-and-package file with no `[profile]`,
   no `[workspace.package]` and no `[workspace.dependencies]`.
   **`desktop/Cargo.toml` is the working template**; mobile mirrors it.

The lint policy is *not* a barrier: this crate's `unsafe_code = "deny"`
byte-matches `desktop/Cargo.toml`, and the rule is "no weaker than desktop",
so the single `android_main` exception survives. The ceiling that blocks a
**root** member does not block a mobile-workspace member.

Two barriers beyond the three above were not reached, because validation
stops at the first rejection. One of them has since been **measured and is a
certain fourth rejection**:

4. **The Skia pin, which cannot be satisfied today.** This archive's
   `Cargo.lock` contains `skia-bindings 0.99.0` and `skia-safe 0.99.0`.
   The trust root requires that wherever a mobile lock contains
   `skia-bindings` it must be the pinned release, and
   `PINNED_BUILD_ARTIFACTS` on `main` is `[(&str, &str, &str, &str, &str); 0]
   = []` — **literally empty**. No release is pinned, so no lock containing
   Skia can pass. A reviver must either land a Skia pin first, or produce a
   lock with no `skia-bindings` line at all — and the next section explains
   why the second option is not available on Android.

The remaining unverified barrier is the single-`slint`-line rule: any `slint`
entry in a mobile lock must match the release recorded in the protected
desktop lock. That has not been checked against this lock.

### Skia is unavoidable on Android, and the trust root records the opposite

This crate selects `default-features = false` with only `renderer-femtovg`
and `renderer-software`. **It still builds Skia.** The cause is upstream and
structural:

```toml
# i-slint-backend-android-activity 1.17.1, Cargo.toml lines 89-91
[target.'cfg(target_os = "android")'.dependencies.i-slint-renderer-skia]
version = "=1.17.1"
default-features = false
```

There is no `optional = true`. `cargo tree -i i-slint-renderer-skia` confirms
it on both `aarch64-linux-android` and `armv7-linux-androideabi`, arriving
through `i-slint-backend-android-activity` — the backend this crate selects
by name. Renderer features select what is *used*; they do not remove a
non-optional dependency of the backend.

**This contradicts the trust root's platform table.** `policy.rs` sets
`skia_is_unavoidable: false` for Android with the comment "The Android
backend can select femtovg or the software renderer, so Skia is optional
here". That is true of Slint's renderer features in general and false of the
`android-activity` backend at 1.17.1. Android is structurally the same case
as iOS, which the table already marks unavoidable. **This is reported to the
trust-root owner and is not this branch's to fix** — recorded here because
anyone reviving this tree will hit it.

### This archive has a JNI trust boundary; the shipped crate does not

An earlier finding, correct for the shipped no-GUI `apps/gta-claw-android`,
was that the Android dependency graph contains none of `jni`, `jni-sys`,
`ndk`, `ndk-sys` or `android-activity`. **That statement does not extend to
this archive.** Measured on `aarch64-linux-android`:

| Crate | Version(s) |
| --- | --- |
| `jni` | 0.22.4 |
| `jni-sys` | **0.3.1 and 0.4.1** |
| `ndk` | 0.9.0 |
| `ndk-sys` | 0.6.0+11769913 |
| `android-activity` | 0.6.1 |

`jni` is likewise a non-optional Android dependency of the backend
(`Cargo.toml` line 93). So if mobile GUI is ever revived, **the JNI audit
that currently has no subject acquires one**, including a `jni-sys` present
at two major versions in a single graph.

**None of this makes the tree shippable.** Mobile ships without a GUI this
release, so conforming to the admitted shape would be speculative work on a
cancelled feature, and reshaping the tree would destroy the byte-identity
to what actually built and linked that gives this archive its value. The
tree is therefore left exactly as it was built and the gap is written down
instead.

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

This was originally established by listing the release assets. It has since
been **reproduced by running the build**, which is stronger, and the failure
is verbatim:

```
TRYING TO DOWNLOAD AND INSTALL SKIA BINARIES:
  0.99.0/<key>-armv7-linux-androideabi-gl-jpegd-jpege-pdf-vulkan
DOWNLOAD AND INSTALL FAILED: curl error code: "22"
curl stderr: "curl: (22) The requested URL returned error: 404"
STARTING A FULL BUILD
...
panicked at skia-bindings-0.99.0/build_support/platform/android.rs:69:35:
ANDROID_NDK variable not set
```

Two details a future reader will need. The variable `skia-bindings` demands
is **`ANDROID_NDK`**, which is *not* the `ANDROID_NDK_HOME` that the rest of
the Android tooling uses; setting only the latter produces a panic that reads
like a missing NDK on a machine that has five. And the fallback is silent in
the sense that matters: a 404 on an artefact that was never published
escalates automatically into fetching and compiling an unvendored C++ tree,
rather than stopping and saying the platform is unsupported.

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
