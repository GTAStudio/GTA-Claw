# gta-claw-ios

UI-independent iOS client core for GTA Claw.

## What this is

The part of an iOS client that sits underneath a user interface: endpoint
intake, credential intake, Gateway v4 client identity, transport configuration
assembly, and a connection-lifecycle model that renders to a snapshot a view
layer can bind to.

## What this is not

**There is no iOS user interface here.** No Slint markup, no `build.rs`, no
`include_modules!`, no application target, no Xcode project, no packaging.

That is not an oversight, and it is not a decision this crate was free to make.
The base-owned trusted supply-chain policy in
`.github/trusted/desktop-supply-chain-policy` refuses a Slint dependency in
every location available to a root workspace member. Running the real validator
from that crate against synthetic candidate trees gives, with a passing baseline
control:

```
CASE 0-baseline-unmodified:                    ACCEPTED
CASE 1-root-member-with-cfg-gated-slint:       REJECTED: root/headless manifest contains forbidden GUI dependency: slint
CASE 2-root-member-with-renamed-slint:         REJECTED: root/headless manifest aliases forbidden GUI package slint as ui-toolkit
CASE 3-separate-ios-workspace-via-exclude:     REJECTED: root workspace resolver/exclude policy changed
CASE 4-root-member-with-own-lint-table:        REJECTED: apps/gta-claw-ios/Cargo.toml lints must inherit exactly from workspace
CASE 5-root-member-without-any-gui-dependency: ACCEPTED
```

Case 5 is this crate. Landing a Slint UI needs three changes inside
`.github/trusted/**`, which is byte-frozen and cannot authorise itself:

1. an exception in `is_forbidden_gui` and `validate_root_lock` for the iOS
   member's GUI dependencies;
2. a `claw-config`-style per-member lint exception, because Slint's generated
   item-tree macros need a local `allow(unsafe_code)` and the workspace sets
   `unsafe_code = "forbid"`, which cannot be overridden (`desktop/` uses `deny`
   for exactly this reason and says so in its manifest);
3. a workflow-allowlist entry for iOS packaging.

## What has actually been executed

**Windows x86_64 (`x86_64-pc-windows-msvc`), rustc 1.97.0. Nothing else.**

| Check | Result |
| --- | --- |
| `cargo test -p gta-claw-ios --all-targets` | 42 passed, 0 failed |
| `cargo clippy -p gta-claw-ios --all-targets -- -D warnings` | clean |
| `cargo fmt -p gta-claw-ios -- --check` | clean |
| `RUSTDOCFLAGS=-D warnings cargo doc -p gta-claw-ios --no-deps` | clean |
| `cargo check -p gta-claw-ios --target aarch64-apple-ios` | **fails** |

The iOS target check fails in `ring 0.17.14`, a mandatory transitive dependency
of `claw-gateway-client`, before it reaches any code in this crate:

```
error occurred in cc-rs: failed to find tool "xcrun": program not found
```

`ring` compiles C and assembly and needs `xcrun` and the iOS SDK, so no
`aarch64-apple-ios` or `aarch64-apple-ios-sim` build of this crate is possible
from a Windows host. The pure-Rust part of the dependency graph *does* check
cleanly for `aarch64-apple-ios` from Windows:

```
cargo check --target aarch64-apple-ios \
  -p claw-application -p claw-domain -p claw-platform -p claw-protocol -p claw-security
Finished `dev` profile
```

That narrows the remaining unknown to the `ring`/`rustls`/`tokio` layer, but it
is not a proof that this crate compiles for iOS. Someone on a macOS runner with
Xcode must run the iOS target check before any iOS claim is made.

## Known limitations

* Never run on an Apple platform, a simulator, or a device.
* Never completed a Gateway handshake against a real server. The integration
  tests prove the transport client *accepts* the configuration this crate
  builds and shuts down deterministically; they connect to `ws://127.0.0.1:1`,
  which refuses immediately.
* `UnobservedDeviceProbe` reports no device facts. Reading
  `UIDevice.current.model` or the `hw.machine` sysctl needs Objective-C or libc
  interop, which `unsafe_code = "forbid"` rules out. An embedder that can read
  them passes them in through `DeclaredDeviceProbe`; the type name records that
  this crate did not measure them.
* `IosClientIdentity` reports `std::env::consts::OS` as the client platform, so
  a build on a workstation truthfully says `windows` while still presenting
  `ClientId::Ios`. Use `IosClientIdentity::targets_ios()` to tell the two apart.
* `ConnectionState::Ready` carries a `ConnectionEpoch` that only
  `claw-gateway-client` may allocate, so the conversion from a live `Ready`
  state into an authenticated snapshot has no test that starts from a real
  `Ready` value. Everything downstream of that conversion is tested.
* No push notifications, no background refresh, no Keychain persistence, no
  device-token storage. `claw-security` provides no persistence either.

## Cross-crate observation, not fixed here

The brief said `crates/claw-clients` records `ClientId::Ios` as
`ContractOnlyThirdPartyClient`. No such crate or symbol exists in this
repository. `ClientId::Ios` is defined in
`crates/claw-protocol/src/gateway/frame.rs` with wire identity
`openclaw-ios`, and `compat/upstream/inventories/clients.json` already
classifies `client:ios` as `official_client_interop`. Nothing needed changing,
and nothing outside this crate was changed.
