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

**Locally: Windows x86_64 (`x86_64-pc-windows-msvc`), rustc 1.97.0. Nothing else.**

Repository CI additionally *executes* this crate's tests — not merely compiles
them — on macOS arm64 (`macos-latest`), Linux and Windows, because the crate is
a root workspace member and the headless matrix runs `--workspace`. All 75 pass
on all three. That is the only non-Windows evidence about this code that exists,
and it says nothing about an Apple *target* build: those runners build for the
host, not for `aarch64-apple-ios`.

| Check | Result |
| --- | --- |
| `cargo test -p gta-claw-ios --all-targets` | 75 passed, 0 failed |
| `cargo clippy -p gta-claw-ios --all-targets -- -D warnings` | clean |
| `cargo fmt -p gta-claw-ios -- --check` | clean |
| `RUSTDOCFLAGS=-D warnings cargo doc -p gta-claw-ios --no-deps` | clean |
| `cargo deny check bans` | `bans ok` |
| `cargo check -p gta-claw-ios --target aarch64-apple-ios` | **fails** |

### Most of these tests compare this crate against itself

That is appropriate for the logic they cover, but it cannot catch the case where
this crate and `claw-security` agree with each other and both differ from
upstream. A suite can be entirely green while the client asks the Gateway for
the wrong scope.

`tests/frozen_scope_contract.rs` therefore takes
`compat/upstream/inventories/gateway-protocol.json` as its subject — read from
the repository, not reconstructed in Rust, and byte-frozen so nothing in this
crate contributes to it. It asserts that the scope registry this build can name
is exactly the frozen six, and that each `IosAction`'s required scope equals the
scope upstream records for a method that performs it (`sessions.list`,
`talk.client.create`, `exec.approval.resolve`, `device.pair.approve`,
`config.set`).

The file opens with a control test, because every other assertion there is a
lookup and a lookup against an empty or mis-parsed document passes vacuously.
Without the control, three green tests would be evidence of nothing. The
mapping was also mutation-checked: pointing `Administer` at `config.get`
(`operator.read`) makes the test fail with

```
action administer the Gateway requires operator.admin but the frozen inventory
records operator.read for config.get, so this client would ask the Gateway for
the wrong scope
```

Incidental finding: the frozen inventories carry a UTF-8 BOM, which
`serde_json` rejects as a leading value. Any Rust consumer of
`compat/upstream/**` has to strip it.

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
is **not** a proof that this crate compiles for iOS, and it must not be reported
as one. It is a `rustc`-only check performed with no Apple toolchain present at
all: no `xcrun`, no iOS SDK, no target `clang`, no linker. Any crate in the
graph that compiles C, assembly or Objective-C is untested by it, and linking is
untested entirely. Someone on a macOS runner with Xcode must run the iOS target
check before any iOS build claim is made.

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

## Platform surfaces recorded as gaps rather than substituted

Three surfaces in the frozen upstream contract have no working iOS form here.
Each is written down, with its reason, in code rather than only in prose, so
that its absence cannot be mistaken for an oversight. See `src/transport.rs`
(`ClientTransport::ios_record`) and `src/host_app.rs`.

**None of these positions has been confirmed on an Apple device.** Every
transport record reports `confirmed_on_ios() == false`, and a test asserts it.

### Bonjour and DNS-SD discovery — needs host-application declarations

`integration.discovery.dns-sd` in `compat/upstream/ledgers/official-integration.json`.

iOS does not fail loudly when `NSLocalNetworkUsageDescription` or
`NSBonjourServices` is missing from the host bundle: it simply returns nothing,
which is indistinguishable from a network with no Gateway on it. `HostAppDeclarations`
therefore refuses to permit discovery unless an embedder positively confirms
both keys **and the specific service type being browsed is among the declared
entries**, and returns a `DiscoveryUnavailable` naming the exact plist key or
service type when it will not.

Declaring `NSBonjourServices` with some *other* service is the case most likely
to be mistaken for an empty network, because the key is present and looks
correct, so `ServiceTypeNotDeclared` names the type that was requested.

**This crate does not own the service type.** Both gates take it as an argument.
The Gateway's DNS-SD service type belongs to the discovery contract and its
owning crate; declaring a copy here would let the two drift apart with nothing
able to notice. Note also that the plist entry and the browsed name are
different strings — `NSBonjourServices` carries the application-label form
(`_example._tcp`), while the fully qualified `_example._tcp.local.` belongs
inside the discovery implementation. Tests assert that the fully qualified form
and the subtype form are both **rejected** by `BonjourServiceType`, so neither
can reach a plist entry by accident.

An *unconfirmed* declaration is treated exactly as strictly as a missing one:
`DeclarationStatus::Unknown` is the default and does not permit anything. This
crate cannot read `Info.plist` — that needs Foundation interop and the workspace
forbids `unsafe_code` — so every status here is declared by the embedder, and
the type names say so.

`BonjourServiceType` is validated down to the RFC 6763 grammar (at most fifteen
characters of `[A-Za-z0-9-]`, no dots, colons, slashes, at-signs or whitespace)
specifically so that it cannot hold credential-shaped text. Narrowing the domain
was preferred to redacting a `Debug`.

Discovery itself is not implemented in this crate and is not this crate's to
implement; only the precondition is.

#### The plist keys are not the whole gate: multicast is an Apple-granted entitlement

Verified against Apple's primary documentation — TN3179 *Understanding local
network privacy* and the entitlement reference for
`com.apple.developer.networking.multicast`, which records `introducedAt: 14.0`
for iOS.

On iOS, **sending or receiving UDP multicast requires the
`com.apple.developer.networking.multicast` entitlement**, and that entitlement
is not a key a developer may add. Apple's own text: *"This entitlement requires
permission from Apple before you can use it in your app"*, requested at
`https://developer.apple.com/contact/request/networking-multicast`. It is a
decision by a third party for a specific application identifier, so **a build
made from source does not have it**, and its failure mode is the worst one
available: the sockets bind, the calls report success, and no packet moves.

The requirement depends on **how** discovery is implemented, and "how" is a
property of the backend rather than a choice the caller makes.
`HostAppDeclarations::discovery_precondition` is therefore generic over a
`LocalDiscoveryBackend`, and reads both the mechanism and the service type from
that backend's own descriptor:

| Backend mechanism | Requires |
| --- | --- |
| `SystemDnsSd` — system DNS-SD, declared service types only | both plist keys, and the backend's service type among the declared entries |
| `InProcessMulticast` — any pure-Rust mDNS stack, `mdns-sd` included | the above, **and** a confirmed multicast entitlement |

The returned `DiscoveryPermit<'_, B>` is parameterised by the backend it was
issued for, so a permit obtained for a system-DNS-SD adapter **cannot be spent**
starting a raw-socket browser. A mode field would have left that to a reviewer
to notice; a type parameter makes it unsayable. The permit's field is private
and it has no public constructor, so the gate is its only source.

`LocalDiscoveryBackend` mirrors the backend contract agreed with the `claw-nodes`
owner and is documented as a mirror: as of PR #57 head `237b386e` that crate
exports `GATEWAY_SERVICE_TYPE` and `MdnsBrowser` but no descriptor trait, so a
re-export would be a cross-PR dependency. `GatewayMdnsBackend` carries
`"_openclaw-gw._tcp.local."` and `InProcessMulticast`, and the `NSBonjourServices`
form is **derived** from the browsed form rather than written down a second time
— with a test asserting the derivation round-trips, because two hand-written
copies of one name can disagree silently.

Entitlement state is tracked by its own `EntitlementStatus` (`Granted` /
`NotGranted` / `Unknown`, fail-closed on `Unknown`) rather than by
`DeclarationStatus`, because a capability a third party grants is a different
kind of thing from text a developer writes, and a caller told to "add the
declaration" would look in the wrong file. `NotGranted` covers a refused request
and a pending one alike — operationally identical — but stays distinct from
`Unknown`, because one is answered by checking the signing profile and the other
by asking Apple.

Per TN3179's own tables, only *"working with arbitrary Bonjour service types"*
and *"browsing for all advertised service types"* pull the entitlement into the
system DNS-SD path. Registering, browsing and resolving a specific declared
service type does not.

This is a genuine architectural fork rather than a flat gap, and it is recorded
as one. It is **not** a route this crate can take today: the system DNS-SD APIs
are C, reaching them needs FFI, and the workspace sets `unsafe_code = "forbid"`.
Recording `SystemDnsSd` is a statement about what iOS permits, not a claim that
this crate can use it.

`DiscoveryUnavailable::awaits_apple_approval` separates the conditions a
developer can fix from the one that waits on Apple, because a user should not be
told to check a setting that does not exist on their machine.

#### Two conditions deliberately left ungated

*The runtime Local Network privilege.* TN3179 gives it three states —
undetermined, allowed, denied — and the alert that resolves it is raised **by**
the first local-network operation. Gating on it would block the call that
produces the prompt, so it is not a precondition. It is modelled *after the
fact* instead: `diagnose_empty_result(privacy, run_state)` turns an empty peer
list into a reason, so a caller never reports "no Gateways found" when the
truthful answer is "we were not allowed to look".

| Privilege | App state | Diagnosis |
| --- | --- | --- |
| granted | either | `NoResponders` — the only case that may be reported as an empty network |
| undetermined | foreground | `AwaitingConsentPrompt` — the browse itself raises the alert |
| undetermined | background | `SilentlyDeniedInBackground` |
| denied | either | `DeniedByUser` |

The background case is called out separately because TN3179 records that iOS
then denies the operation **without showing an alert and without recording a
decision** — so the user has not refused anything, and a foreground retry is the
correct next step. Only `NoResponders` returns `means_nothing_was_there()`, and
the default privilege state is `Undetermined`, so the fail-closed reading is the
one you get by not thinking about it.

*The simulator.* TN3179 states that the simulator does not support local network
privacy and that this behaviour must be tested on a real device.

#### Acceptance boundary

A simulator run, or any CI job this project could plausibly build, can prove
that this crate compiles and that the policy logic behaves as written. It cannot
prove anything about local network privacy or discovery behaviour. **Only a
physical iOS device on a real local network can do that**, and no such run has
happened.

### Tailscale — believed structurally unavailable on iOS

`integration.discovery.tailscale` in the same ledger. The Gateway handshake
already reserves `AUTH_TAILSCALE_IDENTITY_MISSING`, `AUTH_TAILSCALE_PROXY_MISSING`,
`AUTH_TAILSCALE_WHOIS_FAILED` and `AUTH_TAILSCALE_IDENTITY_MISMATCH` in
`crates/claw-protocol/src/gateway/handshake.rs`.

Reaching that path needs an app-accessible Tailscale LocalAPI Unix socket or an
explicit loopback proxy. A stock sandboxed iOS deployment may expose neither.
This is recorded as `IosTransportStatus::BelievedUnavailable` — believed, not
proven, because confirming it requires a device.

**No substitute transport is offered in its place**, deliberately. A documented
gap can be planned around; an invented analogue cannot afterwards be told apart
from the real thing.

### SSH — no Keychain integration, and that is a known regression

`integration.discovery.ssh` in the same ledger. An SSH tunnel needs
caller-provisioned sandbox paths for the private key and `known_hosts`.

**Keychain and Secure Enclave integration is explicitly out of scope for this
crate**, for a stated reason rather than by omission: the Keychain API is
Objective-C/C and reaching it needs FFI, which `unsafe_code = "forbid"` rules
out for a root workspace member. Without it, key material would sit in ordinary
application-container files on a platform that provides a hardware-backed store.
That is a regression against the platform's own norm, and it is why the SSH
transport is recorded as unusable rather than shipped in a weakened form.

The same reasoning applies to `IosCredential`, which holds a secret in memory
for the lifetime of a process and persists nothing.

## Cross-crate observation, not fixed here

The brief said `crates/claw-clients` records `ClientId::Ios` as
`ContractOnlyThirdPartyClient`. No such crate or symbol exists in this
repository. `ClientId::Ios` is defined in
`crates/claw-protocol/src/gateway/frame.rs` with wire identity
`openclaw-ios`, and `compat/upstream/inventories/clients.json` already
classifies `client:ios` as `official_client_interop`. Nothing needed changing,
and nothing outside this crate was changed.
