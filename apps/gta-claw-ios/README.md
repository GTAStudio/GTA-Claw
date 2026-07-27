# gta-claw-ios

UI-independent iOS client core for GTA Claw.

## What this is

The part of an iOS client that sits underneath a user interface: endpoint
intake, credential intake, Gateway v4 client identity, transport configuration
assembly, bounded mobile connection policy, host lifecycle and network-path
coordination, and a connection model that renders a revisioned snapshot a view
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

## Host-shell integration contract

The future application target owns UIKit/SwiftUI lifecycle callbacks,
`NWPathMonitor`, Keychain, DNS-SD, and async task cancellation. This crate owns
the rules those facilities must follow:

1. Create an `IosSessionModel`; it starts fail-closed as `AppRunState::Inactive`
   with `IosNetworkPath::Unknown`.
2. Feed semantic lifecycle and path changes through `set_run_state` and
   `set_network_path`. Keep an `IosNetworkRoute::id` stable for cost-only
   updates and advance it for a real route change, including Wi-Fi-to-Wi-Fi.
3. Process `TransportDirective::Stop` by stopping the named task and dropping
   its `ConnectionAttempt`; call `reconcile` afterward. Process
   `TransportDirective::Resume` by reserving a new `ConnectionAttempt`.
4. Deliver transport state through `ConnectionAttempt::observe`, never through
   an unscoped callback. Once backgrounding, a network transition, or a user
   disconnect invalidates that generation, late observations return
   `ObservationResult::Stale` and cannot restore authorization.
5. Bind UI state to the shared `Arc<IosViewSnapshot>` from `snapshot`.
   `snapshot_if_changed` compares revisions, and duplicate lifecycle, path, and
   transport observations reuse the existing allocation.

`IosGatewayProfile` applies `IosConnectionPolicy::MOBILE_DEFAULT`: 8-second
connect and authentication timeouts, a 20-second request timeout, a 2-second
shutdown timeout, and four foreground retries whose cumulative sleep is capped
at 8.5 seconds including maximum jitter. Backgrounding or losing the network
stops that budget immediately.

Platform facilities remain host-provided:

- `HostCredentialStore` is the future Keychain boundary. Account keys redact
  their `Debug`, secret values remain in `SecretString`, loaded values pass
  normal credential validation again, and one-time bootstrap tokens cannot be
  persisted through the helper API.
- `HostDiscoveryProvider<B>` starts only an owned `DiscoveryRequest<B>` carrying
  a backend-specific `DiscoveryPermit`, an active local route generation, a
  timeout of at most 15 seconds, and a result cap of at most 64. The host must
  cancel the returned `HostDiscoverySession` on backgrounding or route change.
- These are ports, not Apple-framework implementations. No Keychain, DNS-SD,
  Network.framework, UIKit, or Slint code is added here.

## What has actually been executed

**Locally: macOS arm64 (`aarch64-apple-darwin`), rustc 1.97.1.**

| Check | Result |
| --- | --- |
| `cargo test -p gta-claw-ios --all-targets` | 111 passed, 0 failed |
| `cargo clippy -p gta-claw-ios --all-targets -- -D warnings` | clean |
| `cargo fmt -p gta-claw-ios -- --check` | clean |
| `RUSTDOCFLAGS=-D warnings cargo doc -p gta-claw-ios --no-deps` | clean |
| `cargo check -p gta-claw-ios --target aarch64-apple-ios` | blocked in `ring`: iPhoneOS SDK unavailable |
| `cargo check -p gta-claw-ios --target aarch64-apple-ios-sim` | blocked in `ring`: iPhoneSimulator SDK unavailable |

The host has Apple Command Line Tools but not full Xcode. Both Rust targets are
installed, but `xcrun --sdk iphoneos` and `xcrun --sdk iphonesimulator` cannot
locate an SDK. The two target checks therefore stop in `ring 0.17.14` before
this crate is type-checked for iOS. Host execution is evidence for the pure Rust
state and policy logic, not an iOS build, simulator run, or device run.

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
`talk.client.create`, `exec.approval.resolve`, `config.set`).

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

### The frozen inventory does not say which scopes iOS is *granted*

`frozen_scope_contract.rs` proves each action asks for the right scope. It
cannot prove iOS is ever *given* that scope, because
`compat/upstream/inventories/clients.json` records `client:ios` only as
`official_client_interop` with no scope grants at all.

`tests/upstream_ios_grant_set.rs` closes that with `claw-clients` as its
subject — the crate that ports the frozen client surfaces — read through the
public `surface(SurfaceId::Ios)` contract rather than restated here, so there is
no second copy of the grant set to drift. It records that upstream iOS requests

```
operator.admin  operator.read  operator.write  operator.approvals
operator.talk.secrets
```

and **not** `operator.pairing`. That set is a **ceiling, not a quota**:
`validate_gateway_profile` admits any subset of it, so the enforceable claim is
not "pairing is missing from a list" but "a profile requesting pairing is
refused". One test runs that real validator, with a read-only control that must
be admitted so the refusal is not vacuous. (That framing is the Android
session's, from #76.)

Consequences, each asserted:

- **This crate models no pairing action at all.** `IosAction::ManagePairing`
  existed until the fleet coordinator ruled it out: pairing is a desktop and
  terminal operation, and both mobile profiles — Android and iOS — omit
  `operator.pairing`. A mobile client is *paired*; it does not *pair others*.
  Any front end must treat pairing as absent rather than as a control that
  will work.
- **The refusal is still enforced, at the contract rather than at the action.**
  `validate_gateway_profile` rejects an iOS profile that requests
  `operator.pairing`, with an admitted read-only control alongside it so the
  refusal is not vacuous. That test never referenced the action and is
  unchanged.
- **`grants()` is proved to discriminate from a reachable state.** The removed
  action had been carrying that proof: it was the one action the upstream
  profile refused, so it demonstrated `grants()` could return `false` at all.
  Deleting it would have left a fully permissive `grants()` undetected —
  measured, not assumed: with `grants()` stubbed to `true`, every other test in
  that file still passed. The replacement control observes a connection
  confirmed with only `operator.read` and asserts `SendMessage` is refused,
  which is a state the server can actually produce, since the scope set is a
  ceiling and any subset is admissible.
- All four remaining actions *are* granted by the upstream profile, so the
  control above cannot pass by `grants()` refusing everything.
- `operator.talk.secrets` is granted but modelled by no action here, because no
  Talk surface is built yet. That gap is asserted so it cannot change unnoticed.

Mutation-checking `grants()` by stubbing it to return `true` unconditionally
fails the discrimination control with the observed set spelled out — `must
refuse SendMessage (needs OperatorWrite) … from the observed set
["operator.read"]` — rather than `ScopeSet(47)`.

### The Gateway is more permissive than this client, deliberately

`claw_protocol::gateway::authorization` allows **any** operator method when the
granted set contains `operator.admin`, and treats `operator.write` as satisfying
`operator.read`. `IOS_OPERATOR_SCOPES` contains `operator.admin`, so a Gateway
would in fact permit pairing-classified methods on an accepted iOS session even
though the *connect-time* check refuses a profile that asks for
`operator.pairing` outright.

This client does not mirror those implication rules. It asks only whether the
server confirmed the exact scope an action needs. That makes it strictly
stricter than the server, which is the safe direction: it may withhold an action
the Gateway would have allowed, but it never offers one the Gateway would
refuse. Mirroring server-side subsumption would mean inferring a grant the
server never stated, which is the fabricated permission summary
`ObservedAuthorization` exists to prevent.

This does **not** prove upstream's Swift client requests these scopes. That
source is not vendored here and cannot be read from this repository.

Both iOS target checks fail in `ring 0.17.14`, a mandatory transitive dependency
of `claw-gateway-client`, before they reach any code in this crate:

```
xcrun: error: SDK "iphoneos" cannot be located
```

`ring` compiles C and assembly and needs the target SDK, compiler, and linker.
Someone on a macOS runner with full Xcode must rerun both checks before any iOS
build claim is made.

## Known limitations

* Never built or run for an iOS target, simulator, or device. The Rust core has
  run only as a macOS arm64 host binary in this revision.
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
  a build on a workstation truthfully says `macos` while still presenting
  `ClientId::Ios`. Use `IosClientIdentity::targets_ios()` to tell the two apart.
* `ConnectionState::Ready` carries a `ConnectionEpoch` that only
  `claw-gateway-client` may allocate, so the conversion from a live `Ready`
  state into an authenticated snapshot has no test that starts from a real
  `Ready` value. Everything downstream of that conversion is tested.
* `AuthenticationFailure` likewise has no public or test constructor, so this
  crate cannot instantiate `ConnectionState::AuthenticationFailed`; the
  lifecycle renderer's match is exhaustive, but that one formatted detail path
  cannot be exercised here without changing the owning crate.
* No push notifications or background refresh. Background state deliberately
  invalidates connection authorization and asks the host to stop the transport.
* No Keychain or DNS-SD implementation. `HostCredentialStore` and
  `HostDiscoveryProvider` define validated host boundaries, but a future shell
  still has to implement them with Apple frameworks.

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
correct, so `ServiceTypeNotDeclared` names the type that was requested. An input
above the bounded 16-entry inventory is also rejected explicitly instead of
silently truncating away the required type.

`discovery_precondition` remains a fail-fast gate. A diagnostics view should call
`discovery_diagnostics::<B>()`, which reports every independent plist and
signing problem in one pass. Each `DiscoveryDiagnostic` carries a concise title,
an explanation, and a typed `DiscoveryRemediation`: add or verify the exact
plist key, declare the exact service type, inspect the signed entitlement, or
open Apple's restricted-entitlement request URL. It does not invent a private
iOS Settings URL.

**The discovery backend owns the service type.** The gate reads it from
`LocalDiscoveryBackend::DNS_SD_SERVICE_TYPE`, so a caller cannot pair a backend
with a different plist check. `GatewayMdnsBackend` records the
`_openclaw-gw._tcp.local.` value used throughout `claw-discovery`'s executable
DNS-SD fixtures; that crate exports no canonical constant and deliberately
contains no network runtime. Note also that the plist entry and the browsed name
are different strings — `NSBonjourServices` carries the application-label form
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

Discovery itself is not implemented in this crate. `HostDiscoveryProvider`
defines the callback/session port a future system DNS-SD adapter implements, and
`DiscoveryRequest` adds foreground, local-route, timeout, and result-count gates
before that adapter can start.

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

The returned owned `DiscoveryPermit<B>` is parameterised by the backend it was
issued for, so a permit obtained for a system-DNS-SD adapter **cannot be spent**
starting a raw-socket browser. A mode field would have left that to a reviewer
to notice; a type parameter makes it unsayable. The permit's field is private
and it has no public constructor, so the gate is its only source. It owns the
matched service type so a host scan may outlive the declaration object that
produced it.

`LocalDiscoveryBackend` is the host-boundary descriptor missing from
`claw-discovery`, whose crate-level contract explicitly says it has no network
runtime. `GatewayMdnsBackend` carries `"_openclaw-gw._tcp.local."` and
`InProcessMulticast`, and the `NSBonjourServices` form is **derived** from the
browsed form rather than written down a second time — with a test asserting the
derivation round-trips, because two hand-written copies of one name can disagree
silently.

**`GatewayMdnsBackend` is a descriptor, not a shipped capability.**
`claw-discovery` supplies pure packet and resolution logic only; no socket-owning
browser exists for this descriptor to construct. Satisfying the gate therefore
authorises nothing that exists in an iOS build today; it records what a future
audited adapter would have to hold. `ClientTransport::BonjourDiscovery` remains
`NeedsHostAppFacilities`, is not `usable_today()`, and is not
`confirmed_on_ios()` — and a test asserts that a fully satisfied permit does not
change any of those.

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

`DiscoveryUnavailable::awaits_apple_approval` is true only when the shipped build
is confirmed not to have an Apple-restricted entitlement. `Unknown` instead
produces a "verify the signed app" remediation; it does not claim an Apple
request is pending before the signature has been inspected.

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
| undetermined | inactive | `DeferredWhileInactive` — finish the prompt/interruption, then retry |
| undetermined | background | `SilentlyDeniedInBackground` |
| denied | either | `DeniedByUser` |

The background case is called out separately because TN3179 records that iOS
then denies the operation **without showing an alert and without recording a
decision** — so the user has not refused anything, and a foreground retry is the
correct next step. Each diagnosis also yields a typed user remediation: answer
the prompt, return to the foreground, use the host's supported app-settings API,
or check the Gateway and local network. Only `NoResponders` returns
`means_nothing_was_there()`, and the default privilege and lifecycle states are
`Undetermined` and `Inactive`, so the fail-closed reading is the one obtained by
omitting host observations.

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

### SSH — no Keychain implementation, and no plaintext fallback

`integration.discovery.ssh` in the same ledger. An SSH tunnel needs
caller-provisioned sandbox paths for the private key and `known_hosts`.

The Keychain API needs Apple-framework interop that this `unsafe_code = "forbid"`
crate cannot supply. `HostCredentialStore` now defines the protected-storage
port for a future host app, but no implementation is shipped. The helper API
revalidates loaded material, keeps secrets in `SecretString`, redacts account
keys, and refuses to persist bootstrap tokens.

Without a host implementation, SSH key material would still sit in ordinary
application-container files on a platform that provides protected storage. The
SSH transport therefore remains unusable rather than falling back to that
weaker design. `IosCredential` itself holds a secret only in memory unless the
host explicitly persists an eligible kind through the port.

## Client contract anchors

`crates/claw-clients` records `SurfaceId::Ios` as a native
`ContractOnlyThirdPartyClient` with both UI/operator and node profiles.
`tests/upstream_ios_grant_set.rs` reads that public contract directly.
`ClientId::Ios` is defined in `crates/claw-protocol` with wire identity
`openclaw-ios`, while `compat/upstream/inventories/clients.json` classifies
`client:ios` as `official_client_interop`. This crate changes none of those
owners; it consumes and tests their contract.
