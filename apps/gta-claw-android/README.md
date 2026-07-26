# gta-claw-android

The Android client core for GTA Claw: connection policy, credential handling,
attempt lifecycle and Gateway transport, with **no user interface**.

Nothing here links a UI toolkit, so the same code serves a native Android shell,
headless use and test harnesses, and it is reviewable as protocol and state
rather than as rendering.

## There is no Android UI in this repository

This is a limitation, not a design preference, and it is worth stating plainly
because it is not visible as a build failure — it looks like a client that
connects, holds state and draws nothing.

The repository's supply-chain policy (`.github/trusted/…/src/policy.rs`,
byte-frozen) rejects every shape that could carry one. Verified by running
`validate_final_static` against candidate trees built from `origin/main`, with an
unmodified checkout as a passing control:

| Candidate shape | Verdict |
| --- | --- |
| unmodified `main` (control) | **ACCEPTED** |
| separate workspace, root `exclude` extended | REJECTED: `root workspace resolver/exclude policy changed` |
| separate workspace, root manifest untouched | REJECTED: `Cargo.lock inventory changed` |
| root member with its own `deny.toml` | REJECTED: `unexpected deny/audit policy file` |
| root member, `slint` behind `cfg(target_os = "android")` | REJECTED: `forbidden GUI dependency: slint` |
| root member declaring its own `[lints.rust]` | REJECTED: `lints must inherit exactly from workspace` |
| root member, no GUI, inherited lints | **ACCEPTED** |

Two independent walls block a UI:

- **The GUI ban matches on dependency name.** Manifests are read as text and
  never resolved per-target, so `cfg`-gating `slint` does not help.
- **`unsafe_code = "forbid"` is inherited and cannot be overridden.** Slint's
  Android backend needs `#[unsafe(no_mangle)] fn android_main(…)` in a `cdylib`;
  `#[unsafe(…)]` trips the lint, and `forbid` cannot be locally relaxed. Only two
  members hold per-member lint exceptions and both are hard-coded in policy.

A shell would have to live outside this workspace and depend on this crate. That
is what the layering here is for.

## Layout

| Path | Contents |
| --- | --- |
| `src/onboarding.rs` | Input policy, redaction, connection state machine, snapshot rendering |
| `src/session.rs` | Attempt ownership (RAII), `GatewayClientConfig` construction |
| `src/identity.rs` | Session device identity from the platform CSPRNG |
| `src/controller.rs` | Tokio runtime owning one `GatewayClient`; composition against `claw-application` |

## Dependencies

No new third-party crate. Adding this member changes the root `Cargo.lock` by
exactly one entry — `gta-claw-android` itself.

Randomness comes from `ring`'s `SystemRandom` rather than `getrandom`, matching
`gta-claw-cli`. `ring` is already linked for the Gateway's TLS, whereas
`getrandom 0.4` would have added both `getrandom` and `r-efi` (a UEFI crate with
no business in an Android dependency graph) and put a second major version of
`getrandom` in the tree.

## Authorization

The client requests `Role::Operator` with exactly `[Scope::OperatorRead]` and
sets `AuthorizationExpectation::ExactRequested`, so a hello granting anything
other than what was asked for is rejected rather than accepted and ignored.

## Credentials and identity

Nothing is persisted. The endpoint and token live in one `ConnectRequest`; the
token moves into the transport's credential type and drops when the attempt ends.
`onboarding::CREDENTIAL_NOTICE` states this rather than leaving it assumed.

Every type that can carry the endpoint or the token has a hand-written `Debug`
that redacts both, including the URL path — a path carries a token as easily as a
query string does. Tests assert the redaction rather than trusting it.

**The device identity is not durable.** It is generated per process, so every
launch is a new device from the Gateway's point of view. Persisting it properly
means the Android Keystore, which is reachable only through JNI, which needs
`unsafe`. There is no analogue available under `forbid`, and none has been faked.

If the platform CSPRNG fails, the attempt fails with an operator-facing error.
It does not fall back to a weaker source: an identity built from predictable
bytes would authenticate successfully and be forgeable.

## Surfaces this platform cannot satisfy

These are gaps in the frozen upstream contract, recorded rather than papered
over. None has a substitute in this crate, because an invented analogue cannot
later be told apart from a real implementation.

**Tailscale authentication is unreachable.** The Gateway handshake registry can
reject a client with `AuthTailscaleIdentityMissing`, `AuthTailscaleProxyMissing`,
`AuthTailscaleWhoisFailed` or `AuthTailscaleIdentityMismatch`. Supplying that
identity needs an app-accessible LocalAPI Unix socket or an explicit loopback
proxy, and a stock sandboxed Android deployment offers neither. This crate
therefore reports those four codes as a platform limit and explicitly does not
advise retrying or re-entering the token, because neither can succeed. The
transport itself is `cfg(unix)`-gated upstream and is not a dependency here.

**Password authentication is not implemented.** The three `AuthPassword*` codes
are reported as unsupported rather than retried; this client sends a token.

**Pairing is not implemented.** `PairingRequired` is reported as needing another
client, and the frozen Android contract grants no pairing authority, so this is
a permanent property of the surface rather than a gap to fill later.

**This client requests less authority than it is allowed.** The frozen contract
in `claw-clients` permits the Android operator UI profile
`operator.admin`, `operator.approvals`, `operator.read`, `operator.talk.secrets`
and `operator.write`. That is a ceiling, not a quota:
`validate_gateway_profile` admits any subset of it. This crate requests
`operator.read` alone, because it performs exactly four Gateway operations —
connect, subscribe to state, shut down, and take then drop issued device tokens
— and none of the other four scopes has a caller here. Scopes should arrive with
the feature that needs them, so a reviewer can see the privilege and the code
that uses it in the same diff. The tests in `src/session.rs` assert this against
the contract itself rather than against a copy of it: one validates the real
configuration through `validate_gateway_profile`, one confirms that adding
`operator.pairing` is refused, and one reads the ceiling out of the surface
contract and fails if this client ever silently widens to all of it.

**No Android Keystore integration, and no SSH.** SSH is absent from this crate's
dependency tree entirely, so its requirement for caller-provisioned key and
`known_hosts` paths does not arise here. The identity this crate generates is
held in memory for the life of the process and is never written anywhere, so
there is nothing yet for a hardware-backed keystore to protect. That is a real
omission for any future build that persists an identity, and it is deliberate
only in the sense that persistence has not been implemented.

**No discovery, and a warning about adding it.** There is no `mdns-sd` here and
no dependency that pulls it. If discovery is added, note that Android requires
`CHANGE_WIFI_MULTICAST_STATE` plus a held `WifiManager.MulticastLock`; without
the lock, discovery returns an empty result set on many devices, which is
indistinguishable from a quiet network. A missing permission or unheld lock must
surface as a reported condition, never as zero results.

**All four of the above converge on one missing component.** Holding a multicast
lock, reaching Android Keystore, and hosting an activity at all require JNI, and
JNI requires `unsafe`. This workspace sets `unsafe_code = "forbid"` and root
members must inherit workspace lints exactly, so no in-tree crate can contain
that code. This is a structural limit of the current repository, not a task
someone forgot to do.

## Packaging

There is no APK build here and no CI job builds this crate; adding a workflow is
out of scope by instruction. When a shell exists, `cargo apk` is the natural
route — it drives `aapt2` and `apksigner` from the SDK build-tools directly and
invokes neither Gradle nor Node, which keeps npm out of the mobile packaging
path by construction rather than by exception. It has not been exercised.

## Testing

```powershell
cargo test -p gta-claw-android --all-targets
cargo clippy -p gta-claw-android --all-targets -- -D warnings
cargo fmt --all -- --check
```

Host unit tests cover input policy, redaction, the state machine's generation
guard, attempt-slot release on future drop, identity generation and its failure
path, the plaintext opt-in reaching the transport configuration, and the mapping
from every Gateway handshake detail code to an operator-facing remedy.

Tests were run on **Windows 11 x86_64**, rustc/cargo 1.97.0. Local green is a
property of that machine, not of the product.

The crate cross-compiles for `aarch64-linux-android`, `armv7-linux-androideabi`
and `x86_64-linux-android` against NDK 30.0.14904198 at API 24, and
`cargo clippy --target aarch64-linux-android -- -D warnings` is clean. That is a
compilation result only.

**Nothing here has been executed on Android.** There is no emulator, AVD, system
image or device on the machine that produced these results, and no CI job builds
this crate for any Android target. Until a job runs against a real NDK in CI, no
Android claim in this file should be treated as validated.

**What a cross-compile does and does not prove.** A successful
`cargo check`/`cargo clippy` for an Android target proves the Rust type-checks
and that the NDK's target clang accepted every C dependency. It proves nothing
about whether the application starts, whether the Gateway handshake succeeds
over a real radio, whether reconnection survives a network change, or how any of
this behaves under Android's process lifecycle. Those are the failures that only
appear on hardware, and none of them is covered here. **The first person to run
this on a device should expect to find things**, and finding them will not mean
the checks above were wrong — it will mean they were measuring something else.
