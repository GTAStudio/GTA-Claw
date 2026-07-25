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
path, and the plaintext opt-in reaching the transport configuration.

No test has been run on an Android device or emulator, and this crate has never
been cross-compiled as part of a landed CI job.
