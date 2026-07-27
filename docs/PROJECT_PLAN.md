# GTA-Claw — architecture and design decisions

This document explains *why* the Rust workspace is shaped the way it is. For what exists today and
what does not, see [PROGRESS.md](PROGRESS.md). For the deletion checklist governing the surviving
Node service, see [legacy-node-port-obligations.md](legacy-node-port-obligations.md).

## 1. The goal

GTA-Claw is an npm-free, pure-Rust reimplementation of the OpenClaw agent platform, pinned against
a frozen upstream baseline (`openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85`, package
`2026.7.2`). "Reimplementation" is meant literally: the upstream *contracts* are frozen data in
`compat/`, and a Rust crate either satisfies a contract with tested behavior or reports that it does
not. There is no third state.

The predecessor is a Node/TypeScript service that loaded a system prompt and a set of skills from
remote URLs and evaluated skill JavaScript in a V8 isolate. That design is not being ported. It is
being replaced, and two of its capabilities are being deliberately removed rather than reproduced:
remote JavaScript evaluation, and self-mutating package-manager updates.

## 2. Two workspaces

| Workspace | Members | Targets |
|---|---|---|
| root `Cargo.toml` | 31 crates in `crates/`, 6 binaries in `apps/` | Linux, macOS, Windows |
| `desktop/Cargo.toml` | `apps/gta-claw-desktop` | Windows and macOS only |

The root manifest carries `exclude = ["android", "desktop", "ios"]`, so a root build never resolves
the desktop graph.

**Why the split is not a stylistic choice.** The desktop shell needs Slint, and the base-owned
trusted supply-chain policy under `.github/trusted/desktop-supply-chain-policy` refuses a Slint
dependency in every location available to a *root workspace member*. A separate workspace with its
own `Cargo.lock` and its own `deny.toml` is the only shape that policy admits. The same constraint
is why `apps/gta-claw-android` and `apps/gta-claw-ios` are UI-independent client cores with no UI
in this repository at all — their READMEs record the validator verdicts for every alternative
shape that was tried.

Three CI consequences follow, and all three are enforced:

1. Root `cargo metadata` must contain no Slint crate.
2. Every desktop command must pass `--manifest-path desktop/Cargo.toml`.
3. A desktop build on Linux must *fail*, and there is a job that asserts the failure rather than
   merely skipping the platform.

## 3. Crate layering

The layering is expressed in the manifests, so a violation is a compile-time event rather than a
review comment.

```
claw-domain                      no workspace dependencies
   ↑
claw-protocol                    depends on claw-domain only
   ↑
claw-application                 depends on claw-protocol + claw-domain only
   ↑
claw-runtime                     depends on claw-application (feature "runtime-ports") + claw-domain
   ↑
gta-claw-daemon                  composition root
```

- **`claw-domain`** holds the types and invariants every runtime shares. It has no workspace
  dependencies, so nothing can smuggle transport or configuration concerns into the domain.
- **`claw-protocol`** owns everything that crosses a process boundary: the small headless command
  and event vocabulary (`PROTOCOL_VERSION = 1`), and the OpenClaw Gateway v4 wire contract with its
  negotiation reducers, method and event catalogs, and authorization rules. It is
  transport-independent by construction — the reducers are pure functions, which is what makes both
  a server (`claw-gateway`) and a client (`claw-gateway-client`) able to share one contract without
  either depending on the other.
- **`claw-application`** defines the use cases and the port traits adapters must satisfy:
  `ProviderPort`, `ToolPort`, `StatePort`, `GoalStorePort`, `ApprovalPort`, `ClockPort`,
  `ContextEnginePort`. Ports and composition machinery are behind the `runtime-ports` and
  `composition` features, so a front end that links this crate only for `Application` and
  `SystemProbe` does not inherit `claw-domain`, `secrecy` or `url`.
- **`claw-runtime`** owns everything between "an operator submitted something" and "the turn
  reached a terminal state". It performs no I/O: every external dependency is a port trait.
  Concurrency is limited to `CancellationToken`, `TaskTracker` and bounded `mpsc` channels — no
  unbounded queues, no detached tasks.

**Capability crates deliberately sit outside this stack.** `claw-tools`, `claw-skills`,
`claw-memory`, `claw-providers`, `claw-worker`, `claw-relay`, `claw-discovery`, `claw-migrate`,
`claw-config` and others depend on the core either minimally or not at all. They are typed,
independently testable units. The composition root, not the crate itself, decides which one satisfies
which port. That is what makes swapping a stand-in for a real adapter a one-line change instead of a
refactor.

## 4. Ports and adapters

The rule is: **the core defines the trait, the edge implements it, and only the composition root
knows both.**

Two invariants are enforced by the composition rather than left to reviewers, because audits of
sibling crates kept finding the same two defects:

1. **A security decision is never reused.** Every action that needs authority asks for it at the
   moment of the action and receives a capability that dies when the run drains or when its
   lifetime elapses, measured against the clock read at redemption.
2. **Validated objects cross boundaries, never re-resolvable names.** A destination is a set of
   checked addresses, a tool is a resolved binding, a route is a matched route — never a string that
   a later stage looks up again. This closes the entire class of time-of-check/time-of-use bugs
   where a name is validated once and resolved differently later.

The daemon also proves its own shutdown: tasks are spawned through a tracker, terminations are
counted from a guard's `Drop` so a cancelled task still counts, and the process compares the two
counters. "Shutdown returned" is not accepted as evidence that shutdown happened.

## 5. Plugins are WebAssembly components, not scripts

The legacy service executed remotely supplied JavaScript in an `isolated-vm` isolate, with a
`node:vm` fallback when the native module was unavailable. The replacement is not a safer script
engine. It is not a script engine.

`claw-plugin-api` defines the contract — ABI version, deny-by-default capability model with typed
scopes, per-plugin resource limits, a strict manifest schema, a trust model covering load origins
and signing keys, and all 137 frozen upstream plugin descriptors. `claw-plugin-host` runs it on
wasmtime's Component Model.

Why this shape:

- **No ambient authority.** The linker contains exactly the nine interfaces of
  `gta-claw:plugin@1.0.0`. There is no WASI of any kind — wasmtime is compiled without the WASI
  crates — so there is no ambient filesystem, process, socket, environment or high-resolution clock.
  The host additionally refuses to instantiate a component whose imports are not on the allow list.
- **Capabilities are per plugin and checked at the boundary.** Imports are always linked, but every
  host function first proves the calling plugin holds the capability *and* that the concrete
  arguments fall inside the grant's scope. Filesystem-read on one root does not grant another.
- **The operator holds a ceiling.** A manifest's requests are intersected with an operator-owned
  policy, so a manifest can only ever narrow what the operator allowed.
- **Limits are the engine's job, not the guest's.** Fuel bounds instructions, an epoch ticker bounds
  wall-clock time, a `ResourceLimiter` bounds memory, tables and instances, and a bounded gate caps
  concurrent host calls.
- **Crash isolation is structural.** Each plugin owns its own `Store`; a trap destroys that store
  and marks that plugin faulted, touching no other plugin and no host state.

Skills follow the same principle from the other direction. `claw-skills` executes native Rust
handlers, a declarative HTTP port, or the Wasm host. Legacy JavaScript skills are not executable at
all — they can only be *classified* for manual migration, and a port must present signed evidence.

The rule this all serves is recorded in the obligations document and is not negotiable: **never add
an embedded JavaScript engine to Rust.**

## 6. The provider layer is a typed trait, not an SDK

The legacy service delegated model access to `@github/copilot-sdk`, which bridged JSON-RPC to a
Copilot CLI subprocess. Three properties of that arrangement are unacceptable in the replacement:
the process boundary was a package-manager-installed Node binary, the payloads were untyped JSON,
and the transport stack was whatever Node supplied.

`claw-provider-sdk` replaces it with a `Provider` trait and:

- **No untyped JSON in the public API.** The only two places where raw JSON is unavoidable —
  JSON-Schema tool parameter declarations and model-generated tool-call arguments — are wrapped in
  validated `ToolParameters` and `ToolArguments` newtypes.
- **A closed error taxonomy**, so a caller can exhaustively match on failure instead of matching
  strings.
- **Reliability as policy, not as retry loops sprinkled through call sites**: retry, circuit
  breaking, and concurrency limits are crate-level types.
- **Secrets confined to `ApiKey` and `SecretString`**, neither of which implements
  `serde::Serialize`, both of which redact themselves in `Debug` and `Display`.
- **Pure-Rust transport: `hyper` over `rustls`.** No OpenSSL, no Node. This is also what makes the
  binaries statically analyzable for packaging, where the Linux prototype pins the exact glibc/libm/
  libgcc objects it ships.

`claw-providers` sits on top with the frozen 78-provider registry. Three wire dialects are really
implemented — the OpenAI `chat/completions` dialect, Anthropic `POST /v1/messages`, and GitHub
Copilot through a pure-Rust RFC 8628 device authorization flow. Every other descriptor is registered
with exact identifiers and typed metadata and reports `ImplementationStatus::RegistrationOnly`. A
registry entry is never mistakable for a working client.

Around the registry sit the four rules that make an identifier usable: alias resolution that refuses
an alias table capable of sending a caller to the wrong provider, strict configuration
deserialization with endpoint and header validation, credential-mode checking, and capability-based
routing.

## 7. Frozen contracts and conformance discipline

`compat/` is the parity trust root, and it is treated as data, not as documentation.

| Tree | Role |
|---|---|
| `compat/upstream/` | The frozen upstream baseline: 10 inventories (717 rows), a feature-ledger schema, a 120-case enabled-test oracle, a 32-case reachability corpus, three ledgers (47 rows), and hardcoded digests. `validate.ps1` seals it. |
| `compat/legacy/` | The frozen behavior contract of the Node service being replaced, including its config env mapping and HTTP fixtures. |

The discipline that follows:

- **Counts are constants in code, checked against the frozen data.** `FROZEN_PROVIDER_COUNT = 78`,
  a 29-entry channel registry, a 51-entry bundled skill registry, `TOTAL_PLUGINS = 137`, an 18-route
  HTTP inventory, 47 configuration domains. If a registry and its inventory disagree, a test fails.
- **`claw-config` generates its legacy mapping table from the frozen artifact at build time** and
  fails the build on drift. The generated table embeds every behavioral field, so a contract change
  is visible in code review rather than hidden in a rule engine.
- **`claw-conformance` refuses unverifiable claims.** An implementation claim must cite a Rust test,
  and the harness proves that test is literally declared in a libtest target root of a package
  admitted by the workspace topology, following `mod` declarations and exact `#[path]` overrides. It
  rejects orphan files, unlisted packages, cross-package paths and test-disabled targets.
- **Honest status enums beat optimistic prose.** `ImplementationStatus::RegistrationOnly` for
  providers and plugins, `ChannelDescriptor` status for channels, and `DispatchError::NotImplemented`
  for catalogued Gateway methods all exist so that coverage of an *identity* is never reported as
  coverage of a *behavior*.
- **When the seal and honesty conflict, honesty wins outside the seal.** `compat/upstream/validate.ps1`
  requires every ledger feature to remain `unimplemented`, so acceptance evidence for work that *is*
  done lives in `docs/ledger/` instead, leaving the sealed tree byte-identical.

## 8. The migration ratchet

`crates/claw-repo-policy` is a test that fails the build when the JavaScript surface grows. It scans
the working tree, the Git index and the workflow files, and rejects:

- the extensions `js`, `jsx`, `mjs`, `cjs`, `ts`, `tsx`, `mts`, `cts`, `node`;
- the manifests `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
  `pnpm-lock.yaml`, `bun.lock`, `bun.lockb`, `deno.json`, `deno.jsonc`;
- the directories `node_modules`, `.yarn`, `.pnpm-store`;
- the workflow commands `node`, `npm`, `npx`, `pnpm`, `yarn`, `bun`, `deno`, `corepack`;
- a container definition that reintroduces a Node base image;
- tracked symlink and gitlink modes.

Exactly 22 legacy paths are grandfathered by an explicit inventory, with a TypeScript ceiling of 18
that may only be lowered. An inventory entry whose file no longer exists is reported as stale, so
the allowlist cannot rot into a permanent exemption, and the one exempt container is exempt only
while it remains inventoried.

The design consequence is that the legacy service can only ever be *deleted*, never extended. Any
new behavior must land in Rust.

## 9. Security posture as a design input

These are architectural constraints, not a hardening checklist applied afterwards.

- `unsafe_code = "forbid"` across the root workspace; `deny` in `desktop/`, where Slint's generated
  item-tree macros locally allow their own audited internals.
- Tools are deny-by-default with closed parameter schemas. A tool cannot run without an
  authorization that only the registry can mint, after a permission broker granted the exact
  capability and resource. Absent configuration means refusal.
- Every queue, buffer, frame, retry series, identifier budget and byte budget in the Gateway client
  is bounded. Frame size limits are phase-aware — 64 KiB before authentication, 25 MiB after — and
  are applied from the frame header through fragmented-message assembly, before allocation.
  Compression is never offered and any negotiated extension is rejected.
- Remote plaintext `ws://` requires an explicit opt-in flag; `wss://` uses rustls.
- No CLI accepts a token as a command-line argument, because argv is world-readable on the platforms
  that matter. Tokens arrive on standard input, bounded to 4096 bytes, and `--token-file` fails
  closed on every platform rather than claiming ownership and link-safety guarantees that cannot be
  proven portably across filesystems.
- Configuration secrets are persisted only as validated environment or platform-store *references*.
  `claw-crestodian`'s typed configuration writes refuse any path that reaches inference routing
  (`agents.*`, `auth.*`, `cli.*`, `models.*`, root `tools.*`) or credential resolution (`$include`,
  `env.*`, `plugins.*`, `secrets.*`).
- Updates are signed, resumable and rollback-safe. Package-manager and `curl | sh` self-mutation are
  forbidden; on Linux the updater refuses outright and defers to the system package manager.
- Security audit records travel a separate port from ordinary tracing, so evidence cannot be routed
  through a lossy logging pipeline.

## 10. Verification strategy

| Layer | Mechanism |
|---|---|
| Types | Closed enums, newtypes and validated objects; `missing_docs`, `unreachable_pub`, clippy `pedantic` + `nursery` promoted to errors in CI. |
| Unit and integration | `cargo test --workspace --all-targets --locked`, plus per-crate suites (Gateway wire, provider transport, frozen inventories, plugin sandbox). |
| Determinism under concurrency | A dedicated CI job repeats deterministic `claw-gateway-client` regressions on `macos-15-intel`. |
| Compatibility floor | An MSRV job runs `cargo +1.94.0 check --workspace --all-targets --locked`. |
| Architecture | `claw-repo-policy` for the JS/TS ratchet; `cargo metadata` assertions for the Slint boundary. |
| Parity | `claw-conformance` over `compat/upstream`, with evidence verification. |
| Supply chain | `cargo-audit` on both lockfiles, `cargo-deny` lock and exception policy, per-target desktop dependency policy for Windows x64/ARM64 and macOS Intel/ARM64, and the trusted desktop policy validator compiled only from the protected base SHA. |
| Packaging | Per-OS prototypes in `packaging/` producing tarballs, `.deb`, `.rpm` and OCI layouts on Linux; app bundles on macOS; MSI/MSIX on Windows — each with SBOM, provenance and self-tests. |

## 11. What is intentionally absent

Recording these prevents them from being re-proposed as gaps:

- **No embedded JavaScript or script engine**, in any crate, ever.
- **No `@github/copilot-sdk`** in the Rust dependency graph, and no Copilot CLI subprocess —
  `claw-config` deliberately refuses to convert `COPILOT_CLI_PATH`.
- **No remote role/skill URL loading** as the source of the agent's behavior. Configuration is
  strict typed JSON5 with layered resolution.
- **No WASI in the plugin host.**
- **No Android or iOS user interface in this repository**, and no Linux desktop build.
- **No self-updating via a package manager or `curl`.**
- **No unbounded queue or detached task** in the runtime or the Gateway client.
