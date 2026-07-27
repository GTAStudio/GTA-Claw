# GTA-Claw — implementation status

This document reports what exists, what is partial, and what is blocked. It replaces an earlier
tracker that described 20 TypeScript files as "20/20 complete"; that product no longer describes
this repository.

**The authoritative source for anything concerning the legacy Node service and its replacement is
[legacy-node-port-obligations.md](legacy-node-port-obligations.md).** Where this document
summarizes that file, the obligations file wins.

## How to read this

Two different questions get confused constantly, so they are tracked separately:

| Question | Answer lives in |
|---|---|
| Does crate X implement its behavior, with tests? | The crate table below. |
| Is that behavior composed into a running production service? | The composition section — and today the answer is **no**. |

Status vocabulary:

| Status | Meaning |
|---|---|
| **Implemented** | The crate's stated scope is implemented and covered by tests in-tree. |
| **Partial** | Part of the stated scope is implemented; the crate's own docs name what is not. |
| **Registration-only** | Identifiers and typed metadata are frozen and correct; executable behavior is explicitly *not* claimed, and the code reports that status at runtime. |
| **Blocked** | Work cannot proceed without something that does not exist yet. |

Nothing in this file may claim completion that the code does not report about itself. Every crate
listed as registration-only says so in its own API (`ImplementationStatus::RegistrationOnly`,
`DispatchError::NotImplemented`, and equivalents), which is how a reader can check this table
without trusting it.

## Composition status — read this before anything else

`gta-claw-daemon` is the composition root of the product. Its lifecycle, authorization flow, task
tracking and shutdown path are real and are what will ship. **Its subsystem adapters are
deterministic stand-ins**, stated as such in the crate's own documentation. Its manifest depends on
`claw-application`, `claw-domain`, `claw-platform` and `claw-protocol` only — not on
`claw-providers`, `claw-runtime`, `claw-channels`, `claw-config`, `claw-tools` or
`claw-observability`.

Consequently:

- No Rust binary in this repository currently serves the full agent product.
- The Node service in `src/` remains the only fully composed production service.
- `docs/legacy-node-port-obligations.md` records this as an **unowned integration blocker** against
  `src/index.ts`: "No branch currently constructs the complete production service."

Everything below should be read against that fact.

## Library crates

### Core

| Crate | Status | Notes |
|---|---|---|
| `claw-domain` | Implemented | Types and invariants; no workspace dependencies. |
| `claw-protocol` | Implemented | Headless command/event vocabulary at `PROTOCOL_VERSION = 1`, plus the Gateway v4 wire contract, negotiation, catalogs and authorization. |
| `claw-application` | Implemented | Use cases, port traits and composition machinery. `ClientCommand::Submit` deliberately returns `Unsupported("message transport is not configured")` until a transport adapter is composed. |
| `claw-runtime` | Implemented | Session/turn machine, stream assembly, approval-gated tools, goals, suspension, workers, context-engine harness — all over ports, no I/O. |

### Model providers

| Crate | Status | Notes |
|---|---|---|
| `claw-provider-sdk` | Implemented | Typed models, streaming decoder, closed error taxonomy, retry/circuit/limit policies, credential ports, `hyper` + `rustls` transport. |
| `claw-providers` | Partial by design | All 78 frozen descriptors registered. Real clients: OpenAI-compatible dialect, Anthropic `/v1/messages`, GitHub Copilot via RFC 8628 device flow. **Every other provider is registration-only** and says so. |

### Capabilities

| Crate | Status | Notes |
|---|---|---|
| `claw-tools` | Implemented | Closed schemas, deny-by-default grants, per-invocation authorization. |
| `claw-skills` | Partial | Native, declarative-HTTP and Wasm execution over the 51-entry bundled registry. Legacy JavaScript skills are **not executable** — only classifiable for migration, and a port requires signed evidence. This is the deliberate break, not a gap. |
| `claw-plugin-api` | Implemented (contract) / Registration-only (inventory) | ABI, capability model, limits, manifest schema and trust policy are implemented. All 137 upstream plugin descriptors are present and every one reports `RegistrationOnly`. |
| `claw-plugin-host` | Implemented (host) | The wasmtime Component Model host, sandbox, limits and lifecycle are real. It contains **no ports of the 137 upstream plugins**. |
| `claw-memory` | Implemented | Deterministic context assembly with anchor preservation. |
| `claw-goals` | Implemented | The durable on-disk adapter behind `GoalStorePort`; earlier adapters in the tree were in-memory fakes. |

### Transports and interop

| Crate | Status | Notes |
|---|---|---|
| `claw-gateway` | Partial | Transport, lifecycle, dispatch registry, event bus and authorization are implemented. Payload schemas are this crate's own design and are **not** claimed byte-compatible with upstream, because the frozen inventory pins method identities only. Catalogued methods that are not really implemented answer `DispatchError::NotImplemented` rather than being absent. Persistence ships as an in-memory adapter; durable adapters live outside the crate. |
| `claw-gateway-client` | Implemented | Bounded `ws://`/`wss://` transport and lifecycle. No server, RPC handlers or GUI, by design. |
| `claw-http-api` | Partial | The frozen 18-route surface is implemented over narrow ports. The legacy service's own routes and concrete `ApiServices` adapters are **not all present** — see the `src/server.ts` row in the obligations file. |
| `claw-mcp` | Implemented | Server, stdio/streamable-HTTP/legacy-SSE clients, OAuth, configured-server lifecycle, conversation projection. |
| `claw-acp` | Implemented | ACP interoperability over `claw-mcp`. |
| `claw-channel-sdk` | Implemented | Transport-neutral contracts; owns no network client or credential persistence. |
| `claw-channels` | Partial / mostly registration-only | All 29 official channels registered with capabilities and auth modes. Executable behavior is narrow — outbound webhook text for some entries — and `ImplementationStatus` keeps registry coverage separate from working integrations. Teams, Telegram, Discord and WhatsApp have **registry/auth metadata only**, not compatibility transports. |
| `claw-relay` | Implemented | Authentication, framing, connection isolation, CDP policy, routing and lifecycle. Transport independent: an acceptor must supply upgrades and frames. |
| `claw-worker` | Implemented | The closed worker admission protocol, ticket redemption and its own crypto surface. |
| `claw-clients` | Implemented (contracts) | Connection profiles, capability negotiation, session projections and bounded event delivery. GTA-Claw does not ship the upstream mobile apps, Control UI or browser extension. |

### Platform, configuration and governance

| Crate | Status | Notes |
|---|---|---|
| `claw-platform` | Implemented | Native adapters for the application core's ports. |
| `claw-config` | Partial | All 47 frozen domains modeled, JSON5 loading, schema generation, atomic writes with rollback, layered resolution, typed reload, and generated legacy env conversion validated against the frozen artifact at build time. The obligations file records the remaining work: the production daemon still needs the legacy import/override path and acceptance coverage. Windows durability after sudden power loss is explicitly not claimed. |
| `claw-crestodian` | Implemented | Guided setup, backup/restore, recovery classification, closed `/crestodian` rescue grammar, ring-zero single-tool restriction, typed configuration writes. |
| `claw-security` | Implemented (primitives) | Identity, roles, scopes. Deliberately contains no network client, TLS terminator, database, keyring or private-key persistence — those are platform adapters. |
| `claw-observability` | Implemented (primitives) / Not composed | Telemetry, metrics, audit and redaction exist. **No shipped binary installs the subscriber**; no `apps/` manifest depends on this crate. The obligations file lists `src/utils/logger.ts` as **owner required**. |
| `claw-migrate` | Implemented | Side-effect-free plans, verified backups, apply and rollback for Claude, Codex, Hermes and legacy state. |
| `claw-discovery` | Implemented (oracles) | Wire codecs and fail-closed policy oracles. Contains no network runtime, process spawning or container client, on purpose. |
| `claw-conformance` | Implemented | The parity harness and its evidence verifier. It reports parity; it does not create it. |
| `claw-repo-policy` | Implemented | The JS/TS ratchet, container check and index scan, with planted-violation tests proving the checks actually fire. |

## Binaries

| Binary | Status | What actually works |
|---|---|---|
| `gta-claw-cli` | Partial | `--version`, `--help`/`-h`, `health` (prints `healthy runtime=…`), and `gateway health` — one real authenticated Gateway v4 connection, one `operator.read` `health` RPC, bounded shutdown, eight typed exit categories and a deterministic `--json` schema-version-2 report. `send` **fails on purpose**: `unsupported operation: message transport is not configured`. `--token-file` is parsed but always fails closed. Identity is one-shot `--ephemeral-device` only; durable secure-storage identity is deferred. |
| `gta-claw-daemon` | Partial | `--probe` prints one health line. Serving starts, announces `ready protocol=1` and health, handles `SIGTERM`/`SIGINT` (Windows: Ctrl-C/Break/Close/Shutdown) and a `shutdown` control line, and reports a provable drain summary. **The subsystems it composes are stand-ins.** |
| `gta-claw-tui` | Partial | Connects to a Gateway, renders Sessions / Workspace / Runs / Diff / Artifacts / Help, supports the command palette, approve/deny prompts and refresh, and falls back to a single `--plain` snapshot when standard output is not an interactive terminal. Its capability is bounded by what the Gateway it talks to actually implements. |
| `gta-claw-updater` | Implemented | Signed, resumable, rollback-safe update with staged installs and a restart-required outcome. On Linux it refuses and defers to the system package manager. |
| `gta-claw-android` | Partial | Client core only: endpoint and credential intake, Gateway identity, transport assembly, connection lifecycle. **No Android UI exists in this repository** and cannot, under the trusted supply-chain policy. |
| `gta-claw-ios` | Partial | Same scope and same constraint. |
| `gta-claw-desktop` | Partial | A native Slint shell for Windows and macOS with a four-stage onboarding model (welcome, device authorization, workspace trust, Gateway connection) driving a real `claw-gateway-client` connection, plus a product shell. Linux is rejected by design and CI asserts the rejection. |

## Legacy replacement obligations

`docs/legacy-node-port-obligations.md` is the authoritative checklist. Summarized by outcome:

| Outcome | Legacy modules |
|---|---|
| **Blocked** — the Rust owner exists but the behavior is not composed or not compatible | `src/auth/deviceFlow.ts`, `src/bot/teamsBot.ts`, `src/channels/discordGateway.ts`, `src/channels/messageProcessor.ts`, `src/channels/telegramPolling.ts`, `src/channels/whatsappWebhook.ts`, `src/engine/copilotEngine.ts`, `src/engine/sessionManager.ts`, `src/server.ts`, `src/utils/splitMessage.ts` |
| **Partial** | `src/config.ts` → `claw-config`; `src/loader/skillLoader.ts` → `claw-skills` |
| **Partial by deliberate break** | `src/engine/toolExecutor.ts` — JavaScript evaluation must be **removed, not ported** |
| **Owner required** — no Rust crate currently owns the behavior | `src/loader/roleLoader.ts`, `src/updater/sdkUpdater.ts`, `src/utils/logger.ts`, `src/utils/proxy.ts` |
| **Unowned integration blocker** | `src/index.ts` — full production composition |

Build and dependency obligations (`Dockerfile`, `package.json`, `package-lock.json`, `tsconfig.json`,
`@github/copilot-sdk`, `botbuilder`, `restify`, `undici`, `ws`, `pino`, `isolated-vm`/`node:vm`) are
listed in the same file with their exact removal conditions. `isolated-vm` and `node:vm` are a
deliberate removal with no Rust equivalent, now or later.

The ratchet currently grandfathers 22 legacy paths, with a TypeScript ceiling of 18 files that may
only be lowered. `crates/claw-repo-policy` fails the build if that surface grows, if an inventory
entry goes stale, or if a container definition reintroduces a Node base image.

## Continuous verification

These run in CI and are the evidence behind every "Implemented" above.

| Check | Command |
|---|---|
| Formatting | `cargo fmt --all -- --check` |
| Type check | `cargo check --workspace --all-targets --locked` |
| Lints | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| Tests | `cargo test --workspace --all-targets --locked` |
| MSRV floor | `cargo +1.94.0 check --workspace --all-targets --locked` |
| Gateway determinism | Repeated `claw-gateway-client` regressions on `macos-15-intel` |
| Desktop | The same four commands plus `cargo build`, each with `--manifest-path desktop/Cargo.toml`, on Windows and macOS |
| Desktop platform boundary | Linux desktop graph must exclude Slint, and `cargo check` on Linux must fail |
| Slint boundary | Root `cargo metadata` must contain no Slint crate |
| Supply chain | `cargo-audit` on both lockfiles; `cargo-deny` lock and exception policy; per-target desktop dependency policy for Windows x64/ARM64 and macOS Intel/ARM64 |
| Architecture ratchet | `cargo test -p claw-repo-policy` |

Packaging prototypes run from `linux-packaging.yml`, `macos-packaging.yml` and
`windows-packaging.yml`. `docker-publish.yml` still builds the **legacy Node image**; switching it
to the native service is step 5 of the deletion checklist.

## What would change this document

The next status change worth recording is not another crate. It is the composition: when
`gta-claw-daemon` stops using stand-ins and binds real adapters — provider, runtime, state, tools,
channels, HTTP, config and a shared network transport — and passes the behaviors and HTTP shapes in
`compat/legacy`, the "Composition status" section above is what gets rewritten first, and legacy
files start leaving the inventory in the same change that deletes them.
