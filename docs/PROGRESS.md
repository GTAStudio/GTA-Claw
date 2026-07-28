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
| Is that behavior composed into a running production service? | The composition section — and the answer is now **partly, for most of them**, with the exceptions named there. |

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

`gta-claw-daemon` is the composition root of the product, and it now composes a real service.
`apps/gta-claw-daemon/src/main.rs` runs `production.rs`, whose manifest depends on **20 `claw-*`
crates** — `claw-application`, `claw-channel-sdk`, `claw-channels`, `claw-config`,
`claw-crestodian`, `claw-domain`, `claw-gateway`, `claw-goals`, `claw-http-api`, `claw-memory`,
`claw-observability`, `claw-platform`, `claw-plugin-api`, `claw-plugin-host`, `claw-protocol`,
`claw-provider-sdk`, `claw-providers`, `claw-runtime`, `claw-security`, `claw-skills` — plus
`gta-claw-updater`.

What a `gta-claw-daemon` serve actually does, in order: resolves layered configuration (or migrates
the legacy environment when no file is given), reports `claw-crestodian` recovery guidance, installs
`claw-observability`'s redacting subscriber, derives one shared `claw-provider-sdk` proxy policy,
fetches the role document over it, activates signed plugins on the real `claw-plugin-host` under a
bounded candidate limit and deadline, brings up `claw-providers::GitHubCopilot` or leaves the
provider pending Device Flow, starts supervised Telegram and Discord transports, opens a durable
JSON-lines audit log and a durable Gateway pairing store, binds a `claw-gateway` server and three
`TcpListener`s (main HTTP, legacy HTTP, loopback-only MCP), announces the bound addresses, serves a
transactional reload, and drains into an accounted stop summary. A routable bind is refused unless
`--tls-terminated-by-frontend` is passed.

Consequently:

- **A Rust binary now serves real traffic for most of the agent product.** `gta-claw-daemon` accepts
  connections on four listeners and answers them from the shipped crates, not from fixtures.
- It does **not** yet serve all of it. Behind those listeners, these ports are uncomposed and a
  reader should expect exactly this if they run it: **durable session and turn state** does not exist
  (`claw-state` is absent; the daemon's `RuntimeStateStore` is a process `Mutex<HashMap>`, so a
  restart loses every session and turn); **`claw-tools` is a dependency of no binary**, so the model's
  tool surface is signed plugin registrations plus the durable goal tool and none of `claw-tools`'
  closed schemas, path confinement or validated destinations; **skill execution is not dispatched**
  (the daemon counts `claw_skills::registry()` and the `WasmSkillHost` bridge has no production
  caller); **approvals are `claw_runtime::approval::SilentApprovalPort`**, which approves everything
  without asking; **watch pairing and task-flow webhooks are wired to `DisabledExternalPorts`** and
  fail closed; and **plugin/skill HTTP bypasses the shared proxy policy** by going through
  `claw-plugin-host`'s `PinnedHttpTransport`.
- The deterministic stand-ins still in the tree — `adapters/model.rs`, `state.rs`, `support.rs`,
  `plugins.rs`, `ingress.rs`, `engine.rs`, driven by `compose.rs` — are **no longer the serving
  path**. `main.rs` calls `control::serve_production`, not `control::serve`; the stand-in graph is now
  an in-process contract harness for the older `claw-application::composition` port family, and it
  says so in its own module documentation. Reading those files as a description of what the daemon
  runs is now wrong in the opposite direction from the old error.
- The Node service in `src/` is still the only service this repository **ships**: `Dockerfile` and
  `docker-publish.yml` build and run `dist/index.js`.
- **No obligation has been discharged.** `docs/legacy-node-port-obligations.md` now records most rows
  as **composed — evidence outstanding**, because no test under `apps/` reads `compat/legacy`. The
  composition is unproven against the frozen contract.

Across all of `apps/`, the complete set of `claw-*` dependencies is now 22 crates: the daemon's 20
plus `claw-clients` and `claw-gateway-client`. The crates below that are still depended on by no
shipped binary are `claw-tools`, `claw-mcp`, `claw-acp`, `claw-relay`, `claw-worker`, `claw-migrate`,
`claw-discovery` and `claw-conformance`. The daemon's MCP listener serves `claw-http-api`'s
`mcp_router`, not `claw-mcp`.

The distinction the obligations file draws — is the missing piece an **owner**, an
**implementation**, a **composition**, or **evidence**? — is what changed. For the large majority of
rows the answer moved from composition to evidence. For a few it did not, and that file says which
part of the composed service fails to reach them.

Everything below should be read against that.

## Library crates

### Core

| Crate | Status | Notes |
|---|---|---|
| `claw-domain` | Implemented | Types and invariants; no workspace dependencies. |
| `claw-protocol` | Implemented | Headless command/event vocabulary at `PROTOCOL_VERSION = 1`, plus the Gateway v4 wire contract, negotiation, catalogs and authorization. |
| `claw-application` | Implemented | Use cases, port traits and composition machinery. `ClientCommand::Submit` deliberately returns `Unsupported("message transport is not configured")` until a transport adapter is composed. |
| `claw-runtime` | Implemented | Session/turn machine, stream assembly, approval-gated tools, goals, suspension, workers, context-engine harness — all over ports, no I/O. `gta-claw-daemon` composes `Runtime` over a `claw-memory` context engine, a durable `claw-goals` store and an in-memory state port; the approval gate is composed with `approval::SilentApprovalPort`, which approves every request without asking, so the gate exists in the running service but nothing interactive sits behind it. |

### Model providers

| Crate | Status | Notes |
|---|---|---|
| `claw-provider-sdk` | Implemented | Typed models, streaming decoder, closed error taxonomy, retry/circuit/limit policies, credential ports, `hyper` + `rustls` transport. `http::proxy` owns the workspace's single reviewed outbound proxy policy — legacy variable precedence, `NO_PROXY` bypass, URL-free diagnostics. `gta-claw-daemon` now derives one policy value and shares it with the provider, the role fetch, and the Teams, WhatsApp, Telegram and Discord transports, so the module's own "`HttpTransport` is the only adopter" note is now understated for the composed service; the obligation is still open because plugin and skill HTTP goes through `claw-plugin-host`'s `PinnedHttpTransport`, which has no proxy support. |
| `claw-providers` | Partial by design | All 78 frozen descriptors registered. Real clients: OpenAI-compatible dialect, Anthropic `/v1/messages`, GitHub Copilot via RFC 8628 device flow. **Every other provider is registration-only** and says so. `gta-claw-daemon` composes the GitHub Copilot client and the device flow; the other 77 descriptors are not reachable from any binary. |

### Capabilities

| Crate | Status | Notes |
|---|---|---|
| `claw-tools` | Implemented / Not composed | Closed schemas, deny-by-default grants, per-invocation authorization. **No binary depends on this crate**, including the daemon: the composed tool surface is signed plugin registrations plus the durable goal tool, so none of this crate's authorization runs in a serving process. |
| `claw-skills` | Partial | Native, declarative-HTTP and Wasm execution over the 51-entry bundled registry. Legacy JavaScript skills are **not executable** — only classifiable for migration, and a port requires signed evidence. This is the deliberate break, not a gap. Two real gaps remain: nothing in this crate, or anywhere in the tree, performs the legacy concurrent bounded remote skill fetch; and although `gta-claw-daemon` depends on the crate, it only reads `registry()` for its inventory count — the daemon's `WasmSkillHost` bridge has no production caller, so no skill executes in the serving path. |
| `claw-plugin-api` | Implemented (contract) / Registration-only (inventory) | ABI, capability model, limits, manifest schema and trust policy are implemented. All 137 upstream plugin descriptors are present and every one reports `RegistrationOnly`. |
| `claw-plugin-host` | Implemented (host) / Composed | The wasmtime Component Model host, sandbox, limits and lifecycle are real, and `gta-claw-daemon` now runs it: Ed25519 trust policy from `GTA_CLAW_PLUGIN_POLICY`, a deny-all service base extended only with logs, config, store, pinned HTTP, bounded DNS, clock, random, tools and discarded events, discovery bounded by a candidate limit and an activation deadline, and a stable discovery-ordered activation report. It contains **no ports of the 137 upstream plugins**, so a default install activates nothing. |
| `claw-memory` | Implemented / Composed | Deterministic context assembly with anchor preservation; the daemon's context-engine port is built on it. |
| `claw-goals` | Implemented / Composed | The on-disk adapter behind `GoalStorePort`; earlier adapters in the tree were in-memory fakes. `gta-claw-daemon` opens a `FileGoalStore` under its state directory and publishes the goal tool to the model. Publication is a rename whose parent directory is fsynced on Unix, so it survives power loss there; Windows has no equivalent step and durability after sudden power loss is not claimed. Recovery's temp-file unlinks are not directory-synced. |

### Transports and interop

| Crate | Status | Notes |
|---|---|---|
| `claw-gateway` | Partial / Composed | Transport, lifecycle, dispatch registry, event bus and authorization are implemented, and `gta-claw-daemon` binds and starts a `GatewayServer` with a `StaticAuthenticator` and a durable device directory backed by its own `gateway-pairings.json` store, so the in-crate in-memory persistence is no longer the only option in a running service. Payload schemas are this crate's own design and are **not** claimed byte-compatible with upstream, because the frozen inventory pins method identities only. Catalogued methods that are not really implemented answer `DispatchError::NotImplemented` rather than being absent — which bounds what the composed Gateway can actually do. |
| `claw-gateway-client` | Implemented | Bounded `ws://`/`wss://` transport and lifecycle. No server, RPC handlers or GUI, by design. |
| `claw-http-api` | Partial / Composed | The frozen 18-route surface is implemented over narrow ports. A separate opt-in `legacy` facade registers all ten `src/server.ts` method/path identities, the rate limiter, the ordered `/admin/exec` allowlist and the conditional Teams and WhatsApp routes, with frozen-shape acceptance tests. `gta-claw-daemon` binds both routers plus the `mcp_router` to real `TcpListener`s, and every `LegacyApiServices` slot now has a concrete daemon adapter — runtime, device flow, Teams, WhatsApp, reload and host admin — so `ProviderLegacyRuntime` is no longer used by any binary. What is still open is evidence, not composition: nothing replays `compat/legacy` against the bound service, and the optional watch-pairing and task-flow webhook ports are wired to a fail-closed `DisabledExternalPorts`. See the `src/server.ts` row in the obligations file. |
| `claw-mcp` | Implemented | Server, stdio/streamable-HTTP/legacy-SSE clients, OAuth, configured-server lifecycle, conversation projection. |
| `claw-acp` | Implemented | ACP interoperability over `claw-mcp`. |
| `claw-channel-sdk` | Implemented | Transport-neutral contracts, plus the bounded outbound segmenter: an explicit counting unit, the newline-then-space-then-hard-cut preference, and refusal with `SegmentationError::NoDeclaredLimit` when the destination has no proven limit. Owns no network client or credential persistence. |
| `claw-channels` | Partial / Four channels composed | All 29 official channels registered with capabilities and auth modes, and `ImplementationStatus` keeps registry coverage separate from working integrations: 1 `Full`, 3 `OutboundWebhook`, 4 `CompatibilityShim`, 21 `RegistrationOnly`. Teams, Telegram, Discord and WhatsApp are the four shims — inbound and outbound legacy state machines with the frozen replies, timeouts and lifecycles — and `CompatibilityShim` still means the behavior sits behind daemon-owned transport and HTTP composition ports. Those ports now have implementations: `gta-claw-daemon` depends on the crate and supplies `TelegramTransport`, `DiscordTransport` and `WhatsAppTransport`, drives `dispatch_incoming` on the live path, and implements `ConversationService` over its composed runtime. The status stays `CompatibilityShim` because the crate itself still sends nothing, and the other 25 channels remain unreachable from any binary. The same four carry an output limit proven by the frozen behavior ledger (Teams and Telegram 4000, Discord 1900, WhatsApp 3500, all in UTF-16 code units) and segment against it; the other 25 have no stated limit anywhere in the tree, so segmentation refuses rather than cutting against an invented bound. |
| `claw-relay` | Implemented | Authentication, framing, connection isolation, CDP policy, routing and lifecycle. Transport independent: an acceptor must supply upgrades and frames. |
| `claw-worker` | Implemented | The closed worker admission protocol, ticket redemption and its own crypto surface. |
| `claw-clients` | Implemented (contracts) | Connection profiles, capability negotiation, session projections and bounded event delivery. GTA-Claw does not ship the upstream mobile apps, Control UI or browser extension. |

### Platform, configuration and governance

| Crate | Status | Notes |
|---|---|---|
| `claw-platform` | Implemented | Native adapters for the application core's ports. |
| `claw-config` | Partial / Composed | All 47 frozen domains modeled, JSON5 loading, schema generation, atomic writes with rollback, layered resolution, typed reload, and generated legacy env conversion validated against the frozen artifact at build time. It also owns the remote role document contract — size bound, `content`/`prompt` precedence, plain-text fallback and diagnostics — behind the `RoleSourceFetcher` port, which now has a real implementation: `gta-claw-daemon`'s `TransportRoleFetcher` over `claw-provider-sdk`'s `HttpTransport`. The daemon is also the legacy import/override path: it resolves `ConfigLayers` over file plus process environment, or runs `migrate_legacy_environment` when no file is given, and `--check-config` validates without serving. What the obligations file still records is acceptance coverage against `compat/legacy`. Windows durability after sudden power loss is explicitly not claimed. |
| `claw-crestodian` | Implemented / Composed | Guided setup, backup/restore, recovery classification, closed `/crestodian` rescue grammar, ring-zero single-tool restriction, typed configuration writes. `gta-claw-daemon` calls `Crestodian::inspect` on file-backed startup and reports the resulting `RecoveryGuidance`; the rescue grammar itself is not exposed by any binary. |
| `claw-security` | Implemented (primitives) | Identity, roles, scopes. Deliberately contains no network client, TLS terminator, database, keyring or private-key persistence — those are platform adapters. |
| `claw-observability` | Implemented (primitives) / Composed | Telemetry, metrics, audit and redaction exist, and the crate re-exports the `tracing` facade so no caller opens a second logging path. `gta-claw-daemon` now depends on it and installs the redacting subscriber unconditionally on the serve path: level from `core.logging.level`, overridable by `GTA_CLAW_LOG`, human or JSON via `GTA_CLAW_LOG_FORMAT`, to standard error or `--log-file`, with startup stages, subsystem faults and the drain all logged through it, and the handle shut down and checked for late writer failures before exit. `gta-claw-cli` and `gta-claw-tui` also depend on it but install the subscriber only when verbosity is raised explicitly; at the default level neither emits anything. The obligations file now records `src/utils/logger.ts` as **Composed — evidence outstanding**. |
| `claw-migrate` | Implemented | Side-effect-free plans, verified backups, apply and rollback for Claude, Codex, Hermes and legacy state. |
| `claw-discovery` | Implemented (oracles) | Wire codecs and fail-closed policy oracles. Contains no network runtime, process spawning or container client, on purpose. |
| `claw-conformance` | Implemented | The parity harness and its evidence verifier. It reports parity; it does not create it. |
| `claw-repo-policy` | Implemented | The JS/TS ratchet, container check and index scan, with planted-violation tests proving the checks actually fire. |

## Binaries

| Binary | Status | What actually works |
|---|---|---|
| `gta-claw-cli` | Partial | `--version`, `--help`/`-h`, `health` (prints `healthy runtime=…`), and `gateway health` — one real authenticated Gateway v4 connection, one `operator.read` `health` RPC, bounded shutdown, eight typed exit categories and a deterministic `--json` schema-version-2 report. `-v`/`-vv` and `--log-file` install `claw-observability`'s redacting subscriber on standard error or a file; at the default level output is byte-identical to an uninstrumented run. `send` **fails on purpose**: `unsupported operation: message transport is not configured`. `--token-file` is parsed but always fails closed. Identity is one-shot `--ephemeral-device` only; durable secure-storage identity is deferred. |
| `gta-claw-daemon` | Partial | `--probe` prints one health line and `--check-config` validates configuration without serving. Serving composes the shipped crates and **binds real listeners**: a `claw-gateway` server, the frozen 18-route HTTP API, `claw-http-api`'s legacy `src/server.ts` facade on the configured server port, and a loopback-only MCP router. It announces `ready protocol=1`, health and a `service http=… legacy=… gateway=… mcp=… provider=… config_generation=…` line, answers `status` and `reload` control lines, handles `SIGTERM`/`SIGINT` (Windows: Ctrl-C/Break/Close/Shutdown) and a `shutdown` control line, and reports a provable drain summary. A routable bind is refused unless `--tls-terminated-by-frontend` is passed, and `--smoke` swaps in a local diagnostic provider restricted to loopback. **What is behind those listeners is not all real**: sessions and turns are in-memory only, tool authorization is the plugin surface rather than `claw-tools`, no skill executes, approvals are auto-granted, and the watch and webhook routes fail closed. The deterministic stand-in adapters remain in the crate but are a contract harness — `main.rs` does not run them. |
| `gta-claw-tui` | Partial | Connects to a Gateway, renders Sessions / Workspace / Runs / Diff / Artifacts / Help, supports the command palette, approve/deny prompts and refresh, and falls back to a single `--plain` snapshot when standard output is not an interactive terminal. `-v`/`-vv` and `--log-file` install `claw-observability`'s redacting subscriber away from the drawn terminal. Its capability is bounded by what the Gateway it talks to actually implements. |
| `gta-claw-updater` | Implemented / Composed conditionally | Signed, resumable, rollback-safe update with staged installs and a restart-required outcome; `Updater::check` reports installed-versus-latest against a signature-verified manifest. On Linux it refuses and defers to the system package manager. It is still a standalone executable, but it is no longer uninvoked: `gta-claw-daemon` runs one supervised nonblocking `Updater::check` at startup when `core.updates.enabled` is set, joined within a budget at shutdown. That check requires `GTA_CLAW_UPDATE_MANIFEST` and `GTA_CLAW_UPDATE_TARGET` and refuses to run under an explicit proxy policy, so a default deployment performs no check. |
| `gta-claw-android` | Partial | Client core: endpoint and credential intake, Gateway identity, transport assembly, connection lifecycle. A native Slint shell over that core lives in the separate `android/` workspace and is built as an arm64 APK by `android-packaging.yml`. It is a connect-and-status surface for the client core, **not the product UI**; nothing beyond the client core's own scope is rendered, and the upstream mobile app is not ported here. |
| `gta-claw-ios` | Partial | Same scope and same constraint, with its shell in the separate `ios/` workspace. |
| `gta-claw-desktop` | Partial | A native Slint shell for Windows and macOS. The wired path performs a real bounded `claw-gateway-client` connection, authentication, protocol negotiation and health probe. First-run screens explicitly report that desktop device authorization and workspace trust are not composed; they issue no fake code or path. The product shell is preview state, in-app update orchestration is not connected, and desktop diagnostics expose only the live Gateway summary. Linux is rejected by design and CI asserts the rejection. |

## Legacy replacement obligations

`docs/legacy-node-port-obligations.md` is the authoritative checklist. That file now states, for every
row, whether the missing piece is an **owner**, an **implementation**, a **composition**, or
**evidence** — the last being new, and where most rows moved. Summarized by outcome:

| Outcome | Legacy modules |
|---|---|
| **Composed — evidence outstanding.** A running service uses it; no test replays `compat/legacy` against that service | `src/auth/deviceFlow.ts`, `src/bot/teamsBot.ts` (its Teams JWT implementation gap is now closed), `src/channels/discordGateway.ts`, `src/channels/messageProcessor.ts`, `src/channels/telegramPolling.ts`, `src/channels/whatsappWebhook.ts`, `src/config.ts`, `src/index.ts` (with named gaps), `src/loader/roleLoader.ts`, `src/server.ts`, `src/utils/logger.ts` |
| **Composed conditionally — evidence outstanding** | `src/updater/sdkUpdater.ts` — the daemon runs one signed startup check, but only when updates are enabled and a manifest and target are configured |
| **Composed for four channels — evidence outstanding** | `src/utils/splitMessage.ts` — the four channels with a ledger-proven limit segment on the live path; 25 have no proven limit and no transport |
| **Partial — implementation and composition.** `claw-state` does not exist in this repository | `src/engine/copilotEngine.ts`, `src/engine/sessionManager.ts` |
| **Partial — composition** | `src/utils/proxy.ts` → one shared policy now covers provider, role, Teams, WhatsApp, Telegram and Discord; plugin and skill HTTP is still outside it |
| **Partial by deliberate break — composition** | `src/engine/toolExecutor.ts` — JavaScript evaluation is **removed, not ported**; the composed tool surface is signed plugins plus the goal tool, and `claw-tools` is in no binary |
| **Partial — owner required for the fetch half** | `src/loader/skillLoader.ts` → `claw-skills` owns discovery and validation; nothing owns the concurrent bounded remote fetch |

No row is **Owner required** outright, and no row is a blanket composition failure any more. That is
a real change since the last revision. It is still not the same as progress toward deletion: **not
one obligation has been discharged**, because discharging one requires the running service to be
proven against `compat/legacy`, and no test under `apps/` reads that directory.

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
| Docs | `cargo doc --workspace --no-deps --locked` with `RUSTDOCFLAGS=-D warnings` |
| MSRV floor | `cargo +1.94.0 check --workspace --all-targets --locked` |
| Gateway determinism | Repeated `claw-gateway-client` regressions on `macos-15-intel` |
| Desktop | `fmt`, `check`, `clippy`, `test` and `build`, each with `--manifest-path desktop/Cargo.toml`, on Windows and macOS, plus `cargo doc` on Windows |
| Desktop platform boundary | Linux desktop graph must exclude Slint, and `cargo check` on Linux must fail |
| Slint boundary | Root `cargo metadata` must contain no Slint crate |
| Mobile shells | `cargo +1.94.0 check --workspace --all-targets --locked` and `cargo deny check` against `android/Cargo.toml` and `ios/Cargo.toml`, plus an arm64 APK build and an unsigned iOS archive |
| Supply chain | `cargo-audit` on both lockfiles; `cargo-deny` lock and exception policy; per-target desktop dependency policy for Windows x64/ARM64 and macOS Intel/ARM64 |
| Architecture ratchet | `cargo test -p claw-repo-policy` |

Packaging prototypes run from `linux-packaging.yml`, `macos-packaging.yml`, `windows-packaging.yml`,
`android-packaging.yml` and `ios-packaging.yml`. `docker-publish.yml` still builds the **legacy Node
image**; switching it to the native service is step 5 of the deletion checklist.

## What would change this document

The composition landed. `gta-claw-daemon` binds real listeners over the shipped crates, and the
section above is the record of that. The next status change worth recording is therefore neither
another crate nor another adapter: it is **evidence**. When a test under `apps/` replays
`compat/legacy` — behaviors, HTTP shapes, negative, timeout, reload-race, channel, persistence and
shutdown cases — against the bound daemon, obligations start being discharged and legacy files start
leaving the inventory in the same change that deletes them.

Two things would also change this document before that, because they are the named gaps that make
"composed" fall short of "complete": a `claw-state` owner that gives sessions and turns durability
across a restart, and composition of `claw-tools` and skill-execution dispatch so that the running
tool surface is the authorized one rather than whatever signed plugins happen to be installed.
