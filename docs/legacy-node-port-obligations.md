# Legacy Node port obligations

The root Node application remains the only composed production service and must not be deleted until
every obligation below has a tested Rust replacement. `crates/claw-repo-policy` treats this inventory
as a path ratchet: these exact legacy paths may remain or disappear, but a new JavaScript or TypeScript
path fails the repository policy.

The frozen behavior authority remains `compat/legacy/contract.json` and its ledgers. This document is
the operational deletion checklist and does not relax those contracts.

## Current inventory boundary

The authoritative `origin/main` baseline contains exactly 18 TypeScript files. No `dist/` file,
generated JavaScript output, or unmerged legacy feature path is grandfathered.

PR #39 adds four `src/state/*.ts` modules and four `tests/*.test.mjs` files to the legacy runtime.
Every one of those paths is intentionally outside the inventory and therefore fails this ratchet.
If that feature is still required, it must be implemented in the assigned Rust memory/state crates
or receive an explicit repository-policy decision; it cannot enter silently as legacy expansion.

## Module-by-module obligations

An obligation is discharged only when its behavior is composed end to end in a running service.
A crate that implements the behavior perfectly discharges nothing on its own. So that a reader can
tell what is actually missing from a row, every status names which of three things is absent:

| Missing piece | Meaning |
|---|---|
| **owner** | No crate in this repository owns the behavior at all. |
| **implementation** | An owner is assigned, but part of the behavior is not written yet. |
| **composition** | An owner implements the behavior with tests, and no running service uses it. |

Most rows below are composition failures, because `src/index.ts` is still unowned. That is a
different and much later problem than a missing owner, and the two must not be conflated.

| Legacy module | Behavior that must be disposed or replaced | Intended Rust replacement | Deletion status |
|---|---|---|---|
| `src/auth/deviceFlow.ts` | GitHub device-code request, reusable instructions, bounded polling, `slow_down`, expiry/denial handling, user lookup, and engine activation. | `claw-providers` + `claw-provider-sdk` + `claw-http-api` | **Blocked — composition.** `claw-providers::github_copilot` speaks the RFC 8628 grant directly over `claw-provider-sdk`'s `hyper`/`rustls` transport, with the server-dictated interval, `slow_down` backoff, `authorization_pending`, `access_denied`, and `expired_token`; `claw-http-api`'s `LegacyDeviceFlowPort` renders the reusable instructions for `GET /auth/device`. No `apps/` manifest depends on any of those crates, so nothing serves the flow. |
| `src/bot/teamsBot.ts` | Bot Framework activity handling, auth/error behavior, shared engine dispatch, and 4,000-character reply splitting. | `claw-channels` + `claw-http-api` | **Blocked — composition, plus one implementation gap.** `claw-channels::teams` reports `ImplementationStatus::CompatibilityShim`: activity handling, the greeting, the frozen error replies, and 4,000-unit splitting are implemented, and emit `TeamsAction` values for a daemon-owned HTTP composition layer rather than sending anything themselves. `claw-http-api`'s `LegacyTeamsPort` validates, bounds, and forwards the `Authorization` context, and its own documentation states the gap: the daemon-owned adapter must still verify the JWT signature, issuer, audience, lifetime, and Bot Framework claims. Nothing composes either half. |
| `src/channels/discordGateway.ts` | Gateway discovery, identify/heartbeat/reconnect lifecycle, bot filtering, inbound dispatch, REST replies, and error containment. | `claw-channels` | **Blocked — composition.** `claw-channels::discord` reports `CompatibilityShim` and covers the gateway phases, identify/heartbeat/reconnect, bot filtering, inbound dispatch, and REST replies. `DiscordTransport` has no implementation outside `crates/claw-channels/tests/legacy_channel_compat.rs`, and no `apps/` manifest depends on the crate. |
| `src/channels/messageProcessor.ts` | Shared `/help` handling, unauthenticated Device Flow response, and channel-to-conversation engine dispatch. | `claw-channels` + `claw-runtime` + `claw-provider-sdk` | **Blocked — composition.** `claw-channels::message_processor` owns the shared command surface, the frozen unconfigured and failure replies, the Device Flow prompt, and dispatch through `ConversationService`. No production composition joins these ports. |
| `src/channels/telegramPolling.ts` | Offset-based long polling, retry/stop behavior, inbound text normalization, engine dispatch, and segmented replies. | `claw-channels` | **Blocked — composition.** `claw-channels::telegram` reports `CompatibilityShim` and covers offset-based long polling, the frozen poll and send timeouts, retry/stop behavior, inbound normalization, and segmented replies. `TelegramTransport` has no implementation outside the crate's tests. |
| `src/channels/whatsappWebhook.ts` | Webhook challenge verification, inbound payload parsing, engine dispatch, Graph API replies, and segmented output. | `claw-channels` + `claw-http-api` | **Blocked — composition.** `claw-channels::whatsapp` reports `CompatibilityShim` and covers `hub.*` challenge verification, payload normalization, Graph v20 replies, and segmented output; `claw-http-api` registers `GET`/`POST /whatsapp/webhook` behind `LegacyWhatsAppServices`. `WhatsAppTransport` has no implementation outside the crate's tests. |
| `src/config.ts` | Exact environment parsing, defaults, bounds, URL/domain normalization, authentication mode, and conditional channel credential validation. | `claw-config` | **Partial — composition.** Typed config and audited migration exist; no `apps/` manifest depends on the crate, and the production daemon still needs the legacy import/override path and acceptance coverage. |
| `src/engine/copilotEngine.ts` | Provider startup/ping, per-conversation sessions, system prompt/model/tools, approval policy, timeouts, fixed fallback text, reload fencing, and shutdown. | `claw-runtime` + `claw-provider-sdk` + `claw-tools` + `claw-state` (**not in this repository**) | **Blocked — implementation and composition.** `claw-runtime` is I/O-free orchestration, and `claw-http-api::legacy::ProviderLegacyRuntime` is a concrete legacy chat/session adapter — but it runs over a `ProviderPort` that nothing in this tree implements. `claw-state` is named by `claw-application`'s subsystem identities and owned by another workstream; there is no such crate here. |
| `src/engine/sessionManager.ts` | Touch-on-read, capacity LRU eviction, strict idle TTL cleanup, clear, and terminal destruction. | `claw-runtime` + `claw-state` (**not in this repository**) | **Blocked — implementation and composition.** `ProviderLegacyRuntime` implements touch-on-read, oldest-first capacity eviction, idle-TTL expiry, and clear-on-logout over conversation identities held in memory; `crates/claw-http-api/tests/legacy_http.rs` asserts the capacity bound and the clear, not the TTL. It retains no session content, and the persistent-cleanup owner does not exist in the tree. |
| `src/engine/toolExecutor.ts` | Tool registry, domain policy, bounded HTTP/log bridges, disposal, and JavaScript evaluation. | `claw-tools` + `claw-skills` | **Partial by deliberate break — composition.** JavaScript evaluation must be removed, not ported. `claw-tools` implements closed schemas, deny-by-default authorization, path confinement, and validated network destinations; `claw-skills` executes native, declarative-HTTP, and Wasm skills. No composed service invokes either. |
| `src/index.ts` | Full service composition, startup ordering, proxy/config/role/skill loading, token-driven engine swaps, channel lifecycle, reload transaction, update check, and graceful shutdown. | `gta-claw-daemon` composition over all replacement crates | **Unowned integration blocker.** `apps/gta-claw-daemon` depends on `claw-application`, `claw-domain`, `claw-platform`, and `claw-protocol` only, and its subsystem adapters are deterministic stand-ins, stated as such in `apps/gta-claw-daemon/src/adapters/mod.rs`. No branch currently constructs the complete production service — which is why nearly every row above is a composition failure rather than a missing owner. |
| `src/loader/roleLoader.ts` | Bounded remote HTTP fetch, JSON/plain-text fallback, `content`/`prompt` precedence, optional model handling, and diagnostics. | `claw-config` | **Partial — implementation and composition.** `claw-config::role` owns the interpretation half: the 1 MiB bound, the frozen `Accept` header and timeout, status and declared-length checks, `content`/`prompt` precedence, plain-text fallback, optional model, and returned diagnostics. The transport half stays behind the `RoleSourceFetcher` port, whose only implementation in the tree is the test double in `crates/claw-config/tests/role.rs`. |
| `src/loader/skillLoader.ts` | Concurrent bounded remote fetch, per-skill validation, safe names, partial success, and input-order retention. | `claw-skills`, plus an unassigned fetch owner | **Partial — owner required for the fetch half.** Legacy input is migration data only; signed Rust/WASI discovery and equivalent diagnostics must replace executable loading. `claw-skills` discovers and validates the bundled registry and classifies legacy manifests, but nothing in this tree owns the concurrent bounded remote fetch, its partial success, or its input-order retention. |
| `src/server.ts` | Rate limiting plus `/`, `/health`, `/auth/device`, `/chat`, `/api/messages`, WhatsApp webhook, admin reload, system, and allowlisted exec response contracts. | `claw-http-api` | **Blocked — composition.** `claw-http-api::legacy` registers all ten legacy method/path identities (`LEGACY_HTTP_ENDPOINTS`), the rate limiter, the ordered `/admin/exec` allowlist, and the conditional Teams and WhatsApp routes, with frozen-shape acceptance tests in `crates/claw-http-api/tests/legacy_http.rs`. `ProviderLegacyRuntime` is the only concrete `LegacyApiServices` adapter; device flow, Teams, WhatsApp, reload, and host admin remain ports, and nothing binds the router to a listener. |
| `src/updater/sdkUpdater.ts` | Nonblocking installed/latest version reporting and optional package/CLI mutation. | `gta-claw-updater` | **Partial by deliberate break — composition.** Package-manager and curl self-mutation are deliberately forbidden; only verified signed releases may replace them. `apps/gta-claw-updater` is that owner: `Updater::check` reports installed-versus-latest against a signature-verified manifest, and installs are staged, resumable, and rollback-safe. No service performs the legacy nonblocking startup check, and on Linux the updater defers to the system package manager by design. |
| `src/utils/logger.ts` | Structured level-controlled logging used by every runtime component. | `claw-observability` | **Partial — composition.** Rust logs need not reproduce pino bytes. `claw-observability` owns the pipeline and re-exports the `tracing` facade so no caller opens a second logging path, and `RedactingLayer` redacts field values. `gta-claw-cli` and `gta-claw-tui` depend on the crate and install the subscriber, but only when verbosity is raised explicitly. `gta-claw-daemon` does not depend on it and uses an in-crate stand-in, so no component of the replacement service logs through it, and lifecycle/error-field acceptance coverage still needs a composed service. |
| `src/utils/proxy.ts` | `HTTPS_PROXY`/`HTTP_PROXY` precedence, global outbound dispatcher setup, redacted diagnostics, and continue-without-proxy failure behavior. | `claw-provider-sdk` | **Partial — composition.** `claw-provider-sdk::http::proxy` owns the policy: the legacy `HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy`/`ALL_PROXY`/`all_proxy` precedence, `NO_PROXY` bypass matching, diagnostics that never echo the URL, and continue-without-proxy on a malformed one. The module's own documentation records that this does not discharge the obligation: `HttpTransport` is its only adopter, so role, channel, and skill transports still do not share one reviewed policy. |
| `src/utils/splitMessage.ts` | Newline/word-aware bounded splitting with hard slicing fallback. | `claw-channel-sdk` + `claw-channels` | **Partial — composition, and 25 channels still without a proven limit.** `claw-channel-sdk::segmentation` implements the newline-then-space-then-hard-cut preference over an explicit counting unit. Four channels carry a limit proven by `compat/legacy/ledger/behaviors.json` — Teams and Telegram 4,000, Discord 1,900, WhatsApp 3,500, all in UTF-16 code units, the unit the legacy `String.length` counted — and segment against it. The other 25 have no stated limit anywhere in the tree, so segmentation refuses with `SegmentationError::NoDeclaredLimit` rather than cutting against an invented bound. |

## Build and dependency obligations

| Legacy path or dependency | Current role | Removal condition |
|---|---|---|
| `Dockerfile` | The image built by `.github/workflows/docker-publish.yml`; compiles and runs `dist/index.js`. | Replace only after the native daemon composes all required adapters and container acceptance tests cover the legacy service contract. |
| `package.json` | Defines the TypeScript build/start path and production package graph. | Delete together with the final Node runtime, never before it. |
| `package-lock.json` | Pins the published container's production dependency graph. | Delete with `package.json` after the native image cutover. |
| `tsconfig.json` | Produces `dist/` from the legacy TypeScript service. | Delete with the TypeScript source after the native image cutover. |
| `dist/` | Generated build output; currently untracked. | Remains ignored and is not allowed in the repository ratchet. |
| `@github/copilot-sdk` | Production model/session dependency of the legacy Node service. | Replaced by `claw-providers::github_copilot`, which speaks the device grant and chat surface over `claw-provider-sdk`'s pure-Rust HTTPS stack; the dependency leaves only when a composed service uses that client. It remains forbidden from the Rust product dependency graph. |
| `botbuilder`, `restify`, `undici`, `ws`, `pino` | Production channel, HTTP, network, WebSocket, and logging dependencies. | Remove only when their module-level obligations above have composed Rust replacements. Each now has an assigned owner — `claw-channels`, `claw-http-api`, `claw-provider-sdk`, `claw-channels::discord`, and `claw-observability` respectively — so every one of these is a composition condition, not an ownership one. |
| `isolated-vm` and `node:vm` | Execute remotely supplied JavaScript skills. | Deliberate removal; never add an embedded JavaScript engine to Rust. |

## Final deletion checklist

1. Land the Rust provider, runtime, state, tools, channels, HTTP, config, and shared network
   adapters with the exact dependency pins required by repository policy. Most of these owners have
   landed and are tested; what is still outstanding at this step is `claw-state`, an implementation
   of `RoleSourceFetcher`, the channel transport ports (`TelegramTransport`, `DiscordTransport`,
   `WhatsAppTransport`), Teams JWT verification, and the concrete `LegacyApiServices` adapters other
   than `ProviderLegacyRuntime`.
2. Compose those adapters in `gta-claw-daemon`; no mock, metadata-only, registry-only, or
   stand-in adapter satisfies a production obligation, and no crate discharges an obligation by
   implementing it. This step, not step 1, is what almost every row above is waiting on.
3. Pass every behavior and HTTP shape in `compat/legacy`, including negative, timeout, reload-race,
   channel, persistence, and shutdown cases.
4. Port any remaining JavaScript tests to Rust. Do not widen the ratchet for test files or generated
   `dist/` output.
5. Switch `Dockerfile` and `docker-publish.yml` to the native service and validate the built image,
   health behavior, non-root runtime, shutdown, and all enabled channel paths.
6. Delete legacy files and their corresponding `LEGACY_RUNTIME_INVENTORY` entries in the same
   change. The allowlist must monotonically approach empty.
