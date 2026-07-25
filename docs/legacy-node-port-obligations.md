# Legacy Node port obligations

The root Node application remains the only composed production service and must not be deleted until
every obligation below has a tested Rust replacement. `crates/claw-repo-policy` treats this inventory
as a path ratchet: these exact legacy paths may remain or disappear, but a new JavaScript or TypeScript
path fails the repository policy.

The frozen behavior authority remains `compat/legacy/contract.json` and its ledgers. This document is
the operational deletion checklist and does not relax those contracts.

## Current inventory boundary

The branch base contains 18 TypeScript files. Four additional state files are already present on the
in-flight persistence branch and are included in the coordinator-approved 22-file ceiling:

- `src/state/contentScanner.ts`
- `src/state/fileState.ts`
- `src/state/memoryStore.ts`
- `src/state/transcriptStore.ts`

No `dist/` file is tracked, so no generated JavaScript output is grandfathered. The persistence
branch's `tests/*.test.mjs` files are also not grandfathered; those tests must be ported to Rust or
removed before that branch can coexist with the ratchet.

## Module-by-module obligations

| Legacy module | Behavior that must be disposed or replaced | Intended Rust replacement | Deletion status |
|---|---|---|---|
| `src/auth/deviceFlow.ts` | GitHub device-code request, reusable instructions, bounded polling, `slow_down`, expiry/denial handling, user lookup, and engine activation. | `claw-provider-sdk` | **Blocked.** A pure-Rust HTTPS/OAuth adapter and the frozen HTTP response cases are not composed in the daemon. |
| `src/bot/teamsBot.ts` | Bot Framework activity handling, auth/error behavior, shared engine dispatch, and 4,000-character reply splitting. | `claw-channels` + `claw-http-api` | **Blocked.** The channel branch has Teams registry/auth metadata only, not a compatibility transport. |
| `src/channels/discordGateway.ts` | Gateway discovery, identify/heartbeat/reconnect lifecycle, bot filtering, inbound dispatch, REST replies, and error containment. | `claw-channels` | **Blocked.** The current Rust branch implements outbound webhook text only; it has no inbound Gateway compatibility shim. |
| `src/channels/messageProcessor.ts` | Shared `/help` handling, unauthenticated Device Flow response, and channel-to-conversation engine dispatch. | `claw-channels` + `claw-runtime` + `claw-provider-sdk` | **Blocked.** No production composition joins these ports. |
| `src/channels/telegramPolling.ts` | Offset-based long polling, retry/stop behavior, inbound text normalization, engine dispatch, and segmented replies. | `claw-channels` | **Blocked.** Telegram currently has registry/auth metadata only. |
| `src/channels/whatsappWebhook.ts` | Webhook challenge verification, inbound payload parsing, engine dispatch, Graph API replies, and segmented output. | `claw-channels` + `claw-http-api` | **Blocked.** WhatsApp currently has registry/auth metadata only; no legacy webhook adapter is wired. |
| `src/config.ts` | Exact environment parsing, defaults, bounds, URL/domain normalization, authentication mode, and conditional channel credential validation. | `claw-config` | **Partial.** Typed config and audited migration exist; the production daemon still needs the legacy import/override path and acceptance coverage. |
| `src/engine/copilotEngine.ts` | Provider startup/ping, per-conversation sessions, system prompt/model/tools, approval policy, timeouts, fixed fallback text, reload fencing, and shutdown. | `claw-runtime` + `claw-provider-sdk` + `claw-tools` + `claw-state` | **Blocked.** `claw-runtime` is I/O-free orchestration; provider, tool, and state adapters plus daemon wiring are still required. |
| `src/engine/sessionManager.ts` | Touch-on-read, capacity LRU eviction, strict idle TTL cleanup, clear, and terminal destruction. | `claw-runtime` + `claw-state` | **Blocked.** Exact TTL/LRU compatibility and persistent cleanup integration are not demonstrated. |
| `src/engine/toolExecutor.ts` | Tool registry, domain policy, bounded HTTP/log bridges, disposal, and JavaScript evaluation. | `claw-tools` + `claw-skills` | **Partial by deliberate break.** JavaScript evaluation must be removed, not ported. Safe bridge behavior requires typed Rust tools and signed Rust/WASI skill ports. |
| `src/index.ts` | Full service composition, startup ordering, proxy/config/role/skill loading, token-driven engine swaps, channel lifecycle, reload transaction, update check, and graceful shutdown. | `gta-claw-daemon` composition over all replacement crates | **Unowned integration blocker.** No branch currently constructs the complete production service. |
| `src/loader/roleLoader.ts` | Bounded remote HTTP fetch, JSON/plain-text fallback, `content`/`prompt` precedence, optional model handling, and diagnostics. | No assigned runtime owner; likely shared network/config adapter | **Owner required.** `claw-config` models the URL but does not own this fetch lifecycle. |
| `src/loader/skillLoader.ts` | Concurrent bounded remote fetch, per-skill validation, safe names, partial success, and input-order retention. | `claw-skills` | **Partial.** Legacy input is migration data only; signed Rust/WASI discovery and equivalent diagnostics must replace executable loading. |
| `src/server.ts` | Rate limiting plus `/`, `/health`, `/auth/device`, `/chat`, `/api/messages`, WhatsApp webhook, admin reload, system, and allowlisted exec response contracts. | `claw-http-api` | **Blocked.** The Rust HTTP crate implements its frozen API surface, but these legacy routes and concrete `ApiServices` adapters are not all present. |
| `src/state/contentScanner.ts` | NFKC normalization and rejection of invisible/bidi controls, unsafe controls, instruction override, role tags, and credential-exfiltration patterns. | `claw-memory` with a reviewed `claw-security` boundary | **Owner boundary unresolved.** The scanner must be shared by memory and transcript exposure without becoming an ad hoc security oracle. |
| `src/state/fileState.ts` | Per-scope serialization, SHA-256 scoped paths, size-bounded JSON reads, mode-0600 atomic writes, corruption errors, and quarantine. | `claw-state` | **Blocked on in-flight persistence work.** Preserve atomicity, permissions, bounds, and quarantine behavior. |
| `src/state/memoryStore.ts` | Scoped memory/user records, prompt snapshots, add/replace/remove/list tools, deduplication, capacity, pagination, unsafe-content blocking, and corrupt-state recovery. | `claw-memory` + `claw-state` | **Blocked on in-flight memory/state adapters and daemon/provider integration.** |
| `src/state/transcriptStore.ts` | Bounded append/truncation, browsing, ranked search, unsafe-history blocking, retention, scoped persistence, and corrupt-state recovery. | `claw-memory` + `claw-state` | **Blocked on in-flight memory/state adapters and runtime integration.** |
| `src/updater/sdkUpdater.ts` | Nonblocking installed/latest version reporting and optional package/CLI mutation. | No assigned signed-release updater | **Owner required.** Package-manager and curl self-mutation are deliberately forbidden; only verified signed releases may replace them. |
| `src/utils/logger.ts` | Structured level-controlled logging used by every runtime component. | No assigned observability adapter | **Owner required.** Rust logs need not reproduce pino bytes, but lifecycle/error fields and secret redaction need acceptance coverage. |
| `src/utils/proxy.ts` | `HTTPS_PROXY`/`HTTP_PROXY` precedence, global outbound dispatcher setup, redacted diagnostics, and continue-without-proxy failure behavior. | No assigned shared Rust HTTP transport owner | **Owner required.** Provider, role, channel, and skill transports must use one reviewed proxy policy. |
| `src/utils/splitMessage.ts` | Newline/word-aware bounded splitting with hard slicing fallback. | `claw-channels` | **Blocked.** Each production channel adapter must prove its exact output limit and segmentation behavior. |

## Build and dependency obligations

| Legacy path or dependency | Current role | Removal condition |
|---|---|---|
| `Dockerfile` | The image built by `.github/workflows/docker-publish.yml`; compiles and runs `dist/index.js`. | Replace only after the native daemon composes all required adapters and container acceptance tests cover the legacy service contract. |
| `package.json` | Defines the TypeScript build/start path and production package graph. | Delete together with the final Node runtime, never before it. |
| `package-lock.json` | Pins the published container's production dependency graph. | Delete with `package.json` after the native image cutover. |
| `tsconfig.json` | Produces `dist/` from the legacy TypeScript service. | Delete with the TypeScript source after the native image cutover. |
| `dist/` | Generated build output; currently untracked. | Remains ignored and is not allowed in the repository ratchet. |
| `@github/copilot-sdk` | Production model/session dependency of the legacy Node service. | Must be replaced by `claw-provider-sdk` using pure-Rust HTTPS/OAuth. It is forbidden from the Rust product dependency graph. |
| `botbuilder`, `restify`, `undici`, `ws`, `pino` | Production channel, HTTP, network, WebSocket, and logging dependencies. | Remove only when their module-level obligations above have composed Rust replacements. |
| `isolated-vm` and `node:vm` | Execute remotely supplied JavaScript skills. | Deliberate removal; never add an embedded JavaScript engine to Rust. |

## Final deletion checklist

1. Land the Rust provider, runtime, state, memory, tools, channels, HTTP, config, and shared network
   adapters with the exact dependency pins required by repository policy.
2. Compose those adapters in `gta-claw-daemon`; no mock, metadata-only, or registry-only adapter
   satisfies a production obligation.
3. Pass every behavior and HTTP shape in `compat/legacy`, including negative, timeout, reload-race,
   channel, persistence, and shutdown cases.
4. Port any remaining JavaScript tests to Rust. Do not widen the ratchet for test files or generated
   `dist/` output.
5. Switch `Dockerfile` and `docker-publish.yml` to the native service and validate the built image,
   health behavior, non-root runtime, shutdown, and all enabled channel paths.
6. Delete legacy files and their corresponding `LEGACY_RUNTIME_INVENTORY` entries in the same
   change. The allowlist must monotonically approach empty.
