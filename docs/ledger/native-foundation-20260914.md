# Native Development Record: 2026-09-14

Status: implemented partial foundation, not a complete product, migration acceptance or release.
All work was performed by the primary assistant without subagents, Git publication, deployment,
real provider credentials, live channels or user-state migration.

## Source and Versions

- Base commit: `b98e39d135203687397d3549348217f13d458f36`; changes remain uncommitted.
- Rust: `1.98.1 (48a229cea 2026-09-01)`, verified installed stable. Declared MSRV stays `1.94.0`.
- Slint and slint-build: exact `1.17.1`, independently checked as latest official stable.
- State database: exact redb `4.2.0`, pure Rust, MIT OR Apache-2.0, upstream MSRV `1.90`.
- Root: 32 library crates and 6 application members. Desktop, Android and iOS stay independent.
- No npm/Node runtime, embedded JS interpreter, WASI or Copilot CLI subprocess was added or run.
- Existing dependency downloads used the local `127.0.0.1:2080` proxy without changing that service.

Candidate [release identity](../../compat/releases/v2026.9.4/baseline.json) pins release/tag/commit/tree
and Gateway version bounds. GitHub API signature flags are recorded, but local cryptographic
verification is false. The candidate has `complete_contract: false` and `runtime_verified: false`.
It is not a semantic extraction of all September changes. Old sealed compatibility trees remain
unchanged. The CLI can display both baselines:

```sh
cargo +stable run -p claw-conformance --locked -- --root compat/upstream --baselines --format json
```

## Implemented Slices

| Slice | Production implementation | Verified scope |
|---|---|---|
| State | [claw-state](../../crates/claw-state/src/lib.rs) and [runtime adapter](../../crates/claw-state/src/runtime.rs) | Schema validation, bounded CAS batches/pages, strict decoding, revision conflicts, same-turn retry/conflict, high-water ordinals, reset preserving turn history, locks, corrupt/future/empty database refusal |
| Interruption | Same redb adapter | Actual child `process::exit` without destructors preserves committed data and discards an uncommitted transaction; not physical power-loss evidence |
| Context | [persistent_context.rs](../../apps/gta-claw-daemon/src/adapters/persistent_context.rs) | Tracked writes/reset, checkpoint rehydration, bounded session LRU, explicit reset, clean daemon process restart and reload preserving context |
| Plugin safety | [agent_runtime.rs](../../apps/gta-claw-daemon/src/adapters/agent_runtime.rs) | Conservative approval/mutation descriptors, no invented owner=true, HTTP/MCP plugin execution through runtime executor, dry-run without goal writes |
| Approval lifecycle | [approval.rs](../../crates/claw-runtime/src/approval.rs) | Expiry/cancellation checked at redemption; cancellation before execution; accepted-but-unconsumed cancellation/drop dismisses presentation |
| Gateway approvals | [runtime_gateway.rs](../../apps/gta-claw-daemon/src/adapters/runtime_gateway.rs) | Metadata events, paged pending list, bounded complete preview, structured sensitive-field redaction, once-only decisions and duplicate rejection |
| MCP credentials | [production.rs](../../apps/gta-claw-daemon/src/production.rs) | Independent optional owner/read-only tokens, distinct credentials, 4096-byte ASCII bearer bound, no control/whitespace, safe errors; ordinary HTTP token cannot authenticate MCP |
| Native Gateway | [agent_runtime.rs](../../apps/gta-claw-daemon/src/adapters/agent_runtime.rs) | Real paired client chat/send/history/list/abort handlers, tracked turn drain and final events, scope refusal and process-local dedupe |
| CLI | [native_gateway.rs](../../apps/gta-claw-cli/src/native_gateway.rs) | Eight command forms exercised by actual CLI child processes against local WebSocket fixtures, minimum exact scopes, explicit send key, no automatic write replay, bounded JSON, remote errors not echoed |
| Slint product | [controller.rs](../../desktop/apps/gta-claw-desktop/src/controller.rs) and [product_state.rs](../../desktop/apps/gta-claw-desktop/src/product_state.rs) | Empty production models, real chat/history/approval requests, complete-preview gate, reconnect pending queries, bounded queues and stale-response rejection |
| Connection ownership | [client.rs](../../crates/claw-gateway-client/src/client.rs) | Requests use the observed epoch; queued events carry their original epoch. A real reconnect reusing a peer connection ID refuses old approval commands |
| Native rendering | [software_renderer_smoke.rs](../../desktop/apps/gta-claw-desktop/src/software_renderer_smoke.rs) | Headless software rendering of empty and approved native state at 1080x720 and 720x520 with nonblank/change checks, plus existing keyboard/focus regression |

The plugin risk-default task M1-01 and dedicated MCP credential wiring task M3-09 have scoped
implementation and positive/negative evidence. This does not close their parent milestones.

## Verification

Platform: Windows x86_64, local fixtures, ephemeral listeners and isolated temporary state only.
Core source subset, not `--workspace` or all-platform acceptance:

```sh
cargo +stable test -p gta-claw-daemon -p gta-claw-cli -p claw-state -p claw-runtime -p claw-gateway -p claw-gateway-client -p claw-http-api -p claw-repo-policy -p claw-conformance --all-targets --locked
cargo +stable clippy -p gta-claw-cli -p gta-claw-daemon -p claw-state -p claw-runtime -p claw-gateway -p claw-gateway-client -p claw-http-api -p claw-conformance --all-targets --locked -- -D warnings
cargo +stable test --manifest-path desktop/Cargo.toml --bin gta-claw-desktop --locked
cargo +stable clippy --manifest-path desktop/Cargo.toml --bin gta-claw-desktop --all-targets --locked -- -D warnings
```

The final core cohort recorded **922 passed, 0 failed, 3 ignored** across 53 test binaries; the
Slint cohort recorded **69 passed, 0 failed, 0 ignored**. Both scoped all-target Clippy commands
passed with dependencies included. Source fingerprints, commands, exact log hashes and exclusions
are in the [JSON receipt](native-foundation-20260914.json). A final runtime comment-only correction
was followed by another complete runtime test pass. Ignored upstream reference tests are not
interoperability evidence; subprocess-helper markers are not extra product coverage. These counts
include existing tests and are not a project-completion percentage.

Locked root metadata resolves 38 workspace members and 404 packages with zero Slint packages.
An initial offline attempt lacked cached metadata; the locked packages were then fetched through
the existing proxy. This check is a dependency-boundary check, not whole-workspace runtime coverage.
The actual Windows [desktop development executable](../../target/debug/gta-claw-desktop.exe) was
built successfully (38,280,192 bytes); its hash and build log are in the receipt. It was not launched,
installed or signed as a release. Local build outputs can disappear when the target cache is cleaned.

Failures found and corrected were retained in local logs: Windows `env_clear` omitted SystemRoot,
cmd short-path quoting/UTF-16 output, stale reload-clears-context and HTTP owner=true assertions,
and local test/lint defects. No frozen fixture or protected policy was changed to make them pass.
Rust 1.98 fixed-array and platform-hook lint adjustments preserve Windows directory-flush limits.

## Remaining Work and Safety Limits

- State, terminal turns, context, goals, audit and delivery do not share one atomic transaction.
  Gateway admission/dedupe is process-local, capped at 256 without eviction, and receipts explicitly
  report `durable: false`. No durable ingress/outbox or exactly-once external effect is claimed.
- Database commit failures lack a complete typed commit-unknown recovery workflow. Parent-directory
  ACL/path hardening, backups, encryption, migration, power-loss and Linux/macOS fault tests remain.
- Context checkpoints preserve retained messages and summaries, not all historical retrieval-index
  entries or a complete conversation archive. Per-record bounds do not replace archive quotas.
- Approval redaction is structured field-name redaction, not arbitrary secret discovery inside
  free-text commands/URLs. Subject, tool version, parameter digest, resource and policy-generation
  binding need completion. Plugin outcome mutation reporting remains incomplete.
- Native payloads are partial GTA-Claw contracts, not asserted OpenClaw September wire parity.
  Complete baseline extraction/diff, local signature verification and external interoperability are
  still open.
- CLI identity remains one-shot. A Gateway requiring manual device approval cannot be considered
  supported onboarding merely because a shared token is supplied; persistent identity/retry pairing
  needs implementation. CLI receipt/history is not streaming chat or durable run-query support.
- Desktop history responses can race newer events, and current operation events are not fully
  run-fenced. Health-time events rely on resync; full streaming, abort UI, native settings/workspace
  trust and platform credential storage remain unfinished. No visible-window/manual usability
  acceptance was performed. Mobile builds/devices were not tested in this increment.
- Native tools, skill dispatch, additional provider composition, full MCP/ACP lifecycle and channel
  durable cursors/outbox remain incomplete. Smoke provider tests are not real model/account tests.
- Protected supply-chain policy and packaging builders still pin Rust 1.97.1. The development pin
  is 1.98.1. Reviewed trust-policy/toolchain/image-digest updates are required before native packaging;
  trusted validators and historical fixtures were left unchanged. MSRV 1.94 was not freshly run.
- The legacy Node container remains until named obligations and cutover evidence are satisfied.
  No OpenClaw user-state importer, actual migration, deployment, signing or publication was completed.

## Operating This Development Tree

Native CLI commands and credential precautions are in the [CLI guide](../../apps/gta-claw-cli/README.md).
The daemon stores `runtime.redb` under its selected state directory. Use an isolated private state
directory for development; do not open or replace live user databases for tests.

On startup corruption/schema/lock errors, stop and preserve the database. Do not delete it to obtain
a successful empty startup. No automatic downgrade or complete recovery tool is available yet.
Never infer that an interrupted write or missing acknowledgement permits repeating an external
tool call. Review recorded state and known side effects first.

All current test child processes/listeners are owned and bounded by their fixtures; no long-running
daemon or UI is intentionally left running by this record.