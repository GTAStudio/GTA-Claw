# Native Execution and Recovery: 2026-09-14

Status: ongoing implementation, not whole-project completion, migration acceptance or release.
This record supersedes current-state descriptions in the earlier
[foundation record](native-foundation-20260914.md), without changing its historical evidence.
The primary assistant performed all work; no subagents, Git publication, production changes,
real model/channel accounts, user-state migration or visible GUI/device tests were used.

## Implemented Paths

- redb durable run admission, once-only claim, cancellation intent, terminal result/outbox and
  exact-revision acknowledgement. Acceptance is committed before `durable: true` is returned.
  Claimed unfinished work becomes `outcome_unknown` on recovery, never automatically re-executed.
  Unclaimed queued work requires a fresh authenticated request. Device/source/idempotency binding
  survives process restart. Retained runs have a hard quota; pruning is not implemented.
- Windows Credential Manager/macOS Keychain device profiles, with no plaintext fallback or silent
  identity replacement. Actual Windows tests use the same profile across two CLI processes and
  remove only their own test credential. Local forget does not revoke remote grants.
- Shared immutable invocation authority, source/account partition, host permission generation,
  original parameters, publication binding and unpredictable one-use approval tokens. Model call
  IDs are translated into unique host execution IDs, so cancellation cannot cross reused IDs.
- Explicit opt-in native filesystem composition through the existing `claw-tools` registry.
  Model catalogue, HTTP/MCP dispatch and Gateway approvals share the same workspace adapter.
  Pinned workspace roots survive the approval window; Windows root replacement is blocked.
  Read/write handles reject multiple hard links. Traversal, junction, wrong-subject, changed-input,
  cancellation, read-only and default-deny paths are tested. No process/network tools are exposed.
- Native writes durably audit authorization before effects. Audit failure latches under the same
  lock as the writer; subsequent concurrent writers cannot restore readiness. Audit excludes
  file contents, goal text and raw arguments. Parent ACL/crash-tail recovery still need work.
- Runtime-owned goals and owner `!goal` directives use the same bound approval/audit path.
  Non-owner goal mutation and production anonymous model tools are refused. HTTP goal calls are
  bounded tracked tasks; shutdown closes admission and waits for settlement. Audit failure before
  writing produces no goal; failure after writing is unknown and cannot invite model replay.
- Per-device authorization leases cancel pending and already-accepted work when a device is
  removed or re-paired. An old lease never revives. A real two-device daemon test proves the other
  approver cannot approve a revoked owner's goal, the run cancels, no goal is written and the
  unrelated device stays authorized.
- HTTP unknown tool outcomes use `409`, `outcome_unknown`, `retryable: false` and
  `recoveryRequired: true`; MCP retains the classification in `_meta.gta-claw.error` and explicitly
  warns against automatic repetition. A route timeout is conservatively unknown.
- CLI, TUI and Slint validate one native complete-preview contract: caller, account, generation,
  publication/revision and resource must match the actual displayed header. Missing fields,
  changed fingerprints, truncated JSON and ambiguous identity text are refused. CLI decisions
  re-fetch the preview on the same epoch. TUI requires scrolling through the complete display.
- Slint retains pending delivery state, rejects old epochs/history snapshots, recovers active and
  finished runs, acknowledges only complete results, and supports run-bound cancellation.

## Workspace Policy

`GTA_CLAW_WORKSPACE_POLICY` is bounded JSON, read from the daemon's trusted startup environment.
It is absent by default: that exposes no native filesystem tools. Unknown fields are rejected.
The root must already exist. Owner access and writes are independent explicit opt-ins.

```json
{
  "root": "D:\\AgentWorkspace",
  "allowOwner": false,
  "allowWrite": false,
  "subjects": [
    { "source": "gateway", "subject": "PAIRED_DEVICE_WIRE_ID", "account": null }
  ]
}
```

Use an actual authenticated subject, not a session key or routing header. Policy source labels
are `gateway`, `http`, `mcp`, `channel`. Only ingresses that supply verified execution authority
can use these rules. Current limits: 32 KiB policy, 128 subject rules, four concurrent native
operations, 1 MiB files, 2,048 directory entries and 4,096 walked files. A matching rule does not
bypass per-call approval or the sandbox. Restart is required to change this immutable policy;
configuration reload withdraws old work but does not reread this environment variable.

## Verification

The [receipt](native-execution-20260914.json) records exact commands, local logs and hashes.
Windows x86_64 only; private temporary workspaces, loopback listeners and test credentials.

| Check | Result |
|---|---|
| Ten core/runtime/tool/client packages, all test targets | 1,243 passed, 0 failed, 4 ignored helper entries; 65 test binaries |
| Slint desktop complete binary tests | 77 passed, 0 failed |
| Core all-target strict Clippy | Passed; earlier failed lint logs retained separately |
| Desktop all-target strict Clippy | Passed |
| Repository policy | 12 passed, 0 failed |

The core test log precedes two equivalent test-only changes: immediate event-handle drops and
`Result::is_ok_and` in the Windows junction fixture. The final strict lint includes those changes.
These are not a source-frozen build or whole-workspace/all-platform acceptance. The source witness
is a hash of 654 tracked/unignored Rust, TOML and lock files, not a complete build-input manifest.
Old sealed `compat/upstream`, `compat/legacy` and trusted release-policy inputs were not rewritten.
Native execution logs are local ignored build output and may disappear during cache cleanup.

## Remaining Work

- No shared atomic transaction spans run, turn, context, goal, audit and external effects.
  Full archive quotas/pruning, encrypted backup, restore and OpenClaw import remain incomplete.
- Per-account/channel authenticated execution and multi-tenant session ownership remain open.
  Production legacy/channel paths without verified authority cannot execute model tools.
- Plugin binary/resource capability consent, unified plugin effect auditing, skill execution,
  native process/network policy, additional provider composition and full MCP/ACP lifecycle
  remain incomplete. Plugin publication revision is not yet a full binary-digest contract.
- TUI full chat/onboarding/reconnect workflow, Slint settings/workspace trust/streaming and mobile
  platform bridges still need development and independent usability/device acceptance.
- Windows tests do not prove Unix race protection or physical power-loss durability. The native
  write adapter conservatively reports unknown after authorized write failures; a confirmed
  `fs_write` response is not yet a cross-object or physical power-loss durability guarantee.
- September upstream contract extraction, local tag signature verification and external
  interoperability remain open. Native payloads are not asserted exact upstream payload parity.
- Development Rust is 1.98.1 and Slint 1.17.1. Protected builders still pin Rust 1.97.1;
  reviewed policy/toolchain/image changes are required before release packaging. MSRV 1.94,
  real accounts, migration cutover, mobile devices, signing and soak gates are not completed.