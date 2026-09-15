# Native Follow-up, 2026-09-14

This is an incremental development record, not a release or whole-project acceptance.
Its [machine-readable receipt](native-followup-20260914.json) records the current Windows
checks and source witness. The earlier [native execution record](native-execution-20260914.md)
is preserved as historical evidence; its larger, different test cohort does not certify this source.

A later [fixed-address network receipt](native-network-20260914.json) supersedes the six touched
source hashes from the 777-test checkpoint for network composition. It records 497 passing tests
in three related packages and strict Clippy; the earlier source witness remains historical.

The subsequent [state/channel identity receipt](native-state-channel-20260914.json) records
710 passing tests in six related packages and strict Clippy. Its 659-file source witness replaces
earlier witnesses only as a newer snapshot, not proof that every historical test was rerun.

Latest [durable channel delivery and TUI ACK receipt](native-channel-delivery-20260914.json):
336 passing tests in four related packages, strict Clippy, and a new 659-file source witness.
The following delivery section supersedes the earlier statement that channel message IDs and
reply claims were not yet persisted. Each prior receipt remains an immutable historical checkpoint.

Later [preview/desktop receipt](native-preview-desktop-20260914.json): 128 migration/CLI tests and
78 no-window desktop tests, with strict Clippy for both workspaces. Its three source hashes identify
the exact bounded-deserialization and desktop-state changes; earlier matching hashes are historical.

Latest [encrypted native snapshot receipt](native-encrypted-snapshot-20260914.json): 446 passing
tests in five related packages, three-package strict Clippy, and a 661-file source witness. The
temporary background test execution completed; no duplicate run was used to replace its result.

Latest [native skill/device-event receipt](native-skills-device-events-20260914.json): 606 passing
tests in four related packages, strict Clippy, and a 662-file source witness. It includes actual
native, restricted HTTP and signed Wasm skill execution, superseding earlier uncomposed-skill
and missing-positive-plugin claims only for this bounded scope. Concurrent local edits were retained.

Latest [session-query and candidate-contract receipt](native-session-contract-20260914.json):
406 tests across conformance, CLI, TUI and daemon, strict Clippy and 12 separate repository-policy
tests. The 664-file source witness is not a frozen build manifest. Concurrent explicit-memory
development was retained and included in the final passing run, not reverted to an older checkpoint.

## Candidate Requests and Session Queries

The independent September artifact records eight source witnesses from fixed OpenClaw commit
`3a9d69db306cd7f081e06254cb89c4bcc14a7107` and six manually reviewed parameter schemas:
`agent.wait`, `chat.abort`, `chat.history`, `chat.send`, `sessions.describe` and `sessions.send`.
The bounded loader checks artifact drift, source/commit identity and offline validator compilation.
Negative tests cover unknown fields, nulls, numeric and array bounds, duplicate input receipt IDs,
attachments and mentions. Schema construction was reviewed against TypeBox 1.3.18; ungenerated
Record key length hints were not invented as wire restrictions.

Actual Rust CLI child processes and the TUI's real WebSocket tests check their outgoing send,
history, wait and abort parameters against those schemas. CLI description requests are checked too.
Native `agent.wait` with `acknowledgeRevision` is explicitly rejected by the upstream-only schema:
it remains a separately named GTA durable-result extension, not upstream compatibility evidence.

The daemon now reads `sessions.describe` from its owned redb session snapshots, rather than the
standalone Gateway's separate in-memory store. It accepts `key` and the old `id` alias, rejects
conflicting keys and unimplemented options, and returns state/turn/revision/update metadata without
message content. Missing and other-device sessions are unavailable. Real paired-device tests verify
owned queries, restart stability and refusal of another device's session. The generic Gateway method
and sealed July fixtures are unchanged. CLI exposes this as `gateway describe <session>`.

Native `chat.history` now accepts optional `limit` in 1 through 1000, default 256. The existing retained
window remains capped at 256, and responses report both `requestedLimit` and effective `windowLimit`.
A smaller limit returns the latest entries in chronological order. CLI supports `history --limit`.
Tests verify latest-one behavior, explicit cap, invalid/null/fractional bounds and original scopes.
`sessions.send` also recognizes upstream `key`; native sends still require an explicit idempotency key.

These are reviewed parameter contracts and selected native behaviors, not full upstream payload,
response, event, archive or interoperability acceptance. History cursors, other history projections,
derived titles and last-message description options remain unsupported and are refused. Local source
signature verification, all-platform execution and complete product gates remain open.

## Implemented and Checked

- Native filesystem and process tools share the existing registry, schema, bound approval,
  authority, durable audit and tracked shutdown. No workspace policy means no native tools.
  Process execution additionally requires owner authority, an explicit program allowlist,
  trusted SHA-256 and an exact complete argv vector. Invalid arguments are refused before approval.
- The executor checks the trusted digest through the same handle held across spawn. Windows
  denies executable write/delete sharing and pins ancestor directories. Tests reject same-length
  content changes with the original timestamp restored, and reject file/ancestor replacement
  while the actual execution pin is held. These are not claims of equivalent Unix race guarantees.
- Actual daemon HTTP calls, paired Gateway approval, deny/approve, safe audit and a Rust child
  process run end to end in temporary directories. Cancellation and dropping the invocation
  future terminate the owned child and drain tracked work. No unrelated process was signalled.
- OpenAI-compatible and Anthropic clients are composed from explicit native startup policy.
  Endpoint credential trust is enrolled separately and checked before reading the secret.
  Automatic provider retries are disabled. A 503 fixture produces one generation attempt.
  Explicit default models are pinned against file/admin/role reload; another catalogued model
  cannot silently replace them. Both providers use actual Rust HTTP clients against local fixtures.
- Signed-plugin arguments use jsonschema 0.56.0 with offline reference resolution and bounded
  linear regular expressions. Malformed replacement schemas withdraw old publications.
  Durable authorization audit precedes invocation; failed/unknown completion forbids automatic
  replay. The new effect-path test uses a closed/missing-plugin host, not positive plugin acceptance.
- Gateway session ownership is committed atomically with initial run admission and survives reset
  and restart. Session list/history/cancel check that owner. Legacy routing reserves a separate
  namespace; it does not authenticate legacy users or solve channel multi-tenancy.
- TUI supports explicit OS-protected profiles, native send/query/run-bound cancel and retained-key
  reconciliation. Effectful commands carry the ready connection identity observed by the UI.
  A two-connection test rejects old sends, cancel, approvals, ACK and answers with zero extra RPCs.
- TUI recovers pending and active runs through independent bounded cursors. Each page waits for
  workspace rendering and ACK queueing before continuation. Multiple complete results cannot
  overwrite one pending ACK; identical text from different runs retains distinct identities.
  Older results do not replace the current cancel target. Message/tool/question/diff/artifact
  updates are session-scoped; selection changes clear the old view. Outcome unknown is explicit.
- TUI column layout uses unicode-width 0.2.2. Wide glyphs no longer overrun the tool column;
  long transcripts wrap and input/prompt bands do not overlap. This is not full grapheme support.
- OpenClaw read-only preview is exposed through the Rust CLI. It inspects bounded configuration,
  session-index and JSONL containers, without printing config values or message contents. It
  rejects unsafe roots, hard links and exceeded budgets; Windows UNC/device roots are refused
  before access. It never imports, writes source state, follows includes, reads credential files,
  resumes tasks or treats SQLite/WAL inventory as a verified database snapshot.

## Native Provider Policy

`GTA_CLAW_PROVIDER_POLICY` is a closed JSON object, at most 16 KiB. Supported `provider` values
are `openai` and `anthropic`; `model` is exact and `apiKey` is a SecretRef, not the credential.

```json
{"provider":"openai","model":"your-exact-model-id","apiKey":"env:NATIVE_PROVIDER_KEY"}
```

The operator must populate the referenced secret securely in the launch environment or use a
supported platform secret reference. Do not place real secrets in this document, argv or logs.
Default endpoints are `https://api.openai.com/v1/` and `https://api.anthropic.com/`.
Optional `requestTimeoutMs` is 1000 through 120000. `baseUrl` may select a different endpoint,
but credential release to a custom origin requires independent trusted enrollment:

```json
{"openai":["https://models.example.test"]}
```

That separate JSON belongs in `GTA_CLAW_PROVIDER_ORIGINS`. Entries contain only scheme, host
and optional port. No credentials, query or fragment are accepted. HTTPS is required except for
explicit loopback HTTP fixtures. No endpoint policy may grant itself credential trust. Explicit
native mode rejects `--smoke`, disables legacy Copilot Device Flow, and refuses a conflicting role
model. Changing the pinned default requires a reviewed startup-policy change and restart.
Full typed configuration/reload integration and real-account verification remain open.

## Workspace and Process Policy

`GTA_CLAW_WORKSPACE_POLICY` is a closed JSON object of at most 32 KiB. `root` must be an
existing absolute, non-link directory. `allowOwner`, `allowWrite` and `allowProcess` default false.
`subjects` may grant exact verified source/subject/account tuples; at most 128 are accepted.
An owner still needs `allowOwner` or a matching subject rule. Source values are `gateway`,
`http`, `mcp` and `channel`. Caller claims are supplied by the authenticated ingress, not tool JSON.

```json
{"root":"D:\\isolated-workspace","allowOwner":true,"allowWrite":false,"allowProcess":false,"subjects":[]}
```

Process opt-in adds at most 16 unique entries under `programs`, each with `name`, absolute `path`,
lowercase 64-character `sha256` and `args` (the full ordered vector, at most 64 entries). Use a
separately reviewed digest of the exact executable. The file cannot be a shell, interpreter,
script, linked path or executable under the writable workspace. A mismatched digest rejects
the configuration; it is not replaced with an automatically computed enrollment.

`process_exec` accepts only the configured name and exact argv; the optional working directory
is workspace-relative. Environment is cleared except the platform minimum. Execution is bounded
to 30 seconds and 4096 output bytes. Smaller caller deadlines may be selected, not larger ones.
Every call still needs a single bound approval, and its preview identifies executable, digest,
workspace and complete arguments. `allowWrite: false` restricts filesystem tools only.

**This is not an OS filesystem/network sandbox.** An approved native process retains host OS
permissions and may read/write outside its cwd or use networking. Review its actual behavior and
input files before opting in. A digest identifies the executable, not all of its dynamic libraries
or configuration. Authorized failures, cancellation and unconfirmed effects require reconciliation,
not automatic retry.

## Fixed-address Network Policy

The later increment composes `net_fetch` only when `allowNetwork: true` and `networkTargets`
are explicitly configured in the workspace policy. One through sixteen targets are accepted,
each with a unique canonical host, an origin and one through eight static IP addresses.

```json
{"origin":"https://service.example.test","addresses":["1.1.1.1"]}
```

This is a schema example, not a working or recommended destination. Replace both values with a
reviewed matching service/address pair; TLS still verifies the original hostname. Public targets
require HTTPS and public IPs. Only explicitly named loopback literals may use HTTP, with an
explicit nondefault port and the exact same pinned literal. No arbitrary private/metadata access
or DNS lookup is permitted. This narrow mode does not follow service address changes automatically.

Each GET/HEAD requires authenticated owner authority and a bound approval identifying origin,
pins, workspace and complete URL. No caller headers/body or inherited credentials are accepted.
Redirects are returned as failures without following them. One exchange has a 15-second deadline,
4 KiB body bound and 16 KiB header bound. The reused rustls transport returns the actual socket
peer; the existing tool verifies that it is pinned. Truncated responses are not treated as complete.
GET/HEAD is not proof that a remote server has no side effects, so post-authorization failures are
conservatively unknown and require reconciliation before repeating the request.

Shared proxy rules are checked during startup. An unusable proxy or a target selected for a proxy
that the fixed-address transport cannot honor rejects configuration, never silently goes direct.
Explicit configured bypass/loopback behavior follows the existing shared policy. Proxy tunnelling,
general DNS and broader network modes remain unimplemented. Actual local deny/approve tests prove
zero requests before approval and after denial, exactly one after approval, safe audit, rejection
of metadata/mapped-private addresses, no redirect follow, and socket/task drain on cancel/drop.

## Verification

- Current eight-package all-target tests: **777 passed, 0 failed, 7 ignored helper entries**,
  46 test binaries. The repository-policy suite contributes 12 passing tests.
- Seven touched packages and all targets pass strict Clippy with `-D warnings`.
- Root locked offline metadata: 38 workspace members, 428 resolved packages, no Slint or checked
  JavaScript runtime packages. No npm, Node, JS interpreter or WASI product execution was added.
- The source witness covers 658 Rust/TOML/lock paths. It is not a complete build-input manifest
  and does not freeze the worktree. Logs are local ignored evidence, with SHA-256 in the receipt.
- Tests use isolated local HTTP/WebSocket fixtures, temporary directories and owned Rust child
  processes. Test credentials/profiles are independently named and removed by their fixtures.

Remaining code work includes authenticated channel tenancy/durable delivery, complete skill/MCP
composition, general network/proxy coverage, cross-object recovery and archives, full streaming/snapshot
reconciliation, and real OpenClaw snapshot/import/restore. Cross-platform/device/real-account,
physical power-loss, MSRV 1.94, migration, release and soak requirements remain unverified.
Slint remains 1.17.1; no new visible desktop window or mobile session was run in this increment.
Protected release builders still pin Rust 1.97.1 and were not rewritten to allow development 1.98.1.
No Git commit/push, production proxy change, deployment or user-state cutover was performed.

## Unknown State and Channel Identity

The application port now has an explicit non-retryable `OutcomeUnknown` variant. Database commit
uncertainty and lost state-worker results no longer become ordinary retryable unavailability.
Runtime tool execution treats this class as fatal to the current turn, not as a failed tool message
the model may repeat. HTTP tool mappings preserve the class, and Gateway state queries/ACK no
longer flatten storage failures into invalid parameters. Native process/network/write failures
whose effects are uncertain use this class rather than asserting that a commit definitely occurred.

State writes are fenced by a sticky per-open database flag after an unknown commit or worker
failure. Reads remain permitted for reconciliation; shutdown does not clear the flag. The actual
blocking worker catches its own failure so dropping the caller does not hide it. Operator status
and shutdown report recovery required; new Gateway admission is refused. An explicit reopen uses
normal redb recovery and still requires reconciliation of the original operation; it is not proof
that external effects may be repeated. Tests commit a real record, lose the worker result, verify
the record remains readable, refuse later writes, and repeat with an already-dropped waiter.
Physical storage failure/power loss and cross-object atomicity are separate unverified requirements.

Telegram/Discord normalized messages now enter runtime with non-owner Channel authority, a
source/account/sender-derived subject, and a separately hashed source/account/conversation/sender
session. The shared message validator runs before constructing claims. Tool permission generation
and cancellation are bound to that invocation. Explicit workspace subject rules and human approval
still apply; channel messages cannot obtain owner-only tools merely by supplying routing text.

Authenticated session reservation commits ownership once, refuses other identities, and never
adopts an unowned historical checkpoint. Legacy routing cannot take an owned channel session;
reset/reopen preserves ownership. Real channel dispatch through AgentRuntime/redb with an isolated
activated smoke provider verifies two accounts' history and reset isolation. Old channel histories
are preserved but not automatically reassigned to the new scoped sessions. These tests do not
contact real Telegram/Discord accounts. Durable message IDs, delivery claiming/outbox/ACK and
restart deduplication remain incomplete; Teams/WhatsApp's legacy path still lacks this tool identity.

## Durable Channel Admission and Delivery

Telegram/Discord now persist a versioned normalized inbound envelope before execution. The run
key is scoped by channel/account/sender plus conversation/message ID; changing content under an
existing identity is refused. The entire dispatch, including `/reset`, is claimed before work and
tracked independently of its caller. Duplicates read the retained result. Already executing or
unknown messages are not automatically executed again, including after restart.

The production Telegram poller uses a new durable-admission callback. Its next offset advances
only after relevant batch messages are admitted and queueing succeeds; a full queue or storage
failure retains the old offset for provider replay. Previously processed IDs are skipped on replay.
The old `poll_once` compatibility method remains unchanged. Discord admits before dispatch queue
insertion; a full queue retains the input durably and stops the worker instead of discarding it.
The provider cursor/resume session itself is not yet durable; dormant queued inputs have a read-only
operator query but no approved replay workflow, and therefore must not be called fully recovered.

Reply delivery has a separate record bound to run, exact terminal revision and content digest.
Claiming precedes all outbound segments. All confirmed segments allow one transaction to mark
delivered and remove the pending-result notification; retained run/input/result history remains.
Any interrupted/failed attempt remains unknown and cannot automatically be reclaimed. Startup
marks incomplete sending records unknown and validates their original terminal run references.
A claim written before a crash but before any bytes were sent is also conservatively unknown.
This trades automatic redelivery for avoiding duplicate effects; it is not external exactly-once.

Telegram confirmation requires a positive remote message ID. Discord 2xx must contain a positive
numeric message ID and the expected channel; empty or inconsistent success responses are not
delivery confirmation. Explicit 429 handling remains bounded. Remote per-segment receipt IDs are
validated but not yet archived/exported as a complete reconciliation log.

Tests exercise actual redb with seven direct process-exit boundaries: admission, execution claim,
result, result ACK, delivery claim, delivery confirmation and failed delivery. A real AgentRuntime
plus the channel dispatcher and a scripted Discord transport verifies only one send for successful
and unknown replies, both before and after reopen. These are not real-account acceptance tests.

The existing authenticated Admin RPC `channels.status` accepts an explicit native extension:

```json
{"method":"channels.status","params":{"nativeRecovery":{"channelId":"telegram","accountId":"default","conversationId":"telegram:42","senderId":"7"}}}
```

The response retains `channels` and adds `nativeRecovery`, with bounded pending/active pages,
independent `after`/`activeAfter` cursors, run phases, delivery phases and storage-recovery status.
Add `runId` (without cursors) for a specific result's status. Identity must match channel/account/
conversation/sender. No message content is returned, no action occurs, and `automaticReplay` is false.
Actual HTTP production tests cover this extension and reject unknown `execute` fields; the frozen
Admin method allowlist is unchanged.

TUI ACKs now require a response matching exact run/revision, `durable: true` and `acknowledged: true`.
A validated completion event wakes the render loop to continue any backpressured ACK/recovery queue.
Wrong or incomplete success receipts remain unconfirmed without automatic resend. Current TUI
coverage is 57 passing tests, included in the 336-test receipt.

## Preview Parsing and Desktop Unknown Results

OpenClaw preview now builds JSON/JSON5 values through a bounded Serde visitor over the existing
parsers. Depth is limited to 64 and each document/JSONL record to 16,384 value nodes before deeper
values are allocated. Duplicate object keys and non-finite numbers are refused as requiring manual
mapping; they are not silently overwritten or changed to null. Tests reject a 10,000-level input,
wide values and ambiguous session/transcript fields while retaining normal JSON5 comments, trailing
commas, quoted strings, hexadecimal values and finite numbers. Source files remain unchanged.

Slint desktop now presents Outcome unknown as a distinct warning terminal state, clears its active
cancel target, requires durable result responses, and only accepts exact matching ACK revisions.
It does not ACK a result that was rejected as stale or belongs to an unselected session. Tests cover
the 13 states, unknown terminal handling, missing durability, wrong ACK revisions, existing epochs,
focus behavior and software rendering. No visible native window or mobile device was exercised.
These checks do not prove that every byte of a scrollable result was physically read by a user,
and full presentation/recovery reconciliation remains a product requirement.

## Encrypted Native State Snapshots

StateDatabase can stream a bounded portable snapshot from one redb read transaction, retaining
ordered raw JSON records with an exact count and SHA-256 footer. A concurrent source write does
not mix revisions into the snapshot. Restore accepts only an empty independent target and commits
once after validating every record, ordering, count, digest and end of input. Limits are 256 MiB,
262,144 records, the existing per-record/key bounds, and a bounded line reader. Missing/future
headers, duplicate keys, truncation, trailing bytes, corruption and nonempty targets are refused.
An uncertain source before or during export cannot produce a successful backup receipt.

The CLI now exposes `state snapshot export/restore` through age 0.12.1 streaming encryption with
bounded scrypt work factor 18. Passphrases enter through bounded stdin only and are zeroized;
stdout contains metadata, never secrets or state contents. Existing source and exclusive new target
handles reuse sandbox path, ancestor, hard-link and file-identity checks. The state database uses
the same validated handle, not a re-opened output path. Source locking is respected.

Actual CLI subprocess tests verify encrypted bytes, exact large-integer roundtrip, wrong-passphrase
rejection before target creation, truncation/tampering without partial committed records, hard-link
refusal, absent-source refusal, and byte-unchanged existing archive/restore targets. The 446-test
cohort also checks production daemon consumers and the repository policy. The root graph now has
500 packages/38 members; age has no enabled optional features. Only the existing proxy was used
for dependency downloads, including a 483.8 KiB missing cross-platform package during metadata
verification. No proxy settings or production service were changed.

Use the [CLI snapshot guide](../../apps/gta-claw-cli/README.md#encrypted-native-state-snapshots).
The archive is encrypted, but a restored redb file is plaintext and needs a protected parent
directory. Normal redb source recovery may write its internal journal. This is not a forensic
read-only, full at-rest encryption, whole-file I/O deadline, complete ACL or power-loss guarantee.
Goals, files, attachments, pairing, credentials and configuration are not part of this single-store
backup. No external effects, user-state restore, activation or automatic task resumption were run.

## Skill Composition and Device Event Privacy

NativeSkills is now composed into the same provider/MCP tool catalogue, HTTP dry-run and runtime
approval executor as native tools. It accepts an explicit startup-only `GTA_CLAW_SKILL_POLICY`,
not arbitrary discovered instructions or executable files. Schema version 1 allows at most 32
unique manifests, each at most 16 KiB, in a policy of at most 64 KiB. Root parameters must be an
object. The same offline jsonschema validator and bounded linear-pattern options as plugin tools
enforce declared constraints before preparing an invocation; duplicate JSON fields are refused.

```json
{"schemaVersion":1,"skills":[{"id":"project.read","description":"Read a reviewed workspace file","parameters":{"type":"object","required":["path"],"properties":{"path":{"type":"string"}},"additionalProperties":false},"execution":{"kind":"native","handler":"fs_read"}}]}
```

This example also requires a separately approved workspace policy. Native handlers may only name
actually configured native tools. Skill manifests do not grant workspace access or owner status.
Wasm manifests use `execution: {"kind":"wasm","plugin_id":"...","export":"..."}` and require
the exact tool to be published by an active plugin under the existing signature, identity and
capability policy. Skill names are stable bounded native tool names reported by MCP `tools/list`;
clients should discover them rather than guess the generated suffix.

HTTP manifests are limited to `GET`, no static query/fragment, no custom headers and query-encoded
parameters. They require the separately configured fixed-address network policy described above:

```json
{"schemaVersion":1,"skills":[{"id":"service.read","description":"Read an approved service","parameters":{"type":"object","required":["query"],"properties":{"query":{"type":"string"}},"additionalProperties":false},"execution":{"kind":"http","request":{"method":"GET","url":"https://service.example.test/read","parameters":{"kind":"query_parameter","name":"input"},"response":"json"}}}]}
```

The complete arguments are encoded as one query value. No implicit credential release or general
DNS/proxy transport is added. Responses must be complete UTF-8, successful HTTP, and match the
declared `json` or `text` representation. Unsupported methods, unavailable origins, malformed
responses and truncation fail closed; an attempted request is not automatically repeated.

Approval binds the manifest digest, target publication/revision, target resource and encoded
arguments. Preparation is repeated before execution. Skill and underlying effect audits share the
same call ID without storing parameters or output. Four tracked skill tasks own their targets until
settlement; cancellation, dropped callers and shutdown preserve final audit and drain owned work.
The existing in-flight network fixture verifies this ownership rather than only checking counters.

The actual daemon fixture publishes three skills and one locally signed Wasm plugin. MCP discovery,
HTTP preflight, Gateway deny/approve/reload, precise GET query encoding, Wasm JSON output and both
audit layers pass. The test uses a locally signed derivative of the existing probe component and
does not claim any upstream plugin has been ported. Admin status now counts current executable
skill bindings separately from signed-plugin activation. Bundled migration inventory remains partial.

Gateway fan-out additionally supports host-only device routing metadata. Real authenticated
connections register their verified device ID, and native run/tool/session/result events are
filtered before queue insertion. Multiple connections of the same device may receive them; other
devices, even administrators, cannot. Event scopes and session filters still apply and wire sequence
numbers remain per-connection. Approval visibility retains the existing approvals scope. Bus tests
and the real two-device revoke/approval test pass; cancelled state is verified after clean shutdown
through an original-owner lookup, not by leaking its final event to an unrelated approver.

## Explicit Identity-scoped Memory

The [explicit memory receipt](native-explicit-memory-20260914.json) records this later increment:
579 passing tests, zero failures and four ignored helper entries in memory/state/runtime/daemon,
23 test binaries, plus strict Clippy for the same four packages. Earlier receipts remain historical;
the source witness is captured after checks, is not a complete build-input manifest, and does not
freeze the concurrently changing workspace. No real model/channel account, device, visible GUI,
deployment, user-state migration, Git publication or production proxy change was performed.

Memory is disabled unless the operator explicitly supplies startup-only `GTA_CLAW_MEMORY_POLICY`:

```json
{"schemaVersion":1,"enabled":true}
```

Unknown versions/fields, duplicate JSON keys, malformed values and policies over 1024 bytes are
refused. The enabled `memory_notes` tool is shared by the provider catalogue, runtime and HTTP/MCP
tool bridge, backed by the same redb state store. An existing conflicting tool name refuses startup;
later conflicts remove the ambiguous name from both catalogues. Closed memory is not advertised.
Admin status exposes `runtime.explicitMemory` metadata, never stored note contents.

Every operation requires authenticated execution authority and a complete bound approval. An
enabled memory policy does not confer owner access to files/processes/network, and read-only MCP
credentials cannot call the tool. Storage is partitioned by authenticated source, subject and
account, not session. The same identity can recall across its sessions; Gateway devices and distinct
HTTP/MCP/channel identities do not share notebooks automatically. A partition hash is not a credential.

| Action | Required fields and bounds | Result |
|---|---|---|
| `list` | `action`; optional `limit` 1-32 (default 16). `after` requires the returned notebook `revision`. | Metadata only, notebook revision, `nextAfter`. |
| `get` | `action`, `id`; optional byte `offset`. Nonzero offsets require the note `revision`. | Up to 2048 UTF-8 bytes, note/notebook revision, source label, `nextOffset`. |
| `search` | `action`, nonblank `query` up to 4096 UTF-8 bytes; `limit` 1-8 (default 8). | Bounded lexical matches, 256-byte snippets, source labels and coverage. |
| `save` | `action`, `id`, `kind`, `content`, `expectedRevision` of the notebook. | New monotonic notebook/note revision, no echoed body. |
| `delete` | `action`, `id`, `expectedRevision` of the notebook. | Removal result and notebook revision; an absent note does not advance it. |

Each notebook holds at most 256 notes; each note has at most 8192 UTF-8 content bytes and a source
session label of at most 256 bytes. The shared encoded state-record limit also applies. Note IDs
are 1-64 ASCII characters, start alphanumeric and otherwise allow alphanumeric, dot, underscore or
hyphen. Kinds are `fact`, `preference` and `procedure`; these are caller labels, never authority.
Content must be nonblank, with no controls except tab/CR/LF. Tool argument and encoded result bounds
are 16 KiB. JSON Schema describes per-action fields and cursor requirements; UTF-8 byte bounds and
unambiguous JSON parsing are enforced separately. Non-alphanumeric-only search queries are refused.

For example, this HTTP tool request validates without writing; remove `dryRun` only when prepared
to review the corresponding Gateway approval. Transport credentials still belong in the authorized
request channel, not this JSON:

```json
{"name":"memory_notes","sessionKey":"notes-review","dryRun":true,"args":{"action":"save","id":"units","kind":"preference","content":"Use metric units.","expectedRevision":0}}
```

Use `list` first to obtain the current notebook revision. Concurrent writes using the same revision
have one winner; changed notebooks or note revisions reject stale pagination and writes. Deletes
retain the notebook revision, so an old creation request cannot resurrect a removed note. Search
rebuilds the bounded existing keyword index from the current identity's snapshot. It is not semantic
embedding retrieval or CJK substring segmentation, and does not inject notes into system instructions.
`untrustedContent` and caller-supplied source labels remain explicit; a source label is not proof
that a particular transcript exists or belongs to the caller.

The tool uses four tracked tasks, invocation cancellation/revocation, durable authorization before
execution and a matching completed/failed audit afterward. Reads recheck authority before returning
content. Output encoding/size checks precede the completion audit. Shutdown closes tool admission and
joins its tasks before closing the state store. The bound daemon tests verify default-off discovery,
MCP/HTTP separation, dry-run and denial without writes, exact approvals, correction, stale revision
refusal, two process restarts and content-free audit. A local Rust OpenAI HTTP fixture additionally
executes three real Gateway runs: save, cross-session recall and another device's isolated search.

That fixture exposed and now covers an existing runtime defect: a tool-only model response was
ingested as an empty assistant text record, which the context index refused before approval. The
runtime now skips only the absent text in a tool-bearing round, preserving tool calls, approvals,
ordinary text and the existing handling of an empty non-tool response.

Deleting a note removes it from this current notebook and future keyword snapshots. It does not
erase earlier chat/tool history, data already sent to a model, redb free pages or old backups.
Restoring an older backup can restore older notes; full deletion propagation across archives/backups,
semantic recall, automatic memory management, global notebook quotas, dedicated client workflows,
physical storage failure and cross-platform/real-account acceptance remain open. This increment does
not close the full M4-01 or M4-02 checklist items.

## Model-free Memory Client and Portable Notes

The [memory client receipt](native-memory-client-20260914.json) records a subsequent four-package
cohort: **535 passed, 0 failed, 5 ignored entries across 25 test binaries**, strict Clippy and a root
workspace/all-target type check. This cohort differs from the previous 579-test memory cohort and
does not replace its scope by adding counts together. An expected CLI runtime-initialization fault
test emits a diagnostic on stderr; its test and the process command both pass. No new dependency,
real account/device/window, deployment, Git publication or production proxy change was needed.

The runtime now supports one bounded `!tool` JSON envelope with `name` and object `arguments`.
It requires host-authenticated execution authority, cannot mix with other directives or chat text,
and preserves raw argument JSON for the owning tool's validation. Debug output redacts arguments.
The turn never opens a provider round: it uses the existing tool catalogue, binding, approval,
revocation/cancellation and goal-specific authorization, then persists its result. Normal chat,
escaped/fenced literal directives and model-authored calls retain their existing paths. This is a
native input extension, not an added or rewritten frozen Gateway method.

Daemon `health` wraps its original handler/authorization and appends versioned native capabilities.
CLI memory commands require exact authenticated/model-free/durable capability fields, current memory
readiness and, for transfer commands, archive schema version 1. Only then is `chat.send` issued on
the same ready epoch. Unsupported capabilities produce `not_sent`; a malformed/non-durable/mismatched
receipt after sending remains unknown. All seven memory commands require a persistent device profile
and an original idempotency key; no new permission or automatic approval is granted.

CLI `gateway memory list/get/search/save/delete/export/import` is documented in the
[CLI guide](../../apps/gta-claw-cli/README.md#explicit-memory-commands). Save uses bounded content stdin;
import uses bounded archive stdin. Either can use exclusive `--request-stdin` containing a shared
`token` plus `content` or `archive`, with a 64 KiB frame bound and the unchanged inner limits. Duplicate
fields, invalid credentials and mixed modes are rejected before connecting. The token is borrowed
from the zeroized input for decoding into a zeroized buffer/protected credential; it is not copied
into the tool envelope, arguments, logs or output. Actual CLI subprocess/WebSocket tests verify
both token-bearing modes as well as unsupported/disabled/model-backed peers and bad receipts.

Portable archives contain schema version 1 and the source notebook's ordered notes/revisions only.
Export captures the current identity's snapshot, requires a fixed notebook revision, and produces
2048-byte UTF-8 chunks with full SHA-256/byte count. Changed notebooks refuse stale pages. Export is
plaintext and cannot grant destination identity, authority or executable behavior. Import validates
the entire archive, checks the destination notebook revision, and commits one merged record once.
Existing IDs fail unless `overwrite` is explicitly approved; absent notes are not removed. Imported
entries receive the new destination revision and retain untrusted source labels. All failures before
commit leave the destination unchanged, including a conflict after earlier entries were staged.

The encoded direct command/tool arguments remain limited to 16 KiB; large imports fail rather than
silently splitting. Export has a 4 MiB archive ceiling. Client-side automatic page collection/file
encryption and large multi-stage import are not implemented by these commands. Empty import is a
revision-checked no-op. Re-importing an old archive is an explicit new write and can restore a deleted
note; these APIs do not promise erasure from old history, backups or external providers.

Actual daemon integration runs all seven actions through Gateway approval with a real local Rust
OpenAI endpoint recording **zero generation requests**, two daemon restarts, same-key retained-result
queries, overwrite conflicts, archive digest verification and content-free audits. Note text containing
an escaped `!goal` creates no goal records. The test also exposed a pre-existing adapter mismatch:
runtime `Blocked` is not a valid durable RunResult status. Known blocked/denied calls now map to
durable `failed`, keeping their reason and avoiding a false answer-too-large/unknown recovery warning.
Actual mutating interruption still remains unknown; direct calls do not auto-retry it through a model.

M4-02/M5-01 remain open for their full semantic-memory, dedicated GUI, complete deletion and platform
requirements. Previous receipts and failures are retained; the source witness is not a frozen source
tree or complete build-input manifest. Root type checking does not certify independent Slint shells,
real-account interoperability, release toolchain policy or device/runtime acceptance.

## Notebook Quota and Queued-write Revocation

The [quota receipt](native-memory-quota-20260914.json) records 301 passing tests, zero failures and
five ignored entries in state/CLI/daemon, plus strict state/daemon Clippy. It is a later, narrower
cohort than the 535-test client record, not a sum or a new whole-project acceptance claim.

New explicit-memory notebooks are limited to 256 per database. StateDatabase's internal bounded
prefix-insert path holds the existing recovery gate and a redb write transaction while checking
absence, counting matching keys up to the limit, then inserting the first notebook. It does not
decode or copy existing note bodies, and has no separate counter that can diverge from the data.
Normal non-memory commits retain their previous unrestricted-prefix behavior and comparisons.
Memory save and archive import both use the same guarded allocation path.

Deleting the last note retains the notebook and its monotonic revision, including its quota slot.
At capacity, reads, corrections, deletions and imports into existing notebooks still work; a new
identity's first save/import fails normally, without a false storage-recovery fence. The limit does
not truncate pre-existing/ restored over-capacity databases and does not automatically retire
identities. Generic offline snapshot recovery remains a separate privileged workflow; no claim is
made that the total database file, free pages, run history or audit log is capped by this limit.

All memory commits now recheck the immutable invocation's current execution permission after
waiting for writer admission and immediately before modifying records. An actual held-writer test
revokes the request while it waits, then proves that no notebook was written and storage remains
healthy. If cancellation arrives after this mutation admission point, an in-progress commit may
still complete: callers must retain the existing unknown-effect handling, not assume rollback.

Tests fill 255 notebooks, race two independent identities for the final slot, verify exactly one
winner, update/delete an existing notebook at capacity, refuse another identity's import, and
reopen the actual database to confirm the limit and retained empty-notebook revision. Common CAS,
commit-unknown, encrypted snapshot and bound-daemon memory workflows pass in the same scoped run.
The source witness names only the three touched controlling files; it is not a complete build input
manifest. No dependencies, protected contracts, user state, real accounts, devices, deployment or
production networking were changed. Full storage/retention/identity-lifecycle tasks remain open.

## TUI Explicit Memory Commands

The [terminal-memory receipt](native-memory-tui-20260914.json) records 62 passing TUI tests,
zero failures/ignored entries in five test binaries, and strict all-target Clippy. This is a
separate client cohort, not an addition to earlier state/runtime/daemon acceptance totals.

The existing palette now selects list/get/search/save/delete/export/import over the same native
`memory_notes` tool. Structured commands have redacted Debug output and bounded, closed fields;
save/query/archive input uses a distinct editor state bound to its original session. Corrections
and deletion retain notebook CAS revisions; import rejects duplicate/unknown fields and invalid
archive metadata before sending. Supported bracketed paste appends data atomically without submit,
rejects oversized/control-containing pastes, and restores terminal paste mode on normal/panic exit.
The composer tail counts terminal columns, keeping recent wide-character input visible.

The worker requires a persistent device profile and validates native memory capabilities through
health on the same connection epoch before chat.send. All actions reuse complete human approvals,
durable results, recovery and exact ACK; no new RPC method or permission grant was introduced.
Ordinary chat refuses raw direct-tool lines, including case variants. Memory submissions require
complete accepted/revision/phase receipts. Explicit retries preserve the original typed operation,
session and key, while pre-send refusal never clears an earlier unknown effect. Only definitively
unsent input can be discarded; no automatic approval, resubmission or repeated model generation.

The real WebSocket/OS-profile fixture covers fifteen peer/command cases: all seven actions plus
unsupported, disabled, model-backed, missing archive capability, malformed durable receipt,
temporary identity, stale connection and raw direct-tool bypass attempts. Separate input tests
cover UTF-8/envelope limits, closed archives, revision cursors, data containing directives,
session-switch refusal, paste atomicity and unknown-key retention. Eight deterministic terminal
sizes check wide-character editor visibility. Existing approval/reconnect/ACK/terminal tests pass.

Unsubmitted drafts and uncertain client keys remain process-local, not crash-journaled. Archive
pages are plaintext data, not automatic encrypted exports; larger staged imports and complete
TUI/Slint management pages remain open. No actual interactive terminal, real account, deployed
daemon, user profile or external model was exercised. Test-created protected identity aliases
were removed by their owned cleanup guards. Seven source witnesses are captured after checks,
not a complete build-input manifest; the existing dirty Cargo.lock witness is unchanged.

## Slint Explicit Memory Forms

The [desktop-memory receipt](native-memory-desktop-20260914.json) records 84 passing tests,
zero failures/ignored entries and strict desktop all-target Clippy. This is the separate desktop
workspace on Windows, not a sum with TUI or daemon tests and not cross-platform acceptance.

Session now has an explicit seven-action Memory form, independent ID/kind/revision/offset/content
fields, an explicit import-overwrite checkbox, and complete scrollable/selectable read-only result
text. The existing controller requires an OS-protected remembered device and same-epoch native
health negotiation before chat.send. Ordinary chat refuses direct-tool lines; no arbitrary RPC,
new dependency or extra scope was introduced. The strict Gateway codec rejects duplicate/deep
JSON before a validated archive is compacted to one line. Note/query/envelope bounds match the
native service, and all operations retain existing human approval and durable result/ACK paths.

The UI passes its observed session/generation/epoch binding with the form. Changed bindings close
the old form, and stale callbacks are refused. Unknown sends retain the original typed params/key;
explicit retry is disabled while an attempt or bound run is active. A refused retry cannot turn an
earlier unknown effect into a definitive failure. Complete accepted/revision/phase receipts bind
the run before the original pending memory input may be released. A dedicated regression delivers
the result before the receipt, then confirms that exact-key reconciliation and agent.wait recover
the complete result without a new execution or duplicate transcript entry.

Fourteen actual controller/WebSocket cases cover seven actions, unsupported/disabled/model-backed
capabilities, missing archive support, temporary identity, a stale epoch and raw-chat bypass.
Two actual Slint software-renderer sizes (1080x720 and 720x520) exercise the opened form, nonblank
pixels, retained full result text and closing on binding change, without a native visible window.
The original desktop approval, connection, cancellation, history, ACK and rendering tests pass.

The saved profile uses the existing endpoint-scoped `desktop` alias. Test-created profiles for
owned ephemeral local server endpoints were removed with cleanup guards. Local form fields and
unconfirmed keys are not crash-journaled; closing a form/connection discards unsent fields. The
latest memory-result view is session-scoped and cleared on disconnect, not a complete persistent
management database. Export is still plaintext pages, not automatic encrypted-file collection.
Full provenance/deletion, large staged imports, platform interaction and whole-project completion
remain open. Six post-check source witnesses and both existing lock hashes are recorded, not a
complete frozen build manifest. No production service, real account/device or Git operation ran.

## Encrypted Memory File Transfer

The [memory-file receipt](native-memory-files-20260914.json) records 76 passing CLI tests, zero
failures, one existing ignored entry, and strict all-target Clippy. The expected async-runtime
initialization error line comes from the existing passing fault-injection test, not a failed
development environment. This is a CLI-only cohort, not a sum with earlier client/state results.

Memory export now has an explicit new-file mode: destination plus passphrase stdin, or a closed
token/passphrase request-stdin frame. It retains the original revision/session/key, requests each
page through the same native capability-checked direct tool and bound approval path, then waits
for matching durable results using events. Later page keys derive deterministically from the
original key/session/revision/offset. No page is automatically repeated, approved or acknowledged.

The in-memory collector limits archive size to 4 MiB and pages to 4096, checks closed page metadata,
same revision/digest/length, continuous UTF-8 offsets, exact completion, final SHA-256 and strict
MemoryArchive validity. Only then is an age-scrypt-18 output created via the existing pinned
Sandbox parent/exclusive-file API and synchronized. Existing targets are never overwritten;
partial failed outputs are retained. Metadata reports that directory crash durability and server
run-result ACK/cleanup have not been performed.

Encrypted import opens a bounded local file without following unsafe links, caps scrypt work,
authenticates the entire ciphertext into zeroizing bounded memory, validates the archive and
checks the final 16 KiB command before loading identity/connecting. No plaintext temporary file
or source modification occurs. It remains one approved CAS merge, not staged large import. Both
file modes share explicit stdin secret validation with the existing offline database snapshot;
file/KDF jobs are joined after cancellation rather than abandoned under a false hard-I/O deadline.

Actual subprocess/WebSocket tests collect multibyte pages with completion notifications, decrypt
the produced file independently, then import that same file. Bad digest, changed revision, wrong
run, timeout, existing destination and unsupported server cases fail without publishing a new
archive. Wrong passphrase, modified ciphertext and over-limit file cases are refused before any
new Gateway connection; original encrypted bytes remain unchanged. Output/argv never contain the
fixture token, passphrase or note marker. Existing encrypted redb backup/restore tests also pass.

No dependencies, protected policies, production services, real account state or deployment changed.
The four post-check file witnesses are not a frozen or complete build manifest. GUI file dialogs,
large staged import, automatic result cleanup, client crash journals and full semantic/provenance/
deletion workflows remain open. Original checklist completion counts are unchanged.

## Telegram Deferred Batches and Durable Cursors

The [Telegram cursor receipt](native-telegram-cursor-20260914.json) records 313 passing tests,
zero failures and four existing ignored entries across state/channels/daemon, plus strict Clippy
for those same packages. Older channel and memory receipts are separate historical cohorts.

The production Telegram loop no longer treats durable admission/queue insertion as completed host
processing. A deferred batch retains the previous provider offset while messages are drained;
failures or cancellation keep it for re-admission. The next pass uses existing durable run/delivery
claims to skip already handled or uncertain effects. Unknown deliveries are never resent, even
when a batch is re-fetched. Legacy poll_once/poll_once_with_admission behavior remains unchanged;
an outstanding deferred batch prevents any polling mode from bypassing settlement.

The host hashes a domain-separated, length-delimited account/approved-origin/current-credential
binding and persists only that digest and cursor metadata, never token material. Cursor restoration
occurs before the adapter starts. Every poll rechecks the stored cursor; unexpected concurrent
changes, storage errors or failed post-batch CAS stop the worker before it can acknowledge another
batch. A final cancellation check follows the asynchronous state read. New bindings are capped at
256; existing bindings remain writable at capacity, without deleting older records.

A cursor with no advancement for one day, or a regressed wall clock, is conservatively expired to
zero in a compared durable transaction. This precedes Telegram's long-idle random update-ID reset
and affects only the provider offset. Retained run inputs, results and execution/delivery claims
are untouched; old claimed work remains nonreplayable after expiry/restart. The running adapter
can rewind only when connected with no queued or deferred batch. No fake wall-clock waits occur
in tests: timestamp boundaries are explicit inputs to the state API.

Actual state tests race two writers, reopen redb, reject stale/regressing/invalid cursors, fill the
256-binding quota, retain existing updates at capacity and prove expiry cannot re-claim execution.
Adapter tests cover startup-only restore, deferred-batch refusal, processing failure re-fetch and
drained rewind. The actual daemon loop with a scripted Telegram transport and real AgentRuntime
runs both ordinary and concurrent-cursor scenarios: an initial failed reply is sent only once,
the correct persisted cursor survives shutdown/reopen, and a different credential sees offset zero.
Concurrent cursor changes stop the original loop before a further poll; restart uses the newer
committed cursor. No Telegram service, real bot/account or user state was contacted.

An advancing cursor is not proof of successful external delivery. Unknown outcomes remain in the
existing operator recovery query, with no automatic resend. Telegram's upstream retention window,
approved recovery of dormant queued inputs beyond that window, cross-bot account lifecycle,
Discord persistent resume, remote per-segment receipt archives and real-account acceptance remain
open. No dependencies, trusted compatibility fixtures or release policy were changed. Five source
witnesses were captured after tests/lint, not as a complete or frozen build manifest.

## Discord Settled Resume Checkpoints

The [Discord resume receipt](native-discord-resume-20260914.json) records 319 passing tests,
zero failures and four existing ignored entries in state/channels/daemon, plus strict all-target
Clippy for the same packages. It supersedes earlier missing-resume implementation notes without
turning earlier test cohorts into an aggregate project-acceptance total.

The production packet path uses a durable admission callback before accepting message sequence.
Admission failure, malformed dispatch or queue exhaustion retains the earlier sequence and
requests reconnect before later packets can cross the rejected input. The old compatibility
packet entry remains unchanged. A new admitted-input drain works during RESUMING as well as READY,
so replay messages can be processed before RESUMED instead of exhausting a bounded queue.

Resume checkpoints are keyed by a domain-separated digest of exact account, configured Gateway
URL, intents and credential. Stored records contain bounded session/sequence/optional URL, CAS
revision and timestamp, not token material. At most 256 bindings are retained. Clearing/expiration
keeps the revision to reject stale writers; same-session sequence regression is refused. Five
minutes without checkpoint advancement or a regressed wall clock conservatively invalidates the
resume metadata. This is a local expiry policy, not a Discord session-validity guarantee, and
does not remove durable run inputs, results or execution/delivery claims.

The dispatcher reports exact message session/sequence settlement through a bounded channel. Only
the contiguous successful prefix is checkpointed; later ignored packets cannot jump unfinished
work, and equal-sequence replay batches settle together. A failed message stops the worker with
the old checkpoint, while unknown delivery remains nonretryable. Session invalidation is persisted
before reuse, and changing session across unsettled work fails closed. Shutdown drops the settlement
receiver before joining the dispatcher to prevent a full notification queue from deadlocking drain.

Startup restores only before connecting and revalidates saved resume URLs through the current
origin/transport proxy policy. Only the fixed v10/JSON query parameters are accepted; credentials,
foreign origins and unknown queries are refused. Restored connections prefer the validated resume
address and retain the existing bootstrap fallback/RESUME sequence behavior. The actual worker
also no longer exits merely because it receives Opened/HELLO before its business queue is READY;
readiness is reported after the initial checkpoint commit.

Tests use real redb/runtime shutdown and reopen, the actual daemon worker plus local event/transport
queues (no external WebSocket), and the actual dispatcher with a scripted reply transport. They
verify IDENTIFY then saved RESUME, invalid-session clearing, successful-prefix persistence,
unknown second delivery retained across restart, credential/configuration isolation, CAS races,
expiry and clock rollback, allocation quota, and claims not becoming replayable. Adapter tests
drain 100 replayed messages through a two-slot queue before RESUMED and preserve all old Discord
heartbeat/reconnect/close-policy cases. No real bot/account, production proxy or user state ran.

Provider-side session retention, approved recovery of dormant queued messages when resume is no
longer possible, complete cross-bot account lifecycle, per-segment receipt archives, real WSS/
account and platform acceptance remain open. Six post-check source witnesses are not a frozen or
complete build manifest; existing dependency and protected-policy boundaries remain unchanged.

## Durable Segment Receipts

The [segment-receipt record](native-channel-receipts-20260914.json) reports 321 passing tests,
zero failures and four existing ignored entries in state/channels/daemon, with strict all-target
Clippy for state/daemon. It is a separate current cohort, not an addition to earlier test totals.

After every validated Telegram/Discord remote acknowledgement, the production sender commits an
immutable receipt before sending another segment. It retains run ID/result revision, zero-based
segment, UTF-8 byte count, raw UTF-8 SHA-256 and the positive numeric remote message ID, not reply
content. The same transaction compares the original sending claim and inserts the receipt. Foreign
owners, changed claims, noncontiguous indices or conflicting content/remote IDs are refused. A
duplicate identical receipt is an idempotent evidence write, never another network send. Each run
is limited to 1024 receipts and each segment to 16 KiB; queries return at most 32 receipts.

Storage failure after remote acknowledgement stops the remaining sends. The overall claim stays
unknown or sending until startup recovery marks it unknown. Confirmed receipt prefixes survive
that recovery, successful delivery and result notification acknowledgement. No receipt is evidence
that a missing segment was not sent: an external send and local receipt cannot share one atomic
transaction. The records are locally observed transport responses, not remote cryptographic proof.

Use the existing authenticated Admin RPC, retaining the exact channel/account/conversation/sender
and run identity from the earlier recovery query:

```json
{"method":"channels.status","params":{"nativeRecovery":{"channelId":"discord","accountId":"default","conversationId":"discord:room:user","senderId":"user","runId":"<64-lowercase-hex-run-id>","deliveryAfter":31}}}
```

Omit `deliveryAfter` for the first page, then use `nextDeliveryAfter`. The response adds
`deliveryReceipts` and `receiptDigestEncoding: "sha256-utf8"`; `automaticReplay` and `contentIncluded`
remain false. The cursor requires an exact owned run and cannot be mixed with pending/active run
pagination. This is a read-only diagnostic, not an execute/resend or destructive cleanup endpoint.

Actual redb tests persist 34 receipts, reject owner/order/mutation errors and reopen an uncertain
delivery while preserving both receipt pages. The existing independent child-process matrix now
has eight direct-exit boundaries, including receipt-committed/before-delivery-settlement. Actual
runtime and sender tests cover complete Discord segmentation, failure on the second send, and
storage closed after the first remote response: no later send starts, and restart retains only
the confirmed local prefix. Telegram's actual loop covers a successful ID-42 acknowledgement as
well as unknown delivery and concurrent cursor scenarios. HTTP composition rejects malformed or
unscoped receipt cursors. Metadata outputs contain no fixture reply content, and retrying the same
retained delivery after restart performs no network resend.

No dependencies, protected contracts, real channels/accounts, production services or Git operations
were changed. Five post-check source witnesses are not a complete frozen build manifest. Dormant
queue recovery beyond provider retention, full remote reconciliation/bulk receipt export,
cross-platform power-loss and real-account acceptance remain open.

## Credential-scoped Configured Accounts

The [configured-account record](native-channel-accounts-20260914.json) reports 197 passing daemon
tests, zero failures, four existing ignored entries and strict all-target Clippy. Earlier receipts
are historical cohorts, not additional tests in this current result.

Production Telegram and Discord previously normalized every configured bot under `default`, even
though polling/resume checkpoints were already credential-bound. Since runtime sessions and durable
message keys include account ID, replacing a bot could otherwise reuse a former bot's histories
and message IDs. The configured account is now `bot-` plus a domain-separated, length-delimited
SHA-256 of channel and token. The same token/channel pair remains stable across restarts; different
tokens or channels have different partitions. Token bytes are not present in the account ID or
operator output. This is credential-context isolation, not verified provider bot identity.

The derived ID is used by the actual adapters, credential/origin binding, normalized inbound
message, runtime authority, session/dedupe/delivery records and checkpoint bindings. Telegram's
readiness probe and Discord's outbound credential check use the actual bound account, not a
hardcoded label. A message bearing the old/default or another account is refused before the
configured Discord credential is exposed to the transport.

The authenticated Admin RPC `status` exposes `runtime.configuredChannelAccounts.partitions`,
with `binding: "channel/credential"`, `credentialsIncluded: false` and
`automaticHistoryAdoption: false`. Use the current partition for `channels.status` recovery
queries. The map describes configured account identity only, not readiness or a grant of trust;
it is bounded to the two configured channel families.

Rotating a token for the same real bot deliberately creates another partition. Earlier default
and prior-token histories, message claims and receipts remain intact and are not automatically
adopted, reassigned or deleted. Recovery of old records still uses their original account identity.
This may require a future explicit migration after independently verifying the bot identity;
no migration or live token rotation was performed here.

The real runtime history/reset test now uses production-derived account IDs and the same provider
message ID under two credentials. It verifies no conflict with or leakage of the first account,
while same-account changed input is still rejected. Actual Telegram loop/restart/receipt and
Discord complete/partial/storage-failure sender tests use derived IDs; the foreign-account path
performs zero transport sends. Status tests assert current account metadata without token material.
All existing daemon integration and shutdown tests pass. Two post-check source witnesses are not
a complete frozen build manifest. No dependencies, protected contracts, live credentials, real
accounts, production services, data migration or Git operations changed.

## Teams and WhatsApp Inbound Identity

The [verified-channel identity record](native-verified-channel-identity-20260914.json) reports
312 passing tests, zero failures and four existing ignored entries in HTTP API/daemon, plus strict
Clippy for those packages and a root-workspace all-target check. The compile gate covers the shared
message-port change, not platform runtime acceptance. Earlier receipts remain separate cohorts.

LegacyChannelMessage now carries the authenticated adapter's account ID, stable sender ID and
provider message ID in addition to conversation and display metadata. The actual WhatsApp bridge
forwards those values from its normalized SDK message after the existing webhook signature and
configured phone checks. Native runtime processing derives the same scoped non-owner channel
authority/session as other channels and propagates cancellation, rather than calling unscoped chat.
Display-name changes do not change ownership or durable request identity.

An additive process_owned port method lets the native AgentRuntime retain its lifetime and run
the entire model operation under the existing durable input/claim/result path. The default method
preserves compatibility for older implementations; durability is provided by the native override,
not promised by every implementation of the trait. Already claimed or unknown work is not repeated.
The actual WhatsApp adapter uses the owned entry. Malformed identities and pre-cancelled requests
are refused before execution.

Teams keeps its existing bearer JWT issuer/audience/signature/time/endorsement and service-URL
verification before identity normalization. Message/messageUpdate activities now require bounded
activity, conversation and sender IDs and a tenant from channelData or conversation; conflicting
tenant declarations are refused. The account is an app/tenant digest based on configured app ID,
not a display name or claimed owner. Missing sender IDs are no longer filled from names. Only a
bound conversation engine is supplied to the message handler; non-message events receive no
anonymous model engine. The native bridge durably executes normalized message text and routes
deferred status/reset commands into the same app/tenant/sender-owned session and input claim.

Real runtime tests cover two WhatsApp accounts receiving the same message ID, display-name changes,
malformed and cancelled input; the actual adapter tests check complete identity forwarding. Teams
tests cover app/tenant/sender separation, missing/conflicting identifiers, changed content under one
activity ID, repeated messages/reset, wrong conversation routes, actual redb restart and retained
other-tenant history after reset. These are controlled local identities and an existing local
provider, not newly verified live OIDC/JWT sessions. Existing bound HTTP tests still reject
unauthenticated Teams and unsigned or wrong-phone WhatsApp requests.

The inbound fix does not make Teams/WhatsApp outbound sending and remote receipt state durable.
Their reply/typing retry semantics, provider activity edits, full external identity-service matrix,
real tenant/Cloud account and platform acceptance remain open. Reusing a message ID with changed
text fails closed; a complete activity-edit policy is not implemented. Older unscoped histories
are preserved but not automatically adopted. No new dependencies, protected compatibility fixtures,
real account data or production services changed. Five post-check source witnesses are not a
complete frozen build-input manifest, and whole-project acceptance remains false.

## Native WhatsApp Durable Reply Delivery

The [WhatsApp delivery record](native-whatsapp-delivery-20260914.json) reports 328 passing tests,
zero failures and four existing ignored entries in state/channels/daemon, with strict all-target
Clippy for those same packages. It is a current bounded cohort, not an aggregate acceptance total.

The production GraphWhatsAppAdapter now owns the shared AgentRuntime and routes verified webhook
messages through the native persistent processing path. It reads or completes the durable inbound
result, claims delivery once before any outbound call, segments the reply, and commits each remote
acknowledgement before sending the next segment. The legacy SDK handle_webhook/pending-reply retry
behavior remains available for compatibility; the actual production webhook no longer relies on
its process-local reply checkpoints. Constructor wiring selects the native path explicitly.

The new SDK single-segment method checks account/conversation/sender binding, refuses input that
would split into additional calls and performs exactly one request. Success requires one bounded
Cloud `wamid.` identifier; empty 2xx, missing/multiple receipts and invalid IDs are refused. The
shared receipt store accepts bounded wamid IDs as well as the previous positive numeric IDs,
while the runtime selects the valid identifier family for each channel. Exact run/revision/segment,
UTF-8 byte count and SHA-256 are retained; note/reply contents are not included in recovery output.

Any unconfirmed send, invalid response or failed receipt write stops the remaining segments. The
overall delivery remains unknown and cannot be claimed again after restart. This also applies to
a claimed attempt that reports cancelled-before-send: the native path is deliberately stricter
than the older automatic unsent-chunk retry. Evidence cannot prove that a missing local receipt
means nothing was sent, and no automatic compensation or resume of later reply chunks occurs.

Dropping the webhook future cancels its own execution child token and the bound transport token.
An already claimed attempt settles conservatively; later queued inputs do not create model work.
The caller's parent cancellation scope remains unchanged. The blocking worker retains channel and
request-slot ownership until it releases them; transport timeouts and runtime shutdown still bound
in-flight work, not a universal immediate filesystem/network cancellation guarantee.

Actual production-handler tests use real runtime/redb plus a scripted Cloud transport for complete
multi-segment replies, second-segment transport ambiguity, empty success, cancelled-before-send and
storage closed immediately after remote success. A newly created adapter and reopened runtime send
no additional request for any of those claimed deliveries. Confirmed prefixes retain exact wamid,
byte lengths and digests. A paused pre-send test drops the actual native handler, proves zero sends,
no execution of the next queued message, released request slot and retained unknown delivery. SDK
negative tests cover foreign routes/accounts and hidden splitting before transport, as well as
invalid Cloud receipts. Existing signature/wrong-phone HTTP and compatibility tests still pass.

The delivery phase describes confirmed API transport acceptance, not WhatsApp user-delivered/read
state. Template policies, status callbacks, full remote reconciliation, real Cloud credentials,
account lifecycle and physical power-loss/platform acceptance remain open. No dependencies,
protected compatibility fixtures, real user state or production services changed. Five post-check
source witnesses are not a complete frozen build manifest; whole-project acceptance remains false.

## Teams Durable Reply Claims

The [Teams delivery record](native-teams-delivery-20260914.json) reports 331 passing tests,
zero failures and four existing ignored entries in state/channels/daemon, plus strict state/daemon
all-target Clippy. No counts are combined with earlier historical receipts.

Native Teams replies now claim delivery for the exact normalized input and retained runtime result
before typing or sending. RuntimeConversation exposes its successful normalized message/result
pair once; failed calls clear that pair. This matters when the actual Teams handler strips bot
mentions before generation. Deferred commands keep their authenticated input identity. Generated
help and welcome replies also receive durable input/result records, and a replay that generates
different content is refused instead of silently changing the retained response.

Nonempty conversationUpdate/member-added activities require the same stable activity/sender/
conversation and app/tenant identity as message events. Bounded normalized membership metadata is
retained for deduplication, without creating anonymous model work. Existing TeamsAction order and
separate welcome replies are preserved; the sender does not reassemble multiple actions into one
message. Every generated reply requires a durable source activity. The diagnostic reply ring is
kept at its original 16-entry bound even when one activity produces many welcome actions.

Service URLs are validated before generation and again before delivery: only the existing trusted
HTTPS host policy is allowed, without userinfo, query, fragment or nonstandard port. Conversation
IDs are appended using structured URL path segments. Each message response must be bounded,
unambiguous JSON containing a nonblank printable-ASCII resource ID; empty 2xx or duplicated IDs are
not confirmation. The exact ID is retained as `msteams:<resource-id>` in the shared receipt store,
alongside run/revision, segment index, UTF-8 byte count and digest. Strip only that explicit format
prefix when comparing with the provider's original ID. Typing success has no message receipt.

The whole action sequence is owned by one once-only delivery claim. Failure during typing, partial
reply transmission, a missing receipt, storage closure or a dropped send future leaves an unknown
claim and prevents automatic resend after restart. Earlier confirmed receipt prefixes remain
available through the existing read-only recovery query. No compensation or remote delete is
attempted, and API acceptance is not a cryptographic proof of delivery.

Tests use the actual TeamsActivityHandler with mention normalization, scoped runtime and redb,
then verify its normalized result can be claimed. Six real-state delivery cases use a scripted
action sender and actual database shutdown/reopen; none may repeat typing or replies. Separate
tests reject hostile/credential-bearing URLs and malformed or secret-bearing response bodies
without echoing them. These are not new live Bot Framework/OAuth/JWT endpoint or tenant tests.
Existing JWT/HTTP rejection, other channel, shutdown and state compatibility tests remain passing.

Live identity-service matrices, activity edits, provider callback semantics, complete remote
reconciliation and cross-platform runtime acceptance remain open. No dependencies, protected
compatibility fixtures, real accounts or production services changed. Three post-check source
witnesses are not a complete frozen build manifest; whole-project acceptance remains false.

## WhatsApp Provider Status Facts

The [callback record](native-whatsapp-status-20260914.json) reports 445 passing tests, zero failures
and four existing ignored entries across state/channels/HTTP/daemon, with 27 test summaries and
strict all-target Clippy for the same four packages. This is a distinct cohort, not a sum of
earlier results. No real Cloud account, webhook subscription or external delivery was exercised.

The native webhook parses all status metadata before processing it, after the host verifies the
signature over the exact raw request bytes. Nonempty status arrays must match the configured
phone. Receipt IDs, recipients and timestamps are bounded and validated; a payload has at most
1024 status entries and each entry at most 16 numeric error objects. Freeform provider error
descriptions are discarded, never persisted or returned in diagnostics. Parsing status callbacks
does not enqueue model input. A status-only request also cannot drain messages already waiting
in the channel queue; a regression preloads a pending message to exercise that distinction.

New wamid receipts and their hashed source/principal/remote-ID lookup are inserted in the same
transaction as the original claim comparison. The principal includes channel, configured account
and sender; WhatsApp replies require that sender to be the destination recipient. The callback
must resolve that exact partition and the stored run/revision/segment receipt. A remote ID cannot
be reused for another segment in the same partition. Unknown IDs, foreign recipients/accounts,
callbacks arriving before the local receipt, and older receipts without an index are ignored
without allocating records. There is no implicit backfill, scan or remote reconciliation.

Each known receipt retains independent latest sent, delivered, read and failed timestamps. CAS
merging preserves concurrent facts, rejects negative/overflow timestamps and refuses different
failure codes reported at the same failure time. Identical callbacks are idempotent; older facts
cannot replace newer timestamps. Failure retains only the numeric code, and failure together with
delivered/read is exposed as conflictingReports rather than hidden. A partial batch can commit a
valid prefix before storage failure; replay is idempotent per receipt, not an all-batch transaction.

The existing channels.status nativeRecovery exact-run query adds deliveryStatuses alongside
deliveryReceipts on the same 32-receipt page. Each item has reportedState, conflictingReports and
strict schema-versioned facts. Reported read/delivered facts never settle a local unknown delivery,
remove a result, create a send task or grant replay permission. Local delivery still means API
acceptance, not end-user delivery; provider reports remain a separate evidence class.

Tests cover all four parsed states, malformed identities/timestamps, error-text omission, atomic
receipt/index collision refusal, identical and concurrent callbacks, wrong-recipient/phone
notifications, five actual runtime delivery scenarios and real database reopen. The existing HTTP
test now rejects unsigned and raw-byte-modified status requests before adapter processing and
forwards the exact valid bytes without model input. These are fixture-based host/adapter/state
checks, not provider-signed proof or live webhook acceptance.

Template/service-window rules, remote reconciliation, pre-receipt callback recovery, stable account
lifecycle and real Cloud/platform acceptance remain open. No dependencies, protected contracts,
user data or production services changed. Seven post-check source witnesses are not a complete
frozen input manifest; whole-project acceptance remains false.

## Native WhatsApp Reply Window

The [reply-window record](native-whatsapp-window-20260914.json) reports 335 passing tests, zero
failures and four existing ignored entries across state/channels/daemon, with 17 summaries and
strict all-target Clippy for those three packages. The prior four-package callback cohort remains
historical; their counts are not combined.

Native webhook ingestion now requires strictly numeric, positive provider seconds that convert
without overflow and describe a message less than 24 hours old. Future timestamps are refused,
and the exact 24-hour boundary is closed. All relevant text-message timestamps in a bounded batch
are checked before any queue mutation; a missing or invalid later timestamp cannot leave a queued
prefix. Native input never substitutes the local receipt time for missing provider metadata.

The daemon rechecks that original inbound timestamp before model execution and before claiming
reply delivery. The SDK checks account/recipient route and time again before each segment and
immediately before its transport call. Expiration between acknowledged segments stops further
calls, retains the confirmed prefix and leaves the existing claim unknown/nonretryable. Neither
expiration nor failure invokes templates. Timing is conservatively bound to the original message,
not a newly received message elsewhere in the conversation.

Focused tests use an adjustable clock for the inside/exact-boundary/rollback/zero/future cases,
malformed later batch members and preserved legacy-ingress fallback behavior. The actual native
handler/redb matrix now includes six delivery scenarios: the new case expires immediately after
the first Cloud response, retains that receipt and independent callback facts, and sends nothing
after a real runtime reopen. Missing/zero/overflow/future/expired webhook times fail before new
model sessions or transport calls. Existing dropped-request and callback queue-isolation tests
remain passing. No waiting for real time or external accounts was required.

Legacy compatibility ingestion and generic sender APIs keep their existing behavior; this is a
native-reply boundary, not universal template/service-window acceptance. Approved template names,
languages and variables, durable replay timestamp provenance, full latest-customer-message window
handling, remote clock policy and live Cloud acceptance remain open. Two post-check source hashes
are not a frozen build manifest; whole-project acceptance remains false.

## Immutable WhatsApp Timestamp Provenance

The [timestamp binding record](native-whatsapp-provenance-20260914.json) reports 205 passing tests,
zero failures and four existing ignored entries in eight daemon test summaries, with strict
all-target Clippy. It is a later, smaller cohort than the service-window checkpoint, not an
additional whole-workspace total.

The native queue now passes its normalized InboundMessage directly to the owned durable runtime
entry. It no longer round-trips through the legacy message type that omits provider time. The
same scoped authority, cancellation revocation, durable task tracking and model execution are
reused by the legacy owned entry; no new execution bypass or transport is introduced.

For WhatsApp input with nonzero provider time, providerTimestampMs is part of the immutable
submission content while the original account/conversation/message idempotency key is unchanged.
Changing the timestamp, or removing it through a legacy-shaped replay, therefore conflicts before
model execution or delivery claim. The six-scenario actual handler test checks a changed but
otherwise valid timestamp before normal processing, then independently checks changed and removed
timestamps after reopening the database. Original valid delivery and unknown/no-resend behavior
remain unchanged, and no model session or new transport call is created by those replays.

Other channels and old zero-time legacy inputs keep their previous serialization. Existing records
are not silently backfilled or adopted; a newer timestamp-bearing replay against a legacy record
is refused. Historic account migration, remote timestamp trust, global latest-user-message policy,
approved templates and real Cloud acceptance remain open. No dependencies or real state were
changed; two post-check hashes do not constitute a frozen build manifest or whole-project acceptance.

## HTTP MCP Request Cancellation

The [MCP cancellation record](native-mcp-cancellation-20260914.json) reports 319 passing tests,
zero failures and four existing ignored entries in 18 HTTP/daemon test summaries, plus strict
all-target Clippy for the same two packages. No count is combined with prior channel cohorts.

The existing authenticated HTTP facade previously ignored notifications/cancelled. Active
tools/call requests now register a token under the authenticated credential subject and typed
JSON-RPC ID. A numeric ID and a string containing the same digits are distinct. IDs must be bounded
strings without control characters or integers; missing/null/floating-point/oversized IDs and an
already-active ID are rejected before ToolPort invocation. Existing tool authority and approval
paths are unchanged; untrusted cancellation reason text is not stored or returned.

The registry allows 256 active calls globally and 32 per subject. Cancelled but still-running
calls retain their slots until their handler finishes or drops. Dropping the guard cancels that
request and removes its entry. A notification can cancel only the matching subject/ID, not a call
owned by another accepted credential. Settled IDs may be reused for new protocol requests; that
is not a grant to retry effects. Existing unknown-outcome/recoveryRequired/nonretryable mapping
and operation timeout remain in force. Cancellation asks the executor to stop, not to roll back.

Tests exercise typed IDs, duplicate IDs, both quotas, cancellation without premature slot release
and guard cleanup. The real TCP regression keeps two owner credentials with the same ID active,
refuses cancellation by a third read-only credential, targets only the requested owner, rejects
invalid/no-ID calls without invoking the tool port and verifies safe protocol ID reuse. Cancelled
fixture calls return explicit nonretryable unknown outcomes. These are actual HTTP route checks,
not external MCP/OAuth or arbitrary tool shutdown guarantees.

The facade remains stateless at the MCP session level: callers sharing one bearer subject must
coordinate request IDs, and delayed old cancellations cannot be attributed to a separate session.
Full claw-mcp server/client composition, session-bound IDs, stdio/OAuth, resource/prompt lifecycle
and ACP remain open. No dependencies, sealed contracts or production services changed; three
post-check source hashes are not a frozen input manifest or whole-project acceptance.

## MCP Sessions And Native Client Interoperability

The [MCP session record](native-mcp-session-20260914.json) reports 388 passing tests, zero failures
and four existing ignored entries in 24 MCP/HTTP/daemon test summaries. Strict HTTP/daemon
all-target Clippy passed. The wider three-package Clippy attempt remains failed on seven existing
unused-async-trait-impl diagnostics in the stdio fixture; its log is retained. The dependency
library's synchronous conversation tool listing was converted to a ready future so the changed
product packages can pass their required lint, without changing the advertised tools.

Successful single-request initialization issues a 256-bit random URL-safe Mcp-Session-Id. The
registry holds at most 128 sessions globally and 16 per credential subject. Session resolution
checks format, exact credential ownership and duplicate headers. Sessions idle for 30 minutes are
expired when the registry is accessed; this is not a background exact-deadline guarantee. Expiry,
DELETE and registry destruction cancel the session token. Closed/unknown/foreign IDs return 404.

Active calls use subject/session/typed-request-ID namespaces. Stateless legacy calls remain in a
separate namespace, with aggregate per-subject request quotas unchanged. Closing a session cancels
only its child calls and event streams; cancellation still does not roll back or grant effect
replay. Reusing a request ID within the same live session still cannot disambiguate a delayed
cancellation for an earlier invocation. Sessions are process-local, not durable execution journals.

The dedicated MCP listener now reaches GET and DELETE only when a session header is present;
unbound requests keep the frozen POST-only 405 behavior and the existing endpoint inventory is
unchanged. SSE permits enforce 128 global and two per-session response streams, retained until
the response body releases them. A cancelled but not yet released body continues consuming its
slot. The actual TCP regression opens two streams, refuses a third with 429 and verifies DELETE
ends both while another session remains usable. These streams currently carry connection/keepalive
framing, not a claim of complete resource/prompt subscription delivery or replay.

Real client interoperability found that the old facade's 202 JSON null notification response
closed the native MCP transport during initialization. Session notifications now return empty
202 responses; legacy stateless response shape is preserved. A new workspace-only daemon test
dependency uses claw-mcp's actual HttpClient/McpClient against an owned daemon process: two owner
clients and one reader initialize, discover typed tools, reject reader writes, decode missing-tool
errors and close independently. No external service or production daemon was used. Cargo resolved
the existing workspace dependency offline and updated the root lock witness; older lock receipts
remain historical and unchanged.

Tests also cover both session quotas, expiration with injected time, unknown/foreign/duplicate
session headers, cancelled request capacity and independent stateless/session calls with the same
ID. Full initialization-state validation, outbound MCP policy/credentials, OAuth/stdio ownership,
complete resource/prompt events, ACP, live services and platform/power-loss acceptance remain open.
Seven post-check source/manifest hashes are not a frozen input manifest; whole-project acceptance
remains false.

## MCP Handshake State And Strict JSON

The [handshake record](native-mcp-handshake-20260914.json) reports 323 passing tests, zero failures
and four existing ignored entries across 18 HTTP/daemon summaries, with strict all-target Clippy
for those two packages. The earlier MCP fixture lint failure is not retested or claimed fixed.

Session records now share an initialized flag and retain the selected supported protocol version.
Tool discovery and invocation are refused before notifications/initialized. Wrong-shaped
notifications do not enable the session; repeated initialize requests cannot replace it, and a
closed context cannot become ready again. If Mcp-Protocol-Version is supplied it must be unique
and equal to the negotiated version. The two existing supported versions still permit omitting
that header; this is not a claim of implementing newer protocol versions.

Only complete clientInfo/capabilities handshakes allocate sessions. Client name/version and the
requested version are bounded nonblank strings without control characters, and capabilities must
be an object. Partial or mistyped metadata is refused without a session. Simplified historical
initialization keeps its frozen response but remains stateless. Modern initialization batches
are rejected before dispatch, so a malformed handshake cannot also execute a following tool.

MCP body reading retains HTTP byte/time budgets, then uses the existing protocol codec's strict
opaque JSON parser. Duplicate IDs, methods, versions and nested argument keys are rejected before
request dispatch; generic parse errors do not echo the rejected data. Existing codec nesting and
collection limits apply. Other HTTP routes retain their existing parser behavior.

Actual TCP regressions verify all those refusals without additional ToolPort calls, then complete
the handshake and exercise session cancellation/closure. Unit tests verify shared readiness,
version retention and non-revival after close. The native MCP clients still connect to an owned
daemon, discover tools, respect reader authority and close independently. Outbound MCP policy,
service-drain cancellation, exact background expiry, complete events, old-ID cancellation
attribution, OAuth/stdio/ACP and live accounts remain open. Two post-check source hashes are not a
frozen manifest or whole-project acceptance; the current lock witness is unchanged in this slice.

## MCP Service Drain

The [drain record](native-mcp-drain-20260914.json) reports 324 passing tests, zero failures and
four existing ignored entries in 18 HTTP/daemon summaries, with strict all-target Clippy. The
only post-test source adjustment made the pure request-registry constructor const and was
validated by that lint run. The older MCP fixture lint gap remains unchanged.

HttpApi exposes a host-owned MCP shutdown token shared by session and request registries. Both
session-bound and stateless calls, as well as SSE streams, descend from this root. Cancellation
permanently refuses new MCP work; registry capacity is not released until calls/bodies actually
finish or drop. Admission checks occur before body processing, after bounded parsing, per batch
item and during request registration. This closes the path where a partial request finishes its
body after the host begins drain. Existing authorization checks remain in place.

ProductionService cancels this root immediately after announcing drain and before waiting for
HTTP listeners/tasks. Other HttpApi hosts must explicitly drive the token; changing an arbitrary
ServingStatePort alone is not a background cancellation notification. Read-only tools/list now
uses the same bounded subject/session/request-ID registration and selects on its token, allowing
notification cancellation or service drain to end a hung directory query with -32800. Tool calls
retain the existing executor completion/unknown-outcome semantics; cancellation is not rollback.

State tests verify all child tokens are revoked and active slots/stream permits remain held until
release. The real TCP scenario hangs a directory query, independently cancels it, then drains a
second query, a session tool, a stateless tool and an SSE connection. A partially written request
and fresh handshake/call receive 503 without another tool invocation; unrelated HTTP health stays
available when only the MCP root is cancelled. The actual daemon process test leaves a live SSE
until control shutdown and still requires a clean stop, with stream EOF rather than forced HTTP
task abandonment. Native client discovery/reader isolation/independent close remain covered.

Noncooperative backends and blocking I/O still use the existing operation/shutdown budgets and
may require conservative unknown recovery. Exact background expiry, complete events, outbound MCP
authorization, OAuth/stdio/ACP and real accounts remain open. No dependencies changed; six source
witnesses are not a frozen build manifest or whole-project acceptance.

## Native Outbound MCP Tools

The [outbound record](native-mcp-outbound-20260914.json) reports 560 passing tests, zero failures
and six existing ignored entries in 31 tools/MCP/HTTP/daemon summaries. Strict all-target Clippy
passed for all four packages. A later test-only count simplification was rechecked with the actual
daemon approval test. These counts are not added to previous cohorts. The seven previously
reported stdio-fixture async lint errors were fixed with equivalent ready futures; old failure
logs remain historical evidence.

GTA_CLAW_MCP_TOOL_POLICY defaults to an empty configuration. The production daemon now uses
claw-mcp directly for reviewed literal-loopback HTTP tools, with no connection during startup,
listing, dry-run, schema refusal or denied approval. Only explicit mcp_ names are published;
discovered remote tools cannot add themselves to the model catalog. There are at most four
servers, eight tools per server, 16 total tools and two active operations. The policy is closed,
bounded JSON; remote descriptors and argument schemas are validated offline. URLs cannot contain
credentials, query or fragment and cannot use DNS hostnames or non-loopback destinations.

Example policy, for an already approved local service whose actual descriptor exactly matches:

```json
{
  "schemaVersion": 1,
  "servers": [{
    "id": "local-notes",
    "url": "http://127.0.0.1:32109/mcp",
    "reviewRevision": 1,
    "tokenEnv": "GTA_CLAW_MCP_OUTBOUND_LOCAL_NOTES",
    "tools": [{
      "name": "mcp_notes_find",
      "remote": {
        "name": "find",
        "description": "Find local notes",
        "inputSchema": {
          "type": "object",
          "required": ["query"],
          "properties": {"query": {"type": "string", "maxLength": 256}},
          "additionalProperties": false
        }
      }
    }]
  }]
}
```

tokenEnv is optional; when present it may reference only a dedicated GTA_CLAW_MCP_OUTBOUND_ name.
The credential is loaded into SecretString at configuration time, bound into the publication by
digest and never included in approval prompts, status or audit. This is a bounded environment
reference, not the completed native SecretRef/OAuth workflow. Do not place the token in the JSON
URL, tool arguments or command line. Runtime Admin status exposes nativeMcp configuration metadata,
not health or a grant to invoke. Changing this policy currently requires product reconfiguration;
there is no automatic endpoint discovery, token refresh or trust enrollment.

Model, HTTP and inbound MCP calls use the same existing executor and explicit human approval.
Bindings cover server, endpoint, complete typed descriptor, credential digest, caller, session,
permission generation and canonical arguments. Authorization audit precedes connection. Each
operation establishes one fresh bounded client, rejects a missing/duplicate/changed descriptor,
refuses paginated or oversized discovery and watches tool-list-change notifications. Sampling is
disabled. The tool is called at most once and the client is closed on normal and error paths.
Returned data is marked untrusted and limited to 16 KiB. Remote tool errors have failed audit
phases; ambiguous transport, oversized result, cancellation, catalog change or close failure
returns nonretryable unknown semantics. Catalog refusals conservatively report unknown for the
overall operation, not a claim that the remote tool ran.

Inspecting rmcp found its default expired-session handling reinitializes and repeats the in-flight
HTTP request. McpClient now explicitly disables that behavior for all HTTP clients. A real local
server fixture counts a side effect and returns 404: initialization and tool invocation each occur
only once. SSE GET reconnects are distinct from resending a tool call. Native execution retains
TaskTracker ownership after a caller drops; cancellation and shutdown are joined with bounded
client cleanup, not automatic resubmission.

Actual local-server tests cover 11 modes: success, descriptor change/missing/duplicate, list-change
notification, RPC error, isError, oversized output, cancellation, dropped caller and shutdown.
All have paired authorization/terminal audit records; no provider error text is echoed. The real
daemon test pairs an approval device and verifies denial/read-only/dry-run zero connection,
HTTP/MCP approval, exact resource preview, schema drift zero calls and one ambiguous attempt.
No real external service, account or production process was used.

Additional stdio prerequisites are implemented but not yet the product launch path:
connect_stdio_isolated clears inherited environment and supplies only the explicit map, while
the old method remains compatible. A real owned subprocess reports only boolean test markers,
proving Cargo host variables are absent in isolated mode and the parent is unchanged. Debug
formatting now omits argv/environment values. ExecPolicy exposes PinnedExecutable to retain its
existing executable/ancestor handles; Windows write/delete/ancestor-replacement refusal is tested.
That handle does not prove Unix atomic spawn or isolate a child's filesystem/network privileges.

Remote HTTPS/proxy/OAuth, stdio product launch approval and working-directory controls, durable
catalog revocation, automatic discovery, full resources/prompts and ACP remain open. The current
lock hash is unchanged; moving the existing workspace MCP dependency from test to production
required no new dependency versions. Twelve post-check source/manifest witnesses do not form a
frozen build manifest; whole-project acceptance remains false.

## Durable MCP Catalog Revocation

The [revocation record](native-mcp-revocation-20260914.json) reports 252 passing tests, zero failures
and four existing ignored entries in nine state/daemon summaries, with strict all-target Clippy
for those two packages. The previous four-package cohort is historical, not part of this total.

Each configured backend has a positive reviewRevision, defaulting to 1. A domain-separated digest
of its stable server ID and review revision identifies the whole reviewed catalog. All configured
tools on that backend share revocation state and a cancellation token. Descriptor mismatch,
missing/duplicate entries, unsupported discovery bounds or a tools/list_changed notification
immediately removes the group from subsequent publication/binding and cancels concurrent group
work. Other backend groups are unaffected. Invocation cleanup persists the revocation even when
the connection or operation failed, before reporting its final unknown result.

The state layer stores only a strict version and review digest. Records are immutable, duplicate
revocations are idempotent under concurrent insertion and the 256-record quota is checked in the
same transaction. There is no expiry, delete or implicit reset. Startup reads the records before
publishing tools; invocation reads again before connecting. Restoring the old remote descriptor,
changing a URL or credential, or editing the reviewed descriptor cannot implicitly bypass an
already revoked server/revision. Explicitly choosing a new positive review revision creates a new
publication for fresh human approval; the old revocation and execution history remain intact.

If persistence is unavailable or its quota is exhausted, the current NativeMcp runtime disables
all outbound tools and reports unconfirmed revocation. This is not proof that a failed write will
survive restart. A crash before the revocation commit and physical power loss remain unverified;
operators must reconcile those failures before resuming. No record is fabricated to hide an
uncertain write, and unknown remote effects are never automatically repeated.

Tests cover real redb concurrent insertion, quota exhaustion with no partial insert, idempotence
at capacity and reopen. The local-server matrix now has 12 cases, including storage closure after
receiving a changed descriptor, with 24 paired audit events. Tests verify shared group cancellation,
independent backend isolation, post-reopen publication refusal and an explicitly new review while
the old record remains revoked. A real daemon is restarted with the same configured policy after
remote restoration: the tool stays absent and attempts create no connection. A second restart with
a new review offers the tool again but still does not connect without approval. Status includes
per-tool review version and revoked metadata, never credentials or remote error content.

Full administrative re-enrollment workflows, notification recovery across network outages,
precommit crash fencing, remote HTTPS/proxy/OAuth, stdio launch and complete resources/prompts/ACP
remain open. Five post-check source hashes are not a frozen build manifest; the current lock is
unchanged and whole-project acceptance remains false.

## Native Windows MCP Stdio

The [stdio record](native-mcp-stdio-20260914.json) reports 563 passing tests, zero failures and
six existing ignored entries in 32 tools/MCP/HTTP/daemon summaries. Strict all-target Clippy passed
for all four packages. The root lock hash is unchanged; these results are not combined with older
cohorts. No third-party backend or production service was started.

Each server policy now accepts exactly one url or stdio entry. The Windows stdio object requires
program, lowercase sha256, workingDirectory, allowHostPermissions:true and optional fixed
arguments/environment collections. The program must be an existing canonical absolute native
executable outside both its working directory and the agent's configured writable workspace.
Existing ExecPolicy rejects interpreters, scripts, linked paths and changed executable identity.
Other platforms explicitly refuse the product stdio path instead of claiming equivalent pinning.

The working directory is pinned at configuration time. After human approval and authorization
audit, a tracked operation verifies the program through the existing bounded hash/file/ancestor
handles and retains the executable pin through child shutdown. The full transport configuration,
including fixed arguments, environment and directory, contributes to the publication digest.
No tool argument can replace any of those values. Approval resources display program/digest/cwd,
argument count, environment keys and hostOsPermissions=true, never raw environment values.

The child receives only the explicit environment map. There are at most 32 arguments, 2048 bytes
per argument and 8192 total argument bytes; at most 16 environment entries, 2048 bytes per value
and 8192 total value bytes. Controls and case-insensitive duplicate environment names are refused.
The three-second handshake, five-second request timeout, 64 KiB frame and 16 KiB output limits
reuse the reviewed catalog, disabled sampling, cancellation, audit and no-replay rules. Each
approved operation owns a separate process tree. This is identity/environment control, not an
OS sandbox: the child retains the host user's filesystem/network permissions. Static enrollment
must explicitly acknowledge that fact, and each invocation still requires normal approval.

Some Windows APIs need explicitly supplied non-secret system settings. The real cancellation
fixture could not open its loopback notification socket with an empty system environment; adding
only SystemRoot made it work. The product does not inject it automatically or inherit all host
variables. Never place secrets in executable arguments; protected stdio secret references are
still an open integration item. Legacy SDK connect_stdio behavior remains compatible, while the
new connect_stdio_isolated_at requires absolute program/cwd and preserves the parent's directory.

The daemon integration test copies the existing Rust MCP fixture into an owned temporary path,
not a production executable. Startup, catalog listing, read-only calls, dry-run, denial and waiting
approval produce zero child starts. Approved HTTP and MCP calls record actual cwd and boolean
environment checks. An owned loopback signal proves the third child reached its tool before MCP
DELETE cancels it; the result remains nonretryable, and active executable/working-directory
replacement is refused. During a later pending approval, a same-length executable change with
restored mtime is rejected by digest before another child starts. Restoring the owned copy and
restarting the daemon does not clear its committed review revocation. Program/directory rename
after shutdown verifies release of their held handles. No original build output is modified.

Policy tests reject mixed transports, missing host-permission consent, relative paths, malformed
hashes, oversized/control-containing arguments, ambiguous environment keys, and writable programs;
changing argv/environment changes the approval binding. Existing process-tree and protocol tests
remain passing. The shared fixture source is compiled as a dedicated daemon test-support binary;
default-run remains gta-claw-daemon and no production path launches that fixture automatically.

Remote HTTPS/proxy/OAuth, protected stdio credentials, non-Windows product launch, arbitrary
third-party child acceptance, OS containment and full resources/prompts/ACP remain open. Eight
post-check source/manifest hashes are not a frozen build manifest; whole-project acceptance
remains false.

## Explicit MCP HTTPS Proxy Routes

The [HTTPS route record](native-mcp-https-20260914.json) reports 403 passing tests, zero failures
and four existing ignored entries in 25 MCP/HTTP/daemon summaries, plus strict all-target Clippy
for the same three packages. No external MCP endpoint or existing production proxy was contacted.

A remote native MCP server may now use an HTTPS url together with an explicit httpProxy, for
example url https://approved-mcp.example/rpc and httpProxy http://127.0.0.1:32081. The proxy must
be a literal-loopback HTTP origin with an explicit port and no credentials, path, query or fragment.
SOCKS and proxy authentication are not supported in this native policy. Direct HTTP remains
limited to literal loopback and refuses an attached proxy configuration. Stdio cannot carry one.

The product validates remote URLs against the existing public-destination SSRF policy, rejecting
private/metadata literals and internal hostnames before loading credentials. HttpRoutePolicy fixes
the exact endpoint and route for every MCP POST, GET and DELETE. It builds a proxy matcher only
from that policy, not ambient proxy/NO_PROXY variables. Unusable proxies never fall back to direct
TCP. Changing the proxy changes the publication and approval binding. The old general SDK entry
retains its environment-proxy behavior; all native product HTTP connections use the explicit API.

The chosen proxy is a trust boundary: it resolves remote DNS and opens the destination tunnel.
The product does not perform separate DNS or verify the proxy's resolved IP, so this is not a
claim of DNS-rebinding protection beyond the trusted proxy. TLS still uses native trust roots
and validates the target hostname inside CONNECT; there is no product certificate bypass. The
MCP bearer is sent only within the target TLS HTTP exchange, never as proxy authentication.

Local TLS/CONNECT fixtures exercise the enrolled route and existing proxy-auth compatibility,
while a refused proxy test proves the direct target listener sees no connection. Route changes
are rejected before networking. Actual NativeMcp and daemon approval tests use a local proxy that
records CONNECT and returns a controlled failure: configuration/listing/denial/waiting approval
make no proxy request, an approved call makes one, and no service bearer appears in CONNECT or
diagnostics. Existing successful local MCP HTTP/stdio and durable-revocation tests remain passing.
These are local transport and failure-path acceptance, not a live remote account validation.

OAuth/proxy authentication, remote-service success and account lifecycle, trusted-proxy DNS policy,
complete resources/prompts/ACP and platform acceptance remain open. Six post-check source hashes
are not a frozen build manifest; the current lock hash is unchanged and whole-project acceptance
remains false.

## Reviewed MCP Resources And Prompts

The [resource/prompt record](native-mcp-data-20260914.json) reports 214 passing tests, zero failures
and four existing ignored entries in nine daemon test summaries, plus strict all-target Clippy.
No external resource service, local user file or model account was accessed for this increment.

Each tools entry may now include kind: tool, resource or prompt; omitted kind remains tool.
Its remote field contains the complete corresponding MCP descriptor. For resources, name and
absolute uri are statically reviewed and the exposed wrapper accepts only an empty object. For
prompts, the reviewed arguments become a closed string-only schema: at most 16 unique parameters,
the provider's required flags, 4096 characters per string and the existing 16 KiB total invocation
budget. An unregistered URI, prompt name or argument cannot be chosen at call time.

For example, the following entries can be added to an explicitly reviewed server policy when
they match the actual descriptors:

```json
[
  {
    "name": "mcp_notes_resource",
    "kind": "resource",
    "remote": {
      "name": "notes-index",
      "uri": "gta://notes/index",
      "description": "Reviewed notes index",
      "mimeType": "text/plain"
    }
  },
  {
    "name": "mcp_notes_prompt",
    "kind": "prompt",
    "remote": {
      "name": "notes-summary",
      "description": "Reviewed summary prompt",
      "arguments": [{"name": "subject", "required": true}]
    }
  }
]
```

Every operation retains the same authenticated authority, explicit approval, bound publication,
audit and connection lifecycle. The server must advertise the corresponding capability. Discovery
uses resources/list or prompts/list and compares the exact typed descriptor, with the same bounded
single-page rules as tools. Missing/changed/duplicate catalogs or list-change notifications revoke
the backend review; this applies across tool/resource/prompt entries in that group.

Resource wrappers send exactly one resources/read with the configured URI. Each returned content
item must retain that URI, and at most 32 items are accepted. Prompt wrappers send exactly one
prompts/get with the configured name and validated strings, accepting at most 32 messages. The
overall serialized output remains limited to 16 KiB and explicitly labels operation, untrusted
and automaticReplay:false. Data is returned as a tool result, not installed as system instructions,
used to change authority or automatically injected as conversation context. Resource URIs are
handled by the reviewed remote backend, not opened as files by the daemon.

Sixteen local-service cases cover each operation's success, descriptor change/missing/duplicate,
list-change notification, wrong resource URI or excessive prompt messages, oversized output and
absent capability. Invalid caller URIs/argument names/types are refused before connection. The
real daemon test verifies denied resource reads make no connection, approved HTTP resource and
MCP prompt calls use the exact protocol methods once, and persisted group revocation removes their
wrappers after restart. Returned resource/prompt contents and arguments are absent from audit.

Resource templates, subscriptions/event replay, automatic context selection, OAuth and real
third-party resource/prompt acceptance remain open. Two post-check source hashes do not form a
frozen build manifest; the lock witness is unchanged and whole-project acceptance remains false.

## Native MCP Keyring Credentials

The [keyring record](native-mcp-keyring-20260914.json) reports 290 passing tests, zero failures and
four existing ignored entries in 15 MCP/daemon test summaries, with strict all-target Clippy for
both packages. The Windows native-store tests created only dedicated fixture entries, verified
their removal and did not access real model/channel credentials.

HTTP server policy accepts tokenRef as an alternative to tokenEnv. The only accepted form is the
keyring reference generated by CredentialBinding::new(server_id, endpoint).keyring_reference().
It uses a versioned domain and architecture-independent length-delimited profile/resource-origin
hash under keyring://gta-claw.mcp-outbound/. The configured reference must exactly match that
backend and origin before lookup. Origin includes scheme/host/port, not the URL path; full endpoint
and proxy remain separately bound in the approved publication. Plaintext, other namespaces,
cross-profile/origin references, fd/service schemes and mixed tokenEnv/tokenRef are refused.

The daemon reuses the existing Windows Credential Manager and macOS Keychain adapters, without
enumerating unrelated keys or falling back to files/environment when an entry is missing. Only
Windows runtime behavior was validated here; the macOS branch still needs platform acceptance.
Production policy/credential reads run in an owned blocking job. Loaded values use the existing
secret wrappers and only their digest/source binding enters the publication; prompts and audit
do not contain the keyring reference or plaintext token.

After approval, the keyring value is read again before connection and again after discovery,
before the remote operation. Missing, unavailable or changed material revokes the server review
and persists that revocation through the existing path. Re-enrollment after credential rotation
requires an explicitly new review and a fresh approval. There is no silent token refresh or retry.
Reads are joined rather than abandoned; native-keystore calls do not claim a hard blocking-I/O
deadline, and checking then sending is not an atomic transaction with the remote server.

Tests verify a fixed cross-architecture reference vector, same-origin stability and profile/origin
isolation. Actual Windows fixtures cover deletion/rotation before connection and rotation inside
the remote discovery response: the first two yield zero TCP connections, and the last yields one
initialization but zero tool calls. All persist review revocation and omit secret text from errors
and audit. The existing real-daemon approval/resource/prompt/restart test now uses an independently
created keyring credential on Windows and still passes, including explicit cleanup.

CLI provisioning/removal, full OAuth login/refresh, protected stdio environment references,
cross-platform and live-account acceptance remain open. Three post-check source hashes are not a
frozen manifest; the root lock is unchanged and whole-project acceptance remains false.

## Native MCP Credential CLI

The [credential CLI record](native-mcp-credential-cli-20260915.json) reports 156 passing tests,
zero failures and one existing ignored test in 11 CLI/MCP summaries, plus strict all-target Clippy
for both packages. These counts are separate from the earlier daemon/keyring cohort. The root
lock now differs only by the CLI's two dependencies on existing claw-mcp and claw-provider-sdk;
removing those two exact edges in memory reproduced the preceding lock SHA. No versions changed
and no dependency downloads occurred.

The four local commands share the daemon's origin/profile-bound keyring reference. Reference
generation opens no store. Status reads only that key and returns existence, never secret data.
Set accepts bounded, zeroized stdin and requires --confirm-write; it explicitly allows replacement.
Delete requires --confirm-delete. Secret argv/files/environment, echoing terminal entry, duplicate
or invalid UTF-8 options, non-loopback plaintext HTTP and private HTTPS targets are refused.
Native reads/writes are joined; there is no fallback backend, remote login, network call, policy
rewrite, daemon restart or implicit tool approval. See the [CLI guide](../../apps/gta-claw-cli/README.md#local-mcp-credentials).

Writes and deletes read back once. Seven injected error/replacement cases prove unknown outcomes
do not cause retries, compensating writes, rollback, or disclosure of backend errors containing
secret markers. The API explicitly disclaims atomic comparison with external native-store writers.
Status cannot identify which value won an uncertain write. Actual Windows child CLI processes
created, rotated, inspected and deleted one unique fixture key, checked no localhost connections,
and verified cleanup. Noninteractive protected pipes remain supported; no visible prompt or real
credential was used in validation.

MCP credential removal is local only. Running daemons retain their enrolled snapshot and reject
changed material on later approved operations; this command does not clear durable revocations
or settle an already in-flight remote effect. Re-enrollment needs explicit review and approval.
macOS runtime acceptance, full OAuth and upstream token revocation, protected stdio variables,
hard native-I/O deadlines and crash-durable CLI provisioning receipts remain open. Four post-check
source witnesses are not a frozen build manifest; whole-project acceptance remains false.

## MCP OAuth Exchange Guards

The [OAuth guard record](native-mcp-oauth-guards-20260915.json) reports 79 passing tests, zero
failures and zero ignored tests across six MCP summaries, with strict all-target Clippy. This
increment modifies the existing OAuth library and its adjacent tests only. The CLI/keyring
records above remain historical independent cohorts; the current root lock is unchanged.

Authorization requests now retain a private context digest covering issuer, authorization/token
endpoints, client ID/secret, exact redirect and optional resource, final browser URL, state and
PKCE. They expire after ten monotonic minutes. Code exchange checks the original context and
callback before atomically consuming the request, and rechecks expiry after waiting for the
credential lock. Failed HTTP, lost responses, dropped futures and store failures cannot redeem
that same request again. Constructor use is now required: public URL/state/PKCE remain readable,
but changing them invalidates the seal. Callback/request Debug omits URL, code, state and PKCE.
Reserved authorization query injection and ambiguous redirects are refused before networking.

Code exchange, refresh and logout use the same binding lock for an OAuthClient and its clones.
The registry retains at most 256 bindings without eviction that could discard an unknown outcome.
Refresh sets a fence before token I/O and clears it only after a parsed response is successfully
saved. HTTP failure, connection loss, malformed/non-Bearer responses, cancellation and save failure
leave it set. Queued refreshes and fresh-token bearer requests cannot bypass the fence. A newly
authorized code exchange can clear it after successful persistence. Logout keeps the lock through
deletion and remains fenced even when deletion fails. Already-issued bearer headers and in-flight
remote requests are not retroactively revoked by this increment.

Token responses are checked before saving: Bearer type, nonempty bounded access/refresh values,
header-safe access-token characters and bounded control-free scope. Missing token_type retains
the prior Bearer compatibility default. Access/refresh wire fields are zeroized on drop, including
rejected responses. Expiry arithmetic remains checked. These are syntax/budget checks, not a claim
that a token is valid at a real service or that the response proves its resource audience.

Actual local TCP tests cover twelve context/expiry changes with no connection, single-use exchange
success/failure/cancel/store-error, and six refresh failure modes through both explicit refresh and
automatic bearer retrieval. They verify queued-call refusal, explicit new authorization recovery,
failed logout refusal, unchanged old store values, and the binding cap. No browser or real account
was involved. The fence is in memory only: independent clients/processes/restarts are not coordinated,
and a separately issued pending authorization can still require host-level cancellation policy.
Product OAuth network enrollment, native TokenStore persistence, issuer/client-bound token records,
durable refresh uncertainty and full login/refresh acceptance remain open. The single source hash
is not a complete frozen build manifest and whole-project acceptance remains false.

## MCP OAuth Explicit Routes

The [OAuth route record](native-mcp-oauth-routes-20260915.json) reports 82 passing tests, zero
failures and zero ignored tests in six MCP summaries, with strict all-target Clippy. The earlier
79-test OAuth guard record remains a separate historical source witness, not an additional count.

OAuthClient::with_routes accepts one through sixteen unique HttpRoutePolicy entries. Each exact
URL gets the existing native HTTP client bound to its explicit route. Resource metadata, issuer
discovery, registration, token exchange/refresh and authorized resource requests must all use an
enrolled URL. Authorization-server discovery and authorization-URL construction additionally reject
unregistered authorization/token endpoints before handing a browser URL to the caller. Metadata
never enrolls its own new destination. Browser query construction retains the original context seal.

Routes permit explicit literal-loopback HTTP or HTTPS through an explicit loopback CONNECT proxy,
with no ambient proxy variables, NO_PROXY override, redirect following or direct remote fallback.
This low-level route type is not the product public-IP policy: callers still approve endpoint and
issuer/resource relationships, and trust the designated proxy's DNS resolution. The old new/default
constructor deliberately retains its environment-proxy compatibility behavior. No product login
command has silently switched modes or started a network request.

The actual local authorization fixture now runs discovery, registration, code exchange, refresh
and an authorized MCP request using only enrolled routes. Negative tests reject empty/duplicate/
oversized route sets, unreviewed paths and both substituted authorization/token metadata targets
without connecting to those targets. A separate HTTPS fixture sends CONNECT only to an owned
ephemeral proxy, verifies absence of OAuth code/client-secret/bearer data on that hop, and returns
502. It does not claim an end-to-end remote HTTPS OAuth login; the package's existing native TLS
and CONNECT fixtures remain in the same full regression gate.

Product enrollment UI/configuration, issuer/client-bound native TokenStore persistence, a controlled
browser callback workflow, restart-durable refresh uncertainty and live OAuth acceptance remain
open. This increment made no dependency/lock changes, touched no production proxy and contacted
no real authorization server. Its single source witness is not a complete frozen build manifest;
whole-project acceptance remains false.

## Native MCP Stdio Credentials

The [stdio credential record](native-mcp-stdio-credentials-20260915.json) reports 382 passing tests,
zero failures and five existing ignored entries in 20 MCP/CLI/daemon summaries, with strict
all-target Clippy for all three packages. This is one current cohort, not the sum of earlier
keyring, CLI and OAuth records. A delayed terminal notification included old lint failures; the
final counts and log SHA were checked against the independent log on disk.

StdioClientConfig::keyring_reference derives an architecture-independent SHA-256 reference from
server ID, reviewed executable SHA-256 and uppercased environment name, under the dedicated
keyring://gta-claw.mcp-stdio/ namespace. A fixed vector was independently computed and retained in
the test. Different programs, servers and variable names have different bindings. Native policy
accepts only the exact generated reference in stdio.environmentRefs. It rejects other namespaces,
wrong variable bindings and case-insensitive collisions with ordinary environment values before
lookup. Secret values are 16..2048 bytes; both environment maps together allow 16 names and 8192
value bytes. Policy, previews and logs contain names/references or digests, never secret values.

The daemon reads native keyring material into secret wrappers at enrollment and includes its
digest in the publication. Approved execution rechecks before connection, during pinned-program
preparation and after discovery. Changed/deleted entries revoke the review through the existing
durable revocation path. The one-shot prepared config is moved rather than cloned into the stdio
client; executable and directory pins remain held until close. Host environment inheritance stays
disabled. The child deliberately receives plaintext environment values after approval, and its
reviewed host OS permissions still apply: this is not an OS sandbox, network isolation, complete
process-memory erasure, or an atomic keyring-and-process transaction.

CLI credential commands now take either endpoint, or program-sha256 plus environment-name. The
latter uses the same stdio binding, with the smaller value limit checked before writing. Reference
generation does not inspect or start an executable. Actual Windows child CLI tests cover both
target modes with uniquely owned native entries, rotation, deletion, readback, zero TCP connections
and explicit cleanup. The existing real-daemon stdio test now injects one test-owned keyring secret,
records only a match boolean in the child, and retains approval/no-start, cancellation, fixed cwd,
no inherited host token, executable tamper refusal and restart-persistent revocation checks.

The existing native keyring test additionally covers stdio rotation/deletion before connection;
HTTP still covers rotation inside discovery. Policy tests cover exact budget boundaries and
credential-digest changes. All test-owned entries were removed. No live account, production proxy,
dependency download or lock change was involved. Non-Windows product launch, OS process containment,
full OAuth native token persistence and whole-project acceptance remain open. Seven post-check
source witnesses do not form a frozen complete build manifest.

## Native OAuth Token Records

The [native OAuth store record](native-mcp-oauth-store-20260915.json) reports 389 passing tests,
zero failures and five existing ignored entries in 20 MCP/CLI/daemon summaries, with strict
all-target Clippy for all three packages. The lock differs only by claw-mcp's dependency on the
existing claw-provider-sdk; removing that edge in memory reproduces the preceding lock SHA.

TokenSet now retains a private authority digest over profile, resource origin, issuer, exact
authorization/token endpoints, client ID/secret and the complete optional resource. Refresh checks
it both before and after waiting for the binding lock; bearer retrieval also checks fresh tokens.
Missing authority, switched clients/issuers or another already-enrolled token URL cannot reuse the
old credentials. Nine substitution cases and both queued refresh/bearer replacement cases are
refused before network access, without disabling an unchanged original enrollment.

NativeTokenStore implements the existing synchronous port using Windows Credential Manager or
macOS Keychain only. It uses a separate gta-claw.mcp-oauth namespace with profile/origin-derived
accounts, not the static bearer or stdio namespaces. Its closed schema-v1 record retains access,
refresh, token type, scope, exact expiry, authority digest and owner binding. Parsing is bounded to
16 KiB; the native platform may impose a smaller write limit, which fails explicitly. Invalid,
duplicate, unknown, oversized, foreign-owner and unbound records are rejected. Tokens have no
ordinary Serialize implementation; stored values use secret wrappers, and errors omit backend data.

TokenStore::begin_update is called before code-exchange/refresh HTTP. Its compatibility default is
a no-op, not durable protection. The native implementation checks the expected refresh generation,
writes and reads back a pending marker containing no old token bytes, then permits the request.
Only a validated token response saved successfully replaces the marker. Lost responses, cancelled
requests and failed persistence therefore require new authorization when this store is reopened.
Native deletion also writes the refusal marker before deleting; failed deletion cannot return the
previous token. Invalid token route configuration is rejected before writing a marker. No automatic
retry, compensating write, secret file fallback or enumeration was added.

Actual Windows fixtures verify independent store reopening, exact expiry/authority retention and
cleanup of unique entries. The existing six-request loopback OAuth fixture now uses native storage.
Two additional local scenarios drop exchange/refresh responses, create independent OAuth clients
and native stores, refuse old-token use, then accept only a new authorization-code exchange.
Seven injected storage failures verify no retry/rollback and no secret disclosure. Update-marker
refusal causes zero token requests. All test-owned credentials are explicitly removed.

This remains a low-level synchronous adapter: product code must own blocking work and coordinate
the profile lifecycle. The read/write/readback operations are not native compare-and-swap and do
not serialize concurrent independent processes or external credential editors. Reopening tests
are not process-kill or power-loss durability acceptance. The CLI and daemon static tokenRef modes
do not consume these OAuth records yet. Browser callbacks, product login/refresh scheduling,
cross-process coordination, macOS runtime acceptance and full OAuth remain open. Three post-check
source witnesses do not form a frozen build manifest; whole-project acceptance remains false.

## Local OAuth Record Commands

The [OAuth CLI record](native-mcp-oauth-cli-20260915.json) reports 175 passing tests, zero failures
and one existing ignored test in eleven MCP/CLI summaries, with strict all-target Clippy for both
packages. The lock is unchanged from the native-store increment; counts are not combined with
its 389-test cohort.

NativeTokenStatus exposes only absent, reauthorization-required or available state, with local
freshness, refresh availability and known-expiry flags. It reuses the same bounded owner/schema
parser, so corrupt or foreign records are not silently missing. It does not check the expected
issuer/client or contact a remote service; normal token use still performs authority validation.

The CLI's mcp oauth reference/status/logout path is separate from raw credential management.
Reference generation opens no store. Status and confirmed local logout run on awaited blocking
workers using NativeTokenStore. Logout requires --confirm-logout and follows the native refusal-
marker/delete/readback sequence; there is no raw OAuth set, stdio OAuth mode, automatic refresh,
browser, remote revocation or daemon notification. Errors and metadata contain no token or scope
contents. The [CLI guide](../../apps/gta-claw-cli/README.md#oauth-records) describes these distinctions.

Real Windows child CLI processes inspect uniquely owned available, expired, pending and corrupt
record fixtures. They verify no state mutation during status, no removal without confirmation,
explicit cleanup including corrupt records, and zero TCP connections despite an available refresh
token. These CLI records are synthetic local metadata fixtures; the prior native-store test covers
records produced by actual loopback OAuth exchange. No real authorization service or account was
used. Product login and daemon token consumption, coordination with another process's in-flight
authorization, macOS runtime acceptance and full OAuth remain open. Five source witnesses do not
form a frozen build manifest; whole-project acceptance remains false.

## Public-Client OAuth Login

The [OAuth login record](native-mcp-oauth-login-20260915.json) reports 180 passing tests, zero
failures and one existing ignored entry in eleven MCP/CLI summaries, with strict all-target
Clippy for both packages. The lock and package versions are unchanged: the existing hyper server
feature is enabled and CLI tokio-util moved from dev-only to normal dependencies.

AuthorizationRequest now parses exact callback URLs, retaining redirect and issuer from creation.
It rejects nonunique code/state/issuer, wrong state/target/issuer, mixed error/code, malformed or
invalid UTF-8 escapes, control characters and expiration. A valid denial consumes the request.
Optional absent issuer preserves protocol compatibility; a present issuer must match. Parsed
values use secret wrappers and the borrowed callback cannot print its code through Debug.

LoopbackAuthorizationListener binds only an explicitly selected literal loopback address and
fixed /oauth/callback path. It admits at most sixteen connections, bounded header parsing and
five-second per-connection deadlines within the authorization lifetime. Only bodyless origin-form
GET with one exact Host is accepted; responses close the connection, contain no callback secrets
and disable caching/referrers. Listener ownership is released on completion, denial, cancellation,
expiry or admission exhaustion. Tests exercise actual local HTTP, rejection and port release.

The CLI login command requires explicit review/confirmation of resource, issuer, authorization/
token endpoints and a pre-provisioned public client ID. All requested URLs use explicit routes and
the product public-target policy; discovery must exactly match both roles and advertise S256.
The command prints a bounded authorization_required JSON line, waits for the user to open that
URL, receives one local callback, then exchanges once into NativeTokenStore. It never launches a
browser automatically or dynamically registers a client. Its joined blocking worker owns a
current-thread async runtime; timeout/cancellation drops network work without abandoning native
store calls. The default total network/callback budget is 120 seconds. This is not a hard native
I/O deadline or a guarantee against a separate process modifying the credential.

Actual Windows CLI processes cover success, denied access, callback timeout, dropped token
response and changed metadata. The fixture verifies exact PKCE verifier/challenge, public client,
resource, a single exchange, native success/pending/absence and released callback ports. The
existing six-request OAuth library fixture also now uses the real callback receiver and native
token store. No browser or real account was used. The authorization URL intentionally contains
one-time state/challenge/scope for user interaction; final output and callback responses omit tokens
and codes. Test-owned native records and listeners are cleaned up.

Real provider/browser acceptance, macOS, active Ctrl+C, confidential clients, cross-process token
coordination and daemon consumption of OAuth records remain open. Success proves the token
response and native write, not access to the MCP resource or automatic policy approval. See the
[login guide](../../apps/gta-claw-cli/README.md#public-client-login). Seven source witnesses are not
a complete frozen build manifest; whole-project acceptance remains false.

## Daemon OAuth Credential Consumption

The [daemon OAuth record](native-mcp-oauth-daemon-20260915.json) reports 398 passing tests, zero
failures and five existing ignored entries in twenty MCP/CLI/daemon summaries, plus strict
all-target Clippy for all three packages. Dependencies and the lock are unchanged.

The SDK provides an explicitly reviewed offline issuer identity and a fresh-bearer snapshot that
checks original token authority without refreshing. Complete-generation fingerprints include
access/refresh tokens, type, scope, expiry and authority; comparisons use fixed-length digests.
Changing scope or refresh material while retaining the same access token changes publication
identity. These digests are internal binding material, not token output or permission grants.

Native HTTP server policy now supports oauth as an exclusive alternative to tokenEnv/tokenRef.
Its issuer, authorization/token endpoints, public client and dedicated OAuth reference must match
the origin/profile-bound native record and exact resource authority. URLs undergo explicit route
and public-destination policy validation. Startup reads local native storage only, never discovers,
refreshes or starts a remote session. Locally fresh records without expires retain the SDK's prior
unknown-expiry policy; this is not a claim of remote authentication validity.

Approved calls reread the native record before connection and after discovery, checking the full
generation and freshness. Missing, incomplete, expired or changed records revoke the reviewed
server through the existing durable path. Previews show public issuer/client and disabled automatic
refresh; actual credentials remain in secret wrappers. Static and OAuth-backed tools, resources
and prompts keep the same caller/arguments/publication approval and durable audit requirements.

Seven actual loopback OAuth/native-Windows cases cover success, deletion, pending marker, scope
change, refresh-token change, expiry and mutation during discovery. Only the success case invokes
the tool; no case triggers automatic refresh. The real daemon composition test now runs separately
with static keyring and OAuth records generated by actual local code exchange, retaining read-only/
dry-run/deny/wait zero connection, exact approvals, resource/prompt access and restart-persistent
catalog revocation. Each mode creates and deletes only its owned credential, and issuer request
counts remain unchanged during calls and restarts.

There is deliberately no startup/discovery/call-time automatic refresh. Renewed credentials need
explicit review of the new generation and fresh approval; changes do not silently expand an old
grant. Native-store and network actions are not an atomic cross-process operation, and already-sent
requests are not revoked retroactively. Real accounts, macOS, confidential clients and coordinated
refresh remain open. See the [enrollment guide](../../apps/gta-claw-cli/README.md#daemon-oauth-enrollment).
Three post-check source witnesses are not a complete frozen build manifest; whole-project acceptance
remains false.

## Explicit OAuth Refresh

The [refresh record](native-mcp-oauth-refresh-20260915.json) reports 399 passing tests, zero failures
and five existing ignored entries across twenty MCP/CLI/daemon summaries, with strict all-target
Clippy for all three packages. No dependency, lock or production-service changes occurred.

The CLI now accepts mcp oauth refresh using the original reviewed endpoints and public client,
with its own required --confirm-refresh flag. Login confirmation cannot authorize refresh, and
scope/callback options are rejected. It loads a valid refresh-capable native record before any
issuer request, then verifies reviewed metadata and performs exactly one bound refresh. There is
no browser, callback listener, staged authorization URL, automatic retry or daemon-policy update.
Native pending-before-send and confirmed persistence remain the same as the library contract.

The existing real Windows CLI fixture now covers seven login/refresh scenarios. Successful login
is followed by explicit refresh; missing confirmation leaves the generation unchanged. A dropped
refresh response or explicit service refusal leaves native pending state, and another refresh
command is refused before discovery/token networking. Captured forms contain the original refresh
token and resource, without code/verifier/client-secret or requested scope. Success writes a new
generation, not a silent update to an existing daemon grant. The library's actual local OAuth/native
store fixture now omits scope in the refresh response and verifies retention of the prior scope;
omitted refresh tokens continue to retain the prior refresh token.

New credentials still require explicit daemon re-review and fresh approval. Status and tool calls
do not initiate refresh, and concurrent independent processes remain uncoordinated by native CAS.
Automatic refresh UX, real services, macOS and confidential clients remain open. See the
[refresh guide](../../apps/gta-claw-cli/README.md#explicit-refresh). Four post-check source witnesses
are not a complete frozen build manifest; whole-project acceptance remains false.

## Reviewed MCP Resource Templates

The [template record](native-mcp-templates-20260915.json) reports 312 passing tests, zero failures
and four existing ignored entries in fifteen MCP/daemon summaries, with strict all-target Clippy
for both packages. Only one dependency edge to the already-present iri-string 0.7.13 was added;
removing it in memory reproduces the preceding lock hash, with no version changes or downloads.

An explicitly reviewed entry can now use this form inside a server's existing tools array:

```json
{
  "name": "mcp_note_lookup",
  "kind": "resource_template",
  "remote": {
    "name": "notes-by-id",
    "uriTemplate": "gta://notes/item/{id}{?format}",
    "description": "Reviewed note lookup",
    "mimeType": "text/plain"
  }
}
```

This example is a reviewed descriptor shape, not permission to connect to a third-party backend.
The corresponding operation takes an object such as id/format strings. All one through sixteen
distinct variables are required; values are nonempty strings of at most 256 UTF-8 bytes, within
the ordinary 16 KiB argument limit. Extra keys, lists/maps and omitted variables are refused.
The actual RFC 6570 parser/encoder is reused rather than manually substituting braces.

Templates and rendered URIs are bounded to 2048 bytes, with incremental bounded output. The
rendered target must be a canonical absolute URI with fixed scheme/authority, no userinfo/fragment
and no URL-normalization change. Variable authority and path dot-segment normalization are refused.
The target remains an opaque remote resource identifier, not a local filesystem or additional
HTTP route. Full descriptor and canonical arguments remain in the approval binding; a rendered
URI digest is added to resourceScope instead of disclosing argument-derived text there.

Execution requires resources capability and exact resources/templates/list descriptor identity.
Changed, missing, duplicate, notified, paginated or oversized catalogs revoke the server review.
Only resources/read is called, with the exact rendered URI; all returned content URIs must match,
with the same 32-item/16-KiB untrusted output bounds as fixed resources. There is no subscription,
automatic context injection or implicit retry.

The existing resource/prompt fixture now covers thirty actual service cases across all three
data kinds, including pagination and 129-entry catalog refusal. The real daemon composition test
adds HTTP and inbound-MCP template approval in both static keyring and OAuth modes, verifying
invalid target zero connection, denied/waiting zero calls, exact rendered reads and persistent
catalog revocation after restart. Audit omits private variable and returned content markers.
Optional/composite variable contracts, subscriptions/events, full third-party acceptance and the
rest of MCP remain open. Three post-check source witnesses are not a frozen complete build manifest;
whole-project acceptance remains false.

## Bounded Resource Observation

The [observation record](native-mcp-observation-20260915.json) reports a final 405 passing tests,
zero failures and five existing ignored entries in twenty MCP/CLI/daemon summaries, plus strict
all-target Clippy. The first joint attempt failed one native OAuth CLI status assertion: a child
reported absent after a fixture write. The isolated reproduction passed, and the same joint gate
passed after adding pre-child readback and exact-reference assertions. No retry/delay or weakened
assertion was added. The cause remains unconfirmed; the failed log and focused rerun are retained,
and this is not presented as a root-cause fix or stable native-store acceptance.

The SDK now tracks at most 32 subscriptions per connection. Subscribe requires advertised support
and a canonical bounded absolute URI. Pending notifications are coalesced, then released only on
confirmed subscribe success; only active exact-URI updates reach the sink, without arbitrary
remote metadata. Unsolicited, foreign, unsubscribing, unknown and closed-state updates are dropped.
Unsubscribe stops forwarding before I/O. Failed/cancelled transitions retain unknown capacity and
cannot be retried on that connection; success removes the slot, and close/drop clears all state.
The old stdio fixture now expects an update while subscribed rather than after unsubscription.

The daemon supports a deliberately short observation operation using an existing fixed resource:

```json
{
  "name": "mcp_watch_status",
  "kind": "resource_watch",
  "remote": {
    "name": "status",
    "uri": "gta://service/status",
    "description": "Observe the reviewed status resource"
  }
}
```

Arguments must contain durationMs in 1..3000 and maxUpdates in 1..32, with no URI override. They
are bound to the ordinary approval. The backend must advertise subscribe support and return the
exact reviewed resource descriptor before one subscription is sent. Observation retains only a
saturating count and a wakeup signal, not event bodies. Completion attempts one unsubscribe and
closes the owned connection; confirmed success returns counts, limitReached, coalesced and
unsubscribed flags with automaticRead/continuousSubscription false. Cancellation or uncertain
subscribe/unsubscribe remains unknown and is not automatically retried. Credentials and authority
are checked again on successful cleanup; catalog changes revoke the reviewed group as before.

Six actual HTTP SDK lifecycle cases and nine daemon watch cases cover confirmed/failed/cancelled
transitions, foreign/silent streams, missing capability, changed catalogs and cleanup. The real
daemon approval matrix includes denied/HTTP-approved/MCP-approved watch calls in both static
keyring and OAuth modes. Only approved cases subscribe and unsubscribe; resource reads do not
increase and private notification markers never enter results or audit. All owned fixture servers
and execution permits are released.

The duration bounds observation after subscribe, not total connection/discovery/unsubscribe time.
Counts are advisory and coalesced, not a complete event log. Already-admitted callback delivery can
race unsubscription, and protocol notifications cannot distinguish an old event after same-URI
resubscription. Persistent subscriptions, cursors/replay, automatic resource reads/context injection,
live-platform acceptance and the unreproduced native-status failure remain open. Six source hashes
are not a complete frozen build manifest; dependencies/lock are unchanged and whole-project
acceptance remains false.

## Active MCP Idle Expiry

The [active-expiry record](native-mcp-expiry-20260915.json) reports 342 passing tests, zero failures
and four existing ignored entries in nineteen HTTP API/daemon summaries, with strict all-target
Clippy. Dependencies, protocol versions, endpoint inventory and the root lock are unchanged.

McpSessions now owns one deadline-driven cleanup task, started when a session is created within
the HTTP runtime. It waits for the earliest authenticated-activity timestamp plus the existing
30-minute idle limit, or for a registry-change notification. On waking it recomputes from current
state rather than acting on a stale timer. The task holds a weak table reference and a child
shutdown token; registry drop cancels sessions and aborts its owned task, while service drain
signals it to exit. A finished worker can be replaced on a subsequent session creation. Outside
an async runtime, synchronous registry use retains the existing lazy-expiry behavior.

Expiry removes the session and cancels its request/SSE children even when no new request arrives.
It does not release request slots or stream permits while an operation or response body still
owns them. Existing ownership, initialized state, protocol pinning and refusal to revive expired
sessions remain unchanged. Four new tests cover spontaneous idle cancellation, actual SSE response
body completion and permit release, other-owner/activity isolation, worker replacement and shutdown.
They use short internal TTLs or controlled historical timestamps; no 30-minute wall-clock run or
cross-platform suspend/resume acceptance was performed.

The initial activity test incorrectly tried to refresh an already-expired session; its refusal was
correct, and the fixture was changed to exercise activity before the deadline without weakening
expiry. The separate native OAuth status intermittency from the observation record remains open.
Two source witnesses are not a complete frozen build manifest; whole-project acceptance remains false.

## OAuth CLI Process Coordination

The [coordination record](native-oauth-coordination-20260915.json) reports 570 passing tests,
zero failures and seven existing ignored entries in 27 tools/MCP/CLI/daemon summaries, with strict
all-target Clippy for all four packages. Dependencies and the root lock are unchanged.

Login, refresh and confirmed local logout now hold a per-profile/origin advisory file lock from
before native-store/network access until their operation ends, including browser callback waits.
Contending cooperating CLI processes fail immediately without changing native records or issuing
HTTP. Status and reference generation remain unlocked read-only operations. Coordination reuses
the existing per-user device-lock directory with a separate mcp-oauth-prefixed hash filename;
only empty metadata files are created, never credentials.

The first lock test showed that the ordinary verified file open still permitted renaming on
Windows. Sandbox::open_existing_for_coordination fixes that specific gap by retaining the normal
path/handle/hard-link checks while denying delete sharing. The caller retains the pinned directory
and locked file. Existing ordinary opens keep their prior semantics. The test now verifies file
and root rename refusal, nonempty/hard-linked target rejection, distinct-profile independence,
same-origin contention and reuse after release. Empty lock files are intentionally not deleted
between operations, avoiding competing locks on different replacement files.

Actual Windows CLI tests launch competing login, refresh and logout processes while an approved
login waits for its callback. All three report busy before extra network or native mutation. The
existing local OAuth fixture also covers termination of its owned login child before callback;
the callback port closes and another CLI can acquire the lock for confirmed logout. Normal,
timeout, refused and pending-result scenarios likewise clean up through the real CLI. All test
coordination directories are uniquely owned and removed after processes and handles close.

This is coordination among new CLI instances using the same standard per-user directory, not
native keyring CAS or an OS-wide lock on credentials. Older clients, direct SDK consumers,
external editors or processes selecting another lock root do not participate. Daemon snapshots
continue to recheck generation rather than holding this lock across remote calls. macOS runtime
validation remains open. The earlier unexplained native OAuth status failure is not claimed fixed
by this change. Four source hashes are not a frozen complete build manifest; whole-project acceptance
remains false. See the [CLI guide](../../apps/gta-claw-cli/README.md#cli-coordination).

## Native OpenAI Responses

The [Responses record](native-provider-responses-20260915.json) reports 694 passing tests,
zero failures and five existing ignored entries in 17 SDK/provider/daemon summaries. Final
provider/daemon all-target Clippy passes with warnings denied; the two initial lint failure logs
remain recorded. The root lock and dependency versions are unchanged. The public SDK schema was
read to correct plain assistant-history content to input_text; these mutable upstream references
are not a frozen upstream compatibility manifest or evidence of a real-account test.

`GTA_CLAW_PROVIDER_POLICY` accepts this explicit selection, without changing ordinary Chat defaults:

```json
{
  "provider": "openai",
  "model": "gpt-4o-mini",
  "apiKey": "env:NATIVE_PROVIDER_KEY",
  "baseUrl": "https://api.openai.com/v1/",
  "completionApi": "responses",
  "requestTimeoutMs": 120000
}
```

The model is an illustrative explicit selection, not a discovery or account-availability result.
Omitting completionApi retains chat_completions. Unknown/automatic dialect values and any
Anthropic completionApi are refused. Custom credential origins still require independent enrollment;
the existing explicit proxy and secret-resolution rules are unchanged. Selecting Responses changes
the completion endpoint and codec, not model-list/embedding endpoints, credentials or permissions.
No request falls back to another dialect/model or automatically retries under native policy.

The new provider codec emits store:false, a portable stateless input history and only explicit
function tool definitions. It encodes user text/images, ordinary system/assistant text, prior
function calls and matched outputs, sampling/output limits and JSON-object format. Unknown result
IDs, duplicate calls, unanswered history, assistant images and unsupported seed/stop options fail
before HTTP. It does not create previous_response_id, remote conversations or remote built-in tools.
Function strict:false avoids silently imposing the remote strict-schema default on existing schemas.

Buffered responses require a supported terminal state, valid model/IDs, bounded supported output
variants, complete JSON-object function arguments and consistent usage counters. Known token-limit
and content-filter endings retain text but cannot authorize function calls. Serialized request and
buffered response documents are limited to 8 MiB; portable output text/summary/arguments total 4 MiB,
individual function arguments 1 MiB, output items 1024 and combined message/summary parts 1024.
Streaming also retains the shared SSE framing limits and a whole-stream part/output budget.

Responses streaming verifies sequence continuity, response ID/model, output/part identity and
terminal snapshots. Text and reasoning summaries remain incremental; complete function events are
held until the terminal snapshot agrees with all accepted fragments, including interleaved calls.
Part completion is single-use and later deltas fail. Refusal and incomplete/error events do not
become successful tool rounds. A validated terminal closes the transport without waiting for remote
EOF, releases provider capacity and leaves the stream fused. Cancellation and Drop use the existing
shared runtime, not a second retry/cancellation mechanism.

The recorded-stream tests exercise every byte split of a fixture, invalid identity/sequence/parts,
empty text and inconsistent function snapshots. Existing real HTTP fixtures cover a buffered
function-call/result round, exact endpoint/body/credential, terminal on a held-open connection,
retained-stream capacity release, cancellation, Drop, truncated EOF, error and a single 503 attempt.
The real daemon fixture independently runs default Chat, Anthropic and explicit Responses modes,
checks fixed model/origin and store:false, and verifies failure/reload never changes selection.
Daemon native generation in this fixture is buffered; provider streaming is separately tested
over real loopback HTTP, not claimed as a complete end-user streaming workflow.

Chat stream completion was hardened separately: unmarked EOF, empty DONE and invalid/incomplete
tool rounds return typed protocol errors in the live and recorded paths, with no partial set of
completed tools. A finish reason without DONE and an identified response with DONE but no finish
reason remain intentionally compatible. The legacy public decoder finish signature remains, with
an incomplete_stream Other terminal on errors; it is not the live success path.

Open work includes opaque/encrypted reasoning continuation, assistant phase preservation, remote
jobs/conversations/built-ins, model-specific multimodal parameters, complete capability/account
configuration, durable paid-request unknown/billing workflows and real-provider acceptance. Portable
reasoning summaries are not sufficient proof of model-specific multi-turn reasoning support.
The earlier unexplained native OAuth status failure also remains open. Six source hashes are
checkpoint witnesses only; sourceFrozen, completeBuildInputManifest and wholeProjectAccepted remain
false. No real account, browser execution, device, deployment, Git write or production proxy change
was performed, and the provider inventory and checklist checkmarks are not promoted.

## Native Chat Identity

The [Chat identity record](native-chat-identity-20260915.json) reports a final 697 passing tests,
zero failures and five existing ignored entries across the same 17 SDK/provider/daemon summaries.
Provider/daemon all-target strict Clippy passes. This checkpoint includes the preceding Responses
implementation; its earlier six-source record remains a historical witness, not a hash assertion
about files subsequently edited here. Dependencies, lock and inventory counts remain unchanged.

Chat buffered completions now require exactly choice zero; stream frames carry at most that one
choice. The first stream frame must identify a valid response/model; later frames may omit those
fields, but present values must match. Choice data after a finish reason is refused while the
normal usage-only tail remains accepted. Existing no-DONE compatibility still applies, and the
exact prior empty-choices error contract is preserved after the first local check caught a wording
regression. Buffered missing response/model metadata retains its prior compatibility behavior.

Tool IDs are stable per index and cannot be shared across indexes. Invalid/missing completed IDs,
invalid completed names, indexes at or beyond the assembler limit, duplicated buffered IDs and
inconsistent tool/finish reasons fail. No subset of completed functions is emitted from a rejected
round. The existing assembler still handles valid name/argument fragments; it is not reimplemented
or changed for other provider dialects. Six real held-open HTTP scenarios cover changed response,
model, per-index ID, reused cross-index ID, wrong choice and multiple choices. Each fails promptly,
closes its owned socket and records exactly one request without tool completion/replay. Normal
Chat, Responses, Anthropic and Copilot regression coverage remains in the final gate.

The first joint regression did not pass: native_mcp_keyring_rotation_and_deletion_revoke_before_connecting
failed during enrollment with the masked error "MCP stdio native credential is unavailable".
This differs from proof that the key was absent: the wrapper also masks native lookup/access errors.
The unmodified original test passed when run alone. Only that fixture gained immediate native
write/readback verification, an exact configured-reference assertion and static underlying error
classification. No retry, wait, weakened assertion, test serialization or production credential
change was added. The same joint command then passed. The failed and isolated-pass logs are retained
with hashes. This failure and the earlier separate OAuth status absent result remain unexplained;
their root causes must not be reported fixed by these diagnostics or by Chat changes.

Three current source hashes and four log hashes are checkpoint witnesses. Full manifests, stable
native-credential availability, reasoning continuation/phase replay, complete provider billing and
unknown outcomes, real-account/platform acceptance and whole-project completion remain open.

## Native Anthropic Lifecycle

The [Anthropic record](native-anthropic-lifecycle-20260915.json) reports 703 passing tests,
zero failures and five existing ignored entries in 17 SDK/provider/daemon summaries, plus strict
provider/daemon all-target Clippy. The initial one-semicolon lint failure is retained. The two
source hashes are current checkpoint witnesses, not a frozen complete manifest; dependencies,
lock, inventory and checklist completion marks are unchanged.

The Anthropic decoder now requires one valid message_start and a confirmed message_stop with all
content blocks closed. EOF, empty stop, repeated starts, unknown/wrong-type deltas, duplicate
block starts/stops, blocks after a stop reason and mismatched SSE/payload event names fail.
Blocks use contiguous sequential indexes, bounded to 1024, and streamed/buffered tool IDs must be
valid and unique. Initial text/thinking strings are not lost. Initial tool input must be absent
or an empty object; this adapter does not silently ignore a nonempty initial input object.

Text and exposed thinking stay incremental, with already accepted events retained before a later
event failure in the same chunk. Function starts/argument fragments remain incremental, but completed
functions are withheld until the whole message terminal confirms them. Length/refusal/inconsistent
tool reasons cannot publish a partial set of completed functions. Aggregate text/thinking/arguments
is limited to 4 MiB and individual function arguments to 1 MiB. A complete terminal stops the owned
HTTP stream without waiting for the remote socket to finish and returns its concurrency permit.
The existing no-stop_reason message_stop compatibility infers Stop or ToolCalls; the legacy public
finish method retains its signature and reports incomplete_stream rather than normal completion on
failure. Live and recorded paths use typed errors.

Input usage now matches the documented Anthropic breakdown: ordinary input plus cache creation
plus cache reads. The old mapping excluded reads from the portable input total, despite cached
input being a portion of that total. The [official accounting description](https://platform.claude.com/docs/en/build-with-claude/prompt-caching#tracking-cache-performance)
was checked without contacting an inference endpoint. Optional cumulative fields distinguish omitted
values from explicit zero: omitted values retain their previous counts, decreases and integer
overflow fail instead of silently reducing/saturating usage. This is token accounting, not cache-write
pricing or a complete billing implementation; missing usage still retains compatibility defaults.

The tests cover block/identity/type/order/terminal mutations, byte/count boundaries, cache-read sums,
counter regressions and every byte split of a valid framed stream. The old split fixture lacked a
content start/stop pair and now includes them. Seven real HTTP cases verify complete tool messages,
truncated EOF, unclosed blocks, wrong delta type, duplicate function IDs, regressed usage and repeated
message start. They check partial text, no completed tools on failure, exactly one failed attempt,
socket close and reuse of a single capacity slot while the completed stream object is retained.
Existing cancellation, normal Anthropic, Chat, Responses, Copilot and daemon policy fixtures also pass.

Signed thinking/redacted-payload replay, model-specific continuation, accurate monetary pricing,
durable unknown outcomes, real-provider and platform acceptance remain open. Neither earlier native
credential anomaly has a confirmed root cause; this passing run is not a fix claim. No real account,
browser execution, production process/proxy change, deployment or Git write occurred.

## Native Chat Usage Budgets

The [Chat budget record](native-chat-budget-20260915.json) reports 707 passing tests, zero
failures and five existing ignored entries in 17 SDK/provider/daemon summaries. Provider/daemon
all-target strict Clippy passes. Two source hashes are checkpoint witnesses only; dependencies,
root lock, inventory and checklist completion marks remain unchanged.

The shared Chat usage mapping now checks reported total=input+output, cache tokens as a subset
of input, reasoning tokens as a subset of output, integer overflow and cumulative nondecrease.
Optional fields retain prior values in streaming updates instead of silently resetting counters.
The same mapping handles embedding responses; Copilot also uses the Chat decoder. Missing usage
still follows compatibility defaults, so zero must not be interpreted as proof that a paid request
was free or completely accounted. Complete usage-known provenance and durable billing are still open.

Buffered Chat JSON is capped at 8 MiB before decoding. Portable text/reasoning/function arguments
total 4 MiB; function count is capped at 1024 and a single argument document at 1 MiB. Streaming
counts decoded UTF-8 bytes cumulatively across fields and events. An over-budget stream returns a
typed error, not a complete answer/tool round. DONE now terminates the stream without waiting for
remote EOF. Accepted events earlier in a chunk remain visible before a subsequent protocol error.

Tests include exact multi-byte UTF-8 boundaries, shared text/reasoning/argument budgets, usage
subsets/totals/regression and a real HTTP stream reaching the actual 4-MiB decoded-output limit.
Normal DONE on a held-open socket releases the only concurrency slot even while the fused stream
object is retained. Invalid usage and excess output preserve accepted partial text, close and issue
one request only. The first HTTP budget fixture timed out because its existing server waits 5ms
after each HTTP frame and the test sent 512 frames; the same SSE events are now sent in one HTTP
reply frame. The original 5-second deadline and budget assertions are unchanged, and the identical
test passes. This fixture correction is not reported as a product timeout fix.

Runtime cost/provenance/unknown-result persistence, full provider model/account configuration,
reasoning continuation, real-account/platform tests and the prior two native-credential anomalies
remain open. Earlier source witnesses are historical and are not rewritten to match current files.

## Native Generation Terminal Gate

The [adapter record](native-generation-terminal-20260915.json) reports 345 passing tests,
zero failures and four existing ignored entries across 19 HTTP/daemon summaries, with strict
daemon all-target Clippy. The two source witnesses are not a complete frozen build manifest.

The actual provider-to-HTTP adapter previously discarded SDK finish_reason; the HTTP serializer
then synthesized stop or tool_calls. A truncated or filtered response could therefore appear to
be complete despite the codec preserving its terminal reason. The adapter now refuses Length,
ContentFilter, Cancelled, Other and ToolCalls without calls before output/history conversion.
Streamed completed tools remain buffered until the whole provider stream reaches an accepted
complete state. Already emitted text is not permission to invoke a tool; failed turns do not become
complete adapter history. Ordinary Stop remains compatible with complete calls from compatible APIs.

A controlled provider pauses after supplying text and a complete tool call but before terminal.
The test proves no tool/history is published during that interval and checks five terminal outcomes
for both buffered and streamed requests. Actual daemon fixtures return truncated and filtered
answers through Chat, Responses and Anthropic; each returns failure rather than synthetic success,
with no extra provider request and no failed-answer history injected into later requests.

This is a conservative gate, not the final partial-result contract: incomplete outcomes currently
become unavailable/503 and buffered partial text/usage are not returned as structured results.
Lossless typed finish/status propagation through HTTP, application/runtime and durable history
remains open, as do usage-known/billing, reasoning continuation, real accounts/platforms and the two
earlier unexplained native-credential failures. No real account, production proxy/process, browser,
device, Git write or deployment was used.

## Typed Partial Results

The [partial-result record](native-partial-generation-20260915.json) reports 585 passing tests,
zero failures and four existing ignored entries in 30 runtime/HTTP/daemon summaries. All three
packages pass strict all-target Clippy, and the root workspace passes all-target compilation.
The twelve source hashes are checkpoint witnesses, not a complete frozen manifest. Earlier
compiler/lint observations remain recorded; dependencies, lock and checklist marks are unchanged.

This increment replaces the preceding blanket 503 gate for known no-tool length/filter outcomes.
GenerationOutput now carries GenerationFinishReason and streaming returns GenerationSummary,
containing usage and the terminal. Chat emits length/content_filter, while Responses emits
incomplete plus incomplete_details and response.incomplete for streaming. Text, empty text and
reported usage are retained; empty partial output is not replaced with a placeholder answer.
Required-tool and JSON-object constraints do not mislabel a partial response as complete. A partial
result carrying completed tools is refused before any tool events reach the HTTP client. Complete
legacy response shapes retain their previous behavior, including existing tool response status.

The native adapter preserves those partial classifications and does not add incomplete turns to its
complete history. Unknown/cancelled states and partial tools still fail. Controlled ten-mode
provider tests verify buffered and streamed status/usage/history and withholding tools before a
terminal barrier. Real TCP tests cover both HTTP surfaces, both streaming modes, both partial
reasons, empty/nonempty text, required tools, incomplete JSON and malformed partial tool output.

The runtime bridge previously appended MessageEnd regardless of the result. It now forwards a
known partial text then a nonretryable stop error, never a successful message end or tool set.
Runtime provider errors, malformed chunks and unmarked EOF save already assembled partial data
through the existing TurnRecord field/schema. Failed join still returns an error. The existing
Gateway settlement deliberately keeps those runtime errors outcome_unknown because previous
external effects may already exist; this protection was not loosened or replaced with automatic
replay. Partial text does not become a completed assistant turn.

The actual daemon fixture uses explicit Chat, Responses and Anthropic. For each it exercises both
HTTP partial surfaces and pairs an owned Gateway device for two incomplete runs. Repeating the
original idempotency key returns the same run ID with no new provider invocation. Nine exact
completion requests per mode are observed. After clean process exit, reopening redb verifies both
partial texts, no complete message and no pending/completed tools. The first fixture assumptions
about successful failed-turn join, Gateway failed status and one-based first turn were corrected
against the existing contracts; no production protections were removed to satisfy them.

Runtime usage, finish provenance and monetary accounting are not yet stored with partial text;
the Gateway result remains a generic unknown-effect result. Complete retrieval UX, reasoning
continuation, model/account changes, real-provider/platform acceptance and both previous native
credential anomalies remain open. No real account, browser execution, device, production proxy or
process change, deployment or Git write was performed. M3-08 remains open.

## Retained Partial Pages

The [partial-page record](native-partial-pages-20260915.json) reports 318 passing tests,
zero failures and five existing ignored entries in 14 CLI/daemon summaries, with strict all-target
Clippy for both packages. Six source hashes are checkpoint witnesses, not a frozen build manifest.
The first lint failure and corrected missing-endpoint test assumption are retained in the record.

The existing agent.wait method accepts a native partialPage object with terminal revision, byte
offset and optional first-page SHA256. The server loads the original run under its authenticated
device partition before resolving the bound session/turn. A page requires the current terminal run
revision; nonzero offsets also require the original content digest. Visible text is capped at
4 MiB, each page at 2048 UTF-8 bytes, and cursors must land on character boundaries. Output includes
nextOffset, totalBytes, sha256 and explicit incomplete/untrusted flags. No reasoning or completed/
pending tool arguments are returned. The page is separate from the potentially large ordinary
run result, and reading cannot ACK, replay or change the terminal status.

The native CLI command is documented in the [partial-text guide](../../apps/gta-claw-cli/README.md#retained-partial-text).
It requests exactly operator.read and validates closed response identity, revision, page bounds,
cursor, digest and safety flags before rendering. A complete single-page response gets a full
hash check; later pages are pinned to the requested whole-text digest, not independently proven
to match it without collecting the entire text. Automatic collection/export is not implemented.

Real daemon fixtures verify owned pages for all three native provider modes, changed revision,
wrong digest, invalid continuation and refusal to another paired device. Reads leave results
pending and the provider request count unchanged. Actual CLI child processes validate exact
first/continuation RPC parameters and reject a corrupt page without disclosing its text. Local
UTF-8 tests exercise multi-page boundaries, empty text and the independent empty-SHA vector.

These reads do not promote partials to complete context or resolve unknown external effects.
Automatic full export, TUI/desktop views, durable usage/finish provenance, monetary accounting,
reasoning continuation, platform/real-account acceptance and both earlier credential anomalies
remain open. No real account, production proxy/process, browser execution, device migration,
deployment or Git write occurred.

## Typed Tool History

The [tool-history record](native-tool-history-20260915.json) reports 621 passing tests,
zero failures and four existing ignored entries across 21 application/runtime/daemon summaries.
All three packages pass strict all-target Clippy and the root workspace passes all-target compile.
Nine source hashes are checkpoint witnesses, not a frozen complete build manifest.

The original native runtime path flattened every assistant/tool message into a user transcript,
and the context item did not retain the provider call ID. ContextItem now has explicit
AssistantToolCalls and ToolCallResult variants. Runtime ingestion keeps the complete assistant call
list before execution and correlates each actual tool result with the original ID. The reference
and native engines account for these fields rather than manufacturing replacement identifiers.
Legacy textual context items remain supported; absent identities are not reconstructed from text.

Native checkpoints retain a typed metadata entry keyed to the exact retained message ordinal.
Restoration checks the role, canonical encoded content, valid unique call identifiers and JSON-object
arguments. Ordinary assistant text resembling metadata is still ordinary text. Encoded tool context
uses the existing 1-MiB per-message limit and participates in the existing token budget. Compaction
removes metadata for discarded messages. New readers accept old snapshots without this optional
field; older closed-schema readers are not claimed to accept checkpoints written with it.

The native provider bridge validates complete function/result correspondence and passes structured
SDK messages through the same active provider, model parameters, catalog and origin-bound credential.
Persistent context is the history authority for these calls; the HTTP adapter's incidental history
is not duplicated. Unknown or unanswered tool results fail before inference. Current recovery of
incomplete historical groups is therefore conservative and may require explicit context repair.

Legacy tool results, retrieved records and generated summaries no longer receive a system role in
native context. They are explicitly marked data messages. Host instructions and current goal policy
remain system messages. This role fix is not proof that all prompt injection is defeated; every
model-authored action remains subject to the existing execution authority, approval and audit gates.

Tests prove runtime second-round call association, canonical checkpoint roundtrip, corrupt/orphan
metadata refusal and ordinary-text isolation. The existing persistent LRU test now also closes and
reopens redb, confirms call/result association and then exercises explicit reset. The real model
memory fixture runs all three native dialects: Chat assistant/tool_call_id, Responses function_call/
function_call_output and Anthropic tool_use/tool_result. It checks original IDs, exact structured
parameters/results, approved execution, separate device notes and no external result promoted into
system instructions. Each mode issues exactly six inference requests. No real provider is contacted.

Complete incomplete-history recovery, signed/opaque reasoning continuation, external context-engine
acceptance, runtime usage/finish/cost persistence, real accounts/platforms and the two earlier native
credential anomalies remain open. Dependencies, lock, inventory and checklist marks are unchanged;
no deployment, Git write, production proxy/process change, browser or device migration occurred.

## Unconfirmed History Recovery

The [recovery record](native-tool-history-recovery-20260915.json) reports 231 passing tests,
zero failures and four existing ignored entries across nine daemon summaries, plus strict all-target
Clippy. Two source hashes are current checkpoint witnesses; older tool-history evidence remains
historical. Dependencies, lock, inventory and checklist completion marks are unchanged.

Interrupted or truncated historical tool groups no longer permanently poison an otherwise valid
new native prompt. Only complete contiguous assistant/call-result groups are emitted as typed
functions. Unpaired groups or orphan results are explicitly labeled untrusted, unconfirmed data,
including a warning that they are not authorization to retry. This projection preserves the
original records, does not invent missing results and does not grant execution permission.

Final projected messages, including data wrappers, role framing and structured function fields,
are estimated with the existing deterministic heuristic token counter and checked against the
original context allowance. A projection that exceeds its allowance is refused before inference;
this is not an exact provider tokenizer or automatic context compaction. Host rules are not silently
dropped and the configured budget is not expanded. Exact-boundary tests verify wrapper cost is charged.

The real Chat fixture starts an additional reviewed memory save, waits for its pending approval,
then terminates only that owned test daemon process before approval. Restarting the same isolated
state preserves pairing and recovers the old run as outcome_unknown. Submitting the original key
returns the same run without inference or tool replay. A distinct explicit new request completes,
seeing the unresolved old call only as data, not a callable function or fabricated tool result.
The original six tool audit records remain unchanged. Chat now has eight inference requests in
this fixture; complete Responses and Anthropic coverage remains six per mode. Interrupted process
coverage is Chat-only, not claimed for every dialect or platform.

Reconciliation of already-approved external effects, automatic compaction of over-budget projected
history, full reasoning continuation, monetary/usage persistence, real accounts/platforms and both
previous native-credential anomalies remain open. No production or user process was stopped, no
proxy setting was changed, and no real account, browser, device migration, deployment or Git write
occurred.

## Terminal Provider Accounting

The [accounting record](native-provider-accounting-20260915.json) reports 1,283 passing tests,
zero failures and five existing ignored entries across 40 summaries for seven related packages,
plus strict all-target Clippy. The root workspace all-target check passed before the final
behavior-neutral lint cleanup and test-only diagnostics; the final tests and lint cover the current
20 listed source witnesses. These are not a frozen or complete build-input manifest.

SDK responses distinguish Unreported, Partial and Complete primary-counter reporting. Explicit
input/output zeroes are known zeroes, not evidence inferred from defaults. Chat and Anthropic track
which primary fields were supplied; Responses requires them. Native HTTP streaming remains
conservative: a seen UsageUpdate is Partial, not proof of Complete reporting. Public HTTP usage
JSON remains compatible. The application owns an independent typed report and does not depend on
an I/O adapter's SDK types.

Each runtime round starts with an unknown entry and may capture an immutable validated report from
the same active provider instance that produced the output. It records provider/model/response
identity, four token counters, coverage and terminal reason, with at most 1,024 sequential rounds.
Invalid identities, subset/checked-sum failures, disappeared or changed confirmed reports and
contradictory successful stream terminals fail rather than manufacture known usage. Later provider
failure retains earlier round reports and any current partial text.

TurnRecord and its closed redb DTO preserve these entries on terminal persistence; old absent
fields remain unknown. Real database reopen tests distinguish missing reports, partial counters
and explicitly reported zeroes. This is not incremental crash-safe journaling: process termination
before a terminal turn write can lose reports. Missing data is not evidence of free inference.

Owner-bound agent.wait/gateway run adds a fixed-size providerAccounting summary. It checks aggregate
overflow and complete/partial/unreported counts, exposes no prompt or tool arguments, and keeps
costCalculated and billingReconciled false. The real three-dialect fixtures confirm actual identity,
two-round 14-token totals, length/filter single-round 7-token totals and redb reopen. The owned Chat
approval-before-crash case has no turn accounting, keeps its original unknown/no-replay contract,
and a distinct successful request has its own report.

Two joint regressions failed before the final pass. The first could not mutate its owned stdio
executable during a later approval because Windows reported an active file lock; its unmodified
isolated rerun passed. The second native-keyring case returned OutcomeUnknown without the expected
durable revocation. Only test diagnostics for case/phase/static error/remote counts were added;
isolated and final joint runs passed. Neither root cause is established, neither failure was
suppressed, and the older native-credential anomalies remain open. All original logs are retained.

Exact streaming provenance, in-flight per-round durability, pre-request budgets, monetary pricing
and reconciliation, real accounts/platforms and M3-08 remain open. An earlier local linker failure
was resolved by cleaning only the daemon package's build cache, not source/state/other projects.
Dependencies, lock, inventories and checklist marks are unchanged. No production/proxy operation,
dependency download, real account, browser, device migration, deployment or Git write occurred.

## Streaming Usage Provenance

The [stream usage record](native-stream-usage-20260915.json) reports 725 passing tests, zero failures
and five existing ignored entries across 17 summaries for SDK/providers/daemon. Strict all-target
Clippy and the root workspace all-target check pass. Six current source witnesses describe this
increment; the earlier 1,283-test terminal-accounting checkpoint is historical, not an additional
independent coverage total.

StreamEvent adds UsageReported with a validated cumulative counter snapshot and explicit
primary-field coverage. The existing UsageUpdate remains supported but proves only partial
reporting. StreamAccumulator retains Unreported for missing usage, Complete for explicitly
reported zeroes and matching final counters, and Partial for changed legacy-only terminal counts.
An absent or default terminal value does not fabricate a complete zero report.

Chat tracks whether each primary field has appeared, including reports split across frames.
Anthropic distinguishes absent usage from an empty object and emits source changes even when
numeric totals remain zero or unchanged; it reuses the existing validated cumulative wire counters.
Responses forwards the Complete coverage of its already-validated terminal response. Native HTTP
summaries consume the accumulator's coverage instead of marking every stream Partial. Public HTTP
usage JSON, complete-history gates and delayed tool release remain unchanged.

The existing controlled adapter test now covers 50 reason/tool/coverage combinations, including
missing counters, partial zeroes, complete zeroes, complete positive counts and positive legacy
terminal counters. Real HTTP tests verify exact Chat/Anthropic event sequences, Responses terminal
socket/capacity release and missing Copilot usage staying Unreported. The 40 wire tests are a subset
of the complete three-package regression, not added to its count.

Initial local fixes addressed a new zero-usage event in an exact partial-text sequence assertion,
excess flat booleans, eager test fallback calculation and SSE fixture string construction. The
original partial text and subsequent protocol error remain asserted. No production timeout,
automatic retry, test serialization or credential behavior was weakened. Earlier native-keyring
and stdio file-lock failures remain unresolved despite the current regression pass.

Exhaustive external SDK consumers must handle the new event variant; root compile coverage is not
an external binary-compatibility claim. This adds neither a streaming runtime execution path nor
automatic HTTP-stream persistence. In-flight per-round crash durability, monetary budgets/prices,
remote billing reconciliation and actual accounts/platforms remain open, as does M3-08. No new
dependency, lock, inventory/checklist mark, production/proxy, Git, deployment or device change occurred.

## Durable Provider Journals

The [journal record](native-provider-journal-20260915.json) reports 674 passing tests, zero failures
and four existing ignored entries across 22 summaries for application/runtime/state/daemon. Strict
all-target Clippy and the root workspace all-target check pass. Seven current source witnesses
describe the increment; earlier accounting and streaming receipts remain historical.

ProviderRoundJournal is separate from immutable terminal TurnRecord. The native state adapter
stores bounded sequential intent/report entries under a versioned per-session/turn key, with CAS
revision and an explicit closed marker. A new journal must begin with one unknown attempt. Later
updates may append exactly one unknown attempt or fill the latest attempt's first confirmed report,
but cannot change earlier rounds, replay an intent, replace a response or append after closure.
Unsupported state adapters fail closed rather than silently discarding journaling.

Runtime awaits the intent write before even constructing provider.start_round. It rechecks
cancellation after that write and persists the first confirmed response before consuming output
or authorizing subsequent tools. A write refusal stops progression. Repeated identical confirmed
metadata does not perform extra writes. Terminal persistence verifies the exact journal sequence
and atomically writes the immutable result plus closed journal, so concurrent response/seal writes
cannot both succeed. The existing tracked storage workers and unknown-write fence remain in force.

Owner verification still precedes run/turn reads. A recovered terminal run with no TurnRecord can
now expose checked providerAccounting from its independent journal, with recordSource,
journalRevision, journalClosed and attemptsMayBeUnsent. Intent is not proof a request reached the
remote service. Reading does not ACK, resend work, grant approval or clear outcome_unknown. In-memory
smoke/test adapters mirror CAS/sealing but do not gain process-restart durability.

Real redb tests cover competing initial writes, stale/replayed attempts, report replacement,
reopen with an unknown second round, mismatched terminal refusal and concurrent response-versus-seal
commit. Runtime tests prove write failure before inference means zero requests, failure before
report publication means zero tools, live reports precede visible text, and cancellation during a
gated intent write produces no provider invocation. The real three-dialect model-memory fixture
continues to pass; its owned Chat process is killed only while its tool awaits approval, then
restarted. The original run retains a revision-2 open journal with one confirmed 7-token report,
keeps unknown status and deduplication, and does not repeat inference or the unapproved tool.

Two joint runs failed in unrelated existing MCP fixtures: post-initialize discovery received
SessionExpired, then a native OAuth write/readback reported a changed token record. Both unmodified
isolated tests and the final unchanged joint cohort passed. Their root causes are unresolved and
all logs remain recorded; no MCP/credential policy, timeout, retry or test serialization changed.
Earlier native-credential and stdio file-lock anomalies also remain open.

This closes the native runtime's terminal-only accounting gap, not all paid-request uncertainty.
A remote response lost before its report commit still has unknown usage. Old records are not
reconstructed; automatic standalone HTTP-stream persistence, continuous partial-text checkpoints,
monetary limits/pricing/invoices, downgrade acceptance and real-account/platform verification remain
open. Dependencies, lock, inventory and checklist marks are unchanged. No production/proxy,
deployment, Git write, real account, browser or user-state migration occurred.

## Observed Usage Threshold

The [threshold record](native-observed-budget-20260915.json) reports 475 passing tests, zero
failures and four existing ignored entries across 20 runtime/daemon summaries, plus strict
all-target Clippy and a root workspace all-target check. Six current source witnesses describe
this increment; older journal/stream receipts remain historical.

RuntimeConfig can optionally set max_observed_provider_tokens. Before assembling a further model
round, it checks validated, explicitly complete prior primary counters and a checked input/output
sum. Cached and reasoning subsets are not added a second time. At or above the threshold the turn
blocks; absent/partial usage or overflow refuses another budgeted request. Zero blocks the first
model request. The gate precedes intent journaling and provider construction, and defaults to off.

Native OpenAI/Anthropic startup policy exposes maxObservedTurnTokens as an optional unsigned
integer. It is captured before provider construction consumes the policy and passed to the native
runtime. The old AgentRuntime constructor delegates with no threshold, preserving its callers.
The threshold is fixed at startup, not a hot-reloaded or global account balance.

Runtime tests cover zero, equality, remaining allowance, unknown versus explicit-zero counters,
cumulative two-round usage and overflow that prevents a third request. Real isolated daemon tests
cover absent/zero/one thresholds through device pairing and Gateway submission. Each configuration
handles two distinct turns and same-key resubmissions: zero produces no model requests; the other
settings allow one seven-token response per turn, with no replay for the original key. That
one-token threshold intentionally does not truncate or relabel the seven-token response.

This is an observed-usage stop threshold, not a hard per-request token cap, monetary reservation,
rolling/global quota or invoice reconciliation. An allowed request may exceed it. Earlier approved
tool effects are not undone; explicit new turns have independent allowance. Direct tools and
standalone HTTP generation are outside this setting. M3-08 and all earlier native-credential,
stdio-lock, MCP session and OAuth verification anomalies remain open.

The only new strict-lint failure was a missing test-server statement semicolon, repaired without
behavior changes and retained in the receipt. No dependency/lock change, production/proxy action,
real account, browser, device migration, deployment or Git write occurred. Checklist marks and
inventory counts are unchanged.

## Complete Partial Export

The [export record](native-partial-export-20260915.json) reports 95 passing tests, zero failures
and one existing ignored entry across five CLI summaries, plus strict CLI all-target Clippy. Four
current source witnesses cover CLI-local changes; no new root-wide build is claimed or needed for
these private helpers. Earlier daemon page ownership and partial-record evidence remains separate.

gateway export-partial accepts an exact run/revision and an explicit absolute new local destination.
It reuses the closed single-page validator, requests only operator.read on one connection epoch,
and pins session/turn/status/total/digest across contiguous pages. Collection is bounded to 4 MiB,
4096 pages and the existing total command network deadline. No ACK, write idempotency, offset/wait
override, reconnect or automatic retry is permitted. Empty retained text is distinct from absence.

The entire SHA256 is checked before preparing any local write. The existing pinned-parent sandbox
and exclusive create-new handle prevent overwriting an existing target or following a link. The
owned blocking writer writes UTF-8, synchronizes the file and checks the parent identity, then is
joined. Unix creation is owner-only; Windows inherits the trusted parent ACL. This is not atomic
rename publication: local I/O failure can leave an unconfirmed file, reported as fileMayExist,
without deletion of an uncertain output. Network or page validation failure does not create a file.

Output is untrusted incomplete plaintext containing visible text only. The CLI receipt includes
identity/size/digest/page count and safety flags, not the text, reasoning, tool arguments or stdin
credential. Export does not acknowledge, modify or rerun the source. PartialExportPages uses a
zeroizing collection buffer but makes no claim to erase every transport/parser allocation.

Seven actual CLI subprocess/WebSocket-fixture cases cover complete and empty exports, same-length
corrupt final content, changed page identity, disconnection, an existing destination and unavailable
partial data. They check exact read scopes and request shapes, one connection, original-file
preservation, no target on validation failure and no text/credential output. Unit cases additionally
exercise cross-page UTF-8, cursor/revision/length/digest changes and the page-count cap.

The initial unit compile exposed DiagnosticFailure's intentional lack of Debug; tests now match
results without adding diagnostic debug output. That failure is retained in terminal conversation
history, not a separate log. TUI/desktop partial UX, encrypted partial archives, interrupted export
resumption, per-chunk source persistence and full real-platform acceptance remain open. All earlier
native credential, MCP/OAuth and stdio anomalies remain open. Dependencies, lock, inventory and
checklist marks are unchanged; no production/proxy, Git, deployment or real-account action occurred.

## MCP Activity Ordering

The [ordering record](native-mcp-activity-order-20260915.json) reports 360 passing tests, zero
failures and four existing ignored entries across 19 HTTP API/daemon summaries, plus strict
all-target Clippy. One current source witness covers two production-line fixes and a deterministic
regression. The failing baseline is retained alongside the passing focused and integrated results.

Session requests sample Instant before acquiring the shared registry lock. A newer request can
create or touch a session before an older sampled request acquires that lock. The old expiry check
treated checked_duration_since returning None as expired, cancelling an active newer session.
The resolver could also move touched backwards. The deterministic test reproduces this without
probabilistic scheduling by processing newer and older samples in reverse order.

Expiry now requires a nonnegative elapsed duration at least equal to the idle limit, and activity
uses max(previous, sampled). The test verifies that an older create or resolve cannot expire or
backdate the session, that one nanosecond before the real latest-activity deadline remains live,
and that the exact deadline cancels the session and request. Stream capacity remains occupied
until the actual permit is dropped. The 30-minute TTL, explicit DELETE, shutdown, initialization,
authorization and retry behavior are unchanged.

The real MCP client/owned daemon session fixture passes in the full cohort. This establishes a
specific source-level cause compatible with the earlier SessionExpired symptom, not proof that
the historical failure had no other cause: it lacks a timestamp trace. Native credential/OAuth
verification and stdio-lock anomalies are independent and remain unresolved. No retry, timeout
relaxation, serialization or credential workaround was introduced.

The only new lint fixes use checked time subtraction and explicitly release the test lock. Public
interfaces and dependencies are unchanged; no root-wide rebuild is claimed for this local fix.
No production/proxy, real account, browser, device migration, deployment or Git operation occurred.
Inventories and checklist marks remain unchanged; full MCP and whole-project acceptance stay open.

## Native Readback Diagnostics

The [readback record](native-keyring-readback-20260915.json) reports 589 passing tests, zero failures
and five existing ignored entries across 18 SDK/MCP/daemon summaries, plus strict all-target Clippy.
Two current source witnesses cover a Windows-owned-key test and OAuth diagnostic classification.
The initial concurrent native test failure remains in the record; this is not a storage fix.

The adapter holds an explicit native store instance rather than a process-global default store.
The new regression creates four unique owned credentials and independent read handles before
starting worker threads, then coordinates concurrent set/read/rotation/delete stages without
retries or sleeps. It compares only its own keys and reports stage flags, presence or static errors,
never credential values. Setup failure occurs before any barrier waits. Cleanup touches only those
fixture keys.

The first run returned successful deletion but failed the expected absent readback. The original
assertion did not retain whether the value was still present or an underlying read error occurred.
After adding that diagnostic, isolated and full regression runs passed. There is no established
native root cause, no changed Windows backend, persistence mode, operation serialization or retry.

NativeTokenStore write confirmation now distinguishes absent-after-write, changed-content and
readback failure, all still unknown outcomes that refuse continuation. Existing simulated faults
now cover absence for both pending markers and final token writes. Each path writes once, performs
no rollback/deletion and exposes neither backend details nor token material. The new classification
does not make write/readback atomic with external writers.

All previous native credential, OAuth and stdio anomalies remain open. Public interfaces and
dependencies are unchanged; scoped full tests/lint are the verification gate, not a new root-wide
build. No production/proxy, real account, browser, user migration, deployment or Git change occurred;
inventory and checklist marks remain unchanged.

## MCP Cleanup Observation

The [drain record](native-mcp-drain-20260915.json) reports 235 passing tests, zero failures and
four existing ignored entries across nine daemon summaries, plus strict all-target Clippy. Two
current source witnesses cover the operator summary and the existing stdio process test.

ToolExecutor may return an unknown outcome on cancellation before NativeMcp's tracked task has
finished closing its client and recording its audit result. That owned task retains the executable
pin through transport cleanup. Cancellation acknowledgement alone therefore does not prove its
resources are drained. No cancellation, close, execution or approval policy was changed.

The existing authenticated operator status now reports activeInvocations from TaskTracker and a
matching allInvocationsDrained flag. The real owned stdio test verifies one active invocation and
locked executable/working directory while the child runs, preserves the nonretryable cancellation
response, then observes task completion within its existing isolated fixture before testing that
the executable pin has been released. Only then does it run the later approved-binary mutation
case. It does not relax pinning or retry a side-effecting operation.

This makes the previously implicit cleanup boundary observable and corrects the test's assumption
that a cancelled response meant cleanup was already complete. The original Windows file-lock
failure log remains in the earlier accounting receipt; it is not silently replaced by a pass.
The summary is an instantaneous task observation, not a lock against new work, a claim about all
remote effects or permission to modify a live deployment. Unknown effects still require separate
reconciliation. Credential/OAuth and other historical anomalies remain open.

Dependencies, lock, inventories and checklist marks are unchanged. No production/proxy operation,
real account, browser, device migration, deployment or Git write occurred.

## TUI Partial Inspection

The [TUI record](native-tui-partial-20260915.json) reports 66 passing tests, zero failures and no
ignored entries across five TUI summaries, plus strict all-target Clippy. Six current source
witnesses cover the worker contract, selected-session model, palette action and existing tests.

Explicit partial and partial-next actions require an observed terminal run/turn/revision and the
current selected session. The worker issues one agent.wait read on the observed connection epoch,
with no ACK, wait option, replay or added permission. Closed typed responses validate exact identity,
terminal state, 2048-byte pages, 4 MiB total, cursor progression and untrusted/incomplete safety flags.
Continuation requests also retain the original total length and whole-content digest. A complete
single page verifies its full SHA256; a later page cannot independently verify the entire content.

The model rejects stale revision/selection events, duplicate pages and out-of-sequence continuations.
It labels each page as partial with the original byte range, sanitizes text after validation, and
does not change the run state, worker completion eligibility or UI ACK queue. Existing complete
terminal receipt acknowledgements remain unchanged. Only the last cursor and a bounded transcript
are retained; this is not a complete partial archive or automatic full-result download.

Seven real local WebSocket worker cases cover valid two-page UTF-8 text, empty text, bad digest,
changed identity, false completeness, unknown fields and a stale connection. They verify exact
read requests and that even an explicitly attempted ACK after only a partial page is refused locally.
Model tests verify discarded old revisions and selection reset. The in-memory terminal backend
checks 40/80/120 columns at 10/24 rows with wide-character text, range labels and an intact separator.
No visible terminal, real provider or production Gateway was started for this slice.

One strict-lint failure only required separators in a test limit literal; it is retained in the
receipt. TUI usage/cost views, full export/archive, desktop parity, real interactive cross-platform
acceptance and prior native credential anomalies remain open. Dependencies, lock, inventory and
checklist completion marks are unchanged. No production/proxy, user-state migration, Git, deployment
or real-account action occurred.

## Dependency Security, 2026-09-15

The [dependency record](native-dependency-security-20260915.json) starts from public main
`9840094c853951bf9ee540dcf24ef01fdab064f5` and a clean worktree. A fresh GitHub query confirmed
41 open alerts: 39 npm records and two copies of the same Rust JWT advisory. The final local npm
audit and RustSec audit report zero vulnerabilities. Six affected Rust packages pass 828 tests,
with six existing ignored entries, strict all-target Clippy and a root workspace all-target check.
This is not release acceptance: cargo-deny bans still fail on existing dependency-policy debt and
the JWT library's additional signature 2.x line. No policy exceptions or advisory ignores were added.

Retained Node dependencies now resolve patched versions, including find-my-way 9.7.0. Real execution
also required Restify 12: version 11 eagerly imported SPDY code using Node 26's removed http_parser.
An audit-zero tree still failed the CSV prototype test because csv 6.4.1 embeds its own old CommonJS
parser; csv 6.6.3 fixes the actual path. The persistent
[legacy regression script](../../scripts/check-legacy-dependencies.ps1) compiles the real service and
checks 31 assertions on owned HTTP/HTTP2 listeners, parser safety, UUID compatibility, Axios and
admin rejection. Clean offline npm installation uses no lifecycle scripts. An official checksum-checked
Node 26.8.2 is isolated under ignored target; the installed global Node and production proxy are untouched.

Teams JWT verification now uses jsonwebtoken 10.3.0's corrected claim validation with existing ring
RS256 verification only. A trial all-algorithm RustCrypto backend was rejected after audit exposed its
unpatched RSA side-channel dependency. Nineteen genuinely signed fixtures plus key/signature/activity
negative tests preserve optional absent nbf, reject malformed claims, and retain issuer, audience,
expiry, endorsement and service-URL checks. No private signing key is stored. rustls 0.23.45 and
Wasmtime 47.0.4 also fix additional live RustSec findings. Three independent workspace locks retain only
the corresponding TLS package changes and pass locked target dependency resolution, not device builds.

The initial combined regression reproduced the existing native OAuth lost-response/readback anomaly.
Its unchanged isolated test and final combined cohort passed, but all three results remain distinct;
there is no claimed credential root-cause fix. GitHub closure must be checked after main publication.
Real accounts, device and native-addon validation, complete supply-chain policy and release gates
remain open. No deployment, paid request, production proxy restart or user-state migration occurred.

Post-publication queries after `084795e77f14f552735329fcf5c8755d48930baa` now independently report
zero open alerts and 56 fixed records, including the original 41. The push's earlier alert message
preceded GitHub's asynchronous refresh. This is alert closure evidence, not waiver of cargo-deny,
protected release workflows or product acceptance.

## TUI and Desktop Accounting

The [client accounting record](native-accounting-clients-20260915.json) reports 138 passing
protocol/TUI tests and 86 passing desktop tests, with no failures or ignored cases in these cohorts.
Both strict all-target Clippy checks and the root workspace all-target check pass. It records the
13 source witnesses, not a frozen whole-project input manifest.

A shared closed native protocol model validates round counts, exact coverage, observed/subset totals,
overflow and terminal-turn versus journal provenance. Missing, unreported and partial counters never
become complete zeroes; actual complete zeroes stay visible. Unsupported monetary/settlement claims
are rejected rather than silently shown as paid or free. This does not change sealed upstream payloads.

TUI now carries providerAccounting from send_native_run through the worker event and selected run
model to its scrollable workspace. Nine real WebSocket scenarios verify propagation and rejection
before ACK eligibility. Selection, older turns/revisions and disconnects preserve the existing
identity rules. Six terminal dimensions verify wrapping and separation. The summary does not append
assistant text, create ACKs or replay unknown work.

Desktop consumes the same parser, saves a connection/run/revision-bound snapshot and binds a read-only
Usage region in the actual Slint session tree. Seven state cases preserve unknown/partial/zero/open
journal semantics. Repeated identical snapshots still allow a lost ACK to be confirmed, while stale
or same-revision conflicting accounting cannot overwrite or acknowledge. Actual software rendering
at 1080x720 and 720x520 checks state-to-widget values, nonblank/changed pixels and disconnect clearing.
These are headless native component tests, not physical desktop or macOS user acceptance.

Both clients explicitly show uncalculated cost and unreconciled billing, including zero token totals.
Persisted intent is not proof of a sent request. Monetary limits/pricing/invoices, unified model
configuration, full desktop partial paging/export and real account/platform workflows remain open.
Earlier native credential/OAuth anomalies and supply-chain policy gaps remain unchanged. No real
account, OS window, device, deployment or production/proxy operation was performed.

## Provider Preparation and Publication

The [publication record](native-provider-publication-20260915.json) records a genuine failing
baseline: rejecting an unknown configured model changed the provider generation from zero to two.
SwappableProvider had published its slot before validating the model, then restarted the previous
provider as rollback. This could disturb generation-bound work even though activation was refused.

ProviderSlot now holds its existing switch lock through asynchronous host preparation and a final
synchronous commit. The host write guard remains held until the generation is published. Daemon
preparation validates the exact selected model and rechecks the configuration generation, so failed,
cancelled, dropped or stale candidates never replace the old active adapter or replay old startup.
Existing calls retain their original provider instance and may finish normally.

Shutdown retires the owner, cancels pending model preparation and clears host/slot under the same
lock. Subsequent activation and readiness publication on that retired owner are refused. Controlled
barriers verify six daemon outcomes and a real local completion on the old provider while the candidate
is preparing. Slot tests verify serialized preparations, lock-wait cancellation, guard release order,
old startup counts and generation exhaustion. Cancellation is still not proof of no external effect.

The providers/daemon full cohort passes 479 tests with four existing ignored entries; strict all-target
Clippy and an independently completed root all-target check pass. The first root-check capture was
incomplete and is retained separately, not relabeled successful. Unified typed
configuration, full provider-specific cleanup, monetary budgeting/invoice reconciliation and real
account/platform acceptance remain open. Earlier credential/OAuth failures remain unresolved.