# GTA Claw Native CLI

## Local MCP Credentials

`mcp credential reference|status|set|delete` manages only the dedicated native credential for an
explicit MCP server ID and resource origin. It never connects to the endpoint, starts a daemon,
edits policy, approves a tool, or performs an OAuth login. The server ID must match the daemon's
reviewed policy. HTTP requires a literal loopback address; HTTPS follows the public-host policy.
Userinfo, query strings, fragments, private HTTPS targets and ambient proxy selection are refused.
The daemon's separately reviewed HTTPS proxy is still required for actual outbound calls.

```powershell
gta-claw-cli mcp credential reference --server reports --endpoint https://mcp.example.com/mcp
gta-claw-cli mcp credential status --server reports --endpoint https://mcp.example.com/mcp
$credential = [pscredential]::new("token", (Read-Host "MCP token" -AsSecureString))
try {
  $credential.GetNetworkCredential().Password |
    gta-claw-cli mcp credential set --server reports --endpoint https://mcp.example.com/mcp --token-stdin --confirm-write
} finally {
  Remove-Variable credential
}
gta-claw-cli mcp credential delete --server reports --endpoint https://mcp.example.com/mcp --confirm-delete
```

These are separate operations, not a sequence to execute blindly. `--confirm-write` explicitly
allows creating or replacing that one entry; deletion requires `--confirm-delete`. There is no
bulk enumeration, secret-valued argument, secret file, environment-token input or plaintext
fallback. Set accepts piped UTF-8 input only, not an echoing terminal: one 16..4096-byte token,
optionally followed by LF/CRLF, with EOF within 30 seconds. Configure the shell pipeline for UTF-8
when needed, especially in Windows PowerShell 5.1. Neither the shell example nor stdin avoids the
brief in-memory plaintext required for the native write; do not store or log it.

The returned `tokenRef` is derived by the same `CredentialBinding` as the daemon, under
`keyring://gta-claw.mcp-outbound/`. It binds the server ID, scheme, host and port. Same-origin paths
share a credential, while full endpoint, proxy and descriptor remain in the daemon's approval.
Put this reference in reviewed `GTA_CLAW_MCP_TOOL_POLICY` as `tokenRef`, replacing `tokenEnv`.
Reference generation does not open a store. Status reports only existence, not validity at the
remote service. Store operations use Windows Credential Manager or macOS Keychain; other
platforms fail closed. Only Windows runtime behavior has been tested for this increment.

Set/delete read back once and never automatically retry or roll back. Their JSON explicitly
reports `atomicCompareAndSwap: false`; an external writer can race the operation. A failure with
`mayHaveChanged: true` is an unknown local outcome, not proof that the old value remains. Status
can establish existence only, not which concurrent value won. Native-store work is joined, so the
stdin timeout is not a hard keystore-I/O or process-exit deadline. Process interruption can leave
an unknown result without a durable CLI receipt.

Credential changes do not live-refresh a running daemon. It rechecks before connection and after
discovery, then revokes a changed/missing enrollment. Re-review changed credentials and use a new
`reviewRevision` plus a fresh approval; this CLI does not clear prior revocations. Deleting locally
does not revoke the remote provider token or settle an already in-flight operation. Full OAuth,
remote revocation, macOS runtime acceptance and crash-durable provisioning remain separate work.
See the [credential CLI record](../../docs/ledger/native-mcp-credential-cli-20260915.json).

### OAuth Records

OAuth records are separate from raw HTTP/stdio credentials. Use these local-only commands:

```powershell
gta-claw-cli mcp oauth reference --server reports --endpoint https://mcp.example.com/mcp
gta-claw-cli mcp oauth status --server reports --endpoint https://mcp.example.com/mcp
gta-claw-cli mcp oauth logout --server reports --endpoint https://mcp.example.com/mcp --confirm-logout
```

Reference generation accesses no native store. Status returns `record.state` as `absent`,
`reauthorization_required`, or `available`. Available records include local `fresh`,
`refreshAvailable` and `expiryKnown` flags. An available record is not proof that the remote service
accepts it, and freshness without a known expiry is only the library's local policy. Status never
refreshes a token, opens a browser, reveals scope/token contents, or makes a network request.
Corrupt, foreign-bound and unavailable records return an error rather than appearing absent.

Logout requires the distinct `--confirm-logout` flag. It first records a refusal marker, then deletes
and verifies the one native OAuth record; uncertain deletion is not automatically retried. It does
not revoke the provider's token, notify a running daemon, or cancel another process's in-flight
authorization. `remoteRevoked`, `remoteAuthenticationVerified` and `daemonNotified` remain false.
The worker is awaited through completion; this is not a hard native-I/O deadline or cross-process
compare-and-swap. Use this only for the explicit local record you intend to retire.

The returned `credentialRef` uses `keyring://gta-claw.mcp-oauth/`; do not pass it as the daemon's
static `tokenRef`. There is no `mcp oauth set` or stdio OAuth target, and these commands do not
implement login themselves; use the separate confirmed login command below to create the issuer/
client/resource-bound record. Only Windows runtime behavior has been verified here; macOS uses
the existing native adapter but still requires platform acceptance. See the
[OAuth CLI record](../../docs/ledger/native-mcp-oauth-cli-20260915.json).

### Public-Client Login

`mcp oauth login` supports an explicitly provisioned public OAuth client with PKCE S256. Supply
the reviewed resource, issuer, authorization/token endpoints and public client ID. It does not
perform dynamic registration or accept a client secret. HTTPS endpoints require an explicit
literal-loopback HTTP CONNECT proxy; remote plain HTTP, private HTTPS targets, credentials in
URLs and redirects are refused. The issuer metadata must match both reviewed endpoints and
explicitly advertise S256. Metadata cannot enroll a new destination.

```powershell
gta-claw-cli mcp oauth login --server reports --endpoint https://mcp.example.com/mcp --issuer https://auth.example.com/ --authorization-endpoint https://auth.example.com/authorize --token-endpoint https://auth.example.com/token --client-id $RegisteredPublicClientId --http-proxy $ReviewedProxyUrl --scope "tools:read" --confirm-login
```

These example hosts and variables must be replaced by an operator-reviewed registration. The
confirmation authorizes this login attempt and replacement of the selected local OAuth record;
it does not approve a daemon tool or change a production proxy. The default overall network/
callback budget is 120 seconds; `--timeout-ms` accepts 250..120000. `--callback-port` selects a
fixed local port when required by the registration, or zero for an OS-assigned port. The exact
redirect is `http://127.0.0.1:<port>/oauth/callback` and is included in the authorization request.

The command prints a schema-version-1 JSON line with `stage: authorization_required`,
`authorizationUrl` and `redirectUri`, then waits. Open that exact URL in your browser yourself;
there is no automatic browser launch. The URL intentionally contains state, PKCE challenge and
requested scope for this attempt; treat it as transient authorization data and do not publish it.
The final JSON line has `stage: completed` or `failed`. Consumers must not treat the first line
as completed authentication. Callback responses never echo codes or state and use no-store headers.

The owned receiver accepts only bodyless GET at its exact Host/path. It checks unique code/state,
optional issuer, bounded encoding and the request lifetime; repeated, mixed or denied responses
cannot redeem another code. It examines at most 16 connections, with five-second header budgets,
and closes on success, cancellation, timeout or rejection exhaustion. Ctrl+C requests cancellation;
native-store work is joined, so the timeout is not a hard keystore or process-exit deadline.

One code exchange writes a pending native marker before HTTP and saves the validated response
with its original issuer/client/resource authority. Lost responses or unconfirmed persistence
require a new authorization, never automatic replay. Use `mcp oauth status` to inspect the local
record. Successful `tokenResponseReceived`/`nativeRecordVerified` does not prove MCP resource
access: no resource request, daemon configuration or review revision change is performed. Do not
run concurrent login/refresh/logout processes for the same profile; the native store lacks CAS.

Actual Windows tests use owned local protocol servers and simulate the redirect without opening
a browser. Real provider registrations, browser interaction, macOS runtime, active Ctrl+C behavior,
confidential clients and automatic refresh scheduling remain unverified or unfinished. See the
[OAuth login record](../../docs/ledger/native-mcp-oauth-login-20260915.json).

### Explicit Refresh

Refresh is an explicit command, not a side effect of status or an MCP tool call. It requires the
same reviewed server/resource/issuer/authorization/token endpoints and public client ID as login:

```powershell
gta-claw-cli mcp oauth refresh --server reports --endpoint https://mcp.example.com/mcp --issuer https://auth.example.com/ --authorization-endpoint https://auth.example.com/authorize --token-endpoint https://auth.example.com/token --client-id $RegisteredPublicClientId --http-proxy $ReviewedProxyUrl --confirm-refresh
```

The distinct `--confirm-refresh` is mandatory. Scope and callback options are refused: this renews
the current enrollment and does not request additional permissions. It never opens a browser or
callback listener and prints only one terminal JSON result. The same timeout, route, metadata and
native-store checks apply. A missing, invalid or pending native record, or one without a refresh
token, is refused before contacting the issuer. A fresh access token does not bypass confirmation.

Exactly one refresh request uses the original bound client/resource. Pending is stored before
the request; the validated response is saved and read back. Omitted refresh token or scope retains
the prior value as required by the OAuth refresh contract. Refusal, lost response or uncertain save
requires new authorization. Repeating refresh on a pending record is rejected before networking,
never a replay of the old refresh token. Use local status and start a new explicit login when needed.

This command changes the credential generation, including cases where access-token text remains
unchanged. A daemon retaining the prior generation refuses it and needs explicit review of the new
generation with a new `reviewRevision` and fresh approval. Refresh neither rewrites policy nor
restarts/notifies the daemon. Do not run concurrent processes for the same profile; native storage
does not provide cross-process CAS. Actual Windows local fixtures cover refresh success, dropped
response and service refusal. Live providers, macOS, confidential clients and coordinated automatic
refresh remain open. See the [refresh record](../../docs/ledger/native-mcp-oauth-refresh-20260915.json).

### CLI Coordination

New CLI login, refresh and confirmed logout operations for the same server/profile and resource
origin acquire one nonblocking process lock before native-store or network work. Another such
operation returns busy without changing credentials or making a request. Login retains the lock
while waiting for its callback, so a concurrent logout cannot be overwritten by its later exchange.
Status/reference remain read-only and do not acquire the mutation lock.

The lock is an empty, non-secret file under the existing per-user coordination directory:
`%LOCALAPPDATA%\gta-claw-device-locks-v1` on Windows, or `$HOME/gta-claw-device-locks-v1` on macOS.
Its `mcp-oauth-<binding-hash>.lock` name isolates it from device-profile locks. A pinned Sandbox
rejects links, hard links, nonempty files and unsafe directories. The Windows handle prohibits
rename/deletion while held, preventing a second lock from being created by replacing the path.
The operating system releases the advisory lock when the process exits; the empty file remains
for later operations and must not be removed while clients are running. No token is written there.

`cooperatingCliExclusive: true` means that this operation held this CLI lock. It is not native
keyring CAS. Older clients, direct SDK users, different coordination roots and external credential
editors are not coordinated; daemon snapshots retain their existing generation rechecks. Changing
user-directory environment variables between invocations creates different lock domains. macOS
uses the existing private-directory/file-lock pattern but runtime acceptance remains open.
Windows tests verify three competing CLI commands return busy and the same profile can be used
after timeout, failure and termination of an owned login test process. See the
[coordination record](../../docs/ledger/native-oauth-coordination-20260915.json).

### Daemon OAuth Enrollment

After login, explicitly review the same server ID, full resource URL, issuer, endpoints and public
client in `GTA_CLAW_MCP_TOOL_POLICY`. Replace `tokenEnv` or `tokenRef` with an `oauth` object inside
that HTTP server entry; these three credential modes are mutually exclusive:

```json
{
  "oauth": {
    "issuer": "https://auth.example.com/",
    "authorizationEndpoint": "https://auth.example.com/authorize",
    "tokenEndpoint": "https://auth.example.com/token",
    "clientId": "<same registered public client ID>",
    "credentialRef": "<credentialRef from the successful login>"
  }
}
```

This is a fragment of an independently reviewed server policy, not a ready-to-run configuration.
Retain its explicit resource `url`, HTTPS `httpProxy`, `reviewRevision` and reviewed tool/resource/
prompt descriptors. The complete OAuth authority must match the native record, including the full
resource path, not only its origin. Startup reads the native record without contacting the issuer
or opening an MCP session. It requires the SDK's local freshness check; no-expiry records retain
that existing local policy and are not proof of remote validity.

Each approved operation rechecks the complete credential generation before connection and after
discovery, including refresh token, scope, type, expiry and authority. Missing, pending, expired or
changed records revoke the server review through the existing durable path. The full generation
digest is part of publication identity even when the access token string did not change. Previews
show issuer/client and `automaticRefresh=false`, never token values or the full native record.
OAuth-backed tools, resources and prompts still require the ordinary exact approval and audit.

There is no automatic discovery-time/startup/call-time token refresh. Refresh or reauthorize explicitly
when needed, then review the new generation with a new `reviewRevision` and obtain a fresh approval;
the CLI does not restart or edit daemon policy for you. A local logout cannot retract already-sent
requests. Independent credential writers remain a non-atomic boundary. Windows local OAuth and
real-daemon approval tests pass, but real accounts, macOS, confidential clients and coordinated
refresh scheduling remain open. See the
[daemon OAuth record](../../docs/ledger/native-mcp-oauth-daemon-20260915.json).

### Stdio Secrets

For a reviewed Windows stdio backend, replace `--endpoint` with both
`--program-sha256 <lowercase-sha256>` and `--environment-name <variable>`. These modes are mutually
exclusive. All four credential commands support this target form; set/delete retain their explicit
confirmation flags and stdin-only secret intake. A stdio secret must be 16..2048 UTF-8 bytes.

```powershell
$programSha256 = (Get-FileHash -LiteralPath "D:\ReviewedTools\reports-mcp.exe" -Algorithm SHA256).Hash.ToLowerInvariant()
gta-claw-cli mcp credential reference --server reports-stdio --program-sha256 $programSha256 --environment-name API_TOKEN
$credential = [pscredential]::new("token", (Read-Host "MCP child token" -AsSecureString))
try {
  $credential.GetNetworkCredential().Password |
    gta-claw-cli mcp credential set --server reports-stdio --program-sha256 $programSha256 --environment-name API_TOKEN --token-stdin --confirm-write
} finally {
  Remove-Variable credential
}
```

Select and review the executable before using its digest; hashing an untrusted executable does
not approve it. This command neither verifies that a file exists at that digest nor starts a
process. The resulting reference is under `keyring://gta-claw.mcp-stdio/`, bound to server ID,
executable SHA-256 and the uppercase environment name. Changing the program or variable requires
a different entry. The full executable path, working directory, arguments, ordinary environment
and secret digests are separately bound by the daemon's reviewed publication and approval.

Use the returned reference as `stdio.environmentRefs.API_TOKEN` in the existing reviewed server
policy. Ordinary nonsecret values remain in `stdio.environment`; a name cannot occur in both,
including case-only differences. Together the two maps allow at most 16 variables and 8192 value
bytes. No inherited host environment is restored. The daemon checks keyring contents before
connection, again while preparing the pinned executable, and after discovery before the operation.
Missing or changed material revokes the review; a newly reviewed enrollment and fresh approval are
required. Neither configuration nor an unapproved request starts the child.

The child deliberately receives plaintext environment values after approval. It has the reviewed
host OS permissions and may read or disclose them; this feature is not a sandbox, a guarantee of
process-memory erasure, or a network restriction on the child. CLI output, policy JSON, approval
previews and fixture results never need the secret value. Native-keystore checks cannot atomically
coordinate with external credential writers or a process already running. Only the Windows
product launch path is supported; local reference generation does not imply other-platform stdio
acceptance.
See the [stdio credential record](../../docs/ledger/native-mcp-stdio-credentials-20260915.json).

## Native Business Commands

Native GTA-Claw commands use bounded Gateway transport, canonical endpoint checks and stdin-only
shared credential intake. Choose `--device-profile work` for an OS-protected persistent identity
on Windows/macOS, or explicitly choose `--ephemeral-device`. They are mutually exclusive.
Commands request only the scope each operation needs and never automatically replay a write.

```sh
gta-claw-cli gateway device --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway sessions --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway describe session-9 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli send session-9 "hello" --idempotency-key message-1 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway history session-9 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway history session-9 --limit 20 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway run "$RUN_ID" --wait-ms 1000 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway results session-9 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway abort session-9 --run-id "$RUN_ID" --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway ack-run "$RUN_ID" "$REVISION" --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway approvals session-9 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway approval approval-1 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway approve approval-1 --preview-fingerprint "$PREVIEW_FINGERPRINT" --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway deny approval-1 --preview-fingerprint "$PREVIEW_FINGERPRINT" --endpoint ws://127.0.0.1:18789 --device-profile work
```

Add `--token-stdin` when the Gateway requires a shared credential, using the secure-input examples
below. Never put a token or approval binding token in argv. `RUN_ID`, `REVISION` and
`PREVIEW_FINGERPRINT` represent values from the corresponding response. A fingerprint is not a
credential. These examples do not bypass device pairing: an administrator must approve the actual
device and requested scopes. Retry a rejected pairing request with the same profile and send key.
The profile is scoped to the complete canonical endpoint, including its port. Store failure never
falls back to an ephemeral identity. Guided onboarding remains incomplete.

Business success/failure results are separate schema-version-1 JSON, even without `--json`.
`gateway health --json` retains its schema-version-2 diagnostic contract. Argument-parse failures
still follow the shared parser's `--json`/human mode. A send succeeds when the server returns a
receipt, not when the model finishes. Current daemon receipts report `durable: true` after durable
admission. Reusing the same device/key/input returns the same run after restart; a different input
under that key is refused. Unfinished claimed work is recovered as unknown, never automatically
re-executed. Use `run`/`results` to reconcile; ACK only a complete terminal result at its exact
revision. ACK removes the notification, not retained result/dedupe history. `results --after`
accepts the previous page's cursor. Cross-object and external exactly-once execution is not claimed.

`gateway describe` reads the owned session's persisted state, turn, revision and update timestamp;
it does not include messages. Missing and other-device sessions are both unavailable. The native
daemon reads its redb state, not the standalone Gateway's independent session catalog. Derived
titles and last-message options are not supported by this native description.

History is the retained context checkpoint, not a complete archive. `history --limit` accepts
1 through 1000; this daemon caps the retained window at 256 and reports `windowLimit` plus
`requestedLimit`. Smaller limits return the latest entries in chronological order. Unsupported
history cursors and other unimplemented parameters are refused, not ignored. Approval list responses are
paged metadata; `gateway approval` reads one complete, structured-field-redacted preview.
`approve`/`deny` are once-only and require the fingerprint of the complete preview you reviewed.
The CLI re-fetches and checks identity, publication, resource, complete display and fingerprint on
the same connection epoch before resolving. Native output above
16 KiB returns `result_too_large` JSON with `delivery: response_received`, never a truncated preview.
Do not repeat a write merely because its response was too large or delivery is `unknown`.

These are native partial payload contracts, not a claim of full OpenClaw CLI compatibility.
Local `gateway forget-device --device-profile work --endpoint ...` removes only that profile;
revoke its remote device grant separately before discarding it when retiring a device.
See the [development record](../../docs/ledger/native-execution-20260914.md).

## Recorded Provider Usage

On this native daemon, `gateway run` includes `providerAccounting` for an owned terminal run.
The summary reports `recordedRounds`, complete/partial/unreported counter rounds, and checked
`observedTokens` for input, output, cached input and reasoning. `allPrimaryCountersReported`
means the recorded responses explicitly reported both primary token counters; an explicit zero
is different from an absent report. No per-round prompt, tool arguments or reasoning text is exposed.

A missing terminal turn falls back to its independent provider journal. `recordSource` identifies
`terminal_turn` or `provider_journal`; journal summaries also include `journalRevision` and
`journalClosed`. Only when both records are absent is `providerAccounting:null`. Empty legacy
records, unreported rounds and
aggregation overflow never imply complete known usage or free inference. `aggregationOverflow`
prevents publishing a fabricated token total. `costCalculated` and `billingReconciled` remain false:
these are observed counters, not prices, invoices or authorization to repeat a request.

The native runtime durably writes an intent before constructing each provider request and records
the first confirmed response before consuming its output. A journal write failure stops further
inference or tool execution; a terminal turn atomically seals the matching journal. Recorded
intents may never have been sent, reflected by `attemptsMayBeUnsent:true`. A lost response or crash
before the response commit still leaves unknown usage rather than known zero. Old terminal-only
records are not retroactively reconstructed, and this does not persist standalone HTTP streams.
Reading does not ACK, retry or clear an unknown outcome. See the
[journal record](../../docs/ledger/native-provider-journal-20260915.json) and the earlier
[accounting record](../../docs/ledger/native-provider-accounting-20260915.json).

For a response-by-response comparison, read the retained rounds using the current terminal run
revision from `gateway run`:

```powershell
gta-claw-cli gateway accounting-run $runId $revision --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway accounting-run $runId $revision --offset $nextOffset --sha256 $sha256 --endpoint ws://127.0.0.1:18789 --device-profile work
```

Each invocation requests only `operator.read` and returns at most 16 of the retained 1024 rounds.
The offset is a round index, not a byte offset. Use the returned `accounting.nextOffset` and
`accounting.sha256` for the next explicit read. A changed run revision, source, journal revision,
closure state or recorded response refuses continuation. The SHA-256 covers the UTF-8 JSON of
`{"summary":<summary>,"rounds":<all rounds>}` with the server's original field order. A complete
single page verifies this entire digest locally; an individual continuation only binds that digest
and cannot independently prove the entire snapshot. There is no automatic multi-page export yet.

Each reported response includes its actual provider/model/response identity, reporting coverage,
observed token counters and finish reason. `response:null` is an unconfirmed attempt, not a zero-cost
request. `accounting.available:false` means no retained accounting record; an available record with
zero rounds is separately represented. Pages contain no prompt, answer, reasoning or tool arguments.
An open recovered journal and `outcome_unknown` stay open/unknown. Reads never ACK results, repeat
provider calls, change budgets or reconcile invoices. Counters are not monetary cost, and cached/
reasoning counters are included subsets, not extra totals. See the
[round-page record](../../docs/ledger/native-accounting-pages-20260915.json).

The daemon's native OpenAI/Anthropic `GTA_CLAW_PROVIDER_POLICY` may optionally include
`"maxObservedTurnTokens":10000`. This is fixed at runtime startup and defaults to no threshold.
Before another model round, the runtime requires complete prior primary counters and checks their
sum against the threshold. Zero blocks the first model call. Reaching the threshold blocks further
inference; partial/missing prior usage or arithmetic overflow refuses another budgeted call.

This is an observed-usage stop threshold, not a prepaid reservation: one allowed request can itself
exceed it. Already approved tools are not undone, and a separate explicitly submitted turn has a
fresh allowance. Standalone HTTP generation, direct tools, rolling/global quotas and monetary
limits are outside this setting. Same-key re-submission still returns the original run without
inference. See the [threshold record](../../docs/ledger/native-observed-budget-20260915.json).

## Retained Partial Text

Read a terminal run with `gateway run` first, keeping its exact `revision`. The same device can
then inspect retained visible partial text without acknowledging or rerunning the operation:

```powershell
gta-claw-cli gateway partial-run $runId $revision --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway partial-run $runId $revision --offset $nextOffset --sha256 $sha256 --endpoint ws://127.0.0.1:18789 --device-profile work
```

Use the first page's `sha256` and each page's `nextOffset` for continuation. The native `agent.wait`
extension requires the original run owner and current terminal revision. Each page is at most
2048 UTF-8 bytes; a missing partial returns `available:false`, while empty retained text remains
available with zero bytes. No reasoning or tool arguments are exposed. Wrong revisions, digests,
non-character-boundary offsets and cross-device requests are refused.

The CLI checks the closed response schema, run/revision, bounded contiguous cursor and safety
flags before rendering; a complete single-page result also gets a full SHA256 check. Multi-page
responses pin the original whole-content digest, but one later page cannot independently verify
that full digest. `partial-run` returns one page per invocation.
Partial text is untrusted and incomplete. Reading does not ACK the result, clear `outcome_unknown`,
resume execution or authorize any tool. See the [partial-page record](../../docs/ledger/native-partial-pages-20260915.json).

To collect and verify all retained pages into a new local plaintext file:

```powershell
gta-claw-cli gateway export-partial $runId $revision --destination D:\Exports\run.partial.txt --endpoint ws://127.0.0.1:18789 --device-profile work
```

The parent directory must already exist. Export uses only `operator.read` on the same authenticated
connection epoch, with no reconnect or automatic retry. All pages must keep the original run,
revision, session, turn, status, length and SHA256. Limits are 4 MiB and 4096 pages, within the
command's normal total network timeout. No offset, wait or ACK option is accepted for this command.
An empty retained partial can produce an empty file; an absent partial is refused.

Only after the complete content digest passes does the CLI create the explicit absolute local
destination through the existing pinned-directory, no-link, create-new policy. Existing files are
never overwritten. Unix files are owner-only; Windows files inherit the trusted parent ACL. The
file is plaintext and contains only visible partial text, not reasoning, tool arguments or execution
authority. Stdout contains metadata and the digest, never the exported text or credential.

Network, page-identity and digest failures create no target. Local creation/write/synchronization
is not an atomic rename: a local I/O failure can leave an output file and reports `fileMayExist`;
inspect it rather than treating it as a completed export. The owned writer is awaited once started.
Reading/exporting never changes the source, acknowledges a run or permits replay. See the
[export record](../../docs/ledger/native-partial-export-20260915.json).

## Explicit Memory Commands

The native daemon must explicitly enable `GTA_CLAW_MEMORY_POLICY` with
`{"schemaVersion":1,"enabled":true}`. Memory commands require an OS-protected `--device-profile`
and an explicit `--idempotency-key`; an ephemeral identity would not address the same notebook on
the next invocation. The command requests exactly read/write scopes, first checks versioned native
capabilities through `health`, then submits one `chat.send` per explicit operation/page on the same connection epoch. An ordinary
OpenClaw server or disabled/unsupported memory capability receives no memory command.

The input is a native `!tool` envelope, handled directly by the runtime without consulting a model.
It cannot be combined with ordinary chat or other directives. The server still binds the verified
device, tool publication, arguments and resource, and requires the same human approval as a
model-authored memory call. A successful submission prints a durable run receipt, not permission to
skip approval or a claim that the operation has finished. Retain its run ID and the original key.

```powershell
gta-claw-cli gateway memory list notes --idempotency-key notes-list-1 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway memory get notes --note-id units --idempotency-key notes-get-1 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway memory search notes --query metric --limit 8 --idempotency-key notes-search-1 --endpoint ws://127.0.0.1:18789 --device-profile work
"Use metric units." | gta-claw-cli gateway memory save notes --note-id units --kind preference --expected-revision 0 --content-stdin --idempotency-key notes-save-1 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway memory delete notes --note-id units --expected-revision 1 --idempotency-key notes-delete-1 --endpoint ws://127.0.0.1:18789 --device-profile work
```

These are separate examples, not a batch to run without inspecting revisions. Read the notebook
revision from an approved `list` result before save/delete/import. `get --offset` needs that note's
revision; `list --after` needs the notebook revision. Single-operation commands return receipts; the
encrypted file export described below instead waits for verified pages and file completion. An appropriately
authorized approver uses `gateway approvals`, `gateway approval` and `gateway approve/deny` with
the complete preview fingerprint; pairing read/write scopes alone does not grant approval scope.
Query the outcome using `gateway run`, then ACK only the complete observed run result. The note
revision is not the run-result revision. Known tool rejection becomes a retained failed run;
uncertain effects remain `outcome_unknown`, not an automatic retry.

### Content and Shared Tokens

`--content-stdin` reads at most 8192 UTF-8 bytes, preserving line endings. It cannot share stdin with
`--token-stdin`. For save/import against a Gateway that needs a shared token, choose the exclusive
`--request-stdin` mode instead. Its JSON contains `token` plus `content` for save or `archive` for
import. It is capped at 64 KiB before parsing; content, credential and final 16 KiB tool-command
limits still apply. Duplicate/unknown fields, malformed tokens or both data forms are refused
before connection. Raw input and decoded token buffers are zeroized; only the token goes into the
handshake, never the tool arguments or diagnostics.

```powershell
$secret = Read-Host "Gateway token" -AsSecureString
$credential = [pscredential]::new("token", $secret)
@{ token = $credential.GetNetworkCredential().Password; content = "Use metric units." } |
  ConvertTo-Json -Compress |
  gta-claw-cli gateway memory save notes --note-id units --kind preference --expected-revision 0 --request-stdin --idempotency-key notes-save-1 --endpoint ws://127.0.0.1:18789 --device-profile work
Remove-Variable credential, secret
```

Never put a real token in a script literal, argv or a saved JSON file. Configure the shell's pipeline
for UTF-8 when sending non-ASCII notes, especially under Windows PowerShell 5.1. For list/get/search/
delete/export, a separate `--token-stdin` remains available because those commands do not read data
from stdin. Normal note content may itself be sensitive; reviewing/exporting it is an intentional
disclosure to that authorized client, not automatic secret classification.

### Portable Note Archives

```powershell
gta-claw-cli gateway memory export notes --revision 3 --idempotency-key notes-export-0 --endpoint ws://127.0.0.1:18789 --device-profile work
gta-claw-cli gateway memory export notes --revision 3 --offset 2048 --idempotency-key notes-export-next --endpoint ws://127.0.0.1:18789 --device-profile work
```

Use the actual `nextOffset`, not a hardcoded increment: UTF-8 boundaries can shorten a chunk. Each
approved result contains at most 2048 bytes of archive `data`, fixed `notebookRevision`, full archive
`sha256`, `totalBytes`, `offset` and `nextOffset`. Concatenate decoded `data` strings in byte-offset
order, require identical revision/digest/total size, and verify the complete UTF-8 bytes before import.
Without a destination option, the CLI submits/queries one page. The encrypted file mode below
collects approved pages automatically. The underlying export is plaintext, bounded to 4 MiB,
and includes note data/source labels only:

```json
{"schemaVersion":1,"notebook":{"revision":1,"entries":[{"id":"units","kind":"preference","content":"Use metric units.","sourceSession":"notes","revision":1}]}}
```

An inspected archive can be piped to `gateway memory import notes --archive-stdin
--expected-revision <current-notebook-revision> --idempotency-key <unique-key>` with the same
endpoint/profile options. Use `--request-stdin` with `token` and `archive` for shared-token servers.
The whole encoded tool envelope must fit 16 KiB; oversized imports are refused before sending, not
truncated or silently split. Larger database backups use the separate offline encrypted snapshot
workflow below; that is not an online per-notebook import.

Import is one atomic merge. Existing IDs are refused unless `--overwrite` is explicitly provided and
reviewed; notes absent from the archive are retained. Every imported note gets one new destination
notebook revision. The archive grants no identity, owner status, tool permission or executable skill.
Its source session is an untrusted provenance label, not proof of a transcript. Importing a prior
archive intentionally can reintroduce deleted notes; deletion does not wipe old run/chat results,
model disclosures, database free pages or backups. Never automatically re-import after deletion.

The state store allows at most 256 newly allocated persistent notebooks across all authenticated
sources/subjects/accounts in one database. Empty notebooks retain their revision and still count.
The limit is checked inside the same redb write transaction as first save/import, so concurrent
identities cannot take the same last slot. At capacity, existing notebooks remain readable/editable;
new notebook writes fail without setting a storage-recovery fault. Old or restored databases already
over the limit are not truncated; further allocations are refused. This is a logical notebook quota,
not a total database-file/disk quota, and no automatic identity retirement is performed.

Memory writes also recheck execution authority after waiting for the database writer, immediately
before record mutation. Cancellation after that check may still race an in-progress commit and
requires the existing outcome-unknown reconciliation; this is not a promise to roll back committed effects.

See the [memory-client development record](../../docs/ledger/native-memory-client-20260914.json).

### Encrypted Memory Files

`gateway memory export` accepts `--destination <new-local-absolute-file>` plus
`--passphrase-stdin`. It starts at offset zero, so a manual `--offset` is refused. For a shared-token
Gateway, use `--request-stdin` instead: its closed JSON contains exactly `token` and `passphrase`.
These modes cannot share stdin with `--token-stdin`, content/archive stdin or each other. Secrets
never enter tool arguments, argv, stdout or diagnostic messages.

```powershell
$token = [pscredential]::new("token", (Read-Host "Gateway token" -AsSecureString))
$archive = [pscredential]::new("archive", (Read-Host "Archive passphrase" -AsSecureString))
@{ token = $token.GetNetworkCredential().Password; passphrase = $archive.GetNetworkCredential().Password } |
  ConvertTo-Json -Compress |
  gta-claw-cli gateway memory export notes --revision 3 --destination "D:\PrivateBackups\notes.age" --request-stdin --idempotency-key notes-file-3 --timeout-ms 120000 --endpoint ws://127.0.0.1:18789 --device-profile work

@{ token = $token.GetNetworkCredential().Password; passphrase = $archive.GetNetworkCredential().Password } |
  ConvertTo-Json -Compress |
  gta-claw-cli gateway memory import notes --archive-file "D:\PrivateBackups\notes.age" --expected-revision 3 --overwrite --request-stdin --idempotency-key notes-import-3 --endpoint ws://127.0.0.1:18789 --device-profile work
Remove-Variable token, archive
```

These are examples, not permission to migrate user data or overwrite notes. Inspect the current
notebook revision and select overwrite deliberately. Create/protect the parent directory first;
existing output files, unsafe links and nonlocal paths are refused. The encrypted format is the
existing Rust age-scrypt implementation at work factor 18. Retain the passphrase separately; the
tool cannot recover it. Raw passphrase stdin allows one trailing line ending, whereas the JSON
passphrase must have no control characters. Its UTF-8 length is 16..1024 bytes; this is a resource
and syntax rule, not a guarantee of password strength.

Every page still requires normal human approval. Keep an authorized approval client open for the
session. The exporter waits for durable results using the Gateway event stream, rechecks capability
before later pages, and requires the exact session/run, fixed notebook revision, continuous UTF-8
byte cursor, identical full digest/length and valid final archive. There are at most 4096 pages and
4 MiB of decoded archive. Later page keys derive deterministically from the original key, session,
revision and offset; no page is automatically resubmitted. On failure retain `originalIdempotencyKey`
and `lastPage` metadata before explicitly restarting with the same original key.

No target is created until all pages, the full SHA-256 and the complete archive schema pass. The
verified bytes are then encrypted through a pinned parent and exclusively created file, finalized
and synchronized. File errors retain any partial output and never overwrite it on a retry. Success
prints content-free archive bytes/digest/page count and `fileCreated: true`; it does not automatically
ACK or delete the server's retained run results (`runResultsAcknowledged: false`).

`gateway memory import --archive-file` authenticates/decrypts the complete bounded file before
loading a device profile or connecting. Wrong passphrase, corrupt/oversized ciphertext, invalid
archive or oversized final command fails before submission; the source is never modified and no
plaintext temporary file is created. Import still uses one approved CAS merge, with a 16 KiB tool
envelope. Larger exported archives need a future staged-import workflow, not silent splitting.

The existing `--timeout-ms` bounds secret intake, networking and page collection. Local file/KDF
workers are always joined, including when cancellation occurs; the timeout is not a hard filesystem
or process-exit deadline. Parent-directory crash durability, cross-platform interactive acceptance,
automatic run-result cleanup and full history/backup erasure remain unverified. See the
[memory-file record](../../docs/ledger/native-memory-files-20260914.json).

## Read-only OpenClaw Preview

```powershell
gta-claw-cli migrate openclaw preview --source "D:\OpenClaw-snapshot"
gta-claw-cli migrate openclaw preview --source "D:\OpenClaw-snapshot" --after "$CURSOR" --fingerprint "$FINGERPRINT"
```

Use an explicitly selected local absolute root. The command does not make the snapshot consistent:
`snapshotVerified`, `migrationReady` and `resumeExecution` are always false. JSON output is at most
16 KiB, with eight inventory entries per page. Continue with the returned cursor and fingerprint;
changed inspected content or inventory rejects continuation instead of mixing pages.

Only bounded recognized configuration, session-index and JSONL containers are read. Config values,
chat text and credential contents are not returned. Includes and external workspaces are reported,
not followed. SQLite/WAL/SHM needs a separate verified snapshot/reader and is not imported.
Parsing limits nested values to 64 levels and 16,384 nodes per document/JSONL record before
constructing deeper values. Duplicate fields and NaN/Infinity are refused for manual mapping.
Unknown/excluded contents are not hashed: `inspected_content_and_inventory_metadata` is not a full
snapshot proof. Relative paths are visible metadata and may themselves contain sensitive names.
No `--apply`, source writes, credential copying or task resumption is supported by this command.
See [current implementation evidence](../../docs/ledger/native-followup-20260914.md).

## Encrypted Native State Snapshots

`state snapshot export/restore` operates on the native redb state file, not OpenClaw SQLite.
Stop the owning daemon before using this offline command. It refuses a locked source and never
creates an absent source database. Existing target files are always refused, with no overwrite flag.
Both paths must be explicit local absolute files; network/device paths and hard-linked sources
are refused by the current Windows implementation.

```powershell
$secret = Read-Host "Snapshot passphrase" -AsSecureString
$credential = [pscredential]::new("snapshot", $secret)
$credential.GetNetworkCredential().Password | gta-claw-cli state snapshot export `
  --source "D:\ClawState\runtime.redb" --destination "D:\PrivateBackups\runtime.age" --passphrase-stdin
$credential.GetNetworkCredential().Password | gta-claw-cli state snapshot restore `
  --source "D:\PrivateBackups\runtime.age" --destination "D:\RestoreReview\runtime.redb" --passphrase-stdin
Remove-Variable credential, secret
```

This is a command example, not permission to stop a live service or migrate user state. The caller
must create and protect the destination directories first. Use a long randomly generated passphrase
and retain it separately; the tool cannot recover forgotten passphrases. It reads a single UTF-8
line from stdin (at least 16 bytes, at most 1024, no control characters), never from argv or environment.
No secret or record content is printed. Input must reach EOF within 30 seconds.

Backups use the established Rust `age` 0.12.1 format with scrypt work factor 18. Decryption refuses
higher work factors to bound hostile input resource use. Data is encrypted as it streams from one
redb read transaction; no plaintext temporary backup is written. The plaintext snapshot has explicit
schema, ordered unique records, count and SHA-256, with 256 MiB / 262,144-record limits.

Restore authenticates the encrypted stream and validates the snapshot in one write transaction
against a freshly created database. Wrong passphrases fail before creating that database; malformed,
truncated or tampered data never publishes partial records. Failure may leave an incomplete encrypted
file or empty/uncertain isolated database: inspect it and choose a new target, never automatically
retry over it. A success JSON receipt reports record count and snapshot digest, not content.

**The restored database is plaintext** and inherits the trusted parent directory's Windows ACL;
new Unix files are mode 0600. This is not a full ACL/physical-power-loss or at-rest encryption claim.
Source opening may run normal redb recovery and update its journal, so it is not forensic read-only.
Only the state database is included: goals, files, attachments, credentials, pairing, configuration
and other external stores require separate coordinated backups. Runtime/domain compatibility is
not certified by restoring the generic database. No service is activated and no work is resumed.

## Gateway Health Diagnostic

`gta-claw-cli gateway health` is a bounded diagnostic vertical slice. It opens
one real `ws://` or `wss://` connection through `claw-gateway-client`, completes
the authenticated Gateway v4 challenge/connect/hello flow, sends one
`operator.read` `health` RPC, and performs a bounded clean shutdown.

```sh
restore_tty() { stty echo; }
trap 'restore_tty' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 131' 3
trap 'exit 143' 15
stty -echo
IFS= read -r GTA_CLAW_TOKEN
stty echo
trap - 0 1 2 3 15
gta-claw-cli gateway health \
  --endpoint wss://gateway.example.test \
  --ephemeral-device \
  --token-stdin \
  --json <<EOF
$GTA_CLAW_TOKEN
EOF
unset GTA_CLAW_TOKEN
```

This POSIX `sh` sequence disables terminal echo, restores it on normal exit or
signals, and uses shell-managed standard input without putting the token in an
external process argv. It works with `dash`, other POSIX shells, and the default
macOS shell. PowerShell can likewise prompt securely and write only to the CLI
standard input:

```powershell
$secret = Read-Host "Gateway token" -AsSecureString
$credential = [pscredential]::new("token", $secret)
$credential.GetNetworkCredential().Password | gta-claw-cli gateway health `
  --endpoint wss://gateway.example.test `
  --ephemeral-device `
  --token-stdin
Remove-Variable credential, secret
```

The shared token is optional. `--token-stdin` reads at most 4096 bytes from
standard input. `--token-file` is reserved but fails closed on every platform:
this slice does not claim it can prove Unix ownership/link safety and Windows
owner/DACL/FileId safety across every supported filesystem.

The token must be valid UTF-8 and one non-empty line without whitespace; one
trailing LF or CRLF is removed. No token or private key option is accepted on
the command line, and environment variables are never consulted implicitly.
Endpoint credentials, query strings, and fragments are rejected and never
rendered. Non-loopback plaintext `ws://` remains rejected unless
`--allow-insecure-remote-ws` is explicitly supplied; `wss://` uses the client's
rustls transport. Endpoint spelling rejects whitespace, invisible format/bidi
characters, non-canonical ASCII host casing, credentials, query strings, and
fragments before reading standard input. Host text is ASCII-only; international
domains must use their lowercase canonical A-label (punycode) form. Ports use
unpadded decimal values greater than zero, IPv6 uses compressed bracket form,
and paths must contain no dot-segment or percent-normalization ambiguity.

`--ephemeral-device` is mandatory. It generates a one-shot in-memory P03c
Ed25519 identity and never persists the key or any device token returned by the
Gateway. The connection may create a pairing/device entry on the Gateway.
This diagnostic deliberately remains ephemeral-only; persistent profiles apply to business commands.

| Exit | Category | Meaning |
| ---: | --- | --- |
| 0 | success | Authenticated health RPC returned a positive typed result |
| 2 | usage/config | Invalid arguments, endpoint, or secret input |
| 3 | transport/transient | Connection or transient transport failure |
| 4 | authentication/pairing | Authentication rejected or pairing required |
| 5 | protocol | Version, framing, or typed payload validation failed |
| 6 | health-negative | Health response or health payload was negative |
| 7 | timeout/cancel | Command timed out, was interrupted, or could not shut down in time |
| 8 | internal | Local runtime/client state failure or an output safety limit |

`gta-claw-cli --help` prints the same table together with every flag, its
default, and one complete example. Human-readable failures name the endpoint
that was tried and the next action to take; `--json` output is unaffected.

`--json` schema version 2 emits one deterministic object containing only the sanitized
endpoint origin, negotiated protocol, role, sorted unique effective scopes,
typed health booleans/timestamps, elapsed time, status category, and the
non-secret identity mode. Peer-controlled server version text is never emitted;
the version is `null` with `version_status: "redacted_peer_value"`. Human output
uses the same explicit redaction. Command timeout and Ctrl-C also use bounded
runtime teardown so an uncancellable platform resolver or stdin worker cannot
keep the process alive indefinitely. Process output is capped at 16 KiB and a
blocked output stream is abandoned after 250 ms; either safety limit exits `8`.
If timeout or Ctrl-C wins, a clean shutdown gets one independent 250 ms grace
window without replacing the timeout/cancel result.

This command implements diagnostic health only. It is not a full OpenClaw CLI,
admin/chat/provider surface, durable keyring identity, GUI, Gateway server, or
feature-ledger status claim. Local `health`, `--version` and the native business commands above
remain separate from this diagnostic contract.

`-v`/`--verbose` and `-vv` add opt-in diagnostics for the connection path
itself: endpoint resolution, credential source, identity generation, client
start, the negotiated protocol, the granted role and scopes, the health RPC
round trip, and shutdown. `-vv` adds the connection epoch, the negotiated
payload bound, and per-request correlation identifiers. Every record is a
`tracing` event written as a JSON line on standard error by the shared
`claw-observability` subscriber, so standard output — including the `--json`
schema-version-2 object — is byte for byte what a quiet run produces, and a
machine consumer reading standard output sees no difference. Field values are
redacted by `claw-observability` whenever the field name names a secret, and
peer text is stripped of control and bidirectional characters and bounded before
it is written; nothing is ever formatted into a message, because message text
does not pass through the redaction layer. Neither flag ever prints the token,
and neither changes an exit code. `GTA_CLAW_LOG` overrides the filter, which
otherwise scopes to this binary so a dependency's `log` records cannot land on
the same stream.

`--log-file <path>` sends those records to a file instead of standard error,
which is useful when standard error is already carrying something else. The file
is appended to, so a run adds to it rather than replacing it, and its directory
must already exist — the CLI never creates one. If the file cannot be opened the
command stops with the `log_file_unusable` status in the `usage_config` category
(exit code 2) instead of quietly logging to standard error, because a diagnostic
that silently went somewhere other than where it was asked to go is worse than
no diagnostic at all. Without the flag the destination is unchanged: standard
error.
