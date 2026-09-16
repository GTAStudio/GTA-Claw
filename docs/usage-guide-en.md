# GTA-Claw usage guide

This guide covers the Rust binaries in this repository: `gta-claw-cli`, `gta-claw-tui`,
`gta-claw-daemon`, `gta-claw-updater` and the native desktop shell `gta-claw-desktop`.

Everything documented here was read from the source. Where a capability does not exist yet, this
guide says so instead of describing it.

中文版本：[docs/usage-guide-zh.md](usage-guide-zh.md)

---

## Table of contents

- [0. What you can actually do today](#0-what-you-can-actually-do-today)
- [1. Prerequisites](#1-prerequisites)
- [2. Building from source](#2-building-from-source)
- [3. `gta-claw-cli`](#3-gta-claw-cli)
- [4. `gta-claw-tui`](#4-gta-claw-tui)
- [5. `gta-claw-daemon`](#5-gta-claw-daemon)
- [6. `gta-claw-desktop`](#6-gta-claw-desktop)
- [7. `gta-claw-updater`](#7-gta-claw-updater)
- [8. Configuration](#8-configuration)
- [9. Troubleshooting](#9-troubleshooting)
- [10. Not available yet](#10-not-available-yet)

---

## 0. What you can actually do today

Read this first; it will save you time.

The Rust workspace does **not** yet ship a parity-complete agent service, but `gta-claw-daemon` is a
real partial production composition. What works today is:

- **Connecting to an existing OpenClaw Gateway** — with the CLI as a bounded diagnostic, with the
  TUI as an interactive client, and with the desktop shell as a native connection surface.
- **Serving the Rust daemon's usable transports**: the 17-route main HTTP API, the legacy HTTP
  facade and Gateway, with a configured GitHub Copilot provider or the explicit smoke provider. The
  daemon also binds a loopback MCP listener, but current production wiring cannot authenticate any
  MCP caller.
- **Running configured Teams, Telegram, Discord and WhatsApp paths**, plus signal handling,
  configuration reload and a provable shutdown drain.
- **Applying a signed update** with the standalone updater.

The CLI now has native send/history/abort/approval commands, and the daemon persists session/turn
state and context checkpoints in redb. Full recovery, caller binding, `claw-tools` and skill
execution are still incomplete. The legacy Node service in `src/` remains while those gaps and the
frozen compatibility-evidence obligations are closed; see
[legacy-node-port-obligations.md](legacy-node-port-obligations.md).

---

## 1. Prerequisites

| Requirement | Detail |
|---|---|
| Rust toolchain | Development pin `1.98.1`; declared MSRV stays `1.94.0`, not freshly verified for this increment. Protected packaging policy still pins `1.97.1` and requires a reviewed upgrade before release. |
| Platforms | The root workspace builds on Linux, macOS and Windows. The desktop shell builds on **Windows and macOS only** — a Linux desktop build is rejected on purpose. |
| A Gateway | The CLI, TUI and desktop shell are clients. You need a reachable OpenClaw Gateway v4 endpoint (`ws://` or `wss://`) for them to do anything interesting. |

No Node.js, npm or any JavaScript runtime is required, and none may be introduced — repository
policy rejects it as a test failure.

---

## 2. Building from source

```sh
git clone https://github.com/GTAStudio/GTA-Claw.git
cd GTA-Claw

# Root workspace: 32 library crates and 6 application members
cargo build --workspace
cargo test  --workspace
```

Release binaries land in `target/release/` after:

```sh
cargo build --workspace --release
```

Build a single binary if you only need one:

```sh
cargo build -p gta-claw-cli --release
cargo build -p gta-claw-tui --release
cargo build -p gta-claw-daemon --release
```

The desktop shell lives in a **separate workspace** and needs its own manifest path:

```sh
cargo build --manifest-path desktop/Cargo.toml --workspace --release
cargo test  --manifest-path desktop/Cargo.toml --workspace
```

Running that on Linux is expected to fail; the desktop workspace refuses the target deliberately.

To run the checks CI runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test -p claw-repo-policy        # the JavaScript/TypeScript ratchet
```

---

## 3. `gta-claw-cli`

The headless command-line adapter. Its complete argument surface:

```text
usage:
  gta-claw-cli --version
  gta-claw-cli health
  gta-claw-cli send <session-id> <message>
  gta-claw-cli gateway health --endpoint <ws-or-wss-url> --ephemeral-device
      [--token-stdin] [--timeout-ms <250..120000>]
      [--allow-insecure-remote-ws] [--json]
```

`--help` and `-h` print the current usage text, including native business commands.

### 3.1 `health` — local runtime health

```sh
gta-claw-cli health
```

Prints a single line beginning with `healthy runtime=`, describing the local OS and architecture.
It contacts nothing. Exit code `0`.

An unknown command exits `2` with `error: unknown command` on standard error.

### 3.2 Native Gateway Commands

```sh
gta-claw-cli send session-9 "hello" --idempotency-key message-1 --endpoint ws://127.0.0.1:18789 --ephemeral-device
```

Use `--token-stdin` when required; shared credentials never bypass device pairing. Native commands
also include `gateway sessions`, `history`, `abort`, `approvals`, `approval`, `approve` and `deny`.
They request exact minimum scopes and return separate schema-v1 JSON. Send returns an admission
receipt, not a completed answer; current daemon acceptance/dedupe is process-local and explicitly
not durable. Persistent CLI identity and manual-pairing onboarding remain unfinished. See the
[CLI guide](../apps/gta-claw-cli/README.md) for syntax, credential intake and output limits.

### 3.3 `gateway health` — the real Gateway diagnostic

This diagnostic opens one `ws://` or `wss://`
connection, completes the authenticated Gateway v4 challenge/connect/hello flow, sends one
`operator.read` `health` RPC, and shuts down cleanly within bounds.

```sh
gta-claw-cli gateway health \
  --endpoint wss://gateway.example.test \
  --ephemeral-device
```

`--ephemeral-device` is **mandatory**. It generates a one-shot in-memory Ed25519 identity that is
never persisted, along with any device token the Gateway returns. The connection may still create a
pairing or device entry on the Gateway side. Durable secure-storage identity on Windows and macOS
is deferred.

#### Passing a token safely

The shared token is optional. When you need one, `--token-stdin` reads at most 4096 bytes from
standard input. **No token option is accepted on the command line, and environment variables are
never consulted implicitly.**

POSIX shell — disables terminal echo and restores it on exit or signal:

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

PowerShell:

```powershell
$secret = Read-Host "Gateway token" -AsSecureString
$credential = [pscredential]::new("token", $secret)
$credential.GetNetworkCredential().Password | gta-claw-cli gateway health `
  --endpoint wss://gateway.example.test `
  --ephemeral-device `
  --token-stdin
Remove-Variable credential, secret
```

The token must be valid UTF-8 and exactly one non-empty line with no whitespace; a single trailing
LF or CRLF is stripped.

`--token-file` is parsed but **always fails closed on every platform**. This slice does not claim it
can prove Unix ownership and link safety plus Windows owner/DACL/FileId safety across every
supported filesystem, so it refuses rather than pretending.

#### Endpoint rules

The endpoint is validated before standard input is read. It rejects:

- whitespace and invisible format or bidirectional characters,
- embedded credentials, query strings and fragments,
- non-canonical ASCII host casing,
- non-ASCII host text — international domains must use their lowercase punycode A-label,
- padded or zero port numbers; ports are unpadded decimal greater than zero,
- non-compressed or unbracketed IPv6 forms,
- paths with dot-segment or percent-normalization ambiguity.

Non-loopback plaintext `ws://` is rejected unless you pass `--allow-insecure-remote-ws`. `wss://`
uses the client's rustls transport.

#### Other options

| Option | Effect |
|---|---|
| `--timeout-ms <250..120000>` | Overall command deadline. Defaults to 10 000 ms. Values outside the range are a usage error. |
| `--allow-insecure-remote-ws` | Permits plaintext `ws://` to a non-loopback host. |
| `--json` | Emits one deterministic JSON object instead of human text. |

Each option may appear at most once; a repeated or unknown option is a usage error.

#### Output

Human output on success:

```text
Gateway health: healthy
endpoint: wss://gateway.example.test
protocol: 4
role: operator
scopes: operator.read
server_version: [redacted peer value]
server_version_status: redacted_peer_value
health_ok: true
health_timestamp_ms: 1753000000000
health_duration_ms: 3
elapsed_ms: 128
identity: ephemeral (may create a pairing/device entry; not persisted)
```

The server's version string is peer-controlled text and is **never** printed. `--json` emits schema
version 2 with the same redaction: `schema_version`, `command`, `status`, `category`, `message`,
`endpoint`, `protocol`, `role`, sorted unique `scopes`, `server`, `health`, `elapsed_ms`,
`identity` and `pairing_entry_possible`.

On failure, human output goes to standard error as
`Gateway health failed: <message> (<category>)`.

#### Exit codes

| Exit | Category | Meaning |
| ---: | --- | --- |
| 0 | success | Authenticated health RPC returned a positive typed result |
| 2 | usage/config | Invalid arguments, endpoint, or secret input |
| 3 | transport/transient | Connection or transient transport failure |
| 4 | authentication/pairing | Authentication rejected or pairing required |
| 5 | protocol | Version, framing, or typed payload validation failed |
| 6 | health-negative | Health response or health payload was negative |
| 7 | timeout/cancel | Command timed out, was interrupted, or could not shut down in time |
| 8 | internal | Local runtime/client state failure |

Ctrl-C and the timeout both use bounded teardown, so a stuck platform resolver or stdin worker
cannot keep the process alive indefinitely.

#### What this command is not

It is a diagnostic. It is not a full CLI, an admin or chat surface, a provider surface, a durable
keyring identity, a GUI, a Gateway server, or a claim about feature-ledger status.

---

## 4. `gta-claw-tui`

The terminal client. It connects to a Gateway through the same client crate as the CLI.

```text
Usage: gta-claw-tui [--gateway ws://HOST:PORT] [--no-color] [--plain]
Set GTA_CLAW_GATEWAY_TOKEN for authenticated Gateways.
```

`--help` and `-h` print that text and exit `0`. An unknown argument exits `2`.

For the native daemon, `--device-profile work` explicitly retains the same device identity in
Windows/macOS protected storage. It never stores the shared token or falls back silently to an
ephemeral identity. Without the option, identity is temporary and changes on connection recreation.
Pair the requested device/scopes with an administrator; persisted identity is not automatic trust.

### 4.1 Launching

```sh
# Default endpoint: ws://127.0.0.1:18789
gta-claw-tui

# Explicit endpoint
gta-claw-tui --gateway wss://gateway.example.test

# Authenticated
GTA_CLAW_GATEWAY_TOKEN='…' gta-claw-tui --gateway wss://gateway.example.test
```

| Variable | Effect |
|---|---|
| `GTA_CLAW_GATEWAY_URL` | Default endpoint. `--gateway` overrides it. |
| `GTA_CLAW_GATEWAY_TOKEN` | Shared Gateway token. There is no token flag. |
| `NO_COLOR` | Monochrome rendering, same as `--no-color`. |
| `TERM=dumb` | Treated as non-interactive. |

### 4.2 Screens

| Screen | Contents |
|---|---|
| Sessions | Session navigation. |
| Workspace | The selected session's transcript and tools. |
| Runs | Cross-session run state. |
| Diff | Workspace diff viewer. |
| Artifacts | Session artifact viewer. |
| Help | The keyboard reference. |
| Models | Cached native provider descriptors and explicit catalogue refresh. |

### 4.3 Keys

```text
Tab / Shift-Tab   cycle screens
Up/Down or j/k    select and scroll
Enter             open session / submit answer
c / i             new session / compose message
Shift-Enter       newline while composing
x                 cancel the exact observed native run
y / n             approve / deny
r                 refresh from Gateway
Ctrl-P or :       command palette
1..7              jump to a screen
Esc               close palette
?                 keyboard help
q / Ctrl-C        quit safely
```

### 4.4 Command palette

Press `:` or `Ctrl-P`, type a command, press Enter. Recognized commands, case-insensitive:

`sessions`, `workspace`, `runs`, `diff`, `artifacts`, `help`, `refresh`, `quit` (or `q`),
`new`, `message`, `send`, `run`, `partial`, `partial-next`, `accounting`, `accounting-next`,
`cancel`, `retry-send`, `models`, `models-next`, `refresh-models`, `config-provider <JSON>`.

`discard-draft` explicitly clears unsubmitted input. `discard-send` clears a retained submission
only when every attempt is known not to have been sent; queued or possibly delivered input cannot
be discarded through that command. The memory actions below preserve their structured type on retry.

The independent Models view shows the current connection's cached provider directory, selected
model and instance generation, observation time, optional limits and SDK-advertised capabilities.
`models` (also `r` in that view) reads cached data; `models-next` pins the original digest for the
next eight-entry page. `refresh-models` explicitly fetches the provider directory without selecting
a model or invoking inference. Only one catalogue operation is queued at a time. Failure preserves
the last valid page; successful refresh invalidates it until a fresh `models` read. Connection or
request sequence changes reject stale results. These pages never enter chat history or create ACK
eligibility. Live capabilities and full online configuration application remain unverified.
See the [TUI follow-up](ledger/native-model-catalogue-20260916.json).

For a local model candidate, use the `config-provider` command followed by one strict JSON object:

```text
config-provider {"action":"inspect","source":"D:/Configs/claw.json5"}
config-provider {"action":"prepare","source":"D:/Configs/claw.json5","destination":"D:/Configs/claw.model.json5","model":"exact-model-id"}
```

Source inspection is local and can run without a ready Gateway. Preparation requires a current
validated Models page, no in-flight catalogue request, the same inspected source path and an exact
model ID present on that page. Saved provider and current model must match the catalogue; Copilot
configuration `copilot` correctly maps to SDK identity `github-copilot`. A match does not prove this
local file belongs to the remote Gateway. The source hash is rechecked and the candidate is created
without overwrite, synchronized and read back. The source, credentials and online model are not
changed; use the [offline CLI workflow](../apps/gta-claw-cli/README.md#offline-application-and-recovery)
for separately reviewed application. No live readiness or credential validation is inferred.

The JSON is bounded to 16 KiB, paths to 4096 bytes and model IDs to 256 bytes. Spaces in paths stay
data; use JSON escaping or forward slashes. Duplicate/unknown fields, unsupported actions, relative
paths, missing/current models and mixed provider selections are refused. Paste is supported in the
palette; ordinary palette commands retain their smaller bound. Only one local file task is in
flight. Gateway reconnect does not discard its handle or result, and normal exit waits for a started
task before returning. Local results appear in the Models view without entering chat history or ACK
queues. A file I/O error or process interruption may leave a candidate; never overwrite or delete it
as an automatic retry. This is not a crash-durable client journal or a filesystem I/O deadline.

Native sends retain a random idempotency key until a durable receipt is received. Unknown delivery
blocks another send; `retry-send` explicitly reuses the original session/text/key. Reconnection
never automatically resends an old effectful command. Selecting a native session loads retained
history and paged pending/active runs. Complete results are acknowledged at their exact revision
after the workspace render pass. Outcome unknown is distinct from ordinary failure and must be
reconciled before repeating effects. Diff/artifact availability still depends on the server.

For a selected native terminal run, `partial` reads the first retained visible-text page and
`partial-next` explicitly reads its continuation. Use `run` first when the terminal revision has not
been observed. Each page is at most 2048 UTF-8 bytes from a retained result of at most 4 MiB. Requests
are tied to the observed connection, session, run, turn, revision and terminal state; continuations
also pin the original length and digest. Changing the selection or revision invalidates the cursor.

Partial text is shown as unconfirmed data with its original byte range, never as a complete
assistant answer. Viewing a page does not create an ACK or permit execution/replay; the established
post-render ACK policy for complete terminal receipts is unchanged. Control text is sanitized for
display after validating the original bytes. Empty retained text is valid; missing text is refused.
A whole single-page result has its SHA256 checked. Later pages pin the whole-content digest but do
not independently verify it, and the transcript remains a bounded view, not a complete archive.
Use [CLI export-partial](../apps/gta-claw-cli/README.md#retained-partial-text) to collect and verify
the entire retained text. See the [TUI record](ledger/native-tui-partial-20260915.json).

`accounting` reads the first provider-round page for the selected observed terminal run;
`accounting-next` reads its explicit continuation. Pages show at most 16 of 1024 retained rounds,
including provider/model/response identifiers, primary-counter coverage, included cached/reasoning
subsets and finish reason. Missing reports stay unknown; explicitly complete zeroes remain zero.
Connection, session, run, turn, revision, terminal state, count, digest and summary provenance are
pinned. A changed connection or run clears the cursor, and stale responses cannot update the view.
Viewing usage never adds a result ACK or permits replay. A complete single page verifies its full
digest, while a later page only pins the snapshot. Use
[CLI export-accounting](../apps/gta-claw-cli/README.md) for a complete, independently verified
plaintext JSON export. Cost remains uncalculated and billing unreconciled.

Anything else reports `Unknown command: …` in the notice line. `Esc` closes the palette.

### 4.5 Non-interactive mode

`--plain`, or any run where standard output is not an interactive terminal, takes a single snapshot
instead of entering the full-screen loop: the TUI connects, waits up to five seconds for the session
list, prints one rendered frame and exits. If the Gateway does not answer in time it prints
`Gateway snapshot timed out` in the notice line. This is the mode to use in scripts and CI.

### 4.6 Explicit Memory

Start with `gta-claw-tui --device-profile work` against a native daemon whose explicit
`GTA_CLAW_MEMORY_POLICY` is `{"schemaVersion":1,"enabled":true}`. A temporary device identity is
refused for memory commands. The worker checks native model-free memory capabilities on the same
ready connection before `chat.send`; unsupported peers receive no memory submission. Ordinary
chat input containing a direct `!tool` line is refused, including uppercase spellings.

Select a session, or let the first memory action create a draft session, then use the palette:

```text
memory list [limit [after-id notebook-revision]]
memory get note-id [note-revision offset]
memory search [limit]
memory save note-id fact|preference|procedure expected-notebook-revision
memory delete note-id expected-notebook-revision
memory export notebook-revision [offset]
memory import expected-notebook-revision [overwrite]
```

Action names are case-insensitive; note IDs and input retain their exact case. Kind values and
`overwrite` are lowercase literals. Save opens a note editor, search opens query input, and import
opens archive JSON input. Enter submits; Shift-Enter adds a newline. On terminals supporting
bracketed paste, a multiline paste is a single data-only operation and never submits itself;
an oversized paste or forbidden control character rejects the entire paste. Esc suspends the draft,
and `i` reopens it in its original session. Switching sessions cannot redirect a memory draft.

All actions, including reads, still require the existing complete bound approval preview and an
explicit operator decision. Results appear in Workspace and use the same durable run/recovery/ACK
path as native chat. A refused preflight is shown as not sent, but a refused retry cannot erase an
earlier unknown attempt. `retry-send` retains the original command/session/key and never approves
automatically. Unsubmitted drafts and unconfirmed keys are retained only within the running TUI
process; there is no local crash-recovery journal for them yet.

List defaults to 16 entries (maximum 32); a continuation ID needs its notebook revision. Get
returns up to 2048 UTF-8 bytes and needs the note revision for nonzero offsets. Search accepts
4096 UTF-8 bytes and returns at most eight matches. Save accepts 8192 UTF-8 bytes; every fully
encoded direct command, including JSON escaping, must fit 16 KiB. Revision zero is valid for an
initial notebook, and correction/deletion/import use the exact current notebook revision.

Export returns one plaintext, revision-pinned archive page with its full digest; it does not write
an encrypted local file or automatically collect pages. Import accepts the closed schema-version-1
[portable note archive](../apps/gta-claw-cli/README.md#explicit-memory-commands), rejecting duplicate
or unknown fields, invalid note/source/revision data and oversized envelopes before submission.
Existing IDs conflict unless `overwrite` is explicit, which still requires revision matching and
approval. Note/notebook revisions are not run-result ACK revisions. Contents and source labels are
untrusted data, not instructions or authority; no semantic/automatic recall or full historical
erasure is implied. Native notebooks have the existing 256-notebook/256-note allocation limits.

---

## 5. `gta-claw-daemon`

```text
usage: gta-claw-daemon [--probe | --check-config] [--config PATH] [--listen ADDRESS] [--legacy-listen ADDRESS] [--gateway-listen ADDRESS] [--mcp-listen ADDRESS] [--state-dir PATH] [--log-file PATH] [--tls-terminated-by-frontend] [--smoke]
```

`--help` and `-h` are also accepted. Help is global: if either spelling appears anywhere, the daemon
prints the usage line and exits successfully before creating the Tokio runtime, even if another
argument is unknown or missing its value. Without help, each top-level option token must be Unicode
and exactly match a supported flag. Address flags consume the next argument and require it to be a
Unicode `SocketAddr`. The path flags `--config`, `--state-dir` and `--log-file` instead consume the
next raw `OsString`, so the parser accepts non-Unicode paths and flag-like values. A value-taking
flag is rejected as incomplete only when no following argument exists. A token that reaches
top-level option matching is rejected if unsupported, as are prohibited mode/serving-option
combinations; a token already consumed as a path never reaches that matching step. The parser does
not recognize `--`. For example, `--config --smoke` selects a file literally named `--smoke` rather
than enabling smoke mode.

### 5.1 Health probe

```sh
gta-claw-daemon --probe
```

Writes one health line and exits.

`--probe` cannot be combined with `--check-config` or serving-only options. The parser accepts
`--config` and `--state-dir` beside `--probe`, but probe mode does not load or use either value.

### 5.2 Configuration check

```sh
gta-claw-daemon --check-config --config /etc/gta-claw/config.json5
```

Loads layered configuration and runs the current non-network subset: exposure policy over the
options permitted in check mode, state-directory path resolution, proxy-policy construction,
admin-token resolution, update and legacy/channel settings, channel coverage, and provider-auth
configuration and secret resolution. It does not open listeners. It only computes the state
directory path: it does not create the directory, test its usability or permissions, or open the
pairing, audit or goal stores. It also does not initialize telemetry or test its output, fetch the
role, discover or activate plugins, or authenticate/activate a provider. Native API clients and
their transports are constructed for static validation without contacting their endpoints.
`--check-config` accepts `--config` and `--state-dir`; it cannot be combined with `--probe` or any
listener, logging, TLS-assertion or smoke option. Consequently, although the check calls the exposure
policy, it cannot preflight proposed listener overrides or a routable deployment.

The optional `core.provider` object selects one explicit backend independently of legacy
`core.copilot` defaults. Its kinds are `openai`, `anthropic`, `copilot` and `disabled`:

```json5
{
  core: {
    provider: {
      kind: "openai",
      model: "exact-provider-model-id",
      model_aliases: [{ alias: "work", model: "exact-provider-model-id" }],
      api_key: "env:PROVIDER_API_KEY",
      base_url: "https://api.openai.com/v1/",
      credential_origin: "https://api.openai.com",
      completion_api: "responses",
      request_timeout_ms: 30000,
    },
  },
}
```

This is a partial file layer; keep the rest of the required configuration, including the role
source and channel settings. OpenAI/Anthropic require a SecretRef, not a literal key. Model IDs
are exact, nonblank and at most 256 bytes; URLs are at most 2048 bytes, references at most 1024.
Timeout is 1000..120000 ms, default 120000. HTTPS and literal loopback HTTP are accepted without
userinfo, query, fragment, whitespace or ambiguous dot paths. Origin must match the endpoint and
contain no path; absent origin is derived from the validated endpoint. Official API endpoints are
defaults. Custom origins still require separate `GTA_CLAW_PROVIDER_ORIGINS` enrollment. A declared
origin does not authorize credential disclosure. `completion_api` is OpenAI-only and defaults to
`chat_completions`; `responses` is explicit and stateless.

Copilot takes `kind:"copilot"`, an exact `model` and optional `request_timeout_ms`; authentication
remains in `core.auth.github`, and native API-key/endpoint fields are refused. OpenAI/Anthropic and
disabled mode do not require unused GitHub credentials. `kind:"disabled"` accepts no active
provider settings, starts no model or Device Flow, and stays explicitly non-ready for model
requests while administrative inspection remains available. The optional `max_observed_turn_tokens`
is an observed per-turn stop threshold, not a monetary or single-request hard cap.

Optional `model_aliases` also applies to Copilot and Anthropic. It is a case-sensitive, single-hop
alias-to-exact-ID table, limited to 128 entries and 4096 total UTF-8 bytes of names and targets;
each name uses the same 256-byte model-ID grammar. Duplicate names, chains, exact-ID collisions,
`openclaw` and all `openclaw/` names are reserved or refused. Startup and refresh bind every target
to the complete current provider catalogue; a bad refresh preserves the previous catalogue.
`model` itself stays exact. Aliases resolve before fixed-model/capability checks, so an alias to
another model does not bypass the explicit selection. They never infer credentials, change account
or endpoint, or add fallback. Native HTTP accepts only explicitly configured extra aliases; the
generic HTTP adapter's existing model-name contract remains unchanged. Alias edits require restart.

With no `core.provider`, existing selection remains unchanged. Any explicit selection conflicts
with `GTA_CLAW_PROVIDER_POLICY`, including an empty legacy policy value, and cannot use smoke.
Explicit models cannot be replaced by remote role model changes or configuration reload. Provider
edits require restart; refused reload leaves the running configuration/provider generations intact.
Layer changes of `kind` replace the whole provider object so another provider never inherits its
credentials. Same-kind partial layers preserve unmodified fields. Duplicate object fields in
JSON5 layers are rejected before merging. Operator status identifies the selection source and
declared origin without credential identifiers.

[CLI provider inspect/prepare](../apps/gta-claw-cli/README.md#provider-configuration) provides a
local file workflow with source SHA verification and exclusive new candidates. It does not resolve
environment overrides or validate live credentials. See the
[configuration record](ledger/native-provider-config-20260916.json) for tested and open boundaries.

`config provider prepare --model <exact-id>` changes only the model while retaining the provider's
credential reference, endpoint, protocol, timeout and budget. Windows `apply` additionally requires
both reviewed digests, a new backup and `--confirm-apply --confirm-offline`; it verifies the backup
before writing the held source file. This is non-atomic offline saving, not live configuration
publication. A failure may leave source bytes unknown; `restore` uses a separate confirmation and
preserves those bytes before restoring a complete reviewed snapshot. See the
[offline application and recovery procedure](../apps/gta-claw-cli/README.md#offline-application-and-recovery).

Native `gateway models` provides up to eight cached entries per page with exact IDs, declared
capabilities, optional limits, configured aliases, selected model and observation timestamp.
Aliases are configuration metadata covered by the digest, not live provider capability claims.
Encoded pages stay within 16 KiB and can therefore be shorter. New readers accept old pages
without aliases; old strict readers can reject alias-bearing pages and need an upgrade. TUI and
Slint show aliases separately while candidate editors keep exact IDs. Reading performs no network request.
`gateway refresh-models --sha256 <observed-digest>` is a separate explicit read/write operation:
one model-list request, ten-second wait budget, no inference or model switch. Invalid/changed
catalogues, cancelled reads or concurrent provider changes preserve the old cache. SDK-advertised
capabilities are not live per-account capability proof. See the
[CLI model catalogue guide](../apps/gta-claw-cli/README.md#model-catalogue) and
[catalogue verification](ledger/native-model-catalogue-20260916.json).

`gateway models --availability` reads explicit lifecycle status: `disabled`, `authentication_pending`,
`not_initialized` or `retired`. TUI provides `models-status`, and desktop Models has a status control.
These are read-only local facts, not live inference readiness. Ordinary directory queries retain
their previous format; old-server refusal preserves the previous page, and unknown reasons are
rejected. See the [status record](ledger/native-model-status-20260916.json).

`gateway export-models --destination <new-absolute-file>` reads the entire cached directory through
the same authenticated read-only connection. It pins all page metadata and independently verifies
the complete digest and cross-page ID/alias uniqueness before creating a file. No refresh, inference,
model change or ACK occurs. The result is a bounded plaintext metadata archive, not an account proof
or configuration import. Interrupted reads create no file; an uncertain file write must be preserved
and inspected. Existing files are never overwritten. See the
[export procedure](../apps/gta-claw-cli/README.md#complete-catalogue-export) and
[verification record](ledger/native-model-export-20260916.json).

Before a provider completion, stream or embedding call, daemon checks that the exact model is
still present and that provider capabilities, explicit per-model declarations and known output
limits admit the request. Missing per-model declarations stay unknown and use only the existing
provider support checks. Explicit client tools, required tools, image data and typed tool history
are not discarded to force success. Only optional host/runtime declarations are omitted for a
known text-only model. No fallback model, inferred context size or extra network request is added;
see the [admission record](ledger/native-model-admission-20260916.json).

### 5.3 Serving

```sh
gta-claw-daemon
```

Serving mode resolves configuration and initializes telemetry in `main`, then calls
`serve_production`. `ProductionService` startup opens the durable Gateway pairing, security-audit
and goal stores, activates signed plugins, conditionally activates the smoke provider or GitHub
Copilot or an explicit native OpenAI/Anthropic selection, starts configured channel transports,
and binds four listener surfaces:

- the main 17-route HTTP API;
- the legacy Node-compatible HTTP facade;
- the Gateway v4 server;
- a separate loopback-only listener for the `/mcp` route.

The fourth listener requires dedicated `GTA_CLAW_MCP_OWNER_TOKEN` and/or `GTA_CLAW_MCP_TOKEN`
configuration. Owner and read-only tokens must differ, contain 1..=4096 ASCII bearer bytes and no
whitespace/control characters. Missing credentials fail closed. Main HTTP credentials do not
authenticate MCP; the read-only MCP role cannot execute writes.

The four channel paths are conditional: Teams and WhatsApp are wired into the legacy HTTP facade,
while Telegram and Discord are supervised outbound clients. A configured GitHub token activates
GitHub Copilot at startup; otherwise the provider remains pending Device Flow. `--smoke` explicitly
substitutes the local install-diagnostic provider.

The complete option surface is:

| Option | Serving behavior |
|---|---|
| `--config PATH` | Loads strict JSON5 from `PATH`; otherwise uses `GTA_CLAW_CONFIG`, then the audited legacy-environment migration. |
| `--listen ADDRESS` | Main HTTP bind. Default: `127.0.0.1:0` (an OS-assigned port). |
| `--legacy-listen ADDRESS` | Legacy HTTP bind. Default: loopback on `core.server.port`. A routable bind requires both a trusted TLS frontend and proxy-level caller authentication plus a strict route allowlist; the daemon's TLS assertion alone is insufficient. |
| `--gateway-listen ADDRESS` | Gateway bind. Default: `127.0.0.1:0`. |
| `--mcp-listen ADDRESS` | MCP bind. Default: `127.0.0.1:0`; non-loopback addresses are always rejected. This changes only the bound socket: without a production MCP token/JWT authenticator, every request is rejected. |
| `--state-dir PATH` | State root; otherwise `GTA_CLAW_STATE_DIR`, then `$HOME/.gta-claw`. Pairing, audit, goals and `runtime.redb` session/turn/context checkpoints live here; cross-object recovery remains incomplete. |
| `--log-file PATH` | Writes ordinary telemetry to the file instead of standard error. |
| `--tls-terminated-by-frontend` | Asserts that a trusted frontend terminates TLS. It does not enable TLS or add caller authentication; it only passes the daemon's bind policy for routable main HTTP, legacy HTTP or Gateway addresses. |
| `--smoke` | Uses the deterministic local install-diagnostic provider. Every explicitly selected listener must remain loopback. |

Do not expose the legacy listener merely by adding `--tls-terminated-by-frontend`. Legacy `/chat`
has no application-level caller authentication. Setting `GTA_CLAW_ADMIN_TOKEN` does not change that:
it supplies an operator/all-scopes bearer credential for exactly the six protected main-API routes
`GET /v1/models`, `GET /v1/models/{id}`, `POST /v1/embeddings`,
`POST /v1/chat/completions`, `POST /v1/responses` and `POST /tools/invoke`; the same credential
authenticates `POST /api/v1/admin/rpc`. Its presence also registers legacy `/admin/reload`,
`/admin/system` and `/admin/exec`. The reload route requires the exact token, but the system and exec
routes accept either that token or a loopback peer. The token is not installed in the MCP-specific
authenticators, and no JWT alternative is wired, so it cannot make `/mcp` accessible. A same-host
reverse proxy appears loopback to the system and exec handlers. A frontend for a routable legacy
bind must authenticate callers itself and forward only explicitly intended routes; block
`/admin/*` unless the proxy enforces equivalent authorization, and do not forward `/chat` without a
separate caller-authentication policy.

Signal handling does not cover the entire serving-mode startup. `main` loads configuration and
initializes telemetry before it calls `serve_production`; the operating system's default signal
behavior still applies during those earlier phases. On entry, `serve_production` installs the stop
handlers before starting `ProductionService` composition. From that point, a supervisor stop during
composition is observed and startup is cancelled or drained; a signal during the earlier
configuration or telemetry phase can terminate the process without a daemon drain summary. After
composition has bound and started the listeners, the daemon prints:

```text
ready protocol=1
healthy runtime=<os>-<arch>
service http=<address> legacy=<address> gateway=<address> mcp=<address> provider=<name> config_generation=<n>
```

`ready protocol=1` and `healthy runtime=...` are process protocol/health announcements; the
`service ...` line is a listener/startup announcement. None asserts dependency readiness. `/ready`,
`/readyz` and the `status` control response report dependency and serving readiness. The listener
announcement may name `device-flow-pending`; until Device Flow activates the provider, the provider
dependency remains false and readiness remains false. The `mcp` dependency only records that the
listener task started; it can be true while every MCP caller is still rejected.

It then serves until one of:

- a supervisor stop signal — `SIGTERM` on Unix (what `systemd`, `docker stop` and `kubectl delete`
  send), or a console close / system shutdown on Windows,
- an interrupt — `SIGINT` on Unix, Ctrl-C or Ctrl-Break on Windows,
- the line `shutdown` on its control channel (standard input),
- a supervised runtime/ingress fault: the main HTTP, MCP or legacy HTTP task fails, returns or
  disappears unexpectedly,
- a post-start failure writing a reload, status or other control response to the supervisor output.

Reaching the end of standard input is **not** a stop condition: a daemon started with stdin closed
keeps serving. The same channel accepts `status` and `reload`; reload either reports the applied
generation and changed domains or a rejection while the previous generation keeps serving.

On stop it prints one summary line:

```text
stopped reason=<terminate|interrupt|control|runtime> clean=<bool> drained=<n> completed=<n> abandoned=<n> tasks=<terminated>/<spawned>
```

`reason=runtime` identifies a post-start supervised fault: an ingress failure, return or
disappearance, or a failure writing a reload, status or other control response to the supervisor.
After an ingress fault the daemon drains, emits the stop summary and exits with an error because the
fault makes the summary unclean. After an output fault it still drains and attempts the same summary,
but the output is already broken, so the `stopped ...` line is not guaranteed to be emitted. A
failure writing the initial startup announcements also drains and returns the I/O error before the
event loop, without a `reason=runtime` stop line. Work left behind likewise produces an error.
`tasks=t/s` is scoped service-task accounting for work explicitly included by the production stop
ledger, such as ingress, Gateway, plugin, channel, Device Flow and updater tasks. Some included
adapters use drop guards to record termination, but the counters are not a census of every Tokio,
blocking or process task, and equality is not universal leak proof.

Stopping it by hand:

```sh
printf 'shutdown\n' | gta-claw-daemon
```

### 5.4 Current limits

- **Recovery is partial.** `runtime.redb` persists session/turn state and retained context checkpoints,
  and reload/LRU eviction preserve stored history. Run/context/goal/outbox are not one atomic
  transaction; durable admission, full archives and cross-platform fault recovery remain open.
- **Approval policy is partial.** Gateway, CLI and Slint support once-scoped approvals with complete
  redacted previews. Plugin tools require approval, but full caller/resource/version binding remains.
- **MCP needs separate credentials.** Configure the dedicated owner/read-only tokens explicitly.
- **`claw-tools` is not composed.** Tool execution is not wholly absent: signed plugin registrations
  and the durable goal tool are executable through the runtime and authenticated main HTTP surface.
  MCP owner calls share the plugin approval executor. The missing part is the `claw-tools` catalogue and
  its schemas, authorization, path confinement and validated network destinations.
- **Skill execution and migration-evidence ingestion are not dispatched.** Startup counts
  `claw_skills::registry()` for inventory, but the production path has no caller for its
  `WasmSkillHost` bridge and executes no bundled skill. It also has no application caller for
  `validate_migration_evidence`; that validator is structural only, while cryptographic artifact
  verification remains a separate plugin-trust responsibility.
- **Compatibility evidence is outstanding.** No test under `apps/` replays `compat/legacy` against
  the bound daemon. This is a parity-evidence gap, not a claim that security audit evidence is
  absent: the serving path opens a durable security-audit log.

**Packaging blocker:** the current `packaging/linux/systemd/gta-claw-daemon.service`, used by the
Debian and RPM prototypes, is incompatible with production serving and must not be deployed
unchanged. `RestrictAddressFamilies=AF_UNIX` prevents the required `AF_INET`/`AF_INET6` TCP listeners
from being created, and `IPAddressDeny=any` blocks required IP ingress and egress. This remains
pending a packaging fix.

---

## 6. `gta-claw-desktop`

The native shell, built with Slint 1.17.1. **Windows and macOS only.**

```sh
cargo run --manifest-path desktop/Cargo.toml -p gta-claw-desktop --release
```

### 6.1 First-run flow

The window opens on a three-step first-run sequence — **Welcome → Authorize → Trust** — followed by
the Gateway connection surface.

Device authorization and workspace trust remain uncomposed and do not confer access. The Gateway
panel performs real authentication, then the native product surface supports chat/history and
once-scoped approvals. It starts with empty production models, not demo conversations or files.

### 6.2 Connecting

The connection panel performs the challenge/connect/hello and health flow. Product mode requests
exactly `operator.read`, `operator.write` and `operator.approvals`, never `operator.admin`. It asks for:

| Field | Notes |
|---|---|
| Gateway endpoint | Same validation rules as the CLI. |
| Token | Session-only. The field is cleared the moment it is submitted and is never persisted. |
| Ephemeral identity consent | Explicit consent to a session-only identity and chat/approval access. |
| Remember device identity | Optional Windows/macOS protected `desktop` profile for the exact endpoint; does not persist the token or grant trust. Required for memory commands. |

Buttons: **Connect**, **Retry**, **Cancel**, **Disconnect**.

After connecting, the summary panel shows only bounded non-secret fields — endpoint, negotiated
protocol, role, effective scopes, health and identity mode. Pairing may be required. Without explicit
remember-device consent, identity is temporary; a remembered identity uses the OS-protected profile
and fails closed if it cannot be loaded. Issued device tokens remain bounded and process-local.

Pending approvals are queried after reconnect, and approval is disabled until a complete bounded
preview is available. Commands and results are tied to a connection epoch. Full streaming,
history/event reconciliation, workspace trust and full credential lifecycle remain unfinished.

For an observed native terminal run, the Session Usage area shows the stored accounting summary.
Its refresh icon reads provider rounds from the start; the next arrow reads the next page when
available. Controls disable while a page is in flight or the current run/connection cannot be
matched. The scrollable read-only area distinguishes missing reports, complete zeroes, partial
counters, persistence provenance and uncalculated cost. Failed reads preserve the prior valid
page and never change the run outcome or acknowledge a result. Selection/epoch/revision changes
reject stale replies. This is bounded inspection, not full export or invoice reconciliation; see
the [accounting workflow record](ledger/native-accounting-workflow-20260915.json).

Settings > Models now displays the native cached catalogue rather than an automatic-routing
placeholder. The down arrow reads the first cached page, the right arrow reads a pinned next page,
and the refresh icon explicitly fetches the provider directory. These controls use the existing
authenticated connection, disable during a request and never select or configure a model.
Failed/invalid replies keep the previous valid page; a successful refresh clears it until another
cache read. Disconnect/epoch changes clear the view and reject stale responses. Optional limits
stay unknown when absent, and SDK capability declarations remain explicitly unverified. The
scrollable read-only view does not add chat results or ACKs. Full model selection/application is
not implemented by these controls; see the [desktop follow-up](ledger/native-model-catalogue-20260916.json).

The pencil control opens a separate **local** model candidate form. Enter an absolute source path,
inspect it with the down-arrow control, choose an exact model from the current catalogue page,
then enter a new absolute candidate path and create it with the plus control. The local provider
kind and currently saved model must match the observed catalogue, but matching those fields is
not proof that this file belongs to the connected Gateway. Review the source's endpoint and
credential binding independently. Changing catalogue page, connection or instance invalidates
the old selection. No alias, fallback model or new credential is inferred.

The platform service rechecks the original file SHA, creates without overwrite and reads the
candidate back. Only the model field changes; source and live daemon remain unchanged. Receipts
include the source and candidate digests, not credential references, and remain visible across
connection loss so an already created file is not mistaken for an unperformed operation. A local
I/O error can leave a candidate; preserve it. File tasks run outside the UI thread with one task
in flight and are drained on ordinary controller shutdown. For reviewed application and recovery,
use the explicit [offline CLI workflow](../apps/gta-claw-cli/README.md#offline-application-and-recovery).
No local form control applies to a running Gateway or authorizes a restart or a paid request.

### 6.3 Platform Boundaries

The desktop shell is a separate Cargo workspace because the repository's trusted supply-chain policy
refuses a Slint dependency anywhere reachable from a root workspace member. Root Android/iOS client
cores are UI-independent; separate `android/` and `ios/` workspaces contain Slint connection shells.
Their platform bridges and complete product workflows remain incomplete. Linux desktop rejection
and root Slint exclusion remain policy.

### 6.4 Explicit Memory

Connect with the saved-device option to a native daemon with explicit memory enabled, then open a
Session and select the Memory toolbar control. Choose List, Read, Search, Save, Delete, Export or
Import. The form keeps note ID, kind, notebook/note revision, byte offset and content separate;
only fields used by the selected action are enabled. List's optional ID is the `after` cursor;
Read uses a note revision, while save/delete/import use the current notebook revision. Import
conflicts with existing IDs unless the explicit overwrite checkbox is selected. These are not
run-result ACK revisions. All actions still require the normal complete bound approval preview.

The controller verifies native model-free capabilities on the exact ready epoch before submitting,
and refuses memory on temporary identities or unsupported peers. A raw direct-tool chat message
cannot bypass those checks. JSON archives use the existing strict Gateway codec, so duplicate keys,
invalid fields/revisions, oversized/deep data and unsupported versions are rejected before submit.
Pretty-printed valid archives are safely encoded as a single direct command. Content remains
untrusted data, never an extra directive. Note/query and final-envelope limits match the TUI guide.

The form is bound to the displayed session and connection; changes close it and discard its local
unsubmitted fields. Confirmed memory results appear in a separate scrollable, selectable, read-only
area, without transcript-summary truncation, and are cleared on connection loss. An unknown send
retains its original key and enables explicit original-request retry after the current attempt
finishes. A refused retry does not erase earlier uncertainty. Complete durable receipts bind the
key to its run; an early result event cannot release unconfirmed input. Existing approvals, durable
result queries and exact ACK remain in use, without automatic approval or replay.

The desktop uses the endpoint's protected `desktop` profile. Other profile names are distinct
device identities and their notebooks are not automatically merged. Drafts, retained unconfirmed
keys and the latest memory-result view are process-local; no crash journal is implemented.
Export still returns plaintext pages with a revision/digest, not an automatically collected or
encrypted local archive. Large staged imports, full provenance/deletion workflows and actual
Windows/macOS interactive acceptance remain open. Local software-renderer tests do not replace
those platform checks.

For the separate CLI encrypted-file export/import workflow, see
[Encrypted Memory Files](../apps/gta-claw-cli/README.md#encrypted-memory-files). It does not add
automatic file transfer to the desktop form or remove per-page approval requirements.

---

## 7. `gta-claw-updater`

```text
Usage: gta-claw-updater --manifest URL --current VERSION --target PATH
```

All three arguments are required.

```sh
gta-claw-updater \
  --manifest https://releases.example.test/gta-claw/manifest.json \
  --current 0.1.0 \
  --target /Applications/GTA\ Claw.app
```

Outcomes:

| Outcome | Message |
|---|---|
| Already current | `GTA Claw <version> is current.` |
| Installed | `GTA Claw <version> installed successfully.` |
| Verified but the app is running | `GTA Claw <version> is verified at <path>. Close the running application and run the updater again; elevation was not attempted.` |
| Linux | `GTA Claw updates are managed by the system package manager.` — the updater exits `0` without doing anything. |

Updates are signed, resumable and rollback-safe. Self-mutation through a package manager or a piped
install script is forbidden by design.

---

## 8. Configuration

### 8.1 The Rust configuration model

`claw-config` is the configuration boundary for the Rust workspace. It reads UTF-8 **JSON5** into
immutable typed snapshots covering 47 frozen top-level domains, rejects unknown envelope and field
names, writes snapshots atomically with durable backups and rollback, and publishes typed reload
notifications. Layered resolution order:

```text
built-in → system → user → workspace → frozen legacy environment → command line
```

Nested objects merge recursively; arrays and scalars replace lower layers. Secrets are persisted
only as validated environment or platform-store **references**, never as plaintext, and secret types
redact themselves in `Debug`, `Display` and Serde output.

The version 1 runtime envelope requires `schema_version` plus these `core` domains: `auth`, `role`,
`channels`, `server`, `logging`, `sessions`, `copilot`, `legacy`, `updates`, `admin`, `network`.

`gta-claw-daemon` loads this model from `--config PATH` or `GTA_CLAW_CONFIG`; when neither is set it
uses the audited legacy-environment migration. `--check-config` validates the static subset listed
in section 5.2 without serving; it is not a storage, telemetry, role, plugin or provider startup
probe.

### 8.2 Selected environment variables

| Variable | Read by | Meaning |
|---|---|---|
| `GTA_CLAW_GATEWAY_URL` | `gta-claw-tui` | Default Gateway endpoint (`ws://127.0.0.1:18789`). |
| `GTA_CLAW_GATEWAY_TOKEN` | `gta-claw-tui`, `gta-claw-daemon` | Shared Gateway token; the daemon uses it as the Gateway credential when set. |
| `GTA_CLAW_CONFIG` | `gta-claw-daemon` | Config-file fallback when `--config` is absent. |
| `GTA_CLAW_STATE_DIR` | `gta-claw-daemon` | State-root fallback when `--state-dir` is absent. |
| `GTA_CLAW_ADMIN_TOKEN` | `gta-claw-daemon` | Overrides the configured admin bearer token. It authenticates the main API's six protected model/tool routes and `POST /api/v1/admin/rpc`, and registers legacy `/admin/*`. It does not authenticate `/mcp` or legacy `/chat`; legacy system/exec also trust a loopback peer. |
| `NO_COLOR` | `gta-claw-tui` | Monochrome output. |
| `TERM` | `gta-claw-tui` | `dumb` means non-interactive. |
| `GTA_CLAW_CREDENTIALS_DIR` | `claw-provider-sdk` file secret store | Credential root override. Otherwise `$XDG_DATA_HOME/gta-claw/credentials`, else `$HOME` (or `%USERPROFILE%`) `/.local/share/gta-claw/credentials`. |
| `CREDENTIALS_DIRECTORY` | `claw-provider-sdk` file secret store | The systemd credentials directory. |
| `GTA_CLAW_ACPX_LEASE_ID`, `GTA_CLAW_ACPX_SESSION_KEY` | `claw-acp` | ACP extension lease and session key. |
| `CODEX_HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `APPDATA`, `LOCALAPPDATA`, `HOME`, `USERPROFILE` | `claw-migrate`, `gta-claw-updater` | Source and state directory discovery. |
| `GTA_CLAW_LOG`, `GTA_CLAW_LOG_FORMAT` | `gta-claw-daemon` | Tracing filter and `human`/`json` format for serving-mode telemetry. |

`.env.example`, `deploy/run.sh` and `deploy/conf/` are **legacy Node service** artifacts, not the
authoritative Rust configuration surface. The daemon can translate the frozen subset of legacy
process environment through its audited migration path; use typed JSON5 for new deployments.

---

## 9. Troubleshooting

**`error: unknown command`, exit 2.** The CLI only accepts `--version`, `--help`/`-h`, `health`,
`send` and `gateway health`.

**`explicit --ephemeral-device opt-in is required`.** `gateway health` will not run without it. There
is no persistent identity mode yet.

**Exit 2 with an endpoint complaint.** The endpoint validator is strict on purpose. Check for
trailing whitespace, an uppercase host, a query string or fragment, a padded port, a non-punycode
international domain, or an uncompressed IPv6 literal. The message is
`Gateway endpoint spelling is not canonical (usage_config)`.

**`remote plaintext ws requires explicit diagnostic opt-in (usage_config)`, exit 2.** Non-loopback
plaintext requires `--allow-insecure-remote-ws`. Prefer fixing the endpoint to `wss://`.

**Exit 3, `Gateway transport failed`.** The endpoint was accepted but the connection did not
succeed. Check reachability and the port.

**Exit 4.** Authentication was rejected or the Gateway requires pairing. Because
`--ephemeral-device` mints a fresh identity every run, a Gateway that requires an approved device
will keep asking until it is paired.

**Exit 7.** Raise `--timeout-ms` (maximum 120 000) or check reachability.

**`token-file input is disabled because secure permissions cannot be proven portably`.** Use
`--token-stdin`.

**The TUI prints one frame and exits.** Standard output is not an interactive terminal, or `TERM` is
`dumb`, or you passed `--plain`.

**`Gateway snapshot timed out`.** The Gateway did not return a session list within five seconds in
plain mode.

**The daemon exits with "shutdown left work behind".** The summary's `abandoned` value, deadline
state and scoped `tasks=<terminated>/<spawned>` ledger describe the recorded failure. A task-counter
gap applies only to explicitly accounted service tasks; other abandoned work can leave those two
numbers equal.

**The desktop build fails on Linux.** Expected. Build it on Windows or macOS.

---

## 10. Not available yet

State this plainly so nobody hunts for a flag that does not exist:

- **No complete CLI conversation workflow.** Native send/history/abort/approvals exist, but persistent
  identity, pairing onboarding, streaming and durable run queries are not complete.
- **No parity-complete Rust production service.** The daemon serves real transports, providers and
  four configured channel paths, but has the limitations listed in section 5.4.
- **No transport for the other registered channels.** Teams, Telegram, Discord and WhatsApp are
  composed conditionally; the remaining channel inventory is not a serving transport.
- **No skill execution, concurrent remote skill fetch or skill-migration evidence ingestion.** Role
  loading is composed, including its bounded remote fetch path; these skill paths are not.
- **No JavaScript skills.** Skill execution is native Rust, a declarative HTTP port, or a WebAssembly
  component. An embedded JavaScript engine will never be added.
- **No durable device identity** for CLI or desktop; both are ephemeral-only today.
- **No complete mobile product.** Android/iOS Slint connection shells exist; platform bridges,
  credential storage and full conversation workflows are unfinished. Linux GUI remains unsupported.

Current status per crate and binary: [PROGRESS.md](PROGRESS.md). Architecture and the reasoning
behind these boundaries: [PROJECT_PLAN.md](PROJECT_PLAN.md).
