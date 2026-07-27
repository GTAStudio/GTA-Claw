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

The Rust workspace does **not** yet ship a complete agent service. `gta-claw-daemon` is the
composition root, and its subsystem adapters are still deterministic stand-ins. What works today is:

- **Connecting to an existing OpenClaw Gateway** — with the CLI as a bounded diagnostic, with the
  TUI as an interactive client, and with the desktop shell as a native connection surface.
- **Running the daemon's lifecycle**, including its health probe, signal handling and provable
  shutdown drain.
- **Applying a signed update** with the standalone updater.

There is no Rust command that starts a chat with a model provider, loads a role from a URL, or
serves Teams/Telegram/Discord/WhatsApp traffic. The legacy Node service in `src/` still owns those,
and is being deleted module by module — see
[legacy-node-port-obligations.md](legacy-node-port-obligations.md).

---

## 1. Prerequisites

| Requirement | Detail |
|---|---|
| Rust toolchain | Pinned to `1.97.0` by `rust-toolchain.toml`; `rustup` picks it up automatically inside the repository. The minimum supported version is `1.94.0`. |
| Platforms | The root workspace builds on Linux, macOS and Windows. The desktop shell builds on **Windows and macOS only** — a Linux desktop build is rejected on purpose. |
| A Gateway | The CLI, TUI and desktop shell are clients. You need a reachable OpenClaw Gateway v4 endpoint (`ws://` or `wss://`) for them to do anything interesting. |

No Node.js, npm or any JavaScript runtime is required, and none may be introduced — repository
policy rejects it as a test failure.

---

## 2. Building from source

```sh
git clone https://github.com/GTAStudio/GTA-Claw.git
cd GTA-Claw

# Root workspace: all 31 library crates and 6 binaries
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

`--help` and `-h` print that usage text. There are no other commands and no other flags.

### 3.1 `health` — local runtime health

```sh
gta-claw-cli health
```

Prints a single line beginning with `healthy runtime=`, describing the local OS and architecture.
It contacts nothing. Exit code `0`.

An unknown command exits `2` with `error: unknown command` on standard error.

### 3.2 `send` — deliberately unsupported

```sh
gta-claw-cli send session-9 "hello"
```

This exits `8` with `error: unsupported operation: message transport is not configured`. That is the
correct current behavior, not a bug: no message transport adapter is composed yet, and the CLI
refuses to imply that a message was accepted.

### 3.3 `gateway health` — the real Gateway diagnostic

This is the one command that performs real network work. It opens one `ws://` or `wss://`
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

### 4.3 Keys

```text
Tab / Shift-Tab   cycle screens
Up/Down or j/k    select and scroll
Enter             open session / submit answer
y / n             approve / deny
r                 refresh from Gateway
Ctrl-P or :       command palette
1..6              jump to a screen
Esc               close palette
?                 keyboard help
q / Ctrl-C        quit safely
```

### 4.4 Command palette

Press `:` or `Ctrl-P`, type a command, press Enter. Recognized commands, case-insensitive:

`sessions`, `workspace`, `runs`, `diff`, `artifacts`, `help`, `refresh`, `quit` (or `q`).

Anything else reports `Unknown command: …` in the notice line. `Esc` closes the palette.

### 4.5 Non-interactive mode

`--plain`, or any run where standard output is not an interactive terminal, takes a single snapshot
instead of entering the full-screen loop: the TUI connects, waits up to five seconds for the session
list, prints one rendered frame and exits. If the Gateway does not answer in time it prints
`Gateway snapshot timed out` in the notice line. This is the mode to use in scripts and CI.

---

## 5. `gta-claw-daemon`

```text
usage: gta-claw-daemon [--probe]
```

Any other argument is rejected.

### 5.1 Health probe

```sh
gta-claw-daemon --probe
```

Writes one health line and exits.

### 5.2 Serving

```sh
gta-claw-daemon
```

On startup it installs the stop signal handlers *before* starting any subsystem — so a supervisor
that stops the process mid-start is still observed — then prints:

```text
ready protocol=1
healthy runtime=<os>-<arch>
```

It then serves until one of:

- a supervisor stop signal — `SIGTERM` on Unix (what `systemd`, `docker stop` and `kubectl delete`
  send), or a console close / system shutdown on Windows,
- an interrupt — `SIGINT` on Unix, Ctrl-C or Ctrl-Break on Windows,
- the line `shutdown` on its control channel (standard input).

Reaching the end of standard input is **not** a stop condition: a daemon started with stdin closed
keeps serving.

On stop it prints one summary line:

```text
stopped reason=<terminate|interrupt|control> clean=<bool> drained=<n> completed=<n> abandoned=<n> tasks=<terminated>/<spawned>
```

If work was left behind, the process exits with an error describing how many tasks were abandoned.
The task counters are real: terminations are counted from a guard's `Drop`, so a task cancelled
part-way through still counts, which makes `tasks=t/s` a genuine leak check.

Stopping it by hand:

```sh
printf 'shutdown\n' | gta-claw-daemon
```

### 5.3 Current limits

The daemon composes deterministic stand-ins for the runtime subsystems. It does not connect to a
model provider, serve chat traffic, or open a channel. Treat it today as a lifecycle and shutdown
surface, not as the product service.

A reviewed `systemd` unit exists at `packaging/linux/systemd/gta-claw-daemon.service` and is used by
the Debian and RPM packaging prototypes.

---

## 6. `gta-claw-desktop`

The native shell, built with Slint 1.17.1. **Windows and macOS only.**

```sh
cargo run --manifest-path desktop/Cargo.toml -p gta-claw-desktop --release
```

### 6.1 First-run flow

The window opens on a three-step first-run sequence — **Welcome → Authorize → Trust** — followed by
the Gateway connection surface.

Be aware of what is real here: the welcome, device-authorization and workspace-trust steps are a
**presentational** onboarding sequence. The device code and workspace path shown on those screens
are placeholder content, and clicking through them does not perform an account authorization. The
step that does real work is the Gateway connection panel.

### 6.2 Connecting

The connection panel states its own scope: *"Connect performs the real challenge, connect, hello,
and safe health flow."* It asks for:

| Field | Notes |
|---|---|
| Gateway endpoint | Same validation rules as the CLI. |
| Token | Session-only. The field is cleared the moment it is submitted and is never persisted. |
| Ephemeral identity consent | An explicit checkbox: *"I consent to a new ephemeral device identity for this diagnostic session."* |

Buttons: **Connect**, **Retry**, **Cancel**, **Disconnect**.

After connecting, the summary panel shows only bounded non-secret fields — endpoint, negotiated
protocol, role, effective scopes, health and identity mode. Pairing may be required; the identity
and any issued device token stay in bounded memory and are discarded on disconnect or app exit.

The UI states its own boundary: *"This diagnostic does not enroll a persistent device, store
credentials, or enable chat and account features."*

### 6.3 Why there is no Linux build, and no mobile UI

The desktop shell is a separate Cargo workspace because the repository's trusted supply-chain policy
refuses a Slint dependency anywhere reachable from a root workspace member. The same policy is why
`gta-claw-android` and `gta-claw-ios` are UI-independent client cores with no user interface in this
repository. CI asserts both boundaries, including that a Linux desktop build fails.

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

**No shipped binary loads a config file yet.** `claw-config` is a library boundary waiting for the
daemon composition.

### 8.2 Environment variables the binaries actually read

| Variable | Read by | Meaning |
|---|---|---|
| `GTA_CLAW_GATEWAY_URL` | `gta-claw-tui` | Default Gateway endpoint (`ws://127.0.0.1:18789`). |
| `GTA_CLAW_GATEWAY_TOKEN` | `gta-claw-tui` | Shared Gateway token. |
| `NO_COLOR` | `gta-claw-tui` | Monochrome output. |
| `TERM` | `gta-claw-tui` | `dumb` means non-interactive. |
| `GTA_CLAW_CREDENTIALS_DIR` | `claw-provider-sdk` file secret store | Credential root override. Otherwise `$XDG_DATA_HOME/gta-claw/credentials`, else `$HOME` (or `%USERPROFILE%`) `/.local/share/gta-claw/credentials`. |
| `CREDENTIALS_DIRECTORY` | `claw-provider-sdk` file secret store | The systemd credentials directory. |
| `GTA_CLAW_ACPX_LEASE_ID`, `GTA_CLAW_ACPX_SESSION_KEY` | `claw-acp` | ACP extension lease and session key. |
| `CODEX_HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `APPDATA`, `LOCALAPPDATA`, `HOME`, `USERPROFILE` | `claw-migrate`, `gta-claw-updater` | Source and state directory discovery. |
| `GTA_CLAW_LOG` | `claw-observability` default | The tracing filter variable in `TelemetryConfig::default()`. No shipped binary installs that subscriber yet. |

`.env.example`, `deploy/run.sh` and `deploy/conf/` belong to the **legacy Node service**. They do not
configure any Rust binary. Do not use them as a guide to the Rust product.

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

**The daemon exits with "shutdown left work behind".** Tasks were abandoned during the drain. The
`tasks=<terminated>/<spawned>` counters in the stop line show the gap.

**The desktop build fails on Linux.** Expected. Build it on Windows or macOS.

---

## 10. Not available yet

State this plainly so nobody hunts for a flag that does not exist:

- **No Rust chat command.** `gta-claw-cli send` fails on purpose.
- **No Rust production service.** The daemon composes stand-in adapters.
- **No channel traffic.** Teams, Telegram, Discord and WhatsApp are registry and auth metadata in
  `claw-channels`, not working transports.
- **No role or skill loading from remote URLs.** That was the legacy design and is not being ported.
- **No JavaScript skills.** Skill execution is native Rust, a declarative HTTP port, or a WebAssembly
  component. An embedded JavaScript engine will never be added.
- **No durable device identity** for CLI or desktop; both are ephemeral-only today.
- **No Android or iOS application** in this repository, and no Linux desktop build.

Current status per crate and binary: [PROGRESS.md](PROGRESS.md). Architecture and the reasoning
behind these boundaries: [PROJECT_PLAN.md](PROJECT_PLAN.md).
