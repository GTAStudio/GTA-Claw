# GTA Claw Gateway health diagnostic

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
Durable Windows/macOS secure-storage identity is deferred.

| Exit | Category | Meaning |
| ---: | --- | --- |
| 0 | success | Authenticated health RPC returned a positive typed result |
| 2 | usage/config | Invalid arguments, endpoint, or secret input |
| 3 | transport/transient | Connection or transient transport failure |
| 4 | authentication/pairing | Authentication rejected or pairing required |
| 5 | protocol | Version, framing, or typed payload validation failed |
| 6 | health-negative | Health response or health payload was negative |
| 7 | timeout/cancel | Command timed out, was interrupted, or could not shut down in time |
| 8 | internal | Local runtime/client state failure, or an unsupported local command such as `send` |

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
feature-ledger status claim. Existing local `health`, unsupported `send`, and
`--version` foundation behavior remain separate.

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
