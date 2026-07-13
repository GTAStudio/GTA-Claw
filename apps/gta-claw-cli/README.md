# GTA Claw Gateway health diagnostic

`gta-claw-cli gateway health` is a bounded diagnostic vertical slice. It opens
one real `ws://` or `wss://` connection through `claw-gateway-client`, completes
the authenticated Gateway v4 challenge/connect/hello flow, sends one
`operator.read` `health` RPC, and performs a bounded clean shutdown.

```text
printf '%s\n' 'example-automation-token' |
  gta-claw-cli gateway health \
    --endpoint wss://gateway.example.test \
    --ephemeral-device \
    --token-stdin \
    --json
```

PowerShell can use a pipeline without putting the token in the process command
line:

```powershell
$token | gta-claw-cli gateway health `
  --endpoint wss://gateway.example.test `
  --ephemeral-device `
  --token-stdin
```

The shared token is optional. Select at most one input:

- `--token-stdin` reads at most 4096 bytes from standard input.
- `--token-file <filename>` reads at most 4096 bytes from one relative filename
  in the process working directory. Absolute paths, parent traversal, directory
  components, symlinks, and Windows reparse points are rejected. On Unix,
  group/other permission bits must all be clear (for example, mode `0600`).

The token must be valid UTF-8 and one non-empty line without whitespace; one
trailing LF or CRLF is removed. No token or private key option is accepted on
the command line, and environment variables are never consulted implicitly.
Endpoint credentials, query strings, and fragments are rejected and never
rendered. Non-loopback plaintext `ws://` remains rejected unless
`--allow-insecure-remote-ws` is explicitly supplied; `wss://` uses the client's
rustls transport.

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
| 8 | internal | Local runtime/client state failure |

`--json` emits one deterministic-schema object containing only the sanitized
endpoint origin, negotiated protocol, role, sorted unique effective scopes,
bounded server version, typed health booleans/timestamps, elapsed time, status
category, and the non-secret identity mode. Human output exposes the same safe
fields.

This command implements diagnostic health only. It is not a full OpenClaw CLI,
admin/chat/provider surface, durable keyring identity, GUI, Gateway server, or
feature-ledger status claim. Existing local `health`, unsupported `send`, and
`--version` foundation behavior remain separate.
