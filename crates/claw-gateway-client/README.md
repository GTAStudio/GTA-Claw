# `claw-gateway-client`

Pure-Rust WebSocket/WSS transport for the OpenClaw Gateway protocol pinned at
`b43e832fcc8000ed7287c7accc54e381db607f85`.

The crate owns connection authentication, bounded transport and queues, exact
request correlation, event-sequence continuity, reconnect policy, and
deterministic shutdown. It reuses `claw-protocol` for every Gateway wire DTO and
strict codec decision, and `claw-security` for device identity and signing.

## Invariants

- `ws://` and rustls-backed `wss://`; remote plaintext requires explicit opt-in.
- 64 KiB pre-authentication and 25 MiB authenticated caps are applied from frame
  headers through fragmented-message assembly before unbounded allocation.
- Compression is not offered and any negotiated extension is rejected.
- Request IDs are typed, unique per connection, exactly correlated, and retained
  for a bounded per-connection identifier budget without unsafe eviction.
- Event gaps, duplicates, regressions, and bounded queue saturation enter a typed
  resync-required terminal state.
- Every command/event queue, cumulative outbound/event byte budget, serialization
  allocation, pending map, identifier budget, frame, and retry series is bounded.
  Expired queued requests are discarded and in-flight requests are never replayed.
- A single supervised socket lifecycle re-authenticates every connection and
  cancels pending requests before bounded close/task shutdown.
- All primary/secondary tokens issued after bootstrap are exposed atomically
  through secrecy wrappers; the primary replaces the one-time bootstrap
  credential for subsequent reconnects.
- Shared authentication retains the latest primary device token separately and
  permits exactly one server-hinted corrective device authentication.
- Ping, Pong, and Close frames are strictly bounded and validated; only explicit
  transient Close statuses can enter reconnect policy.
- Credentials are secrecy wrappers and never appear in client `Debug`, errors,
  state, events, or tracing.

The local suite has 39 active client/policy checks: 37 integration and
regression cases, deterministic injected clock/jitter coverage, and a static
reference-workflow policy test. One ignored live contract test is run only by
the isolated upstream workflow.

## Pinned upstream reference

`.github/workflows/upstream-gateway-reference.yml` checks out official
`openclaw/openclaw` at exactly
`b43e832fcc8000ed7287c7accc54e381db607f85` (package `2026.7.2`), verifies the
checkout and pinned `pnpm-lock.yaml` digest, installs the package-declared
`pnpm@11.2.2` with lifecycle scripts disabled, proves the known downloaded
Matrix native artifact is absent, and starts:

```text
OPENCLAW_SKIP_CHANNELS=1 OPENCLAW_STATE_DIR=<isolated> OPENCLAW_GATEWAY_TOKEN=<redacted> node openclaw.mjs gateway --port 18789 --bind loopback --auth token --allow-unconfigured --ws-log compact
```

The Rust client performs a real authenticated v4 handshake, safe `health`
interaction, negative token case, negative protocol-version case, and clean
disconnect. The official Node/npm toolchain exists only in that authoritative
Linux reference job; normal CI, product builds, releases, Cargo build scripts,
and runtime stay Node/npm-free. Linux is authoritative because this check starts
the official host Gateway, while normal Rust transport compile/tests remain the
cross-platform Windows/macOS/Linux gate.

It does **not** provide a Rust Gateway server, RPC/business handlers, provider or
model sessions, a GUI, or behavioral parity for the 278 registered methods.
Node.js and npm are absent from this crate and every normal product build. The
only Node.js boundary is the separately triggered pinned-upstream reference CI
workflow.
