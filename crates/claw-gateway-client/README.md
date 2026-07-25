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
- Every authenticated lifecycle receives a monotonic process-local
  `ConnectionEpoch` unrelated to the untrusted server `connId`. Each lifecycle
  owns its bounded command sender and correlation map.
- `AuthorizationExpectation::ExactRequested` rejects a hello before Ready unless
  its effective role and scope set exactly match the configured request.
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

## Epoch-bound requests

`wait_ready` returns a `ReadyConnection` containing the validated hello and its
local epoch. Callers that must not cross a reconnect boundary should retain that
epoch and use `request_for_epoch` or `request_with_timeout_for_epoch`. A changed
or disconnected lifecycle returns `GatewayClientError::ConnectionChanged`; the
request is never routed to the replacement connection or replayed.

The convenient `request` methods atomically capture the current lifecycle and
remain connection-bound. Set `authorization_expectation` to
`AuthorizationExpectation::ExactRequested` when the effective hello
authorization is part of the caller's security contract.

The local suite includes authenticated integration and regression cases,
deterministic injected clock/jitter/barrier coverage, and a static
reference-workflow policy test. One ignored live contract test remains available
for operators who explicitly supply an external Gateway endpoint.

## Pinned upstream reference

`.github/workflows/upstream-gateway-reference.yml` validates the immutable data
under `compat/upstream/` and runs the `claw-protocol` and
`claw-gateway-client` suites against that frozen contract. The workflow does not
checkout, install, build, or execute the upstream implementation.

The ignored `pinned_official_gateway_live_contract` test can still perform a
real authenticated v4 handshake, safe `health` interaction, negative token
case, negative protocol-version case, and clean disconnect when an operator
provides `OPENCLAW_REFERENCE_URL` and `OPENCLAW_REFERENCE_TOKEN` for an external
Gateway. No external implementation is provisioned by this repository.

This crate does **not** provide a Gateway server, RPC/business handlers,
provider or model sessions, a GUI, or behavioral parity for all registered
methods.
