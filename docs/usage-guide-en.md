# GTA-Claw usage guide

GTA-Claw is built and operated with Rust tooling only. The root workspace provides a CLI and a
headless daemon; the separate `desktop/` workspace provides the Slint application for Windows and
macOS.

## Headless health

```text
cargo run --bin gta-claw-cli -- health
cargo run --bin gta-claw-daemon -- --probe
```

The persistent daemon listens on `GTA_CLAW_BIND` (`127.0.0.1:3978` by default) and exposes:

| Endpoint | Method | Description |
|---|---|---|
| `/health` | `GET` | Native process health and target OS/architecture |

```text
cargo run --bin gta-claw-daemon
curl http://127.0.0.1:3978/health
cargo run --bin gta-claw-daemon -- --probe-http
```

Unknown routes fail closed with `404`.

## Gateway diagnostic

Use the CLI to test a separately provisioned OpenClaw Gateway:

```text
cargo run --bin gta-claw-cli -- gateway health \
  --endpoint ws://127.0.0.1:18789 \
  --ephemeral-device
```

Run `cargo run --bin gta-claw-cli -- --help` for credential and output options.

## Desktop

On Windows or macOS:

```text
cargo run --manifest-path desktop/Cargo.toml --package gta-claw-desktop
```

The desktop package is intentionally unavailable on Linux.

## Container

```text
docker build -t gta-claw .
docker run --rm -p 3978:3978 gta-claw
curl http://127.0.0.1:3978/health
```

The image runs the native daemon as an unprivileged user. Its health check invokes
`gta-claw-daemon --probe-http`, which checks the live endpoint rather than only checking that the
binary starts.

## Compatibility data

`compat/legacy/` and `compat/upstream/` are inert contract data consumed by validators and Rust
tests. They are not runtime code. Legacy script skills must be explicitly ported to signed
Rust/WASI components; GTA-Claw never evaluates their script text.
