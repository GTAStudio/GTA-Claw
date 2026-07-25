# GTA-Claw

GTA-Claw is a Rust implementation of the OpenClaw-compatible runtime surface. The repository
contains native headless binaries for Windows, macOS, and Linux, plus a Slint desktop application
for Windows and macOS. Product builds, tests, packaging, and runtime paths do not require a
JavaScript engine or package manager.

## Workspaces

The repository intentionally uses two Cargo workspaces:

- The root workspace contains the headless CLI, daemon, protocol, Gateway client, security,
  configuration, application, and platform crates.
- `desktop/` contains the Slint application and is excluded from the root workspace so Linux
  never resolves the Slint dependency graph.

Both workspaces use Rust edition 2024. The repository toolchain is pinned in
`rust-toolchain.toml`, while workspace crates retain Rust 1.94.0 as their MSRV.

## Build and test

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
```

On Windows or macOS, validate the desktop workspace separately:

```text
cargo check --manifest-path desktop/Cargo.toml --workspace --all-targets --locked
cargo test --manifest-path desktop/Cargo.toml --workspace --all-targets --locked
```

Linux deliberately rejects the desktop application while continuing to build every headless
target.

## Headless binaries

The root workspace provides:

- `gta-claw-cli`: typed local health output and bounded OpenClaw Gateway diagnostics.
- `gta-claw-daemon`: the persistent headless process with a bounded `GET /health` endpoint.
  `--probe` checks native runtime identity and `--probe-http` checks the running endpoint.

Examples:

```text
cargo run --bin gta-claw-cli -- health
cargo run --bin gta-claw-daemon -- --probe
cargo run --bin gta-claw-cli -- gateway health --endpoint ws://127.0.0.1:18789 --ephemeral-device
```

Use `cargo run --bin gta-claw-cli -- --help` for the complete diagnostic command contract.

## Desktop application

The desktop application is built only on Windows and macOS:

```text
cargo run --manifest-path desktop/Cargo.toml --package gta-claw-desktop
```

The desktop workspace shares the audited Rust protocol and application crates but remains isolated
from Linux dependency resolution.

## Configuration and compatibility

`claw-config` owns strict JSON5 parsing, validation, atomic persistence, reload classification, and
deterministic migration of audited legacy environment variables. Secrets are represented as
references rather than serialized plaintext.

`compat/legacy/` contains inert schemas, fixtures, and ledgers describing the retired implementation
contract. `compat/upstream/` is a frozen OpenClaw contract snapshot. These trees are data inputs for
Rust validation only; the product does not execute fixture scripts. Legacy remotely supplied script
skills require an explicit signed Rust/WASI port and are never evaluated by the runtime.

The frozen compatibility snapshot can be checked with:

```text
pwsh -File ./compat/upstream/validate.ps1
```

## Container image

The root `Dockerfile` builds `gta-claw-daemon` with the pinned Rust toolchain and copies only the
native release binary into the runtime image:

```text
docker build -t gta-claw .
docker run --rm gta-claw
```

The image runs as an unprivileged user, listens on port 3978, and uses
`gta-claw-daemon --probe-http` to validate its live health endpoint.

## Repository policy

`crates/claw-repo-policy/tests/repository_policy.rs` recursively checks the checkout and rejects:

- JavaScript and TypeScript source/module extensions, including native runtime modules.
- Package manifests and lockfiles from JavaScript package managers.
- Dependency-store directories such as `node_modules`.

Compatibility exceptions are exact file paths, never directory wildcards. The current compat script
exception list is empty; the base-owned adversarial shell fixture and inert macOS policy-search lines
have separate exact allowlists. The test suite includes planted violations and exact-allowlist
sibling checks so the gate cannot silently degrade into a broad compatibility-tree bypass. The
existing `Headless` jobs exercise the crate through `cargo test --workspace --all-targets --locked`;
the always-on pull-request job in `.github/workflows/upstream-gateway-reference.yml` runs the policy
test explicitly so forbidden-only changes cannot bypass the frozen `rust.yml` path filter.

## Supply chain

CI runs formatting, checks, Clippy, tests, MSRV validation, `cargo deny`, `cargo audit`, platform
packaging checks, and the repository policy. The pinned upstream workflow validates the frozen
snapshot and exercises the Rust protocol/client tests without installing or executing an upstream
package graph.
