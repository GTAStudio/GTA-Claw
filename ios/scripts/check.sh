#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cargo fmt --manifest-path "$workspace_root/Cargo.toml" --all -- --check
cargo check --manifest-path "$workspace_root/Cargo.toml" --workspace --all-targets --locked
cargo clippy --manifest-path "$workspace_root/Cargo.toml" --workspace --all-targets --locked -- -D warnings
cargo test --manifest-path "$workspace_root/Cargo.toml" --workspace --all-targets --locked
