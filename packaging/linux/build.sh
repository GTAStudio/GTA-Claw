#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in cargo jq readelf rustc rustup; do
  require_tool "$tool"
done
[[ "$#" -eq 1 ]] || die "usage: build.sh ARCH"
arch="$1"
target="$(arch_target "$arch")"

metadata="$(
  cargo metadata \
    --manifest-path "$REPO_ROOT/Cargo.toml" \
    --locked \
    --filter-platform "$target" \
    --format-version 1
)"
forbidden="$(
  jq -r '
    [.packages[].name |
      select(. == "slint" or . == "slint-build" or startswith("i-slint"))
    ] | sort | join(",")
  ' <<<"$metadata"
)"
[[ -z "$forbidden" ]] || die "Linux root metadata contains Slint packages: $forbidden"

rustup target list --installed | grep -Fx "$target" >/dev/null ||
  die "Rust target is not installed: $target"

cargo build \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  --locked \
  --release \
  --target "$target" \
  --package gta-claw-daemon \
  --package gta-claw-cli

cargo_target_dir="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
if [[ "$cargo_target_dir" != /* ]]; then
  cargo_target_dir="$REPO_ROOT/$cargo_target_dir"
fi
binary_dir="$cargo_target_dir/$target/release"
for binary in "$LINUX_DAEMON_NAME" "$LINUX_CLI_NAME"; do
  validate_elf_binary "$binary_dir/$binary" "$arch"
done

printf '%s\n' "$binary_dir"
