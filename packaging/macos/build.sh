#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in cargo rustc rustup lipo otool; do
  require_tool "$tool"
done

mode="${1:-native}"
case "$mode" in
  native)
    targets=("$(host_target)")
    ;;
  arm64)
    targets=("aarch64-apple-darwin")
    ;;
  x86_64)
    targets=("x86_64-apple-darwin")
    ;;
  *)
    die "usage: build.sh [native|arm64|x86_64]"
    ;;
esac

if [[ "${GTA_CLAW_OFFLINE:-0}" != "1" ]]; then
  acquire_locked_dependencies
fi

for target in "${targets[@]}"; do
  assert_headless_cargo_tree "$target"
done

build_target() {
  local target="$1"
  local cargo_target_dir="$OUTPUT_ROOT/build/$target"
  local arch
  local encoded_rustflags
  local -a cargo_network_args=()
  arch="$(expected_lipo_arch "$target")"
  assert_output_path "$cargo_target_dir"
  assert_output_path "$cargo_target_dir/root"
  assert_output_path "$cargo_target_dir/desktop"
  if [[ -d "$cargo_target_dir" ]]; then
    reject_symlinks "$cargo_target_dir"
  fi
  encoded_rustflags="${CARGO_ENCODED_RUSTFLAGS:-}"
  if [[ -n "$encoded_rustflags" ]]; then
    encoded_rustflags+=$'\x1f'
  fi
  encoded_rustflags+="--remap-path-prefix=$REPO_ROOT=."
  encoded_rustflags+=$'\x1f-Dwarnings'
  if [[ "${GTA_CLAW_OFFLINE:-0}" == "1" ]]; then
    rustup target list --installed | grep -Fx "$target" >/dev/null ||
      die "offline build requires preinstalled Rust target: $target"
    cargo_network_args=(--offline)
  else
    rustup target add "$target"
  fi

  note "building root headless workspace for $target"
  assert_output_path "$cargo_target_dir/root"
  if [[ -d "$cargo_target_dir" ]]; then
    reject_symlinks "$cargo_target_dir"
  fi
  MACOSX_DEPLOYMENT_TARGET="$MINIMUM_MACOS_VERSION" \
    CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" \
    CARGO_TARGET_DIR="$cargo_target_dir/root" \
    cargo build \
      --manifest-path "$REPO_ROOT/Cargo.toml" \
      --locked \
      "${cargo_network_args[@]+"${cargo_network_args[@]}"}" \
      --release \
      --target "$target" \
      --package gta-claw-cli \
      --package gta-claw-daemon

  note "building desktop workspace for $target"
  assert_output_path "$cargo_target_dir/desktop"
  if [[ -d "$cargo_target_dir" ]]; then
    reject_symlinks "$cargo_target_dir"
  fi
  MACOSX_DEPLOYMENT_TARGET="$MINIMUM_MACOS_VERSION" \
    CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" \
    CARGO_TARGET_DIR="$cargo_target_dir/desktop" \
    cargo build \
      --manifest-path "$REPO_ROOT/desktop/Cargo.toml" \
      --locked \
      "${cargo_network_args[@]+"${cargo_network_args[@]}"}" \
      --release \
      --target "$target" \
      --package gta-claw-desktop

  local cli="$cargo_target_dir/root/$target/release/gta-claw-cli"
  local daemon="$cargo_target_dir/root/$target/release/gta-claw-daemon"
  local desktop="$cargo_target_dir/desktop/$target/release/gta-claw-desktop"
  for binary in "$cli" "$daemon" "$desktop"; do
    assert_binary_arches "$binary" "$arch"
    assert_macho_minimum_version "$binary"
  done

  "$MACOS_DIR/assemble-app.sh" "$desktop" "$arch" "$arch"
  "$MACOS_DIR/archive-headless.sh" "$cli" gta-claw-cli "$arch" "$arch"
  "$MACOS_DIR/archive-headless.sh" "$daemon" gta-claw-daemon "$arch" "$arch"
  write_artifact_set_checksums "$OUTPUT_ROOT/headless/$arch"
}

for target in "${targets[@]}"; do
  build_target "$target"
done

note "macOS $mode build complete under $OUTPUT_ROOT"
