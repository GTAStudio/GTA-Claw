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
  universal2)
    targets=("aarch64-apple-darwin" "x86_64-apple-darwin")
    ;;
  *)
    die "usage: build.sh [native|arm64|x86_64|universal2]"
    ;;
esac

build_target() {
  local target="$1"
  local cargo_target_dir="$OUTPUT_ROOT/build/$target"
  local arch
  local encoded_rustflags
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
  rustup target add "$target"

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
}

for target in "${targets[@]}"; do
  build_target "$target"
done

if [[ "$mode" == "universal2" ]]; then
  universal_dir="$OUTPUT_ROOT/build/universal2"
  safe_reset_dir "$universal_dir"
  "$MACOS_DIR/merge-universal.sh" \
    "$OUTPUT_ROOT/build/aarch64-apple-darwin/desktop/aarch64-apple-darwin/release/gta-claw-desktop" \
    "$OUTPUT_ROOT/build/x86_64-apple-darwin/desktop/x86_64-apple-darwin/release/gta-claw-desktop" \
    "$universal_dir/gta-claw-desktop"
  "$MACOS_DIR/assemble-app.sh" "$universal_dir/gta-claw-desktop" universal2 "arm64 x86_64"
fi

note "macOS $mode build complete under $OUTPUT_ROOT"
