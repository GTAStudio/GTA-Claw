#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! xcrun --sdk iphoneos --show-sdk-path >/dev/null 2>&1; then
  echo "The full Xcode iPhoneOS SDK is required" >&2
  exit 1
fi

targets=(aarch64-apple-ios aarch64-apple-ios-sim)
if (($# > 0)); then
  targets=("$@")
fi

for target in "${targets[@]}"; do
  skia_uri="$(
    "$workspace_root/scripts/fetch-skia.sh" \
      "$target" \
      "${SKIA_CACHE_DIR:-$workspace_root/target/skia}"
  )"
  SKIA_BINARIES_URL="$skia_uri" cargo check \
    --manifest-path "$workspace_root/Cargo.toml" \
    --package gta-claw-ios-shell \
    --target "$target" \
    --locked
done
