#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:-aarch64-linux-android}"
skia_uri="$(
  "$workspace_root/scripts/fetch-skia.sh" \
    "$target" \
    "${SKIA_CACHE_DIR:-$workspace_root/target/skia}"
)"

if ! cargo install --list | grep -Fx "cargo-apk v0.10.0:" >/dev/null; then
  echo "cargo-apk 0.10.0 is required" >&2
  exit 1
fi

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

lock_before="$(sha256 "$workspace_root/Cargo.lock")"
apk="$workspace_root/target/debug/apk/gta-claw-android.apk"
unaligned="$workspace_root/target/debug/apk/gta-claw-android-unaligned.apk"
rm -f "$apk" "$unaligned"
(
  cd "$workspace_root/apps/gta-claw-android-shell"
  CARGO_NET_OFFLINE=true SKIA_BINARIES_URL="$skia_uri" \
    cargo apk build --target "$target" --lib
)
lock_after="$(sha256 "$workspace_root/Cargo.lock")"
if [[ "$lock_after" != "$lock_before" ]]; then
  echo "cargo-apk changed the locked dependency graph" >&2
  exit 1
fi

test -f "$apk"
printf '%s\n' "$apk"
