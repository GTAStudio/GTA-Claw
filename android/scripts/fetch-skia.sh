#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: fetch-skia.sh <target> [cache-directory]}"
cache_directory="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/target/skia}"
release="0.99.0"

case "$target" in
  aarch64-linux-android)
    name="skia-binaries-a25a0fdb7d90429aa2d1-aarch64-linux-android-gl-jpegd-jpege-pdf-textlayout-vulkan.tar.gz"
    digest="46f267b4754ca3af59b4ef30d273425c9585f2cc5fd20481bac4125c1e6f8217"
    ;;
  x86_64-linux-android)
    name="skia-binaries-a25a0fdb7d90429aa2d1-x86_64-linux-android-gl-jpegd-jpege-pdf-textlayout-vulkan.tar.gz"
    digest="d691c9891d153466d5b99c0003fc6891482b97fb900b72c27b460b648f4e9534"
    ;;
  *)
    echo "No reviewed Skia archive pin exists for target: $target" >&2
    exit 1
    ;;
esac

url="https://github.com/rust-skia/skia-binaries/releases/download/$release/$name"
mkdir -p "$cache_directory"
archive="$cache_directory/$name"
partial="$archive.part.$$"
trap 'rm -f "$partial"' EXIT

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

if [[ ! -f "$archive" ]] || [[ "$(sha256 "$archive")" != "$digest" ]]; then
  rm -f "$archive"
  echo "Fetching reviewed Skia archive for $target" >&2
  curl --fail --silent --show-error --location --retry 3 \
    --proto '=https' --tlsv1.2 \
    "$url" \
    --output "$partial"
  actual="$(sha256 "$partial")"
  if [[ "$actual" != "$digest" ]]; then
    echo "Skia archive digest mismatch for $target: expected $digest, got $actual" >&2
    exit 1
  fi
  mv "$partial" "$archive"
fi

actual="$(sha256 "$archive")"
if [[ "$actual" != "$digest" ]]; then
  echo "Cached Skia archive digest mismatch for $target: expected $digest, got $actual" >&2
  exit 1
fi

absolute_directory="$(cd "$(dirname "$archive")" && pwd -P)"
absolute="$absolute_directory/$(basename "$archive")"
# skia-bindings 0.99.0 strips this prefix and passes the remainder directly to
# fs::read; it does not URL-decode percent escapes.
printf 'file://%s\n' "$absolute"
