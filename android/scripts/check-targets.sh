#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [[ -z "$ndk_root" ]]; then
  echo "ANDROID_NDK_HOME or ANDROID_NDK_ROOT must name an installed Android NDK" >&2
  exit 1
fi

host_tag=""
for candidate in darwin-arm64 darwin-x86_64 linux-x86_64; do
  if [[ -d "$ndk_root/toolchains/llvm/prebuilt/$candidate" ]]; then
    host_tag="$candidate"
    break
  fi
done
if [[ -z "$host_tag" ]]; then
  echo "No supported NDK LLVM prebuilt found under $ndk_root" >&2
  exit 1
fi

toolchain="$ndk_root/toolchains/llvm/prebuilt/$host_tag/bin"
targets=(
  aarch64-linux-android
  x86_64-linux-android
)
if (($# > 0)); then
  targets=("$@")
fi

for target in "${targets[@]}"; do
  case "$target" in
    aarch64-linux-android)
      clang="$toolchain/aarch64-linux-android26-clang"
      cargo_linker="CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
      cc="CC_aarch64_linux_android"
      ar="AR_aarch64_linux_android"
      ;;
    x86_64-linux-android)
      clang="$toolchain/x86_64-linux-android26-clang"
      cargo_linker="CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER"
      cc="CC_x86_64_linux_android"
      ar="AR_x86_64_linux_android"
      ;;
    *)
      echo "Unsupported Android target: $target" >&2
      exit 1
      ;;
  esac
  if [[ ! -x "$clang" ]]; then
    echo "Target compiler is missing: $clang" >&2
    exit 1
  fi

  skia_uri="$(
    "$workspace_root/scripts/fetch-skia.sh" \
      "$target" \
      "${SKIA_CACHE_DIR:-$workspace_root/target/skia}"
  )"
  env "$cargo_linker=$clang" "$cc=$clang" "$ar=$toolchain/llvm-ar" \
    "SKIA_BINARIES_URL=$skia_uri" \
    cargo check \
      --manifest-path "$workspace_root/Cargo.toml" \
      --package gta-claw-android-shell \
      --target "$target" \
      --locked
done
