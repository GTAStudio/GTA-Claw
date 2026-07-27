#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: build-for-ios.sh <cargo-binary> [cargo arguments...]}"
shift
workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${CONFIGURATION:?Xcode CONFIGURATION is required}"
: "${ARCHS:?Xcode ARCHS is required}"
: "${DERIVED_FILE_DIR:?Xcode DERIVED_FILE_DIR is required}"
: "${TARGET_BUILD_DIR:?Xcode TARGET_BUILD_DIR is required}"
: "${EXECUTABLE_PATH:?Xcode EXECUTABLE_PATH is required}"

if [[ "$CONFIGURATION" == "Debug" ]]; then
  cargo_profile="debug"
  cargo_profile_args=()
else
  cargo_profile="release"
  cargo_profile_args=(--release)
  export CARGO_PROFILE_RELEASE_DEBUG="${CARGO_PROFILE_RELEASE_DEBUG:-1}"
fi

export CARGO_TARGET_DIR="$DERIVED_FILE_DIR/cargo"
simulator=0
if [[ "${LLVM_TARGET_TRIPLE_SUFFIX:-}" == "-simulator" ]]; then
  simulator=1
fi

executables=()
for arch in $ARCHS; do
  case "$arch:$simulator" in
    arm64:0) cargo_target="aarch64-apple-ios" ;;
    arm64:1) cargo_target="aarch64-apple-ios-sim" ;;
    *)
      echo "Unsupported Xcode architecture/simulator pair: $arch/$simulator" >&2
      exit 1
      ;;
  esac

  skia_uri="$(
    "$workspace_root/scripts/fetch-skia.sh" \
      "$cargo_target" \
      "${SKIA_CACHE_DIR:-$DERIVED_FILE_DIR/skia}"
  )"
  SKIA_BINARIES_URL="$skia_uri" cargo build \
    --manifest-path "$workspace_root/Cargo.toml" \
    --package gta-claw-ios-shell \
    --bin "$binary" \
    --target "$cargo_target" \
    --locked \
    "${cargo_profile_args[@]}" \
    "$@"
  executables+=("$CARGO_TARGET_DIR/$cargo_target/$cargo_profile/$binary")
done

mkdir -p "$(dirname "$TARGET_BUILD_DIR/$EXECUTABLE_PATH")"
xcrun lipo -create -output "$TARGET_BUILD_DIR/$EXECUTABLE_PATH" "${executables[@]}"

if [[ -n "${DWARF_DSYM_FOLDER_PATH:-}" && -n "${DWARF_DSYM_FILE_NAME:-}" ]]; then
  mkdir -p "$DWARF_DSYM_FOLDER_PATH"
  xcrun dsymutil "$TARGET_BUILD_DIR/$EXECUTABLE_PATH" \
    -o "$DWARF_DSYM_FOLDER_PATH/$DWARF_DSYM_FILE_NAME"
fi

if [[ "$simulator" -eq 0 && "${CODE_SIGNING_ALLOWED:-YES}" != "NO" && -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]]; then
  entitlements="${TARGET_TEMP_DIR:-}/${PRODUCT_NAME:-GTA Claw}.app.xcent"
  if [[ -s "$entitlements" ]]; then
    codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" \
      --entitlements "$entitlements" \
      "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"
  else
    codesign --force --sign "$EXPANDED_CODE_SIGN_IDENTITY" \
      "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"
  fi
fi
