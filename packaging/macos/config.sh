#!/usr/bin/env bash

: "${APP_NAME:=GTA Claw}"
if [[ "${EXECUTABLE_NAME:-gta-claw-desktop}" != "gta-claw-desktop" ]]; then
  die "EXECUTABLE_NAME must be exactly gta-claw-desktop"
fi
EXECUTABLE_NAME="gta-claw-desktop"
: "${BUNDLE_ID:=com.gtastudio.gta-claw}"
: "${MINIMUM_MACOS_VERSION:=14.0}"
: "${APP_CATEGORY:=public.app-category.developer-tools}"
: "${APP_COPYRIGHT:=Copyright 2026 GTAStudio. Licensed under MIT.}"
: "${NORMALIZED_MTIME:=200001010000}"
PINNED_RUST_VERSION="1.97.1"

if [[ -z "${VERSION:-}" ]]; then
  VERSION="$(
    awk '
      /^\[workspace\.package\]$/ { in_package = 1; next }
      /^\[/ { in_package = 0 }
      in_package && $1 == "version" {
        gsub(/"/, "", $3)
        print $3
        exit
      }
    ' "$REPO_ROOT/Cargo.toml"
  )"
fi
: "${BUILD_VERSION:=$VERSION}"

validate_safe_component "$APP_NAME" APP_NAME
validate_safe_component "$EXECUTABLE_NAME" EXECUTABLE_NAME
validate_bundle_id "$BUNDLE_ID"
validate_release_version "$VERSION"
validate_build_version "$BUILD_VERSION"
validate_macos_version "$MINIMUM_MACOS_VERSION"

readonly APP_NAME EXECUTABLE_NAME BUNDLE_ID MINIMUM_MACOS_VERSION
readonly APP_CATEGORY APP_COPYRIGHT NORMALIZED_MTIME PINNED_RUST_VERSION VERSION BUILD_VERSION
