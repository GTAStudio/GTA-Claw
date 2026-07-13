#!/usr/bin/env bash

# shellcheck disable=SC2034
LINUX_PACKAGE_NAME="gta-claw"
# shellcheck disable=SC2034
LINUX_DAEMON_NAME="gta-claw-daemon"
# shellcheck disable=SC2034
LINUX_CLI_NAME="gta-claw-cli"
# shellcheck disable=SC2034
LINUX_PACKAGE_RELEASE="${PACKAGE_RELEASE:-1}"
# shellcheck disable=SC2034
LINUX_RUST_TOOLCHAIN="1.97.0"
# shellcheck disable=SC2034
LINUX_GLIBC_CEILING="2.36"
# shellcheck disable=SC2034
LINUX_BUILD_IMAGE="rust:1.97.0-bookworm@sha256:7d0723df719e7f213b69dc7c8c595985c3f4b060cfbee4f7bc0e347a86fe3b6a"
# shellcheck disable=SC2034
LINUX_DEBIAN_SNAPSHOT="20260701T000000Z"

workspace_version="$(
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

: "${VERSION:=$workspace_version}"
: "${SOURCE_DATE_EPOCH:=$(git -C "$REPO_ROOT" log -1 --format=%ct)}"

validate_release_version "$VERSION"
[[ "$VERSION" == "$workspace_version" ]] ||
  die "VERSION must match the Cargo workspace version $workspace_version"
[[ "$LINUX_PACKAGE_RELEASE" =~ ^[1-9][0-9]{0,3}$ ]] ||
  die "PACKAGE_RELEASE must be an integer from 1 to 9999"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]{9,12}$ ]] ||
  die "SOURCE_DATE_EPOCH must be a Unix timestamp"
