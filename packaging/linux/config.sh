#!/usr/bin/env bash

# shellcheck disable=SC2034
LINUX_PACKAGE_NAME="gta-claw"
# shellcheck disable=SC2034
LINUX_DAEMON_NAME="gta-claw-daemon"
# shellcheck disable=SC2034
LINUX_CLI_NAME="gta-claw-cli"
# shellcheck disable=SC2034
LINUX_PACKAGE_RELEASE="1"

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
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]{9,12}$ ]] ||
  die "SOURCE_DATE_EPOCH must be a Unix timestamp"
