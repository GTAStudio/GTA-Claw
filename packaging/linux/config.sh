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
LINUX_RUST_TOOLCHAIN="1.97.1"
# shellcheck disable=SC2034
LINUX_GLIBC_CEILING="2.36"
# shellcheck disable=SC2034
LINUX_BUILD_IMAGE="rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa"
# shellcheck disable=SC2034
LINUX_DEBIAN_SNAPSHOT="20260701T000000Z"
# shellcheck disable=SC2034
LINUX_MINIMAL_IMAGE="debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df"

workspace_rust_toolchain="$(
  awk -F'"' '$1 ~ /^[[:space:]]*channel[[:space:]]*=/ { print $2; exit }' \
    "$REPO_ROOT/rust-toolchain.toml"
)"
dockerfile_rust_toolchain="$(
  awk -F= '$1 == "ENV RUSTUP_TOOLCHAIN" { print $2; exit }' \
    "$LINUX_DIR/Dockerfile.build"
)"
[[ "$workspace_rust_toolchain" == "$LINUX_RUST_TOOLCHAIN" ]] ||
  die "Linux toolchain $LINUX_RUST_TOOLCHAIN differs from rust-toolchain.toml ($workspace_rust_toolchain)"
[[ "$dockerfile_rust_toolchain" == "$LINUX_RUST_TOOLCHAIN" ]] ||
  die "Dockerfile RUSTUP_TOOLCHAIN differs from pinned Linux toolchain $LINUX_RUST_TOOLCHAIN"

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
