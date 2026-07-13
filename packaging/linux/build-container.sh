#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in docker id sha256sum; do
  require_tool "$tool"
done
[[ "$#" -eq 1 ]] || die "usage: build-container.sh ARCH"
arch="$1"
arch_target "$arch" >/dev/null

: "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR must select a new private build root}"
target_root="$(canonical_target_root)"
validate_new_private_root_path "$CARGO_TARGET_DIR" "CARGO_TARGET_DIR"
target_relative="${CARGO_TARGET_DIR#"$target_root/"}"
container_target="/workspace/target/$target_relative"

build_input_umask="${BUILD_INPUT_UMASK:-002}"
case "$build_input_umask" in
  000 | 002) ;;
  *) die "BUILD_INPUT_UMASK must be 000 or 002" ;;
esac

recipe_sha="$(sha256_file "$SCRIPT_DIR/Dockerfile.build")"
image_tag="gta-claw-linux-build:rust-${LINUX_RUST_TOOLCHAIN}-bookworm"
docker build \
  --file "$SCRIPT_DIR/Dockerfile.build" \
  --build-arg "DEBIAN_SNAPSHOT=$LINUX_DEBIAN_SNAPSHOT" \
  --tag "$image_tag" \
  "$REPO_ROOT"

container_manifest="$(
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env "BUILD_IMAGE=$LINUX_BUILD_IMAGE" \
  --env "BUILD_INPUT_UMASK=$build_input_umask" \
  --env "BUILD_RECIPE_SHA256=$recipe_sha" \
  --env "CARGO_HOME=$container_target/cargo-home" \
  --env "CARGO_TARGET_DIR=$container_target" \
  --env "DEBIAN_SNAPSHOT=$LINUX_DEBIAN_SNAPSHOT" \
  --env "HOME=$container_target/home" \
  --env "RUSTFLAGS=-Dwarnings" \
  --volume "$REPO_ROOT:/workspace:ro" \
  --volume "$target_root:/workspace/target:rw" \
  --workdir /workspace \
  "$image_tag" \
  bash -c "umask '$build_input_umask'; ./packaging/linux/build.sh '$arch'"
)"
[[ "$container_manifest" == "$container_target/build-manifest.json" ]] ||
  die "build container returned an unexpected manifest path: $container_manifest"
printf '%s\n' "$CARGO_TARGET_DIR/build-manifest.json"
