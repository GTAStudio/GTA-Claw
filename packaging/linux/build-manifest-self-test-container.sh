#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/container-mount.sh"

require_linux
require_tool docker
[[ "$#" -eq 3 ]] ||
  die "usage: build-manifest-self-test-container.sh ARCH BUILD_MANIFEST EXPECTED_BUILD_KEY_SHA256"
arch="$1"
manifest="$2"
expected_key_sha="$3"
: "${OUTPUT_ROOT:?OUTPUT_ROOT must select a new manifest test root}"
target_root="$(canonical_target_root)"
validate_absolute_path "$manifest" "BUILD_MANIFEST"
[[ "$manifest" == "$target_root/"* ]] || die "BUILD_MANIFEST is outside target"
validate_new_private_root_path "$OUTPUT_ROOT" "OUTPUT_ROOT"
build_component="${manifest#"$target_root/"}"
build_component="${build_component%%/*}"
output_component="${OUTPUT_ROOT#"$target_root/"}"
validate_safe_component "$build_component" "build component"
validate_safe_component "$output_component" "output component"

image="gta-claw-linux-build:rust-${LINUX_RUST_TOOLCHAIN}-bookworm"
packaging_image_id="$(docker image inspect --format '{{.Id}}' "$image")"
exec {repo_mount_fd}<"$REPO_ROOT"
exec {target_mount_fd}<"$target_root"
repo_mount_id="$(stat -Lc '%d:%i' "/proc/$BASHPID/fd/$repo_mount_fd")"
target_mount_id="$(stat -Lc '%d:%i' "/proc/$BASHPID/fd/$target_mount_fd")"
create_anchored_mounts \
  "/proc/$BASHPID/fd/$repo_mount_fd" \
  "/proc/$BASHPID/fd/$target_mount_fd"
docker run --rm \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges \
  --env "SAFEIO_RETURN_UID=$(id -u)" \
  --env "SAFEIO_RETURN_GID=$(id -g)" \
  --env SAFEIO_TARGET_PATH=/gta-claw-target \
  --env "PACKAGING_IMAGE_ID=$packaging_image_id" \
  --env GIT_CONFIG_COUNT=1 \
  --env GIT_CONFIG_KEY_0=safe.directory \
  --env GIT_CONFIG_VALUE_0=/workspace \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/repository,target=/workspace,readonly" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/target,target=/gta-claw-target" \
  --workdir /workspace \
  "$image" \
  /usr/local/bin/gta-claw-safeio \
  run-package \
  "$build_component" \
  "$output_component" \
  -- \
  bash -c '
    exec ./packaging/linux/build-manifest-self-test.sh \
      "$BUILD_MANIFEST" \
      "$1" \
      "$2"
  ' \
  _ \
  "$arch" \
  "$expected_key_sha"
cleanup_anchored_mounts
[[ "$(stat -Lc '%d:%i' "$REPO_ROOT")" == "$repo_mount_id" ]] ||
  die "repository path identity changed during manifest test"
[[ "$(stat -Lc '%d:%i' "$target_root")" == "$target_mount_id" ]] ||
  die "target path identity changed during manifest test"
