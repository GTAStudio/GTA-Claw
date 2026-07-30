#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/container-mount.sh"

require_linux
require_tool docker
[[ "$#" -eq 4 ]] ||
  die "usage: oci-self-test-container.sh ARCH OCI_ARCHIVE BUILD_MANIFEST EXPECTED_BUILD_KEY_SHA256"
arch="$1"
archive="$2"
manifest="$3"
expected_key_sha="$4"
: "${OUTPUT_ROOT:?OUTPUT_ROOT must select a new OCI mutation root}"
target_root="$(canonical_target_root)"
for input in "$archive" "$manifest"; do
  validate_absolute_path "$input" "OCI self-test input"
  [[ "$input" == "$target_root/"* ]] || die "OCI self-test input is outside target"
done
validate_new_private_root_path "$OUTPUT_ROOT" "OUTPUT_ROOT"
build_component="${manifest#"$target_root/"}"
build_component="${build_component%%/*}"
output_component="${OUTPUT_ROOT#"$target_root/"}"
archive_relative="${archive#"$target_root/"}"
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
  --cap-add SETGID \
  --cap-add SETUID \
  --cap-add SYS_CHROOT \
  --security-opt no-new-privileges \
  --env "SAFEIO_RETURN_UID=$(id -u)" \
  --env "SAFEIO_RETURN_GID=$(id -g)" \
  --env "PACKAGING_IMAGE_ID=$packaging_image_id" \
  --env GIT_CONFIG_COUNT=1 \
  --env GIT_CONFIG_KEY_0=safe.directory \
  --env GIT_CONFIG_VALUE_0=/workspace \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/repository,target=/workspace,readonly" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/target,target=/workspace/target" \
  --workdir /workspace \
  "$image" \
  /usr/local/bin/gta-claw-safeio \
  run-package \
  "$build_component" \
  "$output_component" \
  -- \
  bash -c '
    exec ./packaging/linux/oci-self-test.sh \
      "$1" \
      "$2" \
      "$BUILD_MANIFEST" \
      "$3"
  ' \
  _ \
  "/workspace/target/$archive_relative" \
  "$arch" \
  "$expected_key_sha"
cleanup_anchored_mounts
[[ "$(stat -Lc '%d:%i' "$REPO_ROOT")" == "$repo_mount_id" ]] ||
  die "repository path identity changed during OCI mutation transaction"
[[ "$(stat -Lc '%d:%i' "$target_root")" == "$target_mount_id" ]] ||
  die "target path identity changed during OCI mutation transaction"
