#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in docker id; do
  require_tool "$tool"
done
[[ "$#" -eq 3 ]] ||
  die "usage: package-container.sh ARCH BUILD_MANIFEST EXPECTED_BUILD_KEY_SHA256"
arch="$1"
host_manifest="$2"
expected_build_key_sha="$3"
arch_target "$arch" >/dev/null
[[ "$expected_build_key_sha" =~ ^[0-9a-f]{64}$ ]] ||
  die "invalid expected build-key fingerprint"
: "${OUTPUT_ROOT:?OUTPUT_ROOT must select a new private package root}"

target_root="$(canonical_target_root)"
validate_absolute_path "$host_manifest" "BUILD_MANIFEST"
[[ "$host_manifest" == "$target_root/"*/build-manifest.json ]] ||
  die "BUILD_MANIFEST must be in a direct private target child"
build_component="${host_manifest#"$target_root/"}"
build_component="${build_component%%/*}"
validate_safe_component "$build_component" "build component"
validate_new_private_root_path "$OUTPUT_ROOT" "OUTPUT_ROOT"
output_component="${OUTPUT_ROOT#"$target_root/"}"
validate_safe_component "$output_component" "output component"

image_tag="gta-claw-linux-build:rust-${LINUX_RUST_TOOLCHAIN}-bookworm"
packaging_image_id="$(docker image inspect --format '{{.Id}}' "$image_tag")"
[[ "$packaging_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "packaging image ID is invalid"
exec {repo_mount_fd}<"$REPO_ROOT"
exec {target_mount_fd}<"$target_root"
repo_mount_id="$(stat -Lc '%d:%i' "/proc/$BASHPID/fd/$repo_mount_fd")"
target_mount_id="$(stat -Lc '%d:%i' "/proc/$BASHPID/fd/$target_mount_fd")"
docker run --rm \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges \
  --env "PACKAGE_RELEASE=$LINUX_PACKAGE_RELEASE" \
  --env "PACKAGING_IMAGE_ID=$packaging_image_id" \
  --env "SAFEIO_RETURN_UID=$(id -u)" \
  --env "SAFEIO_RETURN_GID=$(id -g)" \
  --mount "type=bind,source=/proc/$BASHPID/fd/$repo_mount_fd,target=/workspace,readonly" \
  --mount "type=bind,source=/proc/$BASHPID/fd/$target_mount_fd,target=/workspace/target" \
  --workdir /workspace \
  "$image_tag" \
  /usr/local/bin/gta-claw-safeio \
  run-package \
  "$build_component" \
  "$output_component" \
  -- \
  bash -c \
  'exec ./packaging/linux/package.sh "$1" "$BUILD_MANIFEST" "$2"' \
  _ \
  "$arch" \
  "$expected_build_key_sha"
[[ "$(stat -Lc '%d:%i' "$REPO_ROOT")" == "$repo_mount_id" ]] ||
  die "repository path identity changed during package transaction"
[[ "$(stat -Lc '%d:%i' "$target_root")" == "$target_mount_id" ]] ||
  die "target path identity changed during package transaction"
[[ "$(stat -Lc '%d:%i' "$OUTPUT_ROOT")" == \
  "$(stat -Lc '%d:%i' "/proc/$BASHPID/fd/$target_mount_fd/$output_component")" ]] ||
  die "package output component identity changed during transaction"

printf '%s\n' "$OUTPUT_ROOT"
