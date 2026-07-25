#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/worktree-git.sh"
bootstrap_windows_worktree_git "$(cd "$SCRIPT_DIR/../.." && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/container-trust.sh"
source "$SCRIPT_DIR/lib/container-mount.sh"

require_linux
for tool in docker findmnt git id python3 realpath stat tar; do
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
: "${GTA_CLAW_TARGET_ROOT:?GTA_CLAW_TARGET_ROOT must select a dedicated external target root}"
: "${TMPDIR:?TMPDIR must select a dedicated external temporary root}"

target_root="$(canonical_target_root)"
git_common_dir="$(git -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir)"
assert_isolated_target_root "$REPO_ROOT" "$git_common_dir" "$target_root"
assert_no_path_overlap "$REPO_ROOT" "source repository" "$TMPDIR" "snapshot temp root"
assert_no_path_overlap "$git_common_dir" "Git common directory" "$TMPDIR" "snapshot temp root"
assert_no_path_overlap "$target_root" "target root" "$TMPDIR" "snapshot temp root"
validate_absolute_path "$host_manifest" "BUILD_MANIFEST"
[[ "$host_manifest" == "$target_root/"*/build-manifest.json ]] ||
  die "BUILD_MANIFEST must be in a direct private target child"
build_component="${host_manifest#"$target_root/"}"
build_component="${build_component%%/*}"
validate_safe_component "$build_component" "build component"
validate_new_private_root_path "$OUTPUT_ROOT" "OUTPUT_ROOT"
output_component="${OUTPUT_ROOT#"$target_root/"}"
validate_safe_component "$output_component" "output component"
[[ "$build_component" != "$output_component" ]] ||
  die "build and package output components must differ"

trap 'cleanup_container_resources "$?"' EXIT
trap 'cleanup_container_resources 129' HUP
trap 'cleanup_container_resources 130' INT
trap 'cleanup_container_resources 143' TERM
create_verified_source_snapshot "$REPO_ROOT"
open_build_component "$target_root" "$build_component"
prepare_output_component "$target_root" "$output_component"
assert_no_path_overlap \
  "$SOURCE_SNAPSHOT_DIRECTORY" \
  "immutable source snapshot" \
  "$target_root" \
  "target root"
assert_no_path_overlap \
  "$SOURCE_SNAPSHOT_DIRECTORY" \
  "immutable source snapshot" \
  "$BUILD_COMPONENT_PATH" \
  "build component"
assert_no_path_overlap \
  "$SOURCE_SNAPSHOT_DIRECTORY" \
  "immutable source snapshot" \
  "$OUTPUT_COMPONENT_PATH" \
  "package output"
[[ "$BUILD_COMPONENT_ID" != "$OUTPUT_COMPONENT_ID" ]] ||
  die "build and package output identities are aliased"
source_receipt="$(trust_receipt "$SOURCE_SNAPSHOT_DIRECTORY" "immutable source snapshot")"
repository_receipt="$(trust_receipt "$REPO_ROOT" "source repository")"
git_receipt="$(trust_receipt "$git_common_dir" "Git common directory")"
build_receipt="$(trust_receipt "$BUILD_COMPONENT_PATH" "build component")"
output_receipt="$(trust_receipt "$OUTPUT_COMPONENT_PATH" "package output")"

image_tag="gta-claw-linux-build:rust-${LINUX_RUST_TOOLCHAIN}-bookworm"
packaging_image_id="$(docker image inspect --format '{{.Id}}' "$image_tag")"
[[ "$packaging_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "packaging image ID is invalid"

exec {source_fd}<"$SOURCE_SNAPSHOT_DIRECTORY"
create_anchored_mounts \
  "/proc/$BASHPID/fd/$source_fd" \
  "/proc/$BASHPID/fd/$OUTPUT_COMPONENT_FD" \
  "/proc/$BASHPID/fd/$BUILD_COMPONENT_FD"
docker run --rm \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges \
  --env "PACKAGE_RELEASE=$LINUX_PACKAGE_RELEASE" \
  --env "PACKAGING_IMAGE_ID=$packaging_image_id" \
  --env IMMUTABLE_SOURCE_SNAPSHOT=1 \
  --env "SOURCE_COMMIT=$SOURCE_COMMIT" \
  --env "SOURCE_TREE=$SOURCE_TREE" \
  --env "SOURCE_TREE_RECEIPT=$SOURCE_TREE_RECEIPT" \
  --env "SOURCE_DATE_EPOCH=$SOURCE_EPOCH" \
  --env "SAFEIO_RETURN_UID=$(id -u)" \
  --env "SAFEIO_RETURN_GID=$(id -g)" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/source,target=/workspace,readonly" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/build,target=/gta-claw-build,readonly" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/output,target=/gta-claw-output" \
  --workdir /workspace \
  "$packaging_image_id" \
  /usr/local/bin/gta-claw-safeio \
  run-mounted-package \
  /gta-claw-build \
  /gta-claw-output \
  -- \
  bash -c \
  'exec ./packaging/linux/package.sh "$1" "$BUILD_MANIFEST" "$2"' \
  _ \
  "$arch" \
  "$expected_build_key_sha"
cleanup_anchored_mounts
verify_container_transaction_receipts
[[ "$(trust_receipt "$SOURCE_SNAPSHOT_DIRECTORY" "immutable source snapshot")" == \
  "$source_receipt" ]] || die "source snapshot receipt changed"
[[ "$(trust_receipt "$REPO_ROOT" "source repository")" == "$repository_receipt" ]] ||
  die "source repository receipt changed"
[[ "$(trust_receipt "$git_common_dir" "Git common directory")" == "$git_receipt" ]] ||
  die "Git common directory receipt changed"
[[ "$(trust_receipt "$BUILD_COMPONENT_PATH" "build component")" == "$build_receipt" ]] ||
  die "build component receipt changed"
[[ "$(trust_receipt "$OUTPUT_COMPONENT_PATH" "package output")" == "$output_receipt" ]] ||
  die "package output receipt changed"
cleanup_container_trust
trap - EXIT HUP INT TERM

printf '%s\n' "$OUTPUT_ROOT"
