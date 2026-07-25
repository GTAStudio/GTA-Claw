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
[[ "$#" -eq 4 ]] ||
  die "usage: oci-self-test-container.sh ARCH OCI_ARCHIVE BUILD_MANIFEST EXPECTED_BUILD_KEY_SHA256"
arch="$1"
archive="$2"
manifest="$3"
expected_key_sha="$4"
: "${OUTPUT_ROOT:?OUTPUT_ROOT must select a new OCI mutation root}"

target_root="$(canonical_target_root)"
git_common_dir="$(git -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir)"
assert_isolated_target_root "$REPO_ROOT" "$git_common_dir" "$target_root"
assert_no_path_overlap "$REPO_ROOT" "source repository" "$TMPDIR" "snapshot temp root"
assert_no_path_overlap "$git_common_dir" "Git common directory" "$TMPDIR" "snapshot temp root"
assert_no_path_overlap "$target_root" "target root" "$TMPDIR" "snapshot temp root"
for input in "$archive" "$manifest"; do
  validate_absolute_path "$input" "OCI self-test input"
  [[ "$input" == "$target_root/"* ]] || die "OCI self-test input is outside target"
done
validate_new_private_root_path "$OUTPUT_ROOT" "OUTPUT_ROOT"
build_component="${manifest#"$target_root/"}"
build_component="${build_component%%/*}"
artifact_component="${archive#"$target_root/"}"
artifact_component="${artifact_component%%/*}"
output_component="${OUTPUT_ROOT#"$target_root/"}"
archive_in_component="${archive#"$target_root/$artifact_component/"}"
validate_safe_component "$build_component" "build component"
validate_safe_component "$artifact_component" "artifact component"
validate_safe_component "$output_component" "output component"
[[ "$archive_in_component" != /* && "$archive_in_component" != *".."* ]] ||
  die "OCI archive path is unsafe within artifact component"

create_verified_source_snapshot "$REPO_ROOT"
trap cleanup_container_trust EXIT INT TERM
open_build_component "$target_root" "$build_component"
open_artifact_component "$target_root" "$artifact_component"
prepare_output_component "$target_root" "$output_component"
assert_no_path_overlap \
  "$SOURCE_SNAPSHOT_DIRECTORY" \
  "immutable source snapshot" \
  "$target_root" \
  "target root"
[[ "$BUILD_COMPONENT_ID" != "$OUTPUT_COMPONENT_ID" &&
  "$ARTIFACT_COMPONENT_ID" != "$OUTPUT_COMPONENT_ID" ]] ||
  die "OCI self-test input and output identities must differ"

image="gta-claw-linux-build:rust-${LINUX_RUST_TOOLCHAIN}-bookworm"
packaging_image_id="$(docker image inspect --format '{{.Id}}' "$image")"
exec {source_fd}<"$SOURCE_SNAPSHOT_DIRECTORY"
create_anchored_mounts \
  "/proc/$BASHPID/fd/$source_fd" \
  "/proc/$BASHPID/fd/$OUTPUT_COMPONENT_FD" \
  "/proc/$BASHPID/fd/$BUILD_COMPONENT_FD" \
  "/proc/$BASHPID/fd/$ARTIFACT_COMPONENT_FD"
trap 'cleanup_anchored_mounts; cleanup_container_trust' EXIT INT TERM
docker run --rm \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --security-opt no-new-privileges \
  --env "SAFEIO_RETURN_UID=$(id -u)" \
  --env "SAFEIO_RETURN_GID=$(id -g)" \
  --env "PACKAGING_IMAGE_ID=$packaging_image_id" \
  --env IMMUTABLE_SOURCE_SNAPSHOT=1 \
  --env "SOURCE_COMMIT=$SOURCE_COMMIT" \
  --env "SOURCE_TREE=$SOURCE_TREE" \
  --env "SOURCE_TREE_RECEIPT=$SOURCE_TREE_RECEIPT" \
  --env "SOURCE_DATE_EPOCH=$SOURCE_EPOCH" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/source,target=/workspace,readonly" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/build,target=/gta-claw-build,readonly" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/artifact,target=/gta-claw-artifact,readonly" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/output,target=/gta-claw-output" \
  --workdir /workspace \
  "$image" \
  /usr/local/bin/gta-claw-safeio \
  run-mounted-package \
  /gta-claw-build \
  /gta-claw-output \
  -- \
  bash -c '
    exec ./packaging/linux/oci-self-test.sh \
      "$1" \
      "$2" \
      "$BUILD_MANIFEST" \
      "$3"
  ' \
  _ \
  "/gta-claw-artifact/$archive_in_component" \
  "$arch" \
  "$expected_key_sha"
cleanup_anchored_mounts
verify_container_transaction_receipts
cleanup_container_trust
trap - EXIT INT TERM
