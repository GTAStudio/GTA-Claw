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
for tool in docker findmnt git id python3 realpath sha256sum stat tar; do
  require_tool "$tool"
done
[[ "$#" -eq 1 ]] || die "usage: build-container.sh ARCH"
arch="$1"
arch_target "$arch" >/dev/null

: "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR must select a new private build root}"
: "${GTA_CLAW_TARGET_ROOT:?GTA_CLAW_TARGET_ROOT must select a dedicated external target root}"
: "${TMPDIR:?TMPDIR must select a dedicated external temporary root}"
: "${CARGO_BUILD_JOBS:=4}"
[[ "$CARGO_BUILD_JOBS" =~ ^[1-9][0-9]?$ && "$CARGO_BUILD_JOBS" -le 64 ]] ||
  die "CARGO_BUILD_JOBS must be an integer from 1 to 64"
target_root="$(canonical_target_root)"
git_common_dir="$(git -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir)"
assert_isolated_target_root "$REPO_ROOT" "$git_common_dir" "$target_root"
assert_no_path_overlap "$REPO_ROOT" "source repository" "$TMPDIR" "snapshot temp root"
assert_no_path_overlap "$git_common_dir" "Git common directory" "$TMPDIR" "snapshot temp root"
assert_no_path_overlap "$target_root" "target root" "$TMPDIR" "snapshot temp root"
validate_new_private_root_path "$CARGO_TARGET_DIR" "CARGO_TARGET_DIR"
target_relative="${CARGO_TARGET_DIR#"$target_root/"}"
validate_safe_component "$target_relative" "CARGO_TARGET_DIR component"

build_input_umask="${BUILD_INPUT_UMASK:-002}"
case "$build_input_umask" in
  000 | 002) ;;
  *) die "BUILD_INPUT_UMASK must be 000 or 002" ;;
esac

trap 'cleanup_container_resources "$?"' EXIT
trap 'cleanup_container_resources 129' HUP
trap 'cleanup_container_resources 130' INT
trap 'cleanup_container_resources 143' TERM
create_verified_source_snapshot "$REPO_ROOT"
assert_no_path_overlap \
  "$SOURCE_SNAPSHOT_DIRECTORY" \
  "immutable source snapshot" \
  "$target_root" \
  "target root"
prepare_output_component "$target_root" "$target_relative"
assert_no_path_overlap \
  "$SOURCE_SNAPSHOT_DIRECTORY" \
  "immutable source snapshot" \
  "$OUTPUT_COMPONENT_PATH" \
  "build output"
source_receipt="$(trust_receipt "$SOURCE_SNAPSHOT_DIRECTORY" "immutable source snapshot")"
repository_receipt="$(trust_receipt "$REPO_ROOT" "source repository")"
git_receipt="$(trust_receipt "$git_common_dir" "Git common directory")"
target_receipt="$(trust_receipt "$target_root" "target root")"
output_receipt="$(trust_receipt "$OUTPUT_COMPONENT_PATH" "build output")"

recipe_sha="$(sha256_file "$SOURCE_SNAPSHOT_DIRECTORY/packaging/linux/Dockerfile.build")"
image_tag="gta-claw-linux-build:rust-${LINUX_RUST_TOOLCHAIN}-bookworm"
image_iid_file="$OUTPUT_COMPONENT_PATH/.build-image-id"
[[ ! -e "$image_iid_file" && ! -L "$image_iid_file" ]] ||
  die "build image ID receipt path already exists"
docker build \
  --provenance=false \
  --iidfile "$image_iid_file" \
  --file "$SOURCE_SNAPSHOT_DIRECTORY/packaging/linux/Dockerfile.build" \
  --build-arg "DEBIAN_SNAPSHOT=$LINUX_DEBIAN_SNAPSHOT" \
  --tag "$image_tag" \
  "$SOURCE_SNAPSHOT_DIRECTORY"
assert_regular_unaliased "$image_iid_file" "build image ID receipt"
environment_image_id="$(cat "$image_iid_file")"
[[ "$environment_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "pinned build environment produced an invalid image ID"
rm -f "$image_iid_file"

exec {source_fd}<"$SOURCE_SNAPSHOT_DIRECTORY"
create_anchored_mounts \
  "/proc/$BASHPID/fd/$source_fd" \
  "/proc/$BASHPID/fd/$OUTPUT_COMPONENT_FD"
container_manifest="$(
  docker run --rm \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --security-opt no-new-privileges \
    --env "BUILD_IMAGE=$LINUX_BUILD_IMAGE" \
    --env "BUILD_INPUT_UMASK=$build_input_umask" \
    --env "BUILD_ENVIRONMENT_IMAGE_ID=$environment_image_id" \
    --env "BUILD_RECIPE_SHA256=$recipe_sha" \
    --env "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS" \
    --env "DEBIAN_SNAPSHOT=$LINUX_DEBIAN_SNAPSHOT" \
    --env IMMUTABLE_SOURCE_SNAPSHOT=1 \
    --env "SOURCE_COMMIT=$SOURCE_COMMIT" \
    --env "SOURCE_TREE=$SOURCE_TREE" \
    --env "SOURCE_TREE_RECEIPT=$SOURCE_TREE_RECEIPT" \
    --env "SOURCE_DATE_EPOCH=$SOURCE_EPOCH" \
    --env "RUSTFLAGS=-Dwarnings" \
    --env "SAFEIO_RETURN_UID=$(id -u)" \
    --env "SAFEIO_RETURN_GID=$(id -g)" \
    --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/source,target=/workspace,readonly" \
    --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/output,target=/gta-claw-output" \
    --workdir /workspace \
    "$environment_image_id" \
    /usr/local/bin/gta-claw-safeio \
    run-mounted \
    /gta-claw-output \
    -- \
    bash -c "
      export CARGO_TARGET_DIR=\"\$OUTPUT_ROOT\"
      export CARGO_HOME=\"\$OUTPUT_ROOT/cargo-home\"
      export HOME=\"\$OUTPUT_ROOT/home\"
      umask '$build_input_umask'
      ./packaging/linux/build.sh '$arch'
    "
)"
cleanup_anchored_mounts
verify_container_transaction_receipts
[[ "$(trust_receipt "$SOURCE_SNAPSHOT_DIRECTORY" "immutable source snapshot")" == \
  "$source_receipt" ]] || die "source snapshot receipt changed"
[[ "$(trust_receipt "$REPO_ROOT" "source repository")" == "$repository_receipt" ]] ||
  die "source repository receipt changed"
[[ "$(trust_receipt "$git_common_dir" "Git common directory")" == "$git_receipt" ]] ||
  die "Git common directory receipt changed"
[[ "$(trust_receipt "$target_root" "target root")" == "$target_receipt" ]] ||
  die "target root receipt changed"
[[ "$(trust_receipt "$OUTPUT_COMPONENT_PATH" "build output")" == "$output_receipt" ]] ||
  die "build output receipt changed"
cleanup_container_trust
trap - EXIT HUP INT TERM

[[ "$container_manifest" == "/proc/self/fd/"*"/build-manifest.json|"* ]] ||
  die "build container returned an unexpected manifest path: $container_manifest"
container_fingerprint="${container_manifest##*|}"
[[ "$container_fingerprint" =~ ^[0-9a-f]{64}$ ]] ||
  die "build container returned an invalid key fingerprint"
printf '%s|%s\n' "$CARGO_TARGET_DIR/build-manifest.json" "$container_fingerprint"
