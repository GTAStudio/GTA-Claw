#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/container-mount.sh"

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
validate_safe_component "$target_relative" "CARGO_TARGET_DIR component"

build_input_umask="${BUILD_INPUT_UMASK:-002}"
case "$build_input_umask" in
  000 | 002) ;;
  *) die "BUILD_INPUT_UMASK must be 000 or 002" ;;
esac

recipe_sha="$(sha256_file "$SCRIPT_DIR/Dockerfile.build")"
image_tag="gta-claw-linux-build:rust-${LINUX_RUST_TOOLCHAIN}-bookworm"
git -C "$REPO_ROOT" archive --format=tar HEAD |
docker build \
  --file packaging/linux/Dockerfile.build \
  --build-arg "DEBIAN_SNAPSHOT=$LINUX_DEBIAN_SNAPSHOT" \
  --tag "$image_tag" \
  -
environment_image_id="$(docker image inspect --format '{{.Id}}' "$image_tag")"
[[ "$environment_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  die "pinned build environment produced an invalid image ID"

git_common_dir="$(git -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir)"
git_dir="$(git -C "$REPO_ROOT" rev-parse --path-format=absolute --git-dir)"
if [[ "$git_dir" == "$git_common_dir" ]]; then
  git_relative=""
elif [[ "$git_dir" == "$git_common_dir/"* ]]; then
  git_relative="${git_dir#"$git_common_dir/"}"
else
  die "worktree Git directory is outside the common Git directory"
fi
container_git_dir="/gta-claw-git${git_relative:+/$git_relative}"
exec {repo_mount_fd}<"$REPO_ROOT"
exec {target_mount_fd}<"$target_root"
exec {git_mount_fd}<"$git_common_dir"
repo_mount="/proc/$BASHPID/fd/$repo_mount_fd"
target_mount="/proc/$BASHPID/fd/$target_mount_fd"
git_mount="/proc/$BASHPID/fd/$git_mount_fd"
repo_mount_id="$(stat -Lc '%d:%i' "$repo_mount")"
target_mount_id="$(stat -Lc '%d:%i' "$target_mount")"
git_mount_id="$(stat -Lc '%d:%i' "$git_mount")"
create_anchored_mounts "$repo_mount" "$target_mount" "$git_mount"
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
  --env "DEBIAN_SNAPSHOT=$LINUX_DEBIAN_SNAPSHOT" \
  --env "RUSTFLAGS=-Dwarnings" \
  --env GIT_CONFIG_COUNT=1 \
  --env GIT_CONFIG_KEY_0=safe.directory \
  --env GIT_CONFIG_VALUE_0=/workspace \
  --env "SAFEIO_RETURN_UID=$(id -u)" \
  --env "SAFEIO_RETURN_GID=$(id -g)" \
  --env SAFEIO_TARGET_PATH=/gta-claw-target \
  --env "GIT_DIR=$container_git_dir" \
  --env GIT_WORK_TREE=/workspace \
  --env GIT_OPTIONAL_LOCKS=0 \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/repository,target=/workspace,readonly" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/target,target=/gta-claw-target" \
  --mount "type=bind,source=$ANCHORED_MOUNT_ROOT/git,target=/gta-claw-git,readonly" \
  --workdir /workspace \
  "$image_tag" \
  /usr/local/bin/gta-claw-safeio \
  run-create \
  "$target_relative" \
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
[[ "$(stat -Lc '%d:%i' "$REPO_ROOT")" == "$repo_mount_id" ]] ||
  die "repository path identity changed during container build"
[[ "$(stat -Lc '%d:%i' "$target_root")" == "$target_mount_id" ]] ||
  die "target path identity changed during container build"
[[ "$(stat -Lc '%d:%i' "$git_common_dir")" == "$git_mount_id" ]] ||
  die "Git common directory identity changed during container build"
[[ "$(stat -Lc '%d:%i' "$CARGO_TARGET_DIR")" == \
  "$(stat -Lc '%d:%i' "$target_mount/$target_relative")" ]] ||
  die "Cargo output component identity changed during container build"
[[ "$container_manifest" == "/proc/self/fd/"*"/build-manifest.json|"* ]] ||
  die "build container returned an unexpected manifest path: $container_manifest"
container_fingerprint="${container_manifest##*|}"
[[ "$container_fingerprint" =~ ^[0-9a-f]{64}$ ]] ||
  die "build container returned an invalid key fingerprint"
printf '%s|%s\n' "$CARGO_TARGET_DIR/build-manifest.json" "$container_fingerprint"
