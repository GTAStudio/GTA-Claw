#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$SCRIPT_DIR/lib/worktree-git.sh"
bootstrap_windows_worktree_git "$(cd "$SCRIPT_DIR/../.." && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/container-trust.sh"
source "$SCRIPT_DIR/lib/container-mount.sh"

require_linux
for tool in findmnt git mountpoint python3 realpath stat tar; do
  require_tool "$tool"
done
: "${TMPDIR:?TMPDIR is required}"
work="$(mktemp -d "$TMPDIR/gta-claw-container-trust.XXXXXXXX")"
cleanup() {
  sudo umount "$work/bind-alias" >/dev/null 2>&1 || true
  sudo umount "$work/bind-descendant" >/dev/null 2>&1 || true
  cleanup_anchored_mounts || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -m 0700 \
  "$work/source" \
  "$work/source/descendant" \
  "$work/git" \
  "$work/target" \
  "$work/bind-alias" \
  "$work/bind-descendant"

expect_overlap_failure() {
  local name="$1"
  shift
  if ("$@") >/dev/null 2>&1; then
    die "container trust accepted overlapping paths: $name"
  fi
}

expect_overlap_failure same \
  assert_no_path_overlap "$work/source" source "$work/source" target
expect_overlap_failure ancestor \
  assert_no_path_overlap "$work/source" source "$work" target
expect_overlap_failure descendant \
  assert_no_path_overlap "$work/source" source "$work/source/descendant" target
sudo mount --bind "$work/source" "$work/bind-alias"
expect_overlap_failure bind-alias \
  assert_no_path_overlap "$work/source" source "$work/bind-alias" target
sudo umount "$work/bind-alias"
sudo mount --bind "$work/source/descendant" "$work/bind-descendant"
expect_overlap_failure bind-descendant \
  assert_no_path_overlap "$work/source" source "$work/bind-descendant" target
sudo umount "$work/bind-descendant"
assert_no_path_overlap "$work/source" source "$work/target" target

fixture="$work/crlf-repository"
mkdir -m 0700 "$fixture"
unset GIT_DIR GIT_WORK_TREE GIT_OPTIONAL_LOCKS
git -C "$fixture" init -q
git -C "$fixture" config user.name "LP4 Fixture"
git -C "$fixture" config user.email "lp4@example.invalid"
mkdir -p "$fixture/packaging/linux/tests"
cp "$SCRIPT_DIR/tests/verify-git-snapshot.py" \
  "$fixture/packaging/linux/tests/verify-git-snapshot.py"
printf 'embedded-line\n' >"$fixture/embedded.sql"
git -C "$fixture" add embedded.sql packaging/linux/tests/verify-git-snapshot.py
GIT_AUTHOR_DATE=1700000000 GIT_COMMITTER_DATE=1700000000 \
  git -C "$fixture" commit -q -m fixture
create_verified_source_snapshot "$fixture"
lf_tree_receipt="$SOURCE_TREE_RECEIPT"
lf_archive_sha="$(sha256sum "$SOURCE_SNAPSHOT_ARCHIVE" | awk '{ print $1 }')"
cleanup_container_trust
printf 'embedded-line\r\n' >"$fixture/embedded.sql"
create_verified_source_snapshot "$fixture"
[[ "$(sha256sum "$SOURCE_SNAPSHOT_DIRECTORY/embedded.sql" | awk '{ print $1 }')" == \
  "$(git -C "$fixture" show HEAD:embedded.sql | sha256sum | awk '{ print $1 }')" ]] ||
  die "immutable snapshot consumed CRLF checkout bytes instead of Git blob bytes"
[[ "$SOURCE_TREE_RECEIPT" == "$lf_tree_receipt" &&
  "$(sha256sum "$SOURCE_SNAPSHOT_ARCHIVE" | awk '{ print $1 }')" == \
    "$lf_archive_sha" ]] ||
  die "CRLF checkout changed immutable build input or tree receipt"
cleanup_container_trust

mount_source="$work/mount-source"
mount_build="$work/mount-build"
mount_output="$work/mount-output"
mount_artifact="$work/mount-artifact"
mkdir -m 0700 "$mount_source" "$mount_build" "$mount_artifact" "$mount_output"
exec {mount_source_fd}<"$mount_source"
exec {mount_build_fd}<"$mount_build"
exec {mount_output_fd}<"$mount_output"
exec {mount_artifact_fd}<"$mount_artifact"
baseline="$(
  findmnt -rn -o TARGET |
    grep '^/run/gta-claw-packaging\.' || true
)"
for fault in \
  after-root \
  after-directories \
  after-source-bind \
  after-source-readonly \
  after-source-identity \
  after-build-bind \
  after-build-readonly \
  after-build-identity \
  after-artifact-bind \
  after-artifact-readonly \
  after-artifact-identity \
  after-output-bind \
  after-output-identity; do
  if (
    export GTA_CLAW_MOUNT_FAULT="$fault"
    create_anchored_mounts \
      "/proc/$BASHPID/fd/$mount_source_fd" \
      "/proc/$BASHPID/fd/$mount_output_fd" \
      "/proc/$BASHPID/fd/$mount_build_fd" \
      "/proc/$BASHPID/fd/$mount_artifact_fd"
  ) >/dev/null 2>&1; then
    die "anchored mount fault unexpectedly succeeded: $fault"
  fi
  current="$(
    findmnt -rn -o TARGET |
      grep '^/run/gta-claw-packaging\.' || true
  )"
  [[ "$current" == "$baseline" ]] ||
    die "anchored mount fault leaked a /run mount: $fault"
done

echo "Container trust and immutable snapshot self-tests passed"
