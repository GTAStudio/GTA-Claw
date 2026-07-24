#!/usr/bin/env bash

ANCHORED_MOUNT_ROOT=""

cleanup_anchored_mounts() {
  if [[ -n "$ANCHORED_MOUNT_ROOT" ]]; then
    sudo umount "$ANCHORED_MOUNT_ROOT/git" >/dev/null 2>&1 || true
    sudo umount "$ANCHORED_MOUNT_ROOT/target" >/dev/null 2>&1 || true
    sudo umount "$ANCHORED_MOUNT_ROOT/repository" >/dev/null 2>&1 || true
    sudo rmdir \
      "$ANCHORED_MOUNT_ROOT/git" \
      "$ANCHORED_MOUNT_ROOT/target" \
      "$ANCHORED_MOUNT_ROOT/repository" \
      >/dev/null 2>&1 || true
    sudo rmdir "$ANCHORED_MOUNT_ROOT" >/dev/null 2>&1 || true
    ANCHORED_MOUNT_ROOT=""
  fi
}

create_anchored_mounts() {
  local repository_fd_path="$1"
  local target_fd_path="$2"
  local git_fd_path="$3"
  ANCHORED_MOUNT_ROOT="$(
    sudo mktemp -d /run/gta-claw-packaging.XXXXXXXXXX
  )"
  sudo chmod 0700 "$ANCHORED_MOUNT_ROOT"
  sudo mkdir -m 0700 \
    "$ANCHORED_MOUNT_ROOT/repository" \
    "$ANCHORED_MOUNT_ROOT/target" \
    "$ANCHORED_MOUNT_ROOT/git"
  sudo mount --bind "$repository_fd_path/" "$ANCHORED_MOUNT_ROOT/repository"
  sudo mount --bind "$target_fd_path/" "$ANCHORED_MOUNT_ROOT/target"
  sudo mount --bind "$git_fd_path/" "$ANCHORED_MOUNT_ROOT/git"
  [[ "$(sudo stat -Lc '%d:%i' "$ANCHORED_MOUNT_ROOT/repository")" == \
    "$(stat -Lc '%d:%i' "$repository_fd_path")" ]] ||
    die "anchored repository mount identity mismatch"
  [[ "$(sudo stat -Lc '%d:%i' "$ANCHORED_MOUNT_ROOT/target")" == \
    "$(stat -Lc '%d:%i' "$target_fd_path")" ]] ||
    die "anchored target mount identity mismatch"
  [[ "$(sudo stat -Lc '%d:%i' "$ANCHORED_MOUNT_ROOT/git")" == \
    "$(stat -Lc '%d:%i' "$git_fd_path")" ]] ||
    die "anchored Git mount identity mismatch"
  trap cleanup_anchored_mounts EXIT INT TERM
}
