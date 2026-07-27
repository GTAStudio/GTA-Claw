#!/usr/bin/env bash

ANCHORED_MOUNT_ROOT=""

cleanup_anchored_mounts() {
  local root
  if [[ -n "$ANCHORED_MOUNT_ROOT" ]]; then
    root="$ANCHORED_MOUNT_ROOT"
    sudo umount "$root/target" >/dev/null 2>&1 || true
    sudo umount "$root/repository" >/dev/null 2>&1 || true
    sudo rmdir "$root/target" "$root/repository" \
      >/dev/null 2>&1 || true
    sudo rmdir "$root" >/dev/null 2>&1 || true
    if [[ -e "$root" || -L "$root" ]]; then
      printf 'error: failed to clean anchored mount root: %s\n' "$root" >&2
      return 1
    fi
    ANCHORED_MOUNT_ROOT=""
  fi
}

create_anchored_mounts() {
  local repository_fd_path="$1"
  local target_fd_path="$2"
  ANCHORED_MOUNT_ROOT="$(
    sudo mktemp -d /run/gta-claw-packaging.XXXXXXXXXX
  )"
  trap cleanup_anchored_mounts EXIT INT TERM
  sudo chmod 0700 "$ANCHORED_MOUNT_ROOT"
  sudo mkdir -m 0700 \
    "$ANCHORED_MOUNT_ROOT/repository" \
    "$ANCHORED_MOUNT_ROOT/target"
  sudo mount --bind "$repository_fd_path/" "$ANCHORED_MOUNT_ROOT/repository"
  sudo mount --bind "$target_fd_path/" "$ANCHORED_MOUNT_ROOT/target"
  [[ "$(sudo stat -Lc '%d:%i' "$ANCHORED_MOUNT_ROOT/repository")" == \
    "$(stat -Lc '%d:%i' "$repository_fd_path")" ]] ||
    die "anchored repository mount identity mismatch"
  [[ "$(sudo stat -Lc '%d:%i' "$ANCHORED_MOUNT_ROOT/target")" == \
    "$(stat -Lc '%d:%i' "$target_fd_path")" ]] ||
    die "anchored target mount identity mismatch"
}
