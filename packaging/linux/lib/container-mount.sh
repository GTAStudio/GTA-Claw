#!/usr/bin/env bash

ANCHORED_MOUNT_ROOT=""

cleanup_anchored_mounts() {
  if [[ -n "$ANCHORED_MOUNT_ROOT" ]]; then
    sudo umount "$ANCHORED_MOUNT_ROOT/target" >/dev/null 2>&1 || true
    sudo umount "$ANCHORED_MOUNT_ROOT/repository" >/dev/null 2>&1 || true
    sudo rmdir "$ANCHORED_MOUNT_ROOT/target" "$ANCHORED_MOUNT_ROOT/repository" \
      >/dev/null 2>&1 || true
    sudo rmdir "$ANCHORED_MOUNT_ROOT" >/dev/null 2>&1 || true
    ANCHORED_MOUNT_ROOT=""
  fi
}

create_anchored_mounts() {
  local repository_fd_path="$1"
  local target_fd_path="$2"
  ANCHORED_MOUNT_ROOT="$(
    sudo mktemp -d /run/gta-claw-packaging.XXXXXXXXXX
  )"
  sudo chmod 0700 "$ANCHORED_MOUNT_ROOT"
  sudo mkdir -m 0700 \
    "$ANCHORED_MOUNT_ROOT/repository" \
    "$ANCHORED_MOUNT_ROOT/target"
  sudo mount --bind "$repository_fd_path/" "$ANCHORED_MOUNT_ROOT/repository"
  sudo mount --bind "$target_fd_path/" "$ANCHORED_MOUNT_ROOT/target"
  mountpoint -q "$ANCHORED_MOUNT_ROOT/repository" ||
    die "failed to create anchored repository mount"
  mountpoint -q "$ANCHORED_MOUNT_ROOT/target" ||
    die "failed to create anchored target mount"
  trap cleanup_anchored_mounts EXIT INT TERM
}
