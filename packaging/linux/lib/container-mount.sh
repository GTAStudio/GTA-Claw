#!/usr/bin/env bash

ANCHORED_MOUNT_ROOT=""
ANCHORED_SOURCE_MOUNTED=0
ANCHORED_BUILD_MOUNTED=0
ANCHORED_ARTIFACT_MOUNTED=0
ANCHORED_OUTPUT_MOUNTED=0

mount_fault() {
  [[ "${GTA_CLAW_MOUNT_FAULT:-}" != "$1" ]] ||
    die "injected anchored-mount fault: $1"
}

cleanup_anchored_mounts() {
  local failed=0
  if [[ -n "$ANCHORED_MOUNT_ROOT" ]]; then
    if [[ "$ANCHORED_OUTPUT_MOUNTED" -eq 1 ]]; then
      if mountpoint -q "$ANCHORED_MOUNT_ROOT/output"; then
        sudo umount "$ANCHORED_MOUNT_ROOT/output" >/dev/null 2>&1 || failed=1
      fi
      ANCHORED_OUTPUT_MOUNTED=0
    fi
    if [[ "$ANCHORED_ARTIFACT_MOUNTED" -eq 1 ]]; then
      if mountpoint -q "$ANCHORED_MOUNT_ROOT/artifact"; then
        sudo umount "$ANCHORED_MOUNT_ROOT/artifact" >/dev/null 2>&1 || failed=1
      fi
      ANCHORED_ARTIFACT_MOUNTED=0
    fi
    if [[ "$ANCHORED_BUILD_MOUNTED" -eq 1 ]]; then
      if mountpoint -q "$ANCHORED_MOUNT_ROOT/build"; then
        sudo umount "$ANCHORED_MOUNT_ROOT/build" >/dev/null 2>&1 || failed=1
      fi
      ANCHORED_BUILD_MOUNTED=0
    fi
    if [[ "$ANCHORED_SOURCE_MOUNTED" -eq 1 ]]; then
      if mountpoint -q "$ANCHORED_MOUNT_ROOT/source"; then
        sudo umount "$ANCHORED_MOUNT_ROOT/source" >/dev/null 2>&1 || failed=1
      fi
      ANCHORED_SOURCE_MOUNTED=0
    fi
    sudo rmdir \
      "$ANCHORED_MOUNT_ROOT/output" \
      "$ANCHORED_MOUNT_ROOT/artifact" \
      "$ANCHORED_MOUNT_ROOT/build" \
      "$ANCHORED_MOUNT_ROOT/source" \
      >/dev/null 2>&1 || true
    sudo rmdir "$ANCHORED_MOUNT_ROOT" >/dev/null 2>&1 || failed=1
    ANCHORED_MOUNT_ROOT=""
  fi
  return "$failed"
}

create_anchored_mounts() {
  local source_fd_path="$1"
  local output_fd_path="$2"
  local build_fd_path="${3:-}"
  local artifact_fd_path="${4:-}"
  ANCHORED_MOUNT_ROOT="$(
    sudo mktemp -d /run/gta-claw-packaging.XXXXXXXXXX
  )"
  trap cleanup_anchored_mounts EXIT INT TERM
  mount_fault after-root
  sudo chmod 0700 "$ANCHORED_MOUNT_ROOT"
  sudo mkdir -m 0700 \
    "$ANCHORED_MOUNT_ROOT/source" \
    "$ANCHORED_MOUNT_ROOT/build" \
    "$ANCHORED_MOUNT_ROOT/artifact" \
    "$ANCHORED_MOUNT_ROOT/output"
  mount_fault after-directories

  ANCHORED_SOURCE_MOUNTED=1
  sudo mount --bind "$source_fd_path/" "$ANCHORED_MOUNT_ROOT/source"
  mount_fault after-source-bind
  sudo mount -o remount,bind,ro "$ANCHORED_MOUNT_ROOT/source"
  mount_fault after-source-readonly
  [[ "$(sudo stat -Lc '%d:%i' "$ANCHORED_MOUNT_ROOT/source")" == \
    "$(stat -Lc '%d:%i' "$source_fd_path")" ]] ||
    die "anchored source mount identity mismatch"
  mount_fault after-source-identity

  if [[ -n "$build_fd_path" ]]; then
    ANCHORED_BUILD_MOUNTED=1
    sudo mount --bind "$build_fd_path/" "$ANCHORED_MOUNT_ROOT/build"
    mount_fault after-build-bind
    sudo mount -o remount,bind,ro "$ANCHORED_MOUNT_ROOT/build"
    mount_fault after-build-readonly
    [[ "$(sudo stat -Lc '%d:%i' "$ANCHORED_MOUNT_ROOT/build")" == \
      "$(stat -Lc '%d:%i' "$build_fd_path")" ]] ||
      die "anchored build mount identity mismatch"
    mount_fault after-build-identity
  fi

  if [[ -n "$artifact_fd_path" ]]; then
    ANCHORED_ARTIFACT_MOUNTED=1
    sudo mount --bind "$artifact_fd_path/" "$ANCHORED_MOUNT_ROOT/artifact"
    mount_fault after-artifact-bind
    sudo mount -o remount,bind,ro "$ANCHORED_MOUNT_ROOT/artifact"
    mount_fault after-artifact-readonly
    [[ "$(sudo stat -Lc '%d:%i' "$ANCHORED_MOUNT_ROOT/artifact")" == \
      "$(stat -Lc '%d:%i' "$artifact_fd_path")" ]] ||
      die "anchored artifact mount identity mismatch"
    mount_fault after-artifact-identity
  fi

  ANCHORED_OUTPUT_MOUNTED=1
  sudo mount --bind "$output_fd_path/" "$ANCHORED_MOUNT_ROOT/output"
  mount_fault after-output-bind
  [[ "$(sudo stat -Lc '%d:%i' "$ANCHORED_MOUNT_ROOT/output")" == \
    "$(stat -Lc '%d:%i' "$output_fd_path")" ]] ||
    die "anchored output mount identity mismatch"
  mount_fault after-output-identity
}
