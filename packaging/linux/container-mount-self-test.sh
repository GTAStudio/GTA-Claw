#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
work="$SCRIPT_DIR/.container-mount-self-test-$$"
rm -rf -- "$work"
mkdir -m 0700 -- "$work"
trap 'rm -rf -- "$work"' EXIT INT TERM

run_mount_failure() (
  set -e
  source "$SCRIPT_DIR/lib/container-mount.sh"
  mount_root="$work/partial-root"
  sudo() {
    local tool="$1"
    shift
    case "$tool" in
      mktemp)
        mkdir -m 0700 -- "$mount_root"
        printf '%s\n' "$mount_root"
        ;;
      mount) exit 42 ;;
      umount) return 0 ;;
      *) command "$tool" "$@" ;;
    esac
  }
  create_anchored_mounts "$work/repository-source" "$work/target-source"
)

if run_mount_failure >"$work/failure.stdout" 2>"$work/failure.stderr"; then
  echo "injected mount failure unexpectedly succeeded" >&2
  exit 1
fi
[[ ! -e "$work/partial-root" ]] ||
  {
    echo "partial anchored mount setup was not rolled back" >&2
    exit 1
  }

(
  source "$SCRIPT_DIR/lib/container-mount.sh"
  mount_root="$work/cleanup-root"
  mkdir -m 0700 -- "$mount_root" "$mount_root/repository" "$mount_root/target"
  ANCHORED_MOUNT_ROOT="$mount_root"
  sudo() {
    local tool="$1"
    shift
    case "$tool" in
      umount) return 0 ;;
      *) command "$tool" "$@" ;;
    esac
  }
  cleanup_anchored_mounts
  [[ -z "$ANCHORED_MOUNT_ROOT" && ! -e "$mount_root" ]]
)

echo "Anchored mount cleanup self-tests passed (2 cases)"
