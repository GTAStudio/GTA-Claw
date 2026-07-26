#!/usr/bin/env bash

# Moves the app and headless artifacts that the `native` job built and tested to
# the `containers` job, so the bytes we sign are the bytes a test ran against.
#
# A tar is used rather than uploading the bundle as a directory tree because
# actions/upload-artifact does not preserve file modes: every uploaded file
# returns as 0644, which would strip the executable bit from
# Contents/MacOS/gta-claw-desktop and fail assert_app_executable_contract.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_tool tar

[[ "$#" -eq 3 ]] || die "usage: transport.sh [pack|unpack] ARCH ARCHIVE"
mode="$1"
arch="$2"
archive="$3"

case "$arch" in
  arm64 | x86_64) ;;
  *) die "unsupported transport architecture: $arch" ;;
esac

validate_absolute_path_components "$archive" "transport archive"
[[ "$archive" == *.tar ]] || die "transport archive must be an uncompressed .tar: $archive"
case "$archive/" in
  "$OUTPUT_ROOT"/*) die "transport archive must live outside OUTPUT_ROOT: $archive" ;;
esac

members=("apps/$arch" "headless/$arch" "manifests")

pack() {
  local member
  for member in "${members[@]}"; do
    [[ -d "$OUTPUT_ROOT/$member" && ! -L "$OUTPUT_ROOT/$member" ]] ||
      die "transport source is missing or not a real directory: $member"
    reject_symlinks "$OUTPUT_ROOT/$member"
  done
  mkdir -p "$(dirname "$archive")"
  rm -f -- "$archive"
  COPYFILE_DISABLE=1 tar --format ustar -C "$OUTPUT_ROOT" -cf "$archive" "${members[@]}"
  [[ -f "$archive" && ! -L "$archive" ]] || die "transport archive was not created: $archive"
  note "packed the tested $arch build into $archive"
}

# Every entry is checked before a single byte is written, because extraction is
# the moment a hostile archive would escape OUTPUT_ROOT.
assert_archive_entries() {
  local entry
  local line
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    case "$entry" in
      /*) die "transport archive contains an absolute path: $entry" ;;
      *..*) die "transport archive contains a parent traversal: $entry" ;;
      "apps/$arch" | "apps/$arch/"* | "headless/$arch" | "headless/$arch/"*) ;;
      manifests | manifests/*) ;;
      *) die "transport archive contains an unexpected entry: $entry" ;;
    esac
  done < <(tar -tf "$archive")

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    case "${line:0:1}" in
      - | d) ;;
      *) die "transport archive contains a non-regular entry: $line" ;;
    esac
  done < <(tar -tvf "$archive")
}

unpack() {
  local member
  local executable
  [[ -f "$archive" && ! -L "$archive" ]] ||
    die "transport archive is missing or not a regular file: $archive"
  assert_archive_entries
  for member in "${members[@]}"; do
    safe_reset_dir "$OUTPUT_ROOT/$member"
  done
  tar -xf "$archive" -C "$OUTPUT_ROOT"
  for member in "${members[@]}"; do
    [[ -d "$OUTPUT_ROOT/$member" && ! -L "$OUTPUT_ROOT/$member" ]] ||
      die "transport did not restore a real directory: $member"
    reject_symlinks "$OUTPUT_ROOT/$member"
  done
  # The narrow property transport is responsible for: upload-artifact would have
  # returned this file as 0644. validate.sh re-checks the full bundle contract a
  # step later, so this asserts transport's own failure mode by name.
  executable="$OUTPUT_ROOT/apps/$arch/$APP_NAME.app/Contents/MacOS/gta-claw-desktop"
  [[ -f "$executable" && ! -L "$executable" && -x "$executable" ]] ||
    die "transported app executable is not executable: $executable"
  note "restored the tested $arch build from $archive"
}

case "$mode" in
  pack) pack ;;
  unpack) unpack ;;
  *) die "usage: transport.sh [pack|unpack] ARCH ARCHIVE" ;;
esac
