#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/build-manifest.sh"

require_linux
for tool in jq readelf sha256sum; do
  require_tool "$tool"
done
[[ "$#" -eq 2 ]] || die "usage: build-manifest-self-test.sh BUILD_MANIFEST ARCH"
input_manifest="$1"
arch="$2"
verify_build_manifest "$input_manifest" "$arch"
source_build_root="$BUILD_ROOT"
source_target="$(arch_target "$arch")"

: "${OUTPUT_ROOT:=$(canonical_target_root)/linux-build-manifest-self-test-$BASHPID}"
initialize_output_root
work="$OUTPUT_ROOT/cases"
ensure_output_directory "$work"
tests=0

expect_failure() {
  local name="$1"
  shift
  tests=$((tests + 1))
  if "$@" >"$OUTPUT_ROOT/$name.stdout" 2>"$OUTPUT_ROOT/$name.stderr"; then
    die "build manifest self-test expected failure but succeeded: $name"
  fi
}

prepare_clone() {
  local name="$1"
  local root="$work/$name"
  local source
  local relative
  ensure_output_directory "$root"
  chmod 0700 "$root"
  write_output_text "$root/.linux-packaging-owner" 0600 $'gta-claw-linux-packaging-v2\n'
  for source in \
    "$source_build_root/build-manifest.json" \
    "$source_build_root/BUILD_COMPLETE" \
    "$source_build_root/$source_target/release/$LINUX_DAEMON_NAME" \
    "$source_build_root/$source_target/release/$LINUX_CLI_NAME"; do
    relative="${source#"$source_build_root/"}"
    copy_verified_input "$source" "$root/$relative" "$(
      [[ "$source" == */release/* ]] && printf '0755\n' || printf '0644\n'
    )"
  done
  while IFS= read -r -d '' source; do
    relative="${source#"$source_build_root/"}"
    copy_verified_input "$source" "$root/$relative" "$(
      stat -c '0%a' "$source"
    )"
  done < <(find "$source_build_root/runtime" -type f -print0 | LC_ALL=C sort -z)
  printf '%s\n' "$root"
}

mutate_manifest() {
  local root="$1"
  local filter="$2"
  local manifest="$root/build-manifest.json"
  local temporary="$root/build-manifest.mutated"
  mv "$manifest" "$root/build-manifest.original"
  open_output_file "$temporary" 0644
  jq -S "$filter" "$root/build-manifest.original" >&"$OPEN_OUTPUT_FD"
  finish_output_file
  publish_output_file "$temporary" "$manifest"
  mv "$root/BUILD_COMPLETE" "$root/BUILD_COMPLETE.original"
  write_output_text \
    "$root/BUILD_COMPLETE" \
    0644 \
    "$(sha256_file "$manifest")  build-manifest.json"$'\n'
}

case_root="$(prepare_clone wrong-rustflags)"
mutate_manifest "$case_root" '.build.rustflags = "-C target-cpu=native"'
expect_failure wrong-rustflags verify_build_manifest "$case_root/build-manifest.json" "$arch"

case_root="$(prepare_clone wrong-toolchain)"
mutate_manifest "$case_root" '.builder.rustcVerbose = "rustc 9.99.0 (forged)"'
expect_failure wrong-toolchain verify_build_manifest "$case_root/build-manifest.json" "$arch"

case_root="$(prepare_clone wrong-target)"
mutate_manifest "$case_root" '.build.rustTarget = "x86_64-unknown-linux-musl"'
expect_failure wrong-target verify_build_manifest "$case_root/build-manifest.json" "$arch"

case_root="$(prepare_clone wrong-source-tree)"
mutate_manifest "$case_root" '.source.tree = "0000000000000000000000000000000000000000"'
expect_failure wrong-source-tree verify_build_manifest "$case_root/build-manifest.json" "$arch"

case_root="$(prepare_clone substituted-binary)"
mv \
  "$case_root/$source_target/release/$LINUX_CLI_NAME" \
  "$case_root/$source_target/release/$LINUX_CLI_NAME.original"
copy_verified_input \
  "$case_root/$source_target/release/$LINUX_DAEMON_NAME" \
  "$case_root/$source_target/release/$LINUX_CLI_NAME" \
  0755
expect_failure substituted-binary \
  verify_build_manifest "$case_root/build-manifest.json" "$arch"

printf 'Build manifest tamper self-tests passed (%d cases)\n' "$tests"
