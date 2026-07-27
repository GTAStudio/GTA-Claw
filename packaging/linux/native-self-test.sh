#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/build-manifest.sh"
source "$SCRIPT_DIR/lib/oci-validation.sh"
source "$SCRIPT_DIR/lib/native-validation.sh"

require_linux
for tool in gzip jq python3 sha256sum stat tar; do
  require_tool "$tool"
done
[[ "$#" -eq 4 ]] ||
  die "usage: native-self-test.sh NATIVE_ARCHIVE ARCH BUILD_MANIFEST EXPECTED_BUILD_KEY_SHA256"
source_archive="$1"
arch="$2"
expected_build_manifest="$3"
expected_build_key_sha="$4"
assert_regular_unaliased "$source_archive" "native mutation source"
base_name="$LINUX_PACKAGE_NAME-$VERSION-linux-$arch"
: "${OUTPUT_ROOT:=$(canonical_target_root)/linux-native-self-test-$BASHPID}"
initialize_output_root
ensure_output_directory "$OUTPUT_ROOT/discard"
tests=0

validate_published_native_archive \
  "$source_archive" \
  "$arch" \
  "$OUTPUT_ROOT/validation-original" \
  "$expected_build_manifest" \
  "$expected_build_key_sha"

expect_invalid() {
  local name="$1"
  local archive="$2"
  tests=$((tests + 1))
  if validate_published_native_archive \
    "$archive" \
    "$arch" \
    "$OUTPUT_ROOT/validation-$name" \
    "$expected_build_manifest" \
    "$expected_build_key_sha" \
    >"$OUTPUT_ROOT/$name.stdout" \
    2>"$OUTPUT_ROOT/$name.stderr"; then
    die "native archive mutation unexpectedly validated: $name"
  fi
}

prepare_case() {
  local name="$1"
  local root="$OUTPUT_ROOT/case-$name"
  ensure_output_directory "$root"
  tar -xzf "$source_archive" -C "$root" --no-same-owner
  printf '%s\n' "$root/$base_name"
}

replace_json() {
  local path="$1"
  shift
  local original="$OUTPUT_ROOT/discard/json-$RANDOM"
  mv "$path" "$original"
  open_output_file "$path" 0644
  jq -S "$@" "$original" >&"$OPEN_OUTPUT_FD"
  finish_output_file
}

rewrite_checksums() {
  local root="$1"
  local manifest="$root/SHA256SUMS"
  mv "$manifest" "$OUTPUT_ROOT/discard/SHA256SUMS-$RANDOM"
  open_output_file "$manifest" 0644
  while IFS= read -r -d '' relative; do
    printf '%s  %s\n' "$(sha256_file "$root/$relative")" "$relative" \
      >&"$OPEN_OUTPUT_FD"
  done < <(cd "$root" && find . -type f ! -path ./SHA256SUMS -print0 | LC_ALL=C sort -z)
  finish_output_file
}

pack_case() {
  local name="$1"
  local root="$2"
  local output="$OUTPUT_ROOT/$name.tar.gz"
  open_output_file "$output" 0644
  (
    cd "$(dirname "$root")"
    tar -cf - "$(basename "$root")"
  ) | gzip -n -9 >&"$OPEN_OUTPUT_FD"
  finish_output_file
  printf '%s\n' "$output"
}

case_root="$(prepare_case substituted-application)"
cli="$case_root/bin/$LINUX_CLI_NAME"
daemon="$case_root/bin/$LINUX_DAEMON_NAME"
mv "$cli" "$OUTPUT_ROOT/discard/original-cli"
copy_regular_input "$daemon" "$cli" 0755
substituted_sha="$(sha256_file "$cli")"
replace_json \
  "$case_root/provenance.json" \
  --arg path "bin/$LINUX_CLI_NAME" \
  --arg sha "$substituted_sha" \
  '(.subject[] | select(.name == $path) | .digest.sha256) = $sha'
replace_json \
  "$case_root/sbom.spdx.json" \
  --arg path "./bin/$LINUX_CLI_NAME" \
  --arg sha "$substituted_sha" \
  '(.files[] | select(.fileName == $path) |
    .checksums[] | select(.algorithm == "SHA256") | .checksumValue) = $sha'
rewrite_checksums "$case_root"
expect_invalid \
  substituted-application \
  "$(pack_case substituted-application "$case_root")"

case_root="$(prepare_case extra-file)"
write_output_text "$case_root/undeclared" 0644 $'undeclared published bytes\n'
rewrite_checksums "$case_root"
expect_invalid extra-file "$(pack_case extra-file "$case_root")"

printf 'Published native archive mutation self-tests passed (%d cases)\n' "$tests"
