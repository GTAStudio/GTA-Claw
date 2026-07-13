#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
require_tool lipo
require_tool otool

[[ "$#" -eq 3 ]] || die "usage: merge-universal.sh ARM64_BINARY X86_64_BINARY OUTPUT"
arm_binary="$1"
x86_binary="$2"
output="$3"
assert_output_path "$output"

assert_binary_arches "$arm_binary" "arm64"
assert_binary_arches "$x86_binary" "x86_64"
assert_macho_minimum_version "$arm_binary"
assert_macho_minimum_version "$x86_binary"

work="$OUTPUT_ROOT/merge-check"
safe_reset_dir "$work"
macho_dependencies "$arm_binary" >"$work/arm64.dependencies"
macho_dependencies "$x86_binary" >"$work/x86_64.dependencies"
cmp -s "$work/arm64.dependencies" "$work/x86_64.dependencies" ||
  die "dynamic dependency parity check failed between arm64 and x86_64 slices"

macho_rpaths "$arm_binary" >"$work/arm64.rpaths"
macho_rpaths "$x86_binary" >"$work/x86_64.rpaths"
cmp -s "$work/arm64.rpaths" "$work/x86_64.rpaths" ||
  die "LC_RPATH parity check failed between arm64 and x86_64 slices"

macho_minimum_versions "$arm_binary" >"$work/arm64.minimum-versions"
macho_minimum_versions "$x86_binary" >"$work/x86_64.minimum-versions"
cmp -s "$work/arm64.minimum-versions" "$work/x86_64.minimum-versions" ||
  die "deployment target parity check failed between arm64 and x86_64 slices"

mkdir -p "$(dirname "$output")"
lipo -create "$arm_binary" "$x86_binary" -output "$output"
chmod 0755 "$output"
lipo -verify_arch arm64 x86_64 "$output"
assert_binary_arches "$output" "arm64 x86_64"
assert_macho_minimum_version "$output"
note "created universal2 binary $output"
