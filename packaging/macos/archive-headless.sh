#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in gzip tar; do
  require_tool "$tool"
done
[[ "$#" -eq 4 ]] || die "usage: archive-headless.sh BINARY COMPONENT ARCH_LABEL EXPECTED_ARCH"
binary="$1"
component="$2"
arch_label="$3"
expected_arch="$4"
case "$component" in
  gta-claw-cli | gta-claw-daemon) ;;
  *) die "unsupported headless component: $component" ;;
esac

assert_binary_arches "$binary" "$expected_arch"
assert_macho_minimum_version "$binary"
validate_macho_dependencies "$binary" "$OUTPUT_ROOT"

archive_root="$OUTPUT_ROOT/headless/$arch_label"
stage="$OUTPUT_ROOT/staging/$component-$VERSION-macos-$arch_label"
safe_reset_dir "$stage"
mkdir -p "$archive_root"
install -m 0755 "$binary" "$stage/$component"
printf '%s  %s\n' "$(sha256_file "$stage/$component")" "$component" >"$stage/SHA256SUMS"
chmod 0644 "$stage/SHA256SUMS"
find "$stage" -exec touch -t "$NORMALIZED_MTIME" {} +

archive="$archive_root/$component-$VERSION-macos-$arch_label.tar.gz"
assert_output_path "$archive"
rm -f -- "$archive"
(
  cd "$(dirname "$stage")"
  COPYFILE_DISABLE=1 tar \
    --format ustar \
    --uid 0 \
    --gid 0 \
    --uname root \
    --gname wheel \
    -cf - \
    "$(basename "$stage")"
) | gzip -n -9 >"$archive"
printf '%s  %s\n' "$(sha256_file "$archive")" "$(basename "$archive")" >"$archive.sha256"
note "created $archive"
