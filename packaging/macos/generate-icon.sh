#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
require_tool xcrun
require_tool sips
require_tool iconutil

output="${1:-$OUTPUT_ROOT/generated/GTAClaw.icns}"
assert_output_path "$output"
work="$OUTPUT_ROOT/icon-work"
safe_reset_dir "$work"
ensure_output_directory "$(dirname "$output")"

base="$work/icon_1024x1024.png"
xcrun swift "$MACOS_DIR/icon/render.swift" "$base"

iconset="$work/GTAClaw.iconset"
ensure_output_directory "$iconset"
for size in 16 32 128 256 512; do
  double=$((size * 2))
  sips -z "$size" "$size" "$base" --out "$iconset/icon_${size}x${size}.png" >/dev/null
  sips -z "$double" "$double" "$base" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done

assert_output_file_slot "$output"
iconutil -c icns "$iconset" -o "$output"
[[ -s "$output" ]] || die "iconutil did not create $output"
touch -t "$NORMALIZED_MTIME" "$output"
note "generated $output"
