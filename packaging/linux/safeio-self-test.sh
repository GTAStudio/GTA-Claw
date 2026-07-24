#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
[[ "${SAFEIO_ACTIVE:-0}" == "1" ]] || die "safeio self-test requires inherited capabilities"
initialize_output_root
work="$OUTPUT_ROOT/work"
ensure_output_directory "$work"

actual="$SAFEIO_OUTPUT_REALPATH"
displaced="$SAFEIO_OUTPUT_REALPATH.displaced"
outside="$(mktemp -d "${TMPDIR:?TMPDIR is required}/gta-claw-safeio-outside.XXXXXXXXXX")"
printf 'outside sentinel\n' >"$outside/sentinel"

mv "$actual" "$displaced"
ln -s "$outside" "$actual"
ensure_output_directory "$work/after-ancestor-swap"
write_output_text "$work/after-ancestor-swap/payload" 0644 $'anchored payload\n'

[[ "$(cat "$outside/sentinel")" == "outside sentinel" ]] ||
  die "ancestor swap modified outside sentinel"
[[ ! -e "$outside/work/after-ancestor-swap/payload" ]] ||
  die "ancestor swap escaped the held output directory FD"
[[ "$(cat "$displaced/work/after-ancestor-swap/payload")" == "anchored payload" ]] ||
  die "held output directory FD did not retain the original ancestor"

rm "$actual"
mv "$displaced" "$actual"
rm -rf "$outside"
echo "Directory-FD ancestor-swap self-test passed"
