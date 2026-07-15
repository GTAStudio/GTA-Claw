#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: verify-macos-app.sh APP_BUNDLE" >&2
  exit 2
fi

readonly app="$1"
readonly contents="$app/Contents"
readonly macos="$contents/MacOS"
readonly plist="$contents/Info.plist"
readonly executable="$macos/gta-claw-desktop"

[[ "$app" = /* && -d "$app" && ! -L "$app" ]]
[[ -d "$contents" && ! -L "$contents" ]]
[[ -d "$macos" && ! -L "$macos" ]]
[[ -f "$plist" && ! -L "$plist" ]]
[[ -z "$(/usr/bin/find "$app" -type l -print -quit)" ]]
/usr/bin/plutil -lint "$plist" >/dev/null
[[ "$(/usr/bin/plutil -extract CFBundleExecutable json -expect string -o - "$plist")" == '"gta-claw-desktop"' ]]

entries=()
while IFS= read -r -d '' entry; do
  entries+=("$entry")
done < <(/usr/bin/find "$macos" -mindepth 1 -maxdepth 1 -print0)
[[ "${#entries[@]}" -eq 1 && "${entries[0]}" == "$executable" ]]
[[ -f "$executable" && ! -L "$executable" && -x "$executable" ]]
