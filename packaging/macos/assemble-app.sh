#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in install plutil; do
  require_tool "$tool"
done
[[ "$#" -eq 3 ]] || die "usage: assemble-app.sh BINARY ARCH_LABEL EXPECTED_ARCHES"
binary="$1"
arch_label="$2"
expected_arches="${3//,/ }"
validate_safe_component "$arch_label" ARCH_LABEL
app_parent="$OUTPUT_ROOT/apps/$arch_label"
app="$(app_bundle_path "$arch_label")"
macos_dir="$app/Contents/MacOS"
executable="$app/Contents/MacOS/$EXECUTABLE_NAME"
resources="$app/Contents/Resources"
plist="$app/Contents/Info.plist"
icon="$resources/GTAClaw.icns"
for destination in "$app_parent" "$app" "$macos_dir" "$executable" "$resources" "$plist" "$icon"; do
  assert_output_path "$destination"
done
safe_reset_dir "$app_parent"
ensure_output_directory "$macos_dir"
ensure_output_directory "$resources"
assert_output_path "$executable"
install -m 0755 "$binary" "$executable"
assert_output_path "$plist"
install -m 0644 "$MACOS_DIR/Info.plist.in" "$plist"
assert_output_path "$icon"
"$MACOS_DIR/generate-icon.sh" "$icon"

/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName $APP_NAME" "$plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleName $APP_NAME" "$plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable $EXECUTABLE_NAME" "$plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BUNDLE_ID" "$plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_VERSION" "$plist"
/usr/libexec/PlistBuddy -c "Set :LSMinimumSystemVersion $MINIMUM_MACOS_VERSION" "$plist"
/usr/libexec/PlistBuddy -c "Set :LSApplicationCategoryType $APP_CATEGORY" "$plist"
/usr/libexec/PlistBuddy -c "Set :NSHumanReadableCopyright $APP_COPYRIGHT" "$plist"
plutil -convert xml1 "$plist"
plutil -lint "$plist" >/dev/null

find "$app" -type d -exec chmod 0755 {} +
find "$app" -type f ! -path '*/Contents/MacOS/*' -exec chmod 0644 {} +
touch -t "$NORMALIZED_MTIME" "$plist" "$icon"

"$MACOS_DIR/sign.sh" adhoc "$app"
"$MACOS_DIR/validate.sh" "$app" "$expected_arches" adhoc
printf '%s\n' "$app"
