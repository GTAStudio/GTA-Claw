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
app="$app_parent/$APP_NAME.app"
executable="$app/Contents/MacOS/$EXECUTABLE_NAME"
resources="$app/Contents/Resources"
assert_output_path "$app_parent"
assert_output_path "$app"
assert_output_path "$executable"
assert_output_path "$resources"
safe_reset_dir "$app_parent"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
assert_output_path "$executable"
assert_output_path "$resources"

install -m 0755 "$binary" "$executable"
install -m 0644 "$MACOS_DIR/Info.plist.in" "$app/Contents/Info.plist"
"$MACOS_DIR/generate-icon.sh" "$app/Contents/Resources/GTAClaw.icns"

plist="$app/Contents/Info.plist"
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
touch -t "$NORMALIZED_MTIME" "$plist" "$app/Contents/Resources/GTAClaw.icns"

"$MACOS_DIR/sign.sh" adhoc "$app"
"$MACOS_DIR/validate.sh" "$app" "$expected_arches" adhoc
printf '%s\n' "$app"
