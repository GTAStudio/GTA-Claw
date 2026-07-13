#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in codesign lipo otool plutil strings; do
  require_tool "$tool"
done

[[ "$#" -ge 2 && "$#" -le 3 ]] || die "usage: validate.sh APP EXPECTED_ARCHES [adhoc|release]"
app="$1"
expected_arches="${2//,/ }"
signature_mode="${3:-adhoc}"
plist="$app/Contents/Info.plist"
binary="$app/Contents/MacOS/$EXECUTABLE_NAME"
icon="$app/Contents/Resources/GTAClaw.icns"

[[ -d "$app" && ! -L "$app" ]] || die "missing app bundle: $app"
reject_symlinks "$app"
[[ -f "$plist" && -f "$binary" && -x "$binary" && -s "$icon" ]] ||
  die "app bundle is missing required plist, executable, or icon"
plutil -lint "$plist" >/dev/null

[[ "$(plist_value "$plist" CFBundlePackageType)" == "APPL" ]] || die "CFBundlePackageType must be APPL"
[[ "$(plist_value "$plist" CFBundleIdentifier)" == "$BUNDLE_ID" ]] || die "bundle identifier mismatch"
[[ "$(plist_value "$plist" CFBundleExecutable)" == "$EXECUTABLE_NAME" ]] || die "bundle executable mismatch"
[[ "$(plist_value "$plist" CFBundleShortVersionString)" == "$VERSION" ]] || die "short version mismatch"
[[ "$(plist_value "$plist" CFBundleVersion)" == "$BUILD_VERSION" ]] || die "build version mismatch"
[[ "$(plist_value "$plist" LSMinimumSystemVersion)" == "$MINIMUM_MACOS_VERSION" ]] ||
  die "Info.plist minimum macOS version mismatch"
[[ "$(plist_value "$plist" LSApplicationCategoryType)" == "$APP_CATEGORY" ]] ||
  die "application category mismatch"
[[ "$(plist_value "$plist" NSHumanReadableCopyright)" == "$APP_COPYRIGHT" ]] ||
  die "copyright mismatch"

while IFS= read -r entry; do
  case "$entry" in
    Frameworks | Info.plist | MacOS | Resources | _CodeSignature) ;;
    *) die "unexpected top-level app bundle content: $entry" ;;
  esac
done < <(find "$app/Contents" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort)

assert_binary_arches "$binary" "$expected_arches"
assert_macho_minimum_version "$binary"
validate_macho_dependencies "$binary" "$app"

if strings "$binary" | grep -F "$REPO_ROOT" >/dev/null; then
  die "binary contains an absolute repository build path"
fi
if find "$app" -type f \( \
  -iname 'node' -o -iname 'node.exe' -o -iname 'npm' -o -iname 'bun' -o -iname 'pnpm' -o \
  -iname '*.js' -o -iname '*.mjs' -o -iname '*.cjs' -o -iname '*.node' \
\) -print -quit | grep . >/dev/null; then
  die "app bundle contains a JavaScript or Node runtime artifact"
fi
if macho_dependencies "$binary" | grep -Ei '(^|/)libnode|javascriptcore' >/dev/null; then
  die "app binary links a JavaScript runtime"
fi

codesign --verify --deep --strict --verbose=2 "$app"
actual_entitlements_template="$OUTPUT_ROOT/actual-entitlements.XXXXXX"
expected_entitlements_template="$OUTPUT_ROOT/expected-entitlements.XXXXXX"
assert_output_path "$actual_entitlements_template"
assert_output_path "$expected_entitlements_template"
actual_entitlements="$(mktemp "$actual_entitlements_template")"
expected_entitlements="$(mktemp "$expected_entitlements_template")"
trap 'rm -f -- "$actual_entitlements" "$expected_entitlements"' EXIT
codesign -d --entitlements - --xml "$app" >"$actual_entitlements" 2>/dev/null
plutil -convert xml1 "$actual_entitlements"
plutil -convert xml1 -o "$expected_entitlements" "$MACOS_DIR/gta-claw.entitlements"
cmp -s "$actual_entitlements" "$expected_entitlements" || die "signed entitlements differ from source"

details="$(codesign -dvvv "$app" 2>&1)"
requirement="$(codesign -d -r- "$app" 2>&1)"
grep -F "designated =>" <<<"$requirement" >/dev/null ||
  die "code signature has no designated requirement"
if [[ "$signature_mode" == "release" ]]; then
  grep -F "identifier \"$BUNDLE_ID\"" <<<"$requirement" >/dev/null ||
    die "release designated requirement does not contain $BUNDLE_ID"
  grep -F "Authority=Developer ID Application:" <<<"$details" >/dev/null ||
    die "release app lacks Developer ID Application authority"
  grep -F "Timestamp=" <<<"$details" >/dev/null || die "release app lacks a secure timestamp"
  grep -E 'flags=.*runtime' <<<"$details" >/dev/null || die "release app lacks hardened runtime"
elif [[ "$signature_mode" == "adhoc" ]]; then
  grep -F "Signature=adhoc" <<<"$details" >/dev/null || die "app is not ad-hoc signed"
else
  die "unknown signature validation mode: $signature_mode"
fi

manifest="$OUTPUT_ROOT/manifests/$(basename "$app" .app)-${expected_arches// /_}.sha256"
assert_output_path "$manifest"
ensure_output_directory "$(dirname "$manifest")"
write_sha256_manifest "$app" "$manifest"
verify_sha256_manifest "$app" "$manifest" >/dev/null
note "validated $app"
