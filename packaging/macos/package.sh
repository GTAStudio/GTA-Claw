#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in codesign ditto hdiutil lipo pkgbuild pkgutil productbuild security xcrun zipinfo; do
  require_tool "$tool"
done
[[ "$#" -ge 2 && "$#" -le 4 ]] ||
  die "usage: package.sh prototype|release APP [APP_ARCHIVE_LABEL] [EXPECTED_ARCHES]"
mode="$1"
app="$2"
app_archive_label="$(distribution_app_archive_label "${3:-}")"
expected_arches="$(distribution_expected_arches "${4:-}")"
[[ -d "$app" && "$app" == *.app && ! -L "$app" ]] || die "invalid app bundle: $app"
reject_symlinks "$app"

if [[ "$mode" == "release" ]]; then
  "$MACOS_DIR/validate.sh" "$app" "$expected_arches" release
  xcrun stapler validate "$app"
  : "${DEVELOPER_ID_APPLICATION:?DEVELOPER_ID_APPLICATION is required in release mode}"
  : "${DEVELOPER_ID_INSTALLER:?DEVELOPER_ID_INSTALLER is required in release mode}"
  [[ "$DEVELOPER_ID_INSTALLER" == "Developer ID Installer:"* ]] ||
    die "installer identity must be a Developer ID Installer identity"
  installer_identity_args=(-v)
  if [[ -n "${SIGNING_KEYCHAIN:-}" ]]; then
    installer_identity_args+=("$SIGNING_KEYCHAIN")
  fi
  security find-identity "${installer_identity_args[@]}" 2>/dev/null |
    grep -F "\"$DEVELOPER_ID_INSTALLER\"" >/dev/null ||
    die "Developer ID Installer identity is unavailable or invalid"
elif [[ "$mode" == "prototype" ]]; then
  "$MACOS_DIR/validate.sh" "$app" "$expected_arches" adhoc
else
  die "unknown package mode: $mode"
fi

distribution="$OUTPUT_ROOT/distribution"
archive_stage_root="$OUTPUT_ROOT/staging/app-archive"
archive_stage="$archive_stage_root/$APP_NAME.app"
dmg_stage="$OUTPUT_ROOT/staging/dmg"
package_work="$OUTPUT_ROOT/staging/pkg"
staged_app="$dmg_stage/$APP_NAME.app"
package_root="$package_work/root"
package_app="$package_root/Applications/$APP_NAME.app"
for destination in \
  "$distribution" "$archive_stage_root" "$archive_stage" "$dmg_stage" "$package_work" \
  "$staged_app" "$package_root" "$package_app"; do
  assert_output_path "$destination"
done
safe_reset_dir "$distribution"
safe_reset_dir "$archive_stage_root"
safe_reset_dir "$dmg_stage"
safe_reset_dir "$package_work"

archive_qualifier="unsigned-non-release"
if [[ "$mode" == "release" ]]; then
  archive_qualifier="signed-notarized"
fi
app_archive="$distribution/$(distribution_app_archive_name "$archive_qualifier" "$app_archive_label")"
assert_output_file_slot "$app_archive"
ditto "$app" "$archive_stage"
find "$archive_stage_root" -exec touch -t "$NORMALIZED_MTIME" {} +
ditto -c -k --keepParent "$archive_stage" "$app_archive"

assert_output_path "$staged_app"
ditto "$app" "$staged_app"
reject_symlinks "$dmg_stage"
write_sha256_manifest "$dmg_stage" "$distribution/dmg-content.sha256"
verify_sha256_manifest "$dmg_stage" "$distribution/dmg-content.sha256" >/dev/null

dmg="$distribution/gta-claw-$VERSION-macos.dmg"
assert_output_file_slot "$dmg"
hdiutil create \
  -srcfolder "$dmg_stage" \
  -volname "$APP_NAME $VERSION" \
  -fs HFS+ \
  -format UDZO \
  -ov \
  "$dmg"
hdiutil verify "$dmg" >/dev/null

component_pkg="$package_work/gta-claw-component.pkg"
ensure_output_directory "$package_root/Applications"
assert_output_path "$package_app"
ditto "$app" "$package_app"
reject_symlinks "$package_root"
assert_output_file_slot "$component_pkg"
pkgbuild \
  --root "$package_root" \
  --install-location / \
  --identifier "$BUNDLE_ID.pkg.component" \
  --version "$VERSION" \
  --ownership recommended \
  "$component_pkg"

pkg="$distribution/gta-claw-$VERSION-macos.pkg"
assert_output_file_slot "$pkg"
if [[ "$mode" == "release" ]]; then
  product_args=(--package "$component_pkg" --sign "$DEVELOPER_ID_INSTALLER")
  if [[ -n "${SIGNING_KEYCHAIN:-}" ]]; then
    product_args+=(--keychain "$SIGNING_KEYCHAIN")
  fi
  productbuild "${product_args[@]}" "$pkg"
  codesign \
    --force \
    --sign "$DEVELOPER_ID_APPLICATION" \
    --timestamp \
    --identifier "$BUNDLE_ID.dmg" \
    "$dmg"
  codesign --verify --verbose=2 "$dmg"
  pkgutil --check-signature "$pkg" | grep -F "Developer ID Installer:" >/dev/null ||
    die "PKG does not have a Developer ID Installer signature"
else
  productbuild --package "$component_pkg" "$pkg"
fi

if [[ "$mode" == "release" ]]; then
  "$MACOS_DIR/notarize.sh" "$dmg"
  "$MACOS_DIR/notarize.sh" "$pkg"
fi

write_artifact_supply_chain "$app_archive" desktop "$expected_arches"
write_artifact_supply_chain "$dmg" desktop "$expected_arches"
write_artifact_supply_chain "$pkg" desktop "$expected_arches"
write_artifact_set_checksums "$distribution" SHA256SUMS-macos
"$MACOS_DIR/validate-artifacts.sh" \
  "$distribution" \
  "$mode" \
  SHA256SUMS-macos \
  "$app_archive_label" \
  "$expected_arches"
note "created validated $mode distribution artifacts under $distribution"
