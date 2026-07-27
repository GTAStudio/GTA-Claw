#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in codesign ditto hdiutil lipo pkgbuild pkgutil plutil productbuild security xcrun zipinfo; do
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

final_distribution="$OUTPUT_ROOT/distribution"
checksum_name=SHA256SUMS
transaction="$OUTPUT_ROOT/staging/package-transaction"
distribution="$transaction/distribution"
archive_stage_root="$transaction/app-archive"
archive_stage="$archive_stage_root/$APP_NAME.app"
dmg_stage="$transaction/dmg"
package_work="$transaction/pkg"
staged_app="$dmg_stage/$APP_NAME.app"
package_root="$package_work/root"
package_app="$package_root/Applications/$APP_NAME.app"
component_plist="$package_work/components.plist"
package_inventory_cache="$package_work/desktop-packages.txt"
for destination in \
  "$final_distribution" "$transaction" "$distribution" "$archive_stage_root" \
  "$archive_stage" "$dmg_stage" "$package_work" "$staged_app" "$package_root" \
  "$package_app" "$component_plist" "$package_inventory_cache"; do
  assert_output_path "$destination"
done
safe_reset_dir "$transaction"
cleanup() {
  if [[ -d "$transaction" && ! -L "$transaction" ]]; then
    remove_output_directory "$transaction"
  fi
}
trap cleanup EXIT INT TERM
ensure_output_directory "$distribution"
safe_reset_dir "$archive_stage_root"
safe_reset_dir "$dmg_stage"
safe_reset_dir "$package_work"

archive_qualifier="unsigned-non-release"
if [[ "$mode" == "release" ]]; then
  archive_qualifier="signed-notarized"
fi
app_archive="$distribution/$(distribution_app_archive_name "$archive_qualifier" "$app_archive_label")"
assert_output_file_slot "$app_archive"
copy_app_bundle "$app" "$archive_stage"
find "$archive_stage_root" -exec touch -t "$NORMALIZED_MTIME" {} +
ditto -c -k --keepParent "$archive_stage" "$app_archive"

assert_output_path "$staged_app"
copy_app_bundle "$app" "$staged_app"
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
copy_app_bundle "$app" "$package_app"
reject_symlinks "$package_root"
write_pkg_component_plist "$component_plist"
assert_output_file_slot "$component_pkg"
pkgbuild \
  --root "$package_root" \
  --component-plist "$component_plist" \
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

write_artifact_supply_chain "$app_archive" desktop "$expected_arches" "$package_inventory_cache"
write_artifact_supply_chain "$dmg" desktop "$expected_arches" "$package_inventory_cache"
write_artifact_supply_chain "$pkg" desktop "$expected_arches" "$package_inventory_cache"
write_artifact_set_checksums "$distribution" "$checksum_name"
"$MACOS_DIR/validate-artifacts.sh" \
  "$distribution" \
  "$mode" \
  "$checksum_name" \
  "$app_archive_label" \
  "$expected_arches"
publish_output_directory "$distribution" "$final_distribution"
note "created validated $mode distribution artifacts under $final_distribution"
