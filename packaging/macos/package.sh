#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in codesign ditto hdiutil lipo pkgbuild pkgutil productbuild security xcrun; do
  require_tool "$tool"
done
[[ "$#" -eq 2 ]] || die "usage: package.sh prototype|release APP"
mode="$1"
app="$2"
[[ -d "$app" && "$app" == *.app && ! -L "$app" ]] || die "invalid app bundle: $app"
reject_symlinks "$app"

binary="$app/Contents/MacOS/$EXECUTABLE_NAME"
expected_arches="$(lipo -archs "$binary")"
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
dmg_stage="$OUTPUT_ROOT/staging/dmg"
package_work="$OUTPUT_ROOT/staging/pkg"
safe_reset_dir "$distribution"
safe_reset_dir "$dmg_stage"
safe_reset_dir "$package_work"

ditto "$app" "$dmg_stage/$APP_NAME.app"
reject_symlinks "$dmg_stage"
write_sha256_manifest "$dmg_stage" "$distribution/dmg-content.sha256"
verify_sha256_manifest "$dmg_stage" "$distribution/dmg-content.sha256" >/dev/null

dmg="$distribution/gta-claw-$VERSION-macos.dmg"
hdiutil create \
  -srcfolder "$dmg_stage" \
  -volname "$APP_NAME $VERSION" \
  -fs HFS+ \
  -format UDZO \
  -ov \
  "$dmg"
hdiutil verify "$dmg" >/dev/null

component_pkg="$package_work/gta-claw-component.pkg"
package_root="$package_work/root"
mkdir -p "$package_root/Applications"
ditto "$app" "$package_root/Applications/$APP_NAME.app"
reject_symlinks "$package_root"
pkgbuild \
  --root "$package_root" \
  --install-location / \
  --identifier "$BUNDLE_ID.pkg.component" \
  --version "$VERSION" \
  --ownership recommended \
  "$component_pkg"

pkg="$distribution/gta-claw-$VERSION-macos.pkg"
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

write_sha256_manifest "$distribution" "$distribution/SHA256SUMS"
verify_sha256_manifest "$distribution" "$distribution/SHA256SUMS" >/dev/null
note "created prototype distribution containers under $distribution"
