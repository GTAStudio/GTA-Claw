#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in codesign ditto hdiutil pkgutil spctl tar xcrun zipinfo; do
  require_tool "$tool"
done
[[ "$#" -ge 2 && "$#" -le 3 ]] ||
  die "usage: validate-artifacts.sh ARTIFACT_DIRECTORY prototype|release [CHECKSUM_NAME]"
artifact_root="$(cd "$1" && pwd -P)"
mode="$2"
checksum_name="${3:-SHA256SUMS}"
[[ "$checksum_name" =~ ^SHA256SUMS(-[a-z]+)?$ ]] ||
  die "invalid artifact checksum manifest name: $checksum_name"
case "$mode" in
  prototype) app_signature=adhoc ;;
  release) app_signature=release ;;
  *) die "validation mode must be prototype or release" ;;
esac
[[ "$artifact_root" == "$OUTPUT_ROOT/"* ]] ||
  die "artifact directory must be below OUTPUT_ROOT"
reject_symlinks "$artifact_root"
assert_no_javascript_payload "$artifact_root"

inspection="$OUTPUT_ROOT/published-inspection/artifacts"
safe_reset_dir "$inspection"
mounted=""
cleanup() {
  if [[ -n "$mounted" ]]; then
    hdiutil detach "$mounted" -force >/dev/null 2>&1 || true
  fi
  rm -rf -- "$inspection"
}
trap cleanup EXIT INT TERM

validate_published_app() {
  local app="$1"
  "$MACOS_DIR/validate.sh" "$app" "arm64 x86_64" "$app_signature"
  assert_no_javascript_payload "$app"
  if [[ "$mode" == "release" ]]; then
    xcrun stapler validate "$app"
    spctl --assess --type execute --verbose=4 "$app"
  fi
}

artifacts=0
allowed_files="$checksum_name"$'\n'
actual_artifacts="$(
  find "$artifact_root" -maxdepth 1 -type f \( \
    -name '*.tar.gz' -o -name '*.app.zip' -o -name '*.dmg' -o -name '*.pkg' \
  \) -exec basename {} \; |
    LC_ALL=C sort
)"
expected_artifacts=""
if grep -E '\.(app\.zip|dmg|pkg)$' <<<"$actual_artifacts" >/dev/null; then
  app_qualifier="unsigned-non-release"
  [[ "$mode" != "release" ]] || app_qualifier="signed-notarized"
  expected_artifacts+="gta-claw-$VERSION-macos-universal2-$app_qualifier.app.zip"$'\n'
  expected_artifacts+="gta-claw-$VERSION-macos.dmg"$'\n'
  expected_artifacts+="gta-claw-$VERSION-macos.pkg"$'\n'
  if grep -E '\.tar\.gz$' <<<"$actual_artifacts" >/dev/null; then
    for arch in arm64 x86_64; do
      expected_artifacts+="gta-claw-cli-$VERSION-macos-$arch.tar.gz"$'\n'
      expected_artifacts+="gta-claw-daemon-$VERSION-macos-$arch.tar.gz"$'\n'
    done
  fi
else
  case "$actual_artifacts" in
    *-arm64.tar.gz*) native_arch=arm64 ;;
    *-x86_64.tar.gz*) native_arch=x86_64 ;;
    *) die "headless publication has no supported architecture label" ;;
  esac
  expected_artifacts+="gta-claw-cli-$VERSION-macos-$native_arch.tar.gz"$'\n'
  expected_artifacts+="gta-claw-daemon-$VERSION-macos-$native_arch.tar.gz"$'\n'
fi
expected_artifacts="$(sed '/^$/d' <<<"$expected_artifacts" | LC_ALL=C sort)"
[[ "$actual_artifacts" == "$expected_artifacts" ]] ||
  die "published macOS artifact set differs from its exact delivery profile"

while IFS= read -r artifact; do
  artifacts=$((artifacts + 1))
  test_artifact_supply_chain "$artifact"
  name="$(basename "$artifact")"
  allowed_files+="$name"$'\n'
  allowed_files+="$name.spdx"$'\n'
  allowed_files+="$name.provenance.json"$'\n'
  if [[ -f "$artifact.sha256" && ! -L "$artifact.sha256" ]]; then
    allowed_files+="$name.sha256"$'\n'
  fi
  case "$artifact" in
    *.tar.gz)
      case "$name" in
        gta-claw-cli-*) component=gta-claw-cli ;;
        gta-claw-daemon-*) component=gta-claw-daemon ;;
        *) die "unexpected headless archive name: $name" ;;
      esac
      case "$name" in
        *-arm64.tar.gz) arch=arm64 ;;
        *-x86_64.tar.gz) arch=x86_64 ;;
        *) die "headless archive lacks an architecture label: $name" ;;
      esac
      validate_headless_archive "$artifact" "$component" "$arch" "$arch"
      ;;
    *.app.zip)
      zip_stage="$inspection/app-zip"
      safe_reset_dir "$zip_stage"
      zipinfo -1 "$artifact" >"$inspection/app-zip.list"
      if grep -E '(^/|(^|/)\.\.(/|$)|\\)' "$inspection/app-zip.list" >/dev/null; then
        die "app ZIP contains an unsafe path: $artifact"
      fi
      if zipinfo -l "$artifact" | awk '$1 ~ /^l/ { found = 1 } END { exit !found }'; then
        die "app ZIP contains a link entry: $artifact"
      fi
      ditto -x -k "$artifact" "$zip_stage"
      reject_symlinks "$zip_stage"
      top="$(find "$zip_stage" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort)"
      [[ "$top" == "$APP_NAME.app" ]] || die "app ZIP top level differs from its allowlist"
      validate_published_app "$zip_stage/$APP_NAME.app"
      ;;
    *.dmg)
      mount="$inspection/dmg"
      safe_reset_dir "$mount"
      hdiutil verify "$artifact" >/dev/null
      hdiutil attach -readonly -nobrowse -mountpoint "$mount" "$artifact" >/dev/null
      mounted="$mount"
      top="$(find "$mount" -mindepth 1 -maxdepth 1 ! -name '.DS_Store' -exec basename {} \; | LC_ALL=C sort)"
      [[ "$top" == "$APP_NAME.app" ]] || die "DMG top level differs from its allowlist"
      validate_published_app "$mount/$APP_NAME.app"
      if [[ "$mode" == "release" ]]; then
        codesign --verify --verbose=2 "$artifact"
        xcrun stapler validate "$artifact"
        spctl --assess --type open --context context:primary-signature --verbose=4 "$artifact"
      elif codesign --verify "$artifact" >/dev/null 2>&1; then
        die "prototype DMG unexpectedly carries a valid signature"
      fi
      hdiutil detach "$mount" >/dev/null
      mounted=""
      ;;
    *.pkg)
      pkg_stage="$inspection/pkg"
      safe_reset_dir "$pkg_stage"
      rmdir "$pkg_stage"
      assert_output_path "$pkg_stage"
      pkgutil --expand-full "$artifact" "$pkg_stage"
      reject_symlinks "$pkg_stage"
      assert_no_javascript_payload "$pkg_stage"
      if find "$pkg_stage" -type d -name Scripts -print -quit | grep . >/dev/null; then
        die "PKG contains forbidden installer scripts"
      fi
      apps=()
      while IFS= read -r packaged_app; do
        apps+=("$packaged_app")
      done < <(find "$pkg_stage" -type d -name "$APP_NAME.app")
      [[ "${#apps[@]}" -eq 1 ]] || die "PKG must contain exactly one GTA Claw app"
      validate_published_app "${apps[0]}"
      payload_files="$(pkgutil --payload-files "$artifact")"
      if grep -E '(^|/)(node|npm|npx|bun|pnpm|package\.json|[^/]+\.(js|mjs|cjs|node))$' \
        <<<"$payload_files" >/dev/null; then
        die "PKG payload contains JavaScript or Node runtime material"
      fi
      payload_files="$(sed 's#^\./##' <<<"$payload_files")"
      grep -Fx "Applications/$APP_NAME.app" <<<"$payload_files" >/dev/null ||
        die "PKG does not install $APP_NAME.app below /Applications"
      while IFS= read -r payload_path; do
        case "$payload_path" in
          . | Applications | "Applications/$APP_NAME.app" | "Applications/$APP_NAME.app/"*) ;;
          *) die "PKG installs a path outside the app allowlist: $payload_path" ;;
        esac
      done <<<"$payload_files"
      if [[ "$mode" == "release" ]]; then
        pkgutil --check-signature "$artifact" |
          grep -F 'Developer ID Installer:' >/dev/null ||
          die "release PKG lacks a Developer ID Installer signature"
        xcrun stapler validate "$artifact"
        spctl --assess --type install --verbose=4 "$artifact"
      elif pkgutil --check-signature "$artifact" 2>&1 |
        grep -F 'Developer ID Installer:' >/dev/null; then
        die "prototype PKG unexpectedly carries a Developer ID Installer signature"
      fi
      ;;
    *)
      die "unsupported published artifact: $artifact"
      ;;
  esac
done < <(find "$artifact_root" -maxdepth 1 -type f \( \
  -name '*.tar.gz' -o -name '*.app.zip' -o -name '*.dmg' -o -name '*.pkg' \
\) | LC_ALL=C sort)

[[ "$artifacts" -gt 0 ]] || die "no published macOS artifacts found in $artifact_root"
if [[ -f "$artifact_root/dmg-content.sha256" && ! -L "$artifact_root/dmg-content.sha256" ]]; then
  allowed_files+="dmg-content.sha256"$'\n'
fi
while IFS= read -r published_file; do
  published_name="$(basename "$published_file")"
  grep -Fx "$published_name" <<<"$allowed_files" >/dev/null ||
    die "unexpected published macOS file: $published_name"
done < <(find "$artifact_root" -maxdepth 1 -type f | LC_ALL=C sort)
verify_sha256_manifest "$artifact_root" "$artifact_root/$checksum_name" >/dev/null
note "validated $artifacts published macOS artifact(s) from $artifact_root"
