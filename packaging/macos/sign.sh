#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
require_tool codesign
require_tool security

[[ "$#" -eq 2 ]] || die "usage: sign.sh adhoc|release APP"
mode="$1"
app="$2"
[[ -d "$app/Contents" && ! -L "$app" ]] || die "invalid app bundle: $app"
reject_symlinks "$app"

identity="-"
timestamp="--timestamp=none"
if [[ "$mode" == "release" ]]; then
  : "${DEVELOPER_ID_APPLICATION:?DEVELOPER_ID_APPLICATION is required in release mode}"
  [[ "$DEVELOPER_ID_APPLICATION" == "Developer ID Application:"* ]] ||
    die "release identity must be a Developer ID Application identity"
  identity_args=(-p codesigning -v)
  if [[ -n "${SIGNING_KEYCHAIN:-}" ]]; then
    identity_args+=("$SIGNING_KEYCHAIN")
  fi
  security find-identity "${identity_args[@]}" 2>/dev/null |
    grep -F "\"$DEVELOPER_ID_APPLICATION\"" >/dev/null ||
    die "Developer ID Application identity is unavailable or invalid"
  identity="$DEVELOPER_ID_APPLICATION"
  timestamp="--timestamp"
elif [[ "$mode" != "adhoc" ]]; then
  die "unknown signing mode: $mode"
fi

if [[ -d "$app/Contents/Frameworks" ]]; then
  while IFS= read -r code; do
    codesign --force --options runtime "$timestamp" --sign "$identity" "$code"
  done < <(
    find "$app/Contents/Frameworks" -type f \( -name '*.dylib' -o -perm -111 \) -print |
      awk '{ print length, $0 }' |
      sort -rn |
      cut -d' ' -f2-
  )
  while IFS= read -r framework; do
    codesign --force --options runtime "$timestamp" --sign "$identity" "$framework"
  done < <(
    find "$app/Contents/Frameworks" -type d -name '*.framework' -print |
      awk '{ print length, $0 }' |
      sort -rn |
      cut -d' ' -f2-
  )
fi

codesign \
  --force \
  --options runtime \
  "$timestamp" \
  --entitlements "$MACOS_DIR/gta-claw.entitlements" \
  --identifier "$BUNDLE_ID" \
  --sign "$identity" \
  "$app"

codesign --verify --deep --strict --verbose=2 "$app"
details="$(codesign -dvvv "$app" 2>&1)"
requirement="$(codesign -d -r- "$app" 2>&1)"
grep -F "designated =>" <<<"$requirement" >/dev/null ||
  die "code signature has no designated requirement"

if [[ "$mode" == "release" ]]; then
  grep -F "identifier \"$BUNDLE_ID\"" <<<"$requirement" >/dev/null ||
    die "release designated requirement does not contain $BUNDLE_ID"
  grep -F "Authority=Developer ID Application:" <<<"$details" >/dev/null ||
    die "release signature has no Developer ID Application authority"
  grep -F "Timestamp=" <<<"$details" >/dev/null ||
    die "release signature has no secure timestamp"
  grep -E 'flags=.*runtime' <<<"$details" >/dev/null ||
    die "release signature does not enable hardened runtime"
else
  grep -F "Signature=adhoc" <<<"$details" >/dev/null ||
    die "CI signature is not ad hoc"
fi

note "$mode signed $app"
