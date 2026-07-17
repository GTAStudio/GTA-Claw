#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in ditto plutil xcrun; do
  require_tool "$tool"
done
[[ "$#" -eq 1 ]] || die "usage: notarize.sh APP|DMG|PKG"
artifact="$1"
[[ -e "$artifact" && ! -L "$artifact" ]] || die "missing notarization artifact: $artifact"

credential_args=()
if [[ -n "${NOTARY_PROFILE:-}" ]]; then
  credential_args+=(--keychain-profile "$NOTARY_PROFILE")
  if [[ -n "${NOTARY_KEYCHAIN:-}" ]]; then
    credential_args+=(--keychain "$NOTARY_KEYCHAIN")
  fi
elif [[ -n "${ASC_KEY_PATH:-}" && -n "${ASC_KEY_ID:-}" && -n "${ASC_ISSUER_ID:-}" ]]; then
  [[ -f "$ASC_KEY_PATH" && ! -L "$ASC_KEY_PATH" ]] || die "ASC_KEY_PATH is not a regular file"
  credential_args+=(--key "$ASC_KEY_PATH" --key-id "$ASC_KEY_ID" --issuer "$ASC_ISSUER_ID")
else
  die "notarization requires NOTARY_PROFILE or complete App Store Connect API credentials"
fi

submission="$artifact"
temporary_zip=""
if [[ -d "$artifact" && "$artifact" == *.app ]]; then
  assert_app_executable_contract "$artifact"
  codesign --verify --deep --strict --verbose=2 "$artifact"
  temporary_zip="$OUTPUT_ROOT/notarization/$(basename "$artifact").zip"
  assert_output_path "$temporary_zip"
  ensure_output_directory "$(dirname "$temporary_zip")"
  remove_output_file "$temporary_zip"
  assert_output_file_slot "$temporary_zip"
  ditto -c -k --keepParent "$artifact" "$temporary_zip"
  submission="$temporary_zip"
elif [[ "$artifact" != *.dmg && "$artifact" != *.pkg ]]; then
  die "notarytool submission must be an app, DMG, or PKG"
fi

result_template="$OUTPUT_ROOT/notary-result.XXXXXX"
assert_output_path "$result_template"
result="$(mktemp "$result_template")"
assert_output_file_slot "$result"
cleanup() {
  rm -f -- "$result"
  if [[ -n "$temporary_zip" ]]; then
    rm -f -- "$temporary_zip"
  fi
}
trap cleanup EXIT INT TERM

xcrun notarytool submit \
  "$submission" \
  "${credential_args[@]}" \
  --wait \
  --output-format json \
  >"$result"

status="$(plutil -extract status raw -o - "$result")"
request_id="$(plutil -extract id raw -o - "$result")"
if [[ "$status" != "Accepted" ]]; then
  printf 'notarization request %s returned status %s\n' "$request_id" "$status" >&2
  xcrun notarytool log "$request_id" "${credential_args[@]}" || true
  die "notarization was not accepted"
fi

xcrun stapler staple "$artifact"
xcrun stapler validate "$artifact"
if [[ -d "$artifact" && "$artifact" == *.app ]]; then
  assert_app_executable_contract "$artifact"
  codesign --verify --deep --strict --verbose=2 "$artifact"
fi
if [[ "$(dirname "$artifact")" == "$OUTPUT_ROOT/distribution" &&
  -f "$OUTPUT_ROOT/distribution/SHA256SUMS" ]]; then
  write_sha256_manifest "$OUTPUT_ROOT/distribution" "$OUTPUT_ROOT/distribution/SHA256SUMS"
fi
note "notarization accepted and stapled for $artifact (request $request_id)"
