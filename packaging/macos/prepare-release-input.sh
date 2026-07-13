#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_macos
for tool in ditto gzip plutil tar; do
  require_tool "$tool"
done
[[ "$#" -eq 3 ]] || die "usage: prepare-release-input.sh APP SOURCE_SHA SOURCE_REF"
app="$1"
source_sha="$2"
source_ref="$3"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || die "source SHA must be a full lowercase commit SHA"
[[ "$source_ref" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "release input requires a semantic vX.Y.Z tag ref"
[[ -d "$app" && "$app" == *.app && ! -L "$app" ]] || die "invalid release app: $app"
reject_symlinks "$app"

release_root="$OUTPUT_ROOT/release-input"
stage="$release_root/stage/release-input"
archive="$release_root/gta-claw-$VERSION-release-input.tar.gz"
for destination in "$release_root" "$stage" "$archive"; do
  assert_output_path "$destination"
done
safe_reset_dir "$release_root"
mkdir -p "$stage"
assert_output_path "$stage/$APP_NAME.app"
ditto "$app" "$stage/$APP_NAME.app"
reject_symlinks "$stage"

metadata="$stage/release-metadata.plist"
plutil -create xml1 "$metadata"
/usr/libexec/PlistBuddy -c "Add :SourceSHA string $source_sha" "$metadata"
/usr/libexec/PlistBuddy -c "Add :SourceRef string $source_ref" "$metadata"
/usr/libexec/PlistBuddy -c "Add :Version string $VERSION" "$metadata"
/usr/libexec/PlistBuddy -c "Add :BundleIdentifier string $BUNDLE_ID" "$metadata"
/usr/libexec/PlistBuddy -c "Add :MinimumSystemVersion string $MINIMUM_MACOS_VERSION" "$metadata"
plutil -lint "$metadata" >/dev/null

write_sha256_manifest "$stage" "$stage/SHA256SUMS"
find "$stage" -exec touch -t "$NORMALIZED_MTIME" {} +
(
  cd "$(dirname "$stage")"
  COPYFILE_DISABLE=1 tar \
    --format ustar \
    --uid 0 \
    --gid 0 \
    --uname root \
    --gname wheel \
    -cf - \
    "$(basename "$stage")"
) | gzip -n -9 >"$archive"
printf '%s\n' "$(sha256_file "$archive")"
