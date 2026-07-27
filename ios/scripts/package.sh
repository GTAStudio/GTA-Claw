#!/usr/bin/env bash
set -euo pipefail

workspace_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_root="${1:-$workspace_root/target/ios-package}"

if ! xcodegen --version | grep -F '2.46.0' >/dev/null; then
  echo "XcodeGen 2.46.0 is required" >&2
  exit 1
fi

mkdir -p "$output_root"
project="$workspace_root/GTAClaw.xcodeproj"
xcodegen generate --spec "$workspace_root/project.yml" --project "$workspace_root"

SKIA_CACHE_DIR="${SKIA_CACHE_DIR:-$output_root/skia}" xcodebuild archive \
  -project "$project" \
  -scheme GTAClaw \
  -configuration Release \
  -sdk iphoneos \
  -archivePath "$output_root/GTAClaw.xcarchive" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGNING_REQUIRED=NO

test -d "$output_root/GTAClaw.xcarchive"
