#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
[[ "$#" -eq 1 ]] || die "usage: release.sh sign|publish"
operation="$1"
case "$operation" in
  sign | publish) ;;
  *) die "unsupported release operation: $operation" ;;
esac

[[ "${RELEASE_MODE:-0}" == "1" ]] ||
  die "$operation requires explicit RELEASE_MODE=1"
[[ "${GITHUB_REF:-}" =~ ^refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "$operation requires an immutable semantic release tag"
[[ "${RELEASE_COMMIT:-}" =~ ^[0-9a-f]{40}$ ]] ||
  die "$operation requires a full lowercase RELEASE_COMMIT"
[[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "$RELEASE_COMMIT" ]] ||
  die "RELEASE_COMMIT does not match the checked-out source"
[[ "$(git -C "$REPO_ROOT" cat-file -t "$GITHUB_REF")" == "tag" ]] ||
  die "release ref must resolve to an annotated tag"
[[ "$(git -C "$REPO_ROOT" rev-parse "$GITHUB_REF^{commit}")" == "$RELEASE_COMMIT" ]] ||
  die "release tag does not select RELEASE_COMMIT"
[[ "${GITHUB_REF#refs/tags/v}" == "$VERSION" ]] ||
  die "release tag does not match the Cargo workspace version"

case "$operation" in
  sign)
    die "production signing is intentionally unconfigured in this prototype"
    ;;
  publish)
    die "repository publication is intentionally unconfigured in this prototype"
    ;;
esac
