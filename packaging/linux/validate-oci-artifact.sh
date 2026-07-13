#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/oci-validation.sh"

require_linux
for tool in jq readelf sha256sum stat tar; do
  require_tool "$tool"
done
[[ "$#" -eq 3 ]] || die "usage: validate-oci-artifact.sh ARCHIVE ARCH VALIDATION_ROOT"
validate_published_oci "$1" "$2" "$3"
echo "Published OCI artifact validation passed"
