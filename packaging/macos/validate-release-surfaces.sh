#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
inventory="$REPO_ROOT/compat/upstream/inventories/release-deployment.json"
implementation="$SCRIPT_DIR/release-surfaces.json"

grep -F '"inventory_id":  "release-deployment"' "$inventory" >/dev/null
grep -F '"total":  24' "$inventory" >/dev/null
grep -F '"schema": 1' "$implementation" >/dev/null
grep -F '"platform": "macos"' "$implementation" >/dev/null

work="$REPO_ROOT/target/macos-release-surfaces-$$"
[[ ! -e "$work" && ! -L "$work" ]] || {
  printf 'validation work path already exists: %s\n' "$work" >&2
  exit 1
}
mkdir -p "$work"
expected="$work/expected"
actual="$work/actual"
trap 'rm -rf -- "$work"' EXIT

awk -F'"' '/"id":/ { print $4 }' "$inventory" |
  while IFS= read -r id; do
    case "$id" in
      github-release | installer | macos | macos-*) printf '%s\n' "$id" ;;
    esac
  done | LC_ALL=C sort >"$expected"

awk '
  /"implemented": \[/ { in_implemented = 1; next }
  in_implemented && /\]/ { exit }
  in_implemented {
    gsub(/[",[:space:]]/, "")
    if (length($0) > 0) print
  }
' "$implementation" | LC_ALL=C sort >"$actual"

cmp -s "$expected" "$actual" || {
  printf 'error: macOS release surfaces differ from the frozen inventory\n' >&2
  diff -u "$expected" "$actual" >&2 || true
  exit 1
}
printf 'macOS frozen release surfaces match exactly: %s\n' "$(paste -sd, "$actual")"
