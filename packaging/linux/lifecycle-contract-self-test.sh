#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/lifecycle-validation.sh"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

work="$SCRIPT_DIR/.lifecycle-contract-self-test-$$"
rm -rf -- "$work"
mkdir -m 0700 -- "$work"
trap 'rm -rf -- "$work"' EXIT INT TERM
tests=0

expect_failure() {
  local name="$1"
  shift
  tests=$((tests + 1))
  if ( "$@" ) >"$work/$name.stdout" 2>"$work/$name.stderr"; then
    printf 'expected lifecycle contract failure: %s\n' "$name" >&2
    exit 1
  fi
}

validate_debian_lifecycle_contract "$SCRIPT_DIR/debian"
rpm_source="$(
  cat \
    "$SCRIPT_DIR/rpm/pre" \
    "$SCRIPT_DIR/rpm/post" \
    "$SCRIPT_DIR/rpm/preun" \
    "$SCRIPT_DIR/rpm/postun" \
    "$SCRIPT_DIR/rpm/posttrans"
)"
validate_rpm_lifecycle_contract "$rpm_source"
"$SCRIPT_DIR/rpm-lifecycle-self-test.sh"

cp -R "$SCRIPT_DIR/debian" "$work/missing-disable"
sed -i.bak \
  '/systemctl --system disable gta-claw-daemon.service/d' \
  "$work/missing-disable/prerm"
rm "$work/missing-disable/prerm.bak"
expect_failure missing-debian-disable \
  validate_debian_lifecycle_contract "$work/missing-disable"

cp -R "$SCRIPT_DIR/debian" "$work/swallowed-stop"
sed -i.bak \
  's/deb-systemd-invoke stop gta-claw-daemon.service >\/dev\/null/& || true/' \
  "$work/swallowed-stop/prerm"
rm "$work/swallowed-stop/prerm.bak"
expect_failure swallowed-debian-stop \
  validate_debian_lifecycle_contract "$work/swallowed-stop"

expect_failure suppressed-rpm-diagnostics \
  validate_rpm_lifecycle_contract \
  "$rpm_source"$'\n''systemctl status gta-claw-daemon.service >/dev/null 2>&1'

printf 'Lifecycle contract self-tests passed (%d negative cases)\n' "$tests"
