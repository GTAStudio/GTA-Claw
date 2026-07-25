#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
HELPER="$SCRIPT_DIR/../direct/config-safeio.py"

[[ "$(id -u)" -eq 0 ]] ||
  {
    echo "direct configuration self-test must run as root" >&2
    exit 1
  }
[[ "$#" -eq 1 && "$1" == /* && ! -e "$1" && ! -L "$1" ]] ||
  {
    echo "usage: direct-config-self-test.sh NEW_ABSOLUTE_ROOT" >&2
    exit 1
  }

root="$1"
environment_source="$root-environment"
credential_source="$root-credential"
entered="$root-gate-entered"
release="$root-gate-release"

cleanup() {
  rm -rf -- \
    "$root" \
    "$environment_source" \
    "$credential_source" \
    "$entered" \
    "$release"
}
trap cleanup EXIT INT TERM

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    echo "direct configuration self-test expected failure: $*" >&2
    exit 1
  fi
}

install -d -o root -g root -m 0755 "$root"
printf '# Valid comments-only environment file.\n' >"$environment_source"
printf 'fixture credential\n' >"$credential_source"
chmod 0644 "$environment_source" "$credential_source"

"$HELPER" \
  install \
  "$root" \
  "$environment_source" \
  "$credential_source"
"$HELPER" \
  verify \
  "$root" \
  "$environment_source" \
  "$credential_source"

chmod 0775 "$root/etc/gta-claw"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
chmod 0755 "$root/etc/gta-claw"

chown 1:1 "$root/etc/gta-claw"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
chown 0:0 "$root/etc/gta-claw"

mv "$root/etc/gta-claw/gta-claw.env" "$root/etc/gta-claw/gta-claw.env.saved"
ln \
  "$root/etc/gta-claw/gta-claw.env.saved" \
  "$root/etc/gta-claw/gta-claw.env"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
rm "$root/etc/gta-claw/gta-claw.env"
mv "$root/etc/gta-claw/gta-claw.env.saved" "$root/etc/gta-claw/gta-claw.env"

printf 'LD_PRELOAD=/tmp/attacker.so\n' >"$environment_source"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
printf '# Valid comments-only environment file.\n' >"$environment_source"

GTA_CLAW_DIRECT_CONFIG_GATE_ENTERED="$entered" \
  GTA_CLAW_DIRECT_CONFIG_GATE_RELEASE="$release" \
  "$HELPER" \
  verify \
  "$root" \
  "$environment_source" \
  "$credential_source" \
  >/dev/null 2>&1 &
helper_pid=$!
deadline=$((SECONDS + 10))
while [[ ! -e "$entered" ]]; do
  ((SECONDS < deadline)) ||
    {
      echo "direct configuration race gate did not open" >&2
      exit 1
    }
  sleep 0.01
done
mv "$root/etc/gta-claw" "$root/etc/gta-claw.saved"
install -d -o root -g root -m 0755 "$root/etc/gta-claw"
install -d -o root -g root -m 0700 "$root/etc/gta-claw/credentials"
touch "$release"
if wait "$helper_pid"; then
  echo "direct configuration validator accepted an ancestor replacement race" >&2
  exit 1
fi
rm -rf "$root/etc/gta-claw"
mv "$root/etc/gta-claw.saved" "$root/etc/gta-claw"

"$HELPER" \
  verify \
  "$root" \
  "$environment_source" \
  "$credential_source"

printf 'direct configuration self-test passed\n'
