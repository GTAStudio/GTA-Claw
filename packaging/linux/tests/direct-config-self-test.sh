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
validated_environment="$root/run/gta-claw-state-init/gta-claw.env"
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

write_valid_environment() {
  cat >"$environment_source" <<'EOF'
ENABLE_TEAMS=false
AGENT_ROLE_URL=http://127.0.0.1:43119/role.json
DEVICE_FLOW_ENABLED=true
GITHUB_CLIENT_ID=gta-claw-lifecycle-fixture
EOF
}

write_predecessor_environment() {
  cat <<'EOF'
# Non-secret process environment only.
#
# The current daemon accepts no environment-backed runtime configuration.
# Never place tokens, passwords, or private keys here. Future secrets must be
# supplied through /etc/gta-claw/credentials/daemon.conf and consumed from the
# systemd CREDENTIALS_DIRECTORY by a daemon version that explicitly supports it.
EOF
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    echo "direct configuration self-test expected failure: $*" >&2
    exit 1
  fi
}

expect_failure "$HELPER" network-deny-check gta-claw-missing-policy.service

install -d -o root -g root -m 0755 "$root"
install -d -o root -g root -m 0755 "$root/run/gta-claw-state-init"
write_valid_environment
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
write_predecessor_environment >"$root/etc/gta-claw/gta-claw.env"
chown 0:0 "$root/etc/gta-claw/gta-claw.env"
chmod 0640 "$root/etc/gta-claw/gta-claw.env"
touch "$root/etc/gta-claw/.gta-claw.env.migrate"
expect_failure \
  "$HELPER" install "$root" "$environment_source" "$credential_source"
[[ ! -e "$root/etc/gta-claw/.gta-claw.env.migrate" ]]
"$HELPER" \
  install \
  "$root" \
  "$environment_source" \
  "$credential_source"
cmp -s "$environment_source" "$root/etc/gta-claw/gta-claw.env"
{
  write_predecessor_environment
  printf '# local drift\n'
} >"$root/etc/gta-claw/gta-claw.env"
expect_failure \
  "$HELPER" install "$root" "$environment_source" "$credential_source"
install -o root -g root -m 0640 \
  "$environment_source" \
  "$root/etc/gta-claw/gta-claw.env"
"$HELPER" \
  materialize \
  "$root" \
  "$root/etc/gta-claw/gta-claw.env" \
  "$root/etc/gta-claw/credentials/daemon.conf"
cmp -s "$environment_source" "$validated_environment"
[[ "$(stat -c '%u:%g:%a:%h' "$validated_environment")" == "0:0:640:1" ]]
mv "$validated_environment" "$validated_environment.saved"
ln -s /bin/true "$validated_environment"
expect_failure \
  "$HELPER" materialize \
  "$root" \
  "$root/etc/gta-claw/gta-claw.env" \
  "$root/etc/gta-claw/credentials/daemon.conf"
rm "$validated_environment"
mv "$validated_environment.saved" "$validated_environment"

rm -f "$entered" "$release"
GTA_CLAW_DIRECT_CONFIG_GATE_ENTERED="$entered" \
  GTA_CLAW_DIRECT_CONFIG_GATE_RELEASE="$release" \
  "$HELPER" \
  materialize \
  "$root" \
  "$root/etc/gta-claw/gta-claw.env" \
  "$root/etc/gta-claw/credentials/daemon.conf" \
  >/dev/null 2>&1 &
helper_pid=$!
deadline=$((SECONDS + 10))
while [[ ! -e "$entered" ]]; do
  ((SECONDS < deadline)) ||
    {
      echo "materialize replacement race gate did not open" >&2
      exit 1
    }
  sleep 0.01
done
mv "$root/etc/gta-claw/gta-claw.env" \
  "$root/etc/gta-claw/gta-claw.env.saved"
sed 's/gta-claw-lifecycle-fixture/replacement-client/' \
  "$root/etc/gta-claw/gta-claw.env.saved" \
  >"$root/etc/gta-claw/gta-claw.env"
chown 0:0 "$root/etc/gta-claw/gta-claw.env"
chmod 0640 "$root/etc/gta-claw/gta-claw.env"
touch "$release"
if wait "$helper_pid"; then
  echo "materializer accepted an environment identity replacement race" >&2
  exit 1
fi
cmp -s "$environment_source" "$validated_environment"
rm "$root/etc/gta-claw/gta-claw.env"
mv "$root/etc/gta-claw/gta-claw.env.saved" \
  "$root/etc/gta-claw/gta-claw.env"

rm -f "$entered" "$release"
GTA_CLAW_DIRECT_CONFIG_GATE_ENTERED="$entered" \
  GTA_CLAW_DIRECT_CONFIG_GATE_RELEASE="$release" \
  "$HELPER" \
  materialize \
  "$root" \
  "$root/etc/gta-claw/gta-claw.env" \
  "$root/etc/gta-claw/credentials/daemon.conf" \
  >/dev/null 2>&1 &
helper_pid=$!
deadline=$((SECONDS + 10))
while [[ ! -e "$entered" ]]; do
  ((SECONDS < deadline)) ||
    {
      echo "materialize in-place race gate did not open" >&2
      exit 1
    }
  sleep 0.01
done
sed 's/gta-claw-lifecycle-fixture/in-place-client/' \
  "$root/etc/gta-claw/gta-claw.env" \
  >"$root/etc/gta-claw/gta-claw.env.replacement"
cat "$root/etc/gta-claw/gta-claw.env.replacement" \
  >"$root/etc/gta-claw/gta-claw.env"
rm "$root/etc/gta-claw/gta-claw.env.replacement"
chmod 0600 "$root/etc/gta-claw/gta-claw.env"
touch "$release"
if wait "$helper_pid"; then
  echo "materializer accepted an in-place environment mutation race" >&2
  exit 1
fi
cmp -s "$environment_source" "$validated_environment"
install -o root -g root -m 0640 \
  "$environment_source" \
  "$root/etc/gta-claw/gta-claw.env"

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
printf 'GITHUB_TOKEN=attacker-token\nENABLE_TEAMS=false\n' >"$environment_source"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
printf 'UNKNOWN_PHASE_ONE_KEY=value\nENABLE_TEAMS=false\n' >"$environment_source"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
printf 'ENABLE_TEAMS=false\nDEVICE_FLOW_ENABLED=true\n' >"$environment_source"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
printf 'ENABLE_TEAMS=false\nENABLE_TEAMS=false\n' >"$environment_source"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
printf 'ENABLE_TEAMS=false\nAGENT_ROLE_URL=http://user@127.0.0.1/role.json\n' \
  >"$environment_source"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
printf 'ENABLE_TEAMS=false\nAGENT_ROLE_URL=http://127.0.0.1/role.json?access_token=secret\n' \
  >"$environment_source"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
printf '# continued comment\\\nGITHUB_TOKEN=attacker-token\nENABLE_TEAMS=false\n' \
  >"$environment_source"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
printf 'ENABLE_TEAMS=false\vGITHUB_TOKEN=attacker-token\n' \
  >"$environment_source"
expect_failure \
  "$HELPER" verify "$root" "$environment_source" "$credential_source"
write_valid_environment

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
