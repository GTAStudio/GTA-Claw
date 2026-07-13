#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in dpkg rpm systemctl; do
  require_tool "$tool"
done
[[ "$#" -eq 4 ]] ||
  die "usage: lifecycle-test.sh DEB_RELEASE_1 DEB_RELEASE_2 RPM_RELEASE_1 RPM_RELEASE_2"
deb1="$1"
deb2="$2"
rpm1="$3"
rpm2="$4"
for package in "$deb1" "$deb2" "$rpm1" "$rpm2"; do
  assert_regular_unaliased "$package" "lifecycle package"
done
[[ "$(ps -p 1 -o comm= | tr -d ' ')" == "systemd" ]] ||
  die "lifecycle test requires systemd as PID 1"

cleanup() {
  sudo systemctl disable --now gta-claw-daemon.service >/dev/null 2>&1 || true
  if dpkg-query -W gta-claw >/dev/null 2>&1; then
    sudo dpkg --purge gta-claw >/dev/null 2>&1 || true
  fi
  if rpm -q gta-claw >/dev/null 2>&1; then
    sudo rpm -e --nodeps gta-claw >/dev/null 2>&1 || true
  fi
  sudo systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
cleanup

assert_disabled_and_inactive() {
  local state
  state="$(systemctl is-enabled gta-claw-daemon.service 2>/dev/null || true)"
  [[ "$state" != "enabled" ]] || die "service was enabled on fresh package install"
  ! systemctl is-active --quiet gta-claw-daemon.service ||
    die "service was started on fresh package install"
}

assert_active_restart() {
  local old_pid="$1"
  local new_pid
  systemctl is-active --quiet gta-claw-daemon.service ||
    die "service is not active after package upgrade"
  new_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
  [[ "$new_pid" =~ ^[1-9][0-9]*$ && "$new_pid" != "$old_pid" ]] ||
    die "active service was not restarted during package upgrade"
}

sudo dpkg -i "$deb1"
assert_disabled_and_inactive
sudo systemctl enable --now gta-claw-daemon.service
deb_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
sudo dpkg -i "$deb2"
assert_active_restart "$deb_pid"
sudo systemctl stop gta-claw-daemon.service
sudo dpkg -i --force-downgrade "$deb1"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "inactive service was started during Debian package replacement"
sudo systemctl start gta-claw-daemon.service
sudo dpkg --remove gta-claw
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian removal left the daemon active"
[[ ! -e /usr/libexec/gta-claw/gta-claw-daemon &&
  ! -e /usr/lib/systemd/system/gta-claw-daemon.service ]] ||
  die "Debian removal left package-owned executable or unit"
sudo dpkg --purge gta-claw

sudo rpm -ivh --nodeps "$rpm1"
assert_disabled_and_inactive
sudo systemctl enable --now gta-claw-daemon.service
rpm_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
sudo rpm -Uvh --nodeps "$rpm2"
assert_active_restart "$rpm_pid"
sudo systemctl stop gta-claw-daemon.service
sudo rpm -Uvh --nodeps --oldpackage "$rpm1"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "inactive service was started during RPM replacement"
sudo systemctl start gta-claw-daemon.service
sudo rpm -e --nodeps gta-claw
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM removal left the daemon active"
[[ ! -e /usr/libexec/gta-claw/gta-claw-daemon &&
  ! -e /usr/lib/systemd/system/gta-claw-daemon.service ]] ||
  die "RPM removal left package-owned executable or unit"

trap - EXIT INT TERM
echo "Debian and RPM install/start/upgrade/remove lifecycle tests passed"
