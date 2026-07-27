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
  sudo rm -rf /etc/systemd/system/gta-claw-daemon.service.d
  sudo rm -f /etc/gta-claw/gta-claw.env.rpmsave
  sudo systemctl disable --now gta-claw-daemon.service >/dev/null 2>&1 || true
  if dpkg-query -W gta-claw >/dev/null 2>&1; then
    sudo dpkg --purge gta-claw >/dev/null 2>&1 || true
  fi
  if rpm -q gta-claw >/dev/null 2>&1; then
    sudo rpm -e --nodeps gta-claw >/dev/null 2>&1 || true
  fi
  sudo rm -f \
    /etc/gta-claw/gta-claw.env.rpmsave \
    /run/gta-claw-daemon.deb-was-active \
    /run/gta-claw-daemon.deb-was-enabled
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

install_failure_dropin() {
  local section="$1"
  local directive="$2"
  sudo mkdir -p /etc/systemd/system/gta-claw-daemon.service.d
  printf '[%s]\n%s\n' "$section" "$directive" |
    sudo tee /etc/systemd/system/gta-claw-daemon.service.d/failure.conf >/dev/null
  sudo systemctl daemon-reload
}

remove_failure_dropin() {
  sudo rm -rf /etc/systemd/system/gta-claw-daemon.service.d
  sudo systemctl daemon-reload
  sudo systemctl reset-failed gta-claw-daemon.service >/dev/null 2>&1 || true
}

sudo dpkg -i "$deb1"
assert_disabled_and_inactive
printf 'DEB_LIFECYCLE_MARKER=preserved\n' |
  sudo tee /etc/gta-claw/gta-claw.env >/dev/null
install_failure_dropin Service 'ExecStartPre=/bin/false'
if sudo systemctl start gta-claw-daemon.service; then
  die "intentional Debian start failure unexpectedly succeeded"
fi
remove_failure_dropin
sudo systemctl enable --now gta-claw-daemon.service
deb_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
install_failure_dropin Service 'ExecStartPre=/bin/false'
if sudo dpkg -i "$deb2"; then
  die "Debian upgrade swallowed an intentional restart failure"
fi
[[ "$(dpkg-query -W -f='${Status}' gta-claw)" != "install ok installed" ]] ||
  die "Debian package reported configured after restart failure"
remove_failure_dropin
sudo systemctl start gta-claw-daemon.service
sudo dpkg --configure gta-claw
assert_active_restart "$deb_pid"
[[ "$(sudo cat /etc/gta-claw/gta-claw.env)" == \
  "DEB_LIFECYCLE_MARKER=preserved" ]] ||
  die "Debian upgrade replaced administrator configuration"
sudo systemctl stop gta-claw-daemon.service
sudo dpkg -i --force-downgrade "$deb1"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "inactive service was started during Debian package replacement"
sudo systemctl start gta-claw-daemon.service
install_failure_dropin Unit 'RefuseManualStop=yes'
if sudo dpkg --remove gta-claw; then
  die "Debian removal swallowed an intentional stop failure"
fi
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "Debian removal unlinked the daemon after stop failure"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian failed removal did not restore the active service state"
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled" ]] ||
  die "Debian failed removal did not restore the enabled service state"
remove_failure_dropin
sudo systemctl start gta-claw-daemon.service
sudo dpkg --remove gta-claw
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian removal left the daemon active"
[[ "$(systemctl is-enabled gta-claw-daemon.service 2>/dev/null || true)" != "enabled" ]] ||
  die "Debian removal left the service enabled"
[[ ! -e /usr/libexec/gta-claw/gta-claw-daemon &&
  ! -e /usr/lib/systemd/system/gta-claw-daemon.service ]] ||
  die "Debian removal left package-owned executable or unit"
[[ "$(sudo cat /etc/gta-claw/gta-claw.env)" == \
  "DEB_LIFECYCLE_MARKER=preserved" ]] ||
  die "Debian removal did not preserve administrator configuration"
sudo dpkg --purge gta-claw
[[ ! -e /etc/gta-claw/gta-claw.env ]] ||
  die "Debian purge left the environment conffile"

sudo rpm -ivh --nodeps "$rpm1"
assert_disabled_and_inactive
printf 'RPM_LIFECYCLE_MARKER=preserved\n' |
  sudo tee /etc/gta-claw/gta-claw.env >/dev/null
install_failure_dropin Service 'ExecStartPre=/bin/false'
if sudo systemctl start gta-claw-daemon.service; then
  die "intentional RPM start failure unexpectedly succeeded"
fi
remove_failure_dropin
sudo systemctl enable --now gta-claw-daemon.service
rpm_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
install_failure_dropin Service 'ExecStartPre=/bin/false'
if sudo rpm -Uvh --nodeps "$rpm2"; then
  die "RPM upgrade swallowed an intentional restart failure"
fi
remove_failure_dropin
sudo systemctl start gta-claw-daemon.service
sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"
assert_active_restart "$rpm_pid"
[[ "$(sudo cat /etc/gta-claw/gta-claw.env)" == \
  "RPM_LIFECYCLE_MARKER=preserved" ]] ||
  die "RPM upgrade replaced administrator configuration"
sudo systemctl stop gta-claw-daemon.service
sudo rpm -Uvh --nodeps --oldpackage "$rpm1"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "inactive service was started during RPM replacement"
sudo systemctl start gta-claw-daemon.service
install_failure_dropin Unit 'RefuseManualStop=yes'
if sudo rpm -e --nodeps gta-claw; then
  die "RPM removal swallowed an intentional stop failure"
fi
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "RPM removal unlinked daemon after stop failure"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM removal stopped daemon despite refused stop"
remove_failure_dropin
sudo rpm -Uvh \
  --nodeps \
  --oldpackage \
  --replacefiles \
  --replacepkgs \
  "$rpm1"
sudo systemctl start gta-claw-daemon.service
sudo rpm -e --nodeps gta-claw
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM removal left the daemon active"
[[ "$(systemctl is-enabled gta-claw-daemon.service 2>/dev/null || true)" != "enabled" ]] ||
  die "RPM removal left the service enabled"
[[ ! -e /usr/libexec/gta-claw/gta-claw-daemon &&
  ! -e /usr/lib/systemd/system/gta-claw-daemon.service ]] ||
  die "RPM removal left package-owned executable or unit"
[[ ! -e /etc/gta-claw/gta-claw.env &&
  "$(sudo cat /etc/gta-claw/gta-claw.env.rpmsave)" == \
    "RPM_LIFECYCLE_MARKER=preserved" ]] ||
  die "RPM removal did not preserve administrator configuration as .rpmsave"

trap - EXIT INT TERM
echo "Debian and RPM install/start/upgrade/remove lifecycle tests passed"
