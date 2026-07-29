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
    /run/gta-claw-daemon.deb-was-enabled \
    /run/gta-claw-daemon.old-nevra \
    /run/gta-claw-daemon.was-active \
    /run/gta-claw-daemon.was-enabled \
    /run/gta-claw-daemon.was-enabled-runtime \
    /run/gta-claw-daemon.upgrade-prepared \
    /run/gta-claw-daemon.upgrade-configured \
    /run/gta-claw-daemon.remove-was-active \
    /run/gta-claw-daemon.remove-was-enabled \
    /run/gta-claw-daemon.remove-was-enabled-runtime \
    /run/gta-claw-daemon.remove-prepared \
    /run/gta-claw-daemon.operator-lifecycle-marker
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
old_nevra="$(rpm -q --qf '%{NEVRA}\n' gta-claw)"
old_payload="$(
  rpm -ql gta-claw |
    while IFS= read -r path; do
      if sudo test -f "$path" && ! sudo test -L "$path"; then
        sudo sha256sum "$path"
      fi
    done
)"
printf 'operator lifecycle marker\n' |
  sudo tee /run/gta-claw-daemon.operator-lifecycle-marker >/dev/null
old_marker="$(
  sudo sha256sum /run/gta-claw-daemon.operator-lifecycle-marker |
    awk '{print $1}'
)"
if sudo env GTA_CLAW_PACKAGE_TEST_FAIL_UPGRADE_PREPARE=1 \
  rpm -Uvh --nodeps "$rpm2"; then
  die "RPM pre-mutation upgrade failure unexpectedly succeeded"
fi
[[ "$(rpm -q --qf '%{NEVRA}\n' gta-claw)" == "$old_nevra" ]] ||
  die "failed RPM upgrade did not retain exactly the old installed NEVRA"
current_payload="$(
  rpm -ql gta-claw |
    while IFS= read -r path; do
      if sudo test -f "$path" && ! sudo test -L "$path"; then
        sudo sha256sum "$path"
      fi
    done
)"
[[ "$current_payload" == "$old_payload" ]] ||
  die "failed RPM upgrade changed the prior package payload"
[[ "$(
  sudo sha256sum /run/gta-claw-daemon.operator-lifecycle-marker |
    awk '{print $1}'
)" == "$old_marker" ]] ||
  die "failed RPM upgrade changed the lifecycle marker"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "pre-mutation RPM failure changed the active service state"
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled" ]] ||
  die "pre-mutation RPM failure changed service enablement"
sudo rpm -Uvh --nodeps "$rpm2"
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
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled" ]] ||
  die "failed RPM removal did not restore the enabled service state"
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

sudo rm -f /run/gta-claw-daemon.operator-lifecycle-marker
trap - EXIT INT TERM
echo "Debian and RPM install/start/upgrade/remove lifecycle tests passed"
