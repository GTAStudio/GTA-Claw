#!/bin/sh

set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$(/usr/bin/id -ru)" != 0 ] || [ "$(/usr/bin/id -u)" != 0 ]; then
  echo "gta-claw direct removal requires real and effective UID 0" >&2
  exit 1
fi

assert_unit_inactive() {
  unit="$1"
  active_state="$(systemctl show -P ActiveState "$unit")"
  main_pid="$(systemctl show -P MainPID "$unit")"
  control_pid="$(systemctl show -P ControlPID "$unit")"
  if { [ "$active_state" != inactive ] && [ "$active_state" != failed ]; } ||
    [ "$main_pid" != 0 ] ||
    [ "$control_pid" != 0 ]; then
    echo "$unit is not in a process-free inactive state" >&2
    exit 1
  fi
}

if [ -d /run/systemd/system ]; then
  systemctl stop gta-claw-daemon.service
  systemctl stop gta-claw-state-init.service
  assert_unit_inactive gta-claw-daemon.service
  assert_unit_inactive gta-claw-state-init.service
  systemctl disable gta-claw-daemon.service
  rm -f \
    /run/gta-claw-daemon.ready-for-replacement \
    /run/gta-claw-daemon.was-active
fi

rm -f \
  /usr/bin/gta-claw-cli \
  /usr/libexec/gta-claw/gta-claw-daemon \
  /usr/libexec/gta-claw/gta-claw-runtime-ready \
  /usr/libexec/gta-claw/gta-claw-state-init \
  /usr/lib/systemd/system/gta-claw-daemon.service \
  /usr/lib/systemd/system/gta-claw-state-init.service \
  /usr/lib/systemd/system-preset/80-gta-claw.preset \
  /usr/lib/sysusers.d/gta-claw.conf \
  /usr/share/doc/gta-claw/LICENSE.txt \
  /usr/share/doc/gta-claw/NOTICE.txt \
  /usr/share/doc/gta-claw/README.md \
  /usr/share/doc/gta-claw/build-manifest.json \
  /usr/share/doc/gta-claw/compose.yaml \
  /usr/share/doc/gta-claw/gta-claw-daemon.socket.deferred \
  /usr/share/doc/gta-claw/kubernetes.yaml \
  /usr/share/doc/gta-claw/package-toolchain.json \
  /usr/share/doc/gta-claw/package-version \
  /usr/share/doc/gta-claw/runtime-manifest.json

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi

echo "preserved /var/lib/gta-claw-protected and the gta-claw service identity"
