#!/bin/sh

set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$(/usr/bin/id -ru)" != 0 ] || [ "$(/usr/bin/id -u)" != 0 ]; then
  echo "gta-claw direct removal requires real and effective UID 0" >&2
  exit 1
fi

stop_unit_if_present() {
  unit="$1"
  disable="$2"
  load_state="$(systemctl show -P LoadState "$unit")"
  if [ "$load_state" = "not-found" ]; then
    return
  fi
  if [ -z "$load_state" ]; then
    echo "gta-claw could not determine unit load state: $unit" >&2
    exit 1
  fi
  systemctl stop "$unit"
  active_state="$(systemctl show -P ActiveState "$unit")"
  case "$active_state" in
    inactive | failed) ;;
    *) {
      echo "gta-claw unit remains $active_state after direct stop: $unit" >&2
      exit 1
    } ;;
  esac
  if [ "$disable" = "yes" ]; then
    systemctl disable "$unit"
  fi
}

if [ -d /run/systemd/system ]; then
  stop_unit_if_present gta-claw-daemon.service yes
  stop_unit_if_present gta-claw-state-init.service no
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
