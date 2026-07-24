#!/bin/sh

set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

source_root="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
package_version="$(cat "$source_root/package-version")"
installed_version_file=/usr/share/doc/gta-claw/package-version
fresh_install=1

if [ "$(/usr/bin/id -ru)" != 0 ] || [ "$(/usr/bin/id -u)" != 0 ]; then
  echo "gta-claw direct installation requires real and effective UID 0" >&2
  exit 1
fi
if [ ! -x /usr/bin/setpriv ]; then
  echo "gta-claw direct installation requires /usr/bin/setpriv from util-linux" >&2
  exit 1
fi

validate_regular_or_absent() {
  path="$1"
  if [ -L "$path" ]; then
    echo "gta-claw install destination must not be a symlink: $path" >&2
    exit 1
  fi
  if [ -e "$path" ] && [ ! -f "$path" ]; then
    echo "gta-claw install destination is not a regular file: $path" >&2
    exit 1
  fi
}

validate_regular_or_absent "$installed_version_file"
validate_regular_or_absent /etc/gta-claw/gta-claw.env
validate_regular_or_absent /etc/gta-claw/credentials/daemon.conf

if [ -e "$installed_version_file" ]; then
  fresh_install=0
  installed_version="$(cat "$installed_version_file")"
  newest_version="$(
    printf '%s\n' "$installed_version" "$package_version" | sort -V | tail -n 1
  )"
  if [ "$installed_version" != "$package_version" ] &&
    [ "$newest_version" = "$installed_version" ]; then
    echo "refusing gta-claw downgrade from $installed_version to $package_version" >&2
    exit 1
  fi
fi

was_active=0
if [ -d /run/systemd/system ] &&
  systemctl is-active --quiet gta-claw-daemon.service; then
  touch /run/gta-claw-daemon.was-active
  systemctl stop gta-claw-daemon.service
fi
if [ -e /run/gta-claw-daemon.was-active ]; then
  was_active=1
fi

install -D -m 0644 "$source_root/lib/sysusers.d/gta-claw.conf" \
  /usr/lib/sysusers.d/gta-claw.conf
/usr/bin/systemd-sysusers /usr/lib/sysusers.d/gta-claw.conf
install -D -m 0755 "$source_root/bin/gta-claw-cli" /usr/bin/gta-claw-cli
install -D -m 0755 "$source_root/bin/gta-claw-daemon" \
  /usr/libexec/gta-claw/gta-claw-daemon
install -D -m 0755 "$source_root/libexec/gta-claw-state-init" \
  /usr/libexec/gta-claw/gta-claw-state-init
install -D -m 0755 "$source_root/libexec/gta-claw-runtime-ready" \
  /usr/libexec/gta-claw/gta-claw-runtime-ready
install -D -m 0644 "$source_root/lib/systemd/system/gta-claw-daemon.service" \
  /usr/lib/systemd/system/gta-claw-daemon.service
install -D -m 0644 "$source_root/lib/systemd/system/gta-claw-state-init.service" \
  /usr/lib/systemd/system/gta-claw-state-init.service
install -D -m 0644 "$source_root/lib/systemd/system-preset/80-gta-claw.preset" \
  /usr/lib/systemd/system-preset/80-gta-claw.preset
install -D -m 0644 "$source_root/package-version" "$installed_version_file"

if [ ! -e /etc/gta-claw/gta-claw.env ]; then
  install -D -m 0640 "$source_root/etc/gta-claw/gta-claw.env" \
    /etc/gta-claw/gta-claw.env
fi
if [ ! -e /etc/gta-claw/credentials/daemon.conf ]; then
  install -D -m 0600 "$source_root/etc/gta-claw/credentials/daemon.conf" \
    /etc/gta-claw/credentials/daemon.conf
fi

for document in \
  LICENSE.txt \
  NOTICE.txt \
  README.md \
  build-manifest.json \
  compose.yaml \
  gta-claw-daemon.socket.deferred \
  kubernetes.yaml \
  package-toolchain.json \
  runtime-manifest.json; do
  install -D -m 0644 "$source_root/share/doc/gta-claw/$document" \
    "/usr/share/doc/gta-claw/$document"
done

/usr/libexec/gta-claw/gta-claw-state-init

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  if [ "$fresh_install" -eq 1 ]; then
    systemctl preset gta-claw-daemon.service
  fi
  if [ "$was_active" -eq 1 ]; then
    systemctl restart gta-claw-daemon.service
    /usr/libexec/gta-claw/gta-claw-runtime-ready
    rm -f \
      /run/gta-claw-daemon.ready-for-replacement \
      /run/gta-claw-daemon.was-active
  fi
fi
