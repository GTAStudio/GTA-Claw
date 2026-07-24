#!/bin/sh

set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

source_root="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
package_version="$(cat "$source_root/package-version")"
installed_version_file=/usr/share/doc/gta-claw/package-version
runtime_directory=/run/gta-claw-state-init
failure_marker=$runtime_directory/initialization-failed
replacement_fence=$runtime_directory/replacement-fenced
lock=/var/lib/gta-claw-protected/state.writer.lock
was_active_marker=/run/gta-claw-daemon.was-active
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

ensure_failure_fence() {
  if [ -L "$runtime_directory" ] ||
    { [ -e "$runtime_directory" ] && [ ! -d "$runtime_directory" ]; }; then
    echo "gta-claw initialization runtime path is not a physical directory" >&2
    exit 1
  fi
  if [ ! -e "$runtime_directory" ]; then
    mkdir -m 0755 -- "$runtime_directory"
  fi
  if [ "$(stat -c '%u:%g:%a' "$runtime_directory")" != "0:0:755" ]; then
    echo "gta-claw initialization runtime directory must be root:root mode 0755" >&2
    exit 1
  fi
  if [ -L "$failure_marker" ] ||
    { [ -e "$failure_marker" ] && [ ! -f "$failure_marker" ]; }; then
    echo "gta-claw initialization failure marker is not a physical file" >&2
    exit 1
  fi
  touch "$failure_marker"
  chown 0:0 "$failure_marker"
  chmod 0644 "$failure_marker"
}

lock_holder_pid() {
  if ! locks="$(lslocks --noheadings --notruncate --output PID,PATH)"; then
    echo "gta-claw writer-lock ownership could not be inspected" >&2
    exit 1
  fi
  printf '%s\n' "$locks" |
    awk -v path="$lock" '$2 == path { print $1; exit }'
}

verify_unit_stopped() {
  unit="$1"
  label="$2"
  active_state="$(systemctl show -P ActiveState "$unit")"
  main_pid="$(systemctl show -P MainPID "$unit")"
  control_pid="$(systemctl show -P ControlPID "$unit")"
  case "$active_state:$main_pid:$control_pid" in
    inactive:0:0 | failed:0:0) ;;
    *) {
      echo "$label remains $active_state with MainPID $main_pid and ControlPID $control_pid" >&2
      exit 1
    } ;;
  esac
}

verify_writer_lock_released() {
  lock_pid="$(lock_holder_pid)"
  if [ -n "$lock_pid" ]; then
    echo "gta-claw writer lock remains held by PID $lock_pid" >&2
    exit 1
  fi
}

verify_runtime_stopped() {
  verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"
  verify_writer_lock_released
}

stop_initializer_for_replacement() {
  initializer_load_state="$(systemctl show -P LoadState gta-claw-state-init.service)"
  case "$initializer_load_state" in
    loaded | masked)
      systemctl stop gta-claw-state-init.service
      verify_unit_stopped gta-claw-state-init.service "gta-claw initializer"
      ;;
    not-found) ;;
    *) {
      echo "unexpected gta-claw initializer load state: $initializer_load_state" >&2
      exit 1
    } ;;
  esac
}

stop_runtime_for_replacement() {
  load_state="$(systemctl show -P LoadState gta-claw-daemon.service)"
  case "$load_state" in
    masked)
      if [ ! -e "$replacement_fence" ] || [ ! -e "$failure_marker" ]; then
        echo "refusing externally masked gta-claw daemon" >&2
        exit 1
      fi
      verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"
      ;;
    not-found)
      if [ ! -e "$replacement_fence" ]; then
        rm -f "$was_active_marker"
      fi
      touch "$replacement_fence"
      systemctl mask --runtime gta-claw-daemon.service
      verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"
      ;;
    loaded)
      if [ ! -e "$replacement_fence" ]; then
        rm -f "$was_active_marker"
        active_state="$(systemctl show -P ActiveState gta-claw-daemon.service)"
        case "$active_state" in
          inactive | failed) ;;
          active | activating | reloading | deactivating)
            touch "$was_active_marker"
            ;;
          *) {
            echo "unexpected gta-claw daemon state before replacement: $active_state" >&2
            exit 1
          } ;;
        esac
      fi
      touch "$replacement_fence"
      systemctl mask --runtime gta-claw-daemon.service
      systemctl stop gta-claw-daemon.service
      verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"
      ;;
    *) {
      echo "unexpected gta-claw daemon load state: $load_state" >&2
      exit 1
    } ;;
  esac
  stop_initializer_for_replacement
  verify_writer_lock_released
}

fail_install_runtime() {
  ensure_failure_fence
  touch "$replacement_fence"
  if [ -d /run/systemd/system ]; then
    if ! systemctl mask --runtime gta-claw-daemon.service >/dev/null 2>&1; then
      echo "gta-claw daemon could not be runtime-masked after install failure" >&2
    fi
    if ! systemctl stop gta-claw-daemon.service >/dev/null 2>&1; then
      echo "gta-claw daemon stop failed after install failure" >&2
    fi
    if ! systemctl stop gta-claw-state-init.service >/dev/null 2>&1; then
      echo "gta-claw initializer stop failed after install failure" >&2
    fi
    verify_runtime_stopped
  else
    verify_writer_lock_released
  fi
  exit 1
}

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

ensure_failure_fence
was_active=0
if [ -d /run/systemd/system ]; then
  stop_runtime_for_replacement
else
  touch "$replacement_fence"
  verify_writer_lock_released
fi
if [ -e "$was_active_marker" ]; then
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
  gta-claw-daemon.socket.deferred \
  package-toolchain.json \
  runtime-manifest.json; do
  install -D -m 0644 "$source_root/share/doc/gta-claw/$document" \
    "/usr/share/doc/gta-claw/$document"
done

/usr/libexec/gta-claw/gta-claw-state-init

if [ -d /run/systemd/system ]; then
  if ! systemctl unmask --runtime gta-claw-daemon.service; then
    fail_install_runtime
  fi
  if ! systemctl daemon-reload; then
    fail_install_runtime
  fi
  if ! systemctl reset-failed gta-claw-daemon.service >/dev/null 2>&1; then
    fail_install_runtime
  fi
  if [ "$fresh_install" -eq 1 ]; then
    if ! systemctl preset gta-claw-daemon.service; then
      fail_install_runtime
    fi
  fi
  if [ "$was_active" -eq 1 ]; then
    if ! systemctl restart gta-claw-daemon.service; then
      fail_install_runtime
    fi
    if ! /usr/libexec/gta-claw/gta-claw-runtime-ready; then
      fail_install_runtime
    fi
    rm -f \
      /run/gta-claw-daemon.ready-for-replacement \
      "$was_active_marker"
  fi
fi
rm -f "$replacement_fence"
