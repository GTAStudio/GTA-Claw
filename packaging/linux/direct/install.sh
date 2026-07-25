#!/bin/sh

set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

source_root="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
package_version="$(cat "$source_root/package-version")"
installed_version_file=/usr/share/doc/gta-claw/package-version
runtime_directory=/run/gta-claw-state-init
failure_marker=$runtime_directory/initialization-failed
complete_marker=$runtime_directory/initialization-complete
replacement_fence=$runtime_directory/replacement-fenced
authorization_marker=$runtime_directory/start-authorized
authorization_helper=/usr/libexec/gta-claw/gta-claw-start-authorized
lock=/var/lib/gta-claw-protected/state.writer.lock
was_active_marker=/run/gta-claw-daemon.was-active
persistent_runtime_directory=/var/lib/gta-claw-install
persistent_failure_marker=$persistent_runtime_directory/transaction-failed
persistent_was_active_marker=$persistent_runtime_directory/was-active
fresh_install=1
resuming_persistent_transaction=0
install_complete=0

if [ "$(/usr/bin/id -ru)" != 0 ] || [ "$(/usr/bin/id -u)" != 0 ]; then
  echo "gta-claw direct installation requires real and effective UID 0" >&2
  exit 1
fi
if [ ! -x /usr/bin/python3 ]; then
  echo "gta-claw direct installation requires /usr/bin/python3 for openat2 validation" >&2
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
validate_regular_or_absent "$persistent_failure_marker"
validate_regular_or_absent "$persistent_was_active_marker"
if [ -e "$persistent_failure_marker" ]; then
  resuming_persistent_transaction=1
fi
/usr/bin/python3 \
  "$source_root/libexec/gta-claw-direct-config" \
  install \
  / \
  "$source_root/etc/gta-claw/gta-claw.env" \
  "$source_root/etc/gta-claw/credentials/daemon.conf"

ensure_persistent_failure_fence() {
  if [ -L "$persistent_runtime_directory" ] ||
    { [ -e "$persistent_runtime_directory" ] &&
      [ ! -d "$persistent_runtime_directory" ]; }; then
    echo "gta-claw persistent install runtime path is not a physical directory" >&2
    return 1
  fi
  if [ ! -e "$persistent_runtime_directory" ]; then
    mkdir -m 0700 -- "$persistent_runtime_directory" || return 1
  fi
  [ "$(stat -c '%u:%g:%a' "$persistent_runtime_directory")" = "0:0:700" ] ||
    {
      echo "gta-claw persistent install runtime directory must be root:root mode 0700" >&2
      return 1
    }
  touch "$persistent_failure_marker" || return 1
  chown 0:0 "$persistent_failure_marker" || return 1
  chmod 0600 "$persistent_failure_marker" || return 1
  if [ -e "$persistent_was_active_marker" ]; then
    chown 0:0 "$persistent_was_active_marker" || return 1
    chmod 0600 "$persistent_was_active_marker" || return 1
  fi
}

ensure_failure_fence() {
  if [ -L "$runtime_directory" ] ||
    { [ -e "$runtime_directory" ] && [ ! -d "$runtime_directory" ]; }; then
    echo "gta-claw initialization runtime path is not a physical directory" >&2
    return 1
  fi
  if [ ! -e "$runtime_directory" ]; then
    mkdir -m 0755 -- "$runtime_directory" || return 1
  fi
  if [ "$(stat -c '%u:%g:%a' "$runtime_directory")" != "0:0:755" ]; then
    echo "gta-claw initialization runtime directory must be root:root mode 0755" >&2
    return 1
  fi
  if [ -L "$failure_marker" ] ||
    { [ -e "$failure_marker" ] && [ ! -f "$failure_marker" ]; }; then
    echo "gta-claw initialization failure marker is not a physical file" >&2
    return 1
  fi
  touch "$failure_marker" || return 1
  chown 0:0 "$failure_marker" || return 1
  chmod 0644 "$failure_marker" || return 1
}

retain_replacement_fence() {
  [ -d "$runtime_directory" ] && [ ! -L "$runtime_directory" ] || return 1
  if [ -L "$replacement_fence" ] ||
    { [ -e "$replacement_fence" ] && [ ! -f "$replacement_fence" ]; }; then
    return 1
  fi
  touch "$replacement_fence" || return 1
  chown 0:0 "$replacement_fence" || return 1
  chmod 0644 "$replacement_fence" || return 1
}

lock_holder_pid() {
  if ! locks="$(lslocks --noheadings --notruncate --output PID,PATH)"; then
    echo "gta-claw writer-lock ownership could not be inspected" >&2
    return 1
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
      return 1
    } ;;
  esac
}

verify_writer_lock_released() {
  if ! lock_pid="$(lock_holder_pid)"; then
    return 1
  fi
  if [ -n "$lock_pid" ]; then
    echo "gta-claw writer lock remains held by PID $lock_pid" >&2
    return 1
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
      if [ -e "$was_active_marker" ]; then
        touch "$persistent_was_active_marker"
        chown 0:0 "$persistent_was_active_marker"
        chmod 0600 "$persistent_was_active_marker"
      fi
      systemctl stop gta-claw-daemon.service
      verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"
      ;;
    not-found)
      if [ ! -e "$replacement_fence" ]; then
        rm -f "$was_active_marker"
        if [ "$resuming_persistent_transaction" -eq 0 ]; then
          rm -f "$persistent_was_active_marker"
        fi
      elif [ -e "$was_active_marker" ]; then
        touch "$persistent_was_active_marker"
        chown 0:0 "$persistent_was_active_marker"
        chmod 0600 "$persistent_was_active_marker"
      fi
      retain_replacement_fence
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
            touch "$persistent_was_active_marker"
            chown 0:0 "$persistent_was_active_marker"
            chmod 0600 "$persistent_was_active_marker"
            ;;
          *) {
            echo "unexpected gta-claw daemon state before replacement: $active_state" >&2
            exit 1
          } ;;
        esac
      fi
      retain_replacement_fence
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

interrupt_install_after() {
  if [ "${GTA_CLAW_DIRECT_TEST_INTERRUPT_AFTER:-}" = "$1" ]; then
    echo "injected hard interruption after direct install $1 boundary" >&2
    kill -KILL "$$"
    exit 137
  fi
}

fail_install_runtime() {
  trap - 0 HUP INT TERM
  failure=0
  if ! rm -f "$authorization_marker"; then
    echo "gta-claw start authorization could not be cancelled" >&2
    failure=1
  fi
  if ! ensure_persistent_failure_fence; then
    echo "gta-claw persistent install failure marker could not be retained" >&2
    failure=1
  fi
  if ! ensure_failure_fence; then
    echo "gta-claw initialization failure marker could not be retained" >&2
    failure=1
  fi
  if ! retain_replacement_fence; then
    echo "gta-claw replacement fence could not be retained" >&2
    failure=1
  fi
  if [ -d /run/systemd/system ]; then
    if ! systemctl mask --runtime gta-claw-daemon.service >/dev/null 2>&1; then
      echo "gta-claw daemon could not be runtime-masked after install failure" >&2
      failure=1
    fi
    if ! systemctl stop gta-claw-daemon.service >/dev/null 2>&1; then
      echo "gta-claw daemon stop failed after install failure" >&2
      failure=1
    fi
    if ! verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"; then
      if ! systemctl kill \
        --kill-whom=all \
        --signal=KILL \
        gta-claw-daemon.service >/dev/null 2>&1; then
        echo "gta-claw daemon processes could not be killed after install failure" >&2
        failure=1
      fi
    fi
    if ! systemctl stop gta-claw-state-init.service >/dev/null 2>&1; then
      echo "gta-claw initializer stop failed after install failure" >&2
      failure=1
    fi
    if ! verify_runtime_stopped; then
      echo "gta-claw runtime cancellation could not be verified" >&2
      failure=1
    fi
  else
    if ! verify_writer_lock_released; then
      failure=1
    fi
  fi
  [ "$failure" -eq 0 ] ||
    echo "gta-claw install failure cancellation completed with errors" >&2
  exit 1
}

cancel_incomplete_install() {
  status=$?
  trap - 0 HUP INT TERM
  if [ "$install_complete" -eq 0 ]; then
    fail_install_runtime
  fi
  exit "$status"
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

ensure_persistent_failure_fence || fail_install_runtime
if [ "$resuming_persistent_transaction" -eq 0 ]; then
  rm -f "$persistent_was_active_marker"
fi
ensure_failure_fence || fail_install_runtime
rm -f "$authorization_marker" || fail_install_runtime
trap cancel_incomplete_install 0 HUP INT TERM
was_active=0
if [ -d /run/systemd/system ]; then
  stop_runtime_for_replacement
else
  retain_replacement_fence
  verify_writer_lock_released
fi
if [ -e "$was_active_marker" ] || [ -e "$persistent_was_active_marker" ]; then
  was_active=1
fi

install -D -m 0644 "$source_root/lib/sysusers.d/gta-claw.conf" \
  /usr/lib/sysusers.d/gta-claw.conf
/usr/bin/systemd-sysusers /usr/lib/sysusers.d/gta-claw.conf
install -D -m 0755 "$source_root/libexec/gta-claw-state-init" \
  /usr/libexec/gta-claw/gta-claw-state-init
install -D -m 0755 "$source_root/libexec/gta-claw-runtime-ready" \
  /usr/libexec/gta-claw/gta-claw-runtime-ready
install -D -m 0755 "$source_root/libexec/gta-claw-start-authorized" \
  "$authorization_helper"
install -D -m 0644 "$source_root/lib/systemd/system/gta-claw-daemon.service" \
  /usr/lib/systemd/system/gta-claw-daemon.service
install -D -m 0644 "$source_root/lib/systemd/system/gta-claw-state-init.service" \
  /usr/lib/systemd/system/gta-claw-state-init.service
install -D -m 0644 "$source_root/lib/systemd/system-preset/80-gta-claw.preset" \
  /usr/lib/systemd/system-preset/80-gta-claw.preset
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || fail_install_runtime
fi
if [ "${GTA_CLAW_DIRECT_TEST_FAIL_AFTER:-}" = "unit" ]; then
  if [ "${GTA_CLAW_DIRECT_TEST_BREAK_FAILURE_FENCE:-0}" = "1" ]; then
    rm -f "$failure_marker"
    ln -s /bin/true "$failure_marker"
  fi
  echo "injected direct install failure after durable unit contract" >&2
  fail_install_runtime
fi
interrupt_install_after unit
install -D -m 0755 "$source_root/bin/gta-claw-cli" /usr/bin/gta-claw-cli
install -D -m 0755 "$source_root/bin/gta-claw-daemon" \
  /usr/libexec/gta-claw/gta-claw-daemon
if [ "${GTA_CLAW_DIRECT_TEST_FAIL_AFTER:-}" = "daemon" ]; then
  if [ "${GTA_CLAW_DIRECT_TEST_BREAK_FAILURE_FENCE:-0}" = "1" ]; then
    rm -f "$failure_marker"
    ln -s /bin/true "$failure_marker"
  fi
  echo "injected direct install failure after daemon replacement" >&2
  fail_install_runtime
fi
interrupt_install_after daemon

GTA_CLAW_DEFER_FENCE_CLEAR=1 \
  /usr/libexec/gta-claw/gta-claw-state-init
/usr/bin/python3 \
  "$source_root/libexec/gta-claw-direct-config" \
  verify \
  / \
  "$source_root/etc/gta-claw/gta-claw.env" \
  "$source_root/etc/gta-claw/credentials/daemon.conf"
install -D -m 0644 "$source_root/package-version" "$installed_version_file"

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

if [ -d /run/systemd/system ]; then
  if ! systemctl unmask --runtime gta-claw-daemon.service; then
    fail_install_runtime
  fi
  if ! systemctl daemon-reload; then
    fail_install_runtime
  fi
  if [ "$(systemctl show -P LoadState gta-claw-daemon.service)" != "not-found" ]; then
    if ! systemctl reset-failed gta-claw-daemon.service >/dev/null 2>&1 &&
      [ "$(systemctl show -P ActiveState gta-claw-daemon.service)" != "inactive" ]; then
      fail_install_runtime
    fi
  fi
  if [ "$fresh_install" -eq 1 ]; then
    if ! systemctl preset gta-claw-daemon.service; then
      fail_install_runtime
    fi
  fi
  if [ "$was_active" -eq 1 ]; then
    if ! "$authorization_helper" arm "$$"; then
      fail_install_runtime
    fi
    interrupt_install_after authorization
    if ! systemctl restart gta-claw-daemon.service; then
      fail_install_runtime
    fi
    if ! /usr/libexec/gta-claw/gta-claw-runtime-ready; then
      fail_install_runtime
    fi
    if ! "$authorization_helper" clear; then
      fail_install_runtime
    fi
    rm -f \
      /run/gta-claw-daemon.ready-for-replacement \
      "$was_active_marker"
  fi
fi
rm -f "$authorization_marker"
rm -f "$failure_marker" "$complete_marker" "$replacement_fence"
rm -f "$persistent_failure_marker" "$persistent_was_active_marker"
rmdir "$persistent_runtime_directory" >/dev/null 2>&1 || true
install_complete=1
trap - 0 HUP INT TERM
