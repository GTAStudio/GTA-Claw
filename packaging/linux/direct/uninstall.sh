#!/bin/sh
# shellcheck disable=SC2317

set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

runtime_directory=/run/gta-claw-state-init
failure_marker=$runtime_directory/initialization-failed
complete_marker=$runtime_directory/initialization-complete
replacement_fence=$runtime_directory/replacement-fenced
authorization_marker=$runtime_directory/start-authorized
ready_marker=/run/gta-claw-daemon.ready-for-replacement
was_active_marker=/run/gta-claw-daemon.was-active
persistent_runtime_directory=/var/lib/gta-claw-install
persistent_failure_marker=$persistent_runtime_directory/transaction-failed
persistent_was_active_marker=$persistent_runtime_directory/was-active
lifecycle_lock=/run/gta-claw-lifecycle.lock
namespace=/var/lib/gta-claw-protected
lock=$namespace/state.writer.lock
persistent_enable_link=/etc/systemd/system/multi-user.target.wants/gta-claw-daemon.service
runtime_enable_link=/run/systemd/system/multi-user.target.wants/gta-claw-daemon.service
persistent_mask_link=/etc/systemd/system/gta-claw-daemon.service
runtime_mask_link=/run/systemd/system/gta-claw-daemon.service
mutation_started=0
payload_mutated=0
lock_held=0

if [ "$(/usr/bin/id -ru)" != 0 ] || [ "$(/usr/bin/id -u)" != 0 ]; then
  echo "gta-claw direct removal requires real and effective UID 0" >&2
  exit 1
fi
if [ -e "$authorization_marker" ] || [ -L "$authorization_marker" ]; then
  echo "gta-claw direct removal refuses an outstanding start authorization" >&2
  exit 1
fi
if [ ! -x /usr/bin/flock ] || [ ! -x /usr/bin/sync ]; then
  echo "gta-claw direct removal requires flock and sync" >&2
  exit 1
fi

marker_state() {
  path="$1"
  if [ -L "$path" ]; then
    echo "gta-claw removal marker must not be a symlink: $path" >&2
    return 1
  fi
  if [ -e "$path" ]; then
    if [ ! -f "$path" ]; then
      echo "gta-claw removal marker is not a physical file: $path" >&2
      return 1
    fi
    printf '1\n'
  else
    printf '0\n'
  fi
}

capture_link() {
  path="$1"
  if [ -L "$path" ]; then
    readlink -- "$path"
  elif [ -e "$path" ]; then
    echo "gta-claw service state path is not a symlink: $path" >&2
    return 1
  else
    printf '\n'
  fi
}

restore_marker() {
  path="$1"
  existed="$2"
  mode="$3"
  if [ "$existed" -eq 1 ]; then
    touch "$path" &&
      chown 0:0 "$path" &&
      chmod "$mode" "$path"
  else
    rm -f -- "$path"
  fi
}

restore_link() {
  path="$1"
  target="$2"
  rm -f -- "$path" || return 1
  if [ -n "$target" ]; then
    mkdir -p -- "${path%/*}" || return 1
    ln -s -- "$target" "$path"
  fi
}

ensure_runtime_directory() {
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
}

acquire_lifecycle_lock() {
  if [ -L /run ] || [ ! -d /run ] ||
    [ "$(stat -c '%u:%g:%a' /run)" != "0:0:755" ]; then
    echo "gta-claw lifecycle lock parent must be a physical root:root mode 0755 directory" >&2
    return 1
  fi
  if [ -L "$lifecycle_lock" ] ||
    { [ -e "$lifecycle_lock" ] && [ ! -f "$lifecycle_lock" ]; }; then
    echo "gta-claw lifecycle lock is not a physical regular file" >&2
    return 1
  fi
  if [ ! -e "$lifecycle_lock" ]; then
    (umask 0177; : >"$lifecycle_lock") || return 1
    chown 0:0 "$lifecycle_lock" || return 1
    chmod 0600 "$lifecycle_lock" || return 1
  fi
  [ "$(stat -c '%u:%g:%a:%h' "$lifecycle_lock")" = "0:0:600:1" ] ||
    {
      echo "gta-claw lifecycle lock metadata is invalid" >&2
      return 1
    }
  lifecycle_identity="$(stat -Lc '%d:%i' "$lifecycle_lock")"
  exec 8<>"$lifecycle_lock" || return 1
  if [ "$(stat -Lc '%d:%i' /proc/self/fd/8)" != "$lifecycle_identity" ] ||
    [ "$(stat -Lc '%d:%i' "$lifecycle_lock")" != "$lifecycle_identity" ] ||
    [ "$(stat -Lc '%u:%g:%a:%h' /proc/self/fd/8)" != "0:0:600:1" ]; then
    echo "gta-claw lifecycle lock identity changed while opening it" >&2
    exec 8>&-
    return 1
  fi
  if ! flock -n 8; then
    echo "another gta-claw lifecycle transaction is already running" >&2
    exec 8>&-
    return 1
  fi
}

ensure_failure_fences() {
  ensure_runtime_directory || return 1
  if [ -L "$persistent_runtime_directory" ] ||
    { [ -e "$persistent_runtime_directory" ] &&
      [ ! -d "$persistent_runtime_directory" ]; }; then
    echo "gta-claw persistent install runtime path is not a physical directory" >&2
    return 1
  fi
  if [ ! -e "$persistent_runtime_directory" ]; then
    mkdir -m 0700 -- "$persistent_runtime_directory" || return 1
  fi
  if [ "$(stat -c '%u:%g:%a' "$persistent_runtime_directory")" != "0:0:700" ]; then
    echo "gta-claw persistent install runtime directory must be root:root mode 0700" >&2
    return 1
  fi
  touch "$failure_marker" "$replacement_fence" "$persistent_failure_marker" ||
    return 1
  chown 0:0 "$failure_marker" "$replacement_fence" "$persistent_failure_marker" ||
    return 1
  chmod 0644 "$failure_marker" "$replacement_fence" || return 1
  chmod 0600 "$persistent_failure_marker" || return 1
  if [ -e "$persistent_was_active_marker" ]; then
    chown 0:0 "$persistent_was_active_marker" || return 1
    chmod 0600 "$persistent_was_active_marker" || return 1
  fi
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

acquire_writer_lock() {
  if [ -L "$lock" ]; then
    echo "gta-claw writer lock must not be a symlink" >&2
    return 1
  fi
  if [ ! -e "$lock" ]; then
    if [ -e "$namespace" ] || [ -L "$namespace" ]; then
      echo "gta-claw protected namespace exists without its writer lock" >&2
      return 1
    fi
    return
  fi
  if [ ! -f "$lock" ] || [ "$(stat -c '%h' "$lock")" != "1" ]; then
    echo "gta-claw writer lock is not an unaliased regular file" >&2
    return 1
  fi
  lock_identity="$(stat -Lc '%d:%i' "$lock")"
  exec 9<>"$lock" || return 1
  if [ "$(stat -Lc '%d:%i' /proc/self/fd/9)" != "$lock_identity" ] ||
    [ "$(stat -Lc '%d:%i' "$lock")" != "$lock_identity" ]; then
    echo "gta-claw writer-lock identity changed while opening it" >&2
    exec 9>&-
    return 1
  fi
  if ! flock -n 9; then
    echo "gta-claw writer lock is held by a process outside the stopped units" >&2
    exec 9>&-
    return 1
  fi
  lock_held=1
}

verify_held_writer_lock() {
  if [ "$lock_held" -eq 0 ]; then
    [ ! -e "$namespace" ] && [ ! -L "$namespace" ]
    return
  fi
  [ "$(stat -Lc '%d:%i' /proc/self/fd/9)" = "$lock_identity" ] &&
    [ "$(stat -Lc '%d:%i' "$lock")" = "$lock_identity" ] &&
    flock -n 9
}

fence_failed_rollback() {
  requested_status="${1:-1}"
  failure=0
  if ! ensure_failure_fences; then
    echo "gta-claw removal rollback could not retain all failure fences" >&2
    failure=1
  elif ! /usr/bin/sync -f "$persistent_failure_marker"; then
    echo "gta-claw removal rollback could not persist its failure fence" >&2
    failure=1
  fi
  if [ -d /run/systemd/system ]; then
    if ! systemctl mask --runtime gta-claw-daemon.service >/dev/null 2>&1; then
      echo "gta-claw daemon could not be runtime-masked after rollback failure" >&2
      failure=1
    fi
    if ! systemctl stop gta-claw-daemon.service >/dev/null 2>&1; then
      echo "gta-claw daemon stop failed after rollback failure" >&2
      failure=1
    fi
    if ! verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"; then
      if ! systemctl kill \
        --kill-whom=all \
        --signal=KILL \
        gta-claw-daemon.service >/dev/null 2>&1; then
        echo "gta-claw daemon processes could not be killed after rollback failure" >&2
        failure=1
      fi
    fi
    if ! verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"; then
      failure=1
    fi
    if ! systemctl stop gta-claw-state-init.service >/dev/null 2>&1; then
      echo "gta-claw initializer stop failed after rollback failure" >&2
      failure=1
    fi
    if ! verify_unit_stopped gta-claw-state-init.service "gta-claw initializer"; then
      failure=1
    fi
  fi
  [ "$failure" -eq 0 ] ||
    echo "gta-claw removal rollback cancellation completed with errors" >&2
  [ "$requested_status" -ne 0 ] || requested_status=1
  exit "$requested_status"
}

rollback_removal() {
  status="${1:-$?}"
  trap - 0 HUP INT TERM
  [ "$mutation_started" -eq 1 ] || exit "$status"
  if [ "$payload_mutated" -eq 1 ]; then
    echo "gta-claw removal crossed the payload boundary and will remain fenced" >&2
    fence_failed_rollback "$status"
  fi

  restore_failed=0
  if [ "$lock_held" -eq 1 ]; then
    exec 9>&-
    lock_held=0
  fi
  if [ -d /run/systemd/system ]; then
    daemon_needs_start=0
    if ! current_daemon_state="$(
      systemctl show -P ActiveState gta-claw-daemon.service 2>/dev/null
    )"; then
      restore_failed=1
    elif [ "$old_daemon_active" -eq 1 ]; then
      case "$current_daemon_state" in
        active | reloading) ;;
        activating | deactivating) daemon_needs_start=1 ;;
        inactive | failed) daemon_needs_start=1 ;;
        *) restore_failed=1 ;;
      esac
    elif ! systemctl stop gta-claw-daemon.service >/dev/null 2>&1 ||
      ! verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"; then
      restore_failed=1
    fi
    initializer_needs_start=0
    if ! current_initializer_state="$(
      systemctl show -P ActiveState gta-claw-state-init.service 2>/dev/null
    )"; then
      restore_failed=1
    elif [ "$old_initializer_active" -eq 1 ]; then
      case "$current_initializer_state" in
        active | reloading) ;;
        activating | deactivating) initializer_needs_start=1 ;;
        inactive | failed) initializer_needs_start=1 ;;
        *) restore_failed=1 ;;
      esac
    elif ! systemctl stop gta-claw-state-init.service >/dev/null 2>&1 ||
      ! verify_unit_stopped gta-claw-state-init.service "gta-claw initializer"; then
      restore_failed=1
    fi
  fi
  if ! restore_link "$persistent_enable_link" "$old_persistent_enable"; then
    restore_failed=1
  fi
  if ! restore_link "$runtime_enable_link" "$old_runtime_enable"; then
    restore_failed=1
  fi
  if ! restore_link "$persistent_mask_link" "$old_persistent_mask"; then
    restore_failed=1
  fi
  if ! restore_link "$runtime_mask_link" "$old_runtime_mask"; then
    restore_failed=1
  fi
  if ! restore_marker "$failure_marker" "$had_failure_marker" 0644; then
    restore_failed=1
  fi
  if ! restore_marker "$complete_marker" "$had_complete_marker" 0644; then
    restore_failed=1
  fi
  if ! restore_marker "$replacement_fence" "$had_replacement_fence" 0644; then
    restore_failed=1
  fi
  if ! restore_marker "$ready_marker" "$had_ready_marker" 0644; then
    restore_failed=1
  fi
  if ! restore_marker "$was_active_marker" "$had_was_active_marker" 0644; then
    restore_failed=1
  fi
  if ! restore_marker \
    "$persistent_failure_marker" \
    "$had_persistent_failure_marker" \
    0600; then
    restore_failed=1
  fi
  if ! restore_marker \
    "$persistent_was_active_marker" \
    "$had_persistent_was_active_marker" \
    0600; then
    restore_failed=1
  fi
  if [ "$had_persistent_runtime_directory" -eq 0 ]; then
    rmdir "$persistent_runtime_directory" >/dev/null 2>&1 || restore_failed=1
  fi
  if [ "$had_runtime_directory" -eq 0 ]; then
    rmdir "$runtime_directory" >/dev/null 2>&1 || restore_failed=1
  fi
  if [ -d /run/systemd/system ]; then
    if ! systemctl daemon-reload >/dev/null 2>&1; then
      restore_failed=1
    fi
    if ! /usr/bin/sync -f /etc/systemd/system; then
      restore_failed=1
    fi
  fi
  if ! /usr/bin/sync -f /var/lib; then
    restore_failed=1
  fi
  if [ -d /run/systemd/system ]; then
    if [ "$restore_failed" -eq 0 ] && [ "$initializer_needs_start" -eq 1 ]; then
      if ! systemctl start gta-claw-state-init.service >/dev/null 2>&1; then
        restore_failed=1
      fi
    fi
    if [ "$restore_failed" -eq 0 ] && [ "$old_initializer_active" -eq 1 ] &&
      ! systemctl is-active --quiet gta-claw-state-init.service; then
      restore_failed=1
    fi
    if [ "$restore_failed" -eq 0 ] && [ "$daemon_needs_start" -eq 1 ]; then
      if ! systemctl start gta-claw-daemon.service >/dev/null 2>&1; then
        restore_failed=1
      fi
    fi
    if [ "$restore_failed" -eq 0 ] && [ "$old_daemon_active" -eq 1 ]; then
      if ! systemctl is-active --quiet gta-claw-daemon.service ||
        ! /usr/libexec/gta-claw/gta-claw-runtime-ready >/dev/null 2>&1; then
        restore_failed=1
      fi
    fi
  fi
  [ "$restore_failed" -eq 0 ] || fence_failed_rollback "$status"
  exit "$status"
}

acquire_lifecycle_lock || exit 1

had_runtime_directory=0
if [ -e "$runtime_directory" ]; then
  had_runtime_directory=1
fi
had_persistent_runtime_directory=0
if [ -e "$persistent_runtime_directory" ]; then
  had_persistent_runtime_directory=1
fi
had_failure_marker="$(marker_state "$failure_marker")"
had_complete_marker="$(marker_state "$complete_marker")"
had_replacement_fence="$(marker_state "$replacement_fence")"
had_ready_marker="$(marker_state "$ready_marker")"
had_was_active_marker="$(marker_state "$was_active_marker")"
had_persistent_failure_marker="$(marker_state "$persistent_failure_marker")"
had_persistent_was_active_marker="$(marker_state "$persistent_was_active_marker")"
old_persistent_enable="$(capture_link "$persistent_enable_link")"
old_runtime_enable="$(capture_link "$runtime_enable_link")"
old_persistent_mask="$(capture_link "$persistent_mask_link")"
old_runtime_mask="$(capture_link "$runtime_mask_link")"
old_daemon_active=0
old_initializer_active=0

if [ -d /run/systemd/system ]; then
  daemon_active_state="$(systemctl show -P ActiveState gta-claw-daemon.service)"
  case "$daemon_active_state" in
    active | activating | reloading | deactivating) old_daemon_active=1 ;;
    inactive | failed) ;;
    *) {
      echo "unexpected gta-claw daemon state before direct removal: $daemon_active_state" >&2
      exit 1
    } ;;
  esac
  initializer_active_state="$(systemctl show -P ActiveState gta-claw-state-init.service)"
  case "$initializer_active_state" in
    active | activating | reloading | deactivating) old_initializer_active=1 ;;
    inactive | failed) ;;
    *) {
      echo "unexpected gta-claw initializer state before direct removal: $initializer_active_state" >&2
      exit 1
    } ;;
  esac
  if [ "$(systemctl show -P RefuseManualStop gta-claw-daemon.service)" = "yes" ]; then
    echo "gta-claw-daemon.service refuses manual stop; refusing removal" >&2
    exit 1
  fi
fi

trap 'rollback_removal "$?"' 0
trap 'rollback_removal 129' HUP
trap 'rollback_removal 130' INT
trap 'rollback_removal 143' TERM
mutation_started=1
ensure_failure_fences
/usr/bin/sync -f "$persistent_failure_marker"

if [ -d /run/systemd/system ]; then
  systemctl mask --runtime gta-claw-daemon.service
  systemctl stop gta-claw-daemon.service
  verify_unit_stopped gta-claw-daemon.service "gta-claw daemon"
fi

acquire_writer_lock
verify_held_writer_lock ||
  {
    echo "gta-claw writer-lock ownership could not be held for removal" >&2
    exit 1
  }

if [ -d /run/systemd/system ]; then
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
fi

verify_held_writer_lock ||
  {
    echo "gta-claw writer-lock ownership could not be held for removal" >&2
    exit 1
  }

rm -f -- \
  "$persistent_enable_link" \
  "$runtime_enable_link" \
  "$persistent_mask_link"
verify_held_writer_lock ||
  {
    echo "gta-claw writer-lock identity changed before payload removal" >&2
    exit 1
  }
payload_mutated=1
rm -f -- \
  /usr/bin/gta-claw-cli \
  /usr/libexec/gta-claw/gta-claw-daemon \
  /usr/libexec/gta-claw/gta-claw-direct-config \
  /usr/libexec/gta-claw/gta-claw-runtime-ready \
  /usr/libexec/gta-claw/gta-claw-start-authorized \
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
verify_held_writer_lock ||
  {
    echo "gta-claw writer-lock identity changed during payload removal" >&2
    exit 1
  }

if [ -d /run/systemd/system ]; then
  /usr/bin/sync -f /etc/systemd/system
fi
/usr/bin/sync -f /usr
/usr/bin/sync -f "$persistent_failure_marker"

if [ -d /run/systemd/system ]; then
  rm -f -- "$runtime_mask_link"
  systemctl daemon-reload
fi
rm -f -- \
  "$failure_marker" \
  "$complete_marker" \
  "$replacement_fence" \
  "$ready_marker" \
  "$was_active_marker" \
  "$persistent_failure_marker" \
  "$persistent_was_active_marker"
/usr/bin/sync -f /var/lib
rmdir "$persistent_runtime_directory" >/dev/null 2>&1 || true
rmdir "$runtime_directory" >/dev/null 2>&1 || true

if [ "$lock_held" -eq 1 ]; then
  exec 9>&-
  lock_held=0
fi
mutation_started=0
trap - 0 HUP INT TERM

echo "preserved /var/lib/gta-claw-protected and the gta-claw service identity"
