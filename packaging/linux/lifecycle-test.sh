#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in dpkg flock jq ps python3 rpm sha256sum systemctl tar; do
  require_tool "$tool"
done
[[ "$#" -eq 6 ]] ||
  die "usage: lifecycle-test.sh TAR_RELEASE_1 TAR_RELEASE_2 DEB_RELEASE_1 DEB_RELEASE_2 RPM_RELEASE_1 RPM_RELEASE_2"
tar1="$1"
tar2="$2"
deb1="$3"
deb2="$4"
rpm1="$5"
rpm2="$6"
for package in "$tar1" "$tar2" "$deb1" "$deb2" "$rpm1" "$rpm2"; do
  assert_regular_unaliased "$package" "lifecycle package"
done
[[ "$(ps -p 1 -o comm= | tr -d ' ')" == "systemd" ]] ||
  die "lifecycle test requires systemd as PID 1"

namespace=/var/lib/gta-claw-protected
expected_names="$(
  printf '%s\n' \
    snapshot-0.meta \
    snapshot-0.sqlite \
    snapshot-1.meta \
    snapshot-1.sqlite \
    snapshot.selector \
    state.sqlite \
    state.sqlite-wal \
    state.writer.lock
)"
direct_root="$(mktemp -d)"
policy_installed=0
lock_gate_dir=
lock_holder_job=
lifecycle_gate_dir=
lifecycle_lock_job=
zombie_parent_job=
transition_gate_dir=
transition_gate_script=
transition_stop_job=
transition_rpm_job=

install_policy_denial() {
  [[ ! -e /usr/sbin/policy-rc.d && ! -L /usr/sbin/policy-rc.d ]] ||
    die "lifecycle test will not replace an existing policy-rc.d"
  printf '#!/bin/sh\nexit 101\n' |
    sudo tee /usr/sbin/policy-rc.d >/dev/null
  sudo chmod 0755 /usr/sbin/policy-rc.d
  policy_installed=1
}

begin_daemon_deactivation() {
  transition_gate_dir="$(sudo mktemp -d /run/gta-claw/transition.XXXXXXXX)"
  sudo chown gta-claw:gta-claw "$transition_gate_dir"
  sudo chmod 0700 "$transition_gate_dir"
  sudo tee "$transition_gate_dir/hold-stop" >/dev/null <<EOF
#!/bin/sh
set -eu
touch '$transition_gate_dir/entered'
while [ ! -e '$transition_gate_dir/release' ]; do
  [ ! -e '$transition_gate_dir/probe' ] ||
    touch '$transition_gate_dir/held'
  sleep 0.05
done
EOF
  sudo chmod 0755 "$transition_gate_dir/hold-stop"
  sudo mkdir -p /etc/systemd/system/gta-claw-daemon.service.d
  sudo tee /etc/systemd/system/gta-claw-daemon.service.d/transition.conf >/dev/null <<EOF
[Service]
ExecStop=$transition_gate_dir/hold-stop
TimeoutStopSec=30s
EOF
  sudo systemctl daemon-reload
  sudo systemctl stop gta-claw-daemon.service &
  transition_stop_job=$!
  deadline=$((SECONDS + 10))
  while ! sudo test -e "$transition_gate_dir/entered" ||
    [[ "$(systemctl show -P ActiveState gta-claw-daemon.service)" != "deactivating" ]]; do
    ((SECONDS < deadline)) ||
      die "daemon did not enter the deactivating RPM fixture"
    sleep 0.05
  done
}

protected_state_snapshot() {
  assert_protected_contract
  state_snapshot
}

begin_daemon_activation() {
  local component="gta-claw-transition-$BASHPID"
  sudo systemctl stop gta-claw-daemon.service
  transition_gate_dir="/run/$component"
  transition_gate_script="/run/$component-gate"
  sudo tee "$transition_gate_script" >/dev/null <<EOF
#!/usr/bin/python3
import os
import signal
import time

for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(handled_signal, signal.SIG_IGN)
open('$transition_gate_dir/entered', 'x').close()
while not os.path.exists('$transition_gate_dir/release'):
    if os.path.exists('$transition_gate_dir/probe'):
        open('$transition_gate_dir/held', 'a').close()
    time.sleep(0.05)
EOF
  sudo chmod 0755 "$transition_gate_script"
  sudo mkdir -p /etc/systemd/system/gta-claw-daemon.service.d
  sudo tee /etc/systemd/system/gta-claw-daemon.service.d/transition.conf >/dev/null <<EOF
[Service]
RuntimeDirectory=gta-claw $component
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ExecStartPre=$transition_gate_script
TimeoutStopSec=30s
EOF
  sudo systemctl daemon-reload
  sudo systemctl start gta-claw-daemon.service &
  transition_stop_job=$!
  deadline=$((SECONDS + 10))
  while ! sudo test -e "$transition_gate_dir/entered" ||
    [[ "$(systemctl show -P ActiveState gta-claw-daemon.service)" != "activating" ]]; do
    ((SECONDS < deadline)) ||
      die "daemon did not enter the activating RPM fixture"
    sleep 0.05
  done
}

rpm_waits_for_daemon_stop() {
  sudo ps -eo pid=,ppid=,comm=,args= |
    awk -v root="$transition_rpm_job" '
      {
        rows += 1
        process_id[rows] = $1
        parent_id[rows] = $2
        command_name[rows] = $3
        $1 = $2 = $3 = ""
        sub(/^[[:space:]]+/, "")
        arguments[rows] = $0
      }
      END {
        descendant[root] = 1
        for (round = 1; round <= rows; round += 1) {
          for (row = 1; row <= rows; row += 1) {
            if (descendant[parent_id[row]]) {
              descendant[process_id[row]] = 1
            }
          }
        }
        for (row = 1; row <= rows; row += 1) {
          if (descendant[process_id[row]] &&
              command_name[row] == "systemctl" &&
              arguments[row] ~ /(^|[[:space:]])([^[:space:]]*\/)?systemctl[[:space:]]+stop[[:space:]]+gta-claw-daemon\.service([[:space:]]|$)/) {
            found = 1
          }
        }
        exit(found ? 0 : 1)
      }
    '
}

assert_rpm_transition_held() {
  local expected_state="$1"
  local label="$2"
  local receipt="$3"
  deadline=$((SECONDS + 10))
  while ! rpm_waits_for_daemon_stop; do
    kill -0 "$transition_rpm_job" >/dev/null 2>&1 ||
      die "RPM $label replacement exited before joining the held stop"
    [[ "$(systemctl show -P ActiveState gta-claw-daemon.service)" == "deactivating" ]] ||
      die "RPM $label fixture left deactivating before joining the held stop"
    [[ "$(stat -Lc '%d:%i:%s:%y:%z' /usr/libexec/gta-claw/gta-claw-daemon)" == \
      "$receipt" ]] ||
      die "RPM replaced the daemon before joining the $label held stop"
    [[ "$(protected_state_snapshot)" == "$expected_state" ]] ||
      die "RPM $label replacement changed protected state before joining the held stop"
    ((SECONDS < deadline)) ||
      die "RPM $label replacement did not join the held daemon stop"
    sleep 0.05
  done
  sudo touch "$transition_gate_dir/probe"
  deadline=$((SECONDS + 10))
  while ! sudo test -e "$transition_gate_dir/held"; do
    kill -0 "$transition_rpm_job" >/dev/null 2>&1 ||
      die "RPM $label replacement exited before the stop gate acknowledged its hold"
    [[ "$(systemctl show -P ActiveState gta-claw-daemon.service)" == "deactivating" ]] ||
      die "RPM $label fixture left deactivating before gate acknowledgment"
    [[ "$(stat -Lc '%d:%i:%s:%y:%z' /usr/libexec/gta-claw/gta-claw-daemon)" == \
      "$receipt" ]] ||
      die "RPM replaced the daemon while the $label stop gate was held"
    [[ "$(protected_state_snapshot)" == "$expected_state" ]] ||
      die "RPM $label replacement changed protected state while the stop gate was held"
    ((SECONDS < deadline)) ||
      die "RPM $label stop gate did not acknowledge its hold"
    sleep 0.05
  done
  kill -0 "$transition_rpm_job" >/dev/null 2>&1 ||
    die "RPM $label replacement exited while the stop gate remained held"
  [[ "$(systemctl show -P ActiveState gta-claw-daemon.service)" == "deactivating" ]] ||
    die "RPM $label fixture left deactivating while the stop gate remained held"
  [[ "$(stat -Lc '%d:%i:%s:%y:%z' /usr/libexec/gta-claw/gta-claw-daemon)" == \
    "$receipt" ]] ||
    die "RPM replaced the daemon before the $label stop gate was released"
  [[ "$(protected_state_snapshot)" == "$expected_state" ]] ||
    die "RPM $label replacement changed protected state before stop release"
}

finish_daemon_deactivation() {
  sudo rm -f /etc/systemd/system/gta-claw-daemon.service.d/transition.conf
  sudo systemctl daemon-reload
  sudo touch "$transition_gate_dir/release"
  wait "$transition_stop_job"
  transition_stop_job=
  wait "$transition_rpm_job"
  transition_rpm_job=
  sudo rm -rf "$transition_gate_dir"
  transition_gate_dir=
}

finish_daemon_activation() {
  sudo rm -f /etc/systemd/system/gta-claw-daemon.service.d/transition.conf
  sudo systemctl daemon-reload
  sudo touch "$transition_gate_dir/release"
  wait "$transition_stop_job" >/dev/null 2>&1 || true
  transition_stop_job=
  wait "$transition_rpm_job"
  transition_rpm_job=
  sudo rm -f "$transition_gate_script"
  transition_gate_script=
  sudo rm -rf "$transition_gate_dir"
  transition_gate_dir=
}

remove_policy_denial() {
  if [[ "$policy_installed" -eq 1 ]]; then
    sudo rm -f /usr/sbin/policy-rc.d
    policy_installed=0
  fi
  if [[ -n "$transition_gate_dir" ]]; then
    sudo touch "$transition_gate_dir/release" >/dev/null 2>&1 || true
  fi
  if [[ -n "$transition_gate_script" ]]; then
    sudo rm -f "$transition_gate_script" >/dev/null 2>&1 || true
  fi
  if [[ -n "$transition_rpm_job" ]]; then
    wait "$transition_rpm_job" >/dev/null 2>&1 || true
  fi
  if [[ -n "$transition_stop_job" ]]; then
    wait "$transition_stop_job" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  remove_policy_denial
  if [[ -n "$lock_gate_dir" ]]; then
    sudo touch "$lock_gate_dir/release" >/dev/null 2>&1 || true
  fi
  if [[ -n "$transition_gate_dir" ]]; then
    sudo rm -rf "$transition_gate_dir"
  fi
  if [[ -n "$lock_holder_job" ]]; then
    wait "$lock_holder_job" >/dev/null 2>&1 || true
  fi
  if [[ -n "$lifecycle_gate_dir" ]]; then
    sudo touch "$lifecycle_gate_dir/release" >/dev/null 2>&1 || true
  fi
  if [[ -n "$lifecycle_lock_job" ]]; then
    wait "$lifecycle_lock_job" >/dev/null 2>&1 || true
  fi
  if [[ -n "$zombie_parent_job" ]]; then
    sudo kill "$zombie_parent_job" >/dev/null 2>&1 || true
    wait "$zombie_parent_job" >/dev/null 2>&1 || true
  fi
  if [[ -n "$lock_gate_dir" ]]; then
    sudo rm -rf "$lock_gate_dir"
  fi
  if [[ -n "$lifecycle_gate_dir" ]]; then
    sudo rm -rf "$lifecycle_gate_dir"
  fi
  sudo rm -rf /etc/systemd/system/gta-claw-daemon.service.d
  sudo rm -rf /etc/systemd/system/gta-claw-state-init.service.d
  sudo systemctl disable --now gta-claw-daemon.service >/dev/null 2>&1 || true
  if dpkg-query -W gta-claw >/dev/null 2>&1; then
    sudo dpkg --purge gta-claw >/dev/null 2>&1 || true
  fi
  if rpm -q gta-claw >/dev/null 2>&1; then
    sudo rpm -e --nodeps gta-claw >/dev/null 2>&1 || true
  fi
  sudo systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ ! -e "$namespace" && ! -L "$namespace" ]]; then
    if getent passwd gta-claw >/dev/null 2>&1; then
      sudo userdel gta-claw >/dev/null 2>&1 || true
    fi
    if getent group gta-claw >/dev/null 2>&1; then
      sudo groupdel gta-claw >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$direct_root"
}
trap cleanup EXIT INT TERM
cleanup
direct_root="$(mktemp -d)"
[[ ! -e "$namespace" && ! -L "$namespace" ]] ||
  die "lifecycle test requires an absent protected namespace"

assert_disabled_and_inactive() {
  local active_state
  local control_pid
  local enabled_state
  local load_state
  local main_pid
  enabled_state="$(systemctl is-enabled gta-claw-daemon.service 2>/dev/null || true)"
  load_state="$(systemctl show -P LoadState gta-claw-daemon.service)"
  active_state="$(systemctl show -P ActiveState gta-claw-daemon.service)"
  main_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
  control_pid="$(systemctl show -P ControlPID gta-claw-daemon.service)"
  [[ "$enabled_state" == "disabled" ]] ||
    die "fresh service enablement is not exactly disabled: $enabled_state"
  [[ "$load_state" == "loaded" ]] ||
    die "fresh service is not loaded and unmasked: $load_state"
  [[ "$active_state:$main_pid:$control_pid" == "inactive:0:0" ]] ||
    die "fresh service runtime state is not exactly inactive with zero PIDs"
  [[ ! -e /run/gta-claw-state-init/initialization-failed &&
    ! -e /run/gta-claw-state-init/initialization-complete &&
    ! -e /run/gta-claw-state-init/replacement-fenced ]] ||
    die "fresh service retained an initialization transaction marker"
}

assert_protected_contract() {
  local service_gid
  local service_uid
  local actual_names
  local name
  service_uid="$(id -u gta-claw)"
  service_gid="$(id -g gta-claw)"
  [[ "$service_uid" =~ ^[1-9][0-9]*$ && "$service_gid" =~ ^[1-9][0-9]*$ ]] ||
    die "static gta-claw identity is invalid"
  [[ "$(sudo stat -c '%u:%g:%a' "$namespace")" == "0:$service_gid:750" ]] ||
    die "protected namespace ownership or mode is invalid"
  [[ -d "$namespace" && ! -L "$namespace" ]] ||
    die "protected namespace is not a physical directory"
  actual_names="$(
    sudo find "$namespace" -mindepth 1 -maxdepth 1 -printf '%f\n' |
      LC_ALL=C sort
  )"
  [[ "$actual_names" == "$expected_names" ]] ||
    die "protected namespace does not contain exactly the eight fixed names"
  for name in $expected_names; do
    path="$namespace/$name"
    { sudo test -f "$path" && sudo test ! -L "$path"; } ||
      die "protected entry is not a physical regular file: $name"
    [[ "$(sudo stat -c '%u:%g:%a:%h' "$path")" == \
      "$service_uid:$service_gid:600:1" ]] ||
      die "protected entry ownership, mode, or link count is invalid: $name"
    sudo -u gta-claw test -w "$path" ||
      die "service identity cannot write held file: $name"
  done
  sudo -u gta-claw test ! -w "$namespace" ||
    die "service identity has directory-entry mutation authority"
}

state_snapshot() {
  local name
  sudo stat -c 'parent:%d:%i:%u:%g:%a' "$namespace"
  for name in $expected_names; do
    sudo stat -c "$name:%d:%i:%u:%g:%a:%h:%s" "$namespace/$name"
    sudo sha256sum "$namespace/$name"
  done
}

state_identity_snapshot() {
  local name
  sudo stat -c 'parent:%d:%i:%u:%g:%a' "$namespace"
  for name in $expected_names; do
    sudo stat -c "$name:%d:%i:%u:%g:%a:%h" "$namespace/$name"
  done
}

assert_preserved() {
  local expected="$1"
  assert_protected_contract
  [[ "$(state_snapshot)" == "$expected" ]] ||
    die "ordinary removal changed protected state"
}

assert_identity_preserved() {
  local expected="$1"
  assert_protected_contract
  [[ "$(state_identity_snapshot)" == "$expected" ]] ||
    die "active removal replaced or deleted protected state entries"
}

reset_test_namespace() {
  assert_protected_contract
  ! systemctl is-active --quiet gta-claw-daemon.service ||
    die "refusing fixture purge while daemon is active"
  sudo rm -rf -- "$namespace"
  [[ ! -e "$namespace" && ! -L "$namespace" ]] ||
    die "test fixture namespace purge failed"
}

assert_identity_absent() {
  ! getent passwd gta-claw >/dev/null 2>&1 ||
    die "lifecycle phase inherited a gta-claw user"
  ! getent group gta-claw >/dev/null 2>&1 ||
    die "lifecycle phase inherited a gta-claw group"
}

reset_test_identity() {
  [[ ! -e "$namespace" && ! -L "$namespace" ]] ||
    die "refusing identity reset while protected state exists"
  ! systemctl is-active --quiet gta-claw-daemon.service ||
    die "refusing identity reset while daemon is active"
  if getent passwd gta-claw >/dev/null 2>&1; then
    sudo userdel gta-claw
  fi
  if getent group gta-claw >/dev/null 2>&1; then
    sudo groupdel gta-claw
  fi
  assert_identity_absent
}

assert_active_restart() {
  local old_pid="$1"
  local new_pid
  systemctl is-active --quiet gta-claw-daemon.service ||
    die "service is not active after replacement"
  wait_for_writer_lock
  new_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
  [[ "$new_pid" =~ ^[1-9][0-9]*$ && "$new_pid" != "$old_pid" ]] ||
    die "active service was not restarted during replacement"
}

assert_start_fenced() {
  local label="$1"
  local active_state
  local main_pid
  local control_pid
  sudo systemctl start gta-claw-daemon.service >/dev/null 2>&1 || true
  sleep 0.2
  active_state="$(systemctl show -P ActiveState gta-claw-daemon.service)"
  main_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
  control_pid="$(systemctl show -P ControlPID gta-claw-daemon.service)"
  case "$active_state:$main_pid:$control_pid" in
    inactive:0:0 | failed:0:0) ;;
    *) die "$label allowed a process or automatic retry: $active_state:$main_pid:$control_pid" ;;
  esac
}

wait_for_writer_lock() {
  local deadline=$((SECONDS + 15))
  local status
  while :; do
    set +e
    sudo -u gta-claw \
      flock --conflict-exit-code 75 -n "$namespace/state.writer.lock" true
    status=$?
    set -e
    case "$status" in
      0)
        ((SECONDS < deadline)) ||
          die "runtime did not acquire the protected writer lock"
        sleep 0.05
        ;;
      75) return 0 ;;
      *) die "writer-lock probe failed with status $status" ;;
    esac
  done
}

start_manual_writer_lock() {
  local deadline
  lock_gate_dir="$(sudo mktemp -d /run/gta-claw-lifecycle-lock.XXXXXXXX)"
  sudo chown gta-claw:gta-claw "$lock_gate_dir"
  sudo chmod 0700 "$lock_gate_dir"
  sudo -u gta-claw \
    flock "$namespace/state.writer.lock" \
    sh -c 'touch "$1"; while [ ! -e "$2" ]; do sleep 0.05; done' \
    sh "$lock_gate_dir/ready" "$lock_gate_dir/release" &
  lock_holder_job=$!
  deadline=$((SECONDS + 10))
  while [[ ! -e "$lock_gate_dir/ready" ]]; do
    ((SECONDS < deadline)) || die "manual writer-lock holder did not become ready"
    sleep 0.05
  done
}

stop_manual_writer_lock() {
  sudo touch "$lock_gate_dir/release"
  wait "$lock_holder_job"
  sudo rm -rf "$lock_gate_dir"
  lock_gate_dir=
  lock_holder_job=
}

assert_live_initializer_rejected() {
  wait_for_writer_lock
  if sudo /usr/libexec/gta-claw/gta-claw-state-init >/dev/null 2>&1; then
    die "root initializer succeeded while the runtime held the writer lock"
  fi
  systemctl is-active --quiet gta-claw-daemon.service ||
    die "live-contention check disturbed the runtime"
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

install_initializer_stop_denial() {
  sudo mkdir -p /etc/systemd/system/gta-claw-state-init.service.d
  printf '[Unit]\nRefuseManualStop=yes\n' |
    sudo tee /etc/systemd/system/gta-claw-state-init.service.d/failure.conf >/dev/null
  sudo systemctl daemon-reload
}

remove_initializer_stop_denial() {
  sudo rm -rf /etc/systemd/system/gta-claw-state-init.service.d
  sudo systemctl daemon-reload
  sudo systemctl reset-failed gta-claw-state-init.service >/dev/null 2>&1 || true
}

establish_package_runtime_fence() {
  sudo install -d -o root -g root -m 0755 /run/gta-claw-state-init
  sudo touch \
    /run/gta-claw-state-init/initialization-failed \
    /run/gta-claw-state-init/replacement-fenced
  sudo chown root:root \
    /run/gta-claw-state-init/initialization-failed \
    /run/gta-claw-state-init/replacement-fenced
  sudo chmod 0644 \
    /run/gta-claw-state-init/initialization-failed \
    /run/gta-claw-state-init/replacement-fenced
  sudo systemctl mask --runtime gta-claw-daemon.service
  sudo systemctl stop gta-claw-daemon.service
  case "$(systemctl is-enabled gta-claw-daemon.service 2>/dev/null || true)" in
    masked | masked-runtime) ;;
    *) die "package-owned runtime fence did not mask the daemon" ;;
  esac
}

simulate_direct_reboot() {
  sudo systemctl unmask --runtime gta-claw-daemon.service
  sudo rm -rf /run/gta-claw-state-init
  sudo rm -f \
    /run/gta-claw-daemon.ready-for-replacement \
    /run/gta-claw-daemon.was-active
  sudo systemctl daemon-reload
  [[ -e /var/lib/gta-claw-install/transaction-failed &&
    -e /var/lib/gta-claw-install/was-active ]] ||
    die "direct hard interruption lost its persistent transaction journal"
  assert_start_fenced "direct hard interruption after simulated reboot"
  ! systemctl is-active --quiet gta-claw-daemon.service ||
    die "direct hard interruption left the daemon active after simulated reboot"
}

mkdir "$direct_root/release1" "$direct_root/release2"
tar -xzf "$tar1" -C "$direct_root/release1"
tar -xzf "$tar2" -C "$direct_root/release2"
direct1="$(find "$direct_root/release1" -mindepth 1 -maxdepth 1 -type d)"
direct2="$(find "$direct_root/release2" -mindepth 1 -maxdepth 1 -type d)"
[[ "$(cat "$direct1/package-version")" == "$VERSION-1" &&
  "$(cat "$direct2/package-version")" == "$VERSION-2" ]] ||
  die "release package-version identities are not distinct"
spdx_namespace1="$(jq -er '.documentNamespace' "$direct1/sbom.spdx.json")"
spdx_namespace2="$(jq -er '.documentNamespace' "$direct2/sbom.spdx.json")"
[[ "$spdx_namespace1" != "$spdx_namespace2" &&
  "$spdx_namespace1" == *"/$VERSION-1/native-tar" &&
  "$spdx_namespace2" == *"/$VERSION-2/native-tar" ]] ||
  die "release SPDX namespaces are not package-release specific"
[[ "$(jq -er '.packages[] | select(.name == "gta-claw") | .versionInfo' \
  "$direct1/sbom.spdx.json")" == "$VERSION-1" &&
  "$(jq -er '.packages[] | select(.name == "gta-claw") | .versionInfo' \
  "$direct2/sbom.spdx.json")" == "$VERSION-2" ]] ||
  die "release SPDX package versions are not package-release specific"
assert_identity_absent
sudo "$direct1/install.sh"
assert_disabled_and_inactive
assert_protected_contract
static_identity="$(id -u gta-claw):$(id -g gta-claw)"
sudo systemctl mask --runtime gta-claw-daemon.service
for _ in 1 2; do
  if sudo "$direct1/install.sh"; then
    die "direct deployment accepted an administrator-owned runtime mask"
  fi
  case "$(systemctl is-enabled gta-claw-daemon.service 2>/dev/null || true)" in
    masked | masked-runtime) ;;
    *) die "direct mask rejection changed administrator mask ownership" ;;
  esac
  [[ ! -e /var/lib/gta-claw-install/transaction-failed &&
    ! -e /run/gta-claw-state-init/replacement-fenced ]] ||
    die "direct mask rejection claimed an administrator-owned transaction"
done
sudo systemctl unmask --runtime gta-claw-daemon.service
sudo systemctl daemon-reload
sudo systemctl enable --now gta-claw-daemon.service
assert_live_initializer_rejected
direct_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
direct_reinstall_snapshot="$(state_identity_snapshot)"
sudo mv /etc/gta-claw/gta-claw.env /etc/gta-claw/gta-claw.env.saved
sudo ln -s /nonexistent/gta-claw.env /etc/gta-claw/gta-claw.env
if sudo "$direct1/install.sh"; then
  die "direct deployment accepted a symlinked configuration destination"
fi
systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct configuration preflight stopped the active service"
[[ "$(systemctl show -P MainPID gta-claw-daemon.service)" == "$direct_pid" ]] ||
  die "direct configuration preflight restarted the active service"
sudo rm /etc/gta-claw/gta-claw.env
sudo mv /etc/gta-claw/gta-claw.env.saved /etc/gta-claw/gta-claw.env
sudo "$direct1/install.sh"
assert_active_restart "$direct_pid"
assert_identity_preserved "$direct_reinstall_snapshot"
direct_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
direct_upgrade_snapshot="$(state_identity_snapshot)"
sudo "$direct2/install.sh"
assert_active_restart "$direct_pid"
assert_identity_preserved "$direct_upgrade_snapshot"
lifecycle_gate_dir="$(mktemp -d)"
sudo sh -c '
  exec 8<>/run/gta-claw-lifecycle.lock
  flock -n 8
  touch "$1/ready"
  while [ ! -e "$1/release" ]; do sleep 0.05; done
' _ "$lifecycle_gate_dir" &
lifecycle_lock_job=$!
for _ in {1..200}; do
  [[ ! -e "$lifecycle_gate_dir/ready" ]] || break
  kill -0 "$lifecycle_lock_job" >/dev/null 2>&1 ||
    die "lifecycle-lock fixture exited before readiness"
  sleep 0.05
done
[[ -e "$lifecycle_gate_dir/ready" ]] ||
  die "lifecycle-lock fixture did not become ready"
direct_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
if sudo "$direct2/install.sh"; then
  die "direct install ignored a concurrent lifecycle transaction"
fi
if sudo "$direct2/uninstall.sh"; then
  die "direct uninstall ignored a concurrent lifecycle transaction"
fi
[[ "$(systemctl show -P MainPID gta-claw-daemon.service)" == "$direct_pid" &&
  -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "lifecycle-lock rejection mutated the active direct installation"
sudo touch "$lifecycle_gate_dir/release"
wait "$lifecycle_lock_job"
lifecycle_lock_job=
sudo rm -rf "$lifecycle_gate_dir"
lifecycle_gate_dir=

zombie_pid_file="$direct_root/zombie.pid"
sudo python3 - "$zombie_pid_file" <<'PY' &
import os
import pathlib
import sys
import time

child = os.fork()
if child == 0:
    os._exit(0)
pathlib.Path(sys.argv[1]).write_text(f"{child}\n", encoding="ascii")
time.sleep(60)
PY
zombie_parent_job=$!
for _ in {1..200}; do
  [[ ! -s "$zombie_pid_file" ]] || break
  kill -0 "$zombie_parent_job" >/dev/null 2>&1 ||
    die "zombie fixture exited before publishing its child PID"
  sleep 0.05
done
[[ -s "$zombie_pid_file" ]] || die "zombie fixture did not publish its child PID"
zombie_pid="$(cat "$zombie_pid_file")"
zombie_state=
for _ in {1..200}; do
  zombie_state="$(
    sudo awk \
      '{ text=$0; sub(/^.*\) /, "", text); split(text, fields, " "); print fields[1] }' \
      "/proc/$zombie_pid/stat" 2>/dev/null || true
  )"
  [[ "$zombie_state" != "Z" ]] || break
  kill -0 "$zombie_parent_job" >/dev/null 2>&1 ||
    die "zombie fixture parent exited before the child became a zombie"
  sleep 0.05
done
[[ "$zombie_state" == "Z" ]] || die "zombie fixture did not reach zombie state"
zombie_start="$(
  sudo awk '{ text=$0; sub(/^.*\) /, "", text); split(text, fields, " "); print fields[20] }' \
    "/proc/$zombie_pid/stat"
)"
sudo install -d -o root -g root -m 0755 /run/gta-claw-state-init
sudo touch /run/gta-claw-state-init/initialization-failed
sudo chown root:root /run/gta-claw-state-init/initialization-failed
sudo chmod 0644 /run/gta-claw-state-init/initialization-failed
printf '%s %s\n' "$zombie_pid" "$zombie_start" |
  sudo tee /run/gta-claw-state-init/start-authorized >/dev/null
sudo chown root:root /run/gta-claw-state-init/start-authorized
sudo chmod 0600 /run/gta-claw-state-init/start-authorized
if sudo /usr/libexec/gta-claw/gta-claw-start-authorized check; then
  die "start authorization accepted a zombie installer process"
fi
sudo rm -f \
  /run/gta-claw-state-init/start-authorized \
  /run/gta-claw-state-init/initialization-failed
sudo kill "$zombie_parent_job"
wait "$zombie_parent_job" >/dev/null 2>&1 || true
zombie_parent_job=
for direct_boundary in unit daemon authorization; do
  direct_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
  if sudo env \
    GTA_CLAW_DIRECT_TEST_INTERRUPT_AFTER="$direct_boundary" \
    "$direct2/install.sh"; then
    die "direct install ignored a hard interruption at $direct_boundary"
  fi
  if [[ "$direct_boundary" == "authorization" ]]; then
    [[ -e /run/gta-claw-state-init/start-authorized ]] ||
      die "direct authorization interruption left no transaction capability"
    assert_start_fenced "dead direct start authorization"
  fi
  simulate_direct_reboot
  sudo "$direct2/install.sh"
  assert_active_restart "$direct_pid"
  [[ ! -e /var/lib/gta-claw-install/transaction-failed &&
    ! -e /var/lib/gta-claw-install/was-active ]] ||
    die "direct install retry left its persistent transaction journal"
done
bin_true_hash="$(sha256sum /bin/true)"
if sudo env \
  GTA_CLAW_DIRECT_TEST_BREAK_FAILURE_FENCE=1 \
  GTA_CLAW_DIRECT_TEST_FAIL_AFTER=unit \
  "$direct2/install.sh"; then
  die "direct install ignored a failure-fence authentication fault"
fi
[[ -L /run/gta-claw-state-init/initialization-failed &&
  "$(readlink /run/gta-claw-state-init/initialization-failed)" == "/bin/true" ]] ||
  die "direct failure-fence authentication fixture was not retained"
[[ "$(sha256sum /bin/true)" == "$bin_true_hash" ]] ||
  die "direct failure handling modified the symlink target"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct marker-authentication failure left a retrying daemon"
sudo rm /run/gta-claw-state-init/initialization-failed
sudo "$direct2/install.sh"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct marker-authentication recovery did not resume the daemon"
if sudo "$direct1/install.sh"; then
  die "direct deployment accepted a downgrade"
fi
systemctl is-active --quiet gta-claw-daemon.service ||
  die "rejected direct downgrade disturbed the active service"
install_failure_dropin Service 'ExecStartPre=/bin/false'
if sudo "$direct2/install.sh"; then
  die "direct deployment swallowed a package-triggered restart failure"
fi
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct restart failure left the service active"
remove_failure_dropin
assert_start_fenced "direct restart failure"
sudo "$direct2/install.sh"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct restart retry did not resume the previously active service"
wait_for_writer_lock
sudo touch "$namespace/state.sqlite-shm"
if sudo "$direct2/install.sh"; then
  die "direct deployment started after failed protected initialization"
fi
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct failed initialization left the service active"
assert_start_fenced "direct initialization failure"
sudo rm "$namespace/state.sqlite-shm"
sudo "$direct2/install.sh"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct retry did not resume the previously active service"
wait_for_writer_lock
install_failure_dropin Unit 'RefuseManualStop=yes'
if sudo "$direct2/uninstall.sh"; then
  die "direct removal swallowed an intentional stop failure"
fi
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "direct removal unlinked the daemon after stop failure"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct stop failure did not leave the daemon active"
remove_failure_dropin
install_initializer_stop_denial
if sudo "$direct2/uninstall.sh"; then
  die "direct removal ignored a late initializer-stop failure"
fi
systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct late removal failure did not restore the active daemon"
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled" ]] ||
  die "direct late removal failure changed persistent enablement"
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "direct late removal failure unlinked the daemon"
remove_initializer_stop_denial

sudo systemctl stop gta-claw-daemon.service
start_manual_writer_lock
if sudo "$direct2/uninstall.sh"; then
  die "direct removal ignored an escaped writer-lock holder"
fi
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "direct lock rejection unlinked the daemon"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct lock rejection changed the inactive runtime state"
direct_lock_enable_state="$(systemctl is-enabled gta-claw-daemon.service 2>/dev/null || true)"
[[ "$direct_lock_enable_state" == "enabled" ]] ||
  die "direct lock rejection changed persistent enablement: $direct_lock_enable_state"
stop_manual_writer_lock
sudo systemctl start gta-claw-daemon.service

sudo systemctl disable gta-claw-daemon.service
sudo systemctl enable --runtime gta-claw-daemon.service
install_initializer_stop_denial
if sudo "$direct2/uninstall.sh"; then
  die "direct removal ignored runtime-only rollback coverage"
fi
systemctl is-active --quiet gta-claw-daemon.service ||
  die "direct runtime-only rollback did not restore the active daemon"
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled-runtime" ]] ||
  die "direct removal changed runtime-only enablement during rollback"
remove_initializer_stop_denial
sudo systemctl disable --runtime gta-claw-daemon.service
sudo systemctl enable gta-claw-daemon.service

direct_snapshot="$(state_identity_snapshot)"
sudo "$direct2/uninstall.sh"
assert_identity_preserved "$direct_snapshot"
sudo "$direct2/uninstall.sh"
assert_identity_preserved "$direct_snapshot"
[[ ! -e /usr/libexec/gta-claw/gta-claw-daemon &&
  ! -e /usr/lib/systemd/system/gta-claw-daemon.service ]] ||
  die "direct removal left package-owned executable or unit"
[[ "$(id -u gta-claw):$(id -g gta-claw)" == "$static_identity" ]] ||
  die "direct removal changed the static service identity"
direct_absent_snapshot="$(state_snapshot)"
start_manual_writer_lock
if sudo "$direct2/install.sh"; then
  die "direct install replaced an absent unit while the writer lock was held"
fi
[[ ! -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "direct lock rejection changed the absent payload"
stop_manual_writer_lock
assert_preserved "$direct_absent_snapshot"
sudo "$direct2/install.sh"
assert_disabled_and_inactive
sudo "$direct2/uninstall.sh"
assert_preserved "$direct_absent_snapshot"
reset_test_namespace

sudo "$direct1/install.sh"
assert_disabled_and_inactive
direct_inactive_upgrade_snapshot="$(state_snapshot)"
sudo "$direct2/install.sh"
assert_disabled_and_inactive
assert_preserved "$direct_inactive_upgrade_snapshot"
direct_inactive_snapshot="$(state_snapshot)"
sudo "$direct2/uninstall.sh"
assert_preserved "$direct_inactive_snapshot"
reset_test_namespace
reset_test_identity

assert_identity_absent
if sudo env GTA_CLAW_PACKAGE_TEST_FAIL_AFTER=preset dpkg -i "$deb1"; then
  die "Debian fresh install ignored a post-preset transaction fault"
fi
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian post-preset fault left the daemon active"
[[ -e /run/gta-claw-state-init/initialization-failed &&
  -e /run/gta-claw-state-init/replacement-fenced ]] ||
  die "Debian post-preset fault lost its transaction fence"
sudo dpkg --configure gta-claw
assert_disabled_and_inactive
assert_protected_contract
[[ "$(id -u gta-claw):$(id -g gta-claw)" == "$static_identity" ]] ||
  die "Debian install changed the static service identity"
sudo systemctl enable --now gta-claw-daemon.service
assert_live_initializer_rejected
deb_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
deb_reinstall_snapshot="$(state_identity_snapshot)"
sudo dpkg -i "$deb1"
assert_active_restart "$deb_pid"
assert_identity_preserved "$deb_reinstall_snapshot"
deb_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
deb_upgrade_snapshot="$(state_identity_snapshot)"
sudo dpkg -i "$deb2"
assert_active_restart "$deb_pid"
assert_identity_preserved "$deb_upgrade_snapshot"
install_failure_dropin Unit 'RefuseManualStop=yes'
deb_preinst_hash="$(sha256sum /usr/libexec/gta-claw/gta-claw-daemon)"
if sudo dpkg -i "$deb2"; then
  die "Debian preinst ignored a RefuseManualStop failure"
fi
[[ "$(sha256sum /usr/libexec/gta-claw/gta-claw-daemon)" == "$deb_preinst_hash" ]] ||
  die "failed Debian preinst replaced the installed daemon"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "failed Debian preinst did not restore the active daemon"
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled" ]] ||
  die "failed Debian preinst changed persistent enablement"
remove_failure_dropin

sudo systemctl stop gta-claw-daemon.service
start_manual_writer_lock
if sudo dpkg -i "$deb2"; then
  die "Debian preinst ignored an escaped writer-lock holder"
fi
[[ "$(sha256sum /usr/libexec/gta-claw/gta-claw-daemon)" == "$deb_preinst_hash" ]] ||
  die "writer-lock-rejected Debian preinst replaced the daemon"
[[ "$(dpkg-query -W -f='${Status}' gta-claw)" == "install ok installed" ]] ||
  die "writer-lock-rejected Debian preinst changed package status"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "writer-lock-rejected Debian preinst changed inactive state"
stop_manual_writer_lock
sudo systemctl start gta-claw-daemon.service

for package_boundary in initialization unmask daemon-reload restart readiness; do
  deb_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
  if sudo env \
    GTA_CLAW_PACKAGE_TEST_FAIL_AFTER="$package_boundary" \
    dpkg -i "$deb2"; then
    die "Debian configure ignored a $package_boundary transaction fault"
  fi
  ! systemctl is-active --quiet gta-claw-daemon.service ||
    die "Debian $package_boundary fault left the daemon active"
  [[ -e /run/gta-claw-state-init/initialization-failed &&
    -e /run/gta-claw-state-init/replacement-fenced ]] ||
    die "Debian $package_boundary fault lost its transaction fence"
  sudo dpkg --configure gta-claw
  assert_active_restart "$deb_pid"
done

bin_true_hash="$(sha256sum /bin/true)"
if sudo env \
  GTA_CLAW_PACKAGE_TEST_BREAK_FAILURE_FENCE=1 \
  GTA_CLAW_PACKAGE_TEST_FAIL_AFTER=initialization \
  dpkg -i "$deb2"; then
  die "Debian configure ignored a failure-fence authentication fault"
fi
[[ -L /run/gta-claw-state-init/initialization-failed &&
  "$(readlink /run/gta-claw-state-init/initialization-failed)" == "/bin/true" ]] ||
  die "Debian failure-fence authentication fixture was not retained"
[[ "$(sha256sum /bin/true)" == "$bin_true_hash" ]] ||
  die "Debian failure handling modified the symlink target"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian marker-authentication failure left a retrying daemon"
sudo rm /run/gta-claw-state-init/initialization-failed
sudo dpkg --configure gta-claw
systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian marker-authentication recovery did not resume the daemon"
if sudo dpkg -i --force-downgrade "$deb1"; then
  die "Debian package accepted a downgrade"
fi
systemctl is-active --quiet gta-claw-daemon.service ||
  die "rejected Debian downgrade disturbed the active service"
install_policy_denial
if sudo dpkg -i "$deb2"; then
  die "Debian replacement ignored a policy-denied restart"
fi
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "policy-denied Debian restart left the service active"
remove_policy_denial
assert_start_fenced "Debian restart failure"
sudo dpkg --configure gta-claw
systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian restart recovery did not resume the service"
wait_for_writer_lock
sudo touch "$namespace/state.sqlite-shm"
if sudo dpkg -i "$deb2"; then
  die "Debian reinstall swallowed protected initialization failure"
fi
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian failed initialization restarted the service"
assert_start_fenced "Debian initialization failure"
sudo rm "$namespace/state.sqlite-shm"
sudo dpkg -i "$deb2"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian re-unpack retry did not preserve prior active state"
sudo systemctl stop gta-claw-daemon.service
install_failure_dropin Service 'ExecStartPre=/bin/false'
if sudo systemctl start gta-claw-daemon.service; then
  die "intentional Debian start failure unexpectedly succeeded"
fi
remove_failure_dropin
sudo systemctl start gta-claw-daemon.service
install_failure_dropin Unit 'RefuseManualStop=yes'
if sudo dpkg --remove gta-claw; then
  die "Debian removal swallowed an intentional stop failure"
fi
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "Debian removal unlinked the daemon after stop failure"
remove_failure_dropin
install_policy_denial
if sudo dpkg --remove gta-claw; then
  die "Debian removal ignored a policy-denied stop"
fi
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "policy-denied Debian removal unlinked the daemon"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "policy-denied Debian stop did not leave the daemon active"
remove_policy_denial
sudo systemctl disable gta-claw-daemon.service
sudo systemctl enable --runtime gta-claw-daemon.service
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled-runtime" ]] ||
  die "Debian runtime-only enablement fixture was not established"
install_initializer_stop_denial
if sudo dpkg --remove gta-claw; then
  die "Debian removal ignored a late initializer-stop failure"
fi
systemctl is-active --quiet gta-claw-daemon.service ||
  die "Debian late removal failure did not restore the active daemon"
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled-runtime" ]] ||
  die "Debian late removal failure changed runtime-only enablement"
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "Debian late removal failure unlinked the daemon"
remove_initializer_stop_denial
sudo systemctl enable gta-claw-daemon.service
install_initializer_stop_denial
if sudo dpkg --remove gta-claw; then
  die "Debian dual-enable removal ignored a late initializer-stop failure"
fi
[[ -L /etc/systemd/system/multi-user.target.wants/gta-claw-daemon.service &&
  -L /run/systemd/system/multi-user.target.wants/gta-claw-daemon.service ]] ||
  die "Debian rollback did not restore both enablement links"
remove_initializer_stop_denial
deb_snapshot="$(state_identity_snapshot)"
sudo dpkg --remove gta-claw
assert_identity_preserved "$deb_snapshot"
sudo dpkg --purge gta-claw
assert_identity_preserved "$deb_snapshot"
[[ "$(id -u gta-claw):$(id -g gta-claw)" == "$static_identity" ]] ||
  die "Debian removal changed the static service identity"
reset_test_namespace

sudo dpkg -i "$deb1"
assert_disabled_and_inactive
deb_inactive_upgrade_snapshot="$(state_snapshot)"
sudo dpkg -i "$deb2"
assert_disabled_and_inactive
assert_preserved "$deb_inactive_upgrade_snapshot"
deb_inactive_snapshot="$(state_snapshot)"
sudo rm -rf /run/gta-claw-state-init
sudo dpkg --remove gta-claw
assert_preserved "$deb_inactive_snapshot"
sudo dpkg --purge gta-claw
assert_preserved "$deb_inactive_snapshot"
sudo dpkg -i "$deb2"
assert_disabled_and_inactive
assert_preserved "$deb_inactive_snapshot"
establish_package_runtime_fence
install_initializer_stop_denial
if sudo dpkg --remove gta-claw; then
  die "Debian package-fenced removal ignored a late initializer-stop failure"
fi
case "$(systemctl is-enabled gta-claw-daemon.service 2>/dev/null || true)" in
  masked | masked-runtime) ;;
  *) die "Debian package-fenced rollback removed the runtime mask" ;;
esac
[[ -e /run/gta-claw-state-init/initialization-failed &&
  -e /run/gta-claw-state-init/replacement-fenced ]] ||
  die "Debian package-fenced rollback lost its authenticated markers"
remove_initializer_stop_denial
sudo dpkg --remove gta-claw
[[ ! -e /run/gta-claw-state-init/initialization-failed &&
  ! -e /run/gta-claw-state-init/replacement-fenced ]] ||
  die "Debian removal did not clear deferred package-fence markers"
assert_preserved "$deb_inactive_snapshot"
sudo dpkg --purge gta-claw
assert_preserved "$deb_inactive_snapshot"
rpm_absent_snapshot="$(state_snapshot)"
start_manual_writer_lock
if sudo rpm -ivh --nodeps "$rpm1"; then
  die "RPM install replaced an absent unit while the writer lock was held"
fi
! rpm -q gta-claw >/dev/null 2>&1 ||
  die "RPM lock rejection installed a package"
stop_manual_writer_lock
assert_preserved "$rpm_absent_snapshot"
reset_test_namespace
reset_test_identity

assert_identity_absent
sudo systemctl mask --runtime gta-claw-daemon.service
if sudo rpm -ivh --nodeps "$rpm1"; then
  die "RPM install accepted an administrator-owned runtime mask"
fi
[[ "$(systemctl show -P LoadState gta-claw-daemon.service)" == "masked" ]] ||
  die "RPM rejection removed an administrator-owned runtime mask"
sudo systemctl unmask --runtime gta-claw-daemon.service
sudo systemctl daemon-reload
set +e
sudo env GTA_CLAW_PACKAGE_TEST_FAIL_AFTER=before-preset rpm -ivh --nodeps "$rpm1"
rpm_preset_status=$?
set -e
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM pre-preset fault left the daemon active"
[[ -e /run/gta-claw-state-init/initialization-failed &&
  -e /run/gta-claw-state-init/replacement-fenced ]] ||
  die "RPM pre-preset fault lost its transaction fence"
if [[ "$rpm_preset_status" -eq 0 ]]; then
  echo "RPM reported failed pre-preset scriptlet as a warning; runtime remained fenced" >&2
fi
sudo rpm -Uvh --nodeps --replacepkgs "$rpm1"
assert_disabled_and_inactive
assert_protected_contract
[[ "$(id -u gta-claw):$(id -g gta-claw)" == "$static_identity" ]] ||
  die "RPM install changed the static service identity"
sudo systemctl enable --now gta-claw-daemon.service
assert_live_initializer_rejected
rpm_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
rpm_reinstall_snapshot="$(state_identity_snapshot)"
sudo rpm -Uvh --nodeps --replacepkgs "$rpm1"
assert_active_restart "$rpm_pid"
assert_identity_preserved "$rpm_reinstall_snapshot"
rpm_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
rpm_upgrade_snapshot="$(state_identity_snapshot)"
sudo rpm -Uvh --nodeps "$rpm2"
assert_active_restart "$rpm_pid"
assert_identity_preserved "$rpm_upgrade_snapshot"
rpm_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
rpm_transition_snapshot="$(state_identity_snapshot)"
rpm_transition_receipt="$(
  stat -Lc '%d:%i:%s:%y:%z' /usr/libexec/gta-claw/gta-claw-daemon
)"
begin_daemon_activation
[[ ! -e /run/gta-claw-state-init/replacement-fenced ]] ||
  die "RPM activating-state fixture started with a stale replacement fence"
rpm_transition_content_snapshot="$(protected_state_snapshot)"
sudo rpm -Uvh --nodeps --replacepkgs "$rpm2" \
  >/dev/null 2>&1 &
transition_rpm_job=$!
deadline=$((SECONDS + 10))
while [[ ! -e /run/gta-claw-state-init/replacement-fenced ]]; do
  kill -0 "$transition_rpm_job" >/dev/null 2>&1 ||
    die "RPM activating-state replacement exited before fencing"
  ((SECONDS < deadline)) ||
    die "RPM activating-state replacement did not establish its fence"
  sleep 0.05
done
deadline=$((SECONDS + 10))
while [[ "$(systemctl show -P ActiveState gta-claw-daemon.service)" != "deactivating" ]]; do
  kill -0 "$transition_rpm_job" >/dev/null 2>&1 ||
    die "RPM activating-state replacement exited before stop was held"
  [[ "$(stat -Lc '%d:%i:%s:%y:%z' /usr/libexec/gta-claw/gta-claw-daemon)" == \
    "$rpm_transition_receipt" ]] ||
    die "RPM replaced the daemon before activating-state stop was held"
  ((SECONDS < deadline)) ||
    die "RPM activating-state replacement did not block in deactivating"
  sleep 0.05
done
assert_rpm_transition_held \
  "$rpm_transition_content_snapshot" \
  "activating-state" \
  "$rpm_transition_receipt"
finish_daemon_activation
assert_active_restart "$rpm_pid"
assert_identity_preserved "$rpm_transition_snapshot"
rpm_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
rpm_transition_snapshot="$(state_identity_snapshot)"
rpm_transition_receipt="$(
  stat -Lc '%d:%i:%s:%y:%z' /usr/libexec/gta-claw/gta-claw-daemon
)"
begin_daemon_deactivation
[[ ! -e /run/gta-claw-state-init/replacement-fenced ]] ||
  die "RPM transitional-state fixture started with a stale replacement fence"
rpm_transition_content_snapshot="$(protected_state_snapshot)"
sudo rpm -Uvh --nodeps --replacepkgs "$rpm2" \
  >/dev/null 2>&1 &
transition_rpm_job=$!
deadline=$((SECONDS + 10))
while [[ ! -e /run/gta-claw-state-init/replacement-fenced ]]; do
  kill -0 "$transition_rpm_job" >/dev/null 2>&1 ||
    die "RPM transitional-state replacement exited before fencing"
  ((SECONDS < deadline)) ||
    die "RPM transitional-state replacement did not establish its fence"
  sleep 0.05
done
assert_rpm_transition_held \
  "$rpm_transition_content_snapshot" \
  "deactivating-state" \
  "$rpm_transition_receipt"
finish_daemon_deactivation
assert_active_restart "$rpm_pid"
assert_identity_preserved "$rpm_transition_snapshot"
install_failure_dropin Unit 'RefuseManualStop=yes'
rpm_pre_hash="$(sha256sum /usr/libexec/gta-claw/gta-claw-daemon)"
if sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"; then
  die "RPM pre-install ignored a RefuseManualStop failure"
fi
[[ "$(sha256sum /usr/libexec/gta-claw/gta-claw-daemon)" == "$rpm_pre_hash" ]] ||
  die "failed RPM pre-install replaced the daemon"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "failed RPM pre-install did not restore the active daemon"
remove_failure_dropin

sudo systemctl stop gta-claw-daemon.service
start_manual_writer_lock
if sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"; then
  die "RPM pre-install ignored an escaped writer-lock holder"
fi
[[ "$(sha256sum /usr/libexec/gta-claw/gta-claw-daemon)" == "$rpm_pre_hash" ]] ||
  die "writer-lock-rejected RPM pre-install replaced the daemon"
[[ "$(rpm -q gta-claw | wc -l)" -eq 1 ]] ||
  die "writer-lock-rejected RPM pre-install changed package instances"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "writer-lock-rejected RPM pre-install changed inactive state"
stop_manual_writer_lock
sudo systemctl start gta-claw-daemon.service

for package_boundary in initialization unmask daemon-reload restart readiness; do
  rpm_pid="$(systemctl show -P MainPID gta-claw-daemon.service)"
  set +e
  sudo env \
    GTA_CLAW_PACKAGE_TEST_FAIL_AFTER="$package_boundary" \
    rpm -Uvh --nodeps --replacepkgs "$rpm2"
  rpm_boundary_status=$?
  set -e
  ! systemctl is-active --quiet gta-claw-daemon.service ||
    die "RPM $package_boundary fault left the daemon active"
  [[ -e /run/gta-claw-state-init/initialization-failed &&
    -e /run/gta-claw-state-init/replacement-fenced ]] ||
    die "RPM $package_boundary fault lost its transaction fence"
  if [[ "$rpm_boundary_status" -eq 0 ]]; then
    echo "RPM reported failed $package_boundary scriptlet as a warning; runtime remained fenced" >&2
  fi
  sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"
  [[ "$(rpm -q gta-claw | wc -l)" -eq 1 ]] ||
    die "RPM $package_boundary recovery left duplicate package instances"
  assert_active_restart "$rpm_pid"
done

bin_true_hash="$(sha256sum /bin/true)"
set +e
sudo env \
  GTA_CLAW_PACKAGE_TEST_BREAK_FAILURE_FENCE=1 \
  GTA_CLAW_PACKAGE_TEST_FAIL_AFTER=initialization \
  rpm -Uvh --nodeps --replacepkgs "$rpm2"
rpm_marker_status=$?
set -e
[[ -L /run/gta-claw-state-init/initialization-failed &&
  "$(readlink /run/gta-claw-state-init/initialization-failed)" == "/bin/true" ]] ||
  die "RPM failure-fence authentication fixture was not retained"
[[ "$(sha256sum /bin/true)" == "$bin_true_hash" ]] ||
  die "RPM failure handling modified the symlink target"
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM marker-authentication failure left a retrying daemon"
if [[ "$rpm_marker_status" -eq 0 ]]; then
  echo "RPM reported marker-authentication scriptlet failure as a warning; runtime remained fenced" >&2
fi
sudo rm /run/gta-claw-state-init/initialization-failed
sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM marker-authentication recovery did not resume the daemon"
if sudo rpm -Uvh --nodeps --oldpackage "$rpm1"; then
  die "RPM package accepted a downgrade"
fi
[[ ! -e /run/gta-claw-daemon.replacement ]] ||
  die "rejected RPM downgrade left a stale replacement marker"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "rejected RPM downgrade disturbed the active service"
install_failure_dropin Service 'ExecStartPre=/bin/false'
if sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"; then
  die "RPM replacement swallowed a package-triggered restart failure"
fi
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM restart failure left the service active"
assert_start_fenced "RPM restart failure"
[[ "$(rpm -q gta-claw | wc -l)" -gt 1 ]] ||
  die "RPM restart failure did not exercise the multi-instance guard"
if sudo rpm -Uvh --nodeps --oldpackage "$rpm1"; then
  die "RPM multi-instance state accepted a downgrade"
fi
remove_failure_dropin
sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"
[[ "$(rpm -q gta-claw | wc -l)" -eq 1 ]] ||
  die "RPM restart recovery left duplicate package instances"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM restart retry did not preserve prior active state"
wait_for_writer_lock
sudo touch "$namespace/state.sqlite-journal"
set +e
sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"
rpm_init_status=$?
set -e
! systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM failed initialization restarted the service"
[[ -e /run/gta-claw-state-init/initialization-failed ]] ||
  die "RPM failed initialization left no durable failure marker"
[[ "$(sudo stat -c '%u:%g:%a' /run/gta-claw-state-init)" == "0:0:755" ]] ||
  die "RPM failure marker directory is not root-owned mode 0755"
[[ "$(sudo stat -c '%u:%g:%a' /run/gta-claw-state-init/initialization-failed)" == \
  "0:0:644" ]] ||
  die "RPM failure marker is not root-owned mode 0644"
assert_start_fenced "RPM initialization failure"
if [[ "$rpm_init_status" -eq 0 ]]; then
  echo "RPM reported failed %post as a warning; runtime remained fenced" >&2
fi
sudo rm "$namespace/state.sqlite-journal"
sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"
[[ "$(rpm -q gta-claw | wc -l)" -eq 1 ]] ||
  die "RPM failed-init recovery left duplicate package instances"
[[ ! -e /run/gta-claw-state-init/initialization-failed ]] ||
  die "RPM recovery did not clear the initialization failure marker"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM init retry did not preserve prior active state"
wait_for_writer_lock
install_failure_dropin Unit 'RefuseManualStop=yes'
if sudo rpm -e --nodeps gta-claw; then
  die "RPM removal swallowed an intentional stop failure"
fi
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "RPM removal unlinked daemon after stop failure"
remove_failure_dropin
sudo systemctl disable gta-claw-daemon.service
sudo systemctl enable --runtime gta-claw-daemon.service
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled-runtime" ]] ||
  die "RPM runtime-only enablement fixture was not established"
install_initializer_stop_denial
if sudo rpm -e --nodeps gta-claw; then
  die "RPM removal ignored a late initializer-stop failure"
fi
systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM late removal failure did not restore the active daemon"
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "enabled-runtime" ]] ||
  die "RPM late removal failure changed runtime-only enablement"
[[ -e /usr/libexec/gta-claw/gta-claw-daemon ]] ||
  die "RPM late removal failure unlinked the daemon"
remove_initializer_stop_denial
sudo systemctl enable gta-claw-daemon.service
install_initializer_stop_denial
if sudo rpm -e --nodeps gta-claw; then
  die "RPM dual-enable removal ignored a late initializer-stop failure"
fi
[[ -L /etc/systemd/system/multi-user.target.wants/gta-claw-daemon.service &&
  -L /run/systemd/system/multi-user.target.wants/gta-claw-daemon.service ]] ||
  die "RPM rollback did not restore both enablement links"
remove_initializer_stop_denial
for remove_marker in \
  /run/gta-claw-daemon.remove-was-active \
  /run/gta-claw-daemon.remove-was-enabled \
  /run/gta-claw-daemon.remove-was-enabled-runtime \
  /run/gta-claw-state-init/remove-was-active \
  /run/gta-claw-state-init/remove-prepared \
  /run/gta-claw-state-init/remove-was-package-fenced; do
  [[ ! -e "$remove_marker" && ! -L "$remove_marker" ]] ||
    die "failed RPM erase left stale removal intent: $remove_marker"
done
sudo systemctl disable gta-claw-daemon.service
sudo systemctl disable --runtime gta-claw-daemon.service
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "disabled" ]] ||
  die "RPM failed-erase administrator change did not take effect"
sudo rpm -Uvh --nodeps --replacepkgs "$rpm2"
systemctl is-active --quiet gta-claw-daemon.service ||
  die "RPM recovery after failed erase did not preserve active state"
[[ "$(systemctl is-enabled gta-claw-daemon.service)" == "disabled" ]] ||
  die "stale RPM removal intent overrode an administrator enablement change"
rpm_snapshot="$(state_identity_snapshot)"
sudo sh "$SCRIPT_DIR/rpm/preun" 0
[[ -e /run/gta-claw-state-init/remove-prepared ]] ||
  die "RPM interrupted-removal fixture did not retain its journal"
sudo rpm -e --nodeps gta-claw
assert_identity_preserved "$rpm_snapshot"
[[ "$(id -u gta-claw):$(id -g gta-claw)" == "$static_identity" ]] ||
  die "RPM removal changed the static service identity"
reset_test_namespace

sudo rpm -ivh --nodeps "$rpm1"
assert_disabled_and_inactive
rpm_inactive_upgrade_snapshot="$(state_snapshot)"
sudo rpm -Uvh --nodeps "$rpm2"
assert_disabled_and_inactive
assert_preserved "$rpm_inactive_upgrade_snapshot"
rpm_inactive_snapshot="$(state_snapshot)"
sudo rm -rf /run/gta-claw-state-init
sudo rpm -e --nodeps gta-claw
assert_preserved "$rpm_inactive_snapshot"
sudo rpm -ivh --nodeps "$rpm2"
assert_disabled_and_inactive
assert_preserved "$rpm_inactive_snapshot"
establish_package_runtime_fence
install_initializer_stop_denial
if sudo rpm -e --nodeps gta-claw; then
  die "RPM package-fenced removal ignored a late initializer-stop failure"
fi
case "$(systemctl is-enabled gta-claw-daemon.service 2>/dev/null || true)" in
  masked | masked-runtime) ;;
  *) die "RPM package-fenced rollback removed the runtime mask" ;;
esac
[[ -e /run/gta-claw-state-init/initialization-failed &&
  -e /run/gta-claw-state-init/replacement-fenced ]] ||
  die "RPM package-fenced rollback lost its authenticated markers"
remove_initializer_stop_denial
sudo rpm -e --nodeps gta-claw
[[ ! -e /run/gta-claw-state-init/initialization-failed &&
  ! -e /run/gta-claw-state-init/replacement-fenced ]] ||
  die "RPM removal did not clear deferred package-fence markers"
assert_preserved "$rpm_inactive_snapshot"
reset_test_namespace
reset_test_identity

trap - EXIT INT TERM
rm -rf "$direct_root"
echo "Tar, Debian, and RPM LinuxProtected lifecycle tests passed"
