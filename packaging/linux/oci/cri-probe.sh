#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

[[ "$#" -eq 3 ]] ||
  {
    echo "usage: cri-probe.sh SANDBOX_JSON INIT_JSON RUNTIME_JSON" >&2
    exit 2
  }
: "${CRI_RUNTIME_ENDPOINT:?CRI_RUNTIME_ENDPOINT must name an explicit CRI socket}"
[[ "$CRI_RUNTIME_ENDPOINT" == unix:///* ]] ||
  {
    echo "CRI_RUNTIME_ENDPOINT must be a fully qualified unix socket" >&2
    exit 2
  }
for tool in crictl find jq stat; do
  command -v "$tool" >/dev/null 2>&1 ||
    {
      echo "missing CRI probe tool: $tool" >&2
      exit 2
    }
done
[[ "$(id -u)" -eq 0 && "$(id -ru)" -eq 0 ]] ||
  {
    echo "CRI credential probe requires real and effective UID 0" >&2
    exit 2
  }

source_sandbox_config="$1"
source_init_config="$2"
source_runtime_config="$3"
state_parent="${CRI_STATE_PARENT:-/var/lib/gta-claw-cri-probes}"
log_parent="${CRI_LOG_PARENT:-/var/log/gta-claw-cri-probes}"
config_parent="${CRI_CONFIG_PARENT:-/run/gta-claw-cri-probes}"
state_root=
log_root=
config_root=
state_receipt=
log_receipt=
config_receipt=
state_fd=
log_fd=
config_fd=
state_created=0
log_created=0
config_created=0
sandbox_id=
init_id=
runtime_id=
cleanup_failed=0

directory_receipt() {
  stat -Lc '%d:%i:%u:%g:%a' "$1"
}

ensure_parent() {
  local path="$1"
  local label="$2"
  if [[ -L "$path" || (-e "$path" && ! -d "$path") ]]; then
    echo "$label parent is not a physical directory" >&2
    return 1
  fi
  if [[ ! -e "$path" ]]; then
    install -d -o root -g root -m 0755 "$path"
  fi
  [[ "$(stat -Lc '%u:%g:%a' "$path")" == "0:0:755" ]] ||
    {
      echo "$label parent must be root:root mode 0755" >&2
      return 1
    }
}

remove_owned_directory() {
  local path="$1"
  local receipt="$2"
  local label="$3"
  local descriptor="$4"
  local capability="/proc/self/fd/$descriptor"
  [[ -n "$path" && -n "$receipt" && -n "$descriptor" ]] || return
  if [[ ! -d "$capability" ||
    "$(directory_receipt "$capability")" != "$receipt" ]]; then
    echo "$label held directory identity changed; refusing cleanup" >&2
    cleanup_failed=1
    return
  fi
  find "$capability/" -depth -mindepth 1 -xdev -delete ||
    {
      echo "$label held contents could not be removed" >&2
      cleanup_failed=1
      return
    }
  if [[ ! -d "$path" || -L "$path" ||
    "$(directory_receipt "$path")" != "$receipt" ]]; then
    echo "$label path identity changed; refusing cleanup: $path" >&2
    cleanup_failed=1
    return
  fi
  if ! rmdir "$path"; then
    echo "$label root identity changed or could not be removed" >&2
    cleanup_failed=1
  fi
}

cri() {
  crictl --runtime-endpoint "$CRI_RUNTIME_ENDPOINT" "$@"
}

wait_for_container_exit() {
  local container_id="$1"
  local attempt=0
  local state
  while ((attempt < 300)); do
    state="$(cri inspect "$container_id" | jq -er '.status.state')"
    if [[ "$state" == "CONTAINER_EXITED" ]]; then
      cri inspect "$container_id" | jq -er '.status.exitCode'
      return
    fi
    [[ "$state" == "CONTAINER_RUNNING" || "$state" == "CONTAINER_CREATED" ]] ||
      {
        echo "CRI container entered unexpected state $state" >&2
        return 1
      }
    sleep 0.1
    ((attempt += 1))
  done
  echo "CRI container did not exit before the probe deadline" >&2
  return 1
}

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  if [[ -n "$runtime_id" ]]; then
    cri rm -f "$runtime_id" >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ -n "$init_id" ]]; then
    cri rm -f "$init_id" >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ -n "$sandbox_id" ]]; then
    cri stopp "$sandbox_id" >/dev/null 2>&1 || cleanup_failed=1
    cri rmp -f "$sandbox_id" >/dev/null 2>&1 || cleanup_failed=1
  fi
  [[ "$config_created" -eq 0 ]] ||
    remove_owned_directory "$config_root" "$config_receipt" "CRI config" "$config_fd"
  [[ "$log_created" -eq 0 ]] ||
    remove_owned_directory "$log_root" "$log_receipt" "CRI log" "$log_fd"
  [[ "$state_created" -eq 0 ]] ||
    remove_owned_directory "$state_root" "$state_receipt" "CRI state" "$state_fd"
  if [[ -n "$config_fd" ]]; then
    exec {config_fd}>&-
  fi
  if [[ -n "$log_fd" ]]; then
    exec {log_fd}>&-
  fi
  if [[ -n "$state_fd" ]]; then
    exec {state_fd}>&-
  fi
  if [[ "$original_status" -eq 0 && "$cleanup_failed" -ne 0 ]]; then
    exit 1
  fi
  exit "$original_status"
}
trap cleanup EXIT INT TERM

ensure_parent "$state_parent" "CRI state"
ensure_parent "$log_parent" "CRI log"
ensure_parent "$config_parent" "CRI config"
state_root="$(mktemp -d "$state_parent/probe.XXXXXXXX")"
chmod 0700 "$state_root"
exec {state_fd}<"$state_root"
state_receipt="$(directory_receipt "/proc/self/fd/$state_fd")"
[[ "$(directory_receipt "$state_root")" == "$state_receipt" ]]
state_created=1
if [[ "${GTA_CLAW_CRI_TEST_FAIL_AFTER_STATE:-0}" == "1" ]]; then
  exit 1
fi
log_root="$(mktemp -d "$log_parent/probe.XXXXXXXX")"
chmod 0700 "$log_root"
exec {log_fd}<"$log_root"
log_receipt="$(directory_receipt "/proc/self/fd/$log_fd")"
[[ "$(directory_receipt "$log_root")" == "$log_receipt" ]]
log_created=1
config_root="$(mktemp -d "$config_parent/probe.XXXXXXXX")"
chmod 0700 "$config_root"
exec {config_fd}<"$config_root"
config_receipt="$(directory_receipt "/proc/self/fd/$config_fd")"
[[ "$(directory_receipt "$config_root")" == "$config_receipt" ]]
config_created=1

if [[ "${GTA_CLAW_CRI_TEST_REPLACE_STATE:-0}" == "1" ]]; then
  rm -rf "$state_root"
  mkdir -m 0700 "$state_root"
  printf 'replacement\n' >"$state_root/replacement"
  exit 1
fi
if [[ "${GTA_CLAW_CRI_TEST_REPLACE_LOG:-0}" == "1" ]]; then
  rm -rf "$log_root"
  mkdir -m 0700 "$log_root"
  printf 'replacement\n' >"$log_root/replacement"
  exit 1
fi
if [[ "${GTA_CLAW_CRI_TEST_REPLACE_CONFIG:-0}" == "1" ]]; then
  rm -rf "$config_root"
  mkdir -m 0700 "$config_root"
  printf 'replacement\n' >"$config_root/replacement"
  exit 1
fi

sandbox_config="$config_root/sandbox.json"
init_config="$config_root/init.json"
runtime_config="$config_root/runtime.json"
jq --arg log_directory "$log_root" \
  '.log_directory = $log_directory' \
  "$source_sandbox_config" >"$sandbox_config"
jq --arg host_path "$state_root" \
  '.mounts[0].host_path = $host_path' \
  "$source_init_config" >"$init_config"
jq --arg host_path "$state_root" \
  '.mounts[0].host_path = $host_path' \
  "$source_runtime_config" >"$runtime_config"
chmod 0600 "$sandbox_config" "$init_config" "$runtime_config"

if [[ "${GTA_CLAW_CRI_TEST_STOP_AFTER_CONFIG:-0}" == "1" ]]; then
  exit 1
fi

image="$(jq -er '.image.image' "$init_config")"
[[ "$(jq -er '.image.image' "$runtime_config")" == "$image" ]] ||
  {
    echo "CRI init and runtime fixtures use different images" >&2
    exit 1
  }
cri pull "$image" >/dev/null
sandbox_id="$(cri runp "$sandbox_config")"
init_id="$(cri create "$sandbox_id" "$init_config" "$sandbox_config")"
cri start "$init_id" >/dev/null
init_exit="$(wait_for_container_exit "$init_id")"
[[ "$init_exit" -eq 0 ]] ||
  {
    echo "CRI initializer exited with status $init_exit" >&2
    exit 1
  }
runtime_id="$(cri create "$sandbox_id" "$runtime_config" "$sandbox_config")"
cri start "$runtime_id" >/dev/null
runtime_exit="$(wait_for_container_exit "$runtime_id")"
[[ "$runtime_exit" -eq 0 ]] ||
  {
    echo "CRI runtime probe exited with status $runtime_exit" >&2
    exit 1
  }

namespace="$state_root/gta-claw-protected"
[[ "$(stat -c '%u:%g:%a' "$namespace")" == "0:65532:750" ]] ||
  {
    echo "CRI probe produced an invalid protected namespace identity" >&2
    exit 1
  }
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
actual_names="$(
  find "$namespace" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort
)"
[[ "$actual_names" == "$expected_names" ]] ||
  {
    echo "CRI probe did not preserve the exact-eight state contract" >&2
    exit 1
  }
while IFS= read -r path; do
  [[ "$(stat -c '%u:%g:%a:%h' "$path")" == "65532:65532:600:1" ]] ||
    {
      echo "CRI probe produced an invalid protected entry: $path" >&2
      exit 1
    }
done < <(find "$namespace" -mindepth 1 -maxdepth 1 -type f -print | LC_ALL=C sort)

echo "CRI root-init and redundant-primary-group runtime probe passed"
