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
for tool in crictl jq stat; do
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

sandbox_config="$1"
init_config="$2"
runtime_config="$3"
state_root=/var/lib/gta-claw-cri-probe
log_root=/var/log/gta-claw-cri-probe
sandbox_id=
init_id=
runtime_id=

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
  if [[ -n "$runtime_id" ]]; then
    cri rm -f "$runtime_id" >/dev/null 2>&1 || true
  fi
  if [[ -n "$init_id" ]]; then
    cri rm -f "$init_id" >/dev/null 2>&1 || true
  fi
  if [[ -n "$sandbox_id" ]]; then
    cri stopp "$sandbox_id" >/dev/null 2>&1 || true
    cri rmp -f "$sandbox_id" >/dev/null 2>&1 || true
  fi
  rm -rf "$state_root" "$log_root"
}
trap cleanup EXIT INT TERM

[[ ! -e "$state_root" && ! -L "$state_root" ]] ||
  {
    echo "CRI probe state path already exists" >&2
    exit 1
  }
install -d -m 0755 "$state_root" "$log_root"
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
