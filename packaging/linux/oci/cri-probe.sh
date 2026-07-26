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
for tool in crictl find jq python3 stat; do
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
state_token=
log_token=
config_token=
state_creation_output=
log_creation_output=
config_creation_output=
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

create_owned_directory() {
  local parent="$1"
  python3 - "$parent" <<'PY'
import os
import secrets
import stat
import sys

parent = sys.argv[1]
fault = os.environ.get("GTA_CLAW_CRI_TEST_FAIL_DIRECTORY_STEP", "")
flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
parent_fd = os.open(parent, flags)
try:
    parent_stat = os.fstat(parent_fd)
    if (
        parent_stat.st_uid != 0
        or parent_stat.st_gid != 0
        or stat.S_IMODE(parent_stat.st_mode) != 0o755
    ):
        raise SystemExit("CRI parent identity changed during directory creation")
    for _ in range(128):
        name = f"probe.{secrets.token_hex(16)}"
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        child_fd = None
        success = False
        try:
            if fault == "after-mkdir":
                raise OSError("injected failure after CRI directory creation")
            child_fd = os.open(name, flags, dir_fd=parent_fd)
            child_stat = os.fstat(child_fd)
            if (
                child_stat.st_uid != 0
                or child_stat.st_gid != 0
                or stat.S_IMODE(child_stat.st_mode) != 0o700
            ):
                raise SystemExit("CRI invocation directory metadata is invalid")
            token = secrets.token_hex(32)
            token_fd = os.open(
                ".gta-claw-probe-owner",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=child_fd,
            )
            try:
                if fault == "after-token-create":
                    raise OSError("injected failure after CRI token creation")
                os.write(token_fd, f"{token}\n".encode("ascii"))
                if fault == "after-token-write":
                    raise OSError("injected failure after CRI token write")
                os.fsync(token_fd)
            finally:
                os.close(token_fd)
            print(os.path.join(parent, name), flush=True)
            print(
                f"{child_stat.st_dev}:{child_stat.st_ino}:"
                f"{child_stat.st_uid}:{child_stat.st_gid}:"
                f"{stat.S_IMODE(child_stat.st_mode):o}",
                flush=True,
            )
            print(token, flush=True)
            success = True
            break
        finally:
            if not success:
                if child_fd is not None:
                    try:
                        os.unlink(".gta-claw-probe-owner", dir_fd=child_fd)
                    except FileNotFoundError:
                        pass
                try:
                    os.rmdir(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            if child_fd is not None:
                os.close(child_fd)
    else:
        raise SystemExit("could not reserve a unique CRI invocation directory")
finally:
    os.close(parent_fd)
PY
}

quarantine_and_remove_directory() {
  local path="$1"
  local receipt="$2"
  local token="$3"
  python3 - "$path" "$receipt" "$token" <<'PY'
import ctypes
import errno
import os
import stat
import sys

path, receipt, token = sys.argv[1:]
parent, name = os.path.split(path)
receipt_parts = receipt.split(":")
expected_device, expected_inode, expected_uid, expected_gid = (
    int(value) for value in receipt_parts[:4]
)
expected_mode = int(receipt_parts[4], 8)
flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
parent_fd = os.open(parent, flags)
quarantine = f".{name}.cleanup.{token}"
libc = ctypes.CDLL(None, use_errno=True)
renameat2 = libc.renameat2
renameat2.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
renameat2.restype = ctypes.c_int
RENAME_NOREPLACE = 1


def rename(source, destination):
    result = renameat2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


renamed = False
child_fd = None
try:
    rename(name, quarantine)
    renamed = True
    child_fd = os.open(quarantine, flags, dir_fd=parent_fd)
    metadata = os.fstat(child_fd)
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )
    expected = (
        expected_device,
        expected_inode,
        expected_uid,
        expected_gid,
        expected_mode,
    )
    owner_metadata = os.stat(
        ".gta-claw-probe-owner",
        dir_fd=child_fd,
        follow_symlinks=False,
    )
    owner_fd = os.open(
        ".gta-claw-probe-owner",
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=child_fd,
    )
    try:
        owner_content = os.read(owner_fd, 256)
    finally:
        os.close(owner_fd)
    stable_metadata = (
        identity[0] == expected[0]
        and identity[2:] == expected[2:]
    )
    if (
        not stable_metadata
        or not stat.S_ISREG(owner_metadata.st_mode)
        or owner_metadata.st_uid != 0
        or owner_metadata.st_gid != 0
        or stat.S_IMODE(owner_metadata.st_mode) != 0o600
        or owner_metadata.st_nlink != 1
        or owner_content != f"{token}\n".encode("ascii")
        or os.listdir(child_fd) != [".gta-claw-probe-owner"]
    ):
        raise OSError(errno.ESTALE, "quarantined CRI directory identity changed")
    os.unlink(".gta-claw-probe-owner", dir_fd=child_fd)
    os.rmdir(quarantine, dir_fd=parent_fd)
    renamed = False
finally:
    if child_fd is not None:
        os.close(child_fd)
    if renamed:
        try:
            rename(quarantine, name)
        except OSError:
            pass
    os.close(parent_fd)
PY
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
  local token="$5"
  local capability="/proc/self/fd/$descriptor"
  local owner_file=".gta-claw-probe-owner"
  if [[ -z "$path" || -z "$receipt" || -z "$descriptor" || -z "$token" ]]; then
    echo "$label cleanup lacks a complete ownership receipt" >&2
    cleanup_failed=1
    return
  fi
  if [[ ! -d "$capability" ||
    "$(directory_receipt "$capability")" != "$receipt" ]]; then
    echo "$label held directory identity changed; refusing cleanup" >&2
    cleanup_failed=1
    return
  fi
  if [[ ! -f "$capability/$owner_file" ||
    -L "$capability/$owner_file" ||
    "$(stat -Lc '%u:%g:%a:%h' "$capability/$owner_file")" != "0:0:600:1" ||
    "$(<"$capability/$owner_file")" != "$token" ||
    ! -f "$path/$owner_file" ||
    -L "$path/$owner_file" ||
    "$(<"$path/$owner_file")" != "$token" ]]; then
    echo "$label ownership token changed; refusing cleanup" >&2
    cleanup_failed=1
    return
  fi
  find "$capability/" \
    -depth \
    -mindepth 1 \
    -xdev \
    ! -path "$capability/$owner_file" \
    -delete ||
    {
      echo "$label held contents could not be removed" >&2
      cleanup_failed=1
      return
    }
  if [[ "$(find "$capability/" -mindepth 1 -maxdepth 1 -printf '%f\n')" != \
    "$owner_file" ]]; then
    echo "$label held directory could not be emptied safely" >&2
    cleanup_failed=1
    return
  fi
  if [[ "$label" == "CRI state" &&
    "${GTA_CLAW_CRI_TEST_REPLACE_EMPTY_STATE:-0}" == "1" ]]; then
    rm -rf "$path"
    mkdir -m 0700 "$path"
  fi
  if ! quarantine_and_remove_directory "$path" "$receipt" "$token"; then
    echo "$label root identity changed or could not be quarantined and removed" >&2
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

recover_unregistered_creation() {
  local output="$1"
  local label="$2"
  local -n root_ref="$3"
  local -n receipt_ref="$4"
  local -n token_ref="$5"
  local -n descriptor_ref="$6"
  local -n created_ref="$7"
  local -a recovered
  local opened_fd
  [[ -n "$output" ]] || return 0
  if [[ "$created_ref" -eq 1 && -n "$descriptor_ref" ]]; then
    return 0
  fi
  mapfile -t recovered <<<"$output"
  if [[ "${#recovered[@]}" -ne 3 ]]; then
    echo "$label creation receipt is incomplete during cleanup" >&2
    cleanup_failed=1
    return 0
  fi
  root_ref="${recovered[0]}"
  receipt_ref="${recovered[1]}"
  # shellcheck disable=SC2034 # Assigned through a nameref for cleanup.
  token_ref="${recovered[2]}"
  created_ref=1
  if [[ -z "$descriptor_ref" ]]; then
    if ! exec {opened_fd}<"$root_ref"; then
      echo "$label directory could not be reopened during cleanup" >&2
      cleanup_failed=1
      return 0
    fi
    descriptor_ref="$opened_fd"
  fi
  if [[ "$(directory_receipt "/proc/self/fd/$descriptor_ref")" != "$receipt_ref" ||
    "$(directory_receipt "$root_ref")" != "$receipt_ref" ]]; then
    echo "$label directory changed before cleanup registration" >&2
    cleanup_failed=1
  fi
}

cleanup() {
  local original_status="${1:-$?}"
  trap - EXIT INT TERM
  recover_unregistered_creation \
    "$state_creation_output" \
    "CRI state" \
    state_root \
    state_receipt \
    state_token \
    state_fd \
    state_created
  recover_unregistered_creation \
    "$log_creation_output" \
    "CRI log" \
    log_root \
    log_receipt \
    log_token \
    log_fd \
    log_created
  recover_unregistered_creation \
    "$config_creation_output" \
    "CRI config" \
    config_root \
    config_receipt \
    config_token \
    config_fd \
    config_created
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
    remove_owned_directory \
      "$config_root" "$config_receipt" "CRI config" "$config_fd" "$config_token"
  [[ "$log_created" -eq 0 ]] ||
    remove_owned_directory \
      "$log_root" "$log_receipt" "CRI log" "$log_fd" "$log_token"
  [[ "$state_created" -eq 0 ]] ||
    remove_owned_directory \
      "$state_root" "$state_receipt" "CRI state" "$state_fd" "$state_token"
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
trap 'cleanup "$?"' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

ensure_parent "$state_parent" "CRI state"
ensure_parent "$log_parent" "CRI log"
ensure_parent "$config_parent" "CRI config"
state_creation_output="$(create_owned_directory "$state_parent")" ||
  {
    echo "CRI state directory could not be created safely" >&2
    exit 1
  }
if [[ "${GTA_CLAW_CRI_TEST_SIGNAL_AFTER_CREATION:-}" == "state" ]]; then
  kill -TERM "$$"
fi
mapfile -t state_creation <<<"$state_creation_output"
[[ "${#state_creation[@]}" -eq 3 ]]
state_root="${state_creation[0]}"
state_receipt="${state_creation[1]}"
state_token="${state_creation[2]}"
state_created=1
exec {state_fd}<"$state_root"
[[ "$(directory_receipt "/proc/self/fd/$state_fd")" == "$state_receipt" ]]
[[ "$(directory_receipt "$state_root")" == "$state_receipt" ]]
if [[ "${GTA_CLAW_CRI_TEST_FAIL_AFTER_STATE:-0}" == "1" ]]; then
  exit 1
fi
log_creation_output="$(create_owned_directory "$log_parent")" ||
  {
    echo "CRI log directory could not be created safely" >&2
    exit 1
  }
if [[ "${GTA_CLAW_CRI_TEST_SIGNAL_AFTER_CREATION:-}" == "log" ]]; then
  kill -TERM "$$"
fi
mapfile -t log_creation <<<"$log_creation_output"
[[ "${#log_creation[@]}" -eq 3 ]]
log_root="${log_creation[0]}"
log_receipt="${log_creation[1]}"
log_token="${log_creation[2]}"
log_created=1
exec {log_fd}<"$log_root"
[[ "$(directory_receipt "/proc/self/fd/$log_fd")" == "$log_receipt" ]]
[[ "$(directory_receipt "$log_root")" == "$log_receipt" ]]
config_creation_output="$(create_owned_directory "$config_parent")" ||
  {
    echo "CRI config directory could not be created safely" >&2
    exit 1
  }
if [[ "${GTA_CLAW_CRI_TEST_SIGNAL_AFTER_CREATION:-}" == "config" ]]; then
  kill -TERM "$$"
fi
mapfile -t config_creation <<<"$config_creation_output"
[[ "${#config_creation[@]}" -eq 3 ]]
config_root="${config_creation[0]}"
config_receipt="${config_creation[1]}"
config_token="${config_creation[2]}"
config_created=1
exec {config_fd}<"$config_root"
[[ "$(directory_receipt "/proc/self/fd/$config_fd")" == "$config_receipt" ]]
[[ "$(directory_receipt "$config_root")" == "$config_receipt" ]]

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
case "${GTA_CLAW_CRI_TEST_SIGNAL_AFTER_CONFIG:-}" in
  HUP | INT | TERM) kill "-${GTA_CLAW_CRI_TEST_SIGNAL_AFTER_CONFIG}" "$$" ;;
  '') ;;
  *) {
    echo "invalid CRI signal test fixture" >&2
    exit 2
  } ;;
esac

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
