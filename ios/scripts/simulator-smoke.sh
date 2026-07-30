#!/usr/bin/env bash
set -euo pipefail

select_runtime_and_device() {
  jq -r '
    [
      .runtimes[] |
      select(.isAvailable != false and (.name | startswith("iOS ")))
    ] |
    last |
    . as $runtime |
    [
      ($runtime.identifier // ""),
      ([
        $runtime.supportedDeviceTypes[]? |
        select(.productFamily == "iPhone")
      ] | last | .identifier // "")
    ] |
    @tsv
  '
}

if [[ "${1:-}" == "--select-runtime-device" ]]; then
  command -v jq >/dev/null || {
    echo "jq is required to select an iOS simulator runtime" >&2
    exit 1
  }
  select_runtime_and_device
  exit 0
fi

app="${1:?usage: simulator-smoke.sh <GTA Claw.app>}"
required="${MOBILE_SMOKE_REQUIRED:-0}"
bundle_id="com.gtastudio.gtaclaw"

if [[ "$required" != "0" && "$required" != "1" ]]; then
  echo "MOBILE_SMOKE_REQUIRED must be 0 or 1" >&2
  exit 1
fi

unavailable() {
  local reason="$1"
  if [[ "$required" == "1" ]]; then
    echo "iOS simulator smoke is required but unavailable: $reason" >&2
    exit 1
  fi
  echo "SKIP(ios-simulator): $reason"
  exit 0
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  unavailable "this gate is supported on macOS runners"
fi
if [[ ! -d "$app" || ! -x "$app/GTA Claw" ]]; then
  echo "iOS simulator app is incomplete: $app" >&2
  exit 1
fi
command -v xcrun >/dev/null || unavailable "xcrun is not installed"
command -v jq >/dev/null || unavailable "jq is not installed"

actual_bundle_id="$(plutil -extract CFBundleIdentifier raw -o - "$app/Info.plist")"
if [[ "$actual_bundle_id" != "$bundle_id" ]]; then
  echo "Unexpected iOS bundle identifier: $actual_bundle_id" >&2
  exit 1
fi

run_with_timeout() {
  local seconds="$1"
  shift
  local marker
  marker="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gta-claw-timeout.XXXXXX")"
  rm -f "$marker"
  "$@" &
  local command_pid=$!
  (
    sleep "$seconds"
    if kill -0 "$command_pid" 2>/dev/null; then
      : >"$marker"
      kill -TERM "$command_pid" 2>/dev/null || true
      sleep 2
      kill -KILL "$command_pid" 2>/dev/null || true
    fi
  ) &
  local watchdog_pid=$!
  local status=0
  wait "$command_pid" || status=$?
  kill "$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  if [[ -e "$marker" ]]; then
    rm -f "$marker"
    echo "Command timed out after ${seconds}s: $*" >&2
    return 124
  fi
  rm -f "$marker"
  return "$status"
}

architectures="$(run_with_timeout 15 xcrun lipo -archs "$app/GTA Claw")"
if [[ "$architectures" != "arm64" ]]; then
  echo "iOS simulator app must contain only arm64, got: $architectures" >&2
  exit 1
fi

runtime_json="$(run_with_timeout 30 xcrun simctl list runtimes available --json)"
runtime_and_device="$(
  printf '%s\n' "$runtime_json" |
    select_runtime_and_device
)"
IFS=$'\t' read -r runtime device_type <<<"$runtime_and_device"
[[ -n "$runtime" ]] || unavailable "no available iOS simulator runtime is installed"
[[ -n "$device_type" ]] ||
  unavailable "selected iOS runtime has no supported iPhone device type"

udid="$(
  run_with_timeout 30 xcrun simctl create \
    "GTA Claw CI ${GITHUB_RUN_ID:-local}-$RANDOM" \
    "$device_type" \
    "$runtime"
)"
if [[ -z "$udid" ]]; then
  echo "simctl did not return a simulator UDID" >&2
  exit 1
fi

cleanup() {
  run_with_timeout 15 xcrun simctl shutdown "$udid" >/dev/null 2>&1 || true
  run_with_timeout 15 xcrun simctl delete "$udid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

run_with_timeout 180 xcrun simctl bootstatus "$udid" -b
run_with_timeout 60 xcrun simctl install "$udid" "$app"
launch="$(run_with_timeout 30 xcrun simctl launch "$udid" "$bundle_id")"
pid="${launch##*: }"
if [[ "$pid" == "$launch" || ! "$pid" =~ ^[0-9]+$ ]]; then
  echo "simctl launch did not return an application PID: $launch" >&2
  exit 1
fi

deadline=$((SECONDS + 30))
stable_since=$SECONDS
while :; do
  if ! run_with_timeout 5 \
    xcrun simctl spawn "$udid" /bin/kill -0 "$pid" >/dev/null 2>&1; then
    echo "GTA Claw exited during the iOS simulator readiness window" >&2
    exit 1
  fi
  if ((SECONDS - stable_since >= 10)); then
    break
  fi
  if ((SECONDS >= deadline)); then
    echo "GTA Claw did not remain alive for 10 seconds within the readiness window" >&2
    exit 1
  fi
  sleep 1
done

echo "iOS simulator smoke passed for $bundle_id (stable pid $pid)"
