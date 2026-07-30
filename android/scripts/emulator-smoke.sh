#!/usr/bin/env bash
set -euo pipefail

apk="${1:?usage: emulator-smoke.sh <apk>}"
required="${MOBILE_SMOKE_REQUIRED:-0}"
avd_name="${ANDROID_AVD_NAME:-gta-claw-ci}"
serial="${ANDROID_EMULATOR_SERIAL:-emulator-5554}"
package_name="com.gtastudio.gtaclaw"

if [[ "$required" != "0" && "$required" != "1" ]]; then
  echo "MOBILE_SMOKE_REQUIRED must be 0 or 1" >&2
  exit 1
fi

unavailable() {
  local reason="$1"
  if [[ "$required" == "1" ]]; then
    echo "Android emulator smoke is required but unavailable: $reason" >&2
    exit 1
  fi
  echo "SKIP(android-emulator): $reason"
  exit 0
}

if [[ "$(uname -s)" != "Linux" ]]; then
  unavailable "this gate is supported on Linux runners"
fi
if [[ ! -f "$apk" ]]; then
  echo "Android emulator smoke APK does not exist: $apk" >&2
  exit 1
fi

adb="${ANDROID_HOME:-}/platform-tools/adb"
emulator="${ANDROID_HOME:-}/emulator/emulator"
[[ -x "$adb" ]] || unavailable "adb is not installed under ANDROID_HOME"
[[ -x "$emulator" ]] || unavailable "the Android emulator is not installed under ANDROID_HOME"
available_avds="$("$emulator" -list-avds)" ||
  unavailable "the Android emulator could not list installed AVDs"
if ! grep -Fqx "$avd_name" <<<"$available_avds"; then
  unavailable "AVD $avd_name is not installed"
fi
if [[ ! "$serial" =~ ^emulator-([0-9]+)$ ]]; then
  echo "ANDROID_EMULATOR_SERIAL must use the emulator-PORT form: $serial" >&2
  exit 1
fi
emulator_port="${BASH_REMATCH[1]}"

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

log="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/gta-claw-android-emulator.log"
acceleration=(-accel off)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  acceleration=(-accel on)
fi
"$emulator" \
  -avd "$avd_name" \
  -port "$emulator_port" \
  -no-window \
  -no-audio \
  -no-boot-anim \
  -no-snapshot \
  -wipe-data \
  -gpu swiftshader_indirect \
  "${acceleration[@]}" >"$log" 2>&1 &
emulator_pid=$!

cleanup() {
  run_with_timeout 10 "$adb" -s "$serial" emu kill >/dev/null 2>&1 || true
  if kill -0 "$emulator_pid" 2>/dev/null; then
    kill -TERM "$emulator_pid" 2>/dev/null || true
    sleep 2
    kill -KILL "$emulator_pid" 2>/dev/null || true
  fi
  wait "$emulator_pid" 2>/dev/null || true
}
trap cleanup EXIT

deadline=$((SECONDS + 240))
until [[ "$(
  run_with_timeout 10 "$adb" -s "$serial" get-state 2>/dev/null || true
)" == "device" ]]; do
  if ! kill -0 "$emulator_pid" 2>/dev/null; then
    echo "Android emulator exited before becoming reachable" >&2
    tail -n 100 "$log" >&2 || true
    exit 1
  fi
  if ((SECONDS >= deadline)); then
    echo "Android emulator was not reachable within 240 seconds" >&2
    tail -n 100 "$log" >&2 || true
    exit 1
  fi
  sleep 2
done

until [[ "$(
  run_with_timeout 10 "$adb" -s "$serial" shell getprop sys.boot_completed \
    2>/dev/null |
    tr -d '\r' ||
    true
)" == "1" ]]; do
  if ((SECONDS >= deadline)); then
    echo "Android emulator did not finish booting within 240 seconds" >&2
    tail -n 100 "$log" >&2 || true
    exit 1
  fi
  sleep 2
done

run_with_timeout 60 "$adb" -s "$serial" install -r "$apk"
component="$(
  run_with_timeout 20 "$adb" -s "$serial" shell \
    cmd package resolve-activity --brief \
    -a android.intent.action.MAIN \
    -c android.intent.category.LAUNCHER \
    "$package_name" |
    tr -d '\r' |
    tail -n 1
)"
if [[ "$component" != "$package_name/"* ]]; then
  echo "Unable to resolve the GTA Claw launch activity: $component" >&2
  exit 1
fi
launch="$(
  run_with_timeout 30 "$adb" -s "$serial" shell am start -W -n "$component"
)"
if [[ "$launch" != *"Status: ok"* ]]; then
  echo "Android activity launch did not report success:" >&2
  printf '%s\n' "$launch" >&2
  exit 1
fi

deadline=$((SECONDS + 30))
stable_since=0
stable_pid=""
while :; do
  current_pid="$(
    run_with_timeout 5 "$adb" -s "$serial" shell pidof "$package_name" \
      2>/dev/null |
      tr -d '\r' ||
      true
  )"
  resumed="$(
    run_with_timeout 5 "$adb" -s "$serial" shell dumpsys activity activities \
      2>/dev/null |
      tr -d '\r' |
      awk '/mResumedActivity|topResumedActivity/ { print; exit }' ||
      true
  )"
  if [[ -n "$current_pid" && "$resumed" == *"$component"* ]]; then
    if [[ -z "$stable_pid" ]]; then
      stable_pid="$current_pid"
      stable_since=$SECONDS
    elif [[ "$current_pid" != "$stable_pid" ]]; then
      echo "GTA Claw process changed during the resumed Activity stability window" >&2
      exit 1
    elif ((SECONDS - stable_since >= 10)); then
      break
    fi
  elif [[ -n "$stable_pid" ]]; then
    echo "Expected Activity stopped being resumed/top during the stability window: $component" >&2
    printf 'Observed resumed Activity: %s\n' "$resumed" >&2
    exit 1
  else
    stable_pid=""
    stable_since=0
  fi
  if ((SECONDS >= deadline)); then
    echo "GTA Claw did not remain resumed/top for 10 seconds within the readiness window" >&2
    run_with_timeout 10 "$adb" -s "$serial" logcat -d -t 200 >&2 || true
    exit 1
  fi
  sleep 1
done

echo "Android emulator smoke passed for resumed Activity $component (stable pid $stable_pid)"
