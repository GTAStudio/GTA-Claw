#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
: "${TMPDIR:?TMPDIR is required}"
work="$(mktemp -d "$TMPDIR/gta-claw-cri-cleanup.XXXXXXXX")"
cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
mkdir -m 0755 "$work/state" "$work/log" "$work/config"
mkdir -m 0700 "$work/state/pre-existing" "$work/log/pre-existing"
printf 'state sentinel\n' >"$work/state/pre-existing/sentinel"
printf 'log sentinel\n' >"$work/log/pre-existing/sentinel"
mkdir -m 0700 "$work/bin"
cat >"$work/bin/crictl" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod 0755 "$work/bin/crictl"

run_probe_failure() {
  if env \
    PATH="$work/bin:$PATH" \
    CRI_RUNTIME_ENDPOINT=unix:///run/nonexistent-cri.sock \
    CRI_STATE_PARENT="$work/state" \
    CRI_LOG_PARENT="$work/log" \
    CRI_CONFIG_PARENT="$work/config" \
    "$@" \
    "$SCRIPT_DIR/oci/cri-probe.sh" \
    "$SCRIPT_DIR/oci/cri-sandbox.json" \
    "$work/init.json" \
    "$work/runtime.json" \
    >/dev/null 2>&1; then
    echo "CRI cleanup failure fixture unexpectedly succeeded" >&2
    return 1
  fi
}

sed 's|@OCI_IMAGE_REFERENCE@|example.invalid/gta-claw@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|g' \
  "$SCRIPT_DIR/oci/cri-init.json.in" >"$work/init.json"
sed 's|@OCI_IMAGE_REFERENCE@|example.invalid/gta-claw@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|g' \
  "$SCRIPT_DIR/oci/cri-runtime.json.in" >"$work/runtime.json"

run_probe_failure GTA_CLAW_CRI_TEST_FAIL_AFTER_STATE=1
[[ "$(find "$work/state" -mindepth 1 -maxdepth 1 -printf '%f\n')" == "pre-existing" ]] ||
  {
    echo "partial CRI state creation was not cleaned exactly" >&2
    exit 1
  }
run_probe_failure GTA_CLAW_CRI_TEST_STOP_AFTER_CONFIG=1
[[ "$(find "$work/state" -mindepth 1 -maxdepth 1 -printf '%f\n')" == "pre-existing" &&
  "$(find "$work/log" -mindepth 1 -maxdepth 1 -printf '%f\n')" == "pre-existing" &&
  -z "$(find "$work/config" -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
  {
    echo "CRI invocation-owned paths were not cleaned after config creation" >&2
    exit 1
  }
run_probe_failure GTA_CLAW_CRI_TEST_REPLACE_STATE=1
state_replacement="$(
  find "$work/state" -mindepth 2 -maxdepth 2 -name replacement -print -quit
)"
[[ -n "$state_replacement" && -f "$state_replacement" ]] ||
  {
    echo "CRI cleanup removed a raced replacement directory" >&2
    exit 1
  }
run_probe_failure GTA_CLAW_CRI_TEST_REPLACE_LOG=1
log_replacement="$(
  find "$work/log" -mindepth 2 -maxdepth 2 -name replacement -print -quit
)"
[[ -n "$log_replacement" && -f "$log_replacement" ]] ||
  {
    echo "CRI cleanup removed a raced log replacement directory" >&2
    exit 1
  }
run_probe_failure GTA_CLAW_CRI_TEST_REPLACE_CONFIG=1
config_replacement="$(
  find "$work/config" -mindepth 2 -maxdepth 2 -name replacement -print -quit
)"
[[ -n "$config_replacement" && -f "$config_replacement" ]] ||
  {
    echo "CRI cleanup removed a raced config replacement directory" >&2
    exit 1
  }
[[ "$(cat "$work/state/pre-existing/sentinel")" == "state sentinel" &&
  "$(cat "$work/log/pre-existing/sentinel")" == "log sentinel" ]] ||
  {
    echo "CRI cleanup modified pre-existing paths" >&2
    exit 1
  }

echo "CRI invocation-owned cleanup self-tests passed"
