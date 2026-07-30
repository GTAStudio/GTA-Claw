#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: run-candidate-gates.sh TOOL_ROOT CANDIDATE_ROOT EVIDENCE" >&2
  exit 2
fi

readonly tool_root="$1"
readonly candidate_root="$2"
readonly evidence="$3"
readonly rust_toolchain="1.94.0-x86_64-unknown-linux-gnu"
readonly toolchain_bin="$tool_root/rustup-home/toolchains/$rust_toolchain/bin"
readonly cargo_bin="$toolchain_bin/cargo"
readonly rustc_bin="$toolchain_bin/rustc"
readonly deny_bin="$tool_root/cargo-deny/cargo-deny"
readonly audit_bin="$tool_root/cargo-audit/bin/cargo-audit"

[[ -f "$evidence" ]]
if ! /usr/bin/grep -Fq "candidate_final=true" "$evidence"; then
  echo "Candidate retained the exact pre-P04f product state; final graph gates are not applicable."
  exit 0
fi

case "$candidate_root" in
  /home/runner/work/*) ;;
  *)
    echo "candidate root is outside the GitHub workspace" >&2
    exit 2
    ;;
esac

readonly logs="$tool_root/candidate-gate-logs"
/usr/bin/mkdir -p "$logs" "$tool_root/candidate-target"
ulimit -t 180
ulimit -f 16384
ulimit -n 256
ulimit -u 256
ulimit -v 2097152

run_bounded() {
  local name="$1"
  shift
  local output="$logs/$name.log"
  if ! /usr/bin/timeout 180 "$@" >"$output" 2>&1; then
    /usr/bin/tail -c 1048576 "$output" >&2 || true
    return 1
  fi
  if [[ "$(/usr/bin/stat --format=%s "$output")" -gt 8388608 ]]; then
    echo "$name output exceeded 8 MiB" >&2
    return 1
  fi
  /usr/bin/cat "$output"
}

run_bounded audit-root \
  /usr/bin/env -i \
  HOME="$tool_root/home" \
  CARGO_HOME="$tool_root/cargo-home" \
  PATH="/usr/bin:/bin" \
  "$audit_bin" audit --no-fetch --file "$candidate_root/Cargo.lock"

run_bounded audit-desktop \
  /usr/bin/env -i \
  HOME="$tool_root/home" \
  CARGO_HOME="$tool_root/cargo-home" \
  PATH="/usr/bin:/bin" \
  "$audit_bin" audit --no-fetch --file "$candidate_root/desktop/Cargo.lock"

run_deny() {
  local name="$1"
  shift
  run_bounded "$name" \
    /usr/bin/env -i \
    HOME="$tool_root/home" \
    CARGO_HOME="$tool_root/cargo-home" \
    RUSTUP_HOME="$tool_root/rustup-home" \
    CARGO="$cargo_bin" \
    CARGO_TARGET_DIR="$tool_root/candidate-target" \
    PATH="/usr/bin:/bin" \
    RUSTC="$rustc_bin" \
    "$deny_bin" "$@"
}

run_deny deny-root \
  --manifest-path "$candidate_root/Cargo.toml" \
  --config "$candidate_root/deny.toml" --locked --all-features \
  check advisories bans licenses sources

for target in \
  x86_64-pc-windows-msvc \
  aarch64-pc-windows-msvc \
  x86_64-apple-darwin \
  aarch64-apple-darwin; do
  run_deny "deny-desktop-$target" \
    --manifest-path "$candidate_root/desktop/Cargo.toml" \
    --config "$candidate_root/desktop/deny.toml" \
    --locked --target "$target" check \
    --warn unmaintained advisories bans licenses sources
done
