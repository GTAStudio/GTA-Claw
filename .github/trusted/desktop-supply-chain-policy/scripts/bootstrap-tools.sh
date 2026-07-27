#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: bootstrap-tools.sh TOOL_ROOT SOURCE_ROOT RUSTUP_BIN" >&2
  exit 2
fi

readonly tool_root="$1"
readonly source_root="$2"
readonly rustup_bin="$3"
readonly manifest="$source_root/.github/trusted/desktop-supply-chain-policy/Cargo.toml"
readonly deny_config="$source_root/.github/trusted/desktop-supply-chain-policy/deny.toml"
readonly validator_lock="$source_root/.github/trusted/desktop-supply-chain-policy/Cargo.lock"

case "$tool_root" in
  /home/runner/work/_temp/*) ;;
  *)
    echo "tool root is outside the GitHub runner temporary directory" >&2
    exit 2
    ;;
esac
case "$source_root" in
  /home/runner/work/*) ;;
  *)
    echo "source root is outside the GitHub workspace" >&2
    exit 2
    ;;
esac
[[ -x "$rustup_bin" ]]
[[ -f "$manifest" && -f "$deny_config" && -f "$validator_lock" ]]
[[ ! -e "$tool_root" ]]

readonly cargo_sha256="77f14b761b02b47e6747473f556b3bc9f98f7e4525b7c3b8d74898ff816e4636"
readonly rustc_sha256="103b60e1b1339968c1d74202ea1d45686037e82c4ea3e0569de24b18a1e6836a"
readonly actionlint_archive_sha256="023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"
readonly actionlint_binary_sha256="9f7dedb4e23f89f2922073d1a6720405b7b520d4f5832ebb96f0d55a2958886c"
readonly cargo_audit_crate_sha256="700c2b240f7fd330c24b675fe429f73a5b676531fcc6300400b2b67f155ba12a"
readonly cargo_deny_archive_sha256="70e769ae3872e34d45132b17040859175e11401dc12dddb0303e0b8c7d088f3f"
readonly actionlint_version="1.7.7"
readonly cargo_audit_version="0.22.2"
readonly cargo_deny_version="0.19.8"
readonly rust_toolchain="1.94.0-x86_64-unknown-linux-gnu"

/usr/bin/mkdir -p \
  "$tool_root/cargo-home" \
  "$tool_root/home" \
  "$tool_root/rustup-home" \
  "$tool_root/downloads" \
  "$tool_root/src" \
  "$tool_root/work" \
  "$tool_root/logs"

/usr/bin/env -i \
  HOME="$tool_root/home" \
  RUSTUP_HOME="$tool_root/rustup-home" \
  PATH="/usr/bin:/bin" \
  "$rustup_bin" toolchain install 1.94.0 \
  --profile minimal --component clippy --component rustfmt --no-self-update

readonly toolchain_bin="$tool_root/rustup-home/toolchains/$rust_toolchain/bin"
readonly cargo_bin="$toolchain_bin/cargo"
readonly rustc_bin="$toolchain_bin/rustc"
[[ -x "$cargo_bin" && -x "$rustc_bin" ]]
/usr/bin/printf '%s  %s\n' "$cargo_sha256" "$cargo_bin" | /usr/bin/sha256sum --check -
/usr/bin/printf '%s  %s\n' "$rustc_sha256" "$rustc_bin" | /usr/bin/sha256sum --check -
[[ "$("$cargo_bin" --version)" == "cargo 1.94.0 (85eff7c80 2026-01-15)" ]]
[[ "$("$rustc_bin" --version)" == "rustc 1.94.0 (4a4ef493e 2026-03-02)" ]]

readonly actionlint_archive="$tool_root/downloads/actionlint.tar.gz"
/usr/bin/curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  "https://github.com/rhysd/actionlint/releases/download/v${actionlint_version}/actionlint_${actionlint_version}_linux_amd64.tar.gz" \
  --output "$actionlint_archive"
/usr/bin/printf '%s  %s\n' "$actionlint_archive_sha256" "$actionlint_archive" |
  /usr/bin/sha256sum --check -
/usr/bin/mkdir "$tool_root/actionlint"
/usr/bin/tar --extract --gzip --file "$actionlint_archive" \
  --directory "$tool_root/actionlint" actionlint
readonly actionlint_bin="$tool_root/actionlint/actionlint"
/usr/bin/printf '%s  %s\n' "$actionlint_binary_sha256" "$actionlint_bin" |
  /usr/bin/sha256sum --check -
[[ "$("$actionlint_bin" -version | /usr/bin/head -n 1)" == "$actionlint_version" ]]

readonly deny_archive="$tool_root/downloads/cargo-deny.tar.gz"
/usr/bin/curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  "https://github.com/EmbarkStudios/cargo-deny/releases/download/${cargo_deny_version}/cargo-deny-${cargo_deny_version}-x86_64-unknown-linux-musl.tar.gz" \
  --output "$deny_archive"
/usr/bin/printf '%s  %s\n' "$cargo_deny_archive_sha256" "$deny_archive" |
  /usr/bin/sha256sum --check -
/usr/bin/mkdir "$tool_root/cargo-deny"
/usr/bin/tar --extract --gzip --file "$deny_archive" \
  --directory "$tool_root/cargo-deny" --strip-components=1
readonly deny_bin="$tool_root/cargo-deny/cargo-deny"
[[ "$("$deny_bin" --version)" == "cargo-deny ${cargo_deny_version}" ]]

readonly audit_archive="$tool_root/downloads/cargo-audit.crate"
/usr/bin/curl --fail --silent --show-error --location \
  --proto '=https' --tlsv1.2 \
  "https://static.crates.io/crates/cargo-audit/cargo-audit-${cargo_audit_version}.crate" \
  --output "$audit_archive"
/usr/bin/printf '%s  %s\n' "$cargo_audit_crate_sha256" "$audit_archive" |
  /usr/bin/sha256sum --check -
/usr/bin/tar --extract --gzip --file "$audit_archive" --directory "$tool_root/src"
readonly audit_source="$tool_root/src/cargo-audit-${cargo_audit_version}"

run_cargo() {
  local -a extra_environment=()
  if [[ -n "${ACTIONLINT_BIN:-}" ]]; then
    extra_environment+=("ACTIONLINT_BIN=$ACTIONLINT_BIN")
  fi
  if [[ -n "${GIT_BIN:-}" ]]; then
    extra_environment+=("GIT_BIN=$GIT_BIN")
  fi
  /usr/bin/env -i \
    HOME="$tool_root/home" \
    CARGO_HOME="$tool_root/cargo-home" \
    RUSTUP_HOME="$tool_root/rustup-home" \
    CARGO_TARGET_DIR="$tool_root/validator-target" \
    PATH="$toolchain_bin:/usr/bin:/bin" \
    RUSTC="$rustc_bin" \
    "${extra_environment[@]}" \
    "$cargo_bin" "$@"
}

cd "$tool_root/work"
run_cargo install --path "$audit_source" --locked \
  --root "$tool_root/cargo-audit" --force
readonly audit_bin="$tool_root/cargo-audit/bin/cargo-audit"
[[ "$("$audit_bin" audit --version)" == "cargo-audit-audit ${cargo_audit_version}" ]]

run_cargo fmt --manifest-path "$manifest" --all -- --check
run_cargo check --manifest-path "$manifest" --locked --all-targets
run_cargo clippy --manifest-path "$manifest" --locked --all-targets -- -D warnings
ACTIONLINT_BIN="$actionlint_bin" \
  GIT_BIN="/usr/bin/git" \
  run_cargo test --manifest-path "$manifest" --locked --all-targets
run_cargo build --manifest-path "$manifest" --locked --release

readonly metadata_json="$tool_root/validator-metadata.json"
run_cargo metadata --manifest-path "$manifest" --locked --format-version 1 >"$metadata_json"
/usr/bin/python3 - "$metadata_json" <<'PY'
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
allowed = {
    ("libc", "0.2.186", "custom-build"),
    ("proc-macro2", "1.0.107", "custom-build"),
    ("quote", "1.0.47", "custom-build"),
    ("serde", "1.0.229", "custom-build"),
    ("serde_core", "1.0.229", "custom-build"),
    ("serde_derive", "1.0.229", "proc-macro"),
    ("serde_json", "1.0.151", "custom-build"),
    ("zmij", "1.0.23", "custom-build"),
}
actual = {
    (package["name"], package["version"], kind)
    for package in metadata["packages"]
    for target in package["targets"]
    for kind in target["kind"]
    if kind in {"custom-build", "proc-macro"}
}
assert actual == allowed, f"validator build/proc target allow-list changed: {actual!r}"
for package in metadata["packages"]:
    if package["name"] == "desktop-supply-chain-policy":
        assert package["source"] is None
    else:
        assert package["source"] == "registry+https://github.com/rust-lang/crates.io-index"
PY

/usr/bin/env -i \
  HOME="$tool_root/home" \
  CARGO_HOME="$tool_root/cargo-home" \
  RUSTUP_HOME="$tool_root/rustup-home" \
  CARGO="$cargo_bin" \
  CARGO_TARGET_DIR="$tool_root/deny-target" \
  PATH="/usr/bin:/bin" \
  RUSTC="$rustc_bin" \
  /usr/bin/timeout 180 "$deny_bin" \
  --manifest-path "$manifest" --locked --all-features \
  check --config "$deny_config" advisories bans licenses sources

/usr/bin/env -i \
  HOME="$tool_root/home" \
  CARGO_HOME="$tool_root/cargo-home" \
  PATH="/usr/bin:/bin" \
  /usr/bin/timeout 180 "$audit_bin" audit --file "$validator_lock"

[[ -x "$tool_root/validator-target/release/desktop-supply-chain-policy" ]]
