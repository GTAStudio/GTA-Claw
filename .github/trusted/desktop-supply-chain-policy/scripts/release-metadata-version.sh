#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 6 ]]; then
  echo "usage: release-metadata-version.sh CARGO RUSTC REPOSITORY ISOLATION TAG_VERSION REQUESTED_VERSION" >&2
  exit 2
fi

readonly cargo_bin="$1"
readonly rustc_bin="$2"
readonly repository="$3"
readonly isolation="$4"
readonly tag_version="$5"
readonly requested_version="$6"
readonly jq_bin="/usr/bin/jq"

[[ "$cargo_bin" = /* && -f "$cargo_bin" && ! -L "$cargo_bin" && -x "$cargo_bin" ]]
[[ "$rustc_bin" = /* && -f "$rustc_bin" && ! -L "$rustc_bin" && -x "$rustc_bin" ]]
[[ "$repository" = /* && -d "$repository" && ! -L "$repository" ]]
[[ "$isolation" = /* && ! -e "$isolation" ]]
[[ -f "$jq_bin" && ! -L "$jq_bin" && -x "$jq_bin" ]]
[[ "$tag_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ -z "$requested_version" || "$requested_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]

/usr/bin/mkdir -p \
  "$isolation/home" \
  "$isolation/cargo-home" \
  "$isolation/rustup-home" \
  "$isolation/root-target" \
  "$isolation/desktop-target" \
  "$isolation/temp" \
  "$isolation/cwd"

run_metadata() {
  local manifest="$1"
  local target="$2"
  local output="$3"
  [[ "$manifest" == "$repository/"* && -f "$manifest" && ! -L "$manifest" ]]
  /usr/bin/env -i \
    HOME="$isolation/home" \
    CARGO_HOME="$isolation/cargo-home" \
    RUSTUP_HOME="$isolation/rustup-home" \
    CARGO_TARGET_DIR="$target" \
    CARGO_NET_OFFLINE=true \
    RUSTC="$rustc_bin" \
    TMPDIR="$isolation/temp" \
    PATH=/usr/bin:/bin \
    LC_ALL=C \
    "$cargo_bin" metadata \
      --locked \
      --offline \
      --no-deps \
      --format-version 1 \
      --manifest-path "$manifest" >"$output"
  [[ "$(/usr/bin/stat --format='%s' "$output")" -le 8388608 ]]
}

workspace_version() {
  # shellcheck disable=SC2016
  "$jq_bin" -er '
    def unique_strings:
      type == "array"
      and all(.[]; type == "string")
      and length == (unique | length);
    if type != "object" then
      error("metadata is not an object")
    elif (.packages | type != "array" or length == 0) then
      error("metadata packages are missing")
    elif (.packages | all(.[];
      type == "object"
      and (.id | type == "string")
      and (.version | type == "string")
      and (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")))) | not then
      error("metadata package identity or version is invalid")
    elif (.workspace_members | unique_strings) | not then
      error("workspace_members is invalid or duplicated")
    elif (.workspace_default_members | unique_strings) | not then
      error("workspace_default_members is invalid or duplicated")
    else
      [.packages[].id] as $ids
      | [.packages[].version] as $versions
      | if ($ids | length) != ($ids | unique | length) then
          error("package IDs are duplicated")
        elif ($ids | sort) != (.workspace_members | sort)
          or ($ids | sort) != (.workspace_default_members | sort) then
          error("workspace package IDs disagree")
        elif ($versions | unique | length) != 1 then
          error("workspace packages do not have one exact version")
        else
          $versions[0]
        end
    end
  ' "$1"
}

readonly root_metadata="$isolation/root-metadata.json"
readonly desktop_metadata="$isolation/desktop-metadata.json"
cd "$isolation/cwd"
run_metadata "$repository/Cargo.toml" "$isolation/root-target" "$root_metadata"
run_metadata "$repository/desktop/Cargo.toml" "$isolation/desktop-target" "$desktop_metadata"

root_version="$(workspace_version "$root_metadata")"
desktop_version="$(workspace_version "$desktop_metadata")"
readonly root_version desktop_version
[[ "$root_version" == "$desktop_version" ]]
[[ "$root_version" == "$tag_version" ]]
[[ -z "$requested_version" || "$root_version" == "$requested_version" ]]
printf '%s\n' "$root_version"
