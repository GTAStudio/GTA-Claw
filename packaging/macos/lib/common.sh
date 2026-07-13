#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

MACOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO_ROOT="$(cd "$MACOS_DIR/../.." && pwd -P)"
: "${OUTPUT_ROOT:=$REPO_ROOT/target/macos-package}"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

note() {
  printf '==> %s\n' "$*"
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

require_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || die "this operation requires macOS"
}

validate_bundle_id() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)+$ ]] ||
    die "invalid bundle identifier: $1"
  [[ "${#1}" -le 255 ]] || die "bundle identifier exceeds 255 characters"
}

validate_release_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be numeric X.Y.Z: $1"
  [[ "${#1}" -le 18 ]] || die "release version exceeds 18 characters"
}

validate_build_version() {
  [[ "$1" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] ||
    die "build version must contain one to three numeric components: $1"
  [[ "${#1}" -le 18 ]] || die "build version exceeds 18 characters"
}

validate_macos_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+$ ]] || die "invalid macOS deployment target: $1"
  awk -v version="$1" 'BEGIN {
    split(version, part, ".")
    if (part[1] < 14) exit 1
  }' || die "minimum macOS version must be 14.0 or newer: $1"
}

assert_output_root() {
  [[ "$OUTPUT_ROOT" == /* ]] || die "OUTPUT_ROOT must be absolute: $OUTPUT_ROOT"
  [[ "$OUTPUT_ROOT" != *$'\n'* ]] || die "OUTPUT_ROOT contains a newline"
  [[ "$OUTPUT_ROOT" != *"/../"* && "$OUTPUT_ROOT" != */.. ]] ||
    die "OUTPUT_ROOT must not contain parent traversal"
  case "$OUTPUT_ROOT/" in
    "$REPO_ROOT/target/"*) ;;
    *) die "OUTPUT_ROOT must remain below $REPO_ROOT/target" ;;
  esac
  if [[ -L "$REPO_ROOT/target" ]]; then
    die "repository target directory must not be a symlink"
  fi
  if [[ -e "$OUTPUT_ROOT" && -L "$OUTPUT_ROOT" ]]; then
    die "OUTPUT_ROOT must not be a symlink: $OUTPUT_ROOT"
  fi
  mkdir -p "$OUTPUT_ROOT"
}

assert_output_path() {
  local path="$1"
  local ancestor
  assert_output_root
  [[ "$path" == "$OUTPUT_ROOT/"* ]] || die "path escapes OUTPUT_ROOT: $path"
  [[ "$path" != *$'\n'* ]] || die "path contains a newline: $path"
  [[ "$path" != *"/../"* && "$path" != */.. ]] || die "path contains parent traversal: $path"
  if [[ -e "$path" && -L "$path" ]]; then
    die "output path must not be a symlink: $path"
  fi
  ancestor="$(dirname "$path")"
  while [[ "$ancestor" == "$OUTPUT_ROOT"* && "$ancestor" != "$OUTPUT_ROOT" ]]; do
    if [[ -e "$ancestor" && -L "$ancestor" ]]; then
      die "output path has a symlinked parent: $ancestor"
    fi
    ancestor="$(dirname "$ancestor")"
  done
}

safe_reset_dir() {
  local path="$1"
  assert_output_path "$path"
  [[ "$path" != "$OUTPUT_ROOT" ]] || die "refusing to reset OUTPUT_ROOT itself"
  rm -rf -- "$path"
  mkdir -p "$path"
}

reject_symlinks() {
  local root="$1"
  local link
  link="$(find "$root" -type l -print -quit)"
  [[ -z "$link" ]] || die "symlinks are not permitted in staged content: $link"
}

sha256_file() {
  shasum -a 256 "$1" | awk '{ print $1 }'
}

write_sha256_manifest() {
  local root="$1"
  local output="$2"
  local relative
  local temporary="$output.tmp"
  local output_relative=""
  local temporary_relative=""
  if [[ "$output" == "$root/"* ]]; then
    output_relative="./${output#"$root/"}"
    temporary_relative="$output_relative.tmp"
  fi
  : >"$temporary"
  while IFS= read -r relative; do
    [[ "$relative" != "$output_relative" && "$relative" != "$temporary_relative" ]] || continue
    printf '%s  %s\n' "$(sha256_file "$root/$relative")" "$relative" >>"$temporary"
  done < <(cd "$root" && find . -type f -print | LC_ALL=C sort)
  mv "$temporary" "$output"
}

verify_sha256_manifest() {
  local root="$1"
  local manifest="$2"
  (cd "$root" && shasum -a 256 -c "$manifest")
}

expected_lipo_arch() {
  case "$1" in
    aarch64-apple-darwin | arm64) printf 'arm64\n' ;;
    x86_64-apple-darwin | x86_64) printf 'x86_64\n' ;;
    universal2) printf 'arm64 x86_64\n' ;;
    *) die "unsupported macOS architecture or target: $1" ;;
  esac
}

host_target() {
  rustc -vV | awk '/^host:/ { print $2 }'
}

assert_binary_arches() {
  local binary="$1"
  local expected="$2"
  [[ -f "$binary" && ! -L "$binary" ]] || die "missing regular Mach-O file: $binary"
  local actual
  actual="$(lipo -archs "$binary" | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')"
  expected="$(
    printf '%s\n' "$expected" |
      tr ' ' '\n' |
      sed '/^$/d' |
      LC_ALL=C sort |
      tr '\n' ' ' |
      sed 's/ $//'
  )"
  [[ "$actual" == "$expected" ]] ||
    die "architecture mismatch for $binary (expected '$expected', found '$actual')"
}

macho_dependencies() {
  otool -L "$1" |
    tail -n +2 |
    sed -E 's/^[[:space:]]*//; /:$/d; s/[[:space:]]+\(compatibility version.*$//' |
    LC_ALL=C sort -u
}

macho_rpaths() {
  otool -l "$1" |
    awk '
      $1 == "cmd" && $2 == "LC_RPATH" { in_rpath = 1; next }
      in_rpath && $1 == "path" { print $2; in_rpath = 0 }
    ' |
    LC_ALL=C sort -u
}

macho_minimum_versions() {
  otool -l "$1" |
    awk '
      $1 == "cmd" && ($2 == "LC_BUILD_VERSION" || $2 == "LC_VERSION_MIN_MACOSX") {
        in_version = 1
        next
      }
      in_version && ($1 == "minos" || $1 == "version") {
        print $2
        in_version = 0
      }
    ' |
    LC_ALL=C sort -u
}

assert_macho_minimum_version() {
  local binary="$1"
  local found=0
  local version
  while IFS= read -r version; do
    [[ -n "$version" ]] || continue
    found=1
    [[ "$version" == "$MINIMUM_MACOS_VERSION" || "$version" == "$MINIMUM_MACOS_VERSION.0" ]] ||
      die "deployment target mismatch for $binary (expected $MINIMUM_MACOS_VERSION, found $version)"
  done < <(macho_minimum_versions "$binary")
  [[ "$found" -eq 1 ]] || die "no macOS deployment target found in $binary"
}

validate_macho_dependencies() {
  local binary="$1"
  local dependency
  local allowed
  local matched
  while IFS= read -r dependency; do
    [[ -n "$dependency" ]] || continue
    matched=0
    while IFS= read -r allowed; do
      [[ -n "$allowed" && "$allowed" != \#* ]] || continue
      if [[ "$dependency" == "$allowed"* ]]; then
        matched=1
        break
      fi
    done <"$MACOS_DIR/dependencies.allowlist"
    if [[ "$dependency" == @rpath/* ]]; then
      local embedded="$2/Contents/Frameworks/${dependency#@rpath/}"
      [[ -f "$embedded" && ! -L "$embedded" ]] ||
        die "unresolved bundled dependency $dependency for $binary"
      matched=1
    fi
    [[ "$matched" -eq 1 ]] || die "unexpected dynamic dependency in $binary: $dependency"
  done < <(macho_dependencies "$binary")

  local rpath
  while IFS= read -r rpath; do
    [[ -n "$rpath" ]] || continue
    case "$rpath" in
      @executable_path/../Frameworks | @loader_path/../Frameworks) ;;
      *) die "unexpected LC_RPATH in $binary: $rpath" ;;
    esac
  done < <(macho_rpaths "$binary")
}

plist_value() {
  /usr/libexec/PlistBuddy -c "Print :$2" "$1"
}

source "$MACOS_DIR/config.sh"
assert_output_root
