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

validate_safe_component() {
  local value="$1"
  local kind="$2"
  [[ -n "$value" && "${#value}" -le 64 ]] ||
    die "$kind must contain 1 to 64 characters"
  [[ "$value" != *"/"* && "$value" != *"\\"* ]] ||
    die "$kind must be a single path component"
  [[ "$value" != "." && "$value" != ".." && "$value" != *".."* ]] ||
    die "$kind contains an ambiguous dot sequence"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]] ||
    die "$kind contains a control character"
  if LC_ALL=C grep -q '[[:cntrl:]]' <<<"$value"; then
    die "$kind contains a control character"
  fi
  case "$kind" in
    APP_NAME)
      [[ "$value" =~ ^[A-Za-z0-9]([[:space:]A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] ||
        die "APP_NAME must start and end with an alphanumeric character"
      ;;
    EXECUTABLE_NAME)
      [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] ||
        die "EXECUTABLE_NAME must be an unspaced executable name"
      ;;
    *)
      [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] ||
        die "$kind must be an unspaced path component"
      ;;
  esac
}

validate_absolute_path_components() {
  local path="$1"
  local label="$2"
  local remaining
  local component
  [[ "$path" == /* ]] || die "$label must be absolute: $path"
  [[ "$path" != *$'\n'* && "$path" != *$'\r'* ]] ||
    die "$label contains a control character"
  [[ "$path" != *"//"* ]] || die "$label contains an empty path component"
  remaining="${path#/}"
  while [[ -n "$remaining" ]]; do
    component="${remaining%%/*}"
    if [[ "$remaining" == */* ]]; then
      remaining="${remaining#*/}"
    else
      remaining=""
    fi
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] ||
      die "$label contains an ambiguous path component: $path"
  done
}

canonical_target_root() {
  local target="$REPO_ROOT/target"
  local repository
  repository="$(cd "$REPO_ROOT" && pwd -P)"
  [[ "$repository" == "$REPO_ROOT" ]] || die "repository root changed during validation"
  if [[ -L "$target" ]]; then
    die "repository target directory must not be a symlink"
  fi
  if [[ ! -e "$target" ]]; then
    mkdir -- "$target"
  fi
  [[ -d "$target" && ! -L "$target" ]] || die "repository target path is not a directory"
  local canonical
  canonical="$(cd "$target" && pwd -P)"
  [[ "$canonical" == "$target" ]] || die "repository target directory resolves outside the repository"
  printf '%s\n' "$canonical"
}

assert_no_symlink_components() {
  local boundary="$1"
  local path="$2"
  local relative
  local component
  local current="$boundary"
  local canonical
  [[ "$path" == "$boundary" || "$path" == "$boundary/"* ]] ||
    die "path escapes canonical target boundary: $path"
  relative="${path#"$boundary"}"
  relative="${relative#/}"
  while [[ -n "$relative" ]]; do
    component="${relative%%/*}"
    if [[ "$relative" == */* ]]; then
      relative="${relative#*/}"
    else
      relative=""
    fi
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] ||
      die "path contains an ambiguous component: $path"
    current="$current/$component"
    [[ ! -L "$current" ]] || die "path contains a symlink component: $current"
    if [[ -e "$current" ]]; then
      if [[ -d "$current" ]]; then
        canonical="$(cd "$current" && pwd -P)"
        [[ "$canonical" == "$current" ]] || die "path component resolves outside target: $current"
      elif [[ -n "$relative" ]]; then
        die "non-directory path component blocks output path: $current"
      fi
    fi
  done
}

assert_nearest_existing_parent() {
  local boundary="$1"
  local path="$2"
  local candidate
  local canonical
  candidate="$(dirname "$path")"
  while [[ ! -e "$candidate" && ! -L "$candidate" ]]; do
    [[ "$candidate" != "/" ]] || die "no existing parent found for $path"
    candidate="$(dirname "$candidate")"
  done
  [[ -d "$candidate" && ! -L "$candidate" ]] ||
    die "nearest existing parent is not a real directory: $candidate"
  canonical="$(cd "$candidate" && pwd -P)"
  case "$canonical/" in
    "$boundary/"*) ;;
    *) die "nearest existing parent resolves outside canonical target: $canonical" ;;
  esac
}

assert_output_root() {
  local target
  local canonical
  validate_absolute_path_components "$OUTPUT_ROOT" "OUTPUT_ROOT"
  target="$(canonical_target_root)"
  case "$OUTPUT_ROOT/" in
    "$target/"*) ;;
    *) die "OUTPUT_ROOT must remain below canonical target directory $target" ;;
  esac
  assert_no_symlink_components "$target" "$OUTPUT_ROOT"
  assert_nearest_existing_parent "$target" "$OUTPUT_ROOT"
  mkdir -p "$OUTPUT_ROOT"
  assert_no_symlink_components "$target" "$OUTPUT_ROOT"
  canonical="$(cd "$OUTPUT_ROOT" && pwd -P)"
  [[ "$canonical" == "$OUTPUT_ROOT" ]] || die "OUTPUT_ROOT resolves outside canonical target"
}

assert_output_path() {
  local path="$1"
  local target
  local canonical_parent
  assert_output_root
  validate_absolute_path_components "$path" "output path"
  [[ "$path" == "$OUTPUT_ROOT/"* ]] || die "path escapes OUTPUT_ROOT: $path"
  target="$(canonical_target_root)"
  assert_no_symlink_components "$target" "$path"
  assert_nearest_existing_parent "$target" "$path"
  canonical_parent="$(cd "$(dirname "$path")" 2>/dev/null && pwd -P || true)"
  if [[ -n "$canonical_parent" ]]; then
    case "$canonical_parent/" in
      "$OUTPUT_ROOT/"*) ;;
      *) die "existing output parent resolves outside OUTPUT_ROOT: $canonical_parent" ;;
    esac
  fi
}

assert_output_file_slot() {
  local path="$1"
  assert_output_path "$path"
  if [[ -e "$path" || -L "$path" ]]; then
    [[ -f "$path" && ! -L "$path" ]] ||
      die "output file path collides with a non-regular object: $path"
  fi
}

ensure_output_directory() {
  local path="$1"
  assert_output_path "$path"
  [[ ! -e "$path" || -d "$path" ]] ||
    die "output directory path collides with a non-directory object: $path"
  mkdir -p "$path"
  assert_output_path "$path"
  [[ -d "$path" && ! -L "$path" ]] || die "failed to create a real output directory: $path"
}

remove_output_file() {
  local path="$1"
  assert_output_file_slot "$path"
  rm -f -- "$path"
  assert_output_path "$path"
  [[ ! -e "$path" && ! -L "$path" ]] || die "failed to remove output file: $path"
}

output_file_identity() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f '%d:%i' "$1"
  else
    stat -c '%d:%i' "$1"
  fi
}

safe_reset_dir() {
  local path="$1"
  local target
  assert_output_path "$path"
  [[ "$path" != "$OUTPUT_ROOT" ]] || die "refusing to reset OUTPUT_ROOT itself"
  target="$(canonical_target_root)"
  assert_no_symlink_components "$target" "$path"
  assert_nearest_existing_parent "$target" "$path"
  [[ ! -L "$path" ]] || die "refusing to delete a symlink: $path"
  rm -rf -- "$path"
  # Shell path APIs cannot hold the validated parent open; callers must exclusively own OUTPUT_ROOT.
  assert_output_path "$path"
  ensure_output_directory "$path"
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
  local restore_noclobber=0
  local reserved_identity
  if [[ "$root" == "$OUTPUT_ROOT/"* ]]; then
    assert_output_path "$root"
  fi
  assert_output_file_slot "$output"
  assert_output_path "$temporary"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] ||
    die "temporary manifest path already exists: $temporary"
  if [[ "$output" == "$root/"* ]]; then
    output_relative="./${output#"$root/"}"
    temporary_relative="$output_relative.tmp"
  fi
  case "$-" in
    *C*) ;;
    *)
      set -o noclobber
      restore_noclobber=1
      ;;
  esac
  if ! exec 9>"$temporary"; then
    [[ "$restore_noclobber" -eq 0 ]] || set +o noclobber
    die "failed to reserve temporary manifest: $temporary"
  fi
  [[ "$restore_noclobber" -eq 0 ]] || set +o noclobber
  reserved_identity="$(output_file_identity "$temporary")"
  while IFS= read -r relative; do
    [[ "$relative" != "$output_relative" && "$relative" != "$temporary_relative" ]] || continue
    printf '%s  %s\n' "$(sha256_file "$root/$relative")" "$relative" >&9
  done < <(cd "$root" && find . -type f -print | LC_ALL=C sort)
  assert_output_file_slot "$output"
  assert_output_file_slot "$temporary"
  [[ "$(output_file_identity "$temporary")" == "$reserved_identity" ]] ||
    die "temporary manifest changed before publication: $temporary"
  # The exclusive OUTPUT_ROOT contract closes the remaining validation-to-rename shell race.
  mv "$temporary" "$output"
  assert_output_file_slot "$output"
  [[ "$(output_file_identity "$output")" == "$reserved_identity" ]] ||
    die "published manifest is not the reserved file: $output"
  exec 9>&-
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
