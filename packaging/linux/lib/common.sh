#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

LINUX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO_ROOT="$(cd "$LINUX_DIR/../.." && pwd -P)"
: "${OUTPUT_ROOT:=$REPO_ROOT/target/linux-package}"

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

require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || die "this operation requires Linux"
}

validate_release_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "version must be numeric X.Y.Z: $1"
  [[ "${#1}" -le 32 ]] || die "version exceeds 32 characters"
}

validate_safe_component() {
  local value="$1"
  local label="$2"
  [[ -n "$value" && "${#value}" -le 64 ]] ||
    die "$label must contain 1 to 64 characters"
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]] ||
    die "$label is not a safe path component: $value"
  [[ "$value" != *".."* ]] || die "$label contains an ambiguous dot sequence"
}

validate_absolute_path() {
  local path="$1"
  local label="$2"
  local remaining
  local component
  [[ "$path" == /* ]] || die "$label must be absolute: $path"
  [[ "$path" != *"\\"* && "$path" != *"//"* ]] ||
    die "$label contains an unsafe separator: $path"
  [[ "$path" != *$'\n'* && "$path" != *$'\r'* && "$path" != *$'\t'* ]] ||
    die "$label contains a control character"
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
  local repository
  local target="$REPO_ROOT/target"
  local canonical
  repository="$(cd "$REPO_ROOT" && pwd -P)"
  [[ "$repository" == "$REPO_ROOT" ]] || die "repository root changed during validation"
  [[ ! -L "$target" ]] || die "repository target directory must not be a symlink"
  if [[ ! -e "$target" ]]; then
    mkdir -- "$target"
  fi
  [[ -d "$target" && ! -L "$target" ]] ||
    die "repository target path is not a real directory"
  canonical="$(cd "$target" && pwd -P)"
  [[ "$canonical" == "$target" ]] ||
    die "repository target directory resolves outside the repository"
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
        [[ "$canonical" == "$current" ]] ||
          die "path component resolves through an alias: $current"
      elif [[ -n "$relative" ]]; then
        die "non-directory component blocks output path: $current"
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
    *) die "nearest existing parent resolves outside target: $canonical" ;;
  esac
}

output_identity() {
  stat -c '%d:%i' "$1"
}

output_link_count() {
  stat -c '%h' "$1"
}

assert_output_candidate() {
  local path="$1"
  local target
  validate_absolute_path "$path" "output path"
  target="$(canonical_target_root)"
  case "$path/" in
    "$target/"*) ;;
    *) die "output path must remain below canonical target directory $target" ;;
  esac
  assert_no_symlink_components "$target" "$path"
  assert_nearest_existing_parent "$target" "$path"
}

OUTPUT_LOCK_PATH=""
OUTPUT_LOCK_ID=""
OUTPUT_ROOT_ID=""
OUTPUT_LOCK_HELD=0

release_output_lock() {
  if [[ "$OUTPUT_LOCK_HELD" -eq 1 ]]; then
    [[ -d "$OUTPUT_LOCK_PATH" && ! -L "$OUTPUT_LOCK_PATH" ]] ||
      die "output lock changed before release"
    [[ "$(output_identity "$OUTPUT_LOCK_PATH")" == "$OUTPUT_LOCK_ID" ]] ||
      die "output lock identity changed before release"
    rmdir -- "$OUTPUT_LOCK_PATH"
    OUTPUT_LOCK_HELD=0
  fi
}

initialize_output_root() {
  local target
  validate_absolute_path "$OUTPUT_ROOT" "OUTPUT_ROOT"
  target="$(canonical_target_root)"
  case "$OUTPUT_ROOT/" in
    "$target/"*) ;;
    *) die "OUTPUT_ROOT must remain below canonical target directory $target" ;;
  esac
  [[ "$OUTPUT_ROOT" != "$target" ]] || die "OUTPUT_ROOT must not equal repository target"
  assert_no_symlink_components "$target" "$OUTPUT_ROOT"
  assert_nearest_existing_parent "$target" "$OUTPUT_ROOT"
  [[ ! -e "$OUTPUT_ROOT" && ! -L "$OUTPUT_ROOT" ]] ||
    die "OUTPUT_ROOT must be new and exclusively owned: $OUTPUT_ROOT"

  OUTPUT_LOCK_PATH="$OUTPUT_ROOT.lock"
  assert_output_candidate "$OUTPUT_LOCK_PATH"
  [[ ! -e "$OUTPUT_LOCK_PATH" && ! -L "$OUTPUT_LOCK_PATH" ]] ||
    die "output lock already exists: $OUTPUT_LOCK_PATH"
  mkdir -- "$OUTPUT_LOCK_PATH"
  OUTPUT_LOCK_ID="$(output_identity "$OUTPUT_LOCK_PATH")"
  OUTPUT_LOCK_HELD=1
  trap release_output_lock EXIT INT TERM

  mkdir -- "$OUTPUT_ROOT"
  [[ -d "$OUTPUT_ROOT" && ! -L "$OUTPUT_ROOT" ]] ||
    die "failed to create a real OUTPUT_ROOT"
  OUTPUT_ROOT_ID="$(output_identity "$OUTPUT_ROOT")"
  printf 'gta-claw-linux-packaging-v1\n' >"$OUTPUT_ROOT/.linux-packaging-owner"
  chmod 0600 "$OUTPUT_ROOT/.linux-packaging-owner"
  assert_output_root_owned
}

assert_output_root_owned() {
  local target
  [[ "$OUTPUT_LOCK_HELD" -eq 1 ]] || die "exclusive output lock is not held"
  [[ -d "$OUTPUT_LOCK_PATH" && ! -L "$OUTPUT_LOCK_PATH" ]] ||
    die "output lock is no longer a real directory"
  [[ "$(output_identity "$OUTPUT_LOCK_PATH")" == "$OUTPUT_LOCK_ID" ]] ||
    die "output lock identity changed"
  [[ -d "$OUTPUT_ROOT" && ! -L "$OUTPUT_ROOT" ]] ||
    die "OUTPUT_ROOT is no longer a real directory"
  [[ "$(output_identity "$OUTPUT_ROOT")" == "$OUTPUT_ROOT_ID" ]] ||
    die "OUTPUT_ROOT identity changed"
  [[ "$(cat "$OUTPUT_ROOT/.linux-packaging-owner")" == "gta-claw-linux-packaging-v1" ]] ||
    die "OUTPUT_ROOT ownership marker changed"
  target="$(canonical_target_root)"
  assert_no_symlink_components "$target" "$OUTPUT_ROOT"
}

assert_output_path() {
  local path="$1"
  assert_output_root_owned
  validate_absolute_path "$path" "output path"
  [[ "$path" == "$OUTPUT_ROOT" || "$path" == "$OUTPUT_ROOT/"* ]] ||
    die "path escapes OUTPUT_ROOT: $path"
  assert_no_symlink_components "$(canonical_target_root)" "$path"
  assert_nearest_existing_parent "$OUTPUT_ROOT" "$path"
}

ensure_output_directory() {
  local path="$1"
  assert_output_path "$path"
  [[ ! -e "$path" || -d "$path" ]] ||
    die "output directory collides with a non-directory object: $path"
  mkdir -p -- "$path"
  assert_output_path "$path"
  [[ -d "$path" && ! -L "$path" ]] || die "failed to create directory: $path"
}

assert_new_output_file() {
  local path="$1"
  assert_output_path "$path"
  [[ ! -e "$path" && ! -L "$path" ]] ||
    die "output file collision: $path"
}

assert_regular_unaliased() {
  local path="$1"
  local label="$2"
  [[ -f "$path" && ! -L "$path" ]] || die "$label is not a regular file: $path"
  [[ "$(output_link_count "$path")" -eq 1 ]] ||
    die "$label has multiple hard links: $path"
}

reject_links_and_special_files() {
  local root="$1"
  local bad
  [[ -d "$root" && ! -L "$root" ]] || die "tree root is not a real directory: $root"
  bad="$(find "$root" -type l -print -quit)"
  [[ -z "$bad" ]] || die "symlink is not permitted in staged content: $bad"
  bad="$(find "$root" -type f -links +1 -print -quit)"
  [[ -z "$bad" ]] || die "hard-linked file is not permitted in staged content: $bad"
  bad="$(find "$root" ! -type d ! -type f -print -quit)"
  [[ -z "$bad" ]] || die "special file is not permitted in staged content: $bad"
}

copy_regular_input() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  assert_regular_unaliased "$source" "input"
  assert_new_output_file "$destination"
  ensure_output_directory "$(dirname "$destination")"
  install -m "$mode" -- "$source" "$destination"
  assert_regular_unaliased "$destination" "copied output"
}

publish_output_file() {
  local temporary="$1"
  local final="$2"
  local identity
  assert_regular_unaliased "$temporary" "temporary output"
  assert_new_output_file "$final"
  identity="$(output_identity "$temporary")"
  mv -T --no-clobber -- "$temporary" "$final"
  [[ ! -e "$temporary" && ! -L "$temporary" ]] ||
    die "temporary output remained after publication: $temporary"
  assert_regular_unaliased "$final" "published output"
  [[ "$(output_identity "$final")" == "$identity" ]] ||
    die "published output is not the reserved file: $final"
}

sha256_file() {
  sha256sum "$1" | awk '{ print $1 }'
}

write_sha256_manifest() {
  local root="$1"
  local output="$2"
  local temporary="$output.tmp"
  local output_relative
  local temporary_relative
  local relative
  assert_output_path "$root"
  assert_new_output_file "$output"
  assert_new_output_file "$temporary"
  [[ "$output" == "$root/"* ]] || die "manifest must be written inside its scanned root"
  output_relative="./${output#"$root/"}"
  temporary_relative="$output_relative.tmp"
  (
    umask 077
    set -o noclobber
    : >"$temporary"
  )
  assert_regular_unaliased "$temporary" "manifest temporary"
  while IFS= read -r -d '' relative; do
    [[ "$relative" != "$output_relative" && "$relative" != "$temporary_relative" ]] ||
      continue
    printf '%s  %s\n' "$(sha256_file "$root/$relative")" "$relative" >>"$temporary"
  done < <(cd "$root" && find . -type f -print0 | LC_ALL=C sort -z)
  chmod 0644 "$temporary"
  touch --date="@$SOURCE_DATE_EPOCH" "$temporary"
  publish_output_file "$temporary" "$output"
}

verify_sha256_manifest() {
  local root="$1"
  local manifest="$2"
  (cd "$root" && sha256sum -c "$manifest")
}

normalize_tree() {
  local root="$1"
  reject_links_and_special_files "$root"
  find "$root" -type d -exec chmod 0755 {} +
  find "$root" -type f -exec touch --date="@$SOURCE_DATE_EPOCH" {} +
  find "$root" -type d -exec touch --date="@$SOURCE_DATE_EPOCH" {} +
}

create_deterministic_tar_gz() {
  local source_parent="$1"
  local source_name="$2"
  local output="$3"
  local temporary="$output.tmp"
  local identity
  assert_output_path "$source_parent/$source_name"
  reject_links_and_special_files "$source_parent/$source_name"
  assert_new_output_file "$output"
  assert_new_output_file "$temporary"
  (
    umask 077
    set -o noclobber
    : >"$temporary"
  )
  identity="$(output_identity "$temporary")"
  (
    cd "$source_parent"
    tar \
      --sort=name \
      --format=posix \
      --pax-option=delete=atime,delete=ctime \
      --mtime="@$SOURCE_DATE_EPOCH" \
      --clamp-mtime \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -cf - \
      "$source_name"
  ) | gzip -n -9 >"$temporary"
  assert_regular_unaliased "$temporary" "tar temporary"
  [[ "$(output_identity "$temporary")" == "$identity" ]] ||
    die "tar temporary identity changed while writing"
  chmod 0644 "$temporary"
  touch --date="@$SOURCE_DATE_EPOCH" "$temporary"
  publish_output_file "$temporary" "$output"
}

arch_target() {
  case "$1" in
    x86_64) printf 'x86_64-unknown-linux-gnu\n' ;;
    arm64) printf 'aarch64-unknown-linux-gnu\n' ;;
    *) die "unsupported Linux architecture: $1" ;;
  esac
}

deb_arch() {
  case "$1" in
    x86_64) printf 'amd64\n' ;;
    arm64) printf 'arm64\n' ;;
    *) die "unsupported Debian architecture: $1" ;;
  esac
}

rpm_arch() {
  case "$1" in
    x86_64) printf 'x86_64\n' ;;
    arm64) printf 'aarch64\n' ;;
    *) die "unsupported RPM architecture: $1" ;;
  esac
}

oci_arch() {
  case "$1" in
    x86_64) printf 'amd64\n' ;;
    arm64) printf 'arm64\n' ;;
    *) die "unsupported OCI architecture: $1" ;;
  esac
}

validate_elf_arch() {
  local binary="$1"
  local arch="$2"
  local machine
  assert_regular_unaliased "$binary" "ELF binary"
  machine="$(readelf -h "$binary" | awk -F: '/Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2 }')"
  case "$arch:$machine" in
    "x86_64:Advanced Micro Devices X86-64" | "arm64:AArch64") ;;
    *) die "ELF architecture mismatch for $binary: expected $arch, found $machine" ;;
  esac
}

validate_elf_dependencies() {
  local binary="$1"
  local dependency
  local allowed
  local matched
  while IFS= read -r dependency; do
    [[ -n "$dependency" ]] || continue
    matched=0
    while IFS= read -r allowed; do
      [[ -n "$allowed" && "$allowed" != \#* ]] || continue
      if [[ "$dependency" == "$allowed" ]]; then
        matched=1
        break
      fi
    done <"$LINUX_DIR/dependencies.allowlist"
    [[ "$matched" -eq 1 ]] ||
      die "unexpected ELF dependency in $binary: $dependency"
  done < <(
    readelf -d "$binary" |
      sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' |
      LC_ALL=C sort -u
  )
}

validate_elf_binary() {
  validate_elf_arch "$1" "$2"
  validate_elf_dependencies "$1"
  if readelf -d "$1" | grep -Eiq 'slint|node|javascript|npm|pnpm|bun'; then
    die "forbidden dynamic dependency found in $1"
  fi
}

reject_forbidden_runtime_content() {
  local root="$1"
  local bad
  bad="$(
    find "$root" -type f \( \
      -iname 'node' -o -iname 'nodejs' -o -iname 'npm' -o -iname 'npx' -o \
      -iname 'pnpm' -o -iname 'bun' -o -iname '*.js' -o -iname '*.mjs' -o \
      -iname '*.cjs' -o -iname '*.node' -o -iname '*slint*.so*' \
    \) -print -quit
  )"
  [[ -z "$bad" ]] || die "forbidden runtime or package-manager content: $bad"
}

validate_service_contract() {
  local service="$1"
  local required
  for required in \
    'DynamicUser=yes' \
    'NoNewPrivileges=yes' \
    'PrivateTmp=yes' \
    'PrivateDevices=yes' \
    'ProtectSystem=strict' \
    'ProtectHome=yes' \
    'ProtectKernelTunables=yes' \
    'ProtectControlGroups=yes' \
    'CapabilityBoundingSet=' \
    'RestrictAddressFamilies=AF_UNIX' \
    'IPAddressDeny=any' \
    'SystemCallFilter=@system-service' \
    'LoadCredential=gta-claw-config:/etc/gta-claw/credentials/daemon.conf'; do
    grep -Fx "$required" "$service" >/dev/null ||
      die "service hardening contract missing: $required"
  done
  if grep -Eiq 'Environment=.*(token|secret|password|private.?key)=' "$service"; then
    die "service embeds a secret-like environment literal"
  fi
  if grep -Eq '^ExecStart=.*--(listen|socket|config|state|log)' "$service"; then
    die "service invents a daemon runtime flag"
  fi
}

source "$LINUX_DIR/config.sh"
