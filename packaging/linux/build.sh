#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in cargo dpkg-query git jq readelf realpath rustc sha256sum; do
  require_tool "$tool"
done
[[ "$#" -eq 1 ]] || die "usage: build.sh ARCH"
arch="$1"
target="$(arch_target "$arch")"

: "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR is required}"
: "${CARGO_HOME:?CARGO_HOME is required}"
: "${HOME:?HOME is required}"
: "${BUILD_IMAGE:?BUILD_IMAGE is required}"
: "${BUILD_INPUT_UMASK:?BUILD_INPUT_UMASK is required}"
: "${BUILD_RECIPE_SHA256:?BUILD_RECIPE_SHA256 is required}"
: "${DEBIAN_SNAPSHOT:?DEBIAN_SNAPSHOT is required}"
: "${RUSTFLAGS:?RUSTFLAGS is required}"

[[ "$BUILD_IMAGE" == "$LINUX_BUILD_IMAGE" ]] || die "unexpected build image identity"
[[ "$DEBIAN_SNAPSHOT" == "$LINUX_DEBIAN_SNAPSHOT" ]] || die "unexpected Debian snapshot"
[[ "$RUSTFLAGS" == "-Dwarnings" ]] || die "unexpected RUSTFLAGS"
[[ "$BUILD_INPUT_UMASK" == "000" || "$BUILD_INPUT_UMASK" == "002" ]] ||
  die "unexpected build input umask"
[[ "$BUILD_RECIPE_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "invalid build recipe digest"

OUTPUT_ROOT="$CARGO_TARGET_DIR"
initialize_output_root
[[ "$CARGO_HOME" == "$OUTPUT_ROOT/cargo-home" ]] ||
  die "CARGO_HOME must be the private cargo-home below CARGO_TARGET_DIR"
[[ "$HOME" == "$OUTPUT_ROOT/home" ]] ||
  die "HOME must be the private home below CARGO_TARGET_DIR"
ensure_output_directory "$CARGO_HOME"
ensure_output_directory "$HOME"

effective_umask="$(umask)"
effective_umask="${effective_umask: -3}"
[[ "$effective_umask" == "$BUILD_INPUT_UMASK" ]] ||
  die "effective build umask does not match BUILD_INPUT_UMASK"
git -C "$REPO_ROOT" diff --quiet
git -C "$REPO_ROOT" diff --cached --quiet
[[ -z "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)" ]] ||
  die "source worktree must be clean"
source_sha="$(git -C "$REPO_ROOT" rev-parse HEAD)"
source_tree="$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ && "$source_tree" =~ ^[0-9a-f]{40}$ ]] ||
  die "invalid source commit or tree identity"

metadata="$(
  cargo metadata \
    --manifest-path "$REPO_ROOT/Cargo.toml" \
    --locked \
    --filter-platform "$target" \
    --format-version 1
)"
forbidden="$(
  jq -r '
    [.packages[].name |
      select(. == "slint" or . == "slint-build" or startswith("i-slint"))
    ] | sort | join(",")
  ' <<<"$metadata"
)"
[[ -z "$forbidden" ]] || die "Linux root metadata contains Slint packages: $forbidden"

case "$arch" in
  x86_64) ;;
  arm64) export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc ;;
  *) die "unsupported architecture: $arch" ;;
esac

cargo build \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  --locked \
  --release \
  --target "$target" \
  --package gta-claw-daemon \
  --package gta-claw-cli

binary_dir="$CARGO_TARGET_DIR/$target/release"
daemon_binary="$binary_dir/$LINUX_DAEMON_NAME"
cli_binary="$binary_dir/$LINUX_CLI_NAME"
for binary in "$daemon_binary" "$cli_binary"; do
  validate_elf_binary "$binary" "$arch"
done
glibc_requirement="$(
  {
    max_glibc_version "$daemon_binary"
    max_glibc_version "$cli_binary"
  } | sort -V | tail -1
)"

runtime_root="$OUTPUT_ROOT/runtime"
ensure_output_directory "$runtime_root/rootfs"
ensure_output_directory "$runtime_root/licenses"

dpkg_file() {
  local package="$1"
  local suffix="$2"
  local found
  found="$(dpkg-query -L "$package" | awk -v suffix="$suffix" 'index($0, suffix) == length($0) - length(suffix) + 1 { print; exit }')"
  [[ -n "$found" && -e "$found" ]] || die "package $package does not provide $suffix"
  realpath -e "$found"
}

case "$arch" in
  x86_64)
    libc_package="libc6:amd64"
    libgcc_package="libgcc-s1:amd64"
    loader_source="$(dpkg_file "$libc_package" "/ld-linux-x86-64.so.2")"
    libc_source="$(dpkg_file "$libc_package" "/libc.so.6")"
    libgcc_source="$(dpkg_file "$libgcc_package" "/libgcc_s.so.1")"
    loader_target="/lib64/ld-linux-x86-64.so.2"
    libc_target="/lib/x86_64-linux-gnu/libc.so.6"
    libgcc_target="/lib/x86_64-linux-gnu/libgcc_s.so.1"
    libc_copyright="/usr/share/doc/libc6/copyright"
    libgcc_copyright="/usr/share/doc/libgcc-s1/copyright"
    ;;
  arm64)
    libc_package="libc6-arm64-cross"
    libgcc_package="libgcc-s1-arm64-cross"
    loader_source="$(dpkg_file "$libc_package" "/ld-linux-aarch64.so.1")"
    libc_source="$(dpkg_file "$libc_package" "/libc.so.6")"
    libgcc_source="$(dpkg_file "$libgcc_package" "/libgcc_s.so.1")"
    loader_target="/lib/ld-linux-aarch64.so.1"
    libc_target="/lib/aarch64-linux-gnu/libc.so.6"
    libgcc_target="/lib/aarch64-linux-gnu/libgcc_s.so.1"
    libc_copyright="/usr/share/doc/libc6-arm64-cross/copyright"
    libgcc_copyright="/usr/share/doc/libgcc-s1-arm64-cross/copyright"
    ;;
esac

copy_verified_input "$loader_source" "$runtime_root/rootfs$loader_target" 0755
copy_verified_input "$libc_source" "$runtime_root/rootfs$libc_target" 0755
copy_verified_input "$libgcc_source" "$runtime_root/rootfs$libgcc_target" 0755
copy_verified_input "$(realpath -e "$libc_copyright")" "$runtime_root/licenses/libc6.copyright" 0644
copy_verified_input "$(realpath -e "$libgcc_copyright")" "$runtime_root/licenses/libgcc-s1.copyright" 0644

libc_version="$(dpkg-query -W -f='${Version}' "$libc_package")"
libc_arch="$(dpkg-query -W -f='${Architecture}' "$libc_package")"
libgcc_version="$(dpkg-query -W -f='${Version}' "$libgcc_package")"
libgcc_arch="$(dpkg-query -W -f='${Architecture}' "$libgcc_package")"

write_json_file() {
  local output="$1"
  shift
  ensure_output_directory "$(dirname "$output")"
  open_output_file "$output" 0644
  jq -S "$@" >&"$OPEN_OUTPUT_FD"
  finish_output_file
}

runtime_manifest="$runtime_root/runtime-manifest.json"
write_json_file "$runtime_manifest" -n \
  --arg arch "$arch" \
  --arg target "$target" \
  --arg libc_package "$libc_package" \
  --arg libc_version "$libc_version" \
  --arg libc_arch "$libc_arch" \
  --arg libc_copyright_sha "$(sha256_file "$runtime_root/licenses/libc6.copyright")" \
  --arg libgcc_package "$libgcc_package" \
  --arg libgcc_version "$libgcc_version" \
  --arg libgcc_arch "$libgcc_arch" \
  --arg libgcc_copyright_sha "$(sha256_file "$runtime_root/licenses/libgcc-s1.copyright")" \
  --arg loader_source "runtime/rootfs$loader_target" \
  --arg loader_target "$loader_target" \
  --arg loader_sha "$(sha256_file "$runtime_root/rootfs$loader_target")" \
  --arg libc_source "runtime/rootfs$libc_target" \
  --arg libc_target "$libc_target" \
  --arg libc_sha "$(sha256_file "$runtime_root/rootfs$libc_target")" \
  --arg libgcc_source "runtime/rootfs$libgcc_target" \
  --arg libgcc_target "$libgcc_target" \
  --arg libgcc_sha "$(sha256_file "$runtime_root/rootfs$libgcc_target")" \
  '{
    schemaVersion: 1,
    architecture: $arch,
    rustTarget: $target,
    packages: [
      {
        id: "libc6",
        dpkgPackage: $libc_package,
        version: $libc_version,
        architecture: $libc_arch,
        licenseExpression: "LGPL-2.1-or-later",
        copyrightFile: "runtime/licenses/libc6.copyright",
        copyrightSha256: $libc_copyright_sha,
        files: [
          {stagedPath: $loader_source, targetPath: $loader_target, sha256: $loader_sha, mode: "0755"},
          {stagedPath: $libc_source, targetPath: $libc_target, sha256: $libc_sha, mode: "0755"}
        ]
      },
      {
        id: "libgcc-s1",
        dpkgPackage: $libgcc_package,
        version: $libgcc_version,
        architecture: $libgcc_arch,
        licenseExpression: "GPL-3.0-or-later WITH GCC-exception-3.1",
        copyrightFile: "runtime/licenses/libgcc-s1.copyright",
        copyrightSha256: $libgcc_copyright_sha,
        files: [
          {stagedPath: $libgcc_source, targetPath: $libgcc_target, sha256: $libgcc_sha, mode: "0755"}
        ]
      }
    ]
  }'

rustc_verbose="$(rustc -vV)"
cargo_version="$(cargo -V)"
manifest="$OUTPUT_ROOT/build-manifest.json"
write_json_file "$manifest" -n \
  --arg source_sha "$source_sha" \
  --arg source_tree "$source_tree" \
  --arg source_epoch "$SOURCE_DATE_EPOCH" \
  --arg build_image "$BUILD_IMAGE" \
  --arg build_recipe_sha "$BUILD_RECIPE_SHA256" \
  --arg debian_snapshot "$DEBIAN_SNAPSHOT" \
  --arg rustc_verbose "$rustc_verbose" \
  --arg cargo_version "$cargo_version" \
  --arg rustflags "$RUSTFLAGS" \
  --arg arch "$arch" \
  --arg target "$target" \
  --arg glibc "$glibc_requirement" \
  --arg daemon_path "$target/release/$LINUX_DAEMON_NAME" \
  --arg daemon_sha "$(sha256_file "$daemon_binary")" \
  --arg cli_path "$target/release/$LINUX_CLI_NAME" \
  --arg cli_sha "$(sha256_file "$cli_binary")" \
  --arg runtime_path "runtime/runtime-manifest.json" \
  --arg runtime_sha "$(sha256_file "$runtime_manifest")" \
  '{
    schemaVersion: 2,
    source: {
      repository: "https://github.com/GTAStudio/GTA-Claw",
      commit: $source_sha,
      tree: $source_tree,
      clean: true,
      sourceDateEpoch: ($source_epoch | tonumber)
    },
    builder: {
      image: $build_image,
      recipeSha256: $build_recipe_sha,
      debianSnapshot: $debian_snapshot,
      rustcVerbose: $rustc_verbose,
      cargoVersion: $cargo_version
    },
    build: {
      architecture: $arch,
      rustTarget: $target,
      profile: "release",
      rustflags: $rustflags,
      locked: true,
      packages: ["gta-claw-cli", "gta-claw-daemon"]
    },
    glibcRequirement: $glibc,
    binaries: [
      {name: "gta-claw-daemon", path: $daemon_path, sha256: $daemon_sha},
      {name: "gta-claw-cli", path: $cli_path, sha256: $cli_sha}
    ],
    runtimeManifest: {path: $runtime_path, sha256: $runtime_sha}
  }'
manifest_sha="$(sha256_file "$manifest")"
write_output_text "$OUTPUT_ROOT/BUILD_COMPLETE" 0644 "$manifest_sha  build-manifest.json"$'\n'

printf '%s\n' "$manifest"
