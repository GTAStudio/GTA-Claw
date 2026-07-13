#!/usr/bin/env bash

verify_build_manifest() {
  local manifest="$1"
  local arch="$2"
  local expected_public_key_sha="$3"
  local target
  local target_root
  local build_root
  local complete
  local expected_seal
  local public_key
  local signature
  local runtime_relative
  local binary_name
  local binary_relative
  local binary
  local expected_sha
  local runtime_file
  local staged_relative
  local material_name
  local material_source
  local material_staged
  local material_target
  local material_sha
  local material_mode
  local material_encoding
  local material_provider
  local material_provider_version
  local material_provider_arch
  local expected_material_set
  local actual_material_set
  local package_id
  local package_name
  local package_license
  local target_path
  local mode
  local expected_runtime_set
  local source_status

  require_tool dpkg-query
  require_tool git
  require_tool jq
  require_tool openssl
  require_tool readelf
  require_tool sha256sum
  target="$(arch_target "$arch")"
  validate_absolute_path "$manifest" "build manifest"
  target_root="$(canonical_target_root)"
  if [[ "${SAFEIO_ACTIVE:-0}" == "1" ]]; then
    if [[ "${BUILD_MANIFEST_TEST_MODE:-0}" == "1" ]]; then
      [[ "$manifest" == "$OUTPUT_ROOT/cases/"*/build-manifest.json ]] ||
        die "test build manifest path is invalid"
    else
      [[ "$manifest" == "/proc/self/fd/$SAFEIO_BUILD_FD/build-manifest.json" ]] ||
        die "build manifest does not match inherited build capability"
    fi
  else
    [[ "$manifest" == "$target_root/"* ]] ||
      die "build manifest must remain below canonical repository target"
  fi
  assert_no_symlink_components "$target_root" "$manifest"
  assert_regular_unaliased "$manifest" "build manifest"
  build_root="$(dirname "$manifest")"
  assert_private_owned_root "$build_root"
  [[ "$(basename "$manifest")" == "build-manifest.json" ]] ||
    die "unexpected build manifest filename"

  complete="$build_root/BUILD_COMPLETE"
  assert_regular_unaliased "$complete" "build completion seal"
  public_key="$build_root/build-public-key.pem"
  signature="$build_root/build-manifest.sig"
  assert_regular_unaliased "$public_key" "build public key"
  assert_regular_unaliased "$signature" "build manifest signature"
  [[ "$expected_public_key_sha" =~ ^[0-9a-f]{64}$ ]] ||
    die "expected build public-key fingerprint is invalid"
  [[ "$(sha256_file "$public_key")" == "$expected_public_key_sha" ]] ||
    die "build public key does not match out-of-band fingerprint"
  openssl pkeyutl \
    -verify \
    -pubin \
    -inkey "$public_key" \
    -sigfile "$signature" \
    -rawin \
    -in "$manifest" \
    >/dev/null 2>&1 ||
    die "build manifest signature verification failed"
  expected_seal="$(
    printf '%s  %s\n' \
      "$(sha256_file "$manifest")" build-manifest.json \
      "$(sha256_file "$public_key")" build-public-key.pem \
      "$(sha256_file "$signature")" build-manifest.sig
  )"
  [[ "$(cat "$complete")" == "$expected_seal" ]] ||
    die "build completion seal does not match build manifest"

  jq -e \
    --arg arch "$arch" \
    --arg target "$target" \
    --arg image "$LINUX_BUILD_IMAGE" \
    --arg snapshot "$LINUX_DEBIAN_SNAPSHOT" \
    --arg rust_toolchain "$LINUX_RUST_TOOLCHAIN" \
    '
      .schemaVersion == 2 and
      .source.clean == true and
      (.source.commit | test("^[0-9a-f]{40}$")) and
      (.source.tree | test("^[0-9a-f]{40}$")) and
      .builder.image == $image and
      (.builder.environmentImageId | test("^sha256:[0-9a-f]{64}$")) and
      .builder.debianSnapshot == $snapshot and
      (.builder.recipeSha256 | test("^[0-9a-f]{64}$")) and
      (.builder.rustcVerbose | startswith("rustc " + $rust_toolchain + " ")) and
      (.builder.cargoVersion | startswith("cargo " + $rust_toolchain + " ")) and
      .build.architecture == $arch and
      .build.rustTarget == $target and
      .build.profile == "release" and
      .build.rustflags == "-Dwarnings" and
      .build.locked == true and
      .build.packages == ["gta-claw-cli", "gta-claw-daemon"] and
      (.glibcRequirement | test("^[0-9]+\\.[0-9]+(\\.[0-9]+)?$")) and
      .runtimeManifest.path == "runtime/runtime-manifest.json" and
      (.runtimeManifest.sha256 | test("^[0-9a-f]{64}$"))
    ' "$manifest" >/dev/null || die "build manifest contract is invalid"
  if [[ -n "${PACKAGING_IMAGE_ID:-}" ]]; then
    [[ "$(jq -er '.builder.environmentImageId' "$manifest")" == \
      "$PACKAGING_IMAGE_ID" ]] ||
      die "packaging container image differs from authenticated build environment"
  fi
    [[ "$(jq -er '.builder.recipeSha256' "$manifest")" == \
      "$(sha256_file "$LINUX_DIR/Dockerfile.build")" ]] ||
      die "build recipe digest does not match current Dockerfile.build"

  git -C "$REPO_ROOT" diff --quiet
  git -C "$REPO_ROOT" diff --cached --quiet
  source_status="$(git -C "$REPO_ROOT" status --porcelain --untracked-files=all)"
  [[ -z "$source_status" ]] || die "current source worktree is dirty: $source_status"
  BUILD_SOURCE_SHA="$(jq -er '.source.commit' "$manifest")"
  BUILD_SOURCE_TREE="$(jq -er '.source.tree' "$manifest")"
  [[ "$BUILD_SOURCE_SHA" == "$(git -C "$REPO_ROOT" rev-parse HEAD)" ]] ||
    die "build source commit does not match current HEAD"
  [[ "$BUILD_SOURCE_TREE" == "$(git -C "$REPO_ROOT" rev-parse 'HEAD^{tree}')" ]] ||
    die "build source tree does not match current HEAD"
  [[ "$(jq -er '.source.sourceDateEpoch' "$manifest")" == "$SOURCE_DATE_EPOCH" ]] ||
    die "build source epoch does not match current commit"

  BUILD_GLIBC_REQUIREMENT="$(jq -er '.glibcRequirement' "$manifest")"
  if ! printf '%s\n%s\n' "$BUILD_GLIBC_REQUIREMENT" "$LINUX_GLIBC_CEILING" | sort -VC; then
    die "build manifest GLIBC requirement exceeds pinned ceiling"
  fi

  for binary_name in "$LINUX_DAEMON_NAME" "$LINUX_CLI_NAME"; do
    binary_relative="$(
      jq -er --arg name "$binary_name" '
        .binaries | map(select(.name == $name)) |
        if length == 1 then .[0].path else error("binary entry") end
      ' "$manifest"
    )"
    [[ "$binary_relative" == "$target/release/$binary_name" ]] ||
      die "unexpected binary path in build manifest: $binary_relative"
    binary="$build_root/$binary_relative"
    assert_no_symlink_components "$build_root" "$binary"
    assert_regular_file "$binary" "built binary"
    expected_sha="$(
      jq -er --arg name "$binary_name" '
        .binaries | map(select(.name == $name)) | .[0].sha256
      ' "$manifest"
    )"
    [[ "$(sha256_file "$binary")" == "$expected_sha" ]] ||
      die "built binary digest does not match manifest: $binary_name"
    validate_elf_binary "$binary" "$arch"
    case "$binary_name" in
      "$LINUX_DAEMON_NAME") BUILD_DAEMON_BINARY="$binary" ;;
      "$LINUX_CLI_NAME") BUILD_CLI_BINARY="$binary" ;;
    esac
  done

  [[ "$BUILD_GLIBC_REQUIREMENT" == "$(
    {
      max_glibc_version "$BUILD_DAEMON_BINARY"
      max_glibc_version "$BUILD_CLI_BINARY"
    } | sort -V | tail -1
  )" ]] || die "manifest GLIBC requirement does not match ELF symbols"

  runtime_relative="$(jq -er '.runtimeManifest.path' "$manifest")"
  BUILD_RUNTIME_MANIFEST="$build_root/$runtime_relative"
  assert_no_symlink_components "$build_root" "$BUILD_RUNTIME_MANIFEST"
  assert_regular_unaliased "$BUILD_RUNTIME_MANIFEST" "runtime manifest"
  [[ "$(sha256_file "$BUILD_RUNTIME_MANIFEST")" == \
    "$(jq -er '.runtimeManifest.sha256' "$manifest")" ]] ||
    die "runtime manifest digest does not match build manifest"
  jq -e --arg arch "$arch" --arg target "$target" '
    .schemaVersion == 1 and
    .architecture == $arch and
    .rustTarget == $target and
    ([.packages[].id] | sort) == ["libc6", "libgcc-s1"]
  ' "$BUILD_RUNTIME_MANIFEST" >/dev/null || die "runtime manifest contract is invalid"
  case "$arch" in
    x86_64)
      expected_runtime_set=$'libc6\t/lib64/ld-linux-x86-64.so.2\nlibc6\t/lib/x86_64-linux-gnu/libc.so.6\nlibgcc-s1\t/lib/x86_64-linux-gnu/libgcc_s.so.1'
      ;;
    arm64)
      expected_runtime_set=$'libc6\t/lib/ld-linux-aarch64.so.1\nlibc6\t/lib/aarch64-linux-gnu/libc.so.6\nlibgcc-s1\t/lib/aarch64-linux-gnu/libgcc_s.so.1'
      ;;
  esac
  [[ "$(
    jq -r '.packages[] as $package | $package.files[] | [$package.id, .targetPath] | @tsv' \
      "$BUILD_RUNTIME_MANIFEST" |
      LC_ALL=C sort
  )" == "$(LC_ALL=C sort <<<"$expected_runtime_set")" ]] ||
    die "runtime manifest does not contain the exact loader/libc/libgcc set"

  for package_id in libc6 libgcc-s1; do
    case "$arch:$package_id" in
      x86_64:libc6) package_name="libc6:amd64"; package_license="LGPL-2.1-or-later" ;;
      x86_64:libgcc-s1)
        package_name="libgcc-s1:amd64"
        package_license="GPL-3.0-or-later WITH GCC-exception-3.1"
        ;;
      arm64:libc6) package_name="libc6-arm64-cross"; package_license="LGPL-2.1-or-later" ;;
      arm64:libgcc-s1)
        package_name="libgcc-s1-arm64-cross"
        package_license="GPL-3.0-or-later WITH GCC-exception-3.1"
        ;;
    esac
    jq -e \
      --arg id "$package_id" \
      --arg package "$package_name" \
      --arg license "$package_license" \
      '
        .packages | map(select(.id == $id)) |
        length == 1 and
        .[0].dpkgPackage == $package and
        .[0].licenseExpression == $license and
        (.[0].version | length > 0) and
        (.[0].architecture | length > 0) and
        (.[0].licenseMaterials | length == (
          if $id == "libc6" then 3 else 2 end
        ))
      ' "$BUILD_RUNTIME_MANIFEST" >/dev/null ||
      die "runtime package metadata is invalid: $package_id"
    case "$package_id" in
      libc6)
        expected_material_set=$'GPL-2\t/usr/share/licenses/libc6/GPL-2\nLGPL-2.1\t/usr/share/licenses/libc6/LGPL-2.1\ncopyright\t/usr/share/licenses/libc6/copyright'
        ;;
      libgcc-s1)
        expected_material_set=$'GPL-3\t/usr/share/licenses/libgcc-s1/GPL-3\ncopyright\t/usr/share/licenses/libgcc-s1/copyright'
        ;;
    esac
    actual_material_set="$(
      jq -r --arg id "$package_id" '
        .packages[] | select(.id == $id) | .licenseMaterials[] |
        [.name, .targetPath] | @tsv
      ' "$BUILD_RUNTIME_MANIFEST" |
        LC_ALL=C sort
    )"
    [[ "$actual_material_set" == "$(LC_ALL=C sort <<<"$expected_material_set")" ]] ||
      die "runtime license material set is invalid: $package_id"
  done

  while IFS=$'\t' read -r \
    package_id material_name material_source material_staged material_target \
    material_sha material_mode material_encoding material_provider \
    material_provider_version material_provider_arch; do
    [[ "$material_staged" =~ ^runtime/licenses/[A-Za-z0-9._-]+$ ]] ||
      die "unsafe staged license material path: $material_staged"
    validate_absolute_path "$material_target" "license material target"
    validate_absolute_path "$material_source" "license material source"
    [[ "$material_mode" == "0644" ]] || die "license material mode must be 0644"
    [[ "$material_encoding" == "identity" || "$material_encoding" == "gzip" ]] ||
      die "license material encoding is invalid"
    [[ "$material_sha" =~ ^[0-9a-f]{64}$ ]] ||
      die "license material digest is invalid"
    [[ "$(dpkg-query -W -f='${Version}' "$material_provider")" == \
      "$material_provider_version" &&
      "$(dpkg-query -W -f='${Architecture}' "$material_provider")" == \
        "$material_provider_arch" ]] ||
      die "license material provider metadata is invalid: $material_name"
    [[ "$(dpkg-query -S "$material_source" | head -1)" == "$material_provider: "* ]] ||
      die "license material provider does not own source: $material_name"
    runtime_file="$build_root/$material_staged"
    assert_regular_unaliased "$runtime_file" "runtime license material"
    [[ "$(sha256_file "$runtime_file")" == "$material_sha" ]] ||
      die "runtime license material digest mismatch: $material_name"
    if [[ "$package_id" == "libgcc-s1" && "$material_name" == "copyright" ]]; then
      grep -F 'GCC RUNTIME LIBRARY EXCEPTION' "$runtime_file" >/dev/null ||
        die "libgcc copyright file lacks the complete runtime exception text"
    fi
  done < <(
    jq -r '
      .packages[].licenseMaterials[] |
      [
        .packageId, .name, .sourcePath, .stagedPath, .targetPath, .sha256,
        .mode, .contentEncoding, .providerPackage, .providerVersion,
        .providerArchitecture
      ] | @tsv
    ' "$BUILD_RUNTIME_MANIFEST"
  )

  while IFS=$'\t' read -r package_id staged_relative target_path expected_sha mode; do
    [[ "$staged_relative" =~ ^runtime/rootfs/[A-Za-z0-9._/-]+$ &&
      "$staged_relative" != *".."* ]] ||
      die "unsafe staged runtime path: $staged_relative"
    validate_absolute_path "$target_path" "runtime target path"
    [[ "$mode" == "0755" ]] || die "runtime file mode must be 0755"
    case "$arch:$package_id:$target_path" in
      x86_64:libc6:/lib64/ld-linux-x86-64.so.2|\
        x86_64:libc6:/lib/x86_64-linux-gnu/libc.so.6|\
        x86_64:libgcc-s1:/lib/x86_64-linux-gnu/libgcc_s.so.1|\
        arm64:libc6:/lib/ld-linux-aarch64.so.1|\
        arm64:libc6:/lib/aarch64-linux-gnu/libc.so.6|\
        arm64:libgcc-s1:/lib/aarch64-linux-gnu/libgcc_s.so.1) ;;
      *) die "unexpected runtime package target: $package_id:$target_path" ;;
    esac
    runtime_file="$build_root/$staged_relative"
    assert_no_symlink_components "$build_root" "$runtime_file"
    assert_regular_unaliased "$runtime_file" "staged runtime file"
    [[ "$(sha256_file "$runtime_file")" == "$expected_sha" ]] ||
      die "staged runtime file digest mismatch: $staged_relative"
  done < <(
    jq -r '
      .packages[] as $package |
      $package.files[] |
      [$package.id, .stagedPath, .targetPath, .sha256, .mode] |
      @tsv
    ' "$BUILD_RUNTIME_MANIFEST"
  )

  # shellcheck disable=SC2034
  BUILD_ROOT="$build_root"
  # shellcheck disable=SC2034
  BUILD_MANIFEST="$manifest"
  # shellcheck disable=SC2034
  BUILD_PUBLIC_KEY_FINGERPRINT="$expected_public_key_sha"
}
