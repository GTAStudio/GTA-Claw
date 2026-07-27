#!/usr/bin/env bash

validate_published_native_archive() {
  local archive="$1"
  local arch="$2"
  local validation_root="$3"
  local expected_build_manifest="$4"
  local expected_build_key_sha="$5"
  local base_name="$LINUX_PACKAGE_NAME-$VERSION-linux-$arch"
  local extract_root="$validation_root/extracted"
  local published_root="$extract_root/$base_name"
  local archive_sha
  local listing
  local expected_files
  local actual_files
  local binary_name
  local binary
  local expected_sha

  [[ "${PACKAGING_IMAGE_ID:-}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    die "PACKAGING_IMAGE_ID must identify the pinned packaging container"
  assert_regular_unaliased "$archive" "published native archive"
  verify_build_manifest "$expected_build_manifest" "$arch" "$expected_build_key_sha"
  archive_sha="$(sha256_file "$archive")"
  [[ ! -e "$validation_root" && ! -L "$validation_root" ]] ||
    die "native archive validation root must be new"
  create_private_validation_directory "$validation_root"
  create_private_validation_directory "$extract_root"
  validate_archive_entries "$archive" gzip

  listing="$(tar --quoting-style=escape -tzf "$archive")"
  [[ "$(awk -F/ 'NF { print $1 }' <<<"$listing" | LC_ALL=C sort -u)" == \
    "$base_name" ]] || die "native archive has an unexpected top-level directory"
  if tar --numeric-owner -tvzf "$archive" |
    awk '$2 != "0/0" { bad = 1 } END { exit !bad }'; then
    die "native archive contains non-root ownership"
  fi
  (
    umask 000
    tar \
      -xzf "$archive" \
      -C "$extract_root" \
      --no-overwrite-dir \
      --no-same-owner \
      --numeric-owner
  )
  [[ "$(sha256_file "$archive")" == "$archive_sha" ]] ||
    die "published native archive changed during extraction"
  [[ -d "$published_root" && ! -L "$published_root" ]] ||
    die "published native archive root is missing"
  reject_links_and_special_files "$published_root"

  expected_files="$(
    printf '%s\n' \
      "bin/$LINUX_CLI_NAME" \
      "bin/$LINUX_DAEMON_NAME" \
      provenance.json \
      sbom.spdx.json \
      SHA256SUMS \
      share/doc/gta-claw/LICENSE.txt \
      share/doc/gta-claw/NOTICE.txt \
      share/doc/gta-claw/README.md \
      share/doc/gta-claw/build-manifest.json \
      share/doc/gta-claw/gta-claw-daemon.socket.deferred \
      share/doc/gta-claw/package-toolchain.json \
      share/doc/gta-claw/runtime-manifest.json |
      LC_ALL=C sort
  )"
  actual_files="$(find "$published_root" -type f -printf '%P\n' | LC_ALL=C sort)"
  [[ "$actual_files" == "$expected_files" ]] ||
    die "published native archive differs from the exact file contract"

  verify_sha256_manifest "$published_root" "$published_root/SHA256SUMS"
  for document in \
    provenance.json \
    sbom.spdx.json \
    share/doc/gta-claw/build-manifest.json \
    share/doc/gta-claw/package-toolchain.json \
    share/doc/gta-claw/runtime-manifest.json; do
    python3 "$LINUX_DIR/strict_artifact.py" json "$published_root/$document" >/dev/null
  done
  [[ "$(sha256_file "$published_root/share/doc/gta-claw/build-manifest.json")" == \
    "$(sha256_file "$BUILD_MANIFEST")" ]] ||
    die "published native build manifest differs from authenticated build manifest"
  [[ "$(sha256_file "$published_root/share/doc/gta-claw/runtime-manifest.json")" == \
    "$(sha256_file "$BUILD_RUNTIME_MANIFEST")" ]] ||
    die "published native runtime manifest differs from authenticated runtime manifest"
  jq -e \
    --arg manifest_sha "$(sha256_file "$BUILD_MANIFEST")" \
    --slurpfile toolchain "$published_root/share/doc/gta-claw/package-toolchain.json" \
    '
      .predicate.buildDefinition.buildManifest.digest.sha256 == $manifest_sha and
      .predicate.buildDefinition.packageToolchain == $toolchain[0]
    ' "$published_root/provenance.json" >/dev/null ||
    die "published native provenance does not bind its build and package toolchains"
  jq -e \
    --arg image "$LINUX_BUILD_IMAGE" \
    --arg snapshot "$LINUX_DEBIAN_SNAPSHOT" \
    --arg dpkg "$(dpkg-query -W -f='${Version}' dpkg)" \
    --arg rpm "$(dpkg-query -W -f='${Version}' rpm)" \
    '
      .image == $image and
      .environmentImageId == env.PACKAGING_IMAGE_ID and
      .debianSnapshot == $snapshot and
      .packages.dpkg == $dpkg and
      .packages.rpm == $rpm
    ' "$published_root/share/doc/gta-claw/package-toolchain.json" >/dev/null ||
    die "published native package toolchain provenance is invalid"

  for binary_name in "$LINUX_DAEMON_NAME" "$LINUX_CLI_NAME"; do
    binary="$published_root/bin/$binary_name"
    expected_sha="$(
      jq -er --arg name "$binary_name" '
        .binaries[] | select(.name == $name) | .sha256
      ' "$BUILD_MANIFEST"
    )"
    [[ "$(sha256_file "$binary")" == "$expected_sha" ]] ||
      die "published native $binary_name differs from authenticated build"
    [[ "$(stat -c '%a' "$binary")" == "755" ]] ||
      die "published native $binary_name mode mismatch"
    validate_elf_binary "$binary" "$arch"
    jq -e \
      --arg path "bin/$binary_name" \
      --arg sha "$expected_sha" \
      '
        (.subject | map(select(
          .name == $path and .digest.sha256 == $sha
        )) | length) == 1
      ' "$published_root/provenance.json" >/dev/null ||
      die "published native provenance does not bind $binary_name"
    jq -e \
      --arg path "./bin/$binary_name" \
      --arg sha "$expected_sha" \
      '
        (.files | map(select(
          .fileName == $path and
          any(.checksums[];
            .algorithm == "SHA256" and .checksumValue == $sha
          )
        )) | length) == 1
      ' "$published_root/sbom.spdx.json" >/dev/null ||
      die "published native SBOM does not bind $binary_name"
  done
  reject_forbidden_runtime_content "$published_root"
}
