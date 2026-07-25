#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/build-manifest.sh"

require_linux
[[ "${SAFEIO_ACTIVE:-0}" == "1" ]] ||
  die "package.sh is internal; use package-container.sh for directory-FD confinement"
for tool in \
  awk date dpkg-deb dpkg-query du find gzip jq md5sum python3 readelf rpm \
  rpmbuild sed sha1sum sha256sum stat tar wc; do
  require_tool "$tool"
done
[[ "$#" -eq 3 ]] || die "usage: package.sh ARCH BUILD_MANIFEST EXPECTED_BUILD_KEY_SHA256"
arch="$1"
input_manifest="$2"
expected_build_key_sha="$3"
: "${PACKAGING_IMAGE_ID:?PACKAGING_IMAGE_ID is required}"
validate_safe_component "$arch" "architecture"
verify_build_manifest "$input_manifest" "$arch" "$expected_build_key_sha"
daemon_binary="$BUILD_DAEMON_BINARY"
cli_binary="$BUILD_CLI_BINARY"

initialize_output_root
ARTIFACT_DIR="$OUTPUT_ROOT/artifacts"
WORK_DIR="$OUTPUT_ROOT/work"
ensure_output_directory "$ARTIFACT_DIR"
ensure_output_directory "$WORK_DIR"

source_sha="$BUILD_SOURCE_SHA"
source_tree="$BUILD_SOURCE_TREE"
build_manifest_sha="$(sha256_file "$BUILD_MANIFEST")"
created_at="$(date -u --date="@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
target="$(arch_target "$arch")"
deb_architecture="$(deb_arch "$arch")"
rpm_architecture="$(rpm_arch "$arch")"
oci_architecture="$(oci_arch "$arch")"
base_name="$LINUX_PACKAGE_NAME-$VERSION-linux-$arch"
validate_oci_orchestration_templates \
  "$LINUX_DIR/oci/compose.yaml.in" \
  "$LINUX_DIR/oci/kubernetes.yaml.in"

write_json() {
  local output="$1"
  shift
  ensure_output_directory "$(dirname "$output")"
  open_output_file "$output" 0644
  jq -S "$@" >&"$OPEN_OUTPUT_FD"
  finish_output_file
}

package_toolchain="$WORK_DIR/package-toolchain.json"
write_json "$package_toolchain" -n \
  --arg image "$LINUX_BUILD_IMAGE" \
  --arg environment_image_id "$PACKAGING_IMAGE_ID" \
  --arg snapshot "$LINUX_DEBIAN_SNAPSHOT" \
  --arg dpkg "$(dpkg-query -W -f='${Version}' dpkg)" \
  --arg rpm "$(dpkg-query -W -f='${Version}' rpm)" \
  --arg tar "$(dpkg-query -W -f='${Version}' tar)" \
  --arg gzip "$(dpkg-query -W -f='${Version}' gzip)" \
  --arg jq "$(dpkg-query -W -f='${Version}' jq)" \
  --arg python3 "$(dpkg-query -W -f='${Version}' python3)" \
  --arg cpio "$(dpkg-query -W -f='${Version}' cpio)" \
  '{
    schemaVersion: 1,
    image: $image,
    environmentImageId: $environment_image_id,
    debianSnapshot: $snapshot,
    packages: {
      dpkg: $dpkg,
      rpm: $rpm,
      tar: $tar,
      gzip: $gzip,
      jq: $jq,
      python3: $python3,
      cpio: $cpio
    }
  }'

generate_provenance() {
  local root="$1"
  local output="$2"
  local daemon_path="$3"
  local cli_path="$4"
  write_json "$output" -n \
    --slurpfile build_manifest "$BUILD_MANIFEST" \
    --slurpfile runtime_manifest "$BUILD_RUNTIME_MANIFEST" \
    --slurpfile package_toolchain "$package_toolchain" \
    --arg source_sha "$source_sha" \
    --arg source_tree "$source_tree" \
    --arg build_manifest_sha "$build_manifest_sha" \
    --arg source_epoch "$SOURCE_DATE_EPOCH" \
    --arg version "$VERSION" \
    --arg arch "$arch" \
    --arg target "$target" \
    --arg daemon_path "$daemon_path" \
    --arg daemon_sha "$(sha256_file "$root/$daemon_path")" \
    --arg cli_path "$cli_path" \
    --arg cli_sha "$(sha256_file "$root/$cli_path")" \
    '{
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [
        {"name": $daemon_path, "digest": {"sha256": $daemon_sha}},
        {"name": $cli_path, "digest": {"sha256": $cli_sha}}
      ],
      "predicateType": "https://slsa.dev/provenance/v1",
      "predicate": {
        "buildDefinition": {
          "buildType": "https://github.com/GTAStudio/GTA-Claw/packaging/linux/v1",
          "externalParameters": {
            "architecture": $arch,
            "rustTarget": $target,
            "version": $version
          },
          "internalParameters": {
            "sourceDateEpoch": ($source_epoch | tonumber)
          },
          "resolvedDependencies": [{
            "uri": ("git+https://github.com/GTAStudio/GTA-Claw.git@" + $source_sha),
            "digest": {"gitCommit": $source_sha, "gitTree": $source_tree}
          }],
          "buildManifest": {
            "digest": {"sha256": $build_manifest_sha},
            "content": $build_manifest[0]
          },
          "runtimeDependencies": $runtime_manifest[0].packages
          ,"packageToolchain": $package_toolchain[0]
        },
        "runDetails": {
          "builder": {
            "id": ("https://github.com/GTAStudio/GTA-Claw/blob/" + $source_sha + "/packaging/linux/package.sh")
          }
        }
      }
    }'
}

generate_spdx() {
  local root="$1"
  local output="$2"
  local label="$3"
  local list="$WORK_DIR/spdx-$label.ndjson"
  local relative
  local index=0
  local owner
  local path
  local file_license
  local sha1
  local gta_verification
  local libc_verification
  local libgcc_verification
  local libc_version
  local libc_arch
  local libgcc_version
  local libgcc_arch
  local sbom_relative
  local checksum_relative
  libc_version="$(jq -er '.packages[] | select(.id == "libc6") | .version' "$BUILD_RUNTIME_MANIFEST")"
  libc_arch="$(jq -er '.packages[] | select(.id == "libc6") | .architecture' "$BUILD_RUNTIME_MANIFEST")"
  libgcc_version="$(jq -er '.packages[] | select(.id == "libgcc-s1") | .version' "$BUILD_RUNTIME_MANIFEST")"
  libgcc_arch="$(jq -er '.packages[] | select(.id == "libgcc-s1") | .architecture' "$BUILD_RUNTIME_MANIFEST")"
  sbom_relative="./${output#"$root/"}"
  checksum_relative="$(dirname "$sbom_relative")/SHA256SUMS"
  open_output_file "$list" 0644
  while IFS= read -r -d '' relative; do
    [[ "$root/$relative" != "$output" ]] || continue
    index=$((index + 1))
    path="/${relative#./}"
    owner="gta-claw"
    if [[ "$label" == "oci" ]]; then
      owner="$(
        jq -r --arg path "$path" '
          [
            .packages[] |
            select(
              any(.files[]; .targetPath == $path) or
              any(.licenseMaterials[]; .targetPath == $path)
            ) |
            .id
          ][0] // "gta-claw"
        ' "$BUILD_RUNTIME_MANIFEST"
      )"
    fi
    case "$owner" in
      libc6) file_license="LGPL-2.1-or-later" ;;
      libgcc-s1) file_license="GPL-3.0-or-later WITH GCC-exception-3.1" ;;
      *) file_license="MIT" ;;
    esac
    sha1="$(sha1sum "$root/$relative" | awk '{ print $1 }')"
    jq -c -n \
      --arg id "SPDXRef-File-$index" \
      --arg name "./${relative#./}" \
      --arg owner "$owner" \
      --arg license "$file_license" \
      --arg sha1 "$sha1" \
      --arg sha "$(sha256_file "$root/$relative")" \
      '{
        SPDXID: $id,
        owner: $owner,
        fileName: $name,
        checksums: [
          {algorithm: "SHA1", checksumValue: $sha1},
          {algorithm: "SHA256", checksumValue: $sha}
        ],
        licenseConcluded: $license,
        licenseInfoInFiles: [$license],
        copyrightText: "NOASSERTION"
      }' >&"$OPEN_OUTPUT_FD"
  done < <(cd "$root" && find . -type f -print0 | LC_ALL=C sort -z)
  finish_output_file
  package_verification() {
    local package="$1"
    jq -r '
      select(.owner == $package) |
      .checksums[] |
      select(.algorithm == "SHA1") |
      .checksumValue
    ' --arg package "$package" "$list" |
      LC_ALL=C sort |
      tr -d '\n' |
      sha1sum |
      awk '{ print $1 }'
  }
  gta_verification="$(package_verification gta-claw)"
  if grep -F '"owner":"libc6"' "$list" >/dev/null; then
    libc_verification="$(package_verification libc6)"
  else
    libc_verification=""
  fi
  if grep -F '"owner":"libgcc-s1"' "$list" >/dev/null; then
    libgcc_verification="$(package_verification libgcc-s1)"
  else
    libgcc_verification=""
  fi
  write_json "$output" -n \
    --slurpfile records "$list" \
    --arg gta_verification "$gta_verification" \
    --arg libc_verification "$libc_verification" \
    --arg libgcc_verification "$libgcc_verification" \
    --arg libc_version "$libc_version" \
    --arg libc_arch "$libc_arch" \
    --arg libgcc_version "$libgcc_version" \
    --arg libgcc_arch "$libgcc_arch" \
    --arg sbom_relative "$sbom_relative" \
    --arg checksum_relative "$checksum_relative" \
    --arg namespace "https://github.com/GTAStudio/GTA-Claw/spdx/$source_sha/$arch/$label" \
    --arg created "$created_at" \
    --arg version "$VERSION" \
    --arg source_sha "$source_sha" \
    '{
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: "gta-claw-linux-headless",
      documentNamespace: $namespace,
      creationInfo: {
        created: $created,
        creators: ["Tool: packaging/linux/package.sh"]
      },
      packages: [
        {
          SPDXID: "SPDXRef-Package-GTA-Claw",
          name: "gta-claw",
          versionInfo: $version,
          downloadLocation: "NOASSERTION",
          filesAnalyzed: true,
          packageVerificationCode: {
            packageVerificationCodeValue: $gta_verification,
            packageVerificationCodeExcludedFiles: [
              $sbom_relative,
              $checksum_relative
            ]
          },
          licenseConcluded: "MIT",
          licenseDeclared: "MIT",
          copyrightText: "NOASSERTION",
          externalRefs: [{
            referenceCategory: "PACKAGE-MANAGER",
            referenceType: "purl",
            referenceLocator: ("pkg:github/GTAStudio/GTA-Claw@" + $source_sha)
          }]
        },
        ({
          SPDXID: "SPDXRef-Package-libc6",
          name: "libc6",
          versionInfo: $libc_version,
          comment: ("Debian architecture: " + $libc_arch),
          supplier: "Organization: Debian",
          downloadLocation: "NOASSERTION",
          filesAnalyzed: ($libc_verification != ""),
          licenseConcluded: "LGPL-2.1-or-later",
          licenseDeclared: "LGPL-2.1-or-later",
          copyrightText: "NOASSERTION"
        } + if $libc_verification == "" then {} else {
          packageVerificationCode: {packageVerificationCodeValue: $libc_verification}
        } end),
        ({
          SPDXID: "SPDXRef-Package-libgcc-s1",
          name: "libgcc-s1",
          versionInfo: $libgcc_version,
          comment: ("Debian architecture: " + $libgcc_arch),
          supplier: "Organization: Debian",
          downloadLocation: "NOASSERTION",
          filesAnalyzed: ($libgcc_verification != ""),
          licenseConcluded: "GPL-3.0-or-later WITH GCC-exception-3.1",
          licenseDeclared: "GPL-3.0-or-later WITH GCC-exception-3.1",
          copyrightText: "NOASSERTION"
        } + if $libgcc_verification == "" then {} else {
          packageVerificationCode: {packageVerificationCodeValue: $libgcc_verification}
        } end)
      ],
      files: ($records | map(del(.owner))),
      relationships: (
        [
          {
            spdxElementId: "SPDXRef-DOCUMENT",
            relationshipType: "DESCRIBES",
            relatedSpdxElement: "SPDXRef-Package-GTA-Claw"
          },
          {
            spdxElementId: "SPDXRef-Package-GTA-Claw",
            relationshipType: "DEPENDS_ON",
            relatedSpdxElement: "SPDXRef-Package-libc6"
          },
          {
            spdxElementId: "SPDXRef-Package-GTA-Claw",
            relationshipType: "DEPENDS_ON",
            relatedSpdxElement: "SPDXRef-Package-libgcc-s1"
          }
        ] + (
          $records |
          map({
            spdxElementId: (
              if .owner == "libc6" then "SPDXRef-Package-libc6"
              elif .owner == "libgcc-s1" then "SPDXRef-Package-libgcc-s1"
              else "SPDXRef-Package-GTA-Claw"
              end
            ),
            relationshipType: "CONTAINS",
            relatedSpdxElement: .SPDXID
          })
        )
      )
    }'
}

stage_documentation() {
  local destination="$1"
  copy_regular_input "$LINUX_DIR/LICENSE.txt" "$destination/LICENSE.txt" 0644
  copy_regular_input "$LINUX_DIR/NOTICE.txt" "$destination/NOTICE.txt" 0644
  copy_regular_input "$LINUX_DIR/README.md" "$destination/README.md" 0644
  copy_verified_input "$BUILD_MANIFEST" "$destination/build-manifest.json" 0644
  copy_verified_input \
    "$BUILD_RUNTIME_MANIFEST" \
    "$destination/runtime-manifest.json" \
    0644
  copy_regular_input \
    "$package_toolchain" \
    "$destination/package-toolchain.json" \
    0644
  copy_regular_input \
    "$LINUX_DIR/systemd/gta-claw-daemon.socket.deferred" \
    "$destination/gta-claw-daemon.socket.deferred" \
    0644
}

archive_stage="$WORK_DIR/archive/$base_name"
ensure_output_directory "$archive_stage/bin"
ensure_output_directory "$archive_stage/etc/gta-claw/credentials"
ensure_output_directory "$archive_stage/lib/systemd/system"
ensure_output_directory "$archive_stage/lib/systemd/system-preset"
ensure_output_directory "$archive_stage/lib/sysusers.d"
ensure_output_directory "$archive_stage/libexec"
ensure_output_directory "$archive_stage/share/doc/gta-claw"
copy_verified_input "$daemon_binary" "$archive_stage/bin/$LINUX_DAEMON_NAME" 0755
copy_verified_input "$cli_binary" "$archive_stage/bin/$LINUX_CLI_NAME" 0755
copy_regular_input "$LINUX_DIR/direct/install.sh" "$archive_stage/install.sh" 0755
copy_regular_input "$LINUX_DIR/direct/uninstall.sh" "$archive_stage/uninstall.sh" 0755
write_output_text \
  "$archive_stage/package-version" \
  0644 \
  "$VERSION-$LINUX_PACKAGE_RELEASE"$'\n'
copy_regular_input \
  "$LINUX_DIR/libexec/gta-claw-state-init" \
  "$archive_stage/libexec/gta-claw-state-init" \
  0755
copy_regular_input \
  "$LINUX_DIR/libexec/gta-claw-runtime-ready" \
  "$archive_stage/libexec/gta-claw-runtime-ready" \
  0755
copy_regular_input \
  "$LINUX_DIR/systemd/gta-claw-daemon.service" \
  "$archive_stage/lib/systemd/system/gta-claw-daemon.service" \
  0644
copy_regular_input \
  "$LINUX_DIR/systemd/gta-claw-state-init.service" \
  "$archive_stage/lib/systemd/system/gta-claw-state-init.service" \
  0644
copy_regular_input \
  "$LINUX_DIR/systemd/80-gta-claw.preset" \
  "$archive_stage/lib/systemd/system-preset/80-gta-claw.preset" \
  0644
copy_regular_input \
  "$LINUX_DIR/sysusers/gta-claw.conf" \
  "$archive_stage/lib/sysusers.d/gta-claw.conf" \
  0644
copy_regular_input \
  "$LINUX_DIR/systemd/gta-claw.env" \
  "$archive_stage/etc/gta-claw/gta-claw.env" \
  0640
copy_regular_input \
  "$LINUX_DIR/systemd/daemon.conf" \
  "$archive_stage/etc/gta-claw/credentials/daemon.conf" \
  0600
stage_documentation "$archive_stage/share/doc/gta-claw"
generate_provenance \
  "$archive_stage" \
  "$archive_stage/provenance.json" \
  "bin/$LINUX_DAEMON_NAME" \
  "bin/$LINUX_CLI_NAME"
generate_spdx "$archive_stage" "$archive_stage/sbom.spdx.json" "native-tar"
write_sha256_manifest "$archive_stage" "$archive_stage/SHA256SUMS"
normalize_tree "$archive_stage"
chmod 0755 \
  "$archive_stage/bin/$LINUX_DAEMON_NAME" \
  "$archive_stage/bin/$LINUX_CLI_NAME" \
  "$archive_stage/install.sh" \
  "$archive_stage/uninstall.sh" \
  "$archive_stage/libexec/gta-claw-state-init" \
  "$archive_stage/libexec/gta-claw-runtime-ready"
chmod 0640 "$archive_stage/etc/gta-claw/gta-claw.env"
chmod 0600 "$archive_stage/etc/gta-claw/credentials/daemon.conf"
validate_service_contract \
  "$archive_stage/lib/systemd/system/gta-claw-daemon.service"
validate_initializer_service_contract \
  "$archive_stage/lib/systemd/system/gta-claw-state-init.service"
validate_sysusers_contract "$archive_stage/lib/sysusers.d/gta-claw.conf"
validate_initializer_wrapper_contract "$archive_stage/libexec/gta-claw-state-init"
validate_runtime_ready_contract "$archive_stage/libexec/gta-claw-runtime-ready"
validate_direct_lifecycle_contract \
  "$archive_stage/install.sh" \
  "$archive_stage/uninstall.sh"
tar_artifact="$ARTIFACT_DIR/$base_name.tar.gz"
create_deterministic_tar_gz "$(dirname "$archive_stage")" "$(basename "$archive_stage")" "$tar_artifact"

rootfs="$WORK_DIR/rootfs"
ensure_output_directory "$rootfs/usr/bin"
ensure_output_directory "$rootfs/usr/libexec/gta-claw"
ensure_output_directory "$rootfs/usr/lib/systemd/system"
ensure_output_directory "$rootfs/usr/lib/systemd/system-preset"
ensure_output_directory "$rootfs/usr/lib/sysusers.d"
ensure_output_directory "$rootfs/usr/share/doc/gta-claw"
ensure_output_directory "$rootfs/etc/gta-claw/credentials"
copy_verified_input "$cli_binary" "$rootfs/usr/bin/$LINUX_CLI_NAME" 0755
copy_verified_input \
  "$daemon_binary" \
  "$rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME" \
  0755
copy_regular_input \
  "$LINUX_DIR/systemd/gta-claw-daemon.service" \
  "$rootfs/usr/lib/systemd/system/gta-claw-daemon.service" \
  0644
copy_regular_input \
  "$LINUX_DIR/systemd/gta-claw-state-init.service" \
  "$rootfs/usr/lib/systemd/system/gta-claw-state-init.service" \
  0644
copy_regular_input \
  "$LINUX_DIR/systemd/80-gta-claw.preset" \
  "$rootfs/usr/lib/systemd/system-preset/80-gta-claw.preset" \
  0644
copy_regular_input \
  "$LINUX_DIR/sysusers/gta-claw.conf" \
  "$rootfs/usr/lib/sysusers.d/gta-claw.conf" \
  0644
copy_regular_input \
  "$LINUX_DIR/libexec/gta-claw-state-init" \
  "$rootfs/usr/libexec/gta-claw/gta-claw-state-init" \
  0755
copy_regular_input \
  "$LINUX_DIR/libexec/gta-claw-runtime-ready" \
  "$rootfs/usr/libexec/gta-claw/gta-claw-runtime-ready" \
  0755
copy_regular_input \
  "$LINUX_DIR/systemd/gta-claw.env" \
  "$rootfs/etc/gta-claw/gta-claw.env" \
  0640
copy_regular_input \
  "$LINUX_DIR/systemd/daemon.conf" \
  "$rootfs/etc/gta-claw/credentials/daemon.conf" \
  0600
stage_documentation "$rootfs/usr/share/doc/gta-claw"
generate_provenance \
  "$rootfs" \
  "$rootfs/usr/share/doc/gta-claw/provenance.json" \
  "usr/libexec/gta-claw/$LINUX_DAEMON_NAME" \
  "usr/bin/$LINUX_CLI_NAME"
generate_spdx \
  "$rootfs" \
  "$rootfs/usr/share/doc/gta-claw/sbom.spdx.json" \
  "native-package"
write_sha256_manifest \
  "$rootfs" \
  "$rootfs/usr/share/doc/gta-claw/SHA256SUMS"
normalize_tree "$rootfs"
chmod 0755 "$rootfs/usr/bin/$LINUX_CLI_NAME"
chmod 0755 "$rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME"
chmod 0755 "$rootfs/usr/libexec/gta-claw/gta-claw-state-init"
chmod 0755 "$rootfs/usr/libexec/gta-claw/gta-claw-runtime-ready"
chmod 0640 "$rootfs/etc/gta-claw/gta-claw.env"
chmod 0600 "$rootfs/etc/gta-claw/credentials/daemon.conf"
validate_service_contract "$rootfs/usr/lib/systemd/system/gta-claw-daemon.service"
validate_initializer_service_contract \
  "$rootfs/usr/lib/systemd/system/gta-claw-state-init.service"
validate_sysusers_contract "$rootfs/usr/lib/sysusers.d/gta-claw.conf"
validate_initializer_wrapper_contract \
  "$rootfs/usr/libexec/gta-claw/gta-claw-state-init"
validate_runtime_ready_contract \
  "$rootfs/usr/libexec/gta-claw/gta-claw-runtime-ready"
reject_forbidden_runtime_content "$rootfs"

deb_root="$WORK_DIR/deb-root"
ensure_output_directory "$deb_root"
cp -a -- "$rootfs/." "$deb_root/"
reject_links_and_special_files "$deb_root"
ensure_output_directory "$deb_root/DEBIAN"
installed_size="$(du -sk "$rootfs" | awk '{ print $1 }')"
control="$deb_root/DEBIAN/control"
open_output_file "$control" 0644
cat >&"$OPEN_OUTPUT_FD" <<EOF
Package: $LINUX_PACKAGE_NAME
Version: $VERSION-$LINUX_PACKAGE_RELEASE
Section: utils
Priority: optional
Architecture: $deb_architecture
Maintainer: GTAStudio <noreply@github.com>
Installed-Size: $installed_size
Depends: libc6 (>= $BUILD_GLIBC_REQUIREMENT), libgcc-s1, systemd (>= 249), util-linux
Homepage: https://github.com/GTAStudio/GTA-Claw
Description: GTA Claw native Rust headless prototype
 Packages gta-claw-daemon and gta-claw-cli without the legacy JavaScript
 runtime or the Slint desktop application. This is not a feature-parity claim.
EOF
finish_output_file
open_output_file "$deb_root/DEBIAN/conffiles" 0644
cat >&"$OPEN_OUTPUT_FD" <<'EOF'
/etc/gta-claw/gta-claw.env
/etc/gta-claw/credentials/daemon.conf
EOF
finish_output_file
open_output_file "$deb_root/DEBIAN/preinst" 0755
sed \
  "s/@PACKAGE_VERSION@/$VERSION-$LINUX_PACKAGE_RELEASE/g" \
  "$LINUX_DIR/debian/preinst.in" \
  >&"$OPEN_OUTPUT_FD"
finish_output_file
copy_regular_input "$LINUX_DIR/debian/postinst" "$deb_root/DEBIAN/postinst" 0755
copy_regular_input "$LINUX_DIR/debian/prerm" "$deb_root/DEBIAN/prerm" 0755
copy_regular_input "$LINUX_DIR/debian/postrm" "$deb_root/DEBIAN/postrm" 0755
open_output_file "$deb_root/DEBIAN/md5sums" 0644
(
  cd "$deb_root"
  find . -path ./DEBIAN -prune -o -type f -print |
    sed 's#^\./##' |
    LC_ALL=C sort |
    xargs md5sum
) >&"$OPEN_OUTPUT_FD"
finish_output_file
normalize_tree "$deb_root"
chmod 0755 "$deb_root/DEBIAN"
chmod 0755 \
  "$deb_root/DEBIAN/preinst" \
  "$deb_root/DEBIAN/postinst" \
  "$deb_root/DEBIAN/prerm" \
  "$deb_root/DEBIAN/postrm"
chmod 0644 "$deb_root/DEBIAN/control" "$deb_root/DEBIAN/conffiles" "$deb_root/DEBIAN/md5sums"
chmod 0640 "$deb_root/etc/gta-claw/gta-claw.env"
chmod 0600 "$deb_root/etc/gta-claw/credentials/daemon.conf"
deb_artifact="$ARTIFACT_DIR/${LINUX_PACKAGE_NAME}_${VERSION}-${LINUX_PACKAGE_RELEASE}_${deb_architecture}.deb"
deb_temporary="$deb_artifact.tmp"
assert_new_output_file "$deb_temporary"
deb_temporary_real="$SAFEIO_OUTPUT_REALPATH/${deb_temporary#"$OUTPUT_ROOT/"}"
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  dpkg-deb \
    --root-owner-group \
    -Zgzip \
    -z9 \
    --build \
    "$deb_root" \
    "$deb_temporary_real"
assert_regular_unaliased "$deb_temporary" "Debian package temporary"
chmod 0644 "$deb_temporary"
touch --date="@$SOURCE_DATE_EPOCH" "$deb_temporary"
publish_output_file "$deb_temporary" "$deb_artifact"

rpm_work="$WORK_DIR/rpm"
ensure_output_directory "$rpm_work/BUILD"
ensure_output_directory "$rpm_work/BUILDROOT"
ensure_output_directory "$rpm_work/RPMS"
ensure_output_directory "$rpm_work/SOURCES"
ensure_output_directory "$rpm_work/SPECS"
ensure_output_directory "$rpm_work/SRPMS"
rpm_source="$rpm_work/SOURCES/gta-claw-rootfs.tar"
rpm_source_temporary="$rpm_source.tmp"
open_output_file "$rpm_source_temporary" 0644
(
  cd "$rootfs"
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
    .
) >&"$OPEN_OUTPUT_FD"
finish_output_file
touch --date="@$SOURCE_DATE_EPOCH" "$rpm_source_temporary"
publish_output_file "$rpm_source_temporary" "$rpm_source"
rpm_spec="$rpm_work/SPECS/gta-claw.spec"
changelog_date="$(LC_ALL=C date -u --date="@$SOURCE_DATE_EPOCH" '+%a %b %d %Y')"
rpm_scriptlet_dir="$WORK_DIR/rpm-scriptlets"
ensure_output_directory "$rpm_scriptlet_dir"
rpm_pre="$rpm_scriptlet_dir/pre"
open_output_file "$rpm_pre" 0755
sed \
  "s/@PACKAGE_VERSION@/$VERSION-$LINUX_PACKAGE_RELEASE/g" \
  "$LINUX_DIR/rpm/pre.in" \
  >&"$OPEN_OUTPUT_FD"
finish_output_file
for scriptlet in post preun posttrans postun; do
  copy_regular_input \
    "$LINUX_DIR/rpm/$scriptlet" \
    "$rpm_scriptlet_dir/$scriptlet" \
    0755
done
open_output_file "$rpm_spec" 0644
cat >&"$OPEN_OUTPUT_FD" <<EOF
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none
%global _buildhost reproducible.invalid
%global use_source_date_epoch_as_buildtime 1
%global clamp_mtime_to_source_date_epoch 1
%global _binary_payload w9.gzdio

Name:           $LINUX_PACKAGE_NAME
Version:        $VERSION
Release:        $LINUX_PACKAGE_RELEASE
Summary:        GTA Claw native Rust headless prototype
License:        MIT
URL:            https://github.com/GTAStudio/GTA-Claw
Source0:        gta-claw-rootfs.tar
Requires:       glibc >= $BUILD_GLIBC_REQUIREMENT
Requires:       libgcc
Requires:       systemd >= 249
Requires:       util-linux

%description
Packages gta-claw-daemon and gta-claw-cli without a JavaScript runtime or
the Slint desktop application. This prototype does not claim feature parity.

%prep

%build

%install
rm -rf "%{buildroot}"
mkdir -p "%{buildroot}"
tar -xf "%{SOURCE0}" -C "%{buildroot}"

%files
%defattr(-,root,root,-)
%config(noreplace) %attr(0640,root,root) /etc/gta-claw/gta-claw.env
%config(noreplace) %attr(0600,root,root) /etc/gta-claw/credentials/daemon.conf
/usr/bin/gta-claw-cli
/usr/libexec/gta-claw/gta-claw-daemon
/usr/libexec/gta-claw/gta-claw-runtime-ready
/usr/libexec/gta-claw/gta-claw-state-init
/usr/lib/systemd/system/gta-claw-daemon.service
/usr/lib/systemd/system/gta-claw-state-init.service
/usr/lib/systemd/system-preset/80-gta-claw.preset
/usr/lib/sysusers.d/gta-claw.conf
/usr/share/doc/gta-claw

%pre
EOF
cat "$rpm_pre" >&"$OPEN_OUTPUT_FD"
printf '\n%%post\n' >&"$OPEN_OUTPUT_FD"
cat "$rpm_scriptlet_dir/post" >&"$OPEN_OUTPUT_FD"
printf '\n%%preun\n' >&"$OPEN_OUTPUT_FD"
cat "$rpm_scriptlet_dir/preun" >&"$OPEN_OUTPUT_FD"
printf '\n%%posttrans\n' >&"$OPEN_OUTPUT_FD"
cat "$rpm_scriptlet_dir/posttrans" >&"$OPEN_OUTPUT_FD"
printf '\n%%postun\n' >&"$OPEN_OUTPUT_FD"
cat "$rpm_scriptlet_dir/postun" >&"$OPEN_OUTPUT_FD"
cat >&"$OPEN_OUTPUT_FD" <<EOF

%changelog
* $changelog_date GTAStudio <noreply@github.com> - $VERSION-$LINUX_PACKAGE_RELEASE
- Deterministic native Rust headless packaging prototype
EOF
finish_output_file
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  rpmbuild \
    -bb \
    --define "_topdir $rpm_work" \
    --define "_source_filedigest_algorithm 8" \
    --define "_binary_filedigest_algorithm 8" \
    --target "$rpm_architecture" \
    "$rpm_spec"
mapfile -t built_rpms < <(find "$rpm_work/RPMS" -type f -name '*.rpm' -print)
[[ "${#built_rpms[@]}" -eq 1 ]] ||
  die "expected exactly one binary RPM, found ${#built_rpms[@]}"
rpm_artifact="$ARTIFACT_DIR/$LINUX_PACKAGE_NAME-$VERSION-$LINUX_PACKAGE_RELEASE.$rpm_architecture.rpm"
rpm_temporary="$rpm_artifact.tmp"
copy_regular_input "${built_rpms[0]}" "$rpm_temporary" 0644
touch --date="@$SOURCE_DATE_EPOCH" "$rpm_temporary"
publish_output_file "$rpm_temporary" "$rpm_artifact"

oci_rootfs="$WORK_DIR/oci-rootfs"
ensure_output_directory "$oci_rootfs/usr/bin"
ensure_output_directory "$oci_rootfs/usr/libexec/gta-claw"
ensure_output_directory "$oci_rootfs/usr/share/doc/gta-claw"
ensure_output_directory "$oci_rootfs/usr/share/licenses/libc6"
ensure_output_directory "$oci_rootfs/usr/share/licenses/libgcc-s1"
ensure_output_directory "$oci_rootfs/etc"
ensure_output_directory "$oci_rootfs/var/lib"
ensure_output_directory "$oci_rootfs/var/cache/gta-claw"
ensure_output_directory "$oci_rootfs/var/log/gta-claw"
ensure_output_directory "$oci_rootfs/run/gta-claw"
copy_verified_input "$cli_binary" "$oci_rootfs/usr/bin/$LINUX_CLI_NAME" 0755
copy_verified_input \
  "$daemon_binary" \
  "$oci_rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME" \
  0755
stage_documentation "$oci_rootfs/usr/share/doc/gta-claw"
write_output_text \
  "$oci_rootfs/etc/passwd" \
  0644 \
  $'root:x:0:0:root:/nonexistent:/sbin/nologin\ngta-claw:x:65532:65532:GTA Claw:/nonexistent:/sbin/nologin\n'
write_output_text \
  "$oci_rootfs/etc/group" \
  0644 \
  $'root:x:0:\ngta-claw:x:65532:\n'
while IFS=$'\t' read -r staged_path target_path mode; do
  [[ "$target_path" == /* ]] || die "runtime target path must be absolute"
  copy_verified_input \
    "$BUILD_ROOT/$staged_path" \
    "$oci_rootfs$target_path" \
    "$mode"
done < <(
  jq -r '.packages[].files[] | [.stagedPath, .targetPath, .mode] | @tsv' \
    "$BUILD_RUNTIME_MANIFEST"
)
while IFS=$'\t' read -r staged_path target_path mode; do
  [[ "$target_path" == /usr/share/licenses/* ]] ||
    die "runtime license target path is outside /usr/share/licenses"
  copy_verified_input \
    "$BUILD_ROOT/$staged_path" \
    "$oci_rootfs$target_path" \
    "$mode"
done < <(
  jq -r '
    .packages[].licenseMaterials[] |
    [.stagedPath, .targetPath, .mode] |
    @tsv
  ' "$BUILD_RUNTIME_MANIFEST"
)
generate_provenance \
  "$oci_rootfs" \
  "$oci_rootfs/usr/share/doc/gta-claw/provenance.json" \
  "usr/libexec/gta-claw/$LINUX_DAEMON_NAME" \
  "usr/bin/$LINUX_CLI_NAME"
generate_spdx \
  "$oci_rootfs" \
  "$oci_rootfs/usr/share/doc/gta-claw/sbom.spdx.json" \
  "oci"
write_sha256_manifest \
  "$oci_rootfs" \
  "$oci_rootfs/usr/share/doc/gta-claw/SHA256SUMS"
normalize_tree "$oci_rootfs"
chmod 0755 "$oci_rootfs/usr/bin/$LINUX_CLI_NAME"
chmod 0755 "$oci_rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME"
chmod 0644 "$oci_rootfs/etc/passwd" "$oci_rootfs/etc/group"
find "$oci_rootfs/lib" -type f -exec chmod 0755 {} +
chmod 0700 \
  "$oci_rootfs/var/cache/gta-claw" \
  "$oci_rootfs/var/log/gta-claw" \
  "$oci_rootfs/run/gta-claw"
reject_forbidden_runtime_content "$oci_rootfs"

oci_work="$WORK_DIR/oci"
oci_layout="$oci_work/$base_name.oci"
ensure_output_directory "$oci_layout/blobs/sha256"
root_layer="$oci_work/rootfs.tar"
writable_layer="$oci_work/writable.tar"
open_output_file "$root_layer" 0644
(
  cd "$oci_rootfs"
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
    .
) >&"$OPEN_OUTPUT_FD"
finish_output_file
open_output_file "$writable_layer" 0644
(
  cd "$oci_rootfs"
  tar \
    --sort=name \
    --format=posix \
    --pax-option=delete=atime,delete=ctime \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=65532 \
    --group=65532 \
    --numeric-owner \
    --no-recursion \
    -cf - \
    var/cache/gta-claw \
    var/log/gta-claw \
    run/gta-claw
) >&"$OPEN_OUTPUT_FD"
finish_output_file
root_layer_digest="$(sha256_file "$root_layer")"
writable_layer_digest="$(sha256_file "$writable_layer")"
root_layer_size="$(wc -c <"$root_layer" | tr -d ' ')"
writable_layer_size="$(wc -c <"$writable_layer" | tr -d ' ')"
copy_regular_input \
  "$root_layer" \
  "$oci_layout/blobs/sha256/$root_layer_digest" \
  0644
copy_regular_input \
  "$writable_layer" \
  "$oci_layout/blobs/sha256/$writable_layer_digest" \
  0644

oci_config_source="$oci_work/config.json"
write_json "$oci_config_source" -n \
  --arg created "$created_at" \
  --arg architecture "$oci_architecture" \
  --arg version "$VERSION" \
  --arg revision "$source_sha" \
  --arg root_digest "sha256:$root_layer_digest" \
  --arg writable_digest "sha256:$writable_layer_digest" \
  '{
    created: $created,
    architecture: $architecture,
    os: "linux",
    config: {
      User: "65532:65532",
      Entrypoint: ["/usr/libexec/gta-claw/gta-claw-daemon"],
      Cmd: [
        "--state-profile",
        "linux-protected",
        "--state-path",
        "/var/lib/gta-claw-protected"
      ],
      WorkingDir: "/",
      Env: ["RUST_BACKTRACE=0"],
      Volumes: {
        "/var/lib": {},
        "/var/cache/gta-claw": {},
        "/var/log/gta-claw": {},
        "/run/gta-claw": {}
      },
      Labels: {
        "org.opencontainers.image.created": $created,
        "org.opencontainers.image.description": "GTA Claw native Rust headless prototype",
        "org.opencontainers.image.licenses": "MIT AND LGPL-2.1-or-later AND (GPL-3.0-or-later WITH GCC-exception-3.1)",
        "org.opencontainers.image.revision": $revision,
        "org.opencontainers.image.source": "https://github.com/GTAStudio/GTA-Claw",
        "org.opencontainers.image.title": "gta-claw",
        "org.opencontainers.image.version": $version,
        "io.gta-claw.linux-protected.init": "/usr/libexec/gta-claw/gta-claw-daemon --prepare-linux-protected --state-path /var/lib/gta-claw-protected --service-uid 65532 --service-gid 65532",
        "io.gta-claw.linux-protected.mode": "two-phase"
      }
    },
    rootfs: {
      type: "layers",
      diff_ids: [$root_digest, $writable_digest]
    },
    history: [{
      created: $created,
      created_by: "packaging/linux/package.sh",
      comment: "Node-free scratch OCI two-phase runtime"
    }]
  }'
oci_config_digest="$(sha256_file "$oci_config_source")"
oci_config_size="$(wc -c <"$oci_config_source" | tr -d ' ')"
copy_regular_input \
  "$oci_config_source" \
  "$oci_layout/blobs/sha256/$oci_config_digest" \
  0644

oci_manifest_source="$oci_work/manifest.json"
write_json "$oci_manifest_source" -n \
  --arg config_digest "sha256:$oci_config_digest" \
  --argjson config_size "$oci_config_size" \
  --arg root_digest "sha256:$root_layer_digest" \
  --argjson root_size "$root_layer_size" \
  --arg writable_digest "sha256:$writable_layer_digest" \
  --argjson writable_size "$writable_layer_size" \
  '{
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      digest: $config_digest,
      size: $config_size
    },
    layers: [
      {
        mediaType: "application/vnd.oci.image.layer.v1.tar",
        digest: $root_digest,
        size: $root_size
      },
      {
        mediaType: "application/vnd.oci.image.layer.v1.tar",
        digest: $writable_digest,
        size: $writable_size,
        annotations: {
          "org.opencontainers.image.title": "writable-directory-ownership"
        }
      }
    ]
  }'
oci_manifest_digest="$(sha256_file "$oci_manifest_source")"
oci_manifest_size="$(wc -c <"$oci_manifest_source" | tr -d ' ')"
copy_regular_input \
  "$oci_manifest_source" \
  "$oci_layout/blobs/sha256/$oci_manifest_digest" \
  0644
write_json "$oci_layout/index.json" -n \
  --arg digest "sha256:$oci_manifest_digest" \
  --argjson size "$oci_manifest_size" \
  --arg architecture "$oci_architecture" \
  --arg version "$VERSION" \
  '{
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [{
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      digest: $digest,
      size: $size,
      platform: {architecture: $architecture, os: "linux"},
      annotations: {
        "org.opencontainers.image.ref.name": ("gta-claw:" + $version)
      }
    }]
  }'
write_json "$oci_layout/oci-layout" -n '{imageLayoutVersion: "1.0.0"}'
normalize_tree "$oci_layout"
oci_artifact="$ARTIFACT_DIR/$base_name.oci.tar.gz"
create_deterministic_tar_gz "$(dirname "$oci_layout")" "$(basename "$oci_layout")" "$oci_artifact"
compose_artifact="$ARTIFACT_DIR/$base_name.compose.yaml"
kubernetes_artifact="$ARTIFACT_DIR/$base_name.kubernetes.yaml"
render_oci_orchestration \
  "$LINUX_DIR/oci/compose.yaml.in" \
  "$compose_artifact" \
  "$oci_manifest_digest"
render_oci_orchestration \
  "$LINUX_DIR/oci/kubernetes.yaml.in" \
  "$kubernetes_artifact" \
  "$oci_manifest_digest"
validate_oci_orchestration_contract \
  "$compose_artifact" \
  "$kubernetes_artifact" \
  "$oci_manifest_digest"

artifact_provenance="$ARTIFACT_DIR/provenance-$arch.json"
write_json "$artifact_provenance" -n \
  --slurpfile build_manifest "$BUILD_MANIFEST" \
  --slurpfile runtime_manifest "$BUILD_RUNTIME_MANIFEST" \
  --slurpfile package_toolchain "$package_toolchain" \
  --arg source_sha "$source_sha" \
  --arg source_tree "$source_tree" \
  --arg build_manifest_sha "$build_manifest_sha" \
  --arg version "$VERSION" \
  --arg architecture "$arch" \
  --arg tar_name "$(basename "$tar_artifact")" \
  --arg tar_sha "$(sha256_file "$tar_artifact")" \
  --arg deb_name "$(basename "$deb_artifact")" \
  --arg deb_sha "$(sha256_file "$deb_artifact")" \
  --arg rpm_name "$(basename "$rpm_artifact")" \
  --arg rpm_sha "$(sha256_file "$rpm_artifact")" \
  --arg oci_name "$(basename "$oci_artifact")" \
  --arg oci_sha "$(sha256_file "$oci_artifact")" \
  --arg compose_name "$(basename "$compose_artifact")" \
  --arg compose_sha "$(sha256_file "$compose_artifact")" \
  --arg kubernetes_name "$(basename "$kubernetes_artifact")" \
  --arg kubernetes_sha "$(sha256_file "$kubernetes_artifact")" \
  '{
    schemaVersion: 1,
    source: {
      repository: "https://github.com/GTAStudio/GTA-Claw",
      revision: $source_sha,
      tree: $source_tree
    },
    buildManifest: {
      digest: {sha256: $build_manifest_sha},
      content: $build_manifest[0]
    },
    runtimeDependencies: $runtime_manifest[0].packages,
    packageToolchain: $package_toolchain[0],
    package: {name: "gta-claw", version: $version, architecture: $architecture},
    subjects: [
      {name: $tar_name, digest: {sha256: $tar_sha}},
      {name: $deb_name, digest: {sha256: $deb_sha}},
      {name: $rpm_name, digest: {sha256: $rpm_sha}},
      {name: $oci_name, digest: {sha256: $oci_sha}},
      {name: $compose_name, digest: {sha256: $compose_sha}},
      {name: $kubernetes_name, digest: {sha256: $kubernetes_sha}}
    ]
  }'
write_sha256_manifest "$ARTIFACT_DIR" "$ARTIFACT_DIR/SHA256SUMS"

"$LINUX_DIR/validate.sh" \
  "$OUTPUT_ROOT" \
  "$arch" \
  "$BUILD_MANIFEST" \
  "$BUILD_PUBLIC_KEY_FINGERPRINT"
note "created deterministic Linux artifacts in $ARTIFACT_DIR"
