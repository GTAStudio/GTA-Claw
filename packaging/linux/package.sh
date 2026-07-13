#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in \
  awk date dpkg-deb du find gzip install jq md5sum readelf realpath rpm \
  rpmbuild sed sha1sum sha256sum stat tar wc; do
  require_tool "$tool"
done
[[ "$#" -eq 2 ]] || die "usage: package.sh ARCH BINARY_DIRECTORY"
arch="$1"
binary_dir="$2"
validate_safe_component "$arch" "architecture"
[[ "$binary_dir" == /* ]] || die "binary directory must be absolute"
[[ -d "$binary_dir" && ! -L "$binary_dir" ]] ||
  die "binary directory is not a real directory: $binary_dir"

daemon_binary="$binary_dir/$LINUX_DAEMON_NAME"
cli_binary="$binary_dir/$LINUX_CLI_NAME"
validate_elf_binary "$daemon_binary" "$arch"
validate_elf_binary "$cli_binary" "$arch"

initialize_output_root
ARTIFACT_DIR="$OUTPUT_ROOT/artifacts"
WORK_DIR="$OUTPUT_ROOT/work"
ensure_output_directory "$ARTIFACT_DIR"
ensure_output_directory "$WORK_DIR"

source_sha="$(git -C "$REPO_ROOT" rev-parse HEAD)"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || die "source revision is not a full commit SHA"
created_at="$(date -u --date="@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
target="$(arch_target "$arch")"
deb_architecture="$(deb_arch "$arch")"
rpm_architecture="$(rpm_arch "$arch")"
oci_architecture="$(oci_arch "$arch")"
base_name="$LINUX_PACKAGE_NAME-$VERSION-linux-$arch"

write_json() {
  local output="$1"
  shift
  assert_new_output_file "$output"
  ensure_output_directory "$(dirname "$output")"
  jq -S "$@" >"$output"
  chmod 0644 "$output"
  assert_regular_unaliased "$output" "JSON output"
}

generate_provenance() {
  local root="$1"
  local output="$2"
  local daemon_path="$3"
  local cli_path="$4"
  write_json "$output" -n \
    --arg source_sha "$source_sha" \
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
            "digest": {"gitCommit": $source_sha}
          }]
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
  local sha1
  local verification_code
  assert_new_output_file "$list"
  : >"$list"
  while IFS= read -r -d '' relative; do
    [[ "$root/$relative" != "$output" ]] || continue
    index=$((index + 1))
    sha1="$(sha1sum "$root/$relative" | awk '{ print $1 }')"
    jq -c -n \
      --arg id "SPDXRef-File-$index" \
      --arg name "./${relative#./}" \
      --arg sha1 "$sha1" \
      --arg sha "$(sha256_file "$root/$relative")" \
      '{
        SPDXID: $id,
        fileName: $name,
        checksums: [
          {algorithm: "SHA1", checksumValue: $sha1},
          {algorithm: "SHA256", checksumValue: $sha}
        ],
        licenseConcluded: "NOASSERTION",
        licenseInfoInFiles: ["NOASSERTION"],
        copyrightText: "NOASSERTION"
      }' >>"$list"
  done < <(cd "$root" && find . -type f -print0 | LC_ALL=C sort -z)
  verification_code="$(
    jq -r '
      .checksums[] |
      select(.algorithm == "SHA1") |
      .checksumValue
    ' "$list" |
      LC_ALL=C sort |
      tr -d '\n' |
      sha1sum |
      awk '{ print $1 }'
  )"
  write_json "$output" -n \
    --slurpfile files "$list" \
    --arg verification_code "$verification_code" \
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
      packages: [{
        SPDXID: "SPDXRef-Package-GTA-Claw",
        name: "gta-claw",
        versionInfo: $version,
        downloadLocation: "NOASSERTION",
        filesAnalyzed: true,
        packageVerificationCode: {
          packageVerificationCodeValue: $verification_code
        },
        licenseConcluded: "MIT",
        licenseDeclared: "MIT",
        copyrightText: "NOASSERTION",
        externalRefs: [{
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: ("pkg:github/GTAStudio/GTA-Claw@" + $source_sha)
        }]
      }],
      files: $files,
      relationships: (
        [{
          spdxElementId: "SPDXRef-DOCUMENT",
          relationshipType: "DESCRIBES",
          relatedSpdxElement: "SPDXRef-Package-GTA-Claw"
        }] + (
          $files |
          map({
            spdxElementId: "SPDXRef-Package-GTA-Claw",
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
  copy_regular_input \
    "$LINUX_DIR/systemd/gta-claw-daemon.socket.deferred" \
    "$destination/gta-claw-daemon.socket.deferred" \
    0644
}

archive_stage="$WORK_DIR/archive/$base_name"
ensure_output_directory "$archive_stage/bin"
ensure_output_directory "$archive_stage/share/doc/gta-claw"
copy_verified_input "$daemon_binary" "$archive_stage/bin/$LINUX_DAEMON_NAME" 0755
copy_verified_input "$cli_binary" "$archive_stage/bin/$LINUX_CLI_NAME" 0755
stage_documentation "$archive_stage/share/doc/gta-claw"
generate_provenance \
  "$archive_stage" \
  "$archive_stage/provenance.json" \
  "bin/$LINUX_DAEMON_NAME" \
  "bin/$LINUX_CLI_NAME"
generate_spdx "$archive_stage" "$archive_stage/sbom.spdx.json" "native-tar"
write_sha256_manifest "$archive_stage" "$archive_stage/SHA256SUMS"
normalize_tree "$archive_stage"
tar_artifact="$ARTIFACT_DIR/$base_name.tar.gz"
create_deterministic_tar_gz "$(dirname "$archive_stage")" "$(basename "$archive_stage")" "$tar_artifact"

rootfs="$WORK_DIR/rootfs"
ensure_output_directory "$rootfs/usr/bin"
ensure_output_directory "$rootfs/usr/libexec/gta-claw"
ensure_output_directory "$rootfs/usr/lib/systemd/system"
ensure_output_directory "$rootfs/usr/share/doc/gta-claw"
ensure_output_directory "$rootfs/etc/gta-claw/credentials"
ensure_output_directory "$rootfs/var/lib/gta-claw"
ensure_output_directory "$rootfs/var/cache/gta-claw"
ensure_output_directory "$rootfs/var/log/gta-claw"
ensure_output_directory "$rootfs/run/gta-claw"
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
chmod 0640 "$rootfs/etc/gta-claw/gta-claw.env"
chmod 0600 "$rootfs/etc/gta-claw/credentials/daemon.conf"
chmod 0700 \
  "$rootfs/var/lib/gta-claw" \
  "$rootfs/var/cache/gta-claw" \
  "$rootfs/var/log/gta-claw" \
  "$rootfs/run/gta-claw"
validate_service_contract "$rootfs/usr/lib/systemd/system/gta-claw-daemon.service"
reject_forbidden_runtime_content "$rootfs"

deb_root="$WORK_DIR/deb-root"
ensure_output_directory "$deb_root"
cp -a -- "$rootfs/." "$deb_root/"
reject_links_and_special_files "$deb_root"
ensure_output_directory "$deb_root/DEBIAN"
installed_size="$(du -sk "$rootfs" | awk '{ print $1 }')"
control="$deb_root/DEBIAN/control"
assert_new_output_file "$control"
cat >"$control" <<EOF
Package: $LINUX_PACKAGE_NAME
Version: $VERSION-$LINUX_PACKAGE_RELEASE
Section: utils
Priority: optional
Architecture: $deb_architecture
Maintainer: GTAStudio <noreply@github.com>
Installed-Size: $installed_size
Depends: libc6 (>= 2.31), libgcc-s1, systemd (>= 249)
Homepage: https://github.com/GTAStudio/GTA-Claw
Description: GTA Claw native Rust headless prototype
 Packages gta-claw-daemon and gta-claw-cli without the legacy JavaScript
 runtime or the Slint desktop application. This is not a feature-parity claim.
EOF
assert_new_output_file "$deb_root/DEBIAN/conffiles"
cat >"$deb_root/DEBIAN/conffiles" <<'EOF'
/etc/gta-claw/gta-claw.env
/etc/gta-claw/credentials/daemon.conf
EOF
assert_new_output_file "$deb_root/DEBIAN/md5sums"
(
  cd "$deb_root"
  find . -path ./DEBIAN -prune -o -type f -print |
    sed 's#^\./##' |
    LC_ALL=C sort |
    xargs md5sum
) >"$deb_root/DEBIAN/md5sums"
normalize_tree "$deb_root"
chmod 0755 "$deb_root/DEBIAN"
chmod 0644 "$deb_root/DEBIAN/control" "$deb_root/DEBIAN/conffiles" "$deb_root/DEBIAN/md5sums"
chmod 0640 "$deb_root/etc/gta-claw/gta-claw.env"
chmod 0600 "$deb_root/etc/gta-claw/credentials/daemon.conf"
chmod 0700 \
  "$deb_root/var/lib/gta-claw" \
  "$deb_root/var/cache/gta-claw" \
  "$deb_root/var/log/gta-claw" \
  "$deb_root/run/gta-claw"
deb_artifact="$ARTIFACT_DIR/${LINUX_PACKAGE_NAME}_${VERSION}-${LINUX_PACKAGE_RELEASE}_${deb_architecture}.deb"
deb_temporary="$deb_artifact.tmp"
assert_new_output_file "$deb_temporary"
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  dpkg-deb --root-owner-group -Zgzip -z9 --build "$deb_root" "$deb_temporary"
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
assert_new_output_file "$rpm_source_temporary"
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
    -cf "$rpm_source_temporary" \
    .
)
touch --date="@$SOURCE_DATE_EPOCH" "$rpm_source_temporary"
publish_output_file "$rpm_source_temporary" "$rpm_source"
rpm_spec="$rpm_work/SPECS/gta-claw.spec"
assert_new_output_file "$rpm_spec"
changelog_date="$(LC_ALL=C date -u --date="@$SOURCE_DATE_EPOCH" '+%a %b %d %Y')"
cat >"$rpm_spec" <<EOF
%global debug_package %{nil}
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
BuildArch:      $rpm_architecture
Requires:       glibc >= 2.31
Requires:       libgcc
Requires:       systemd >= 249

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
/usr/lib/systemd/system/gta-claw-daemon.service
/usr/share/doc/gta-claw
%dir %attr(0700,root,root) /var/lib/gta-claw
%dir %attr(0700,root,root) /var/cache/gta-claw
%dir %attr(0700,root,root) /var/log/gta-claw
%dir %attr(0700,root,root) /run/gta-claw

%changelog
* $changelog_date GTAStudio <noreply@github.com> - $VERSION-$LINUX_PACKAGE_RELEASE
- Deterministic native Rust headless packaging prototype
EOF
chmod 0644 "$rpm_spec"
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  rpmbuild \
    -bb \
    --define "_topdir $rpm_work" \
    --define "_source_filedigest_algorithm 8" \
    --define "_binary_filedigest_algorithm 8" \
    --target "$rpm_architecture-linux" \
    "$rpm_spec"
mapfile -t built_rpms < <(find "$rpm_work/RPMS" -type f -name '*.rpm' -print)
[[ "${#built_rpms[@]}" -eq 1 ]] ||
  die "expected exactly one binary RPM, found ${#built_rpms[@]}"
rpm_artifact="$ARTIFACT_DIR/$LINUX_PACKAGE_NAME-$VERSION-$LINUX_PACKAGE_RELEASE.$rpm_architecture.rpm"
rpm_temporary="$rpm_artifact.tmp"
copy_regular_input "${built_rpms[0]}" "$rpm_temporary" 0644
touch --date="@$SOURCE_DATE_EPOCH" "$rpm_temporary"
publish_output_file "$rpm_temporary" "$rpm_artifact"

copy_runtime_library() {
  local source="$1"
  local destination="$2"
  source="$(realpath -e "$source")"
  copy_verified_input "$source" "$destination" 0755
}

copy_x86_runtime() {
  local binary
  local interpreter
  local library
  for binary in "$daemon_binary" "$cli_binary"; do
    interpreter="$(
      readelf -l "$binary" |
        sed -n 's/.*Requesting program interpreter: \([^]]*\)\].*/\1/p'
    )"
    [[ "$interpreter" == /* ]] || die "ELF interpreter is missing for $binary"
    if [[ ! -e "$oci_rootfs$interpreter" ]]; then
      copy_runtime_library "$interpreter" "$oci_rootfs$interpreter"
    fi
    while IFS= read -r library; do
      [[ -n "$library" ]] || continue
      if [[ ! -e "$oci_rootfs$library" ]]; then
        copy_runtime_library "$library" "$oci_rootfs$library"
      fi
    done < <(
      ldd "$binary" |
        awk '/=> \// { print $3 } /^\// { print $1 }' |
        LC_ALL=C sort -u
    )
  done
}

find_arm_library() {
  local name="$1"
  local candidate
  for candidate in \
    "/usr/aarch64-linux-gnu/lib/$name" \
    "/lib/aarch64-linux-gnu/$name" \
    "/usr/lib/aarch64-linux-gnu/$name"; do
    if [[ -e "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  die "arm64 runtime library not found: $name"
}

copy_arm_runtime() {
  local interpreter
  local name
  local source
  local dependency
  local index=0
  local -a queue=()
  local -A seen=()
  interpreter="$(
    readelf -l "$daemon_binary" |
      sed -n 's/.*Requesting program interpreter: \([^]]*\)\].*/\1/p'
  )"
  [[ "$interpreter" == "/lib/ld-linux-aarch64.so.1" ]] ||
    die "unexpected arm64 ELF interpreter: $interpreter"
  source="$(find_arm_library ld-linux-aarch64.so.1)"
  copy_runtime_library "$source" "$oci_rootfs$interpreter"
  while IFS= read -r name; do
    [[ -n "$name" ]] && queue+=("$name")
  done < <(
    {
      readelf -d "$daemon_binary"
      readelf -d "$cli_binary"
    } |
      sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' |
      LC_ALL=C sort -u
  )
  while [[ "$index" -lt "${#queue[@]}" ]]; do
    name="${queue[$index]}"
    index=$((index + 1))
    [[ -z "${seen[$name]:-}" ]] || continue
    seen[$name]=1
    source="$(find_arm_library "$name")"
    copy_runtime_library "$source" "$oci_rootfs/lib/aarch64-linux-gnu/$name"
    while IFS= read -r dependency; do
      [[ -n "$dependency" && -z "${seen[$dependency]:-}" ]] &&
        queue+=("$dependency")
    done < <(
      readelf -d "$(realpath -e "$source")" |
        sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p'
    )
  done
}

oci_rootfs="$WORK_DIR/oci-rootfs"
ensure_output_directory "$oci_rootfs/usr/bin"
ensure_output_directory "$oci_rootfs/usr/libexec/gta-claw"
ensure_output_directory "$oci_rootfs/usr/share/doc/gta-claw"
ensure_output_directory "$oci_rootfs/etc"
ensure_output_directory "$oci_rootfs/var/lib/gta-claw"
ensure_output_directory "$oci_rootfs/var/cache/gta-claw"
ensure_output_directory "$oci_rootfs/var/log/gta-claw"
ensure_output_directory "$oci_rootfs/run/gta-claw"
copy_verified_input "$cli_binary" "$oci_rootfs/usr/bin/$LINUX_CLI_NAME" 0755
copy_verified_input \
  "$daemon_binary" \
  "$oci_rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME" \
  0755
stage_documentation "$oci_rootfs/usr/share/doc/gta-claw"
assert_new_output_file "$oci_rootfs/etc/passwd"
cat >"$oci_rootfs/etc/passwd" <<'EOF'
root:x:0:0:root:/nonexistent:/sbin/nologin
gta-claw:x:65532:65532:GTA Claw:/nonexistent:/sbin/nologin
EOF
assert_new_output_file "$oci_rootfs/etc/group"
cat >"$oci_rootfs/etc/group" <<'EOF'
root:x:0:
gta-claw:x:65532:
EOF
case "$arch" in
  x86_64)
    require_tool ldd
    copy_x86_runtime
    ;;
  arm64) copy_arm_runtime ;;
  *) die "unsupported OCI architecture: $arch" ;;
esac
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
find "$oci_rootfs/lib" -type f -exec chmod 0755 {} + 2>/dev/null || true
chmod 0700 \
  "$oci_rootfs/var/lib/gta-claw" \
  "$oci_rootfs/var/cache/gta-claw" \
  "$oci_rootfs/var/log/gta-claw" \
  "$oci_rootfs/run/gta-claw"
reject_forbidden_runtime_content "$oci_rootfs"

oci_work="$WORK_DIR/oci"
oci_layout="$oci_work/$base_name.oci"
ensure_output_directory "$oci_layout/blobs/sha256"
root_layer="$oci_work/rootfs.tar"
writable_layer="$oci_work/writable.tar"
assert_new_output_file "$root_layer"
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
    -cf "$root_layer" \
    .
)
assert_new_output_file "$writable_layer"
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
    -cf "$writable_layer" \
    var/lib/gta-claw \
    var/cache/gta-claw \
    var/log/gta-claw \
    run/gta-claw
)
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
      WorkingDir: "/",
      Env: ["RUST_BACKTRACE=0"],
      Volumes: {
        "/var/lib/gta-claw": {},
        "/var/cache/gta-claw": {},
        "/var/log/gta-claw": {},
        "/run/gta-claw": {}
      },
      Labels: {
        "org.opencontainers.image.created": $created,
        "org.opencontainers.image.description": "GTA Claw native Rust headless prototype",
        "org.opencontainers.image.licenses": "MIT",
        "org.opencontainers.image.revision": $revision,
        "org.opencontainers.image.source": "https://github.com/GTAStudio/GTA-Claw",
        "org.opencontainers.image.title": "gta-claw",
        "org.opencontainers.image.version": $version
      }
    },
    rootfs: {
      type: "layers",
      diff_ids: [$root_digest, $writable_digest]
    },
    history: [{
      created: $created,
      created_by: "packaging/linux/package.sh",
      comment: "Node-free scratch OCI prototype"
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

artifact_provenance="$ARTIFACT_DIR/provenance-$arch.json"
write_json "$artifact_provenance" -n \
  --arg source_sha "$source_sha" \
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
  '{
    schemaVersion: 1,
    source: {
      repository: "https://github.com/GTAStudio/GTA-Claw",
      revision: $source_sha
    },
    package: {name: "gta-claw", version: $version, architecture: $architecture},
    subjects: [
      {name: $tar_name, digest: {sha256: $tar_sha}},
      {name: $deb_name, digest: {sha256: $deb_sha}},
      {name: $rpm_name, digest: {sha256: $rpm_sha}},
      {name: $oci_name, digest: {sha256: $oci_sha}}
    ]
  }'
write_sha256_manifest "$ARTIFACT_DIR" "$ARTIFACT_DIR/SHA256SUMS"

"$LINUX_DIR/validate.sh" "$OUTPUT_ROOT" "$arch"
note "created deterministic Linux artifacts in $ARTIFACT_DIR"
