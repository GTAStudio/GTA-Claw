#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/build-manifest.sh"
source "$SCRIPT_DIR/lib/oci-validation.sh"

require_linux
adopt_safe_output_root
for tool in cpio cmp diff dpkg-deb jq readelf rpm rpm2cpio sha256sum stat tar; do
  require_tool "$tool"
done
[[ "$#" -eq 4 ]] ||
  die "usage: validate.sh OUTPUT_ROOT ARCH BUILD_MANIFEST EXPECTED_BUILD_KEY_SHA256"
validation_root="$1"
arch="$2"
input_manifest="$3"
expected_build_key_sha="$4"
verify_build_manifest "$input_manifest" "$arch" "$expected_build_key_sha"
assert_private_owned_root "$validation_root"
reject_links_and_special_files "$validation_root"

native_rootfs_files() {
  printf '%s\n' \
    etc/gta-claw/credentials/daemon.conf \
    etc/gta-claw/gta-claw.env \
    usr/bin/gta-claw-cli \
    usr/lib/systemd/system-preset/80-gta-claw.preset \
    usr/lib/systemd/system/gta-claw-daemon.service \
    usr/lib/systemd/system/gta-claw-state-init.service \
    usr/lib/sysusers.d/gta-claw.conf \
    usr/libexec/gta-claw/gta-claw-daemon \
    usr/libexec/gta-claw/gta-claw-runtime-ready \
    usr/libexec/gta-claw/gta-claw-state-init \
    usr/share/doc/gta-claw/LICENSE.txt \
    usr/share/doc/gta-claw/NOTICE.txt \
    usr/share/doc/gta-claw/README.md \
    usr/share/doc/gta-claw/SHA256SUMS \
    usr/share/doc/gta-claw/build-manifest.json \
    usr/share/doc/gta-claw/gta-claw-daemon.socket.deferred \
    usr/share/doc/gta-claw/package-toolchain.json \
    usr/share/doc/gta-claw/provenance.json \
    usr/share/doc/gta-claw/runtime-manifest.json \
    usr/share/doc/gta-claw/sbom.spdx.json
}

native_tar_files() {
  printf '%s\n' \
    SHA256SUMS \
    bin/gta-claw-cli \
    bin/gta-claw-daemon \
    etc/gta-claw/credentials/daemon.conf \
    etc/gta-claw/gta-claw.env \
    install.sh \
    lib/systemd/system-preset/80-gta-claw.preset \
    lib/systemd/system/gta-claw-daemon.service \
    lib/systemd/system/gta-claw-state-init.service \
    lib/sysusers.d/gta-claw.conf \
    libexec/gta-claw-runtime-ready \
    libexec/gta-claw-state-init \
    package-version \
    provenance.json \
    sbom.spdx.json \
    share/doc/gta-claw/LICENSE.txt \
    share/doc/gta-claw/NOTICE.txt \
    share/doc/gta-claw/README.md \
    share/doc/gta-claw/build-manifest.json \
    share/doc/gta-claw/gta-claw-daemon.socket.deferred \
    share/doc/gta-claw/package-toolchain.json \
    share/doc/gta-claw/runtime-manifest.json \
    uninstall.sh
}

expected_tree_entries() {
  local file
  local directory
  while IFS= read -r file; do
    printf '%s\n' "$file"
    directory="$(dirname "$file")"
    while [[ "$directory" != "." ]]; do
      printf '%s\n' "$directory"
      directory="$(dirname "$directory")"
    done
  done | LC_ALL=C sort -u
}

assert_exact_tree() {
  local root="$1"
  local expected_files="$2"
  local label="$3"
  local expected
  local actual
  expected="$(expected_tree_entries <<<"$expected_files")"
  actual="$(find "$root" -mindepth 1 -printf '%P\n' | LC_ALL=C sort)"
  [[ "$actual" == "$expected" ]] ||
    die "$label published tree differs from the exact member allowlist"
}

assert_root_owned_tree() {
  local root="$1"
  local label="$2"
  local bad
  bad="$(
    find "$root" -mindepth 1 -printf '%u:%g %P\n' |
      awk '$1 != "root:root" { print; exit }'
  )"
  [[ -z "$bad" ]] || die "$label contains non-root ownership: $bad"
}

assert_no_protected_payload_path() {
  local label="$1"
  local listing="$2"
  if grep -Eq '(^|/)(var/lib/gta-claw-protected)(/|$)' <<<"$listing"; then
    die "$label owns the LinuxProtected namespace or a descendant"
  fi
}

assert_mode() {
  local root="$1"
  local path="$2"
  local expected="$3"
  [[ "$(stat -c '%a' "$root/$path")" == "$expected" ]] ||
    die "published file mode mismatch for $path"
}

compare_native_sources() {
  local root="$1"
  cmp -s "$LINUX_DIR/systemd/gta-claw.env" "$root/etc/gta-claw/gta-claw.env" ||
    die "published environment file differs from reviewed source"
  cmp -s \
    "$LINUX_DIR/systemd/daemon.conf" \
    "$root/etc/gta-claw/credentials/daemon.conf" ||
    die "published credential file differs from reviewed source"
  for source_target in \
    "systemd/gta-claw-daemon.service|usr/lib/systemd/system/gta-claw-daemon.service" \
    "systemd/gta-claw-state-init.service|usr/lib/systemd/system/gta-claw-state-init.service" \
    "systemd/80-gta-claw.preset|usr/lib/systemd/system-preset/80-gta-claw.preset" \
    "sysusers/gta-claw.conf|usr/lib/sysusers.d/gta-claw.conf" \
    "libexec/gta-claw-runtime-ready|usr/libexec/gta-claw/gta-claw-runtime-ready" \
    "libexec/gta-claw-state-init|usr/libexec/gta-claw/gta-claw-state-init" \
    "LICENSE.txt|usr/share/doc/gta-claw/LICENSE.txt" \
    "NOTICE.txt|usr/share/doc/gta-claw/NOTICE.txt" \
    "README.md|usr/share/doc/gta-claw/README.md" \
    "systemd/gta-claw-daemon.socket.deferred|usr/share/doc/gta-claw/gta-claw-daemon.socket.deferred"; do
    source="${source_target%%|*}"
    target="${source_target##*|}"
    cmp -s "$LINUX_DIR/$source" "$root/$target" ||
      die "published native payload differs from reviewed source: $target"
  done
  cmp -s "$BUILD_MANIFEST" "$root/usr/share/doc/gta-claw/build-manifest.json" ||
    die "published native build manifest differs from authenticated input"
  cmp -s "$BUILD_RUNTIME_MANIFEST" "$root/usr/share/doc/gta-claw/runtime-manifest.json" ||
    die "published native runtime manifest differs from authenticated input"
}

validate_published_native_root() {
  local root="$1"
  local label="$2"
  local expected_files
  expected_files="$(native_rootfs_files)"
  reject_links_and_special_files "$root"
  assert_exact_tree "$root" "$expected_files" "$label"
  assert_root_owned_tree "$root" "$label"
  assert_no_protected_payload_path "$label" "$(find "$root" -mindepth 1 -printf '%P\n')"
  compare_native_sources "$root"
  validate_elf_binary "$root/usr/bin/$LINUX_CLI_NAME" "$arch"
  validate_elf_binary "$root/usr/libexec/gta-claw/$LINUX_DAEMON_NAME" "$arch"
  [[ "$(sha256_file "$root/usr/bin/$LINUX_CLI_NAME")" == "$(
    jq -er --arg name "$LINUX_CLI_NAME" \
      '.binaries[] | select(.name == $name) | .sha256' "$BUILD_MANIFEST"
  )" ]] || die "$label CLI differs from authenticated build"
  [[ "$(sha256_file "$root/usr/libexec/gta-claw/$LINUX_DAEMON_NAME")" == "$(
    jq -er --arg name "$LINUX_DAEMON_NAME" \
      '.binaries[] | select(.name == $name) | .sha256' "$BUILD_MANIFEST"
  )" ]] || die "$label daemon differs from authenticated build"
  for executable in \
    usr/bin/gta-claw-cli \
    usr/libexec/gta-claw/gta-claw-daemon \
    usr/libexec/gta-claw/gta-claw-runtime-ready \
    usr/libexec/gta-claw/gta-claw-state-init; do
    assert_mode "$root" "$executable" 755
  done
  assert_mode "$root" etc/gta-claw/gta-claw.env 640
  assert_mode "$root" etc/gta-claw/credentials/daemon.conf 600
  while IFS= read -r file; do
    case "$file" in
      etc/gta-claw/gta-claw.env | etc/gta-claw/credentials/daemon.conf | \
        usr/bin/gta-claw-cli | usr/libexec/gta-claw/*) ;;
      *) assert_mode "$root" "$file" 644 ;;
    esac
  done <<<"$expected_files"
  while IFS= read -r directory; do
    [[ -d "$root/$directory" ]] || continue
    assert_mode "$root" "$directory" 755
  done < <(expected_tree_entries <<<"$expected_files")
  validate_service_contract "$root/usr/lib/systemd/system/gta-claw-daemon.service"
  validate_initializer_service_contract \
    "$root/usr/lib/systemd/system/gta-claw-state-init.service"
  validate_sysusers_contract "$root/usr/lib/sysusers.d/gta-claw.conf"
  validate_initializer_wrapper_contract \
    "$root/usr/libexec/gta-claw/gta-claw-state-init"
  validate_runtime_ready_contract \
    "$root/usr/libexec/gta-claw/gta-claw-runtime-ready"
  reject_forbidden_runtime_content "$root"
  verify_sha256_manifest "$root" "$root/usr/share/doc/gta-claw/SHA256SUMS"
}

artifact_dir="$validation_root/artifacts"
work_dir="$validation_root/work"
base_name="$LINUX_PACKAGE_NAME-$VERSION-linux-$arch"
deb_architecture="$(deb_arch "$arch")"
rpm_architecture="$(rpm_arch "$arch")"
tar_artifact="$artifact_dir/$base_name.tar.gz"
deb_artifact="$artifact_dir/${LINUX_PACKAGE_NAME}_${VERSION}-${LINUX_PACKAGE_RELEASE}_${deb_architecture}.deb"
rpm_artifact="$artifact_dir/$LINUX_PACKAGE_NAME-$VERSION-$LINUX_PACKAGE_RELEASE.$rpm_architecture.rpm"
oci_artifact="$artifact_dir/$base_name.oci.tar.gz"
compose_artifact="$artifact_dir/$base_name.compose.yaml"
kubernetes_artifact="$artifact_dir/$base_name.kubernetes.yaml"

for artifact in \
  "$tar_artifact" "$deb_artifact" "$rpm_artifact" "$oci_artifact" \
  "$compose_artifact" "$kubernetes_artifact" \
  "$artifact_dir/provenance-$arch.json" "$artifact_dir/SHA256SUMS"; do
  assert_regular_unaliased "$artifact" "artifact"
done
verify_sha256_manifest "$artifact_dir" "$artifact_dir/SHA256SUMS"

validate_archive_entries "$tar_artifact" gzip
tar_listing="$(tar -tzf "$tar_artifact")"
assert_no_protected_payload_path "native tar" "$tar_listing"
if grep -Eiq '(^|/)(node(js)?|npm|npx|pnpm|bun)(/|$)|\.(js|mjs|cjs|node)$' \
  <<<"$tar_listing"; then
  die "native archive contains a JavaScript runtime or package-manager file"
fi
if tar --numeric-owner -tvzf "$tar_artifact" |
  awk '$2 != "0/0" { bad = 1 } END { exit !bad }'; then
  die "native archive contains non-root ownership"
fi
published_tar_root="$work_dir/published-tar"
create_private_validation_directory "$published_tar_root"
tar --numeric-owner -xzf "$tar_artifact" -C "$published_tar_root"
archive_root="$published_tar_root/$base_name"
tar_files="$(native_tar_files)"
reject_links_and_special_files "$archive_root"
assert_exact_tree "$archive_root" "$tar_files" "native tar"
assert_root_owned_tree "$archive_root" "native tar"
assert_no_protected_payload_path \
  "native tar extraction" \
  "$(find "$archive_root" -mindepth 1 -printf '%P\n')"
for source_target in \
  "direct/install.sh|install.sh" \
  "direct/uninstall.sh|uninstall.sh" \
  "systemd/gta-claw-daemon.service|lib/systemd/system/gta-claw-daemon.service" \
  "systemd/gta-claw-state-init.service|lib/systemd/system/gta-claw-state-init.service" \
  "systemd/80-gta-claw.preset|lib/systemd/system-preset/80-gta-claw.preset" \
  "sysusers/gta-claw.conf|lib/sysusers.d/gta-claw.conf" \
  "libexec/gta-claw-runtime-ready|libexec/gta-claw-runtime-ready" \
  "libexec/gta-claw-state-init|libexec/gta-claw-state-init" \
  "systemd/gta-claw.env|etc/gta-claw/gta-claw.env" \
  "systemd/daemon.conf|etc/gta-claw/credentials/daemon.conf" \
  "LICENSE.txt|share/doc/gta-claw/LICENSE.txt" \
  "NOTICE.txt|share/doc/gta-claw/NOTICE.txt" \
  "README.md|share/doc/gta-claw/README.md" \
  "systemd/gta-claw-daemon.socket.deferred|share/doc/gta-claw/gta-claw-daemon.socket.deferred"; do
  source="${source_target%%|*}"
  target="${source_target##*|}"
  cmp -s "$LINUX_DIR/$source" "$archive_root/$target" ||
    die "published tar differs from reviewed source: $target"
done
cmp -s "$BUILD_MANIFEST" "$archive_root/share/doc/gta-claw/build-manifest.json" ||
  die "published tar build manifest differs from authenticated input"
cmp -s \
  "$BUILD_RUNTIME_MANIFEST" \
  "$archive_root/share/doc/gta-claw/runtime-manifest.json" ||
  die "published tar runtime manifest differs from authenticated input"
[[ "$(cat "$archive_root/package-version")" == \
  "$VERSION-$LINUX_PACKAGE_RELEASE" ]] ||
  die "published tar package version is invalid"
[[ "$(sha256_file "$archive_root/bin/$LINUX_CLI_NAME")" == "$(
  jq -er --arg name "$LINUX_CLI_NAME" \
    '.binaries[] | select(.name == $name) | .sha256' "$BUILD_MANIFEST"
)" ]] || die "published tar CLI differs from authenticated build"
[[ "$(sha256_file "$archive_root/bin/$LINUX_DAEMON_NAME")" == "$(
  jq -er --arg name "$LINUX_DAEMON_NAME" \
    '.binaries[] | select(.name == $name) | .sha256' "$BUILD_MANIFEST"
)" ]] || die "published tar daemon differs from authenticated build"
for executable in \
  bin/gta-claw-cli \
  bin/gta-claw-daemon \
  install.sh \
  uninstall.sh \
  libexec/gta-claw-runtime-ready \
  libexec/gta-claw-state-init; do
  assert_mode "$archive_root" "$executable" 755
done
assert_mode "$archive_root" etc/gta-claw/gta-claw.env 640
assert_mode "$archive_root" etc/gta-claw/credentials/daemon.conf 600
while IFS= read -r file; do
  case "$file" in
    bin/* | install.sh | uninstall.sh | libexec/* | \
      etc/gta-claw/gta-claw.env | etc/gta-claw/credentials/daemon.conf) ;;
    *) assert_mode "$archive_root" "$file" 644 ;;
  esac
done <<<"$tar_files"
while IFS= read -r directory; do
  [[ -d "$archive_root/$directory" ]] || continue
  assert_mode "$archive_root" "$directory" 755
done < <(expected_tree_entries <<<"$tar_files")
verify_sha256_manifest "$archive_root" "$archive_root/SHA256SUMS"
if find "$archive_root" -type f -printf '%P\n' |
  grep -Eiq '(^|/)(node(js)?|npm|npx|pnpm|bun)(/|$)|\.(js|mjs|cjs|node)$'; then
  die "native archive contains a JavaScript runtime or package-manager file"
fi
validate_direct_lifecycle_contract \
  "$archive_root/install.sh" \
  "$archive_root/uninstall.sh"
validate_service_contract \
  "$archive_root/lib/systemd/system/gta-claw-daemon.service"
validate_initializer_service_contract \
  "$archive_root/lib/systemd/system/gta-claw-state-init.service"
validate_sysusers_contract "$archive_root/lib/sysusers.d/gta-claw.conf"
validate_initializer_wrapper_contract "$archive_root/libexec/gta-claw-state-init"
validate_runtime_ready_contract "$archive_root/libexec/gta-claw-runtime-ready"
[[ "$(stat -c '%a' "$archive_root/install.sh")" == "755" &&
  "$(stat -c '%a' "$archive_root/uninstall.sh")" == "755" ]] ||
  die "direct lifecycle scripts are not executable"

[[ "$(dpkg-deb --field "$deb_artifact" Architecture)" == "$deb_architecture" ]] ||
  die "Debian architecture mismatch"
[[ "$(dpkg-deb --field "$deb_artifact" Depends)" == \
  "libc6 (>= $BUILD_GLIBC_REQUIREMENT), libgcc-s1, systemd (>= 249), util-linux" ]] ||
  die "Debian dependencies do not match ELF-derived requirements"
deb_contents="$(dpkg-deb --contents "$deb_artifact")"
deb_payload_tar="$work_dir/published-deb-payload.tar"
deb_control_tar="$work_dir/published-deb-control.tar"
open_output_file "$deb_payload_tar" 0644
dpkg-deb --fsys-tarfile "$deb_artifact" >&"$OPEN_OUTPUT_FD"
finish_output_file
open_output_file "$deb_control_tar" 0644
dpkg-deb --ctrl-tarfile "$deb_artifact" >&"$OPEN_OUTPUT_FD"
finish_output_file
validate_archive_entries "$deb_payload_tar" none
validate_archive_entries "$deb_control_tar" none
deb_payload_listing="$(
  tar -tf "$deb_payload_tar" |
    sed -e 's#^\./##' -e 's#/$##' -e '/^$/d' |
    LC_ALL=C sort -u
)"
assert_no_protected_payload_path "Debian package" "$deb_payload_listing"
deb_control_listing="$(
  tar -tf "$deb_control_tar" |
    sed -e 's#^\./##' -e 's#/$##' -e '/^$/d' |
    LC_ALL=C sort -u
)"
expected_deb_control="$(
  printf '%s\n' conffiles control md5sums postinst postrm preinst prerm |
    LC_ALL=C sort
)"
[[ "$deb_control_listing" == "$expected_deb_control" ]] ||
  die "Debian control archive differs from the exact member allowlist"
for script in postinst prerm postrm; do
  cmp -s "$LINUX_DIR/debian/$script" \
    <(tar -xOf "$deb_control_tar" "./$script") ||
      die "Debian maintainer script differs from reviewed source: $script"
done
cmp -s \
  <(
    sed \
      "s/@PACKAGE_VERSION@/$VERSION-$LINUX_PACKAGE_RELEASE/g" \
      "$LINUX_DIR/debian/preinst.in"
  ) \
  <(tar -xOf "$deb_control_tar" ./preinst) ||
  die "Debian preinst differs from reviewed template"
for script in preinst postinst prerm postrm; do
  extracted_script="$work_dir/deb-$script"
  tar -xOf "$deb_control_tar" "./$script" >"$extracted_script"
  if grep -Eq '\|\|[[:space:]]*(true|:)' "$extracted_script"; then
    die "Debian maintainer script swallows a lifecycle failure: $script"
  fi
done
python3 \
  "$LINUX_DIR/tests/reject-javascript-commands.py" \
  "$work_dir/deb-preinst" \
  "$work_dir/deb-postinst" \
  "$work_dir/deb-prerm" \
  "$work_dir/deb-postrm"
if awk 'substr($1, 1, 1) !~ /^[-d]$/ { bad = 1 } END { exit !bad }' \
  <<<"$deb_contents"; then
  die "Debian payload contains a link or special entry"
fi
deb_payload_root="$work_dir/deb-payload-validation"
create_private_validation_directory "$deb_payload_root"
(
  umask 000
  tar --numeric-owner -xf "$deb_payload_tar" -C "$deb_payload_root"
)
validate_published_native_root "$deb_payload_root" "Debian package"

[[ "$(rpm -qp --qf '%{ARCH}' "$rpm_artifact")" == "$rpm_architecture" ]] ||
  die "RPM architecture mismatch"
rpm -qpl "$rpm_artifact" | grep -Fx '/usr/bin/gta-claw-cli' >/dev/null
rpm -qpl "$rpm_artifact" |
  grep -Fx '/usr/libexec/gta-claw/gta-claw-daemon' >/dev/null
rpm_file_listing="$(rpm -qpl "$rpm_artifact" | sed 's#^/##' | LC_ALL=C sort -u)"
assert_no_protected_payload_path "RPM package" "$rpm_file_listing"
rpm -qp --requires "$rpm_artifact" | grep -Fx "glibc >= $BUILD_GLIBC_REQUIREMENT" >/dev/null ||
  die "RPM glibc dependency does not match ELF-derived requirement"
rpm -qp --requires "$rpm_artifact" | grep -Fx "util-linux" >/dev/null ||
  die "RPM does not require the setpriv provider"
rpm_script_validation="$work_dir/published-rpm-scriptlets"
create_private_validation_directory "$rpm_script_validation"
for scriptlet in \
  'pre|PREIN|pre.in' \
  'post|POSTIN|post' \
  'preun|PREUN|preun' \
  'posttrans|POSTTRANS|posttrans' \
  'postun|POSTUN|postun'; do
  name="${scriptlet%%|*}"
  remainder="${scriptlet#*|}"
  tag="${remainder%%|*}"
  source="${remainder##*|}"
  expected_script="$rpm_script_validation/$name.expected"
  actual_script="$rpm_script_validation/$name.actual"
  if [[ "$name" == "pre" ]]; then
    sed \
      -e "s/@PACKAGE_VERSION@/$VERSION-$LINUX_PACKAGE_RELEASE/g" \
      -e 's/%%/%/g' \
      "$LINUX_DIR/rpm/$source" >"$expected_script"
  else
    sed 's/%%/%/g' "$LINUX_DIR/rpm/$source" >"$expected_script"
  fi
  rpm -qp --qf "%{$tag}" "$rpm_artifact" >"$actual_script"
  cmp -s "$expected_script" "$actual_script" ||
    die "RPM $name scriptlet differs from canonical generated source"
done
python3 \
  "$LINUX_DIR/tests/reject-javascript-commands.py" \
  "$rpm_script_validation"
rpm_payload_listing="$(rpm -qplv "$rpm_artifact")"
if awk 'substr($1, 1, 1) !~ /^[-d]$/ { bad = 1 } END { exit !bad }' \
  <<<"$rpm_payload_listing"; then
  die "RPM payload contains a link or special entry"
fi
rpm_payload_root="$work_dir/rpm-payload-validation"
create_private_validation_directory "$rpm_payload_root"
(
  cd "$rpm_payload_root"
  rpm2cpio "$rpm_artifact" | cpio -idm --no-absolute-filenames --quiet
)
reject_links_and_special_files "$rpm_payload_root"
validate_published_native_root "$rpm_payload_root" "RPM package"
diff --no-dereference --recursive "$deb_payload_root" "$rpm_payload_root" >/dev/null ||
  die "Debian and RPM published payload bytes or metadata differ"

rootfs="$deb_payload_root"
python3 "$LINUX_DIR/strict_artifact.py" \
  json \
  "$rootfs/usr/share/doc/gta-claw/package-toolchain.json" \
  >/dev/null
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
  ' "$rootfs/usr/share/doc/gta-claw/package-toolchain.json" >/dev/null ||
  die "packaging toolchain provenance is invalid"
validate_elf_binary "$rootfs/usr/bin/$LINUX_CLI_NAME" "$arch"
validate_elf_binary "$rootfs/usr/libexec/gta-claw/$LINUX_DAEMON_NAME" "$arch"
validate_service_contract "$rootfs/usr/lib/systemd/system/gta-claw-daemon.service"
validate_initializer_service_contract \
  "$rootfs/usr/lib/systemd/system/gta-claw-state-init.service"
validate_sysusers_contract "$rootfs/usr/lib/sysusers.d/gta-claw.conf"
validate_initializer_wrapper_contract \
  "$rootfs/usr/libexec/gta-claw/gta-claw-state-init"
validate_runtime_ready_contract \
  "$rootfs/usr/libexec/gta-claw/gta-claw-runtime-ready"
[[ "$(stat -c '%a' "$rootfs/usr/libexec/gta-claw/gta-claw-state-init")" == "755" ]] ||
  die "initializer wrapper mode is not 0755"
[[ "$(stat -c '%a' "$rootfs/usr/libexec/gta-claw/gta-claw-runtime-ready")" == "755" ]] ||
  die "runtime readiness wrapper mode is not 0755"
[[ ! -e "$rootfs/usr/lib/systemd/system/gta-claw-daemon.socket" ]] ||
  die "unsupported socket unit was installed"
[[ "$(cat "$rootfs/usr/lib/systemd/system-preset/80-gta-claw.preset")" == \
  $'disable gta-claw-daemon.service\ndisable gta-claw-state-init.service' ]] ||
  die "systemd preset contract mismatch"
[[ "$(stat -c '%a' "$rootfs/etc/gta-claw/gta-claw.env")" == "640" ]] ||
  die "environment file mode is not 0640"
[[ "$(stat -c '%a' "$rootfs/etc/gta-claw/credentials/daemon.conf")" == "600" ]] ||
  die "credential file mode is not 0600"
for directory in var/lib/gta-claw var/cache/gta-claw var/log/gta-claw run/gta-claw; do
  [[ ! -e "$rootfs/$directory" && ! -L "$rootfs/$directory" ]] ||
    die "native package stages systemd-managed directory: $directory"
done
reject_forbidden_runtime_content "$rootfs"
verify_sha256_manifest "$rootfs" "$rootfs/usr/share/doc/gta-claw/SHA256SUMS"

for sbom in \
  "$archive_root/sbom.spdx.json" \
  "$rootfs/usr/share/doc/gta-claw/sbom.spdx.json"; do
  jq -e \
    --arg libc_version "$(
      jq -er '.packages[] | select(.id == "libc6") | .version' "$BUILD_RUNTIME_MANIFEST"
    )" \
    --arg libgcc_version "$(
      jq -er '.packages[] | select(.id == "libgcc-s1") | .version' "$BUILD_RUNTIME_MANIFEST"
    )" \
    '
      .spdxVersion == "SPDX-2.3" and
      .dataLicense == "CC0-1.0" and
      any(.packages[];
        .SPDXID == "SPDXRef-Package-libc6" and
        .versionInfo == $libc_version and
        .filesAnalyzed == false
      ) and
      any(.packages[];
        .SPDXID == "SPDXRef-Package-libgcc-s1" and
        .versionInfo == $libgcc_version and
        .filesAnalyzed == false
      )
    ' "$sbom" >/dev/null || die "native SPDX dependency metadata is invalid: $sbom"
done
jq -e \
  --arg manifest_sha "$(sha256_file "$BUILD_MANIFEST")" \
  '.predicate.buildDefinition.buildManifest.digest.sha256 == $manifest_sha' \
  "$rootfs/usr/share/doc/gta-claw/provenance.json" >/dev/null ||
  die "native provenance does not bind the build manifest"

validate_published_oci \
  "$oci_artifact" \
  "$arch" \
  "$work_dir/published-oci-validation" \
  "$BUILD_MANIFEST" \
  "$BUILD_PUBLIC_KEY_FINGERPRINT"
published_oci_layout="$work_dir/published-oci-validation/extracted/$base_name.oci"
published_manifest_digest="$(
  jq -er '.manifests[0].digest | sub("^sha256:"; "")' \
    "$published_oci_layout/index.json"
)"
validate_oci_orchestration_contract \
  "$compose_artifact" \
  "$kubernetes_artifact" \
  "$published_manifest_digest"
cmp -s \
  <(sed "s/@OCI_MANIFEST_DIGEST@/$published_manifest_digest/g" \
    "$LINUX_DIR/oci/compose.yaml.in") \
  "$compose_artifact" ||
  die "published Compose file differs from the packaged OCI manifest rendering"
cmp -s \
  <(sed "s/@OCI_MANIFEST_DIGEST@/$published_manifest_digest/g" \
    "$LINUX_DIR/oci/kubernetes.yaml.in") \
  "$kubernetes_artifact" ||
  die "published Kubernetes file differs from the packaged OCI manifest rendering"

note "validated published Linux $arch tar, package, lifecycle, and OCI artifacts"
