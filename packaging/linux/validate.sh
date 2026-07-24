#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/build-manifest.sh"
source "$SCRIPT_DIR/lib/oci-validation.sh"

require_linux
adopt_safe_output_root
for tool in cpio cmp dpkg-deb jq readelf rpm rpm2cpio sha256sum stat tar; do
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

artifact_dir="$validation_root/artifacts"
work_dir="$validation_root/work"
base_name="$LINUX_PACKAGE_NAME-$VERSION-linux-$arch"
deb_architecture="$(deb_arch "$arch")"
rpm_architecture="$(rpm_arch "$arch")"
tar_artifact="$artifact_dir/$base_name.tar.gz"
deb_artifact="$artifact_dir/${LINUX_PACKAGE_NAME}_${VERSION}-${LINUX_PACKAGE_RELEASE}_${deb_architecture}.deb"
rpm_artifact="$artifact_dir/$LINUX_PACKAGE_NAME-$VERSION-$LINUX_PACKAGE_RELEASE.$rpm_architecture.rpm"
oci_artifact="$artifact_dir/$base_name.oci.tar.gz"

for artifact in \
  "$tar_artifact" "$deb_artifact" "$rpm_artifact" "$oci_artifact" \
  "$artifact_dir/provenance-$arch.json" "$artifact_dir/SHA256SUMS"; do
  assert_regular_unaliased "$artifact" "artifact"
done
verify_sha256_manifest "$artifact_dir" "$artifact_dir/SHA256SUMS"

validate_archive_entries "$tar_artifact" gzip
tar -tzf "$tar_artifact" | grep -Fx "$base_name/bin/$LINUX_DAEMON_NAME" >/dev/null
tar -tzf "$tar_artifact" | grep -Fx "$base_name/bin/$LINUX_CLI_NAME" >/dev/null
tar -tzf "$tar_artifact" | grep -Fx "$base_name/install.sh" >/dev/null
tar -tzf "$tar_artifact" | grep -Fx "$base_name/uninstall.sh" >/dev/null
tar -tzf "$tar_artifact" |
  grep -Fx "$base_name/lib/systemd/system/gta-claw-state-init.service" >/dev/null
tar -tzf "$tar_artifact" |
  grep -Fx "$base_name/lib/sysusers.d/gta-claw.conf" >/dev/null
tar -tzf "$tar_artifact" | grep -Fx "$base_name/provenance.json" >/dev/null
tar -tzf "$tar_artifact" | grep -Fx "$base_name/sbom.spdx.json" >/dev/null
tar -tzf "$tar_artifact" |
  grep -Fx "$base_name/share/doc/gta-claw/build-manifest.json" >/dev/null
if tar -tzf "$tar_artifact" |
  grep -Eiq '(^|/)(node(js)?|npm|npx|pnpm|bun)(/|$)|\.(js|mjs|cjs|node)$'; then
  die "native archive contains a JavaScript runtime or package-manager file"
fi
if tar --numeric-owner -tvzf "$tar_artifact" |
  awk '$2 != "0/0" { bad = 1 } END { exit !bad }'; then
  die "native archive contains non-root ownership"
fi
archive_root="$work_dir/archive/$base_name"
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
grep -F './usr/bin/gta-claw-cli' <<<"$deb_contents" >/dev/null
grep -F './usr/libexec/gta-claw/gta-claw-daemon' <<<"$deb_contents" >/dev/null
if grep -E '\./(var/(lib|cache|log)|run)/gta-claw/?$' <<<"$deb_contents"; then
  die "Debian package owns a systemd-managed runtime directory"
fi
deb_control_listing="$(dpkg-deb --ctrl-tarfile "$deb_artifact" | tar -tf - | LC_ALL=C sort)"
for control_file in control conffiles md5sums preinst postinst prerm postrm; do
  grep -Eq "(^|/)$control_file$" <<<"$deb_control_listing" ||
    die "Debian control archive is missing $control_file"
done
for script in postinst prerm postrm; do
  cmp -s "$LINUX_DIR/debian/$script" \
    <(dpkg-deb --ctrl-tarfile "$deb_artifact" | tar -xOf - "./$script") ||
      die "Debian maintainer script differs from reviewed source: $script"
done
cmp -s \
  <(
    sed \
      "s/@PACKAGE_VERSION@/$VERSION-$LINUX_PACKAGE_RELEASE/g" \
      "$LINUX_DIR/debian/preinst.in"
  ) \
  <(dpkg-deb --ctrl-tarfile "$deb_artifact" | tar -xOf - ./preinst) ||
  die "Debian preinst differs from reviewed template"
for script in preinst postinst prerm postrm; do
  extracted_script="$work_dir/deb-$script"
  dpkg-deb --ctrl-tarfile "$deb_artifact" | tar -xOf - "./$script" >"$extracted_script"
  if grep -Eq '\|\|[[:space:]]*(true|:)' "$extracted_script"; then
    die "Debian maintainer script swallows a lifecycle failure: $script"
  fi
done
if awk 'substr($1, 1, 1) !~ /^[-d]$/ { bad = 1 } END { exit !bad }' \
  <<<"$deb_contents"; then
  die "Debian payload contains a link or special entry"
fi
deb_payload_root="$work_dir/deb-payload-validation"
create_private_validation_directory "$deb_payload_root"
(
  umask 000
  dpkg-deb --fsys-tarfile "$deb_artifact" |
    tar -xf - -C "$deb_payload_root" --no-same-owner
)
reject_links_and_special_files "$deb_payload_root"
verify_sha256_manifest \
  "$deb_payload_root" \
  "$deb_payload_root/usr/share/doc/gta-claw/SHA256SUMS"

[[ "$(rpm -qp --qf '%{ARCH}' "$rpm_artifact")" == "$rpm_architecture" ]] ||
  die "RPM architecture mismatch"
rpm -qpl "$rpm_artifact" | grep -Fx '/usr/bin/gta-claw-cli' >/dev/null
rpm -qpl "$rpm_artifact" |
  grep -Fx '/usr/libexec/gta-claw/gta-claw-daemon' >/dev/null
if rpm -qpl "$rpm_artifact" | grep -E '^/(var/(lib|cache|log)|run)/gta-claw/?$'; then
  die "RPM owns a systemd-managed runtime directory"
fi
rpm -qp --requires "$rpm_artifact" | grep -Fx "glibc >= $BUILD_GLIBC_REQUIREMENT" >/dev/null ||
  die "RPM glibc dependency does not match ELF-derived requirement"
rpm -qp --requires "$rpm_artifact" | grep -Fx "util-linux" >/dev/null ||
  die "RPM does not require the setpriv provider"
rpm_scripts="$(rpm -qp --scripts "$rpm_artifact")"
for contract in \
  'systemctl daemon-reload' \
  'systemctl preset gta-claw-daemon.service' \
  'systemctl restart gta-claw-daemon.service' \
  'systemctl stop gta-claw-daemon.service' \
  '/usr/bin/systemd-sysusers /usr/lib/sysusers.d/gta-claw.conf' \
  '/usr/libexec/gta-claw/gta-claw-state-init' \
  '/usr/libexec/gta-claw/gta-claw-runtime-ready' \
  'refusing gta-claw downgrade' \
  'installed_versions=' \
  'while IFS= read -r installed_version' \
  '/run/gta-claw-daemon.replacement' \
  '/run/gta-claw-daemon.ready-for-replacement' \
  '/run/gta-claw-daemon.old-removal-succeeded' \
  '/run/gta-claw-initialization-failed' \
  'systemctl is-active --quiet gta-claw-daemon.service' \
  'systemctl disable gta-claw-daemon.service'; do
  grep -F "$contract" <<<"$rpm_scripts" >/dev/null ||
    die "RPM lifecycle script contract missing: $contract"
done
if grep -Eiq '(^|[[:space:]])(curl|wget|nc|bash -c|sh -c|eval)([[:space:]]|$)' \
  <<<"$rpm_scripts"; then
  die "RPM lifecycle script contains network or dynamic execution"
fi
if grep -Eq '\|\|[[:space:]]*(true|:)' <<<"$rpm_scripts"; then
  die "RPM lifecycle script swallows a lifecycle failure"
fi
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
verify_sha256_manifest \
  "$rpm_payload_root" \
  "$rpm_payload_root/usr/share/doc/gta-claw/SHA256SUMS"

rootfs="$work_dir/rootfs"
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
  "$work_dir/archive/$base_name/sbom.spdx.json" \
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

note "validated published Linux $arch tar, package, lifecycle, and OCI artifacts"
