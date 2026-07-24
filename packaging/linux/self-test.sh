#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
: "${OUTPUT_ROOT:=$REPO_ROOT/target/linux-self-test-$BASHPID}"
source "$SCRIPT_DIR/lib/common.sh"

require_linux
for tool in gcc jq patchelf python3 readelf sha256sum tar; do
  require_tool "$tool"
done
[[ "$(sha256_file "$REPO_ROOT/crates/claw-sqlite-file-control/Cargo.toml")" == \
  "b2ce476ecc84143cfa0c071d6289ab35ec1f425ac4aa5af5fc47e6cc3258da82" ]] ||
  die "protected SQLite file-control manifest hash changed"
if grep -Eq 'test-hooks|public.*raw.?handle|raw.?handle.*public' \
  "$REPO_ROOT/crates/claw-sqlite-file-control/Cargo.toml"; then
  die "protected SQLite file-control manifest exposes a test or raw-handle feature"
fi
initialize_output_root
work="$OUTPUT_ROOT/tests"
ensure_output_directory "$work"
common="$SCRIPT_DIR/lib/common.sh"
tests=0

expect_failure() {
  local name="$1"
  shift
  tests=$((tests + 1))
  if "$@" >"$work/$name.stdout" 2>"$work/$name.stderr"; then
    die "self-test expected failure but succeeded: $name"
  fi
}

expect_success() {
  local name="$1"
  shift
  tests=$((tests + 1))
  "$@" >"$work/$name.stdout" 2>"$work/$name.stderr" ||
    die "self-test failed: $name"
}

expect_failure missing-tool \
  bash -c "source '$common'; require_tool gta-claw-tool-that-does-not-exist"
expect_failure unsafe-version \
  env VERSION=../escape bash -c "source '$common'"
expect_failure unsafe-output-traversal \
  env OUTPUT_ROOT="$OUTPUT_ROOT/../escape" \
  bash -c "source '$common'; initialize_output_root"
expect_failure unsafe-output-absolute \
  env OUTPUT_ROOT=/tmp/gta-claw-escape \
  bash -c "source '$common'; initialize_output_root"
expect_failure unsafe-architecture \
  bash -c "source '$common'; arch_target '../arm64'"
expect_failure cargo-target-relative \
  bash -c "source '$common'; validate_new_private_root_path 'target/build' CARGO_TARGET_DIR"
expect_failure cargo-target-traversal \
  bash -c "source '$common'; validate_new_private_root_path '$REPO_ROOT/target/../escape' CARGO_TARGET_DIR"
expect_failure cargo-target-outside \
  bash -c "source '$common'; validate_new_private_root_path '/tmp/gta-claw-build' CARGO_TARGET_DIR"

expect_success umask-000-private-root \
  env OUTPUT_ROOT="$work/umask-000" bash -c "
    umask 000
    source '$common'
    initialize_output_root
    test \"\$(stat -c '%a' \"\$OUTPUT_ROOT\")\" = 700
    test \"\$(stat -c '%a' \"\$OUTPUT_ROOT.lock\")\" = 700
  "
expect_success umask-002-private-root \
  env OUTPUT_ROOT="$work/umask-002" bash -c "
    umask 002
    source '$common'
    initialize_output_root
    test \"\$(stat -c '%a' \"\$OUTPUT_ROOT\")\" = 700
    test \"\$(stat -c '%a' \"\$OUTPUT_ROOT.lock\")\" = 700
  "

existing="$work/existing-output"
mkdir "$existing"
expect_failure existing-output-collision \
  env OUTPUT_ROOT="$existing" bash -c "source '$common'; initialize_output_root"

real_parent="$work/real-parent"
mkdir "$real_parent"
ln -s "$real_parent" "$work/intermediate-link"
expect_failure existing-intermediate-symlink \
  env OUTPUT_ROOT="$work/intermediate-link/output" \
  bash -c "source '$common'; initialize_output_root"
ln -s "$work/missing-parent" "$work/dangling-link"
expect_failure dangling-intermediate-symlink \
  env OUTPUT_ROOT="$work/dangling-link/output" \
  bash -c "source '$common'; initialize_output_root"

printf 'hard link input\n' >"$work/hardlink-a"
ln "$work/hardlink-a" "$work/hardlink-b"
expect_failure hardlink-input \
  bash -c "source '$common'; assert_regular_unaliased '$work/hardlink-a' input"
expect_success verified-hardlink-ingestion \
  copy_verified_input "$work/hardlink-a" "$work/hardlink-copy" 0644

printf 'temporary\n' >"$work/publish.tmp"
printf 'collision\n' >"$work/publish.final"
expect_failure regular-output-collision \
  env OUTPUT_ROOT="$OUTPUT_ROOT" bash -c "
    source '$common'
    OUTPUT_LOCK_PATH='$OUTPUT_LOCK_PATH'
    OUTPUT_LOCK_ID='$OUTPUT_LOCK_ID'
    OUTPUT_ROOT_ID='$OUTPUT_ROOT_ID'
    OUTPUT_LOCK_HELD=1
    publish_output_file '$work/publish.tmp' '$work/publish.final'
  "

write_output_text "$work/outside-sentinel" 0644 $'outside sentinel\n'
expect_failure symlink-replacement-during-write \
  env \
    OUTPUT_ROOT="$work/swap-output" \
    OUTSIDE_SENTINEL="$work/outside-sentinel" \
    bash -c "
      source '$common'
      initialize_output_root
      open_output_file \"\$OUTPUT_ROOT/payload\" 0644
      mv \"\$OUTPUT_ROOT/payload\" \"\$OUTPUT_ROOT/displaced\"
      ln -s \"\$OUTSIDE_SENTINEL\" \"\$OUTPUT_ROOT/payload\"
      printf 'attacker-controlled bytes\n' >&\"\$OPEN_OUTPUT_FD\"
      finish_output_file
    "
[[ "$(cat "$work/outside-sentinel")" == "outside sentinel" ]] ||
  die "open-descriptor write followed a replacement symlink"
[[ "$(cat "$work/swap-output/displaced")" == "attacker-controlled bytes" ]] ||
  die "open-descriptor write did not remain bound to the reserved inode"
tests=$((tests + 1))

mkdir "$work/tree-with-link"
ln -s "$work/hardlink-a" "$work/tree-with-link/link"
expect_failure staged-symlink \
  bash -c "source '$common'; reject_links_and_special_files '$work/tree-with-link'"
mkdir "$work/tree-with-hardlink"
ln "$work/hardlink-a" "$work/tree-with-hardlink/alias"
expect_failure staged-hardlink \
  bash -c "source '$common'; reject_links_and_special_files '$work/tree-with-hardlink'"

mkdir "$work/archive-input"
printf 'unsafe archive member\n' >"$work/archive-input/input"
tar \
  --transform='s#^#../#' \
  -C "$work/archive-input" \
  -czf "$work/unsafe.tar.gz" \
  input
expect_failure traversal-archive bash -c "
  listing=\$(tar -tzf '$work/unsafe.tar.gz')
  ! grep -E '(^/|(^|/)\\.\\.(/|$)|\\\\)' <<<\"\$listing\"
"

if [[ "$(uname -m)" == "x86_64" ]]; then
  expect_failure architecture-mismatch \
    bash -c "source '$common'; validate_elf_arch /bin/true arm64"

  write_output_text "$work/hello.c" 0644 $'int main(void) { return 0; }\n'
  gcc "$work/hello.c" -o "$work/hello-pie"
  expect_success valid-pie \
    bash -c "source '$common'; validate_elf_binary '$work/hello-pie' x86_64"

  gcc -no-pie "$work/hello.c" -o "$work/hello-exec"
  expect_failure elf-type \
    bash -c "source '$common'; validate_elf_binary '$work/hello-exec' x86_64"

  cp "$work/hello-pie" "$work/hello-interpreter"
  patchelf \
    --set-interpreter '/lib64/ld-linux-x86-64.so.2]evil' \
    "$work/hello-interpreter"
  expect_failure elf-interpreter \
    bash -c "source '$common'; validate_elf_binary '$work/hello-interpreter' x86_64"

  cp "$work/hello-pie" "$work/hello-runpath"
  patchelf --set-rpath /tmp/evil-library "$work/hello-runpath"
  expect_failure elf-runpath \
    bash -c "source '$common'; validate_elf_binary '$work/hello-runpath' x86_64"

  cp "$work/hello-pie" "$work/hello-needed"
  patchelf \
    --replace-needed libc.so.6 'libc.so.6]evil' \
    "$work/hello-needed"
  expect_failure elf-needed-delimiter \
    bash -c "source '$common'; validate_elf_binary '$work/hello-needed' x86_64"

  write_output_text "$work/glibc-version.map" 0644 \
    $'GLIBC_9.99 { global: too_new; };\n'
  write_output_text "$work/too-new.c" 0644 \
    $'int too_new(void) { return 0; }\n'
  write_output_text "$work/use-too-new.S" 0644 \
    $'.global _start\n_start:\n  call too_new\n  mov $60, %rax\n  xor %rdi, %rdi\n  syscall\n'
  gcc -shared -fPIC \
    -Wl,--version-script="$work/glibc-version.map" \
    -Wl,-soname,libc.so.6 \
    "$work/too-new.c" \
    -o "$work/libc-too-new.so"
  gcc -nostdlib -fPIE -pie \
    "$work/use-too-new.S" \
    "$work/libc-too-new.so" \
    -o "$work/use-too-new"
  expect_failure glibc-ceiling \
    bash -c "source '$common'; validate_glibc_requirement '$work/use-too-new'"

  write_output_text "$work/glibc-malformed.map" 0644 \
    $'GLIBC_2.34evil { global: malformed; };\n'
  write_output_text "$work/malformed.c" 0644 \
    $'int malformed(void) { return 0; }\n'
  write_output_text "$work/use-malformed.S" 0644 \
    $'.global _start\n_start:\n  call malformed\n  mov $60, %rax\n  xor %rdi, %rdi\n  syscall\n'
  gcc -shared -fPIC \
    -Wl,--version-script="$work/glibc-malformed.map" \
    -Wl,-soname,libc.so.6 \
    "$work/malformed.c" \
    -o "$work/libc-malformed.so"
  gcc -nostdlib -fPIE -pie \
    "$work/use-malformed.S" \
    "$work/libc-malformed.so" \
    -o "$work/use-malformed"
  expect_failure glibc-malformed-boundary \
    bash -c "source '$common'; validate_elf_binary '$work/use-malformed' x86_64"
fi

mkdir "$work/forbidden-runtime"
printf 'not executable\n' >"$work/forbidden-runtime/node"
expect_failure forbidden-runtime \
  bash -c "source '$common'; reject_forbidden_runtime_content '$work/forbidden-runtime'"

cp "$SCRIPT_DIR/systemd/gta-claw-daemon.service" "$work/service-good"
grep -v '^NoNewPrivileges=yes$' "$work/service-good" >"$work/service-weakened"
grep -v '^User=gta-claw$' "$work/service-good" >"$work/service-dynamic"
expect_success hardened-service \
  bash -c "source '$common'; validate_service_contract '$work/service-good'"
expect_failure weakened-service \
  bash -c "source '$common'; validate_service_contract '$work/service-weakened'"
expect_failure missing-static-user \
  bash -c "source '$common'; validate_service_contract '$work/service-dynamic'"
{
  cat "$work/service-good"
  printf 'Environment=API_TOKEN=plaintext\n'
} >"$work/service-secret"
expect_failure environment-secret \
  bash -c "source '$common'; validate_service_contract '$work/service-secret'"
expect_success hardened-initializer-service \
  bash -c "source '$common'; validate_initializer_service_contract '$SCRIPT_DIR/systemd/gta-claw-state-init.service'"
expect_success static-sysusers \
  bash -c "source '$common'; validate_sysusers_contract '$SCRIPT_DIR/sysusers/gta-claw.conf'"
expect_success nonrepairing-initializer-wrapper \
  bash -c "source '$common'; validate_initializer_wrapper_contract '$SCRIPT_DIR/libexec/gta-claw-state-init'"
expect_success runtime-readiness-wrapper \
  bash -c "source '$common'; validate_runtime_ready_contract '$SCRIPT_DIR/libexec/gta-claw-runtime-ready'"
expect_success direct-lifecycle \
  bash -c "source '$common'; validate_direct_lifecycle_contract '$SCRIPT_DIR/direct/install.sh' '$SCRIPT_DIR/direct/uninstall.sh'"
expect_success oci-two-phase-orchestration \
  bash -c "source '$common'; validate_oci_orchestration_contract '$SCRIPT_DIR/oci/compose.yaml' '$SCRIPT_DIR/oci/kubernetes.yaml'"
python3 - \
  "$SCRIPT_DIR/oci/compose.yaml" \
  "$work/compose-root-runtime.yaml" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
needle = '    user: "65532:65532"\n'
assert source.count(needle) == 1
Path(sys.argv[2]).write_text(source.replace(needle, '    user: "0:0"\n'), encoding="utf-8")
PY
expect_failure oci-compose-root-runtime \
  bash -c "source '$common'; validate_oci_orchestration_contract '$work/compose-root-runtime.yaml' '$SCRIPT_DIR/oci/kubernetes.yaml'"
python3 - \
  "$SCRIPT_DIR/oci/compose.yaml" \
  "$work/compose-unshared-state.yaml" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
needle = "      - gta-claw-state:/var/lib\n"
index = source.rfind(needle)
assert index >= 0
Path(sys.argv[2]).write_text(source[:index] + source[index + len(needle):], encoding="utf-8")
PY
expect_failure oci-compose-unshared-state \
  bash -c "source '$common'; validate_oci_orchestration_contract '$work/compose-unshared-state.yaml' '$SCRIPT_DIR/oci/kubernetes.yaml'"
python3 - \
  "$SCRIPT_DIR/oci/kubernetes.yaml" \
  "$work/kubernetes-root-runtime.yaml" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
needle = "            runAsUser: 65532\n"
assert source.count(needle) == 1
Path(sys.argv[2]).write_text(source.replace(needle, "            runAsUser: 0\n"), encoding="utf-8")
PY
expect_failure oci-kubernetes-root-runtime \
  bash -c "source '$common'; validate_oci_orchestration_contract '$SCRIPT_DIR/oci/compose.yaml' '$work/kubernetes-root-runtime.yaml'"

expect_failure release-signing-without-release-mode "$SCRIPT_DIR/release.sh" sign
expect_failure publication-without-release-mode "$SCRIPT_DIR/release.sh" publish
expect_failure release-commit-mismatch \
  env \
    RELEASE_MODE=1 \
    GITHUB_REF=refs/tags/v"$VERSION" \
    RELEASE_COMMIT=0000000000000000000000000000000000000000 \
    "$SCRIPT_DIR/release.sh" publish
expect_failure missing-package-input \
  env OUTPUT_ROOT="$work/missing-input-output" \
  "$SCRIPT_DIR/package.sh" "$([[ "$(uname -m)" == "x86_64" ]] && echo x86_64 || echo arm64)" \
  "$work/missing-binaries"

printf 'Linux packaging security self-tests passed (%d cases)\n' "$tests"
