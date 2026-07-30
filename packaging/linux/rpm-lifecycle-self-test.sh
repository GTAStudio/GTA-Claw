#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
work="$SCRIPT_DIR/.rpm-lifecycle-self-test-$$"
rm -rf -- "$work"
mkdir -m 0700 -- \
  "$work" \
  "$work/bin" \
  "$work/rendered" \
  "$work/state" \
  "$work/systemd"
trap 'rm -rf -- "$work"' EXIT INT TERM

for scriptlet in pre post preun postun posttrans; do
  sed 's/%%{NEVRA}/%{NEVRA}/g' \
    "$SCRIPT_DIR/rpm/$scriptlet" >"$work/rendered/$scriptlet"
done

printf 'gta-claw-0:0.1.0-1.x86_64\n' >"$work/installed-nevras"
printf 'old daemon payload bytes\n' >"$work/daemon"
printf 'administrator lifecycle marker\n' >"$work/state/operator-marker"
printf 'active\n' >"$work/active"
printf 'enabled\n' >"$work/enabled"

cat >"$work/bin/rpm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 4 ||
  "$1" != "-q" ||
  "$2" != "--qf" ||
  "$3" != '%{NEVRA}\n' ||
  "$4" != "gta-claw" ]]; then
  echo "unexpected rpm query: $*" >&2
  exit 2
fi
cat "${RPM_TEST_ROOT:?}/installed-nevras"
EOF
cat >"$work/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root="${RPM_TEST_ROOT:?}"
printf '%s\n' "$*" >>"$root/systemctl-commands"
case "$1" in
  is-active)
    [[ "$(cat "$root/active")" == "active" ]]
    ;;
  is-enabled)
    cat "$root/enabled"
    [[ "$(cat "$root/enabled")" == enabled* ]]
    ;;
  disable)
    current="$(cat "$root/enabled")"
    case "$current:${2:-}" in
      enabled:--runtime | enabled-runtime:gta-claw-daemon.service)
        echo "disable scope did not match prior enablement: $current" >&2
        exit 1
        ;;
    esac
    printf 'disabled\n' >"$root/enabled"
    ;;
  enable)
    if [[ "${2:-}" == "--runtime" ]]; then
      printf 'enabled-runtime\n' >"$root/enabled"
    else
      printf 'enabled\n' >"$root/enabled"
    fi
    ;;
  stop)
    if [[ "${RPM_TEST_FAIL_STOP:-0}" == "1" ]]; then
      exit 1
    fi
    printf 'inactive\n' >"$root/active"
    ;;
  start)
    if [[ "${RPM_TEST_FAIL_START:-0}" == "1" ]]; then
      exit 1
    fi
    printf 'active\n' >"$root/active"
    ;;
  restart)
    if [[ "${RPM_TEST_FAIL_RESTART:-0}" == "1" ]]; then
      printf 'inactive\n' >"$root/active"
      exit 1
    fi
    case "$(cat "$root/enabled")" in
      masked | masked-runtime)
        echo "masked service must not be restarted" >&2
        exit 1
        ;;
    esac
    printf 'active\n' >"$root/active"
    ;;
  daemon-reload | preset)
    ;;
  *)
    echo "unsupported fake systemctl command: $*" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$work/bin/rpm" "$work/bin/systemctl"
: >"$work/systemctl-commands"

old_nevra="$(cat "$work/installed-nevras")"
old_payload="$(sha256sum "$work/daemon" | awk '{print $1}')"
old_marker="$(sha256sum "$work/state/operator-marker" | awk '{print $1}')"
if PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  GTA_CLAW_PACKAGE_TEST_FAIL_UPGRADE_PREPARE=1 \
  sh "$work/rendered/pre" 2; then
  echo "injected RPM preparation failure unexpectedly succeeded" >&2
  exit 1
fi
[[ "$(cat "$work/installed-nevras")" == "$old_nevra" ]] ||
  {
    echo "failed upgrade changed the installed NEVRA" >&2
    exit 1
  }
[[ "$(sha256sum "$work/daemon" | awk '{print $1}')" == "$old_payload" ]] ||
  {
    echo "failed upgrade changed the prior payload" >&2
    exit 1
  }
[[ "$(sha256sum "$work/state/operator-marker" | awk '{print $1}')" == "$old_marker" ]] ||
  {
    echo "failed upgrade changed the prior lifecycle marker" >&2
    exit 1
  }
test ! -e "$work/state/gta-claw-daemon.old-nevra"
test ! -e "$work/state/gta-claw-daemon.upgrade-prepared"

printf 'active\n' >"$work/active"
printf 'enabled\n' >"$work/enabled"
if PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  RPM_TEST_FAIL_STOP=1 \
  sh "$work/rendered/pre" 2; then
  echo "injected RPM upgrade stop failure unexpectedly succeeded" >&2
  exit 1
fi
[[ "$(cat "$work/installed-nevras")" == "$old_nevra" ]]
[[ "$(sha256sum "$work/daemon" | awk '{print $1}')" == "$old_payload" ]]
[[ "$(cat "$work/active")" == "active" ]]
[[ "$(cat "$work/enabled")" == "enabled" ]]
test ! -e "$work/state/gta-claw-daemon.old-nevra"
test ! -e "$work/state/gta-claw-daemon.upgrade-prepared"

rm -f "$work/state"/gta-claw-daemon.*
printf 'active\n' >"$work/active"
printf 'enabled\n' >"$work/enabled"
if PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  GTA_CLAW_PACKAGE_TEST_FAIL_UPGRADE_PREPARE=1 \
  RPM_TEST_FAIL_START=1 \
  sh "$work/rendered/pre" 2; then
  echo "RPM upgrade with a failed service restoration unexpectedly succeeded" >&2
  exit 1
fi
[[ "$(cat "$work/installed-nevras")" == "$old_nevra" ]]
[[ "$(sha256sum "$work/daemon" | awk '{print $1}')" == "$old_payload" ]]
[[ "$(cat "$work/active")" == "inactive" ]]
test -f "$work/state/gta-claw-daemon.was-active"
test -z "$(
  find \
    "$work/state" \
    -maxdepth 1 \
    -name 'gta-claw-daemon.*' \
    ! -name 'gta-claw-daemon.was-active' \
    -print \
    -quit
)"
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/pre" 2
printf 'gta-claw-0:0.1.0-2.x86_64\n' >"$work/installed-nevras"
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/post" 2
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/preun" 1
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/postun" 1
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/posttrans" 2
[[ "$(cat "$work/active")" == "active" ]]
test -z "$(find "$work/state" -maxdepth 1 -name 'gta-claw-daemon.*' -print -quit)"
printf '%s\n' "$old_nevra" >"$work/installed-nevras"

PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  RPM_TEST_FAIL_STOP=1 \
  sh "$work/rendered/preun" 0 &&
  {
    echo "injected RPM erase failure unexpectedly succeeded" >&2
    exit 1
  }
[[ "$(cat "$work/enabled")" == "enabled" ]] ||
  {
    echo "failed RPM erase did not restore prior enablement" >&2
    exit 1
  }
[[ "$(cat "$work/active")" == "active" ]] ||
  {
    echo "failed RPM erase did not preserve prior activity" >&2
    exit 1
  }
test ! -e "$work/state/gta-claw-daemon.remove-prepared"

printf 'active\n' >"$work/active"
printf 'enabled-runtime\n' >"$work/enabled"
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  RPM_TEST_FAIL_STOP=1 \
  sh "$work/rendered/preun" 0 &&
  {
    echo "runtime-enabled RPM erase failure unexpectedly succeeded" >&2
    exit 1
  }
[[ "$(cat "$work/enabled")" == "enabled-runtime" ]] ||
  {
    echo "failed RPM erase did not restore runtime enablement" >&2
    exit 1
  }

rm -f "$work/state"/gta-claw-daemon.*
printf 'active\n' >"$work/active"
printf 'enabled\n' >"$work/enabled"
printf 'gta-claw-0:0.1.0-1.x86_64\n' >"$work/installed-nevras"
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/pre" 2
printf 'gta-claw-0:0.1.0-2.x86_64\n' >"$work/installed-nevras"
if PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  RPM_TEST_FAIL_RESTART=1 \
  sh "$work/rendered/post" 2; then
  echo "injected post-commit RPM activation failure unexpectedly succeeded" >&2
  exit 1
fi
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/preun" 1
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/postun" 1
if PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/posttrans" 2; then
  echo "post-commit RPM activation failure was reported as success" >&2
  exit 1
fi
[[ "$(cat "$work/installed-nevras")" == "gta-claw-0:0.1.0-2.x86_64" ]]
[[ "$(cat "$work/active")" == "inactive" ]]
test -f "$work/state/gta-claw-daemon.was-active"
test -z "$(
  find \
    "$work/state" \
    -maxdepth 1 \
    -name 'gta-claw-daemon.*' \
    ! -name 'gta-claw-daemon.was-active' \
    -print \
    -quit
)"
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/pre" 2
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/post" 2
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/preun" 1
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/postun" 1
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/posttrans" 2
[[ "$(cat "$work/active")" == "active" ]]
test -z "$(find "$work/state" -maxdepth 1 -name 'gta-claw-daemon.*' -print -quit)"

printf 'active\n' >"$work/active"
printf 'enabled-runtime\n' >"$work/enabled"
PATH="$work/bin:$PATH" \
  RPM_TEST_ROOT="$work" \
  GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
  GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
  sh "$work/rendered/preun" 0
  PATH="$work/bin:$PATH" \
    RPM_TEST_ROOT="$work" \
    GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
    GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
    sh "$work/rendered/postun" 0
  [[ "$(cat "$work/enabled")" == "disabled" ]] ||
  {
    echo "successful RPM erase retained runtime enablement" >&2
    exit 1
  }

test_masked_upgrade() {
  local enabled_state="$1"
  local expected_marker="$2"
  rm -f "$work/state"/gta-claw-daemon.*
  : >"$work/systemctl-commands"
  printf 'active\n' >"$work/active"
  printf '%s\n' "$enabled_state" >"$work/enabled"
  printf 'gta-claw-0:0.1.0-1.x86_64\n' >"$work/installed-nevras"

  PATH="$work/bin:$PATH" \
    RPM_TEST_ROOT="$work" \
    GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
    GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
    sh "$work/rendered/pre" 2
  test -f "$work/state/gta-claw-daemon.was-active"
  test -f "$work/state/$expected_marker"

  printf 'gta-claw-0:0.1.0-2.x86_64\n' >"$work/installed-nevras"
  PATH="$work/bin:$PATH" \
    RPM_TEST_ROOT="$work" \
    GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
    GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
    sh "$work/rendered/post" 2
  [[ "$(cat "$work/active")" == "active" ]]
  [[ "$(cat "$work/enabled")" == "$enabled_state" ]]
  if grep -Fq 'restart gta-claw-daemon.service' "$work/systemctl-commands"; then
    echo "$enabled_state upgrade attempted to restart a masked active unit" >&2
    exit 1
  fi

  PATH="$work/bin:$PATH" \
    RPM_TEST_ROOT="$work" \
    GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
    GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
    sh "$work/rendered/preun" 1
  PATH="$work/bin:$PATH" \
    RPM_TEST_ROOT="$work" \
    GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
    GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
    sh "$work/rendered/postun" 1
  PATH="$work/bin:$PATH" \
    RPM_TEST_ROOT="$work" \
    GTA_CLAW_PACKAGE_STATE_ROOT="$work/state" \
    GTA_CLAW_SYSTEMD_RUNTIME_DIR="$work/systemd" \
    sh "$work/rendered/posttrans" 2

  [[ "$(cat "$work/installed-nevras")" == "gta-claw-0:0.1.0-2.x86_64" ]]
  [[ "$(cat "$work/active")" == "active" ]]
  [[ "$(cat "$work/enabled")" == "$enabled_state" ]]
  test -z "$(find "$work/state" -maxdepth 1 -name 'gta-claw-daemon.*' -print -quit)"
}

test_masked_upgrade masked gta-claw-daemon.was-masked
test_masked_upgrade masked-runtime gta-claw-daemon.was-masked-runtime

echo "RPM pre/post-commit, failed-erase, and masked-upgrade self-tests passed"
