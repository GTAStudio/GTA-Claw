#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/lifecycle-validation.sh"
source "$SCRIPT_DIR/lib/common.sh"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

work="$SCRIPT_DIR/.lifecycle-contract-self-test-$$"
rm -rf -- "$work"
mkdir -m 0700 -- "$work"
trap 'rm -rf -- "$work"' EXIT INT TERM
tests=0

insert_service_directive() {
  local source="$1"
  local directive="$2"
  local destination="$3"
  awk -v directive="$directive" '
    $0 == "[Install]" { print directive }
    { print }
  ' "$source" >"$destination"
}

expect_failure() {
  local name="$1"
  shift
  tests=$((tests + 1))
  if ( "$@" ) >"$work/$name.stdout" 2>"$work/$name.stderr"; then
    printf 'expected lifecycle contract failure: %s\n' "$name" >&2
    exit 1
  fi
}

validate_debian_lifecycle_contract "$SCRIPT_DIR/debian"
rpm_source="$(
  cat \
    "$SCRIPT_DIR/rpm/pre" \
    "$SCRIPT_DIR/rpm/post" \
    "$SCRIPT_DIR/rpm/preun" \
    "$SCRIPT_DIR/rpm/postun" \
    "$SCRIPT_DIR/rpm/posttrans" |
    sed 's/%%{NEVRA}/%{NEVRA}/g'
)"
validate_rpm_lifecycle_contract "$rpm_source"

mkdir "$work/bin"
rpm_report="$work/rpm-scripts"
{
  printf 'preinstall scriptlet (using /bin/sh):\n'
  cat "$SCRIPT_DIR/rpm/pre"
  printf '\npostinstall scriptlet (using /bin/sh):\n'
  cat "$SCRIPT_DIR/rpm/post"
  printf '\npreuninstall scriptlet (using /bin/sh):\n'
  cat "$SCRIPT_DIR/rpm/preun"
  printf '\npostuninstall scriptlet (using /bin/sh):\n'
  cat "$SCRIPT_DIR/rpm/postun"
  printf '\nposttrans scriptlet (using /bin/sh):\n'
  cat "$SCRIPT_DIR/rpm/posttrans"
} >"$rpm_report"
touch "$work/gta-claw.rpm"
cat >"$work/bin/rpm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${2:-}" in
  --scripts)
    cat "${RPM_TEST_REPORT:?}"
    ;;
  --qf)
    format="${3:?}"
    if [[ "$format" == *'%{PREINPROG}'* ]]; then
      printf '/bin/sh\n%.0s' {1..5}
    elif [[ "$format" =~ ^%\{(PREIN|POSTIN|PREUN|POSTUN|POSTTRANS)\}$ ]]; then
      case "${BASH_REMATCH[1]}" in
        PREIN) script=pre ;;
        POSTIN) script=post ;;
        PREUN) script=preun ;;
        POSTUN) script=postun ;;
        POSTTRANS) script=posttrans ;;
      esac
      sed 's/%%{NEVRA}/%{NEVRA}/g' "${RPM_TEST_SCRIPT_ROOT:?}/$script"
      if [[ "${RPM_TEST_EXTRA_BODY_TAG:-}" == "${BASH_REMATCH[1]}" ]]; then
        printf '\nprintf "unreviewed root command\\n" >&2\n'
      fi
    elif [[ -n "${RPM_TEST_NONZERO_FLAG:-}" &&
      "$format" == "%{$RPM_TEST_NONZERO_FLAG}" ]]; then
      printf '1'
    elif [[ -n "${RPM_TEST_FORBIDDEN_TAG:-}" &&
      "$format" == "[%{$RPM_TEST_FORBIDDEN_TAG}]" ]]; then
      printf 'forbidden script body'
    fi
    ;;
  *)
    printf 'unexpected RPM test query: %q\n' "$*" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$work/bin/rpm"
PATH="$work/bin:$PATH" \
RPM_TEST_REPORT="$rpm_report" \
RPM_TEST_SCRIPT_ROOT="$SCRIPT_DIR/rpm" \
  validate_rpm_scriptlet_metadata "$work/gta-claw.rpm"

{
  printf 'pretrans scriptlet (using /bin/sh):\nexit 0\n'
  cat "$rpm_report"
} >"$work/rpm-scripts-pretrans"
expect_failure extra-rpm-pretrans \
  env \
    PATH="$work/bin:$PATH" \
    RPM_TEST_REPORT="$work/rpm-scripts-pretrans" \
    RPM_TEST_SCRIPT_ROOT="$SCRIPT_DIR/rpm" \
    bash -c \
      "source '$SCRIPT_DIR/lib/lifecycle-validation.sh'; source '$SCRIPT_DIR/lib/common.sh'; validate_rpm_scriptlet_metadata '$work/gta-claw.rpm'"

expect_failure nonzero-rpm-scriptlet-flags \
  env \
    PATH="$work/bin:$PATH" \
    RPM_TEST_REPORT="$rpm_report" \
    RPM_TEST_NONZERO_FLAG=PREINFLAGS \
    RPM_TEST_SCRIPT_ROOT="$SCRIPT_DIR/rpm" \
    bash -c \
      "source '$SCRIPT_DIR/lib/lifecycle-validation.sh'; source '$SCRIPT_DIR/lib/common.sh'; validate_rpm_scriptlet_metadata '$work/gta-claw.rpm'"

expect_failure forbidden-rpm-trigger \
  env \
    PATH="$work/bin:$PATH" \
    RPM_TEST_REPORT="$rpm_report" \
    RPM_TEST_FORBIDDEN_TAG=TRIGGERSCRIPTS \
    RPM_TEST_SCRIPT_ROOT="$SCRIPT_DIR/rpm" \
    bash -c \
      "source '$SCRIPT_DIR/lib/lifecycle-validation.sh'; source '$SCRIPT_DIR/lib/common.sh'; validate_rpm_scriptlet_metadata '$work/gta-claw.rpm'"

expect_failure extra-rpm-post-command \
  env \
    PATH="$work/bin:$PATH" \
    RPM_TEST_EXTRA_BODY_TAG=POSTIN \
    RPM_TEST_REPORT="$rpm_report" \
    RPM_TEST_SCRIPT_ROOT="$SCRIPT_DIR/rpm" \
    bash -c \
      "source '$SCRIPT_DIR/lib/lifecycle-validation.sh'; source '$SCRIPT_DIR/lib/common.sh'; validate_rpm_scriptlet_metadata '$work/gta-claw.rpm'"

service="$SCRIPT_DIR/systemd/gta-claw-daemon.service"
validate_service_contract "$service"
insert_service_directive \
  "$service" \
  'IPAddressDeny=any' \
  "$work/service-blocked-provider-egress"
expect_failure blocked-provider-egress \
  validate_service_contract "$work/service-blocked-provider-egress"
sed 's/^RestrictAddressFamilies=.*/RestrictAddressFamilies=AF_UNIX/' \
  "$service" >"$work/service-unix-only"
expect_failure unix-only-service \
  validate_service_contract "$work/service-unix-only"
insert_service_directive \
  "$service" \
  'PrivateNetwork=yes' \
  "$work/service-private-network"
expect_failure private-network-service \
  validate_service_contract "$work/service-private-network"
insert_service_directive \
  "$service" \
  'RestrictAddressFamilies=' \
  "$work/service-reset-address-families"
expect_failure reset-address-families \
  validate_service_contract "$work/service-reset-address-families"

cp -R "$SCRIPT_DIR/debian" "$work/missing-disable"
sed -i.bak \
  '/systemctl --system disable gta-claw-daemon.service/d' \
  "$work/missing-disable/prerm"
rm "$work/missing-disable/prerm.bak"
expect_failure missing-debian-disable \
  validate_debian_lifecycle_contract "$work/missing-disable"

cp -R "$SCRIPT_DIR/debian" "$work/swallowed-stop"
sed -i.bak \
  's/deb-systemd-invoke stop gta-claw-daemon.service >\/dev\/null/& || true/' \
  "$work/swallowed-stop/prerm"
rm "$work/swallowed-stop/prerm.bak"
expect_failure swallowed-debian-stop \
  validate_debian_lifecycle_contract "$work/swallowed-stop"

expect_failure suppressed-rpm-diagnostics \
  validate_rpm_lifecycle_contract \
  "$rpm_source"$'\n''systemctl status gta-claw-daemon.service >/dev/null 2>&1'

runtime_mask_only="$(
  sed '/gta-claw-daemon\.was-masked"/d' <<<"$rpm_source"
)"
grep -F 'gta-claw-daemon.was-masked-runtime' <<<"$runtime_mask_only" >/dev/null
expect_failure runtime-mask-cannot-satisfy-persistent-mask \
  validate_rpm_lifecycle_contract "$runtime_mask_only"

runtime_enablement_only="$(
  sed '/gta-claw-daemon\.was-enabled"/d' <<<"$rpm_source"
)"
grep -F 'gta-claw-daemon.was-enabled-runtime' <<<"$runtime_enablement_only" >/dev/null
expect_failure runtime-enablement-cannot-satisfy-persistent-enablement \
  validate_rpm_lifecycle_contract "$runtime_enablement_only"

printf 'Lifecycle contract self-tests passed (%d negative cases)\n' "$tests"
