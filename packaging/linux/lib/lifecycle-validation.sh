#!/usr/bin/env bash

validate_debian_lifecycle_contract() {
  local directory="$1"
  local contract
  local script
  local command

  for script in postinst prerm postrm; do
    [[ -f "$directory/$script" && ! -L "$directory/$script" ]] ||
      die "Debian lifecycle script is missing: $script"
    if grep -Eq '\|\|[[:space:]]*(true|:)' "$directory/$script"; then
      die "Debian maintainer script swallows a lifecycle failure: $script"
    fi
  done
  for contract in \
    'postinst:systemctl --system preset gta-claw-daemon.service' \
    'postinst:systemctl --system restart gta-claw-daemon.service' \
    'postinst:deb-systemd-invoke try-restart gta-claw-daemon.service' \
    'postinst:systemctl --system enable gta-claw-daemon.service' \
    'postinst:systemctl --system start gta-claw-daemon.service' \
    'postinst:systemctl --system enable --runtime gta-claw-daemon.service' \
    'postinst:/run/gta-claw-daemon.deb-upgrade-was-active' \
    'prerm:deb-systemd-invoke stop gta-claw-daemon.service' \
    'prerm:systemctl --system disable gta-claw-daemon.service' \
    'prerm:systemctl --system disable --runtime gta-claw-daemon.service' \
    'prerm:/run/gta-claw-daemon.deb-upgrade-was-active' \
    'postrm:deb-systemd-helper purge gta-claw-daemon.service'; do
    script="${contract%%:*}"
    command="${contract#*:}"
    grep -F "$command" "$directory/$script" >/dev/null ||
      die "Debian lifecycle script contract missing in $script: $command"
  done
}

validate_rpm_lifecycle_contract() {
  local scripts="$1"
  local contract
  local marker

  for marker in \
    gta-claw-daemon.old-nevra \
    gta-claw-daemon.was-active \
    gta-claw-daemon.was-enabled \
    gta-claw-daemon.was-enabled-runtime \
    gta-claw-daemon.upgrade-prepared \
    gta-claw-daemon.upgrade-configured \
    gta-claw-daemon.was-masked \
    gta-claw-daemon.was-masked-runtime \
    gta-claw-daemon.remove-was-active \
    gta-claw-daemon.remove-was-enabled \
    gta-claw-daemon.remove-was-enabled-runtime \
    gta-claw-daemon.remove-prepared; do
    grep -Eq "(^|[^A-Za-z0-9._-])${marker//./\\.}([^A-Za-z0-9._-]|$)" \
      <<<"$scripts" ||
      die "RPM lifecycle script contract missing exact marker token: $marker"
  done

  for contract in \
    "rpm -q --qf '%{NEVRA}\\n' gta-claw" \
    'systemctl daemon-reload' \
    'systemctl preset gta-claw-daemon.service' \
    'systemctl restart gta-claw-daemon.service' \
    'systemctl is-active --quiet gta-claw-daemon.service' \
    'systemctl disable gta-claw-daemon.service' \
    'systemctl enable gta-claw-daemon.service'; do
    grep -F "$contract" <<<"$scripts" >/dev/null ||
      die "RPM lifecycle script contract missing: $contract"
  done
  if grep -Eiq '(^|[[:space:]])(curl|wget|nc|bash -c|sh -c|eval)([[:space:]]|$)' \
    <<<"$scripts"; then
    die "RPM lifecycle script contains network or dynamic execution"
  fi
  if grep -Eq 'systemctl .*>/dev/null 2>&1' <<<"$scripts"; then
    die "RPM lifecycle script suppresses actionable systemctl diagnostics"
  fi
  if grep -Eq '\|\|[[:space:]]*(true|:)' <<<"$scripts"; then
    die "RPM lifecycle script swallows a lifecycle failure"
  fi
}

validate_rpm_scriptlet_metadata() {
  local artifact="$1"
  local actual
  local expected
  local forbidden_tag
  local forbidden_value
  local flag_tag
  local flag_value
  local script_name
  local script_source
  local script_tag
  local scripts

  scripts="$(rpm -qp --scripts "$artifact")"
  actual="$(
    grep -E '^[^[:space:]].* scriptlet \(using [^)]+\):$' <<<"$scripts" || true
  )"
  expected="$(
    printf '%s\n' \
      'preinstall scriptlet (using /bin/sh):' \
      'postinstall scriptlet (using /bin/sh):' \
      'preuninstall scriptlet (using /bin/sh):' \
      'postuninstall scriptlet (using /bin/sh):' \
      'posttrans scriptlet (using /bin/sh):'
  )"
  [[ "$actual" == "$expected" ]] ||
    die "RPM scriptlet set or interpreter differs from the reviewed contract"

  for script_name in pre post preun postun posttrans; do
    case "$script_name" in
      pre) script_tag=PREIN ;;
      post) script_tag=POSTIN ;;
      preun) script_tag=PREUN ;;
      postun) script_tag=POSTUN ;;
      posttrans) script_tag=POSTTRANS ;;
    esac
    script_source="$LINUX_DIR/rpm/$script_name"
    expected="$(sed 's/%%{NEVRA}/%{NEVRA}/g' "$script_source")"
    actual="$(rpm -qp --qf "%{$script_tag}" "$artifact")"
    [[ "$actual" == "$expected" ]] ||
      die "RPM $script_name scriptlet differs from reviewed source"
  done

  actual="$(
    rpm -qp --qf $'%{PREINPROG}\n%{POSTINPROG}\n%{PREUNPROG}\n%{POSTUNPROG}\n%{POSTTRANSPROG}\n' \
      "$artifact"
  )"
  expected="$(
    printf '/bin/sh\n%.0s' {1..5}
  )"
  expected="${expected%$'\n'}"
  [[ "$actual" == "$expected" ]] ||
    die "RPM scriptlet interpreters differ from the reviewed contract"

  for flag_tag in \
    PREINFLAGS \
    POSTINFLAGS \
    PREUNFLAGS \
    POSTUNFLAGS \
    POSTTRANSFLAGS; do
    flag_value="$(rpm -qp --qf "%{$flag_tag}" "$artifact")"
    case "$flag_value" in
      '' | '(none)' | 0) ;;
      *) die "RPM scriptlet $flag_tag is not zero: $flag_value" ;;
    esac
  done

  for forbidden_tag in \
    PRETRANS \
    PRETRANSFLAGS \
    VERIFYSCRIPT \
    VERIFYSCRIPTFLAGS; do
    forbidden_value="$(
      rpm -qp --qf "%{$forbidden_tag}" "$artifact"
    )"
    [[ -z "$forbidden_value" || "$forbidden_value" == "(none)" ]] ||
      die "RPM contains forbidden $forbidden_tag scriptlet content"
  done

  for forbidden_tag in \
    PRETRANSPROG \
    VERIFYSCRIPTPROG \
    TRIGGERCONDS \
    TRIGGERFLAGS \
    TRIGGERINDEX \
    TRIGGERNAME \
    TRIGGERSCRIPTFLAGS \
    TRIGGERSCRIPTPROG \
    TRIGGERSCRIPTS \
    TRIGGERTYPE \
    TRIGGERVERSION \
    FILETRIGGERCONDS \
    FILETRIGGERFLAGS \
    FILETRIGGERINDEX \
    FILETRIGGERNAME \
    FILETRIGGERPRIORITIES \
    FILETRIGGERSCRIPTFLAGS \
    FILETRIGGERSCRIPTPROG \
    FILETRIGGERSCRIPTS \
    FILETRIGGERTYPE \
    FILETRIGGERVERSION \
    TRANSFILETRIGGERCONDS \
    TRANSFILETRIGGERFLAGS \
    TRANSFILETRIGGERINDEX \
    TRANSFILETRIGGERNAME \
    TRANSFILETRIGGERPRIORITIES \
    TRANSFILETRIGGERSCRIPTFLAGS \
    TRANSFILETRIGGERSCRIPTPROG \
    TRANSFILETRIGGERSCRIPTS \
    TRANSFILETRIGGERTYPE \
    TRANSFILETRIGGERVERSION; do
    forbidden_value="$(
      rpm -qp --qf "[%{$forbidden_tag}]" "$artifact"
    )"
    [[ -z "$forbidden_value" || "$forbidden_value" == "(none)" ]] ||
      die "RPM contains forbidden $forbidden_tag scriptlet content"
  done
}
