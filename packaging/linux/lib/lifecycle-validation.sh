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
    'postinst:deb-systemd-invoke try-restart gta-claw-daemon.service' \
    'postinst:systemctl --system enable gta-claw-daemon.service' \
    'postinst:systemctl --system start gta-claw-daemon.service' \
    'prerm:deb-systemd-invoke stop gta-claw-daemon.service' \
    'prerm:systemctl --system disable gta-claw-daemon.service' \
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

  for contract in \
    "rpm -q --qf '%{NEVRA}\\n' gta-claw" \
    'gta-claw-daemon.old-nevra' \
    'gta-claw-daemon.upgrade-prepared' \
    'gta-claw-daemon.upgrade-configured' \
    'gta-claw-daemon.remove-was-enabled' \
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
