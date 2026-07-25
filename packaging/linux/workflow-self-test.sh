#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
workflow="$REPO_ROOT/.github/workflows/linux-packaging.yml"
[[ -f "$workflow" ]] || {
  printf 'missing workflow: %s\n' "$workflow" >&2
  exit 1
}

workflow_event_names() {
  awk '
    $0 == "on:" {
      in_on = 1
      next
    }
    in_on && /^[^ ]/ {
      exit
    }
    in_on && /^  [[:alnum:]_-]+:$/ {
      line = $0
      sub(/^  /, "", line)
      sub(/:$/, "", line)
      print line
    }
  ' "$1"
}

validate_workflow_on_structure() {
  awk '
    function reject(message) {
      print "workflow on structure: " message > "/dev/stderr"
      bad = 1
    }
    $0 == "on:" {
      in_on = 1
      next
    }
    in_on && /^[^ ]/ {
      exit
    }
    in_on && /^  [^ ]/ {
      section = ""
      if ($0 == "  push:") {
        event = "push"
        push_events++
      } else if ($0 == "  pull_request:") {
        event = "pull_request"
        pull_request_events++
      } else if ($0 == "  workflow_dispatch:") {
        event = "workflow_dispatch"
        workflow_dispatch_events++
      } else {
        reject("unsupported event declaration: " $0)
        event = "unsupported"
      }
      next
    }
    in_on && /^    [^ ]/ {
      if (event == "push" && $0 == "    branches:") {
        section = "branches"
        push_branches++
      } else if ((event == "push" || event == "pull_request") &&
                 $0 == "    paths:") {
        section = "paths"
        if (event == "push") {
          push_paths++
        } else {
          pull_request_paths++
        }
      } else {
        reject("unsupported " event " option: " $0)
        section = "unsupported"
      }
      next
    }
    in_on && /^      - / {
      if (section == "branches") {
        if ($0 != "      - main") {
          reject("unsupported push branch entry: " $0)
        }
        push_branch_entries++
      } else if (section != "paths") {
        reject("list entry outside an allowed trigger list: " $0)
      }
      next
    }
    in_on && /^        / {
      if (section != "paths") {
        reject("nested trigger content outside paths: " $0)
      }
      next
    }
    in_on && $0 == "" && event == "workflow_dispatch" {
      separator_blanks++
      next
    }
    in_on {
      reject("unsupported trigger content: " $0)
    }
    END {
      if (push_events != 1 ||
          pull_request_events != 1 ||
          workflow_dispatch_events != 1 ||
          push_branches != 1 ||
          push_branch_entries != 1 ||
          push_paths != 1 ||
          pull_request_paths != 1 ||
          separator_blanks != 1) {
        reject("required event structure missing or duplicated")
      }
      exit bad
    }
  ' "$1"
}

workflow_trigger_paths() {
  local event="$1"
  local candidate="$2"
  awk -v event="$event" '
    function reject(message) {
      print event " trigger paths: " message > "/dev/stderr"
      bad = 1
    }
    function emit_path(line, scalar, quote, value) {
      scalar = line
      sub(/^      - /, "", scalar)
      quote = substr(scalar, 1, 1)
      if (quote == "\"" || quote == sprintf("%c", 39)) {
        if (length(scalar) < 2 ||
            substr(scalar, length(scalar), 1) != quote) {
          reject("unterminated quoted scalar: " scalar)
          return
        }
        value = substr(scalar, 2, length(scalar) - 2)
        if (index(value, quote) || (quote == "\"" && index(value, "\\"))) {
          reject("unsupported quoted scalar: " scalar)
          return
        }
      } else {
        value = scalar
        if (quote == "!" || quote == "&" || quote == "*") {
          reject("unsupported YAML indicator: " scalar)
          return
        }
      }
      if (substr(value, 1, 1) == "!") {
        reject("negative path pattern is forbidden: " scalar)
        return
      }
      if (value !~ /^[A-Za-z0-9._\/?*+-]+$/) {
        reject("unsupported path scalar: " scalar)
        return
      }
      print value
    }
    $0 == "on:" {
      in_on = 1
      next
    }
    in_on && /^[^ ]/ {
      exit
    }
    in_on && $0 == "  " event ":" {
      in_event = 1
      found_event++
      next
    }
    in_event && /^  [^ ]/ {
      exit
    }
    in_event && /^    paths-ignore([[:space:]]|:)/ {
      reject("paths-ignore is forbidden")
      next
    }
    in_event && $0 == "    paths:" {
      if (found_paths++) {
        reject("duplicate paths key")
      }
      in_paths = 1
      next
    }
    in_event && /^    paths:/ {
      reject("unsupported paths declaration: " $0)
      next
    }
    in_paths && /^      - / {
      emit_path($0)
      next
    }
    in_paths {
      reject("unsupported path-list content: " $0)
    }
    END {
      if (found_event != 1) {
        reject("event block missing or duplicated")
      }
      if (found_paths != 1) {
        reject("paths key missing or duplicated")
      }
      exit bad
    }
  ' "$candidate"
}

workflow_push_branches() {
  awk '
    $0 == "on:" {
      in_on = 1
      next
    }
    in_on && /^[^ ]/ {
      exit
    }
    in_on && $0 == "  push:" {
      in_push = 1
      next
    }
    in_push && /^  [^ ]/ {
      exit
    }
    in_push && $0 == "    branches:" {
      in_branches = 1
      next
    }
    in_branches && /^      - / {
      line = $0
      sub(/^      - /, "", line)
      print line
      next
    }
    in_branches && /^    [^ ]/ {
      exit
    }
  ' "$1"
}

workflow_permissions() {
  awk '
    $0 == "permissions:" {
      in_permissions = 1
      next
    }
    in_permissions && /^[^ ]/ {
      exit
    }
    in_permissions && /^  [^ ]/ {
      line = $0
      sub(/^  /, "", line)
      print line
    }
  ' "$1"
}

workflow_top_level_lines() {
  awk '/^[^[:space:]]/ { print }' "$1"
}

workflow_top_level_block() {
  local key="$1"
  local candidate="$2"
  awk -v key="$key" '
    $0 == key ":" {
      in_block = 1
      found++
    }
    in_block && $0 != key ":" && /^[^[:space:]]/ {
      exit
    }
    in_block {
      print
    }
    END {
      if (found != 1) {
        exit 1
      }
    }
  ' "$candidate"
}

workflow_job_ids() {
  awk '
    $0 == "jobs:" {
      in_jobs = 1
      next
    }
    in_jobs && /^[^ ]/ {
      exit
    }
    in_jobs && /^  [[:alnum:]_-]+:$/ {
      line = $0
      sub(/^  /, "", line)
      sub(/:$/, "", line)
      print line
    }
  ' "$1"
}

workflow_job_headers() {
  awk '
    $0 == "jobs:" {
      in_jobs = 1
      next
    }
    in_jobs && /^[^ ]/ {
      exit
    }
    in_jobs && /^  [^ ]/ {
      print
    }
  ' "$1"
}

workflow_step_names() {
  local job="$1"
  local candidate="$2"
  awk -v job="$job" '
    $0 == "  " job ":" {
      in_job = 1
      next
    }
    in_job && /^  [^ ]/ {
      exit
    }
    in_job && /^      - name: / {
      line = $0
      sub(/^      - name: /, "", line)
      print line
    }
  ' "$candidate"
}

workflow_job_block() {
  local job="$1"
  local candidate="$2"
  awk -v job="$job" '
    $0 == "  " job ":" {
      in_job = 1
      found++
    }
    in_job && $0 != "  " job ":" && /^  [[:alnum:]_-]+:$/ {
      exit
    }
    in_job {
      print
    }
    END {
      if (found != 1) {
        exit 1
      }
    }
  ' "$candidate"
}

assert_exact_block() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  [[ "$actual" == "$expected" ]] || {
    printf '%s mismatch\nexpected:\n%s\nactual:\n%s\n' \
      "$label" "$expected" "$actual" >&2
    return 1
  }
}

assert_required_job() {
  local job="$1"
  local expected_digest="$2"
  local expected_steps="$3"
  local candidate="$4"
  local actual
  local actual_digest
  local block

  actual="$(workflow_step_names "$job" "$candidate")" || return 1
  assert_exact_block "$job steps" "$expected_steps" "$actual" || return 1

  block="$(workflow_job_block "$job" "$candidate")" || {
    printf 'required workflow job missing: %s\n' "$job" >&2
    return 1
  }
  if grep -Eq \
    '^    (if|continue-on-error):|^        (if|continue-on-error):' \
    <<<"$block"; then
    printf 'required job or step can be skipped or error-masked: %s\n' \
      "$job" >&2
    return 1
  fi

  actual_digest="$(
    printf '%s\n' "$block" |
      tr -d '\r' |
      sha256sum |
      awk '{ print $1 }'
  )"
  [[ "$actual_digest" == "$expected_digest" ]] || {
    printf '%s structure differs from the exact command/action allowlist (expected %s, actual %s)\n' \
      "$job" "$expected_digest" "$actual_digest" >&2
    return 1
  }
}

validate_workflow() {
  local candidate="$1"
  local actual
  local expected

  awk '
    /uses:/ {
      split($0, parts, "@")
      if (length(parts) != 2 || parts[2] !~ /^[0-9a-f]{40}$/) {
        print "unpinned action: " $0 > "/dev/stderr"
        bad = 1
      }
    }
    END { exit bad }
  ' "$candidate" || return 1

  expected="$(printf '%s\n' \
    'name: Linux headless packaging prototype' \
    'on:' \
    'permissions:' \
    'concurrency:' \
    'env:' \
    'jobs:')"
  actual="$(workflow_top_level_lines "$candidate")"
  assert_exact_block "workflow top-level declarations" \
    "$expected" "$actual" || return 1

  validate_workflow_on_structure "$candidate" || return 1

  expected="$(printf '%s\n' push pull_request workflow_dispatch)"
  actual="$(workflow_event_names "$candidate")"
  assert_exact_block "workflow events" "$expected" "$actual" || return 1

  expected='**'
  for event in push pull_request; do
    actual="$(workflow_trigger_paths "$event" "$candidate")" || return 1
    assert_exact_block "$event trigger paths" "$expected" "$actual" || return 1
  done

  actual="$(workflow_push_branches "$candidate")"
  assert_exact_block "push branches" "main" "$actual" || return 1

  actual="$(workflow_permissions "$candidate")"
  assert_exact_block "workflow permissions" "contents: read" "$actual" || return 1

  expected="$(printf '%s\n' \
    'permissions:' \
    '  contents: read')"
  actual="$(workflow_top_level_block permissions "$candidate")" || return 1
  assert_exact_block "permissions structure" "$expected" "$actual" || return 1

  expected="$(printf '%s\n' \
    'concurrency:' \
    '  group: linux-packaging-${{ github.workflow }}-${{ github.ref }}' \
    '  cancel-in-progress: true')"
  actual="$(workflow_top_level_block concurrency "$candidate")" || return 1
  assert_exact_block "concurrency structure" "$expected" "$actual" || return 1

  expected="$(printf '%s\n' \
    'env:' \
    '  CARGO_TERM_COLOR: always' \
    '  RUSTFLAGS: -Dwarnings')"
  actual="$(workflow_top_level_block env "$candidate")" || return 1
  assert_exact_block "workflow environment structure" \
    "$expected" "$actual" || return 1

  expected="$(printf '%s\n' \
    source-policy \
    rust-supply-chain \
    native-x86 \
    cross-arm64)"
  actual="$(workflow_job_ids "$candidate")"
  assert_exact_block "workflow jobs" "$expected" "$actual" || return 1

  expected="$(printf '%s\n' \
    '  source-policy:' \
    '  rust-supply-chain:' \
    '  native-x86:' \
    '  cross-arm64:')"
  actual="$(workflow_job_headers "$candidate")"
  assert_exact_block "workflow job declarations" \
    "$expected" "$actual" || return 1

  assert_required_job \
    source-policy \
    a429b74dcce18dc1d0269963c2da4d68a66b8f2fc3db316b4d448cc07f9b449f \
    "$(printf '%s\n' \
      'Checkout without credential persistence' \
      'Install native policy tools' \
      'Check shell, workflow, source, and release policy' \
      'Preserve root Linux metadata and desktop rejection')" \
    "$candidate" || return 1

  assert_required_job \
    rust-supply-chain \
    3eb617e6b307c5eee65053150ea88b3a03128fdb38bcee8bd2aa0886eaa2eb70 \
    "$(printf '%s\n' \
      'Checkout' \
      'Format, check, lint, and test root workspace' \
      'Check root workspace at MSRV' \
      'Check dependency policy' \
      'Audit advisories')" \
    "$candidate" || return 1

  assert_required_job \
    native-x86 \
    18293a5133aa6521e9edbda2025d8c3ed11f861104ca7e1bf71afdc213bdccdf \
    "$(printf '%s\n' \
      'Checkout' \
      'Install native package inspection tools' \
      'Build twice in pinned Bookworm with different umasks' \
      'Execute binaries on the pinned oldest supported environment' \
      'Reject forged build manifests and substituted binaries' \
      'Package independent builds and prove deterministic outputs' \
      'Mutate every published OCI trust edge' \
      'Install and execute Debian package on pinned Bookworm' \
      'Verify systemd unit with packaged executable' \
      'Prove real Debian and RPM lifecycle' \
      'Prove release and publication stay disabled' \
      'Upload short-lived x86_64 prototype artifacts')" \
    "$candidate" || return 1

  assert_required_job \
    cross-arm64 \
    08e8afe33de18c9aa944d3397d3d3ef5df39efb993a4bf4edd520efe067e572c \
    "$(printf '%s\n' \
      'Checkout' \
      'Install arm64 cross and native package tools' \
      'Cross-build arm64 twice in pinned Bookworm' \
      'Package twice and prove deterministic arm64 layouts' \
      'Upload short-lived arm64 prototype artifacts')" \
    "$candidate" || return 1
}

workflow_accepts_path() {
  local event="$1"
  local changed_path="$2"
  local candidate="$3"
  local pattern
  local prefix

  while IFS= read -r pattern; do
    case "$pattern" in
      '**') return 0 ;;
      */'**')
        prefix="${pattern%/**}"
        [[ "$changed_path" == "$prefix"/* ]] && return 0
        ;;
      *)
        [[ "$changed_path" == "$pattern" ]] && return 0
        ;;
    esac
  done < <(workflow_trigger_paths "$event" "$candidate")
  return 1
}

expect_validation_failure() {
  local label="$1"
  local candidate="$2"
  if validate_workflow "$candidate" >/dev/null 2>&1; then
    printf 'workflow validation accepted tampering: %s\n' "$label" >&2
    return 1
  fi
}

expect_actionlint_valid_validation_failure() {
  local label="$1"
  local candidate="$2"
  actionlint "$candidate" >/dev/null || {
    printf 'semantic mutation is not actionlint-valid: %s\n' "$label" >&2
    return 1
  }
  expect_validation_failure "$label" "$candidate" || return 1
  printf 'actionlint-valid semantic mutation rejected: %s\n' "$label"
}

expect_actionlint_valid_validation_success() {
  local label="$1"
  local candidate="$2"
  actionlint "$candidate" >/dev/null || {
    printf 'scalar-form fixture is not actionlint-valid: %s\n' "$label" >&2
    return 1
  }
  validate_workflow "$candidate" >/dev/null || {
    printf 'workflow validation rejected equivalent scalars: %s\n' "$label" >&2
    return 1
  }
  printf 'actionlint-valid equivalent fixture accepted: %s\n' "$label"
}

insert_event_path() {
  local event="$1"
  local entry="$2"
  local candidate="$3"
  local output="$4"
  awk -v event="$event" -v entry="$entry" '
    $0 == "  " event ":" {
      in_event = 1
    }
    in_event && $0 != "  " event ":" && /^  [^ ]/ {
      in_event = 0
    }
    in_event && !inserted && $0 == "      - \"**\"" {
      print
      print entry
      inserted++
      next
    }
    { print }
    END {
      if (inserted != 1) {
        exit 1
      }
    }
  ' "$candidate" >"$output"
}

insert_event_block_path() {
  local event="$1"
  local style="$2"
  local candidate="$3"
  local output="$4"
  awk -v event="$event" -v style="$style" '
    $0 == "  " event ":" {
      in_event = 1
    }
    in_event && $0 != "  " event ":" && /^  [^ ]/ {
      in_event = 0
    }
    in_event && !inserted && $0 == "      - \"**\"" {
      print
      print "      - " style
      print "        !apps/**"
      inserted++
      next
    }
    { print }
    END {
      if (inserted != 1) {
        exit 1
      }
    }
  ' "$candidate" >"$output"
}

consumed_paths="$(
  printf '%s\n' \
    apps/gta-claw-cli/src/lib.rs \
    .cargo/audit.toml \
    .gitignore \
    .github/workflows/upstream-gateway-reference.yml \
    desktop/Cargo.toml \
    .github/workflows/windows-packaging.yml \
    .github/workflows/macos-packaging.yml
)"
for event in push pull_request; do
  while IFS= read -r consumed_path; do
    workflow_accepts_path "$event" "$consumed_path" "$workflow" || {
      printf '%s does not accept consumed input change: %s\n' \
        "$event" "$consumed_path" >&2
      exit 1
    }
  done <<<"$consumed_paths"
done

validate_workflow "$workflow"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

grep -vF './packaging/linux/self-test.sh' "$workflow" \
  >"$tmp_dir/missing-security-self-test.yml"
expect_actionlint_valid_validation_failure \
  "removed Linux security self-test" \
  "$tmp_dir/missing-security-self-test.yml"

awk '
  $0 == "  native-x86:" {
    skip = 1
    removed++
    next
  }
  skip && $0 == "  cross-arm64:" {
    skip = 0
  }
  !skip {
    print
  }
  END {
    if (removed != 1 || skip) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/missing-package-job.yml"
expect_actionlint_valid_validation_failure \
  "removed native package job" \
  "$tmp_dir/missing-package-job.yml"

awk '
  /^      - name: Check shell, workflow, source, and release policy$/ {
    print "      - name: Enforce focused source ownership"
    print "        shell: bash"
    print "        run: git diff --name-only --diff-filter=ACDMRT"
    inserted++
  }
  { print }
  END {
    if (inserted != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/reintroduced-ownership-gate.yml"
expect_actionlint_valid_validation_failure \
  "reintroduced PR-diff ownership gate" \
  "$tmp_dir/reintroduced-ownership-gate.yml"

awk '
  /^      - name: Check shell, workflow, source, and release policy$/ {
    inserted++
  }
  {
    print
  }
  inserted == 1 && /^            \.\/packaging\/linux\/safeio-self-test\.sh$/ {
    print "          git diff --name-status \"origin/$GITHUB_BASE_REF...HEAD\" |"
    print "            awk '\''$2 !~ /^(packaging\\/linux\\/|\\.github\\/workflows\\/linux-packaging\\.yml$)/ { bad=1 } END { exit bad }'\''"
    inserted++
  }
  END {
    if (inserted != 2) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/equivalent-ownership-gate.yml"
expect_actionlint_valid_validation_failure \
  "equivalent Git-history ownership gate" \
  "$tmp_dir/equivalent-ownership-gate.yml"

awk '
  $0 == "  source-policy:" {
    print
    print "    if: github.event_name == '\''schedule'\''"
    inserted++
    next
  }
  { print }
  END {
    if (inserted != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/conditional-source-policy-job.yml"
expect_actionlint_valid_validation_failure \
  "false condition on source-policy job" \
  "$tmp_dir/conditional-source-policy-job.yml"

awk '
  $0 == "      - name: Audit advisories" {
    print
    print "        if: github.event_name == '\''schedule'\''"
    inserted++
    next
  }
  { print }
  END {
    if (inserted != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/skipped-audit-step.yml"
expect_actionlint_valid_validation_failure \
  "skipped audit security step" \
  "$tmp_dir/skipped-audit-step.yml"

awk '
  $0 == "      - name: Audit advisories" {
    print
    print "        continue-on-error: true"
    inserted++
    next
  }
  { print }
  END {
    if (inserted != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/continue-on-error-audit-step.yml"
expect_actionlint_valid_validation_failure \
  "error-masked audit security step" \
  "$tmp_dir/continue-on-error-audit-step.yml"

awk '
  $0 == "      - name: Audit advisories" {
    skip = 1
    removed++
    next
  }
  skip && (/^      - name: / || /^  [[:alnum:]_-]+:$/) {
    skip = 0
  }
  !skip {
    print
  }
  END {
    if (removed != 1 || skip) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/missing-audit-step.yml"
expect_actionlint_valid_validation_failure \
  "complete audit security step deletion" \
  "$tmp_dir/missing-audit-step.yml"

awk '
  $0 == "          ./packaging/linux/self-test.sh" {
    print "          # ./packaging/linux/self-test.sh"
    changed++
    next
  }
  { print }
  END {
    if (changed != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/commented-security-command.yml"
expect_actionlint_valid_validation_failure \
  "required security command commented out" \
  "$tmp_dir/commented-security-command.yml"

awk '
  $0 == "  pull_request:" {
    in_pr = 1
  }
  in_pr && $0 == "    paths:" {
    print "    branches:"
    print "      - never-run"
    print
    inserted++
    next
  }
  { print }
  END {
    if (inserted != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/conditional-pr-branches.yml"
expect_actionlint_valid_validation_failure \
  "pull-request branch filter suppresses mandatory checks" \
  "$tmp_dir/conditional-pr-branches.yml"

awk '
  $0 == "  workflow_dispatch:" {
    print "  pull_request_target:"
    inserted++
  }
  { print }
  END {
    if (inserted != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/extra-trigger-event.yml"
expect_actionlint_valid_validation_failure \
  "extra pull-request-target trigger" \
  "$tmp_dir/extra-trigger-event.yml"

awk '
  $0 == "  source-policy:" {
    print "  \"extra-job\":"
    print "    runs-on: ubuntu-latest"
    print "    steps:"
    print "      - run: echo unexpected"
    inserted++
  }
  { print }
  END {
    if (inserted != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/quoted-extra-job.yml"
expect_actionlint_valid_validation_failure \
  "quoted extra workflow job" \
  "$tmp_dir/quoted-extra-job.yml"

awk '
  $0 == "jobs:" {
    print "defaults:"
    print "  run:"
    print "    shell: bash -c '\''exit 0'\'' {0}"
    print ""
    inserted++
  }
  { print }
  END {
    if (inserted != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/masking-workflow-defaults.yml"
expect_actionlint_valid_validation_failure \
  "workflow defaults mask mandatory run steps" \
  "$tmp_dir/masking-workflow-defaults.yml"

awk '
  !changed && /^      - "\*\*"$/ {
    print "      - '\''**'\''"
    changed = 1
    next
  }
  { print }
  END {
    if (changed != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/equivalent-path-scalars.yml"
expect_actionlint_valid_validation_success \
  "single-quoted positive path scalar" \
  "$tmp_dir/equivalent-path-scalars.yml"

insert_event_path \
  push \
  '      - "!apps/**"' \
  "$workflow" \
  "$tmp_dir/push-double-quoted-negative-path.yml"
expect_actionlint_valid_validation_failure \
  "push double-quoted negative path pattern" \
  "$tmp_dir/push-double-quoted-negative-path.yml"

insert_event_path \
  pull_request \
  '      - "!apps/**"' \
  "$workflow" \
  "$tmp_dir/pr-double-quoted-negative-path.yml"
expect_actionlint_valid_validation_failure \
  "pull-request double-quoted negative path pattern" \
  "$tmp_dir/pr-double-quoted-negative-path.yml"

insert_event_path \
  pull_request \
  "      - '!apps/**'" \
  "$workflow" \
  "$tmp_dir/pr-single-quoted-negative-path.yml"
expect_actionlint_valid_validation_failure \
  "pull-request single-quoted negative path pattern" \
  "$tmp_dir/pr-single-quoted-negative-path.yml"

insert_event_path \
  pull_request \
  "      - !!str '!apps/**'" \
  "$workflow" \
  "$tmp_dir/pr-tagged-negative-path.yml"
expect_actionlint_valid_validation_failure \
  "pull-request tagged negative path pattern" \
  "$tmp_dir/pr-tagged-negative-path.yml"

insert_event_block_path \
  pull_request \
  '>-' \
  "$workflow" \
  "$tmp_dir/pr-folded-negative-path.yml"
expect_actionlint_valid_validation_failure \
  "pull-request folded negative path pattern" \
  "$tmp_dir/pr-folded-negative-path.yml"

insert_event_block_path \
  pull_request \
  '|-' \
  "$workflow" \
  "$tmp_dir/pr-literal-negative-path.yml"
expect_actionlint_valid_validation_failure \
  "pull-request literal negative path pattern" \
  "$tmp_dir/pr-literal-negative-path.yml"

awk '
  $0 == "  pull_request:" {
    in_pr = 1
  }
  in_pr && $0 != "  pull_request:" && /^  [^ ]/ {
    in_pr = 0
  }
  in_pr && $0 == "    paths:" {
    print "    paths-ignore:"
    changed++
    next
  }
  { print }
  END {
    if (changed != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/pr-paths-ignore.yml"
expect_actionlint_valid_validation_failure \
  "pull-request paths-ignore replaces required paths" \
  "$tmp_dir/pr-paths-ignore.yml"

awk '
  $0 == "  pull_request:" {
    in_pr = 1
  }
  in_pr && $0 != "  pull_request:" && /^  [^ ]/ {
    in_pr = 0
  }
  in_pr && !changed && /^      - "\*\*"$/ {
    print "      - \"**\" # semantically equivalent but unsupported comment"
    changed++
    next
  }
  { print }
  END {
    if (changed != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/commented-path-scalar.yml"
expect_actionlint_valid_validation_failure \
  "commented path scalar cannot be proved equivalent" \
  "$tmp_dir/commented-path-scalar.yml"

awk '
  $0 == "  pull_request:" {
    in_pr = 1
  }
  in_pr && $0 != "  pull_request:" && /^  [^ ]/ {
    in_pr = 0
  }
  in_pr && !inserted && /^      - "\*\*"$/ {
    print
    print "      - docs/**"
    inserted++
    next
  }
  { print }
  END {
    if (inserted != 1) {
      exit 1
    }
  }
' "$workflow" >"$tmp_dir/extra-path.yml"
expect_actionlint_valid_validation_failure \
  "extra path entry" \
  "$tmp_dir/extra-path.yml"

source_policy="$SCRIPT_DIR/tests/validate-source-surfaces.py"
python3 "$source_policy" "$SCRIPT_DIR"
mkdir -p "$tmp_dir/source-type-fixture"
ln -s /bin/true "$tmp_dir/source-type-fixture/validator.sh"
if python3 "$source_policy" --types-only "$tmp_dir/source-type-fixture" \
  >/dev/null 2>&1; then
  echo "Linux source policy accepted a /bin/true validator symlink" >&2
  exit 1
fi
rm "$tmp_dir/source-type-fixture/validator.sh"
if python3 "$source_policy" --types-only /dev/null \
  >/dev/null 2>&1; then
  echo "Linux source policy accepted a special file" >&2
  exit 1
fi

command_policy="$SCRIPT_DIR/tests/reject-javascript-commands.py"
python3 "$command_policy" "$SCRIPT_DIR" "$workflow"
python3 "$SCRIPT_DIR/tests/reject-javascript-commands-self-test.py"
mkdir -p "$tmp_dir/recursive-policy/nested"
ln -s /bin/true "$tmp_dir/recursive-policy/nested/validator.sh"
if python3 "$command_policy" "$tmp_dir/recursive-policy" >/dev/null 2>&1; then
  echo "command policy skipped a /bin/true command-surface symlink" >&2
  exit 1
fi
rm "$tmp_dir/recursive-policy/nested/validator.sh"
yaml_command_pattern='(^|[^[:alnum:]_.-])(npm|npx|node|nodejs|bun|pnpm)([^[:alnum:]_.-]|$)'
grep -Eq "$yaml_command_pattern" <<< 'command: ["/usr/bin/node", "daemon.js"]' ||
  {
    echo "YAML JavaScript-command policy misses absolute executable paths" >&2
    exit 1
  }
for yaml in "$workflow" "$SCRIPT_DIR/oci/"*.yml "$SCRIPT_DIR/oci/"*.yaml; do
  [[ -e "$yaml" ]] || continue
  if grep -InE "$yaml_command_pattern" "$yaml"; then
    echo "JavaScript runtime or package-manager command found in Linux YAML surface" >&2
    exit 1
  fi
done

if git -C "$REPO_ROOT" ls-files packaging/linux |
  grep -Ei '\.(deb|rpm|tar\.gz|oci|sig|asc|key|pem|crt|bin)$'; then
  echo "Generated package, signature, key, or binary committed under packaging/linux" >&2
  exit 1
fi

if grep -RIlF 'packaging/linux' \
  "$REPO_ROOT/.github/workflows/windows-packaging.yml" \
  "$REPO_ROOT/.github/workflows/macos-packaging.yml" |
  grep .; then
  echo "Existing non-Linux packaging workflows must not execute Linux scripts" >&2
  exit 1
fi

echo "Linux workflow trust-boundary self-tests passed"
