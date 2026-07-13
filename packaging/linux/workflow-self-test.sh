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

workflow_trigger_paths() {
  local event="$1"
  local candidate="$2"
  awk -v event="$event" '
    $0 == "on:" {
      in_on = 1
      next
    }
    in_on && /^[^ ]/ {
      exit
    }
    in_on && $0 == "  " event ":" {
      in_event = 1
      next
    }
    in_event && /^  [^ ]/ {
      exit
    }
    in_event && $0 == "    paths:" {
      in_paths = 1
      next
    }
    in_paths && /^      - "/ {
      line = $0
      sub(/^      - "/, "", line)
      sub(/"$/, "", line)
      print line
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

validate_workflow() {
  local candidate="$1"
  local actual
  local contract
  local expected
  local forbidden

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

  expected="$(printf '%s\n' push pull_request workflow_dispatch)"
  actual="$(workflow_event_names "$candidate")"
  assert_exact_block "workflow events" "$expected" "$actual" || return 1

  expected="$(printf '%s\n' \
    '.github/workflows/linux-packaging.yml' \
    'packaging/linux/**' \
    'apps/**' \
    'crates/**' \
    'compat/**' \
    'Cargo.lock' \
    'Cargo.toml' \
    'deny.toml' \
    'rust-toolchain.toml' \
    'rustfmt.toml')"
  for event in push pull_request; do
    actual="$(workflow_trigger_paths "$event" "$candidate")"
    assert_exact_block "$event trigger paths" "$expected" "$actual" || return 1
  done

  actual="$(workflow_push_branches "$candidate")"
  assert_exact_block "push branches" "main" "$actual" || return 1

  actual="$(workflow_permissions "$candidate")"
  assert_exact_block "workflow permissions" "contents: read" "$actual" || return 1

  expected="$(printf '%s\n' \
    source-policy \
    rust-supply-chain \
    native-x86 \
    cross-arm64)"
  actual="$(workflow_job_ids "$candidate")"
  assert_exact_block "workflow jobs" "$expected" "$actual" || return 1

  expected="$(printf '%s\n' \
    'Checkout without credential persistence' \
    'Install native policy tools' \
    'Check shell, workflow, source, and release policy' \
    'Preserve root Linux metadata and desktop rejection')"
  actual="$(workflow_step_names source-policy "$candidate")"
  assert_exact_block "source-policy steps" "$expected" "$actual" || return 1

  for forbidden in \
    'Enforce focused source ownership' \
    'git diff --name-only' \
    '--diff-filter' \
    'BASE_SHA' \
    'github.event.pull_request.base.sha' \
    'P04d changed a path outside its ownership'; do
    if grep -F -- "$forbidden" "$candidate" >/dev/null; then
      printf 'PR-diff ownership restriction found: %s\n' "$forbidden" >&2
      return 1
    fi
  done
  if grep -Ein \
    '(non-packaging|outside (the )?packaging|outside (its |the )?ownership)' \
    "$candidate" >/dev/null; then
    echo "non-packaging changed-path rejection contract found" >&2
    return 1
  fi

  for contract in \
    'name: Source policy and shell security' \
    'name: Root Rust, MSRV, deny, and audit' \
    'name: Native x86_64 runtime and packages' \
    'name: Cross-built arm64 layouts' \
    'retention-days: 3' \
    'persist-credentials: false' \
    './packaging/linux/workflow-self-test.sh' \
    './packaging/linux/self-test.sh' \
    './packaging/linux/safeio-self-test.sh' \
    'cargo metadata --locked --format-version 1' \
    'select(. == "slint" or . == "slint-build" or startswith("i-slint"))' \
    'gta-claw-desktop supports only Windows and macOS' \
    'systemd-analyze verify' \
    'cmp -s' \
    'RELEASE_MODE'; do
    grep -F -- "$contract" "$candidate" >/dev/null || {
      printf 'workflow contract missing: %s\n' "$contract" >&2
      return 1
    }
  done
}

workflow_accepts_path() {
  local event="$1"
  local changed_path="$2"
  local candidate="$3"
  local pattern
  local prefix

  while IFS= read -r pattern; do
    case "$pattern" in
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

synthetic_app_path="apps/gta-claw-cli/src/lib.rs"
for event in push pull_request; do
  workflow_accepts_path "$event" "$synthetic_app_path" "$workflow" || {
    printf '%s does not accept apps-only change: %s\n' \
      "$event" "$synthetic_app_path" >&2
    exit 1
  }
done

validate_workflow "$workflow"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

grep -vF './packaging/linux/self-test.sh' "$workflow" \
  >"$tmp_dir/missing-security-self-test.yml"
expect_validation_failure \
  "removed Linux security self-test" \
  "$tmp_dir/missing-security-self-test.yml"

grep -vF '  native-x86:' "$workflow" >"$tmp_dir/missing-package-job.yml"
expect_validation_failure \
  "removed native package job" \
  "$tmp_dir/missing-package-job.yml"

awk '
  /^      - name: Check shell, workflow, source, and release policy$/ {
    print "      - name: Enforce focused source ownership"
    print "        shell: bash"
    print "        run: git diff --name-only --diff-filter=ACDMRT"
  }
  { print }
' "$workflow" >"$tmp_dir/reintroduced-ownership-gate.yml"
expect_validation_failure \
  "reintroduced PR-diff ownership gate" \
  "$tmp_dir/reintroduced-ownership-gate.yml"

if grep -RInE '(^|[[:space:]])(npm|npx|node|nodejs|bun|pnpm)([[:space:]]|$)' \
  "$SCRIPT_DIR" "$workflow" \
  --include='*.sh' --include='*.yml'; then
  echo "JavaScript runtime or package-manager command found in Linux packaging" >&2
  exit 1
fi

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
