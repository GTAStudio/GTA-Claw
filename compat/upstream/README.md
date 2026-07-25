# Frozen upstream compatibility contract

This directory is the parity trust root for the npm-free Rust reimplementation of
OpenClaw. It pins the frozen upstream baseline
`openclaw/openclaw@b43e832fcc8000ed7287c7accc54e381db607f85` (package `2026.7.2`)
and records, per feature row, whether GTA-Claw actually implements it.

| Artifact | Mutability |
| --- | --- |
| `baseline.json` | frozen, never changes |
| `inventories/*.json` (10 files, 717 rows) | frozen, digest hardcoded in `validate.ps1` |
| `feature-ledger.schema.json` | frozen, digest hardcoded in `validate.ps1` |
| `manifest.json` | only `evidence_policy.status_totals` may change |
| `ledgers/*.json` (3 files, 47 rows) | only `status`, `acceptance_evidence`, `implementation_pointers` and `known_differences` may change |
| `ledger-digests.sha256` | regenerated only by `validate.ps1 -WriteLedgerDigests` |

## Validation

```text
powershell -NoProfile -File compat/upstream/validate.ps1        # Windows PowerShell 5.1
pwsh       -NoProfile -File compat/upstream/validate.ps1        # PowerShell 7+, any OS
pwsh       -NoProfile -File compat/upstream/validate-self-test.ps1
```

`validate.ps1` resolves acceptance-evidence paths against the repository working
tree. It defaults to the parent of `compat/`; pass `-RepositoryRoot` only when the
contract is being validated from a copy (the self-test does this).

### Portability

Both scripts are supported on Windows PowerShell 5.1 and on PowerShell 7+ under
Linux and macOS, and must produce identical digests and identical accept/reject
decisions on every host. A validator that gates Linux CI cannot be pinned to
`windows-latest`.

The two hosts disagree by default in ways that silently corrupt a trust root, so
`validate.ps1` never relies on host defaults. `Assert-PortabilityInvariants` runs
before any contract file is read and checks the following against pinned vectors,
failing loudly rather than drifting:

| Divergence | Host default | What the validator does instead |
| --- | --- | --- |
| `ConvertFrom-Json` coerces ISO-8601 strings to `[datetime]` on 7+, leaves them `[string]` on 5.1; `[string]` then renders per current culture | culture-dependent text | `ConvertTo-ContractString` renders `[datetime]`/`[DateTimeOffset]` as invariant `yyyy-MM-ddTHH:mm:ssZ` |
| `ConvertTo-Json` escapes `<` `>` `&` `'` as `\uXXXX` on 5.1 and emits them raw on 7+ | different bytes, different digest | `ConvertTo-CanonicalJson` is a hand-written encoder that escapes only `"`, `\` and control characters |
| JSON integers parse as `Int32` on 5.1 and `Int64` on 7+ | `-is [int]` is false on 7+ | `Test-JsonInteger` accepts any integral width |
| `Get-Content -Raw` decodes BOM-less files as system ANSI on 5.1, UTF-8 on 7+ | mojibake on non-ASCII | `[System.IO.File]::ReadAllText` (UTF-8 detection on both) |
| `Set-Content -Encoding UTF8` writes a BOM on 5.1, none on 7+ | digest changes with the writer | `UTF8Encoding($false)` explicitly |
| `String.StartsWith/EndsWith/IndexOf(String)` and `Sort-Object` are culture-sensitive | locale-dependent ordering and matching | `[StringComparison]::Ordinal` and `[StringComparer]::Ordinal` everywhere |
| Git checks files out CRLF on Windows and LF on Linux | digest changes with the checkout | digests are structural, so line endings never reach a hash; `ledger-digests.sha256` is normalised to LF on read |

Digests are **structural**: every digest is taken over the parsed JSON
re-encoded by `ConvertTo-CanonicalJson` (ordinally sorted keys, invariant scalar
rendering) and hashed as UTF-8 without a BOM. Insignificant whitespace, indent
style and line endings are therefore discarded before hashing, so a digest is a
property of the contract content and never of the checkout, the locale or the
host. `ledger-digests.sha256` is itself read with `\r\n` normalised to `\n`,
because `.gitattributes` is frozen and carries no rule for `*.sha256`, so that
file checks out CRLF on Windows and LF on Linux. The self-test asserts this end
to end; see `culture-sensitive-key-sort-is-rejected`,
`ledger-digest-file-with-crlf-line-endings` and
`contract-digests-ignore-crlf-checkout`.

The only thing that legitimately differs between hosts is `repository_root` in
the JSON report, plus the whitespace of the report itself, because each host
pretty-prints with its own `ConvertTo-Json`. No digest and no decision depends
on either.

## Feature lifecycle

A feature row moves through exactly three states. Nothing else is accepted; the
former `blocked` and `not_applicable` states were removed because they let a row
claim parity outcomes without evidence.

| `status` | required `acceptance_evidence.status` | artifacts |
| --- | --- | --- |
| `unimplemented` | `missing` | none, and `known_differences` must stay the frozen baseline placeholder |
| `partial` | `partial` | at least one, and every one names an enabled Rust test |
| `implemented` | `accepted` | at least one, and every one names an enabled Rust test |

`last_verified_sha` stays pinned to the frozen upstream SHA in every state.

### Acceptance evidence artifacts

`acceptance_evidence.artifacts` is a list of objects with exactly two fields,
never bare strings and never a `path#test` string:

```json
{
  "path": "crates/claw-migrate/tests/claude.rs",
  "test": "migrates_every_frozen_claude_fixture"
}
```

There is deliberately only one artifact shape, because there is only one thing
that proves behaviour: an existing Rust file plus the name of an **enabled**
`#[test]` inside it. `path` must be a repository-relative forward-slash `.rs`
path that exists in the working tree, and `test` must be a Rust test path such
as `codex_home_override_is_injected` or `providers::rollback_is_reversible`.

A source file with no test name, a test file with no test name, a fixture and a
workflow job all prove nothing on their own, so none of them is evidence. They
also would not satisfy the Rust parity harness, which would leave rows that pass
one trust root and fail the other.

"Enabled `#[test]`" is decided by the same algorithm the Rust parity harness in
`crates/claw-conformance` uses, ported line for line, so a row can never pass one
trust root and fail the other. A cited name does **not** count when it is
`#[ignore]`d, gated by a nearby `#[cfg(...)]`, inside a line or block comment,
inside a string literal, or an ordinary function with no test attribute.

#### Ownership of the enabled-test rule

`declares_enabled_test` in `crates/claw-conformance/src/claims.rs` is the
**normative** implementation. `Test-DeclaresEnabledRustTest` in `validate.ps1`
is a follower port and has no independent authority: where the two ever disagree,
the Rust harness is correct and this script is the bug.

The two trees are independently owned, so this is a real drift risk. The rule is
binding in one direction only:

- Any change to `declares_enabled_test` must be reported to the coordinating
  session and re-ported here in the same cycle.
- This port must never be "improved" unilaterally. Tightening or loosening it
  here without a matching change in the harness creates exactly the split the
  port exists to prevent: a row that passes one trust root and fails the other.

The port was verified against all eight of the harness's own unit cases, and the
self-test re-checks the same eight behaviours (`synthetic-enabled-test-passes`,
`synthetic-async-enabled-test-passes`, `implemented-with-ignored-test`,
`implemented-with-cfg-gated-test`, `implemented-with-line-commented-test`,
`implemented-with-block-commented-test`,
`implemented-with-plain-function-not-a-test`,
`implemented-with-test-name-in-string-literal`). Those cases are the drift
detector: if the harness changes and the port does not, they are where it should
be caught.

### Implementation pointers are not evidence

A row may optionally carry `implementation_pointers`, a list of
`{ "path": ..., "note": ... }` objects, to record where the implementation
lives:

```json
"implementation_pointers": [
  { "path": "crates/claw-migrate/src/providers.rs", "note": "provider implementations" }
]
```

This field is explicitly **non-evidential**. It never counts toward the
"at least one artifact" requirement, and a row whose only content is pointers is
rejected with `requires at least one acceptance evidence artifact naming an
enabled Rust test`. Pointers are still validated — the path must exist and the
same legacy-JavaScript bans apply — so a pointer cannot be used to smuggle a
fabricated or TypeScript path into a ledger. An `unimplemented` row must not
carry pointers at all.

`partial` is a first-class state with exactly the same evidence burden as
`implemented`; the two differ only in `acceptance_evidence.status`. A subsystem
that is genuinely half done should be recorded as `partial` with real evidence
for the part that works, never as `unimplemented` and never as `implemented`.

Every artifact path must exist in the working tree; a fabricated citation fails.
Paths are matched ordinally, so evidence that only resolves on a case-insensitive
filesystem fails the same way it would on Linux CI. Symlinks and junctions are
rejected, because they can resolve outside the repository.

Legacy TypeScript and JavaScript is never Rust acceptance evidence. Anything with
a `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs` or `.cjs` extension is rejected, as is
anything under `src/`, `compat/legacy/`, `packages/`, `node_modules/` or
`_upstream/`. Rows may not cite `compat/upstream/` itself.

## Recording a transition

1. Land the Rust implementation and its tests.
2. Edit only the affected rows in `ledgers/*.json`: set `status`,
   `acceptance_evidence.status`, the `artifacts`, optionally
   `implementation_pointers`, and replace the baseline `known_differences`
   placeholder with the real remaining differences.
3. Update `manifest.json` `evidence_policy.status_totals` so the three counts
   still sum to 47 and match reality. The validator cross-checks them.
4. Regenerate the ledger digests through the reviewed command and review the
   printed values against the diff:

   ```text
   powershell -NoProfile -File compat/upstream/validate.ps1 -WriteLedgerDigests
   ```

   This is the only supported way to change a ledger digest. It rewrites
   `ledger-digests.sha256` and nothing else: inventory digests, the feature schema
   digest and `baseline.json` stay hardcoded in `validate.ps1` and are unreachable
   from this command.
5. Re-run `validate.ps1` and `validate-self-test.ps1`.

## Continuous integration

`validate.ps1` is a gate, not a report: a contract nobody runs is decoration.
It is not wired into a workflow from this directory, because the repository
trust-root allowlist is frozen at eight workflow files and this tree may not add
one. The following step is written to be lifted verbatim into an existing
allowed workflow by whoever owns that allowlist.

```yaml
      - name: Validate frozen upstream parity contract
        shell: pwsh
        working-directory: ${{ github.workspace }}
        run: |
          $ErrorActionPreference = "Stop"
          try {
              & ./compat/upstream/validate.ps1 | Out-Null
              Write-Host "compat/upstream parity contract OK"
          } catch {
              Write-Host "::error title=compat/upstream parity contract::$($_.Exception.Message)"
              exit 1
          }
```

Contract:

- **Runner** — any. `ubuntu-latest` is now correct; no `windows-latest` pin is
  needed. Both Windows PowerShell 5.1 and PowerShell 7+ are supported and produce
  identical digests and identical accept/reject decisions.
- **Working directory** — the repository checkout root, the directory containing
  `compat/` and `crates/`. The validator resolves acceptance-evidence paths
  against `-RepositoryRoot`, which defaults to the parent of `compat/`. Do not
  pass `-RepositoryRoot` in CI.
- **Checkout** — a normal `actions/checkout` working tree. Evidence paths are
  resolved against files on disk, so a sparse or partial checkout that omits
  `crates/` will fail honestly rather than pass vacuously.
- **Exit 0** — every check passed. The JSON report goes to stdout; the step
  discards it above, drop the `| Out-Null` to keep it in the log.
- **Exit 1** — some check failed, and the single-line reason is emitted as a
  GitHub error annotation. **This must fail the job.** There is no advisory or
  warning mode and no non-zero code that means "passed with remarks".
- The `try`/`catch` exists only so the rejection reason is one clean line;
  PowerShell 7's default error view wraps long messages mid-word and buries them
  under source-line art. Exit codes are the same without it.
- **Never** run `-WriteLedgerDigests` in CI. It rewrites `ledger-digests.sha256`,
  which is a reviewed, committed artifact; regenerating it inside a job would
  re-bless whatever the job happens to be looking at.

The adversarial self-test is a separate, slower step. It spawns about 139 child
validator processes — one per case, plus a second run for the 44 cases that first
re-bless the ledger digests, plus one baseline run — and takes several minutes,
so prefer a job with a `paths:` filter on `compat/upstream/**` over running it on
every push:

```yaml
      - name: Validate the parity validator itself
        shell: pwsh
        run: ./compat/upstream/validate-self-test.ps1
```

It exits 0 when every case passes and 1 otherwise, printing `ok`/`FAIL` per case
followed by an aggregate. It evaluates every case even after one fails, so a
single regression cannot hide the cases behind it.
