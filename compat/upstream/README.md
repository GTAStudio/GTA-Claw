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
| `ledgers/*.json` (3 files, 47 rows) | only `status`, `acceptance_evidence` and `known_differences` may change |
| `ledger-digests.sha256` | regenerated only by `validate.ps1 -WriteLedgerDigests` |

## Validation

```text
powershell -NoProfile -File compat/upstream/validate.ps1
powershell -NoProfile -File compat/upstream/validate-self-test.ps1
```

`validate.ps1` resolves acceptance-evidence paths against the repository working
tree. It defaults to the parent of `compat/`; pass `-RepositoryRoot` only when the
contract is being validated from a copy (the self-test does this).

## Feature lifecycle

A feature row moves through exactly three states. Nothing else is accepted; the
former `blocked` and `not_applicable` states were removed because they let a row
claim parity outcomes without evidence.

| `status` | required `acceptance_evidence.status` | artifacts |
| --- | --- | --- |
| `unimplemented` | `missing` | none, and `known_differences` must stay the frozen baseline placeholder |
| `partial` | `partial` | at least one, including at least one `rust_test` |
| `implemented` | `accepted` | at least one, including at least one `rust_test` |

`last_verified_sha` stays pinned to the frozen upstream SHA in every state.

### Acceptance evidence artifacts

`acceptance_evidence.artifacts` is a list of typed objects, never bare strings:

```json
{
  "kind": "rust_test",
  "path": "crates/claw-migrate/tests/claude.rs",
  "check": "migrates_every_frozen_claude_fixture"
}
```

| `kind` | `path` must be | `check` names | verified by |
| --- | --- | --- | --- |
| `rust_test` | a `.rs` file that contains a Rust test attribute | the test function | `fn <name>` exists in that file |
| `rust_source` | a `.rs` file | an implementation symbol | the symbol is declared in that file |
| `rust_fixture` | a non-Rust fixture file | the test that consumes it | that test is one of this row's own `rust_test` artifacts |
| `ci_check` | a workflow under `.github/workflows` | a job key or step name | that key or `name:` value exists in the workflow |

Every artifact path must exist in the working tree; a fabricated citation fails.
Paths are matched ordinally, so evidence that only resolves on a case-insensitive
filesystem fails the same way it would on Linux CI.

Legacy TypeScript and JavaScript is never Rust acceptance evidence. Anything with
a `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs` or `.cjs` extension is rejected, as is
anything under `src/`, `compat/legacy/`, `packages/`, `node_modules/` or
`_upstream/`. Rows may not cite `compat/upstream/` itself.

## Recording a transition

1. Land the Rust implementation and its tests.
2. Edit only the affected rows in `ledgers/*.json`: set `status`,
   `acceptance_evidence.status`, the typed `artifacts`, and replace the baseline
   `known_differences` placeholder with the real remaining differences.
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
