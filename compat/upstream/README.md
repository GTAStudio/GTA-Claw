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
| `enabled-test-oracle.json` (120 cases) | frozen, digest hardcoded in `validate.ps1` |
| `reachability-corpus.json` (32 cases) | frozen, digest hardcoded in `validate.ps1` |
| `evidence-reachability-sweep.tsv` | regenerated only by `validate.ps1 -ReplayEvidenceSweep`; digest, dated commit and reviewed totals are hardcoded in `validate.ps1` |
| `manifest.json` | only `evidence_policy.status_totals` may change, and only through the composite `validate.ps1 -WriteLedgerDigests -WriteStatusTotals ...` command |
| `ledgers/*.json` (3 files, 47 rows) | only `status`, `acceptance_evidence.status`, `acceptance_evidence.artifacts`, `implementation_pointers` and `known_differences` may change; every other field, **including `acceptance_evidence.required`**, is frozen by a digest hardcoded in `validate.ps1` |
| `ledger-digests.sha256` | regenerated only by `validate.ps1 -WriteLedgerDigests` |
| `validate-self-test.ps1` | frozen, LF-normalised digest hardcoded in `validate.ps1` |
| `README.md` (this file) | normative and frozen, LF-normalised digest hardcoded in `validate.ps1` |

The last two are trust-root artifacts. A hollowed-out rejection instrument or a
stale specification can weaken the contract without changing a ledger rule, so
both require a reviewed digest-pin change.

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

JSON contract digests are **structural**: they are taken over parsed JSON
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

Three text artifacts are intentionally byte-oriented after normalising CRLF to
LF: this README, `validate-self-test.ps1`, and the reachability sweep. The sweep
also requires valid BOM-less UTF-8 and one uniform line-ending style. The
manifest status writer is different again: it preserves the input file's UTF-8
BOM state and every byte outside the three integer tokens. This distinction is
load-bearing because `[System.IO.File]::ReadAllText` consumes a UTF-8 BOM; a
string round trip cannot prove byte preservation.

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
`crates/claw-conformance` uses, so a row can never pass one trust root and fail
the other. That algorithm is a **tokenizer plus an item-tree walker**, not a
line matcher:

- Line comments, doc comments, nested block comments, normal strings, byte
  strings, raw strings and char literals are discarded **before** any matching,
  so Rust-shaped text inside a comment or a string literal can never be cited.
- A **macro invocation is consumed whole**, so a `#[test] fn` spelled inside a
  token tree is never a test. `stringify!({} #[test] fn forged() {})`,
  `discard! { #[test] fn forged() {} }` and the body of a `macro_rules!`
  definition all fail, in all three delimiter forms. A malformed token tree
  fails closed: scanning stops rather than resuming inside the tree. An
  invocation that *is* the item — including one written `::std::thread_local!`
  — is skipped without hiding the real test that follows it.
- A `#[test]` attribute must attach to the **cited function itself**. An
  unrelated test attribute earlier in the file does not bless a later ordinary
  function.
- In-file module identity is exact. A test declared in `mod real_module` must be
  cited as `real_module::the_test`; neither a bare name nor a fabricated module
  path matches it.
- One rule governs `cfg` everywhere, on the function and on every enclosing
  scope alike: an attribute may carry no `cfg` at all, or exactly `cfg(test)`.
  Every other predicate — `cfg(any())`, `cfg(not(test))`, `cfg(all(test))`,
  `cfg(test = "disabled")`, feature gates — plus `cfg_attr` and `ignore`
  disqualifies. A function-level `#[cfg(test)] #[test] fn` is therefore
  **accepted**, because such a test genuinely does run under `cargo test`;
  disqualifying it would reject honest evidence. On an enclosing module the
  disqualification is transitive through outer modules.
- `#[test]` and `#[tokio::test]` are both accepted; any attribute path whose last
  segment is `test` counts, which is intentionally broad.
- Identifiers may contain non-ASCII characters, so a macro named with a CJK or
  other non-ASCII identifier is still recognised as a macro rather than leaking
  its token tree out as items. An unrecognised byte is itself a token, so a
  stray byte in front of an attribute opens an item that swallows it — also
  fail-closed.

Because carriage return is ASCII whitespace to the tokenizer, a CRLF checkout on
Windows and an LF checkout on Linux produce identical tokens and therefore
identical verdicts.

#### Shared enabled-test rule and function mapping

Rust and PowerShell are co-equal implementations of one enabled-test rule.
Neither side may tighten or loosen it alone; a disagreement is a drift defect,
not an authority decision.

| Stage | Rust (`crates/claw-conformance/src/claims.rs`) | PowerShell (`validate.ps1`) |
| --- | --- | --- |
| enabled-test decision | `declares_enabled_test` | `Test-DeclaresEnabledRustTest` |
| tokenization | `rust_tokens` | `Get-RustTokens` |
| item-tree walk | `declares_in_items` | `Test-RustDeclaresInItems` |

The frozen oracle retains the historical field names
`normative_implementation` and `follower_implementation` and the commit where
the original port was taken. Those names are frozen provenance, not present-day
ownership or permission for unilateral changes.

#### The drift check is mechanical, not manual

`enabled-test-oracle.json` is a **shared fixture corpus** that both
implementations must classify identically. It holds 120 cases — the 22 cases of
the harness's own `evidence_requires_an_enabled_test_declaration` unit test, plus
98 lexer, attribute, item-shape, module-identity, citation-shape, macro,
function-level `cfg` and stray-byte cases.

`validate.ps1` replays every case through `Test-DeclaresEnabledRustTest` on
**every run**, before any evidence is judged, and fails with
`enabled-test oracle drift on case '<name>'` on the first disagreement. The
harness replays the same file through `declares_enabled_test`. A re-port that
silently changes behaviour therefore fails a build on both sides instead of
quietly accepting or rejecting a claim the other side disagrees with.

The `expected` values were produced by running the Rust implementation when the
corpus was created, then frozen. Both current implementations are measured
against those same recorded decisions.

The corpus is frozen like the inventories. Its digest, its case count and its
accept/reject split are pinned as constants in `validate.ps1`, and
`-WriteLedgerDigests` is structurally incapable of regenerating any of them, so
weakening a case to let a forged citation through requires a reviewed edit to the
validator itself.

#### The cited file must actually be compiled

A structurally perfect, enabled `#[test]` in a file that no Cargo target builds
never runs. Adding `crates/foo/src/orphan.rs`, never referencing it from any
`mod`, and citing a test inside it would otherwise produce a parity claim backed
by code that is compiled into nothing.

`validate.ps1` therefore also requires the cited path to be reached by a target
that `cargo test` builds **and runs tests in**. The reachable set of the owning
crate — the nearest ancestor directory whose `Cargo.toml` declares a `[package]`
— is:

- `src/lib.rs` and `src/main.rs`;
- every `*.rs` directly under `tests/` and `src/bin/`, plus `<dir>/main.rs` for a
  subdirectory of those;
- any target file named by an explicit `path = "..."` in a `[lib]`, `[[bin]]` or
  `[[test]]` section of the crate manifest;
- everything reached transitively from those roots by a `mod name;` declaration,
  resolving to `<scope>/name.rs` or `<scope>/name/mod.rs`, honouring
  `#[path = "..."]`, and descending into inline `mod name { ... }` blocks. A
  restricted visibility (`pub(crate) mod name;`, `pub(super)`, `pub(in ...)`) is
  a declaration like any other.

`#[path = "..."]` resolves the way `rustc` resolves it, which is **not** simply
"relative to the module directory":

- Outside an inline `mod { }` block, the path is relative to the directory
  **holding the source file**. For `src/a/b.rs`, `#[path = "foo.rs"] mod c;`
  names `src/a/foo.rs`, not `src/a/b/foo.rs`. The two coincide for *mod-rs*
  files — crate roots and `mod.rs` — and differ for every other file.
- Inside an inline `mod { }` block, a path on a *nested* declaration is relative
  to the module directory plus the inline components.
- A path attribute **on an inline `mod name { ... }` block itself** renames the
  directory that block's children live in. `#[path = "actual"] mod outer {
  #[path = "proof.rs"] mod proof; }` compiles `actual/proof.rs`, never
  `outer/proof.rs`; the value is a directory, and it is resolved by the same
  base rule as the two bullets above — against the directory holding the source
  file at the top level of a file, and against the enclosing module directory
  when nested. The enclosing scopes therefore cannot be carried as a list of
  plain module names.
- A path naming a `mod.rs` makes that module mod-rs, so **its** children resolve
  beside it: `#[path = "sub/mod.rs"] mod two;` puts `two`'s children in `sub/`,
  not in `sub/mod/`.
- The value may be a raw string (`#[path = r"foo.rs"]`).
- A `path` attribute whose value this reader cannot resolve resolves to
  **nothing**. It must never fall back to resolving by module name, or an
  attribute pointing at one file blesses another.

If a `mod name;` declaration is answered by **both** `<scope>/name.rs` and
`<scope>/name/mod.rs`, the resolution fails closed and **neither** file is
citable. `rustc` rejects that ambiguity outright — `E0761: file for module found
at both paths` — and compiles neither, so a rule that picked either one, or both,
would bless a test out of a crate that does not build. The rejection names the
counterpart file and the error code rather than reporting the file as unwired,
because telling someone to wire in a module that is already wired twice sends
them the wrong way. Only the two ambiguous files are withdrawn; this validator is
not a compiler and does not attempt to prove that the rest of the crate builds,
which `cargo test` establishes far more directly in CI.

Getting any of these wrong is a forgery vector and not merely a false rejection,
because each wrong answer names a *specific* other file — one that nothing
compiles — and blesses it. Each has a decoy planted at the wrong location in
`validate-self-test.ps1`.

Four kinds of target are deliberately **excluded**, because `cargo test` does not
run `#[test]` items in any of them. Each was measured against `cargo metadata`
rather than recalled:

- `build.rs`. `cargo test` does not run tests in a build script.
- `benches/` and `examples/`. Bench and example targets default to
  `test = false`. The file is compiled, and the `#[test]` inside it never runs.
  This needs no manifest edit — a file dropped in `examples/` is enough.
- Any target with an explicit `test = false`.
- Any target with `harness = false`, whose own `main()` replaces the libtest
  harness and makes every `#[test]` item in the file inert.
- Any target with a non-empty `required-features`, including a multiline TOML
  array. A plain `cargo test` skips that target unless every named feature is
  enabled. Presence is read, never resolved: reproducing Cargo's default-feature
  expansion, transitive feature edges and workspace unification here would
  create a new way to bless a target Cargo did not build. The target is therefore
  refused even if the named feature is enabled by default, and an explicit
  `test = true` cannot override the gate. `required-features = []` gates nothing
  and remains accepted.

Auto-discovery is suppressed by `autotests = false` and `autobins = false`, and a
file named by an explicit target section is governed by that section alone —
auto-discovery must not resurrect a target the manifest disabled.

##### The owning package must itself be built

Reachability from a target root proves cargo would compile the file **within its
package**. It says nothing about whether anything builds that package. A package
that no workspace lists is never compiled by `cargo test` at the repository root,
so a `#[test]` inside it never runs — and adding one is a two-file change needing
no unusual Rust and no manifest trickery, which makes it the cheapest forgery in
the pipeline if membership is not checked.

`validate.ps1` therefore also requires the owning package to be built. Walking up
from the package directory, the **first** ancestor `Cargo.toml` carrying a
`[workspace]` table decides, exactly as cargo does:

- a manifest carrying its own `[workspace]` table is a separate build root and is
  built on its own terms;
- otherwise the package must match an entry of that workspace's `members`, where
  entries may be globs (`crates/*` matches `crates/foo` but not
  `crates/foo/bar`; `**` crosses separators);
- an `exclude` entry removes the named directory and everything beneath it, and
  is checked before `members`;
- `members` and `exclude` are read from the `[workspace]` table only. Neither
  `[workspace.package]` nor `[workspace.dependencies]` confers membership —
  honouring a path there would repeat the mistake of treating a bare `path =`
  under `[dependencies.<name>]` as a target.

Two deliberate limits, both disclosed rather than left to be found:

- Cargo also treats a **path dependency of a member** as a member. This validator
  does not, so it is the stricter side: a package cargo builds but the workspace
  manifest does not list is rejected. The repository lists all twenty-five root
  members explicitly, so this costs nothing today, and the remedy when it does
  cost something is one line in the workspace manifest rather than a change to
  any production source.
- A manifest carrying its own `[workspace]` is accepted as built. Whether CI
  actually invokes that workspace is not statically knowable — the workflow files
  are outside this contract and are themselves unpinned — so tightening here
  would be a guess that falsely rejects real evidence. Two such roots exist
  (`desktop/` and `.github/trusted/desktop-supply-chain-policy/`) and both are
  built by named CI jobs. This is pinned in the **accepting** direction by
  `implemented-citing-self-rooted-workspace-package-passes` so it cannot change
  silently.

Verified against cargo itself rather than reasoned: on a planted workspace,
`cargo test --workspace` compiles only the listed member and never touches an
unlisted or excluded package, and expands a `crates/*` member glob. On the real
tree the rule changes **no** verdict — all twenty-nine packages are accounted
for by twenty-seven root members, one `desktop/` member and one self-rooted
workspace.

Three limits, stated plainly rather than left to be discovered:

- The rule catches files that **nothing references**, and targets that
  `cargo test` does not run. It does not evaluate `cfg` predicates, so a module
  behind `#[cfg(feature = "off-by-default")]` still counts as referenced even
  though `cargo test` would not run it by default. The same permissiveness applies
  when a `cfg` decides the *path* rather than the module's existence:
  `#[cfg_attr(unix, path = "unix.rs")] mod imp;` is read as a plain `mod imp;`,
  so `imp.rs` is treated as reachable. That is the honest answer on a non-unix
  host and a permissive one on unix. Target-level `required-features` is not a
  `cfg` predicate and is handled separately by the fail-closed exclusion above.
- Reachability is computed within the owning crate: the crate that owns the
  *cited* file must itself reach it. A file pulled in only by a
  `#[path = "..."]` from a *different* crate is not recognised; cite a test in
  the crate that compiles it. One real cross-crate `#[path]` exists —
  `apps/gta-claw-cli/tests/gateway_health.rs` reaches into
  `crates/claw-gateway-client/tests/support/mod.rs` — and nothing is lost by it,
  because a `mod support;` in that crate's own `tests/gateway_client.rs` reaches
  the same file.
- It proves a file is compiled and a test is enabled. It does not prove the test
  passes; that is `cargo test`'s job.

Rust and PowerShell implement the same core rule — "a target root, or reachable
from a target root." The current function mapping is:

| Stage | Rust (`crates/claw-conformance/src/claims.rs`) | PowerShell (`validate.ps1`) |
| --- | --- | --- |
| orchestration | `CargoTestTargets::load` | `Assert-EvidenceFileIsCompiled` |
| workspace/package admission | `CargoWorkspaceSpec::includes_package` | `Test-CratePackageIsBuilt` |
| test-enabled target roots | target discovery in `CargoTestTargets::load` | `Get-CargoManifestTargetSections`, `Test-CargoSectionRunsTests`, `Get-CrateTargetRootFiles` |
| module-reference discovery | `rust_module_references_from_tokens` | `Get-RustModuleReferences` |
| transitive source walk | `reachable_rust_sources` | `Get-CrateCompiledFileSet` |
| final membership | `CargoTestTargets::contains_compiled_source` | final membership check in `Assert-EvidenceFileIsCompiled` |

The Rust side uses `cargo metadata` and PowerShell models Cargo hermetically, so
this maps decisions rather than claiming line-for-line mechanics. One disclosed
gap remains: PowerShell rejects non-empty `required-features` target declarations
while the Rust loader currently trusts metadata's `target.test` flag. The shared
corpus has no required-features case and does not arbitrate that gap. Until Rust
implements the same exclusion, the two are not truthfully identical on that
shape.

The shared core followed a proposal to require the cited file to *be* a target
root that was put to the compatibility owner and then withdrawn:
target-root-only left, at the time it was proposed, 225 tests across 34 files in
9 crates with no legal citation at all, and the only workaround was widening the
visibility of private items in production code, which would have let the ledger
dictate the API surface.
Re-measured when this rule was settled — 292 tracked `.rs` files at that point,
counting `#[test]` occurrences in files this rule accepts that are not themselves
target roots — the cost was **822 tests across 99 files in 17 packages**. The figure is a lower
bound on the harm and it grows with every crate the fleet adds, which is why it
is recorded with its method and denominator rather than as a bare number.

Outside the disclosed required-features gap, the two implementations are
intended to be identical, not merely ordered. A divergence in either direction
is a defect and must be reported rather than managed.

The root set is derived here by reading the manifest rather than by shelling out
to `cargo metadata`, which keeps this trust root hermetic: it reads files and
executes nothing. That is a deliberate trade. It costs exactness at the margins
of cargo's auto-discovery rules, and it means the per-kind defaults above are a
model of cargo rather than cargo's own answer — a model that was **wrong** once
already, when `benches/` and `examples/` were treated as roots.

The `harness = false` case is the one where the model was, for a time, the
*stricter* side: it cannot be expressed in `cargo metadata` at all, which still
reports such a target as `test = true`. Measured directly — a package carrying
an explicit `harness = false` test target, a default example, a default bench, a
`src/bin/` target, a lib and an ordinary integration test — `cargo metadata`
reports `test = true` for the `harness = false` target, while
`cargo test -- --list` yields exactly `lib_test`, `bin_test` and `normal_test`.
Metadata alone therefore admits a target whose `#[test]` never runs.
`claw-conformance` reads the manifest to overlay that one field, so the two
implementations now agree here; the corpus pins all six of those paths so
neither side can drift back.

A tightening rule needs its false-positive cases pinned as much as its
true-positive ones. The accepting cases pin reachability — a
`mod`-wired module, a `#[path]`-relocated module, a transitive `lib.rs` →
`nested/mod.rs` → `nested/deep.rs` chain, a `src/bin/` target, a top-level
`#[path]` sibling, the child of a `#[path]`-named `mod.rs`, a raw-string
`#[path]`, an inline `#[path] mod { … }` block, a `#[path]` module nested inside
one, a `pub(crate) mod`, a glob-matched workspace member, and a package
carrying its own `[workspace]` — so that a later "improvement" to this rule
cannot quietly turn it into a false-rejection engine without turning the
self-test red. The other two pin the enabled-test oracle. The `src/bin/` case is
there specifically because dropping `benches/` and `examples/` from the root set
must not take `src/bin/` with them.

Four of those accepting cases were added after a peer implementation's
adversarial review found the corresponding bugs here, each proved by execution
against a planted tree rather than argued: a six-line file with three top-level
`#[path]` declarations produced **two false acceptances and four false
rejections**. A fifth, `pub(crate) mod`, was found by sweeping the real tree
after a merge: `Get-RustSkipVisibility` takes three parameters and the module
walk was calling it with two, so PowerShell supplied `0` for the end bound and
the walk could not step over the visibility group. The enabled-test oracle called
the same function correctly. **A rule verified only against a corpus cannot find
a divergence the corpus does not exercise** — which is why the whole-tree sweep
runs on every change and why its result is reported as a per-file verdict list
rather than as a count.

#### `evidence-reachability-sweep.tsv` — the checked-in cross-check

The whole-tree verdict list is a committed artifact rather than a number quoted
in prose. It holds one `<verdict><TAB><path>` row for every tracked non-legacy
`.rs` file in its cited `base-commit` tree, sorted ordinally, with a header naming
the generator, commit, date and totals. Regenerate it only with:

```text
powershell -NoProfile -File compat/upstream/validate.ps1 -ReplayEvidenceSweep
```

Replay reruns the shipped PowerShell reachability rule over git's tracked Rust
universe, rewrites the record, prints additions, removals and verdict changes,
and prints the commit/date/digest pins to review. It is mutually exclusive with
the ledger and status writers and, like every writer mode, is refused in CI
before any artifact write.

**The sweep grants no evidence permission.** Citation admission always invokes
the live rule and never consults this file. Every ordinary run independently
enforces:

- the LF-normalised pinned digest;
- one positional canonical header, valid BOM-less UTF-8, uniform LF or CRLF,
  exactly one final newline, exactly two TAB-separated row fields, and unique
  strictly ordinal paths;
- a fresh live verdict for every recorded path, followed only then by the exact
  reviewed file/accept/reject totals.

A coordinated edit that flips a verdict, repairs the totals and re-pins the
digest still fails the semantic comparison. A new tracked Rust file absent from
the dated record is deliberately tolerated, so later tree growth does not
invalidate a historical measurement; a recorded path becoming absent,
non-ordinal, non-regular, a reparse point, or differently classified is not.
Intentional replay surfaces later additions in its differential.

The universe comes from `git ls-files`, not a filesystem walk that reimplements
ignore rules or admits untracked sources. Replay also refuses to cite `HEAD` if
any tracked or untracked Rust path differs from it. That keeps `base-commit` a
truthful claim about the tree swept while allowing the validator and this
artifact themselves to be edited during review.

#### The sweep is silent on rules the tree never exercises

A whole-tree sweep is high-yield for rules the tree exercises and no instrument
at all for shapes it does not. That is why `reachability-corpus.json` exists.

`reachability-corpus.json` holds 32 synthetic workspaces — 15 that must be
accepted and 17 that must be rejected — each a complete set of files, a cited
path and the expected verdict. It covers explicit `test = false` targets,
`harness = false` targets, default examples and default benches, the three
`#[path]` base-directory rules, raw-string `#[path]`, `E0761` ambiguity in
both directions, package boundaries, and target roots in excluded and
self-rooted workspaces.

The replay proves agreement **only for those 32 encoded shapes**. It is not an
exhaustive proof of reachability behaviour outside them, and a green 32/32 must
never be reported as one. The corpus and the sweep are complementary and neither
is sufficient on its own: the sweep covers what the tree exercises, the corpus
covers what it does not, and any rule outside both is pinned by nothing.

Canonical case names are append-only, including future additions.
`$CanonicalReachabilityCaseNames` and the corpus must be exact sets. Adding a
case therefore appends its name and updates the count, split and digest pins;
deleting or renaming any old case requires a conspicuous deletion from the
never-remove registry. A new corpus case omitted from the registry is rejected,
so additions cannot enter unprotected and disappear later.

**Neither implementation is normative here.** The `arbiter` field records that
every expectation was produced by running `cargo` and `rustc` against the
fixture, not by asking either resolver what it thinks. Accepting cases place
`compile_error!` decoys at each formerly wrong path, so a successful `cargo
build` is itself proof that cargo compiles none of them; rejecting cases that
model a non-building crate are ones `cargo` actually fails on. One expectation
in this corpus was **written wrong by hand and corrected by the toolchain**: a
package that is neither a workspace member nor excluded and carries no
`[workspace]` table of its own makes `cargo` exit 101, which is why the corpus
distinguishes a legal standalone package from an unbuildable orphan.

`validate.ps1` pins this file structurally and by digest but deliberately does
**not** materialize and replay it during a validation run. The resolver memoizes
per crate directory, and seeding those caches from fixtures carried in a file
that lives in the tree under audit would turn a convenience into a forgery
vector. Behavioural replay belongs in a harness that runs each case in its own
process against its own root, never in the read-only trust root. What
`validate.ps1` does enforce is that no case may cite a path it does not itself
define — otherwise a case could name a real repository file and assert a verdict
about something the fixture never contained — and that no path may contain a dot
segment, so no replayer can be induced to write outside its fixture root.

**This file is the single copy, and it now is one.** `crates/claw-conformance`
loads it from `compat/upstream/reachability-corpus.json`, exactly as it already
loads `compat/upstream/enabled-test-oracle.json`, and replays every case against
`cargo` before comparing its own resolver's verdict to `expect`. The private
duplicate that previously lived under that crate's fixtures has been deleted.
A corpus that exists twice is not shared: it is two corpora that agree until one
is edited, and the cheapest drift detector — comparing digests — is unavailable
the moment the copies differ in whitespace or member order, which two independent
serializers will do immediately. The schema is deliberately additive-only for
that reason; a reader may ignore `schema_version`, `purpose`, `rule`, `arbiter`,
`implementations` and each case's `why` and still see `name`, `files`, `cite` and
`expect`.

Sharing the file means an addition must update consumers that pin an exact count.
That coupling is explicit rather than hidden: a coverage addition and its new
canonical registry entry land together, while consumers may use a lower bound
when they need additions to remain independently deployable.

#### A row may not rewrite its own acceptance bar

Each row carries `acceptance_evidence.required` — a sentence stating what parity
means for that feature, written when the baseline was frozen and nothing was
implemented. It is contract text, not a working field.

Making the ledger digests regenerable is what transitions require, but it also
removed the only thing that had been holding every *descriptive* field in place.
Without a second freeze, a session recording a transition could rewrite
`required` from "A Rust protocol constant test proves v4 negotiation and rejects
unsupported general-client versions" to "A test exists", re-bless the digest
through the documented command, and pass — having set the bar it was judged
against. The same edit works on `title`, `tier`, `domain`, `profile` and
`upstream_source.paths`, which is the surface the row is measured over.

`validate.ps1` therefore pins a second digest per ledger, over the **frozen
projection** of its rows: every field except `status`,
`acceptance_evidence.status`, `acceptance_evidence.artifacts`,
`implementation_pointers` and `known_differences`. Those five are the entire
mutable surface; everything else must hash to `frozen_digest` in `$LedgerSpecs`.

Two properties make this hold:

- the constant lives in `validate.ps1`, so `-WriteLedgerDigests` cannot reach it,
  exactly like the inventory, schema and corpus digests;
- it is checked in **both** modes, so `-WriteLedgerDigests` also exits non-zero on
  a ledger whose frozen text moved, rather than reporting success.

The barrier is the constant, not the command. `ledger-digests.sha256` is an
ordinary file that anyone can recompute and write by hand, so the self-test
assumes an attacker has already re-blessed it — every frozen-text case runs
`-WriteLedgerDigests` first and must still be rejected. What stops the forgery is
that no sidecar contents can satisfy a digest hardcoded in the script.

An honest transition changes only the five mutable fields, so the projection does
not move and the command works normally.

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

1. Land the Rust implementation and its tests. Every test you intend to cite must
   live in a file some `cargo test` target compiles — an integration test under
   `tests/`, or a `src/` module wired in through a `mod` chain.
2. Edit only the affected rows in `ledgers/*.json`: set `status`,
   `acceptance_evidence.status`, the `artifacts`, optionally
   `implementation_pointers`, and replace the baseline `known_differences`
   placeholder with the real remaining differences.
3. State the new totals and let the composite reviewed command update both
   derived files:

   ```text
   powershell -NoProfile -File compat/upstream/validate.ps1 `
       -WriteLedgerDigests -WriteStatusTotals "unimplemented=3,partial=10,implemented=34"
   ```

   You state the totals; the command does not derive the declaration. It checks
   the declaration against all 47 validated rows, then atomically replaces the
   digest sidecar and only the three integer tokens in
   `manifest.evidence_policy.status_totals`. Every other manifest byte, including
   its UTF-8 BOM state and line endings, is preserved.

   Both reviewed byte sequences are prepared before either file is touched.
   Every contract and sweep check runs first; a rejected composite transition
   leaves the manifest and digest sidecar byte-identical, with temporary files
   removed. If the second replacement itself fails, the first is restored from
   its original bytes.

4. Review the printed digests, totals and inventory of every non-unimplemented
   row against the ledger diff.
5. Re-run `validate.ps1` and `validate-self-test.ps1`.

`-WriteLedgerDigests` may still be run alone. Its historical write ordering is
deliberate and different: it rewrites the sidecar before the mutable ledger rows
finish semantic validation so anti-forgery tests can model an attacker who
already re-blessed those digests. A standalone run that later fails can therefore
leave `ledger-digests.sha256` changed. Restore it before retrying. It cannot bless
frozen ledger text because the frozen projections remain hardcoded in the
validator.

The README, self-test, schema, corpora, sweep pin, inventory digests and baseline
are unreachable from either ledger writer. If this README changes, update
`$ExpectedReadmeDigest` in the same reviewed commit before invoking a writer,
because writer modes enforce the same specification pin as verify mode.

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
- **Never** run `-WriteLedgerDigests`, `-WriteStatusTotals`, or
  `-ReplayEvidenceSweep` in CI. The validator detects standard CI environment
  markers and rejects every writer mode before reading or writing a contract
  artifact.

The adversarial self-test is a separate, slower step. It spawns one child
validator per case, plus a baseline run and re-blessing pre-runs for cases that
model an attacker who already regenerated ledger digests. Prefer a job with a
`paths:` filter on `compat/upstream/**` over running it on every push:

```yaml
      - name: Validate the parity validator itself
        shell: pwsh
        run: ./compat/upstream/validate-self-test.ps1
```

It exits 0 when every case passes and 1 otherwise, printing `ok`/`FAIL` per case
followed by an aggregate carrying the positive and negative counts. It evaluates
every case even after one fails, so a single regression cannot hide later cases.

### Where the self-test builds its throwaway trees

Both throwaway trees — the per-case copies of this directory and the synthetic
repository root used by the enabled-test cases — are created under the system
temp directory by default. That directory is not private to the run. On Windows,
Storage Sense deletes `%TEMP%` content under disk pressure, and a machine running
several concurrent `cargo` builds produces exactly that pressure. Set

```text
GTA_CLAW_SELFTEST_WORK_ROOT=/some/stable/directory
```

to place them somewhere a temp cleaner will not reach.

The self-test verifies its own fixture against a sentinel set immediately after
construction and again before every case, and reports a disappearance as an
explicit environment failure. This matters because of how the failure presents
otherwise: the fixture is built once and never modified by any case, so if it is
deleted mid-run every later case fails its precondition and reports "not a
GTA-Claw tree", which reads exactly like a semantic regression in the validator.
One such run cost a downstream session a real investigation before the cause was
identified as the temp cleaner.

The cases themselves degrade safely, which is the property that made that run
diagnosable at all. A negative case asserts the *specific* rejection reason, not
merely a non-zero exit, so a vanished fixture makes it fail with "failed for the
wrong reason" rather than pass. Had the harness only checked that the validator
rejected something, every one of the negative cases would have passed vacuously
against a fixture that no longer existed — a green anti-forgery suite testing
nothing.

## Why the specification is digest-pinned

`$ExpectedReadmeDigest` freezes this file as LF-normalised UTF-8 before any
evidence is judged. Editing the specification therefore requires moving the pin
in the same reviewed commit; no writer mode can regenerate it.

This is not ceremonial. The README once continued to say the Cargo reachability
rule was locally owned and unported after the Rust implementation had acquired
the same core rule. A competent reader could reasonably act on that stale
ownership claim without re-deriving the program. Pinning makes specification and
validator changes move together and makes ownership assertions reviewable as
trust-root edits rather than harmless prose.

The digest cannot prove a sentence was true when written. It does guarantee that
the rules cannot move while the normative description silently stays behind.
Claims here therefore prefer stable symbols and measured mechanisms over line
numbers, file counts, or other citations that decay without changing meaning.
