# GTA-Claw Audit Remediation Handoff

Last updated: 2026-07-30

## 0. Final immutable stop snapshot

This section is authoritative and supersedes any older status wording later in this
document.

The user requested a new session. All implementation, review, build, test, commit,
push, and PR activity is stopped. No GTA-Claw build process was running when this
snapshot was taken.

### Git baseline

- Last product-code baseline before the documentation-only handoff merge:
  `5e85d6d080712c82dc0814985df1472bdfab5dd9`
- PR #230 merged as `d2493b07b7c064bd8b72c836852c4ae1617b56f5`.
- PR #238 merged as `5e85d6d080712c82dc0814985df1472bdfab5dd9`.
- Closed as unsafe, duplicate, or superseded:
  #223, #237, #181, #155, #150, #133, #129, #116, #160, #18, #171, #144.
- This handoff worktree is intentionally not an integration base:
  branch `aizhihuxiao-modernize-gta-claw`, HEAD `c65133c284c9`.

### Exact preservation of every dirty worktree

Every dirty GTA-Claw worktree was preserved without changing its branch, index, or
open PR. A temporary Git index captured staged, unstaged, and untracked source files
while excluding ignored build output. Each resulting unvalidated commit was pushed
to a dedicated remote handoff ref.

These refs are immutable recovery inputs, **not merge candidates**. Resume from the
corresponding source worktree or diff the snapshot against its recorded parent,
rebase onto current `main`, independently review, and validate before publication.

| Scope | Remote handoff ref | Snapshot commit | Parent |
|---|---|---|---|
| Config Layer 1 | `handoff/2026-07-30-0833/config-layer-1` | `72f9d5ecbc150d713b5e5191d5738234ba5a3ede` | `4ef4d921e5301bc34a436d416b913cbb0f65f83c` |
| Desktop | `handoff/2026-07-30-0833/desktop` | `6901a59f8ecb6bf4f7f9d2dc92b54eb23cdd977c` | `92c2329b151d4b71b342a54d944254da2f3c61a5` |
| Legacy / PR #227 | `handoff/2026-07-30-0908/legacy-pr227-phase-a-corrected` | `94e766605c75e3060e5d80a36e39124486d6675c` | `3dafa9d3adaebd9628c0c46c630db66934ef9152` |
| Updater / PR #236 | `handoff/2026-07-30-0833/updater-pr236` | `efae570296e36c8c20ba4eca2c09e6dd62a9bce6` | `0f31d8eaf71f16724407489ade364263e6b20f9a` |
| Local performance harness | `handoff/2026-07-30-0833/local-perf-harness` | `3b1b76972fd3b0b181c1a8b564ed40d8e3a4f39c` | `4ef4d921e5301bc34a436d416b913cbb0f65f83c` |
| Durable-memory port | `handoff/2026-07-30-0904/durable-memory-terminated` | `8f1eb5ec4f17f50e952ad6683a4e3684344d6142` | `4f4455f3d7e5290d94697a2393996ef05488e4e3` |
| Packaging / PR #233 | `handoff/2026-07-30-0901/packaging-pr233-terminated` | `a9301965e6b10c24be75bfafe359577afc0b20a4` | `b0d2b49fd1a2f00717c38a9c4809b3217871465b` |
| Daemon / PR #232 | `handoff/2026-07-30-0833/daemon-pr232` | `1bfe93661dd959702732d672f80be57bca6ccd1a` | `97b19df94799974167bb1c193833e2d1efeaeb26` |
| Plugin / PR #235 | `handoff/2026-07-30-0901/plugin-pr235-terminated` | `7d17a15598497334c409262d3e108dbc0abd81c4` | `517810ff524aacc2c31b04a088f935f95c9c9ecb` |
| Discovery/fleet port | `handoff/2026-07-30-0840/discovery-fleet-port-final` | `152bfbc81e10967a3eff3f1627b222f1ba4f3bd2` | `8686c27fa55ba768db473c3d4e7f602b978aa021` |
| Trusted A1 candidate | `handoff/2026-07-30-0833/trusted-a1-candidate` | `221226f4a4dc77795696994f8930aae39f8a2260` | `5e85d6d080712c82dc0814985df1472bdfab5dd9` |
| Trusted A1 new-owner candidate | `handoff/2026-07-30-0859/trusted-a1-new-owner-locked` | `7a3542484141d21983e4f6acfbb907c0a620787e` | `3d21c1fa24ad1c552fa32a7cafd68c124ee49b52` |
| Compat-oracle partial port | `handoff/2026-07-30-0859/compat-oracle-locked` | `8c8e1766770ebbfd1dc219b5bca570680ef15bcb` | `df0baddc1812acf41b2504dca824ddb94b45259b` |
| Duplicate trusted supply-chain candidate | `handoff/2026-07-30-0833/duplicate-trusted-supply-chain` | `9f3f3a23fbedfccd48981c9bc306b775b9c00c95` | `92c2329b151d4b71b342a54d944254da2f3c61a5` |
| Dirty PR #234 source | `handoff/2026-07-30-0833/supply-chain-pr234-dirty` | `e70aedb0b2cb4e1e18baf398de4f1b4b78114d4f` | `28fba25d12817f04c8fddee63c6b6fa711941f33` |
| Duplicate Rust channels | `handoff/2026-07-30-0833/duplicate-rust-channels` | `6c07745e267900683629421f69c231faeed3ab6a` | `c1444f5fb37e5bb625d1b6b40a9c465a1d90c357` |
| Duplicate channel remediation | `handoff/2026-07-30-0833/duplicate-channel-remediation` | `e7dbccef04191965dcf4dd2b699e3743cc875d76` | `92c2329b151d4b71b342a54d944254da2f3c61a5` |
| Duplicate trusted product policy | `handoff/2026-07-30-0833/duplicate-trusted-product-policy` | `76f7a94ae26ea566f09361bec53ee058ba7ad341` | `92c2329b151d4b71b342a54d944254da2f3c61a5` |
| Residual ACP bounds change | `handoff/2026-07-30-0833/residual-protocol-bounds` | `69fafeaae3129decf54d7f43d335392f8548c694` | `84ddb5d664a74956d833b71e0093431d2b57189d` |

The duplicate/residual refs are preservation-only. Do not combine them with the
authoritative scopes without a fresh source comparison.

Legacy, Packaging, and Discovery received small writes after the first stop message.
Their `-final` refs are successor commits whose parents are the earlier snapshots.
Those raced edits were not reviewed or tested.

The new Trusted A1 and compat-oracle sessions also wrote after the first inventory.
Their final refs are independent snapshots. In total, 35 handoff refs exist: the 19
final table entries plus sixteen predecessor refs in the Legacy, Packaging, Discovery,
Compat, Plugin, Durable Memory, and Trusted successor chains.

### Current open PR inventory

There are 51 open PRs.

Current remediation PRs:

- #226 Conformance walker — final reviewed head `4f91f203...`; blocked on Trusted A1.
- #227 Legacy runtime — remote head `224a2efc...`; dirty snapshot above is newer.
- #232 Daemon lifecycle — remote head `c43874c5...`; dirty snapshot above is newer.
- #233 Packaging/mobile — remote head `a861f95d...`; dirty snapshot above is newer.
- #234 Supply-chain remainder — remote head `28fba25d...`; must remain last.
- #235 Plugin/tools/skills — remote head `c7d22a2d...`; dirty snapshot above is newer.
- #236 Updater — remote head `0f31d8ea...`; dirty snapshot above is newer.

Historical PRs with unique behavior that must be ported onto current architecture,
not merged from their stale heads:

```text
#212 #211 #189 #188 #187 #186 #184 #183 #182 #180 #179
#177 #175 #174 #173 #172 #170 #169 #167 #166 #164 #163
#161 #158 #157 #151 #148 #147 #142 #141 #140 #139 #138
#137 #136 #132 #131 #130 #128 #124 #115 #68 #57 #10
```

### Audit and task ledger at stop

- Confirmed findings: 184
  - resolved: 25
  - locally validated but dependency-blocked: 11
  - assigned/unresolved: 148
- Tracked todos: 88
  - done: 57
  - in progress at freeze: 16
  - pending: 15

### Exact unfinished state by active scope

1. **Trusted A1**
   - Two A1-only candidates based on the same product main are preserved:
     `trusted-a1-candidate` and `trusted-a1-new-owner-final`.
   - The new-owner candidate also changes `crates/claw-conformance/Cargo.toml` to bind
     the exact consumer edge. Compare both candidates before selecting a base.
   - Scope is limited to `claw-windows-file-id`, root workspace/lock, CODEOWNERS,
     exact frozen fixtures, repository policy, trusted-policy tests, and the exact
     conformance dependency edge.
   - Repo-policy tests, bootstrap decisions/snapshot, fingerprint, README, and trusted
     security-policy edits raced the stop and are preserved in the frozen new-owner
     snapshot. No validation or independent final review was completed after the
     final split.
   - The locked new-owner snapshot also contains a duplicate
     `AUDIT_REMEDIATION_HANDOFF.md` copied from main. Drop that duplicate when
     reconstructing the A1 product diff.
   - Do not use the older mixed trusted snapshots as authority.

2. **PR #226 Conformance**
   - Reviewed and locally validated at `4f91f203...`.
   - Rebase current main after Trusted A1 lands, drop any duplicate helper ownership,
     rerun the strict local matrix and merge.

3. **PR #227 Legacy**
   - The current snapshot contains exactly the post-head
     `src/channels/discordGateway.ts` and `test/discordGateway.test.mjs` changes.
   - The broader historical #172 hardening was removed from the current worktree but
     remains recoverable from predecessor snapshot `e6c7692f...`.
   - Final Discord review found three blockers: backslash URL normalization can bypass
     raw host suffix checks; exact configured bootstrap host must be accepted;
     malformed/whitespace/control session IDs must be rejected atomically. A two-file
     fix attempt is included in the corrected snapshot, but was not independently
     reviewed or tested; re-audit all three findings. Its test-file SHA-256 is
     `ae6c2d3503a548f02b0bc9c9c6772538f9c4bca703398191d11f613b8969959d`.
   - After fixing those two Discord files, freeze the final seven test bytes, land
     Trusted A2, then rebase/validate/merge #227.
   - Continue #172 as a separate reviewed follow-up if it cannot remain cleanly within
     #227: remove shipped `node:vm`/`isolated-vm` execution, insecure URL/admin bypass,
     runtime package mutation, and stale vulnerable dependency behavior.

4. **Desktop**
   - Thirteen dirty files are preserved in the desktop snapshot.
   - No corrected full validation was run.
   - Re-review responsive matrices at 720/1080 for 80/100/125/150/175/200%, require
     fresh positive glyph/control containment, and recheck palette modality/focus,
     first-run, session header, cards, prompts, state truth, NaN and index handling.

5. **Daemon / PR #232**
   - The final independent review found ten blockers, including two compile failures:
     malformed `tokio::select!` structure and nested `authorize_tool_access`.
   - Remaining semantic blockers: reload reset-before-commit, premature channel
     readiness, response-ID epoch race, failed-history contamination, output-error
     drain omission, unowned audit worker, hidden task panics, and a nested test module.
   - Fix and re-review before any Cargo command.

6. **Plugin / PR #235**
   - Dirty snapshot is preserved; no final validation.
   - Late schema/runtime limit tests and `claw-windows-handle-dir` edits are included
     in the locked snapshot and remain unreviewed.
   - A final `claw-tools/src/sandbox.rs` edit completed before the owner CLI was
     forcibly terminated; it is included in the terminated snapshot and is unreviewed.
   - Still requires current-safe helper API/policy, construction-time budgets,
     lossless public/enforced schema identity, fail-closed unsupported keys, Windows
     handle-relative semantics, exact lifecycle rollback/deadlines, and adaptive
     sandbox-race coverage from historical #128.

7. **Updater / PR #236**
   - Dirty snapshot is preserved; no final validation.
   - Use the reduced design: Windows fails closed before mutation; Unix single-file
     no-replace only until proven.
   - Remaining work includes immutable macOS byte binding, unambiguous tree digest,
     verified rollback/quarantine identities, complete fsync/journal ordering,
     unjournaled-backup conflict, async blocking isolation, cfg/test compilation, and
     historical #151's pathless fresh-redownload restart contract.

8. **Packaging/mobile / PR #233**
   - Thirty-nine dirty files are preserved; no final validation or immutable final
     source commit.
   - Final `packaging/windows/self-test.ps1` and
     `.github/workflows/windows-packaging.yml` edits raced the stop and are preserved
     but unreviewed.
   - The Packaging and Plugin owner CLIs were ultimately stopped by exact PID after
     their current turns continued writing despite queued stop messages.
   - Finish Linux service/RPM/DEB/OCI lifecycle, release signing/retry safety,
     Android/iOS runtime gates, TUI cooperative EOF shutdown, and historical
     #141/#158/#138/#124/#142/#182/#179 plus current-safe #68 packaging behavior.
   - Only after the source tree is immutable may Trusted Phase B pin its exact closure.

9. **Config**
   - Layer 1 dirty snapshot is preserved. Finish current blockers and review before
     validation.
   - Layers 2-4 have not started and must stack in order:
     Crestodian CAS/recovery, provider/source semantics, transaction durability.
   - PRs #223 and #237 remain closed; do not revive them wholesale.

10. **Local performance harness**
    - The complete untracked `tools/perf/**` tree is preserved in its snapshot.
    - Its independent review was interrupted before producing a verdict; no tests ran.
    - Review schema/identity, process-group timeout cleanup, atomic artifacts, locking,
      threshold direction/units, honest BLOCKED reporting, then validate locally.

11. **Historical ports**
    - Durable memory is partially implemented in its snapshot. Its final Cargo,
      persistence, durable-state, transcript, and test edits completed before the
      owner CLI was terminated and remain unreviewed.
    - Discovery/fleet is partially implemented in its snapshot. A one-line
      `dns_sd.rs` change raced the stop and is unreviewed.
    - Durable state stopped before writing files.
    - Compat-oracle produced unreviewed README, validator/self-test, reachability
      sweep, gateway/client/integration ledger, and provider-ledger changes, stored in
      `compat-oracle-locked`.
    - PR #238 already completed the #171/#144 client-contract port and is on main.
    - Still create reviewed current-main ports for compat/conformance, trusted policy,
      HTTP API, durable state, durable memory, discovery/fleet, remaining iOS/client
      contracts, and owner-routed requirements.

12. **PR #234**
    - Keep last. Restack only independently reviewed product/dependency remainder after
      all trusted closures and source PRs are final. Never allow it to self-authorize.

### Required resume order

1. Fetch current `origin/main` and read this section first. The last product-code
   baseline before the handoff documentation is `5e85d6d...`.
2. Review/validate/land Trusted A1.
3. Rebase/validate/merge #226.
4. Fix final Legacy Discord blockers, land Trusted A2, then merge #227.
5. Finish immutable Plugin and Packaging sources; land Trusted Phase B.
6. Rebase/validate/merge #235 and #233.
7. Finish Desktop, Daemon, Updater, Config Layers 1-4.
8. Complete all grouped historical current-main ports and close their stale PRs.
9. Restack the safe #234 remainder last.
10. Run one full local correctness matrix on one final SHA.
11. Run the retained local performance matrix on that same SHA.
12. Close every superseded PR and verify no dirty worktree or handoff ref was omitted.

### Validation policy

- CI is not evidence and must not be used as a merge or release gate.
- Every Cargo command must start with:
  `env -u CARGO_TARGET_DIR -u TMPDIR -u CARGO_BUILD_JOBS`
- Use `-j8`; run heavy local validation in one slot.
- No handoff snapshot may be merged directly.

## 1. Historical context

The remaining sections preserve earlier technical decisions and detailed audit
context. Their status wording is historical; section 0 is the only authoritative
resume state.

## 2. Where the source changes live

Authoritative source changes are in isolated worktrees under:

```text
/Users/jason/Desktop/github copilot projects/copilot-worktrees/GTA-Claw/
```

The configured main checkout is:

```text
/Users/jason/Desktop/github copilot projects/GTA-Claw
```

Do not edit the main checkout directly. Continue using isolated worktrees.

Non-source data also exists outside Desktop:

- session metadata and scratch artifacts: `/Users/jason/.copilot/session-state/`
- derived Rust build artifacts: `/Users/jason/.rustbuild/`
- pushed branches and pull requests: GitHub

Those locations are not authoritative source worktrees. The handoff document itself is:

```text
/Users/jason/Desktop/github copilot projects/copilot-worktrees/GTA-Claw/aizhihuxiao-verbose-couscous/AUDIT_REMEDIATION_HANDOFF.md
```

This file is committed to `main`; the path above identifies the worktree where the
final snapshot was authored.

## 3. Current Git baseline

Last product-code baseline before the handoff documentation:

```text
5e85d6d080712c82dc0814985df1472bdfab5dd9
```

Recent merged remediation commits:

```text
d2493b0 Repair Rust channel reliability (#230)
4ef4d92 Fix durable Gateway pairing linearizability
526a53b Fix goal and memory durability
a596af9 Harden protocol bounds and cancellation flow
2692c28 Enforce complete provider exchange deadlines
2a12734 Document the production daemon accurately
92c2329 Make daemon help global and runtime-independent
```

The current handoff worktree is an older clean integration branch:

```text
branch: aizhihuxiao-modernize-gta-claw
HEAD:   c65133c284c906fcc01a47d49492f38a08cd8ee5
```

Do not use this branch as the integration base. Fetch and use current `origin/main`.

## 4. Audit completion

Tracked confirmed findings: **171**

| State | Count |
|---|---:|
| Merged/resolved | 25 |
| Locally validated but dependency-blocked | 11 |
| Assigned / still unresolved | 135 |

Severity among unresolved findings:

| Severity | Count |
|---|---:|
| Critical | 3 |
| High | 53 |
| Medium | 70 |
| Low | 9 |

Strict closure:

- merged only: 25 / 171 = 14.6%
- merged + validated: 36 / 171 = 21.1%

The original modernization baseline is merged. The new deep-audit remediation is not complete.

## 5. Critical and high-priority unresolved areas

### Critical

1. Rust WhatsApp POST authenticity / native channel composition.
2. Migration conflict finalization can mark a partial rollback complete.

### High-priority groups

- Config publication:
  - concurrent-edit overwrite
  - ABA/file identity on Windows
  - alias-split locks
  - conflict DACL preservation
  - missing-destination recovery
  - fast-path/journal race
- Migration:
  - non-atomic overwrite
  - partial rollback state
  - real Codex bearer/header semantics
  - target-owner collisions
  - source authority completeness
- Daemon:
  - startup/reload cancellation and transactionality
  - Gateway/channel ingress before deferred reload
  - task joining and absolute deadlines
  - output backpressure
  - response-history epoch/cache consistency
  - audited tool authorization
  - committed-but-not-durable regression protection
- Desktop:
  - diagnostic preview truth
  - focus/accessibility modality
  - 80-200% responsive geometry
  - state/count/consent correctness
- Plugin/tools/skills:
  - lifecycle rollback/publication windows
  - Windows handle-relative safe FFI boundary
  - exact/bounded schema construction
  - Unix post-verification rename race
- Packaging:
  - complete signed release profile
  - Windows signing boundary
  - RPM/Debian rollback
  - OCI state path
  - mobile executable smoke
  - complete protected transitive closure
- Updater:
  - signed-digest binding
  - quarantine/rollback identity
  - Windows fail-closed durability
  - anti-rollback state durability
- Supply chain:
  - full Node lock/scripts contract
  - exact protected modes and immutable provenance
  - Skia/host graph
  - deny-version reconciliation
- Performance:
  - no retained local performance harness or baseline yet

## 6. Pull requests

### Merged

- documentation daemon truth
- provider exchange deadlines
- MCP/ACP/discovery/relay bounds
- goals/memory durability
- durable pairing linearizability

These are already represented by remote main `4ef4d92`.

### Open remediation PRs

| PR | Head | Status / next action |
|---:|---|---|
| #226 | `4f91f20348b030cdf6817bc1bb9c527a999a25d2` | Code reviewed and locally validated. Blocked only on Trusted A1 exact admission for `claw-windows-file-id`. |
| #227 | `224a2efc9e411288f7562270e3a7e0c92c8c4f2b` + two dirty Discord files | Prior head was reviewed/Node-validated. Final Discord URL/session semantics remain under review; its final seven-test bytes feed Trusted A2. |
| #230 | `77516f24ddec48ac178b2301336238f33c693176` | **Merged** as `d2493b0`. Final raced raw-HMAC increment received an independent review and focused local test. |
| #232 | `c43874c5f70412dcd63183da6f7fb2217a7541e3` | Remote head is stale relative to a large dirty worktree. Continue only after inspecting actual worktree and all latest daemon blockers. |
| #233 | `a861f95d4e747e4f6d07f331971e30ad50f5f28a` | Remote head is stale relative to dirty Packaging worktree. Must not merge until bottom trusted integration lands, then rebase/drop protected files. |
| #234 | `28fba25d12817f04c8fddee63c6b6fa711941f33` | Frozen/unsafe. Do not merge first. Later rebase and keep only product/dependency remainder after trusted + Packaging + Legacy changes. |
| #235 | `c7d22a2d13f46eb2b2b7b18d818ab7820f1b9c18` | Active. Remote head may advance. Latest blockers include helper policy/FFI, construction-time schema budgets, public/enforced schema identity, lifecycle deadlines/publication. |
| #236 | `0f31d8eaf71f16724407489ade364263e6b20f9a` | Remote head stale; dirty updater worktree contains major redesign. Not ready. |
| #237 | `93901758eee3459b15ff033bb58e90cc9ef072d7` | **Closed.** Superseded source snapshot; never merge. |
| #223 | `bc1168e5736edafdf4faf4f9ee6dc0ae2b1155c1` | **Closed.** Alternate unsafe Config/Migration implementation. |

### Historical open PR audit

Eight GPT-5.6 Sol/max batches audited all 54 older open PRs against current source,
without using CI.

- Closed as superseded: #181, #155, #150, #133, #129, #116, #160, #18.
- The remaining 46 contain unique behavior and are tracked for current-main ports;
  their stale heads must not be merged directly.
- Port groups: compat/conformance; trusted policy; HTTP API; durable state; durable
  memory; discovery/fleet; client contracts; and requirements routed to the existing
  Legacy/Updater/Packaging/Plugin owners.

## 7. Authoritative worktrees

| Scope | Worktree |
|---|---|
| Trusted atomic bottom layer | `aizhihuxiao-urban-chainsaw` |
| Config Layer 1 publication/CAS | `aizhihuxiao-automatic-bassoon` |
| Desktop UX | `aizhihuxiao-potential-couscous` |
| Plugin/tools/skills | `aizhihuxiao-turbo-carnival` |
| Updater | `aizhihuxiao-refactored-spoon` |
| Daemon lifecycle/API | `aizhihuxiao-symmetrical-bassoon` |
| Packaging/mobile | `aizhihuxiao-stunning-chainsaw` |
| Rust Channels PR #230 | `pr-230-aizhihuxiao-repair-rust-channels` |
| Legacy TypeScript PR #227 | `aizhihuxiao-psychic-funicular` |
| Conformance PR #226 | `pr-226-aizhihuxiao-fix-conformance-symlink-walker` |
| Local performance harness | `aizhihuxiao-special-dollop` |
| Superseded Config source snapshot | `aizhihuxiao-turbo-dollop` |

Duplicate trusted-policy worktrees are non-authoritative and must remain frozen:

- `aizhihuxiao-shiny-winner`
- the worktree/session behind `0409e3d1-4201-45c7-a71f-076f6062b6f3`

## 8. Required merge order

1. Finish and independently review Trusted A1.
   - It must be based on current main.
   - It contains only the actual `claw-windows-file-id` helper plus exact FFI,
     workspace, lock, consumer-edge, ownership, frozen fixtures, and negative tests.
   - It has zero Node, PR227, Packaging, PR233, PR234, or handle-directory paths.
2. Rebase and merge PR #226 after trusted admission for `claw-windows-file-id`.
3. PR #230 is complete and merged.
4. Freeze PR #227's final seven tests, then land Trusted A2 containing the actual
   tests/config execution closure and exact policy.
5. Rebase PR #227 onto main after Trusted A2, preserve signed native WhatsApp fixtures, run final integration validation, then merge.
6. Finish immutable Packaging and Plugin source; Trusted Phase B must use their exact
   final protected bytes and complete transitive closure.
7. Rebase PR #233/#235, drop protected files already landed by Phase B, validate, and merge.
8. Finish/review Desktop, Updater, and Daemon branches; rebase current main and merge in low-conflict order.
9. Complete Config Split stack:
   - Layer 1: config publication/CAS
   - Layer 2: Crestodian CAS/recovery
   - Layer 3: migration provider/source semantics
   - Layer 4: migration transaction durability
10. Land all eight grouped historical current-main ports and close their 46 stale PRs.
11. Rebase PR #234 last, remove all trusted-tree duplicates, retain only independently reviewed product/dependency/runtime changes, validate, merge.
12. Run one final local full correctness matrix.
13. Run the retained local performance matrix.

## 9. Trusted bottom-layer requirements

Do not merge a trust-only preauthorization PR.

The bottom layer must atomically bind:

- actual protected workflows and every executable/transitive input they invoke
- complete Linux packaging/RPM/systemd closure
- complete Windows signing scripts/modules/assets
- macOS packaging/signing/SPDX closure
- Android/iOS workflows, projects, manifests, scripts and smoke validators
- exact file modes
- immutable source commit/tree/blob provenance
- CODEOWNERS
- removal/tamper/rename/mode/no-op negative tests
- exact seven PR227 test paths, hashes and execution command
- product repo-policy exact allowlist for those tests
- synchronized `WHATSAPP_APP_SECRET` mappings
- complete Node `package-lock.json` and scripts/lifecycle contract
- exact Python requirements hashes and executed helper scripts
- exact FFI admissions for:
  - `claw-windows-file-id`
  - final `claw-windows-handle-dir`

Do not authorize provisional PR234 combined config hashes.

Post-stop clarification:

- Packaging source commit `a861f95d4e747e4f6d07f331971e30ad50f5f28a` is superseded and is not a final immutable source.
- The Packaging worktree contains newer uncommitted TUI/Gateway cooperative-shutdown
  changes: `GatewayWorker::shutdown` returns an explicit cooperative/forced/task-failed
  ledger, and stalled-connect tests require client-caused EOF before fixture shutdown.
  These changes are newer than `a861f95d` and require review before creating the next
  immutable Packaging source commit.
- The next Packaging source must additionally include and protect
  `packaging/linux/tests/make-malicious-tar.py` plus every workflow/script that executes it.
- The trusted bottom layer must pin the complete `package-lock.json` bytes and the complete
  approved `package.json.scripts` / lifecycle map.
- The trusted bottom layer must contain no PR234 `docker-publish` preauthorization. PR234
  remains frozen until the bottom layer, PR230, PR227, and Packaging are integrated.

## 10. Config Split requirements

### Layer 1: Config publication

Must expose safe guarded APIs:

- canonical, deadlock-safe multi-path locks
- locked raw-byte/absence snapshots
- conditional compare-write
- conditional compare-remove
- distinct conflict outcomes
- durability warnings
- fail-closed unsupported cases

Known unresolved review points:

- absent destination recovery
- Windows 128-bit identity / ABA
- long/8.3 alias lock convergence
- conflict DACL preservation
- failed-write inherited DACL preservation
- fast-path journal race

### Layer 2: Crestodian

Wait for Layer 1 API. Implement:

- tolerant schema-version pre-read
- future-schema refusal
- lock + reread
- CAS setup/recovery
- conditional rollback only
- rollback durability warnings
- relative filename parent `"."`

### Layer 3: Migration semantics

Implement:

- explicit vs discovered source authority
- complete aggregate authority digest
- no-follow verified source I/O
- real Codex TOML semantics
- target ownership trie / collision rejection
- directory ownership

### Layer 4: Migration durability

Implement:

- journal v2 per-operation states
- one lock across apply/recovery/rollback
- stage exact outputs before journaled publication
- domain-separated lossless digests
- transactional secrets
- conflict-preserving rollback of every entry
- journaled trash/cleanup
- subprocess crash/fault tests at every state transition
- Windows fail-closed where durability cannot be proven

## 11. Local validation rules

CI is not a completion or release gate.

Use local validation only.

Every Cargo command in the current long-lived environment must begin with:

```sh
env -u CARGO_TARGET_DIR -u TMPDIR -u CARGO_BUILD_JOBS
```

Use `-j8` where supported.

Run only one heavy build process at a time.

Do not use `/Users/jason/.rustbuild` as a target directory.

Before deleting build artifacts:

1. resolve the exact path;
2. verify no process holds it using `lsof`;
3. delete only the literal derived target directory;
4. never delete a worktree or source directory.

Current stop-time resources:

```text
no active GTA-Claw build processes
data volume: approximately 115 GiB free
memory disk: approximately 47 GiB free
```

## 12. Final local correctness matrix

After every remediation branch is integrated:

```sh
env -u CARGO_TARGET_DIR -u TMPDIR -u CARGO_BUILD_JOBS cargo fmt --all -- --check
env -u CARGO_TARGET_DIR -u TMPDIR -u CARGO_BUILD_JOBS cargo check --workspace --all-targets --locked -j8
env -u CARGO_TARGET_DIR -u TMPDIR -u CARGO_BUILD_JOBS cargo clippy --workspace --all-targets --locked -j8 -- -D warnings
env -u CARGO_TARGET_DIR -u TMPDIR -u CARGO_BUILD_JOBS cargo test --workspace --all-targets --locked --no-fail-fast -j8
env -u CARGO_TARGET_DIR -u TMPDIR -u CARGO_BUILD_JOBS RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked -j8
env -u CARGO_TARGET_DIR -u TMPDIR -u CARGO_BUILD_JOBS cargo +1.94.0 check --workspace --all-targets --locked -j8
```

Also run the documented Desktop, Android, iOS, Node 26, repository-policy, packaging, and native process matrices locally.

Do not silently retry failures. Capture the first failing test identity and output.

## 13. Performance testing

Performance testing is not ready until:

- all remediation PRs are integrated;
- one final SHA and lockfile exist;
- the full local correctness matrix passes;
- the local performance harness is retained and validated.

Performance harness worktree:

```text
aizhihuxiao-special-dollop
```

Required local-only performance surfaces:

- clean/no-op release builds
- daemon cold/warm startup and readiness
- HTTP JSON/SSE latency and throughput
- Gateway RPC/fan-out/saturation
- MCP/ACP framing and sustained requests
- provider TTFT/inter-chunk latency using local fixtures
- memory/goals scale and restart/contention
- plugin activation/invoke and tools sandbox corpus
- channel queue boundaries
- Slint frame/input responsiveness at both viewports and all densities
- Node legacy facade
- mobile/package launch smoke

Suggested default comparison thresholds:

- throughput >= 95% of reference
- median/startup <= 105%
- p95/p99 <= 110%
- peak RSS <= 110%
- package/binary size <= 105%
- zero errors below declared capacity

Store raw JSON, environment inventory, toolchain versions, artifact hashes and ABBA reference/candidate order.

## 14. New-session startup checklist

1. Read this file completely.
2. Fetch `origin/main`; verify current SHA.
3. Query each PR through GitHub API; do not trust cached session messages.
4. Inspect each authoritative dirty worktree before issuing instructions.
5. Verify all old sessions remain stopped.
6. Close or ignore duplicate/obsolete PRs; never merge #223 or #237.
7. Resume only one actual implementation owner per file scope.
8. Re-run independent code review before granting a validation slot.
9. Keep heavy local validation serialized.
10. Update this handoff document after every merge or dependency-order change.

## 15. Important operational history

- User explicitly forbids relying on CI.
- Direct main push is governed by repository/organization rules; app-native PR plus locally proven merge was previously used.
- Global Git proxy was repaired from stale `172.16.8.95:2080` to `127.0.0.1:2080`.
- The shared memory disk was filled multiple times by inherited `CARGO_TARGET_DIR`; always unset it per command.
- Derived targets were safely cleaned only after every holder exited naturally.
- Many delayed cross-session messages report stale PR heads. Always query GitHub first.
- Security is lower priority than correctness, UX, performance and stability, but confirmed authentication/durability defects remain blockers.
