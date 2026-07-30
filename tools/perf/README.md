# GTA-Claw local performance harness

`tools/perf` is a retained, **local-only** reference/candidate harness. It runs committed Git
revisions in separate detached worktrees, uses exact ABBA interleaving, and writes a versioned JSON
record containing raw command samples, comparison summaries, Git/tree/toolchain/artifact hashes,
and the host/environment inventory. It does not add or depend on CI.

The harness never checks out or updates a source branch. `--reference` and `--candidate` must resolve
to commits; uncommitted working-tree changes are intentionally excluded. Benchmark children receive
a minimal environment, an isolated home/temp directory, and no ambient credential or proxy
variables. Cargo and npm-related hooks are forced offline, and runnable service fixtures use only
process pipes or loopback sockets.

## Requirements

- Python 3.10 or newer, using only the standard library.
- Git.
- The existing tool for a selected suite (`cargo`, `rustc`, or `node`).
- Dependencies already present in local caches. The harness never installs or downloads them.
- The Node suites additionally require this checkout's existing `node_modules` directory. It is
  linked read-only-by-convention into each disposable detached worktree; if absent, the suite is
  reported `BLOCKED`.

## Commands

List every workload and its current host availability:

```sh
python3 tools/perf/perf.py list
python3 tools/perf/perf.py list --suite daemon --json
```

Resolve refs, validate tracked fixtures and print the exact plan without creating worktrees or
running a workload:

```sh
python3 tools/perf/perf.py dry-run \
  --reference main \
  --candidate HEAD \
  --suite daemon,protocol,state \
  --output /tmp/gta-claw-perf-plan
```

Run the default functional suites and evaluate thresholds:

```sh
python3 tools/perf/perf.py run \
  --reference main \
  --candidate HEAD \
  --output /tmp/gta-claw-perf-run \
  --compare
```

Select suites with repeated or comma-separated `--suite` values. Explicitly selecting `build`
enables its otherwise-disabled cold/no-op hooks:

```sh
python3 tools/perf/perf.py run \
  --reference main \
  --candidate HEAD \
  --suite build \
  --output /tmp/gta-claw-build-perf \
  --compare
```

The default is one warmup and six measured samples per variant. The measured order is exact ABBA
cycles (`reference`, `candidate`, `candidate`, `reference`). Overrides must retain an even
repetition count:

```sh
python3 tools/perf/perf.py run \
  --reference main \
  --candidate HEAD \
  --suite protocol \
  --warmups 2 \
  --repetitions 10 \
  --output /tmp/gta-claw-protocol-perf \
  --compare
```

After an interrupt, rerun the same command with `--resume`. The harness marks any in-flight attempt
`interrupted`, recreates detached worktrees, reconditions workload-scoped targets, and executes only
unfinished ABBA slots:

```sh
python3 tools/perf/perf.py run \
  --reference main \
  --candidate HEAD \
  --suite protocol \
  --output /tmp/gta-claw-protocol-perf \
  --compare \
  --resume
```

Re-evaluate a retained run with the configured thresholds without rerunning workloads:

```sh
python3 tools/perf/perf.py compare \
  --input /tmp/gta-claw-perf-run/run.json \
  --output /tmp/gta-claw-perf-run/recomparison.json
```

Global `--catalog` and `--thresholds` options may point to local JSON files. Put global options before
the command name.

## Suites and declared capacities

| Suite | Workload | Capacity per sample | Availability |
|---|---|---:|---|
| `daemon` | One-shot production `--probe` | 1 probe | Cargo + cached dependencies |
| `daemon` | Smoke readiness/supervision fixture | 1 scenario | Cargo + cached dependencies |
| `daemon` | Loopback `/health`, `/ready`, legacy health fixture | 1 scenario | Cargo + cached dependencies |
| `protocol` | MCP stdio framing fixture | 1 full scenario | Cargo + cached dependencies |
| `protocol` | ACP newline framing/EOF drain | 3 request frames | Cargo + cached dependencies |
| `state` | Deterministic memory planning | 3 planning passes | Cargo + cached dependencies |
| `state` | Durable goal compaction/reopen | 1 scenario | Cargo + cached dependencies |
| `desktop` | Slint software-renderer product smoke | 1 full render scenario | macOS/Windows; otherwise `BLOCKED` |
| `node` | Existing `splitMessage` local fixture | 10,000 messages | Node + existing `node_modules`; otherwise `BLOCKED` |
| `build` | Rust cold and unchanged workspace builds | 1 build | Disabled by default |
| `build` | Node cold and unchanged-output builds | 1 build | Disabled by default; requires existing `node_modules` |

Missing tools, fixtures, supported platforms, or local Node dependencies are always reported
`BLOCKED` with a reason. They are never converted to N/A or a pass. Command failures below a declared
capacity are failures, not skipped samples. Compared runs exit `3` when blocked and `1` on a
threshold failure; uncompared runs use the same codes for blocked or failed execution.

## Threshold policy

`config/thresholds.json` is versioned with these defaults:

| Metric | Candidate requirement |
|---|---:|
| Median throughput | at least 95% of reference |
| Median latency or startup | at most 105% of reference |
| p95 latency | at most 110% of reference |
| p99 latency | at most 110% of reference |
| Maximum RSS | at most 110% of reference |
| Declared artifact size | at most 105% of reference |
| Errors at/below declared capacity | zero |

Maximum RSS is captured by a fresh Python measurement process using `resource.getrusage` on POSIX.
Where that API is unavailable, the RSS check and workload comparison report `BLOCKED` rather than
passing silently.

## Retained output

`run.partial.json` is atomically replaced after every state change. A completed run becomes
`run.json`; stdout/stderr logs and command control records remain beside it. The
`schema/v1/perf-run.schema.json` contract covers:

- exact requested refs, commit IDs, tree IDs, and merge base;
- hashed harness sources/config/schema and hashed toolchain executables;
- hardware, OS, disk, load, environment-name inventory, and redaction inventory;
- rendered argv/cwd/environment, timestamps, exit/signal/timeout state, wall time, and RSS;
- SHA-256, size, mode, and mtime for every declared artifact;
- warmup and measured raw samples plus threshold checks and aggregate status.

Potential secret values are never retained. Their variable names appear only in the redaction
inventory so the omission is auditable.

## Dedicated-host controls

For comparable results:

1. Use the same physical host, OS build, filesystem, power source, and toolchain caches for both refs.
2. Connect AC power, select the host's performance power mode, prevent sleep, and keep thermal
   protection enabled.
3. Stop interactive applications, indexers, backup jobs, updates, antivirus scans, containers, and
   other build/test processes; record anything that cannot be stopped.
4. Pre-populate Cargo/npm caches before the timed run, disconnect external networking or apply a
   loopback-only firewall, then use `dry-run` to confirm no suite needs a download.
5. Allow the host to reach a stable idle temperature and load. Do not compare runs taken across
   thermal throttling, battery transitions, reboots, or material load-average changes.
6. Keep CPU affinity, priority, frequency governor, turbo policy, memory pressure, and disk free
   space identical. If manually pinned, record the controls outside the run and do not change them
   between variants.
7. Do not run the opt-in build suite concurrently with functional suites. Cold builds use a fresh
   target per sample; unchanged builds prepare once per variant and reuse only that variant's target.

## Validation commands

Run these only in an approved validation slot:

```sh
python3 -m unittest discover -s tools/perf/tests -t tools/perf -v
python3 tools/perf/perf.py list
python3 tools/perf/perf.py dry-run \
  --reference main \
  --candidate HEAD \
  --suite daemon,protocol,state,desktop,node \
  --output /tmp/gta-claw-perf-validation-plan
```

Cargo, npm, build, and performance commands are deliberately not part of the harness unit-test gate.
