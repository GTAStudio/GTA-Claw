# `claw-config`

`claw-config` is the strict configuration boundary for the Rust workspace. It
loads UTF-8 JSON5 into immutable typed snapshots, emits generated JSON Schemas,
writes snapshots atomically, resolves layered runtime configuration, publishes
tear-free typed reload notifications, and converts the frozen GTA legacy
environment contract without reading process environment state.

`OpenClawConfig` represents all 47 top-level domains in the frozen
`config-domains` inventory. Fixed domains reject unknown keys and
plugin-extensible domains preserve their named extension objects. The original
version 1 runtime envelope remains additive and requires `schema_version` plus
these `core` domains:

`auth`, `role`, `channels`, `server`, `logging`, `sessions`, `copilot`,
`legacy`, `updates`, `admin`, and `network`.

Unknown envelope, top-level domain, and fixed-field names are rejected. Secrets
are persisted only as validated environment or platform-store references.
`SecretRef` and `SecretMaterial` redact Debug, Display, and direct Serde output;
the explicit platform store port is the only API that receives borrowed
plaintext.

The frozen remote role contract is split in two. `parse_role_document` owns the
interpretation half: the `ROLE_DOCUMENT_MAX_BYTES` bound, the JSON and
plain-text encodings, a string `content` winning over `prompt`, an absent or
non-string `content` falling back to a string `prompt`, a rejected empty
selection, an optional string `model`, and ordered `RoleDiagnostic` values in
place of the log lines the legacy loader emitted. A body that declares a JSON
content type is rejected outright when it is not a usable role; a body that
merely looks like JSON falls back to being used verbatim. `load_role` drives
the `RoleSourceFetcher` port and rejects non-2xx responses, an over-long
declared length, an over-long body, and a body that is not UTF-8.

This crate owns no HTTP client and does not gain one, so no adapter implementing
`RoleSourceFetcher` ships here and nothing in this crate fetches a role. Three
deliberate differences from the legacy loader are recorded rather than hidden:
the size bound counts UTF-8 bytes instead of UTF-16 code units, a non-UTF-8 body
is rejected instead of being decoded with replacement characters, and the
unknown-model warning belongs to whichever component owns a provider catalog,
because a model string is returned exactly as the document spelled it.

Layered runtime resolution uses built-in, system, user, workspace, frozen
legacy environment, then command-line precedence. Nested objects merge
recursively while arrays and scalars replace lower layers. Every cooperating
publication API uses one stable target-sidecar lock. Current and unsupported
schema probes stay read-only; `read_config_schema_version` exposes that tolerant
probe without accepting the rest of a future document as typed configuration.
Before returning from a read-only fast path, migration rechecks both the
handle-pinned generation and canonical recovery-journal path, so a journal or
edit arriving during the probe forces locked recovery/re-read.
`PublicationLock::acquire_all` canonicalizes, sorts, and deduplicates a complete
target set before taking its first lock. A held lock can snapshot raw
bytes/absence and feed that private generation token to `compare_write` or
`compare_remove`; comparison loss is a `CompareOutcome::Conflict`, not an I/O
failure. Conditional removal returns post-linearization cleanup and directory
sync limitations through the applied `WriteOutcome`.
Destructive migration re-reads under the publication lock, then publishes
through a synchronized recovery journal and atomic displacement so the exact
object replaced at the CAS point can be validated by both digest and stable
filesystem identity. Same-byte replacement objects are therefore conflicts
rather than an ABA success. Conflicting bytes are backed up and restored without
replacing a still-newer live edit, and the active journal is retired so a
corrected retry is not poisoned. File migrations keep exact
restrictive-permission backups and expose rollback. `ConfigHub` and
`ConfigFileWatcher` publish complete immutable snapshots and ordered typed
notifications.
`ResolvedConfig::environment_diagnostics` records each exact legacy mapping that
contributed and each unknown input that was ignored, while `applied_layers`
includes the environment layer only when a runtime mapping actually applied.

Legacy conversion supports the runtime rows in
`compat/legacy/config/env-mapping.json`, except `COPILOT_CLI_PATH`, because the
production Rust runtime does not execute Copilot CLI. Present deployer, build,
CI, and Copilot CLI rows produce ordered `ManualRequired` diagnostics. Runtime
rows produce `Applied` diagnostics and unknown supplied names produce
`IgnoredUnknown`, allowing a caller to render a complete deterministic report:

- `COPILOT_CLI_PATH`
- `DOCKER_IMAGE`
- `APP_LANG`
- `COPILOT_CLI_VERSION`
- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`
- `DOCKERHUB_IMAGE`

The mapping table is generated and validated from the frozen JSON artifact by
`build.rs`. The package-contained `data/env-mapping.json` is the canonical
crate input so `cargo package` verification is independent of the repository
layout. Normal workspace builds compare the complete typed record, including
defaults, conversions, validation, requirements, aliases, targets, and known
quirks, against `compat/legacy/config/env-mapping.json` and fail on any drift.
The generated Rust table embeds every behavioral field so contract changes are
visible to code review; executable conversion remains an explicitly tested,
typed Rust implementation rather than an interpreted rule engine.

Atomic writes require a trusted configuration directory. The destination and
configuration directory symlinks/reparse points are rejected. Canonicalization
resolves platform layout aliases above that directory (including normal macOS
`/var` aliases) before the resolved chain is validated, but path-based
replacement cannot eliminate every rename race in a directory writable by an
attacker.
Unix flushes the temporary file and directory around atomic rename. When a
Windows destination already exists, the writer flushes the temporary file and
uses `ReplaceFileW` with a recovery backup, preserving destination ACLs and
filesystem metadata. Ambiguous partial `ReplaceFileW` outcomes keep every
recovery path and fail closed instead of deleting a possibly authoritative
backup; restoration uses an atomic no-replace move rather than an
absence-check/rename pair. Windows backup and conflict artifacts copy the source
DACL and protect that effective access list from broader inheritance. A first
write has no destination metadata to preserve and uses a same-directory rename.
Windows does not document a supported directory-handle flush equivalent, so
final directory entry durability across sudden power loss is not claimed.
Post-publication cleanup/durability problems are returned as `WriteOutcome`
warnings rather than falsely reporting that the atomic replacement failed.
Existing Windows destinations are normalized from their open handles and use
the full volume plus 128-bit `FILE_ID_INFO` identity; long, extended, and
available 8.3 spellings therefore derive the same sidecar and journal. Multiply
linked regular files fail closed rather than splitting cooperating locks.
Targets without no-follow identity, atomic exchange, or atomic no-replace
support return an explicit unsupported I/O error instead of approximating CAS.
