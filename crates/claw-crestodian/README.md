# `claw-crestodian`

`claw-crestodian` provides explicit-path, backup-first first-run setup and
recovery. It never discovers or writes real user directories by itself.

Guided setup validates typed answers, writes the strict configuration
atomically, then publishes non-secret setup state. A later failure restores the
exact pre-setup bytes. Recovery distinguishes missing, corrupt, interrupted,
and incompatible config/state, flushes exact backups before replacement,
preserves orphaned atomic-write artifacts, and rolls earlier writes back when a
later real filesystem operation fails.

Remote rescue uses a closed `/crestodian` grammar with no model inference. It
fails closed for sandboxed, non-owner, anonymous, or disallowed group contexts.
Read-only status runs directly; a gateway restart or a typed configuration write
requires an unexpired approval from the same message identity and mandatory
metadata-only audit persistence.

## Ring-zero authority

A Crestodian session runs the ordinary agent loop restricted to exactly one
OpenClaw authority tool, `crestodian`, which wraps the closed set of typed
operations `status`, `validate_config`, `config_set`, `config_set_ref`, and
`restart_gateway`. A normal agent session never receives that tool, and a
backend that cannot prove the single-tool restriction — always-on native tools,
or a contract this build does not recognise — is refused before any inference
happens. The Codex app server is allowed one authority tool beside its inert
`update_plan` planner, and invoking the planner as an authority tool is refused
on its own terms.

## Typed mutation

Configuration is never edited ad hoc. Every write names one field of a closed
table, is typed and bounded before it is accepted, and is refused outright when
the path reaches inference-route state (`agents.*`, `auth.*`, `cli.*`,
`models.*`, root `tools.*`) or credential resolution (`$include`, `env.*`,
`plugins.*`, `secrets.*`). Values are never coerced across their declared type.
Secret material is only ever written as a reference — `config set-ref
gateway.auth.token env <NAME>` — so no proposal, transcript, or audit record can
carry the secret itself.

## Restart durability

`CrestodianRuntime` owns the durable ring-zero settings and writes them
atomically before they take effect, so a failed write can never leave a running
gateway enforcing a policy that is not on disk. Settings loaded from disk are
re-validated rather than trusted, and a hand-edited file fails closed instead of
silently reverting to defaults. A pending approval lives only in memory, so a
restart always drops it and an approval that arrives afterwards has nothing to
apply. Applied configuration mutations record the SHA-256 configuration digest
on both sides of the write into the durable JSON Lines audit trail.
