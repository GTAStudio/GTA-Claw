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
fails closed for sandboxed, non-owner, or disallowed group contexts. Read-only
status runs directly; gateway restart requires an unexpired approval from the
same message identity and mandatory metadata-only audit persistence.
