diff --git a/.github/trusted/desktop-supply-chain-policy/README.md b/.github/trusted/desktop-supply-chain-policy/README.md
index c303649..f5219a4 100644
--- a/.github/trusted/desktop-supply-chain-policy/README.md
+++ b/.github/trusted/desktop-supply-chain-policy/README.md
@@ -193,12 +193,44 @@ cargo +1.94.0 clippy --manifest-path .github/trusted/desktop-supply-chain-policy
 cargo +1.94.0 test --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked --all-targets
 ```
 
-During an audited Bootstrap trust-root update, regenerate the binary snapshot only
-through the validator and then copy its printed fingerprint into the reviewed constant:
+The Bootstrap snapshot is a historical anchor/composite, not a mirror of current Final policy.
+The writer is all-or-nothing over all 28 Bootstrap inputs. Every successful invocation compares
+the existing archive with the generated canonical archive and prints this deterministic contract
+before the result is accepted:
 
 ```text
-cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- write-bootstrap-snapshot --root "$PWD" --output "$PWD/.github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"
-cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- bootstrap-fingerprint --root "$PWD"
+bootstrap_snapshot_delta changed_count=1 preserved_count=27
+changed_path=".github/workflows/upstream-gateway-reference.yml" status=modified
+```
+
+Changed paths are sorted. First writes report all 28 paths as `added`, with
+`changed_count=28 preserved_count=0`. Inventory differences use `added` and `removed`; payload
+differences use `modified`. A malformed or noncanonical existing archive fails closed without
+being overwritten.
+
+For an audited, reviewed single-entry Bootstrap update, first materialize the immutable Bootstrap
+root byte-for-byte, replace only the reviewed path, run the canonical all-or-nothing writer against
+that materialization, and inspect its mandatory delta output. Accept the result only when it says
+`changed_count=1 preserved_count=27` and names the exact reviewed path. For example, Git can safely
+materialize and replace tree entries without routing binary bytes through a shell text stream:
+
+```text
+git worktree add --detach "$MATERIALIZED_ROOT" "$IMMUTABLE_BOOTSTRAP_OID"
+git -C "$MATERIALIZED_ROOT" restore --source="$REVIEWED_OID" --worktree -- ".github/workflows/upstream-gateway-reference.yml"
+cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- write-bootstrap-snapshot --root "$MATERIALIZED_ROOT" --output "$PWD/.github/trusted/desktop-supply-chain-policy/policy/bootstrap.snapshot"
+```
+
+Never generate the historical Bootstrap snapshot from live Final merely because that checkout is
+convenient. Binary extraction must remain byte-preserving: do not use PowerShell text redirection
+such as `git show > file`, and avoid `cmd.exe` commands whose commit/path syntax is exposed to caret
+escaping. There is not yet a first-class single-entry update command; the full materialization and
+mandatory delta review above remain required.
+
+After the snapshot delta is accepted, compute the fingerprint from the same materialized Bootstrap
+root and copy it into the reviewed constant:
+
+```text
+cargo +1.94.0 run --manifest-path .github/trusted/desktop-supply-chain-policy/Cargo.toml --locked -- bootstrap-fingerprint --root "$MATERIALIZED_ROOT"
 ```
 
 During an audited Final dependency-surface update, copy the reviewed live root deny
