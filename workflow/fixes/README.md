# Fix records

`INDEX.yaml` is a schema-version-2 discovery marker. The workflow derives the
complete, sorted fix index at read time from each `*/STATUS.yaml`; it does not
rewrite the marker when a fix changes. Historical aliases live beside their
record in `ALIASES.yaml`. Always resolve work through `load_fix_index()` or the
workflow commands; historical directory names are intentionally preserved.
The marker's `required_alias_metadata` list protects only the ten aliases
migrated from the former projection, so deleting one cannot silently drop a
legacy lookup. New aliases are discovered from their record-local file.

`STATUS.yaml` is authoritative for mutable state. `sync-index` validates the
discovered fix projection, aliases, issue links, and the separately generated
intake and campaign indexes. Schema-version-1 fixture indexes remain writable
for compatibility; repository schema-version-2 fix indexes are read-only.

New fixes use `_template/` and the canonical `T<tier>-M<zero-padded-id>`
form for a single M-issue. Enablers or multi-issue program items receive a
stable human-approved fix ID recorded in their intake.

## Create or resume

```bash
python3 workflow/tools/workflow.py new-fix T1-M123 --issue M-123
python3 workflow/tools/workflow.py brief T1-M160
```

The command refuses duplicate issue ownership unless the new cycle declares
itself a follow-up with `--follow-up-to <fix-id>`.

## Historical records

The migrated directories retain their original content. Missing historical
steps are marked in `STATUS.yaml`; they are not fabricated. In particular,
the recent M-020/M-023/M-160 root `06-verdict.md` files were P3/PR-ready
verdicts rather than final live closure. The workflow copy relocates those
three files byte-for-byte to `evidence/p3/verdict.md`; the original local fix
trees remain unchanged. Future `06-verdict.md` files are final results only.

## Branch and worktree rules

- Never implement through the shared dirty checkout.
- Record base and head SHA.
- Declare `stacked_on` and merge order.
- After a dependency merge, prove patch equivalence or rerun verification.
- Workflow files are committed only on workflow/documentation changes;
  production fix commits contain only ticket-relevant source and tests.
