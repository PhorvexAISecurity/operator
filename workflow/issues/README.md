# Master issues

Issue source lives in `entries/`, one file per M-number. The consolidated
`MASTER_ISSUES.md` is generated for humans and must not be edited directly.
Each rendered issue gets a generated `WORKFLOW` line from its front matter;
the preserved legacy heading may still describe how the issue was originally
observed (`LIVE`, `STATIC`, and so on).

Each entry preserves the issue narrative and adds machine-readable front
matter for:

- ID, title, severity and evidence status;
- workflow state;
- tier and anatomy tag;
- dependencies and blockers;
- fix IDs, PRs, merge/deployed pins and verdict links;
- last source/live verification.

`migration_body_sha256` permanently proves the imported legacy body.
`source_body_sha256` tracks the current body and is advanced only by the
explicit `rehash-issue` command after review.

`joins.yaml` stores the Anatomy V2 locus/touches projection separately from
the issue body. Curated overrides carry a reason and provenance; they do not
live as hard-coded Python dictionaries.

## Routine update

1. Edit only the target entry.
2. If its prose/body changed, explicitly accept the new body hash:
   `python3 workflow/tools/workflow.py rehash-issue M-NNN`.
3. Validate schema and state transition.
4. Regenerate `MASTER_ISSUES.md`.
5. Assert:
   - no issue disappeared or duplicated;
   - body hashes changed only for declared entries;
   - all generated counts match parsed data;
   - anatomy joins satisfy expectations;
   - the rendered document is reproducible.

Run:

```bash
python3 workflow/tools/workflow.py render-issues
python3 workflow/tools/workflow.py render-issues --check
python3 workflow/tools/workflow.py doctor
```

## Retirement of old register files

The original base register and V2 snapshot are retained under
`archive/register-v1/` as migration inputs. They are read-only. The old tier
rebuild script is intentionally not part of the new toolchain because it
reconstructed current state from a stale backup.

## State changes

- Issue state and fix-cycle state are deliberately different. An issue stays
  `OPEN` while its fix is `DESIGNING` through `IN_PR`; the generated
  `WORKFLOW` line lists linked fixes, and `workflow.py brief M-NNN` shows both.
- PR merged: `MAIN_PENDING_DEPLOY`
- deployed: `DEPLOYED_PENDING_L3`
- scoped verification passed: `CLOSED`
- scoped verification failed: `REOPENED` or a distinct regression issue
- accepted risk/design decision: explicit human approval in the entry

The register may be regenerated at any state; only `CLOSED` requires a final
fix verdict and release synchronization.
