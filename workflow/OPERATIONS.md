# Request router

Read one runbook, then the exact record it names. Commands below are relative
to the repository root: `python3 workflow/tools/workflow.py …`.

| Request | Route | First read/command |
|---|---|---|
| Fix/resume/review an M-issue | `operations/FIX.md` | `brief <id> --agent <id>` |
| Investigate a finding | `operations/INTAKE.md` | `new-intake` when investigation is authorized |
| File/update/defer an issue | `operations/ISSUE.md` | target entry and dedup candidates |
| Reconcile main or deployment | `operations/SYNC.md` | `sync-main --check` or `release-sync --check` |
| Test Phorvex/the dev cluster, or run a broad live experiment | `operations/CAMPAIGN.md` | `attacks preflight`, then `new-campaign` and a selected test plan |
| Inspect state/provenance | `operations/AUDIT.md` | `doctor`, then bounded `brief` |
| Unclear request | `operations/TRIAGE.md` | `guide triage` |
| Improve this harness | `tools/`, `stages/`, relevant tests | inspect and test; no product-fix cycle required |

## Authority

- Issue: `issues/entries/<id>.md`; register is generated.
- Fix: `fixes/<id>/STATUS.yaml`; one revision and next action.
- Pre-issue claim: `intake/<id>/STATUS.yaml`.
- Anatomy: inventories at `anatomy/PIN.yaml`; joins have separate review status.
- Main/deployment: separate pins in `releases/CURRENT.yaml` and sync records.
- Campaign: `campaigns/<id>/STATUS.yaml`.
- Evidence: record-local `evidence/manifest.yaml`; bus/chat only notify.

## Scope and completion

The user's request may authorize multiple stages. Record that scope once and
reuse it; do not invent approvals. A gate is missing authorization or evidence,
not an excuse to stop ordinary authorized work. Unknown requests remain
read-only until classified. Ambiguous duplicate root causes need a ruling.

A code fix completes after independent review, required verification and
release/issue synchronization. An intake completes as duplicate/filed/rejected/
unavailable; a campaign after review and cleanup. Main synchronization ends at
`MAIN_RECORDED`; deployed reconciliation at `RECONCILED` or a recorded blocker.
An audit ends with a sourced answer and no repair. A harness change ends with
relevant checks and an accurate change report; PR/merge follow user scope.
