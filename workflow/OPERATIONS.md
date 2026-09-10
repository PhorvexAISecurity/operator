# Request router

Read the relevant runbook and target record. From repo root: `python3 workflow/tools/workflow.py …`.

| Request | Route | First read/command |
|---|---|---|
| Fix/resume/review an M-issue | `operations/FIX.md` | `brief <id> --agent <id>` |
| Investigate a finding | `operations/INTAKE.md` | `new-intake` when investigation is authorized |
| File/update/defer an issue | `operations/ISSUE.md` | target entry and dedup candidates |
| Reconcile main or deployment | `operations/SYNC.md` | `sync-main --check` or `release-sync --check` |
| Run cluster tests or live experiments | `operations/CAMPAIGN.md` | `attacks preflight`, `new-campaign`, selected test plan |
| Regenerate master issues / system assessment | `operations/ASSESSMENT.md` | `guide assessment --show` |
| Assess and resolve issues in parallel tiers | `operations/TIERS.md` | pin source/deployment; assess coverage |
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

Record user scope once and reuse it across authorized stages. Gates require evidence
or authorization, not routine permission checks. Classify unknown requests read-only;
ambiguous duplicate root causes need a ruling.

A named-fix request defaults to reviewed PR delivery (`IN_PR`); issue closure
still requires verification and release synchronization. Intake completes as duplicate/filed/rejected/
unavailable; a campaign after review and cleanup. Main synchronization ends at
`MAIN_RECORDED`; deployed reconciliation at `RECONCILED` or a recorded blocker.
An audit ends with a sourced answer and no repair. A harness change ends with
relevant checks and an accurate change report; PR/merge follow user scope.
