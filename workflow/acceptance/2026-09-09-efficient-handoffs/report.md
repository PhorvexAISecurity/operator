# Efficient handoffs validation

Request: implement earlier baseline reproduction, CI-matched preflight, batched
role-owned evidence/transitions, single baseline evidence ownership, and scoped
review/reuse of unchanged inputs. User explicitly emphasized the last three.

Implemented commands: preflight, submit-review, review-verdict, review-delta,
handoff-notify. Existing individual commands and historical records remain valid.
New fixes require a current passing preflight before offline acceptance. Existing
fixes retain their recorded contract; no historical evidence or M6 signature was
retroactively upgraded or waived.

Validation on Python 3.11.16:
- `PATH=/tmp/phorvex-workflow-ci-311/bin:$PATH bash workflow/tools/check.sh`: PASS,
  94 tests, reproducible index/register, doctor 0 errors / 13 pre-existing warnings.
- New preflight command exercised end to end against this workflow worktree with
  the Python 3.11 environment: diff/workflow checks PASS. Its final full check was
  rerun after the last implementation changes; retained output is check.txt.
- Regression cases cover one-revision handoffs, early reviewer-owned RED, role
  separation, retaining current evidence/authorized waivers without re-signing, stale revisions, missing preflight, rollback of partially signed
  batches and later failed scope approvals, missing incident proof, explicit
  reuse approval, changed dependencies, dirty code, modified raw output, blind
  review protection, notification failures/retry/deduplication, CI tool-version
  mismatch, failed local commands, unknown CI steps, and template-vs-record inputs.
- Startup instructions remain within the existing 1,250-word common+stage limit.

Quality boundaries retained: independent incident/P3 signoff, no P3 reuse, no
implicit scope approval, no baseline mutation control mislabeled as execution,
no automatic shared E2E/deployment or evidence waiver. Notifications occur only
following a committed handoff; a failed transport retry does not re-sign evidence.
Git-tracked dependency hashes establish sameness only for the explicitly reviewed
input scope, so reviewers must include code, tests, config and dependency inputs.

Preflight executes selected local checks only; remote CI and shared environments
remain separate. The local CI adapter fails on missing/mismatched tools or new
unsupported setup rather than silently skipping those obligations.
