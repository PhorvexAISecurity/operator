# Agent bootstrap

This directory is the authoritative operating system for the Phorvex fix
program. Chat history and bus archives are not authoritative.

## When asked to “start fix X”

1. Read `MANIFEST.yaml` and `WORKFLOW.md`.
2. Run:

   ```bash
   python3 workflow/tools/workflow.py doctor
   python3 workflow/tools/workflow.py brief X
   ```

3. Resolve X through `fixes/INDEX.yaml`. Read, in this order:
   - `issues/entries/<issue>.md`;
   - the issue's entry in `issues/joins.yaml`;
   - only the relevant locus in `anatomy/ANATOMY.md`;
   - `fixes/<fix-id>/STATUS.yaml`, if the cycle already exists.
4. Confirm the assigned role and the single `next_action` in `STATUS.yaml`.
   Never infer either from agent names, folder names, prior tickets, or chat.
5. Confirm the code base SHA, deployed SHA, dependencies, stacked branches,
   worktree cleanliness, and required capabilities before doing work.
6. Perform only the current transition. Update the fix artifact and required
   status fields, then use `python3 workflow/tools/workflow.py transition`
   (or `sync-index` when recording no state change). Send a handoff that
   references those files.

## Blind-review rule

For a new cycle, if your role is `skeptic` and
`blind_derivation.status: pending`, do
not open:

- `01-proposal.md`;
- `04-diff.patch`;
- the implementation branch or its commits;
- proposal/diff bus messages.

Write `02A-blind-derivation.md` from the intake, issue entry, anatomy, pinned
baseline, and source code. Seal it with:

```bash
python3 workflow/tools/workflow.py seal <fix-id>
```

Only after the seal succeeds may you read the proposal and write
`02B-critique.md`.

Migrated cycles may say `legacy-complete` and point to a combined
`02-critique.md`. Do not rerun their blind stage or invent missing seal
metadata; follow their structured state and P3 artifact. `not-started` means
the held legacy cycle never entered design.

## Roles

- `human_owner`: scope, priority, deadlock, merge, deployment, destructive
  testing, prediction amendments, and waivers.
- `proposer`: root-cause model, proposal, declared behavioral delta.
- `implementer`: code, tests, RED/GREEN evidence; defaults to proposer.
- `skeptic`: blind derivation, adversarial design review, independent diff
  review, final verdict.
- `live_verifier`: scoped post-deploy verification; defaults to skeptic and
  must have cluster access.
- `coordinator`: state transitions, issue/register synchronization, release
  synchronization.

One person or agent may fill multiple compatible roles. The implementation's
author may not sign its independent diff review or final verdict.

## Human gates

Stop and ask the human owner before:

- opening or merging a pull request unless explicitly authorized;
- deploying or rolling back a shared environment;
- running a mutating, destructive, fault-injection, or attack test;
- weakening or amending a pre-registered prediction;
- resolving a three-round deadlock;
- waiving a required verification level;
- closing an accepted-risk or design-call item.

## Evidence rules

- Every code claim names a source SHA.
- Every live claim names image tag, digest when available, embedded `gitSHA`,
  observation window, and ambient conditions.
- A null result requires a positive control.
- RED must fail at the assertion named by the invariant, not at compile time
  or an unrelated setup error.
- Raw artifacts are listed in `evidence/manifest.yaml` with hashes.
- `Selected`, `Dispatched`, `Emitted`, `Executed`, `Confirmed`, and
  `Attack-mitigated` are distinct stages.

## Reading limits

Do not scan `archive/`, `artifacts/`, raw campaign corpora, or bus history
unless a current artifact explicitly points there. A fresh fix should be
recoverable from this file, the target issue/anatomy locus, and its status.

## Code-repository hygiene

- Use an isolated worktree for implementation and review.
- Do not disturb unrelated dirty changes.
- Production commits and PR text contain no agent attribution.
- Workflow artifacts belong under `workflow/`; production code
  commits contain only ticket-relevant code and tests.
