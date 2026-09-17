# Agent entrypoint

User scope controls. Named fixes follow reviewed PR delivery under
`operations/AUTONOMY.md`. The local-only override is
`assessments/20260916-local-continuation/AUTHORIZATION.md`: open no new PRs,
continue unblocked source tiers and retain live acceptance debt.

1. Classify with `OPERATIONS.md`; read one runbook. Run `doctor` once; historical
   warnings do not block authorized work.
2. Run `brief <fix> --agent <assigned-id>`; coordinator assigns roles. Read its
   stage, issue, source and artifacts. Don't preload the register, anatomy,
   archives or raw history. `MANIFEST.yaml` locates authorities.
3. Complete owned work; use `submit-review` / `review-verdict` for evidence and
   state handoffs (`operations/HANDOFFS.md`). Continue the peer loop
   until PR delivery or a concrete external blocker; no human relay is needed.

## Quality boundaries

- New fixes use `fix_loop: lead_worker`: lead signs `03-decision.md`, reviews,
  delivers and live-verifies; worker implements. Lead owns proposer, skeptic,
  coordinator and live_verifier; worker owns implementer.
- Authors cannot review or live-verify their code. Older absent `fix_loop`/`blind_peer`
  records retain blind design gates; never invent seals.
- `record-check` and handoffs bind signer, artifact hash and source. Missing evidence
  stays missing. Selection, dispatch, execution, confirmation and mitigation differ.
- Before P3, independently reproduce the incident through real producers, assert
  fixture relevance, test relevant predicate arms/defaults/stale inputs, and include
  a positive control. A mocked final flag is insufficient.
- Use revision-checked commands. Implementers may configure only source pins.
  Changed sources/artifacts invalidate affected checks. Preserve superseded evidence.
- Autonomous scope grants no weaker guarantee or evidence waiver. Merge, shared
  deployment, live mutation and risk acceptance require separately recorded scope;
  reuse existing authorization. Branch push and PR opening are already included.

## Handoff

Keep code and fix records in the same issue worktree; preserve unrelated edits.
Bus runtime is shared through Git common directory. Follow each message’s
`workflow_root`; see `operations/WORKTREES.md`.
Generated register/anatomy views are read-only. History is not current deployment proof.

Never add assistant attribution or `Co-authored-by` trailers to commits.

Send fix · state/revision · next owner/action · references · pins · blockers.
Follow `coordination/BUS.md`: drain/ack mail with a tested adapter or `bus.py wait`.
Messages change no state. Legacy unsealed skeptics cannot read proposals.
Communication stays within authorized collaboration.
