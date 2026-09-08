# Release: PR_READY → CLOSED

The coordinator records external state; the live verifier observes behavior;
the skeptic signs the final verdict. Approval to implement is not deployment
approval, but an existing explicit authorization need not be requested again.

1. At PR_READY, push the reviewed issue branch and open/update the PR using its
   recorded `pr_open` scope. Record URL, reviewed head and check results, transition
   to IN_PR, and return the link. This completes default delivery; it does not
   close the issue or claim post-deployment L3/L4. After separately authorized merge,
   record merge SHA; `sync-main --publish` updates source truth and issue state.
2. Observe running image, digest, embedded source SHA and rollout time in the
   approved environment. `release-sync --publish` records deployment, then
   publish anatomy at that exact source using its audit suite.
3. Execute scoped L3/L4 against agreed criteria. Retain window, population,
   ambient conditions, positive control, abort/cleanup ledger and raw artifacts.
   Sign `l3`/`l4` with `record-check`; NOT_REQUIRED needs a human rationale.
   A failure reopens/invalidates the claim; a blocked run remains blocked.
   Recreate the incident's decisive conditions, not just a quiet environment.
   For suppression/cadence fixes, require the named veto plus a control proving
   the action can otherwise execute. Disabled policy, denied RBAC, missing
   capability, no selection or absent observation cannot prove suppression.
   Require observed opportunities and recovery/re-emission across the planned
   window; zero actions alone is NON_DISCRIMINATING.
4. Skeptic reviews accepted behavior, source/deployment identity, controls,
   residuals and permanent regression tests; write `06-verdict.md` and sign
   `final`. Its PASS/CLOSED verdict is conditional on successful synchronization.
5. `release-sync --finalize` validates the same contracts as transitions, runs
   offline `verify.sh`, synchronizes issue/register/anatomy records, and closes.
   `synchronization` references use `PASS:<workflow-relative-artifact>`.

The required live layers belong to the fix even when several fixes share a
release. An optional future campaign cannot stand in for missing L3/L4.
A failing release's anatomy still follows what is deployed; its issues reopen.
Retain the issue branch after its code PR merges, incorporate main without losing
evidence, and continue verification in that branch's own fix directory. Publish
later evidence through a follow-up PR; see `operations/WORKTREES.md`.

Historical cycle records may lack new attestations. Do not invent old runs or
seals. Collect missing current evidence, keep original artifacts and explain
coverage limits. Historical “closed” is not a claim about today's deployment.

For attack-based L3, select cases with `workflow.py attacks plan --fix <id>`.
Read `attacks/README.md` and only those procedures. Retain results with `attacks
record/report`, then sign aggregate L3 through `record-check`. The selected plan
and every required case gate closure; health-only checks do not establish L3.
