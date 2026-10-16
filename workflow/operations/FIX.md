# Named issue → reviewed PR → live verification

“Start issue X” delegates PR delivery under `AUTONOMY.md`. Merge and shared-cluster
changes use their separately recorded scope.

Run `doctor`, select/create the fix and reuse the assigned peers. New fixes use
`fix_loop: lead_worker` roles from `AGENTS.md`. Keep code/records in the issue
worktree (`WORKTREES.md`). Read `brief <fix> --agent <id>`.

The lead investigates, using authorized live observations when useful, and signs
one plan in `03-decision.md`. Transition DESIGNING → AGREED and instruct the worker
to implement. Older blind peer records retain their gates unless migrated.

The worker implements/tests and runs `preflight` and `submit-review`. The lead
uses `review-delta` / `review-verdict` to return defects until accepted. See
`HANDOFFS.md`. After offline and independent incident/P3 pass, deliver the PR.

After merge/deployment the lead verifies the running source/digest, fix behavior
and controls. Keep L3/L4 pending until evidence passes; reopen on failure.
PR delivery is not closure. Continue authorized work until delivery or a concrete blocker.
