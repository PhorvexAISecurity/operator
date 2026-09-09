# Named issue → reviewed PR

“Start issue X” delegates PR delivery under `AUTONOMY.md`; narrower user scope wins.
Merge and shared-cluster changes remain separate.

Run `doctor`, select/create the fix, assign two independent participants, then
`brief <fix> --agent <id>`. Reuse peers; if none is available, spawn an independent
reviewer with baseline-only context. Keep code and records in the issue
worktree (`WORKTREES.md`). Check push/PR access early. New fixes inherit PR scope;
use `start` for an existing authorized fix. Holds aren't silently resumed.

Follow the indicated stage. Freeze one implementation contract in `03-decision`.
After the blind seal, start the baseline reproduction alongside implementation
preparation. Use `preflight`, `submit-review`, `review-delta` and `review-verdict`;
read `HANDOFFS.md` for package schemas and reuse rules when needed.

After offline checks and independent incident/P3 pass, push/open the PR, record
URL/reviewed head and return the link. Continue until delivery or a concrete blocker.
Required post-deployment L3/L4 remain pending; opening a PR is not closure.
