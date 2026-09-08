# Named issue → reviewed PR

“Start issue X” delegates the PR path under `AUTONOMY.md`; merge and shared-cluster
changes are separate. Explicit narrower user scope wins.

Run `doctor`, select/create the fix, assign two independent participants, then
`brief <fix> --agent <id>`. Reuse peers or spawn a reviewer with baseline-only context.
Keep the fix record in the code branch's own `workflow/fixes/<id>` (`WORKTREES.md`).
Check push/PR access early. New fixes inherit PR scope; coordinator uses `start <fix>
--by <id> --expect-revision N` for an existing authorized fix. Holds aren't silently resumed.

Follow the indicated stage. Agents settle conservative design/security choices with
evidence, without routine human signoffs. Keep only current findings; `03-decision`
becomes the single implementation contract. Implementers record their own source pins.

After offline checks and independent incident/P3 pass, push/open the PR, record its
URL/reviewed head, reach IN_PR and return the link. Don't stop at PR_READY or ask again.
Required post-deployment L3/L4 remain pending and visible; PR delivery is not closure.
