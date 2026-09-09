# Implement and verify: AGREED → PR_READY

The implementer owns code and its tests; the skeptic owns independent incident/P3
review. Both use the frozen acceptance matrix in `03-decision.md`. A missing proof
is not a passing check. The reviewer never silently fixes the patch under review.

1. Continue the baseline reproduction prepared during investigation. Either its
   implementer or the independent reviewer may sign `red`; one valid baseline
   signature is enough. Do not send evidence back merely to change its signer.
   Keep the same real producers, decisive assertions and legitimate controls at head.
2. Implement at the reviewed base. Commit code, record source pins, and run
   `preflight <fix> --run`. It selects local CI checks with matching tool versions;
   shared E2E/deployment are explicitly separate. Missing tools or failed/stale
   checks block submission. Run the acceptance matrix's L0–L2 tests too: preflight
   does not invent issue-specific coverage. Retain exact commands and raw outputs.
3. `submit-review <fix> --file submit.yaml --by <implementer> --expect-revision N`
   records the author's checks, generates the exact pinned diff, validates the
   offline gates, advances state and notifies the assigned reviewer in one transaction.
   The package may include source pins. See `operations/HANDOFFS.md` for its small schema.
4. Reviewer: run `review-delta <fix> --agent <reviewer>`, inspect the complete changed
   paths, reproduce the incident, and challenge defaults, missing/stale inputs and
   relevant predicate arms. A mocked final boolean is not producer evidence. Sign
   `review-verdict <fix> --result PASS|FAIL --file review.yaml --by <reviewer>
   --expect-revision N`. PASS requires independent incident evidence; FAIL returns
   concrete counterexamples to the implementer. PASS advances to PR_READY and hands
   PR delivery to the coordinator. An existing PR stays open while its new head is reviewed.
5. Reuse a previous passing check only when its COMPLETE dependency paths were
   declared and independently approved. Reuse validates unchanged Git tree entries,
   raw evidence and the retained scope approval; it records the original run source
   instead of claiming another run. Changed inputs require affected checks again.
   Incident/P3 still need current independent signoff; P3 is never reused. Packaging
   changes always need their own archive/render checks even when Go code is unchanged.

A failed batch rolls back its status, attestations and transitions. Notification
happens after commit; if transport fails, use `handoff-notify`, not another submission.
`record-check` and explicit transitions remain available for individual work and
historical records. New fixes require local preflight before offline acceptance.

After PR_READY, push/open under recorded scope and return the link. Required live
verification remains explicit; opening a PR does not establish deployed behavior.
