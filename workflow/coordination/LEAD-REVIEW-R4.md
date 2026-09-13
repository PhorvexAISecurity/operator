# Runner pre-publication review R4

Lead: codex-lead. Reviewed source 62df1bbb06b1367c0f2ed18b4dd400ba02eef57c.
Resume the assigned runner session. Opus 5, high reasoning, per the latest user
instruction. Never add co-author/assistant attribution to commits.

1. Repair test cleanup process ownership. A direct unittest invocation as its
   process-group leader was killed by cleanup using a test record of its own
   PID. A waiting parent driver allowed all 90 runner tests to pass. Track only
   children actually created by the fixture, verify process identity and never
   kill the test runner/group from an arbitrary simulated runtime record.
   Verify both ordinary child invocation and session/group-leader invocation
   through bounded subprocess tests with an outside observer.
2. Complete typed final metadata validation. The real summarize probes in
   lead-runner-r4-probes.json show num_turns=true accepted as an integer and a
   permission_denials string element converted to an anonymous denial without
   a shape problem. Preserve occurrence provenance while reporting malformed
   metadata explicitly. Positive clean result remains accepted.
   Correction to earlier informal concern: list/dict subtype values ALREADY
   produce problems without throwing at this source. Keep that property; do
   not claim an unhashable-subtype crash was reproduced.
3. Actual quota failures contain synthetic error output. Preserve those records
   and quota failure as failure; distinguish an explicitly synthetic error
   sentinel from a substituted real assistant model. Continue to flag any real
   model mismatch and retain auxiliary modelUsage separately. Use a sanitized
   fixture drawn from the actual private quota streams, with real-mismatch and
   error-only controls; do not broaden acceptance to unknown model strings.
4. Latest campaign default is claude-opus-5/high. Change DEFAULT_EFFORT and
   current usage examples accordingly, retaining supported explicit max and
   historical max receipts. Every launch/resume argv must retain exact session,
   model, effort and bounded tool settings. No billing fallback.

Implement only this workflow runner scope. No raw runtime state edits, service
restart, push, merge, deployment, new agents or product changes. The lead owns
runtime adoption. Preserve existing uncommitted lead acceptance/review artifacts.
Run relevant tests under pinned Python 3.11, then required workflow checks;
submit source commits and evidence for independent review, not self-approval.
