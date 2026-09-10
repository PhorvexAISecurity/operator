# Add or update a master issue

Canonical issue source is `issues/entries/*.md`; `MASTER_ISSUES.md` is always
generated.

## Add

1. Search existing entries and joins by symptom, component, invariant, and
   suspected root cause. For a reported finding, complete the intake dedup
   stage first.
2. Synchronize the workflow branch with `origin/main`.
3. Run `new-issue` with title, severity, anatomy tag, kind, and approval
   reference. The tool reserves the next M-number, creates the entry and join
   placeholder, inserts its layout token, and regenerates the register.
4. Replace template prose with the accepted claim and evidence; run
   `rehash-issue`, `render-issues --check`, and `doctor`.
5. Start a fix only when remediation was requested.

## Update

- Edit only the target entry; preserve `migration_body_sha256`.
- Use `rehash-issue` for reviewed body changes.
- Use `issue-transition` only for triage states (`OPEN`, `IN_PROGRESS`,
  `REOPENED`, `DEFERRED`, `ACCEPTED_RISK`, `SUPERSEDED`).
- Merge, observed rollout, and closure are recorded by `sync-main`,
  `release-sync --publish`, and `release-sync --finalize`. Do not hand-set
  `MAIN_PENDING_DEPLOY`, `DEPLOYED_PENDING_L3`, or `CLOSED`.
- `ACCEPTED_RISK`, `SUPERSEDED`, forced edges, and autonomous filing require a
  human approval reference.

M-number allocation is fail-closed. The local lock prevents same-worktree
races; `issues/NEXT_ID` and the entry filename produce an integration conflict
if two branches reserve the same number.
