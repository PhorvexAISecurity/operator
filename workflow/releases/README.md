# Release synchronization

`CURRENT.yaml` is the single workflow record of code-main, deployed image,
embedded source SHA and anatomy currency. It is evidence-backed, not inferred
from a Helm values file or a tag name.

Use `operations/SYNC.md`. `sync-main --check` reports colleague/main drift
without changing records; reviewed `sync-main --publish` creates an immutable
`MAIN-*` reconciliation and updates only source-main facts.

For each observed deployment, `release-sync --publish` creates:

```text
releases/<DEPLOY-sync-id>/
  STATUS.yaml
  RELEASE_SYNC.md
  anatomy-diff.md
  fixes.yaml
  verifier-results.yaml
```

The deployment transaction is:

1. observe the actual running image, digest and embedded `gitSHA`;
2. publish the deployment observation and create its `DEPLOY-*` record;
3. refresh/validate anatomy against that exact source;
4. run each included fix's scoped L3/L4;
5. finalize issue and fix records as closed/reopened/blocked;
6. regenerate the master register and joins;
7. run permanent offline verifiers;
8. publish any new golden baseline after verdicts.

`release-sync --finalize --record <DEPLOY-id>` requires a PASS, FAIL, or
explicit BLOCKED result for every included issue and refuses finalization
until canonical Anatomy matches the observed deployed source. A terminal
reconciliation record is not edited again.

Several fixes may share one transaction. Each keeps independent criteria,
evidence and verdict.
