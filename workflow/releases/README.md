# Release synchronization

`CURRENT.yaml` is the single workflow record of code-main, deployed image,
embedded source SHA and anatomy currency. It is evidence-backed, not inferred
from a Helm values file or a tag name.

For each deployed release create:

```text
releases/<tag>/
  STATUS.yaml
  RELEASE_SYNC.md
  anatomy-diff.md
  fixes.yaml
  verifier-results.yaml
```

The release transaction is:

1. observe the actual running image, digest and embedded `gitSHA`;
2. refresh/validate anatomy against that exact source;
3. run each included fix's scoped L3/L4;
4. update issue entries to closed/reopened;
5. regenerate the master register and joins;
6. run permanent offline verifiers;
7. publish any new golden baseline after verdicts;
8. update `CURRENT.yaml`.

Several fixes may share one transaction. Each keeps independent criteria,
evidence and verdict.
