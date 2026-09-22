# Development verification configurations

These examples support the remaining math verification controls. They do not
change the installed configuration or enable tests when merged. Use a checkout
of the reviewed repository revision and the current Argo values as the baseline.

- [Loss history and scoped outcomes (M100/M106)](math-observers/README.md):
  dedicated storage, authenticated observer configurations, current fixture pins,
  cluster-based private Secret transfer, phase ordering and rollback.
- [Vulnerability-feed consumption and expiry (M104)](m104-voice-canary/README.md):
  a scoped, suspended canary template. Wait for Codex to confirm the policy
  dry-run barrier and fresh registry Secret before deploying it.

Coordinate the temporary configuration rollout with Codex so it can capture the
before/after evidence and execute the controls within their validity windows.
DevOps owns shared deployment and restoration; Codex owns the bounded trials,
interpretation and exact fixture cleanup. M106 transfer pins expire at
2026-09-23T18:00:00Z and require fresh validation before use.

The guardrail console retest separately requires both manager and console images
containing [PR312](https://github.com/PhorvexSecurity/operator/pull/312), merge
commit `99a3b7717094f478b13c8ea7b0bcfbe266b0dc67`. Confirm the image source revisions;
the image version alone is insufficient. The math configurations here do not
depend on that repair. Preserve the shared audit storage and serving journals.
