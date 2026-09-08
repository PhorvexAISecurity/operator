# First M6 PR CI result

PR: https://github.com/PhorvexSecurity/operator/pull/143
Reviewed head: 9eb14271625620aef6b6184386764e29f0d71ea3
Run: https://github.com/PhorvexSecurity/operator/actions/runs/34285273595

- chart-sync FAIL: vendored subchart differs from phorvex/charts/phorvex. CI requests
  `helm dependency update deploy/helm/phorvex-stack` and committing the vendored chart.
  Implementer owns this packaging correction and renewed source/evidence pins.
- e2e FAIL in preflight: console readiness deadline (60s); Kubernetes reports no
  endpoints for service phorvex-console. This did not reach M6 behavior testing.
  Report publication then fails because runs/run-*.json does not exist; summary.py
  attempts to read a directory, and the comment body is missing. These follow the
  preflight failure and do not establish a Phorvex defense result.
- changes and e2e-contract PASS; build/deploy jobs skipped in this run.

No shared service repair/deploy or risk waiver performed. Existing independent
incident/P3 signatures describe their exact reviewed head; any packaging commit
requires renewed review of affected pins before merge. PR opening is complete,
but CI is not green. Do not claim merge readiness or live verification.
