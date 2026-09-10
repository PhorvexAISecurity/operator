# PHORVEXSEC-211 — direct execution default approved and implemented

Date: 2026-09-09. Update to PR136.

Mostafa approved enabling leader election by default for direct execution in Telegram group message 1100801 at 05:48:24 UTC, replying to Milad's question 1100800. His reason: default safety should not depend on the installation method. This resolves the previously pending default decision.

`phorvex/cmd/main.go` now registers `--leader-elect` with default `true` instead of `false`. The flag still feeds the existing controller-runtime manager's `LeaderElection` option. Helm already enabled it. Explicit `--leader-elect=false` remains supported for isolated single-instance use. No election timing, lock identity, mathematical behavior, or CI configuration changed.

Validation on this update:

- Actual compiled command help reports `(default true)` for `--leader-elect` (default-help.txt).
- Runner leader-election requirement and Helm default regression tests pass (default-regressions.txt). The first run skips the API test when assets are absent.
- Separately reran TestM005TwoManagersAndHandoff with Kubernetes 1.33.0 envtest assets. It passes using isolated API/etcd, including the disabled-election positive control and enabled-leader handoff (default-election-envtest.txt).
- `git diff --check` passes.

The pre-existing migration runbook still applies: drain old election-disabled writers, grant namespaced Lease access, then start the enabled cohort. Direct execution requires the existing namespace resolution and Kubernetes permissions to work. This change does not add a namespace override or prove live operational failover, fencing, or restricted-service-account correctness. Independent review and the remaining operational checks remain open. No merge or deployment was performed.

The final commit and PR link are recorded in the Plane delivery receipt.
