# PR150 conflict resolution, round 2

Scope is the signed LEAD_PLAN.md in this directory: update the existing PR branch,
not merge the GitHub PR or deploy. This record supersedes neither round-1 evidence
nor historical product reviews. Independent review belongs to the lead.

Exact merge parents:

- PR150: `ccc0efe062e4eb1bad669a5c0d66105604b56e6e` (includes PR167/M048).
- Main: `f0348b36e12d751a84ffdac1414c6ff6952d2ee1` (audit-volume guard and console history).

## Resolution

Only the vendored binary chart and generated workflow/fixes/INDEX.yaml conflicted.
No production source conflict required a manual edit.

- Regenerated `deploy/helm/phorvex-stack/charts/phorvex-0.1.4.tgz` from combined
  source with Helm 3.16.4 `helm package phorvex/charts/phorvex --destination deploy/helm/phorvex-stack/charts`.
- Regenerated the fix index using workflow.py's `synchronized_index` over the union
  of both parents' indexed records, reading the merged authoritative STATUS.yaml
  files. Both M-048 and AUDIT-VOLUME-GUARD are retained; sync-index --check passes.
- Inspected auto-merged dashboard-web/lib/api.ts and console/server.go against both
  parents. Main's history route, LiveHistoryPage, abort signal, and clear-context
  parameter coexist with PR150's evidence-based dispatched/isolationAttempts
  rollups. Existing owner projections and history implementation are untouched.
- Retain PR150 owner/emission behavior and M048 quarantine policy incarnation/RBAC.
  Retain main audit guard, default-disabled generic chart behavior, EKS system
  node selector/toleration and operator/console images 0.4.107.

## Verification

Go 1.26.1 at `/private/tmp/phorvex-go-toolchain.3MV9Wy/go/bin/go`;
GOTOOLCHAIN=local, GOPATH=/private/tmp/phorvex-review-go,
GOCACHE=/private/tmp/phorvex-review-go-cache, GOMAXPROCS=2,
KUBECONFIG=/dev/null, KUBEBUILDER_ASSETS='', USE_EXISTING_CLUSTER=false,
HELM_BIN=/opt/homebrew/bin/helm. Focused native arm64 test execution, from phorvex/:

```text
go test -mod=readonly -p 2 -count=1 ./internal/runner ./internal/actuator ./internal/console ./internal/audit ./internal/decision ./internal/recon ./internal/auditguard
runner PASS 0.925s
actuator PASS 0.748s
console PASS 8.172s
audit PASS 2.850s
decision PASS 7.923s
recon PASS 0.402s
auditguard PASS 2.526s
```

The test command had localhost permission for httptest; it had no live kubeconfig.
Auditguard tests evaluate CEL from actual chart renders, including scope/control
arms and the vendored EKS Deployment. Full Go suite was not run in this round.
API-server tests remain skipped without assets: TestM005TwoManagersAndHandoff,
TestM013RealEventSink, TestM007RestrictedRequests, TestM47APIServerPreconditions,
TestM038APIServerConditionalDetach. No live admission claim follows from local CEL.

From repository root with Python 3.11 `/private/tmp/phorvex-pr144-venv/bin/python`:

- `bash tools/check-vendored-chart.sh`: PASS extracted-source parity.
- Generated/config CRD versus chart CRD `diff -u`: PASS.
- `python tools/test_chart_sync.py`: 8 PASS.
- `python tools/test_e2e_detector_chart.py`: 3 PASS.
- `python workflow/tools/workflow.py sync-index --check`: PASS.
- `python workflow/tools/workflow.py doctor`: 0 errors, 17 historical evidence,
  anatomy and release-synchronization warnings, retained without fabricated fixes.
- Staged source-delta whitespace check: PASS. No unresolved index entries.

Actual EKS render command:

```text
helm template phorvex deploy/helm/phorvex-stack -n phorvex-system --kube-version 1.30.0 -f deploy/helm/phorvex-stack/values.yaml -f deploy/helm/phorvex-stack/values-eks.yaml --include-crds
```

Parsed assertions PASS: exactly one audit guard policy/binding, system node selector,
CriticalAddonsOnly=true NoSchedule toleration, manager and console images 0.4.107.
Default actuatorNamespaces is empty, hence no routine actuator Role; an additional
render with `--set phorvex.phorvex.actuatorNamespaces[0]=test-tenant` proves the
namespaced quarantine Role retains NetworkPolicy create/get/list/delete/update.
The initial ad hoc assertion wrongly expected a Role before opt-in; corrected
both-arm assertions passed. No chart/source change was needed.

Frontend TypeScript 5.6.2 `tsc --noEmit` PASS over this worktree's complete TS/TSX
source, using existing matching dependencies from the original workspace and
temporary `/private/tmp/phorvex-pr150-round2-tsconfig.json`. That config extends
the tracked config, disables incremental writes and maps dependency/type paths
to `/Users/hami/Downloads/Phorvex/dashboard-web/node_modules`. Explicit react and
react-dom declaration mappings were necessary; an initial generic module mapping
failed dependency resolution, not a source assertion. No dependencies installed,
tracked tsconfig changed or Next.js production build claimed.

Historical evidence preservation checked with git ls-tree + git hash-object:
all 72 M-048 blobs match ccc0efe; all 60 AUDIT-VOLUME-GUARD and 60
CONSOLE-LIVE-HISTORY blobs match f0348b36 byte-for-byte.

No branch push, PR state/base change, GitHub merge, cluster mutation, live E2E,
remote CI result or renewed P3/L3 sign-off is claimed by this implementation record.
