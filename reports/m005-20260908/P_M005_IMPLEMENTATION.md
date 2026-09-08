# PHORVEXSEC-211 / M-5 — implementation and remaining verification

Baseline: ea5d5cad4990365f55e61eddb3da2c6bfc2009a1 (v0.4.96), controller-runtime v0.21.0, client-go v0.33.0, chart 0.1.4. DEV: Milad. Independent review requested from Hami. DEVOPS verifier assignment and approval remain open.

## Corrected diagnosis and delivered scope

The Helm and umbrella defaults already enable election. The binary defaults false. Per the ticket's explicit product-support decision, this PR does **not** change that binary default. Direct production invocation must explicitly use `--leader-elect=true` until its support/default ruling is settled.

The existing runner implements NeedLeaderElection=true. Pinned controller-runtime pkg/manager/runnable_group.go also classifies ordinary custom runnables into LeaderElection by default. The historical missing-interface diagnosis is therefore not a demonstrated bypass. Corrected the misleading source comment.

Confirmed packaging defect: no Lease grant in the committed installation manifests. Added a separate namespaced Role/RoleBinding for get/create/update on coordination.k8s.io/leases in the release namespace, plus the equivalent phorvex-system raw manifest. These are the operations used by client-go resourcelock.LeaseLock. Create cannot use a resourceNames restriction. No cluster-wide Lease permissions added. Repackaged the umbrella dependency.

Coordinated CONTRACT scope is the two new RBAC manifests and packaged chart. Lock ID remains phorvex.phorvex.ai. Namespace remains controller-runtime's existing in-cluster namespace resolution. Production lease/renew/retry defaults remain unchanged. No early-release option enabled.

## Execution/state inventory

cmd/main.go registers the policy controller, runner through mgr.Add(rmgr), and optional EPSSRefresher through mgr.Add. Runner tick calls maintenance (ResumeWarmSwaps and orphan quarantine cleanup), tenant processing, actuator dispatch and status updates synchronously under its tick context. The tick timeout derives from the manager cancellation context. Framework leadership-loss callback returns an error, main exits. Metrics, probes, caches and admission webhooks have framework-specific non-leader startup paths. EPSS refresh is process-local file state, though its ordinary runnable uses the leader group.

cmd/calib-soak directly starts runner with a denyWritesClient, static kill switch and dry-run policies. One-shot scan/ablation/demo/feed commands are distinct CLI paths, not a multi-replica elected service. In particular native-demo and feed-apply require exclusive isolated operation and are not covered by this election guarantee.

Process-local emit windows, learned state, pending rotation observations and policy state reset on process restart. No persistence, math initialization or update rule changed. A standby's lifecycle is not a state replication mechanism.

Cancellation is not fencing: a previously issued API request may already have committed. A context-cancelled tick select can still select a ready tick, but requests inherit the cancelled context. No unconditional stale-writer or in-flight rollback guarantee is asserted. Partitions/abrupt loss and full actuator scheduling require the independent operational rig.

## Predicted and actual checks

Before running: with election disabled both probes should write. With election enabled only one writes during a 500ms standby observation. On leader cancellation each replica must eventually demonstrate an API write, with a healthy local test timeout of 15 seconds. Test timings are deliberately shorter than production and are not a product recovery target.

`KUBEBUILDER_ASSETS=.../k8s/1.33.0-linux-amd64 GOMAXPROCS=2 go test -p 2 ./internal/runner -run 'TestM005|TestManagerTickLoop|TestHelmChart' -count=1 -v`: PASS. Actual Kubernetes API/etcd, two controller-runtime managers with the same Lease. The probe embeds production runner classification and performs disposable ConfigMap writes. It does not execute full tenant actuation. Both disabled managers write. Enabled standby remains at zero and subsequently writes after cancellation. Observed cancellation-to-first-useful-write 2.085s in this run. Acquisition is separately visible in raw client-go logs, not a precisely instrumented acquisition latency measurement.

Runner/cmd regression and Helm lint/render results accompany this report. Test intentionally skips without envtest assets in ordinary runs.

## First upgrade / rollback and remaining gates

DEVOPS must first stop **all** old election-disabled writers (including external binary instances), wait for termination and account for already-issued requests, then install Lease RBAC and start the new enabled cohort. A rolling overlap with a nonparticipating old writer is unsafe. The existing chart uses Recreate for persistent RWO audit storage, but that is not proof that external writers or all deployment profiles are drained. Do not rely on it as an automatic migration guarantee.

Rollback likewise drains active writers before starting an election-disabled old version. Preserve namespace and lock ID across all cooperating instances and retain needed Lease grants for any enabled version. Operational runbook must record actual replicas/config/image, identities and all bindings. Forbidden Lease acquisition logs an error and retries without starting leader work according to pinned client-go, but constrained-credential behavior was not tested here.

Remaining before closure: named independent DEV/DEVOPS approvals, actual restricted-SA authorization tests, metrics/probe continuity, isolated abrupt-loss/partition measurements, full actuator cancellation/in-flight observations, first-upgrade and rollback exercises. Mostafa's support, recovery and stronger-fencing decisions gate only those respective changes/claims. No live deployment or HA certification is claimed.
