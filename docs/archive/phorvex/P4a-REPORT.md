# P4a-REPORT — production-grade read-only EKS connector + live-telemetry→physics (built + proven on kind)

**Date:** 2026-06-07 · **Status: BUILT + PROVEN BY RUNNING.** All conditions of approval met — the SSRF
fix elevated to MUST-FIX, the narrower read-only scanner Role, `--prometheus-url` wired into the scan (the
telemetry-blind gap closed), the EKS context DERIVED (never hardcoded), the DCGM-via-Prometheus templates
shipped, the inert surfaces marked `[SP-0-PENDING]`. **brain / optimizer / actuator / recon / killchain +
the harness are UNCHANGED** (proven by diff). Verified by RUNNING on `kind-amtd-test` with change-source
proofs — not by build alone. The user's real-EKS run is the final live confirm; GPU/DCGM magnitudes stay
`[SP-0-PENDING-P4]`.

## What was built
| Module | Delivered | Files |
|---|---|---|
| **SSRF MUST-FIX** | `/api/metrics?url=` hardened: scheme http/https, **blocks IMDS/link-local/metadata always**, loopback-or-`--metrics-allow` only, **dial-pinned to the validated IP** (defeats DNS rebind), GET-only, no redirects | `internal/console/safefetch.go` (+test), `analytics.go`, `config.go`, `cmd/console/main.go` (`--metrics-allow`) |
| **M1 — Scan RBAC** | the read-only **List-only** `phorvex-scanner-role` (SA+ClusterRole+binding), disjoint from the actuator write Role; every verb maps 1:1 to a `client.List` call | `config/rbac/phorvex-scanner-rbac.yaml` |
| **M2 — EKS adapter** | node-label projection (`NodeInfo.Labels`); EKS detection **keyed on real `eks.amazonaws.com/*` labels** (not registration-order luck); GPU `Derive()` override stays absent → `GPUPresent=false` | `internal/ingest/kube.go`, `internal/platform/adapters.go` (+test) |
| **M3 — Telemetry→physics** | `--prometheus-url` wired into `runScan` (was nil/**telemetry-blind**); a live-telemetry section feeding cost/continuity/feasibility/context; `absentSource` stays default | `cmd/main.go` |
| **M4 — DCGM templates** | live `DCGMWitnessQueries()` for FB_USED/FB_FREE, **PROF_SM_ACTIVE only for SM occupancy**, and T4 PCIe RX+TX. Missing PROF_SM_ACTIVE stays honest-absent; GPU_UTIL remains separate duty-cycle telemetry and is never substituted. | `internal/ingest/prometheus.go` |
| **M5 — Plug-and-play** | `ClusterTargets()` **DERIVES** targets from the live kubeconfig contexts (never a baked string); `phorvex --context` honors a derived context; `/api/scan` threads `context` + SSRF-validated `prometheus-url` | `internal/console/cluster.go`, `runs.go`, `subsystems.go`, `server.go`, `cmd/main.go` |
| **Honesty** | the inert surfaces marked `[SP-0-PENDING-P4a] UNWIRED`: `SeedEPSS` (0 callers → EPSS≡1.0), `ObserveRotation` (0 callers → C_flow never calibrates) | `internal/platform/epss.go`, `internal/cost/p1cost.go` (comment-only) |

## Verified by RUNNING (kind-amtd-test) — change-source proofs, not build-passing
| Proof | Result |
|---|---|
| **A · live scan + change-source** | `phorvex --scan` derives the real witness; **imageRarity 2.00 → 1.39** when 4 redis pods are added to the live fleet (live-derived, not a constant) |
| **B · telemetry → Phorvex** | with `--prometheus-url`, the scan's reqRate moves **7.00 → 42.00** as the live Prometheus value changes; **B2:** without `--prometheus-url`, **no telemetry section** (honest-absent, nil source) — the telemetry-blind gap is closed |
| **C · SSRF closed (live)** | `/api/metrics?url=http://169.254.169.254/…/iam/security-credentials/` → **BLOCKED** ("target blocked: metadata/link-local"); `?url=http://127.0.0.1:18080/metrics` → **allowed** (loopback) |
| **D · least-privilege (live)** | `kubectl auth can-i` as the scanner SA: **ALLOW** list pods / get nodes / list networkpolicies / PDBs / clusterroles; **DENY** get secrets / create·delete·patch pods / update nodes / pods/exec / impersonate |
| **E · gates preserved** | `git diff`: **decision / actuator / recon / killchain / harness UNTOUCHED**; the only brain-adjacent edits (cost/epss) are **comment-only** markers (verified); the ablation mechanism runs intact (fleet-dependent ratio) |
| **F · adapter on kind** | `platform-adapter: generic-k8s` (kind has no `eks.amazonaws.com` labels — correct); the EKS adapter is validated by `TestAdapterSelectionIsLabelDriven` |
| **Tests** | `TestSSRFGuard`, `TestAdapterSelectionIsLabelDriven`, `TestGPUAdapterKsHalfByteIdentical` (gate), `TestScopedDefaultDeny`, `TestOwnerEndpointNoIPLeak` PASS; **all 9 phorvex packages green** |

## Gate preservation (1.62× + P3 + lead-demo; brain/actuator/harness UNCHANGED)
P4a is an ingest/platform/console/cmd delta. The diff confirms **zero changes** to `internal/decision`,
`internal/actuator`, `internal/recon`, `internal/killchain`, or `build/test-harness`; the two brain-adjacent
files (`cost/p1cost.go`, `platform/epss.go`) are **comment-only** `[SP-0-PENDING]` markers (no logic). The EMR
scalar is telemetry-independent (verified), so wiring `--prometheus-url` cannot move the 1.62× — the live
ratio is purely structural fleet dispersion. **The 1.62× / P3 / lead-demo gates are preserved by construction**
(the `TestGPUAdapterKsHalfByteIdentical` test pins the K8s-half witness byte-identical with the new
label/adapter code).

## "How I connect my real EKS" runbook (plug-and-play; your creds out-of-process, none in this build)
1. `aws eks update-kubeconfig --name <cluster> --region <region>` — writes the exec-credential kubeconfig
   (the AWS CLI mints the STS token out-of-process; Phorvex links **no AWS SDK**).
2. Create a read-only IAM role; map it to the `phorvex-scanner` SA group via an **EKS access entry** (or
   `aws-auth`). (Only needed if you run the scanner in-cluster via IRSA; the agentless out-of-cluster scan
   authenticates with your kubeconfig.)
3. `kubectl apply -f config/rbac/phorvex-scanner-rbac.yaml` — the read-only List-only scan scope.
4. Point `KUBECONFIG`/current-context at the cluster (the console **derives** it into the Connect step), and
   OPTIONALLY pass `--prometheus-url https://<prom-or-AMP>` (self-hosted Prometheus/Thanos is plug-and-play;
   AMP needs a SigV4 signer — a one-file `MetricsSource` variant, `[PENDING]`).
5. Connect → Scan → Discovered. Absent Prometheus/DCGM, the GPU half + telemetry terms stay honest-absent.
   **Keep the console localhost-bound** until real authn (`[PENDING-P-VCLUSTER]`); the SSRF guard holds regardless.

## What kind verified NOW vs what only the real-EKS run confirms
**Kind verified:** the cluster-agnostic client path; the List-only scan + least-privilege `can-i` matrix; the
full K8s-half witness as live snapshot statistics + the imageRarity change-source; telemetry→Phorvex moving
with a live Prometheus value; the DCGM query SHAPES (against a mock); the SSRF block; the label-driven adapter
selection; the kubeconfig-derived Connect targets. **Only your real-EKS run confirms:** the EKS
exec-credential + IAM/access-entry round-trip on a live control plane; real multi-tenant fleet dispersion; and
**real GPU/DCGM magnitudes `[SP-0-PENDING-P4]`**.

## Honest standing items (carried, not hidden)
- **recon-per-$ is fleet-dependent** — ~0 on a flat fleet, lifts only on heavy-tail dispersion; the live panel
  shows the real ratio; the production multiplier is measured at P4/P4a, **not a universal 1.62×**.
- **Inert until wired:** `SeedEPSS` (EPSS≡1.0 — one EMR leg dead), `ObserveRotation` (C_flow stays a prior),
  `SchedulerSlack`/PDB witness (derived-but-unconsumed) — all marked `[SP-0-PENDING-P4a]`, not claimed live.
- **GPU/AI half DESIGNED, UNMEASURED** — eksGPU inherits genericK8s.Derive; AI physics is a stub until a real
  DCGM run (`[SP-0-PENDING-P4]`).
- **Operator start/stop write-path `[PENDING]`** (P4a/P-VCLUSTER); **AMP SigV4 signer `[PENDING]`**; **console
  authn `[PENDING-P-VCLUSTER]`** (read-only + SSRF-guarded + rate-limited today); **Next.js advisory — bump
  before any external demo**; **RL Red-Team `[PENDING-P-REDTEAM]`**.

**P4a BUILT + PROVEN ON KIND — stopping for your on-screen review.** P4b (soak/chaos), P4c (self-security
review incl. the P-ACTUATOR privilege-widening), and P4 (GPU/CoreWeave magnitudes) remain separate stages.
Your real-EKS run is the final live confirm.
