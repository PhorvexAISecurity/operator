# P4a-DECISION — production-grade read-only EKS connector + live-telemetry→physics (design for approval)

**Date:** 2026-06-07 · **Status: DESIGN — STOP for approval. Build nothing yet.** A 15-agent search
(3 code-readers → a 10-persona world-class panel with adversarial scoring → a red-team judge → synthesis)
designed the P4a capability against the REAL codebase. **Verdict: ELIGIBLE for P4a as scoped — DESIGN only —
with 2 MUST-FIX deltas and 3 hard tripwires.** No design element needs your AWS creds in this build; it is
not K8s-only; it hardcodes no live-derivable value in the K8s half. The honest center of gravity is **(B):
the marquee "live telemetry into physics" is currently UNMET on the scan path** — a small, kind-verifiable
wiring fix, not a redesign.

**Reconciled scores (panel + red-team):** A connection/RBAC **8** · B telemetry→physics **5** · C
plug-and-play **6** · D no-hardcoded **7** · E honesty **8** · gate-preservation **9** (unanimous).

> The single most load-bearing finding (8 personas + red-team independently confirmed at source): **EKS
> readiness is auth-plumbing + an RBAC manifest, NOT a client-constructor code change.** `runScan` builds the
> client via `client.New(ctrl.GetConfigOrDie(), …)` (cmd/main.go:272) and `cmd/main.go:20` blank-imports
> `k8s.io/client-go/plugin/pkg/client/auth` — so a standard EKS kubeconfig whose `users[].user.exec` shells
> out to `aws eks get-token` authenticates with **ZERO AWS-SDK code in Phorvex** (`go.mod` verified clean of
> aws-sdk-go / aws-iam-authenticator). The AWS CLI mints the STS token out-of-process; the EKS control plane
> validates it. **IRSA** (a projected SA token, OIDC→IAM) also works with zero code change if the scanner is
> later run in-cluster. P4a is the RBAC manifest + production hardening + the telemetry/console wiring.

---

## A — SECURE CONNECTION MODEL (the strongest part; least-privilege by verified construction)

**One credential-agnostic, agentless seam.** The agentless one-shot scan runs the cluster-agnostic binary
against the API server from wherever it executes; the exec-credential kubeconfig is the right primitive
(IRSA is the in-cluster variant — same seam). No in-cluster agent pod is required for the scan.

**EXACT minimal SCAN scope** — derived strictly from the `client.List` calls in `internal/ingest`
(`CollectSnapshot`/`collectRBAC`/`collectEvents`); **every call is verb `list` — grep for
Create/Update/Delete/Patch in `internal/ingest` returns EMPTY.** Read-only, end to end:

| apiGroup | resources | verbs | why (source) |
|---|---|---|---|
| core `""` | `pods`, `namespaces`, `nodes` | get,list,watch | kube.go:72/76/181 (image-rarity, co-residency, slack) |
| `policy` | `poddisruptionbudgets` | get,list,watch | kube.go:208 (PDB witness) |
| `networking.k8s.io` | `networkpolicies` | get,list,watch | kube.go:80 (blast-radius) |
| `rbac.authorization.k8s.io` | `roles,clusterroles,rolebindings,clusterrolebindings` | get,list,watch | kube.go:399-411 (RBAC reach graph) |
| `amtd.r6security.com` | `securityevents` | get,list,watch | events.go:26 — **OPTIONAL**, omit if the CRD is absent |

**No `secrets`, no `pods/exec`, no `pods/log`, no `impersonate`, no `create/update/delete/patch` — anywhere.**
Cluster-wide READ is required because image-rarity / co-residency / blast-radius are inherently fleet-wide.

**Scan scope is DISJOINT from the actuate scope.** The actuator's namespaced write Role
(`internal/actuator`) shares **zero verbs** with the scan ClusterRole. A stolen scan token reads cluster
topology + the RBAC graph and **nothing else** — it cannot mutate a pod, read a secret's contents, exec,
port-forward, or impersonate. **Scan→actuate escalation FAILS by construction** (verified). This is the
trust boundary a customer's security team audits, and it holds.

### The customer-applied least-privilege manifest (design artifact — `config/rbac/phorvex-scanner-rbac.yaml`)
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: phorvex-scanner
  namespace: phorvex-system
  # EKS: annotate for IRSA ONLY if run in-cluster; the agentless out-of-cluster
  # scan authenticates via the operator's own kubeconfig exec credential.
  # eks.amazonaws.com/role-arn: arn:aws:iam::<acct>:role/phorvex-scanner-readonly
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: phorvex-scanner-role     # READ-ONLY. No write verb anywhere. Disjoint from the actuator Role.
rules:
- apiGroups: [""]
  resources: ["pods", "namespaces", "nodes"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["get", "list", "watch"]
# - apiGroups: ["amtd.r6security.com"]   # OPTIONAL — only if the SecurityEvent CRD is installed
#   resources: ["securityevents"]
#   verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: phorvex-scanner-binding
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: phorvex-scanner-role }
subjects:
- { kind: ServiceAccount, name: phorvex-scanner, namespace: phorvex-system }
```
A CI test will assert `kubectl auth can-i` **DENIES every write verb** and **ALLOWS every scan read**, that
the role has zero verbs outside `{get,list,watch}`, and that it is **disjoint from the actuator Role**.

---

## B — LIVE TELEMETRY → PHYSICS (the swappable MetricsSource; the honest weak point)

**The seam exists and is swappable by construction.** `ingest.MetricsSource` (metricssource.go:22) =
`registry.Named` + `PodMetrics(ctx, ns, pods) → map[pod]model.Telemetry`; default `absentSource` returns empty
(`Telemetry.Present=false`, **never fabricated**). `PromHTTP` (prometheus.go) is a real instant-PromQL
provider (per-signal query with a `{namespace}` placeholder, 5s timeout, best-effort per signal). AMP /
Thanos / managed-Prometheus is a **one-file provider swap**.

**The live-signal → term map** (grounded in the *verified* consumers — this is where telemetry already flows
into the deterministic brain, untouched):

| Live signal (`DefaultPromQueries`) | Feasibility | Cost (C_flow) | Continuity | Context | EMR |
|---|---|---|---|---|---|
| `ReqRate` rate(http_requests_total[1m]) | — | flowCost load term + RLS f[5] | littlesLaw residual | PhaseOf | **none (structural)** |
| `P99Ms` histogram_quantile(0.99,…) | sloHeadroom (defaults.go:43) | — | — | SLOHeadroom | **none** |
| `ConnCount` | — | quarantine base term | residual | — | **none** |
| `GPUUtil` `DCGM_FI_DEV_GPU_UTIL/100` | — | gpu-tax term | residual | PhaseOf; LLM-jacking gate >0.8 | **none** |
| `TokensPerSec` rate(nim_tokens_total[1m]) | tokensFloor | — | residual | — | **none** |
| `BytesIn/Out` | — | — | residual | — | **none** |

**⚠ MUST-FIX (the honest center):** `runScan` passes a **nil MetricsSource** (cmd/main.go:279) — so the
plug-and-play scan is **telemetry-blind even on a Prometheus/DCGM EKS cluster.** Presenting the scan as "live
telemetry into physics" is unsubstantiated until the `--prometheus-url`-into-`runScan` delta lands (M3). The
fix is small and **kind-verifiable** with a stub MetricsSource (no EKS needed). **Note:** EMR has **no
telemetry input by design** — the 1.62× gate is structural heavy-tail and Prometheus will not move it one bit
(see Gate preservation).

### DCGM-via-Prometheus GPU path — DESIGNED, values [SP-0-PENDING-P4]
GPU telemetry is scraped **through Prometheus (read-only HTTP GET), not the kube API → zero additional K8s
verb.** `DefaultPromQueries` keeps `DCGM_FI_DEV_GPU_UTIL` as general duty-cycle telemetry, while
`PopulateGPUWitness` independently runs the DCGM witness queries below. Missing series remain
honest-absent; no DCGM value is hardcoded into a witness float:
- **VRAMFraction** = `FB_USED / (FB_USED + FB_FREE)`; demand = `Pod.VRAMRequestBytes` (today unpopulated → the [SP-0-PENDING] input).
- **SMOccupancy** = only `DCGM_FI_PROF_SM_ACTIVE` (true occupancy; needs DCP profiling), with the source recorded. If that series is unavailable—as on the live Tesla T4 stack—the value stays honest-absent. `GPU_UTIL/100` remains separate duty-cycle telemetry and is never substituted. *Conflating duty-cycle with occupancy would overstate the AI kill-chain model-theft leakage gate (hazard.go:239) — load-bearing, not cosmetic.*
- **LinkBandwidth** = normalized `rate(DCGM_FI_PROF_PCIE_RX_BYTES + DCGM_FI_PROF_PCIE_TX_BYTES)` on the live PCIe-attached T4; KVRebuildSec/ColdLoadSec remain separate serving-counter inputs.

---

## C — PLUG-AND-PLAY (Connect → Scan → Discovered on real cluster data)
**Verified flow:** `/api/targets` → `ClusterTargets()` (kind Runnable; eks/coreweave `Runnable:false
[PENDING-P4a]`); `/api/scan` execs the real cluster-agnostic `phorvex --scan --scan-namespace <ns>`
(ns guarded by `scenarioRe`, 60s timeout, `exec.CommandContext` — no shell), parses real stdout into
`ScanResult`. **P4a flips `eks` Runnable mechanically (no brain change):** (1) add a kubeconfig-context input
and **DERIVE `eks.Context` from the operator's own kubeconfig at connect-time** — `eks.Context` is `""` today
and **hardcoding a context string is a do-not-hardcode tripwire**; (2) flip `Runnable` gated on a resolvable
context; (3) thread the optional `--prometheus-url` into `runScan` so Discovered shows live-derived numbers.

**Minimal customer setup (EKS-accurate, your creds out-of-process):** `aws eks update-kubeconfig …` →
create a read-only IAM role + EKS access-entry (or aws-auth) → `kubectl apply -f phorvex-scanner-rbac.yaml`
→ point KUBECONFIG at the cluster, optionally `--prometheus-url` → Connect → Scan → Discovered. Absent
Prometheus/DCGM, the GPU half + Class-2 telemetry terms stay honest-absent.

---

## D — NO-HARDCODED / TELEMETRY AUDIT (K8s half is already live; the inert surfaces are the real finding)
**Conclusion (8 personas + red-team agree):** `genericK8s.Derive` contains **essentially no fabricated
values** — every K8s-half term is an empirical statistic of the live snapshot. The only constants are
**dimensionless guards** (`CoResidencyCap=4`, `MaxDispersionMult=4`, `pol_floor=50` — comment says NOT a
tuned number) and declared fail-safe ceilings; honest-absent neutrals (1.0 mults, −1 PDB, 0 GPU) guarantee
byte-identical pre-scan decisions. **These are not no-hardcoded violations.**

| Term | Live source | Status / change-source proof |
|---|---|---|
| ImageRarity / CoResidency / ModelRarity / SchedulerSlack / PDB / MIG | snapshot statistics (kube.go) | **ALREADY live** on any real cluster; 1.0/neutral on flat kind. Proof: fixture perturbation → assert closed-form Δ; nil → byte-identical-to-neutral. Add a small-N (Miller-Madow) bias guard so a singleton in a 4-pod fleet isn't sampling-noise "crown jewel." |
| EPSS (=1.0 honest-absent) | offline CVE cache via `SeedEPSS` | **INERT today — `SeedEPSS` has zero callers** → EPSS=1.0 on every image → one of three EMR legs dead. Mark `[SP-0-PENDING]`/unwired; wire a scanner/NVD export feed. |
| C_flow (RLS prior) | `ObserveRotation` online calibration | **INERT today — `ObserveRotation` has zero callers** → the RLS prior never calibrates. Mark `[SP-0-PENDING]`/unwired. |
| SchedulerSlack, PDB witness fields | derived | **Derived-but-unconsumed** (no downstream reader). Either wire a consumer or document as diagnostic. |
| GPU half (VRAM/SM/NVLink/KV/cold-load) | DCGM-via-Prometheus | `[SP-0-PENDING-P4]` — designed, unmeasured until a real GPU run. |

---

## E — HONEST: kind-verifiable NOW vs real-EKS-pending
**Kind verifies now (traced in source):** the `GetConfigOrDie`+auth-plugin client path (kind vs EKS differ
only in the exec credential); all scan reads List-only + the minimal RBAC denies every write via
`kubectl auth can-i`; the full K8s-half derivation as snapshot statistics; the 1.62× ablation as an EXACT TIE
on the flat kind fleet (s=1.0 → EMR byte-identical); PromHTTP + the DCGM_FI_DEV_GPU_UTIL/nim query SHAPES
against a kind-hosted Prometheus / synthetic dcgm-exporter; the B-delta change-source proofs
(SLOHeadroom/flowCost/RLS) with a stub MetricsSource; the agentless Connect→Scan→Discovered console path.
**Only your real-EKS run confirms:** the EKS exec-credential + IAM/access-entry round-trip on a live control
plane; real multi-tenant fleet dispersion lifting the structural scalars; **real GPU/DCGM magnitudes
`[SP-0-PENDING-P4]`** (AMP needs a SigV4-signing provider — a one-file MetricsSource variant).

---

## SECURITY REVIEW (trust boundary + the surviving concern)
**Won by construction:** the scan path is non-actuating (List-only, grep-verified), read-only end to end,
disjoint from the actuator write Role. **⚠ MUST-FIX before any non-localhost exposure — SSRF (concrete):**
`PromHTTP.instantQuery` (prometheus.go:131) and the console `/api/metrics?url=` (server.go — the increment-2
endpoint) pass an **attacker-controlled URL to a server-side GET**, gated only by the spoofable
`X-Phorvex-Lens` header → a caller can reach `http://169.254.169.254/…/iam/security-credentials/` (IMDSv1
cred theft) or internal endpoints. **Required:** allowlist `scheme=https` + block RFC1918/169.254.0.0/16/::1,
enforce IMDSv2, never let the console pass an arbitrary `url=` to a server-side fetch, and PromQL-sanitize the
`{namespace}` substitution. The console stays **localhost-only** until authn (`[PENDING-P-VCLUSTER]`) + this
fix land. (Console auth is demo-trust today; read-only + rate-limited `maxConcurrentRuns=2` + 3s.)

---

## REQUIREMENT-COVERAGE MAP
| Requirement / ineligibility bar | Satisfied by | Status |
|---|---|---|
| A secure read-only least-privilege connection | GetConfigOrDie+exec-cred; the List-only scan ClusterRole; disjoint from actuate | ✅ (manifest is M1) |
| B live telemetry → physics | MetricsSource/PromHTTP + the signal→term map | ⚠ seam real, **scan-path wiring is M3 (must-fix)** |
| C plug-and-play Connect→Scan→Discovered | console flow + derive-context + `--prometheus-url` | ✅ (M5) |
| D no-hardcoded | K8s half already live; guards are dimensionless; **3 inert surfaces marked pending** | ✅ + honesty fixes |
| E honest kind-vs-EKS | section E | ✅ |
| no AWS creds in this build | go.mod clean; creds out-of-process via AWS CLI | ✅ verified |
| least-privilege only | List-only, no secrets/exec/write | ✅ |
| not K8s-only | DCGM-via-Prometheus designed, `[SP-0-PENDING-P4]` | ✅ |
| both products first-class | K8s real; AI structural, GPU `[SP-0-PENDING-P4]` | ✅ honest |

---

## GATE PRESERVATION (1.62× + P3 + lead-demo; brain/actuator/harness UNCHANGED)
P4a is an **ingest/platform/console delta only** — it does not touch `internal/decision`,
`internal/actuator`, or the harness. **1.62×:** the EMR scalar (recon/ucw.go) is **telemetry-independent**
(grep-verified — reads only structural Physics, never Telemetry); at nil-data s=1.0 → EMR byte-identical →
the ablation reproduces an EXACT TIE on flat kind; it is **re-established on real EKS data** (the K8s
dispersion scalars are live on a real multi-tenant fleet) and lifts only on heavy-tail — honest, never faked.
**P3** (suite `p3-v3`) and the **lead-demo** (suite `pactuator`) are untouched (no decision path added). A
nil → byte-identical regression test gates every wiring delta.

---

## HONEST RISKS (carried, not hidden)
1. **Telemetry-blind scan path TODAY** (`runScan` nil MetricsSource) — the "live telemetry into physics"
   claim is unmet until M3. Small, kind-verifiable, **unshipped**.
2. **1.62× is decoupled from telemetry** — wiring Prometheus will not move the lift; it's purely structural
   heavy-tail. Must communicate to avoid a false dependency claim.
3. **Three "live/self-calibrating" surfaces are INERT** (`ObserveRotation`, `SeedEPSS` have zero callers;
   SchedulerSlack/PDB derived-but-unconsumed) — not fabricated constants, but "live today" would be overclaim
   → mark `[SP-0-PENDING]`/unwired.
4. **The GPU/AI half is DESIGNED but UNMEASURED** — eksGPU inherits genericK8s.Derive verbatim; AI-product
   physics is a stub until a real DCGM run (`[SP-0-PENDING-P4]`).
5. **SSRF** (above) — localhost-only until fixed.

---

## STEP-2 BUILD PLAN (production-grade; build nothing until approved)
- **M1 — Scan RBAC manifest + IAM trust template.** `config/rbac/phorvex-scanner-rbac.yaml`. Tests:
  `kubectl auth can-i` write-DENIED / read-ALLOWED matrix; zero-verb-outside-{get,list,watch}; disjoint-from-
  actuator.
- **M2 — EKS adapter + node-label projection.** Add `Labels` to `NodeInfo`, populate from `collectNodes`
  (within the existing `list nodes` RBAC — no privilege delta); EKS `Detected()` keyed on
  `node.kubernetes.io/instance-type` (disambiguates the three identical `hasGPUNode` detectors); fall back
  with a "platform-unverified" flag (never silently mislabel). GPU `Derive()` override stays absent →
  GPUPresent=false → K8s half byte-identical.
- **M3 — MetricsSource into `runScan` (the B-delta).** Optional `--prometheus-url`; `NewPromHTTP`; thread into
  CollectSnapshot + ContextScan/AblateScarcity. `absentSource` stays default (no invented URL); retry-with-jitter
  + per-signal timeout + a scrape-health record (queried/ok/errored/empty) so honest-absence ≠ breakage.
  Tests: stub MetricsSource at two operating points proving SLOHeadroom/flowCost move by the closed-form Δ;
  nil → byte-identical (gate test).
- **M4 — DCGM query templates (designed, `[SP-0-PENDING-P4]`).** FB_USED/FB_FREE, PROF_SM_ACTIVE (+GPU_UTIL
  fallback + source label), NVLINK/PCIE, site-overridable `nim_*` — query STRINGS only, no value hardcoded.
- **M5 — Console Connect/Scan deltas + the SSRF fix.** kubeconfig-context input; derive `eks.Context`; flip
  `Runnable`; a `--scan --json` output mode (keep Raw passthrough); **allowlist/validate `--prometheus-url`
  and the console `?url=`** (block RFC1918/169.254/IMDSv1, scheme=https) before any non-localhost exposure.

---

## RECOMMENDATION
**APPROVE P4a as scoped — DESIGN only — with 2 MUST-FIX deltas and 3 hard tripwires.**
- **MUST-FIX #1:** author the strictly-narrower read-only `phorvex-scanner-role` (M1). Binding the scan SA to
  the write-carrying manager-role would be **INELIGIBLE privilege-widening**.
- **MUST-FIX #2:** wire `--prometheus-url` into `runScan` (M3) so "live telemetry → physics" is substantiated
  (currently nil → telemetry-blind), with the nil→byte-identical gate test.
- **TRIPWIRE A:** flipping `eks.Runnable` must DERIVE the context from the kubeconfig — **never hardcode a
  context string** (a live-derivable hardcode).
- **TRIPWIRE B:** ship the DCGM query templates (M4) so the design isn't K8s-only — values `[SP-0-PENDING-P4]`.
- **TRIPWIRE C:** the SSRF allowlist (M5) before any non-localhost exposure.

The design beats a naive cluster-admin + structural-default baseline **decisively** on privilege, no-creds,
no-hardcoded (K8s half), and honesty. The only axis it does not yet beat baseline is live-telemetry on the
scan path — a small, kind-verifiable wiring fix (M3), not a redesign. **brain / optimizer / actuator /
harness + extended Phoenix UNCHANGED.**

**STOP — awaiting your approval before Step 2 (build + prove-by-running on kind).**
