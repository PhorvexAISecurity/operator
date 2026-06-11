# BENCHMARK-RUNBOOK — running the Phorvex benchmark in a real environment (GPU + K8s)

A standalone, end-to-end guide for a developer to reproduce the Phorvex with/without-Phorvex evidence base on
**infrastructure they own and are authorized to test**. The same harness binary and the same metric schema run
on kind, EKS, GKE, AKS, CoreWeave, or a bare vcluster — only the per-run config changes. Real GPU magnitudes
(the AI actuator state machines) require a real GPU/DCGM environment; on a non-GPU cluster those scenarios are
honestly gated `[SP-0-PENDING-P4]` and skip-with-note.

## 0. CURRENT CORRECTED FRAMING (read first — supersedes any older phrasing below)

So a developer running this on real EKS gets correctly-framed results:

- **Recon-per-$ is a ratio > 1.0, FLEET-DEPENDENT — NOT a fixed "1.62×".** Phorvex's claim is that it invalidates
  more attacker reconnaissance per dollar of disruption than equal-budget random targeting (ratio > 1.0); the
  exact ratio depends on the fleet (crown-jewel density, blast-radius topology, cost weights). The 1.62× seen in
  one earlier fixture was that fixture's value, not a universal constant. **Report the measured ratio for YOUR
  fleet**; the gate is `ratio > 1.0`, asserted by `TestAblationP1BeatsRandomPerDollar` + the runtime
  `PolicySafetyGate`. Never quote a single multiplier as the headline.
- **Audited oracles (P-ORACLE-FIX / P-AUDIT).** The prevention/harm/infeasible oracles were corrected + audited:
  prevention is counted only on a verified moved-before-next-stage, harm only on a real workpreserved=false, and
  the per-decision audit (`--audit-json`) is the source of truth. Use the audited oracle outputs, not raw arm
  counters.
- **The 6 defender arms** are fixed (see §5): `d-nomtd`, `d-r6blindtimer`, `d-randomequal`, `d-reactive-only`,
  `d-fullphoenix`, `d-phorvex` (PX). The recon-per-$ ablation compares PX vs `d-randomequal` at equal budget.
- **AI/GPU actuators are `[PENDING-GPU-VALIDATION]`.** The vLLM control-plane ops + `mig-rebind` are real code,
  CI-tested with mocks; their magnitudes + route correctness are validated on a real GPU per
  `REAL-ENV-VALIDATION.md`. On a non-GPU cluster they skip-with-note (no fabricated GPU numbers).
- **Multi-tenancy flags (P-VCLUSTER).** Per-tenant decision isolation is proven exact-zero (Pass 1); OIDC
  identity + the safe apply-fix write-path + per-tenant DoS quotas are built (Pass 2). For a benchmark run,
  multi-tenant is single-tenant-equivalent by default (cross-tenant prior OFF) — the brain is byte-identical to
  the singleton, so benchmark numbers are unaffected. To exercise isolation, see the Pass-1 obligation tests
  (`go test ./internal/decision -run TestO`).

> **HARD RULE (read first).** This is an **offensive** harness. It only runs against a cluster you **own or are
> explicitly authorized to test**. The harness enforces this: `ownedAck: true` is **required** (it refuses to
> start otherwise), and before any mutating call it verifies the **live kube-context AND the apiserver host**
> match the named context in your config, and confines every created object to the sandbox namespace. Do not
> point it at shared, production, or third-party clusters.

---

## 0. Layout + binaries

```
<repo-root>/
  phorvex/                      # the Phorvex brain/operator + cmd/p3report (report generator)
  build/test-harness/           # the attack harness (cmd/harness) + scenarios + defender arms
  build/phoenix-extended/       # the unmodified extended-Phoenix operator (FullPhoenix + PX actuator)
```

Build the binaries once (Go 1.21+; on Windows the names get `.exe`):

```bash
# the attack harness
cd build/test-harness && go build -o bin/harness.exe ./cmd/harness

# the report generator (EFFECTIVENESS-PHORVEX.md) + the Phorvex operator (built per-run by the PX arm too)
cd ../../phorvex && go build -o bin/p3report.exe ./cmd/p3report
```

The `d-phorvex` (PX) and `d-fullphoenix` arms **build the operators from source at run time** using
`phoenixSrcDir` — so `build/phoenix-extended/` (and the `phorvex/` tree) must be present and buildable on the
machine that runs the harness.

---

## 1. Prerequisites

- **An owned/authorized cluster** — EKS, GKE, AKS, CoreWeave, or self-managed K8s ≥ 1.27. You must own it or
  hold written authorization to run offensive tests against it.
- **`kubectl`** configured with a context that points at that cluster, plus cluster-admin (or enough rights to
  create a namespace, RBAC, and the CRDs the PX/Phoenix arms install).
- **Go 1.21+** and a working toolchain on the runner host (the PX/FullPhoenix arms compile operators at run
  time).
- **GPU nodes + the NVIDIA device plugin** (for real AI/GPU magnitudes). Install the device plugin so
  `nvidia.com/gpu` is schedulable:
  ```bash
  kubectl create -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.15.0/deployments/static/nvidia-device-plugin.yml
  # verify GPUs are advertised:
  kubectl get nodes -o custom-columns=NAME:.metadata.name,GPU:.status.allocatable.'nvidia\.com/gpu'
  ```
- **Optional: Prometheus + DCGM-exporter** for live GPU telemetry. The Phorvex operator ingests GPU/continuity
  signals via `--prometheus-url`; without it, Phorvex runs on K8s-only signals and the GPU-physics half is
  honestly `[SP-0-PENDING]`. Install NVIDIA DCGM-exporter (e.g. via the GPU Operator) so Prometheus scrapes
  `DCGM_FI_*` metrics.
- **The harness + report binaries built** (Section 0).

---

## 2. Connect

```bash
# EKS:
aws eks update-kubeconfig --name <cluster-name> --region <region>

# (GKE: gcloud container clusters get-credentials <cluster> --region <region>)
# (AKS: az aks get-credentials --name <cluster> --resource-group <rg>)

# pin the context this run is authorized to target, then verify:
kubectl config use-context <your-context>
kubectl config current-context           # note this exact string -> goes in the config's `context:`
kubectl get nodes                         # confirm reachability + GPU nodes Ready
```

Record the **exact** `current-context` string — the harness safety guard compares it (and the apiserver host)
against your config before mutating anything.

---

## 3. Sandbox namespace + RBAC

All attack behavior is confined to one sandbox namespace you create and own.

```bash
# 3a. the dedicated, owned sandbox namespace (every created object is confined here)
kubectl create namespace amtd-attack-test

# 3b. the read-only scanner RBAC (Phorvex ingest: get/list/watch pods, services, endpoints, nodes, etc.)
kubectl apply -f phorvex/config/rbac/phorvex-scanner-rbac.yaml

# 3c. the actuator's NAMESPACED least-privilege Role (P4c) for the PX arm
#     (scoped to the sandbox: emit SecurityEvents + maintain the AMTD strategy; delete/patch only matched pods)
kubectl apply -f phorvex/config/rbac/phorvex-actuator-role.yaml
# (+ phorvex/config/rbac/role_binding.yaml, service_account.yaml if your layout binds them separately)
```

Least-privilege note: the PX actuator never holds cluster-wide write. It writes only Phorvex-owned
SecurityEvents + AMTD CRs and acts only on pods the policy selector matches in the sandbox namespace. The
extended-Phoenix CRDs are installed by the FullPhoenix/PX arms from `build/phoenix-extended/config/crd`.

---

## 4. Config — `config.<env>.yaml`

Nothing environment-specific is hardcoded in the code; the config is the only place the environment is named.
Create one file per target (e.g. `build/test-harness/config.eks.yaml`):

```yaml
kubeconfig: ""                       # empty => standard KUBECONFIG / ~/.kube/config (still validated vs context)
context: "<your-context>"            # MUST equal `kubectl config current-context`
namespace: "amtd-attack-test"        # the owned sandbox; all objects confined here
ownedAck: true                       # REQUIRED authorization gate (see Section 5)
trialsPerArm: 20                     # 20 = canonical statistics; 5 = fast read; 2 = smoke
masterSeed: 1337                     # fixed -> fully reproducible
phoenixSrcDir: "../phoenix-extended" # source tree the PX/FullPhoenix arms build operators from
outDir: "out-eks"                    # metrics.jsonl, raw/, provenance.json, report.md land here
defenderFilter: []                   # [] = all 6 arms; or pin a subset by name
scenarioFilter: []                   # [] = all registered scenarios; or pin a subset (see Section 6)

# ---- ROI ($) knobs — swap the PLACEHOLDER defaults for YOUR real numbers ----
roiGpuCount: 8                       # your fleet GPU count the ROI prices against (default 8 = a DGX node)
roiDollarsPerGpuHour: 2.50           # your contract/reserved $/GPU-hr (default 2.50 = an H100-ish placeholder)
roiGpuOverheadPercent: 0.015         # measured rotation/MTD overhead avoided (default 0.015 = 1.5%)
roiAvoidedBreachValueDollars: 4880000 # breach value an averted compromise saves (default = industry-avg placeholder)
roiHorizonYears: 1.0                 # costing horizon
```

The **6 defender arms** (the with/without-Phorvex matrix) are: `d-nomtd` (no MTD — the attack-lands baseline),
`d-r6blindtimer` (fixed-interval blind rotation), `d-randomequal` (random equal-rate rotation), `d-reactive-only`
(reactive matcher only), `d-fullphoenix` (full extended-Phoenix), `d-phorvex` (**PX** — the deterministic
recon-coverage brain driving Phoenix). `d-nomtd` is the "without-Phorvex" anchor; `d-phorvex` is "with-Phorvex".

---

## 5. The safety gate (hard rule, enforced in code)

The harness **refuses to run** unless:
1. `ownedAck: true` is present (else `ErrAckMissing` — "you must acknowledge you OWN/are AUTHORIZED on the
   target cluster"), **and**
2. the live kube-context equals `context:`, **and** the live apiserver host matches that named context, **and**
3. every mutating call targets the configured sandbox `namespace:` (objects elsewhere are refused).

On a good start you will see, e.g.:
```
Safety guard OK: context=<your-context> host=https://<apiserver> namespace=amtd-attack-test ownedAck=true
```
**Validate first, without mutating anything:**
```bash
cd build/test-harness
bin/harness.exe -config config.eks.yaml -dry-run   # checks config + safety guard + capabilities, lists the matrix
bin/harness.exe -config config.eks.yaml -list      # lists registered scenarios + defenders
```

> Only ever run this against infrastructure you own and are authorized to test. The gate is a backstop, not a
> license.

---

## 6. Run

The harness loop is identical at every scale — only `trialsPerArm` and `scenarioFilter` change.

### 6a. Focused fast read (~12 differentiating scenarios)
The scenarios that best separate PX from the baselines (stateful, zero-day, fast-attacker, multi-step) plus the
honest-weak cases (cloud-cred, AI in-request ceiling). Set `scenarioFilter` to, e.g.:
```yaml
trialsPerArm: 20
outDir: "out-focusbench"
scenarioFilter:
  - c2-stateful-training      # stateful: PX preserves, blind/reactive destroy
  - c2-persistence-evict      # reactive eviction path
  - c2-dwell-rotation         # proactive rotation
  - c1-heldout-cve            # held-out / structural zero-day (no events)
  - c1-fast-attacker          # timing-bound
  - c1-escape-persist         # escape + persistence
  - c1-lateral                # multi-step lateral movement
  - c3-imds-theft             # cloud cred theft — where PX is HONESTLY weak
  - c1-credtheft-rbac         # exfiltrated cred — honest ceiling
  - ai1-prompt-injection      # AI in-request leg — MTD-CANNOT-HELP ceiling
  - ai1-model-theft           # AI model/IP theft (partial)
  - ai2-rag-retrieval-poisoning
```
```bash
bin/harness.exe -config config.focusbench.yaml
```
≈ 12 × 6 arms × 20 = **1,440 trials** (+ negative-control + adaptive arms). On a real cluster expect a few
hours; rate is dominated by the per-scenario oracle windows and the operator (PX/Phoenix) arms.

### 6b. Full canonical matrix (the comprehensive run)
`scenarioFilter: []` (or the curated ~52 catalog) × all 6 arms × 20 trials ≈ **6,240 trials** (+ controls).
This is a long job — budget tens of hours. Run it batched (Section 6c) or in the background.

### 6c. Batching a long run with `-resume`
`-resume` **appends** to `outDir/metrics.jsonl` instead of truncating, and regenerates the report over the
running total — so you can split the catalog into disjoint `scenarioFilter` batches that share one `outDir` +
`masterSeed`:
```bash
bin/harness.exe -config config.batch1.yaml                 # first batch creates out-full/metrics.jsonl
bin/harness.exe -config config.batch2.yaml -resume         # appends; keep batch scenarioFilters DISJOINT
bin/harness.exe -config config.batch3.yaml -resume
```

### 6d. Background-run guidance
Run long matrices detached and tail the artifacts:
```bash
# linux/mac:
nohup bin/harness.exe -config config.full.yaml > out-full.log 2>&1 &
# progress:
wc -l out-full/metrics.jsonl                  # row count grows live
# (windows: Start-Process; check the harness process StartTime for elapsed)
```
Each `(scenario,defender)` cell writes ~`trialsPerArm + 2` records (the 20 trials + 1 negative-control + 1
adaptive). `-negative-control=false` / `-adaptive=false` drop those if you only want the headline trials.

---

## 7. GPU / AI — real magnitudes vs `[SP-0-PENDING-P4]`

The AI defense value lives in the **actuator state machines** (`phorvex/internal/actuator/handlers_ai.go`):
`kv-reset`, `mig-rebind`, `warm-swap`, `model-shard-replace`, `endpoint-rotate`. These produce **real
magnitudes only on real GPU**:

- **On kind / non-GPU clusters:** GPU-microarch scenarios are `CapGPU`-gated. The harness detects capabilities
  at start (`Detected capabilities: GPU=false MultiNode=false MIG=false`) and these scenarios **skip-with-note**
  — recorded as `skipped` with an `[SP-0-PENDING-P4]` reason, **never faked**. Everything K8s-observable still
  runs for real.
- **On real GPU + DCGM:** point the Phorvex operator at Prometheus so the GPU/continuity physics is live:
  ```
  --prometheus-url=http://<prometheus>:9090     # feeds cost/continuity/feasibility/context from DCGM_FI_* metrics
  ```
  (The PX arm wires this; set it in the arm's policy/launch for your env. Without it the operator runs K8s-only
  signals and the GPU half stays `[SP-0-PENDING]`.) The telemetry path is **DCGM-exporter → Prometheus →
  `--prometheus-url` → Phorvex ingest**.

To preview what the physics will read on your cluster (one-shot, no benchmark):
```bash
cd phorvex && go build -o bin/phorvex.exe ./cmd
bin/phorvex.exe --scan --scan-namespace amtd-attack-test --context <your-context>
# K8s values come back live; "AI:[SP-0-PENDING] (no GPU/DCGM scan)" until DCGM is wired.
```

---

## 8. Metrics + report regeneration

### 8a. The complete metric set (per trial, in `metrics.jsonl`)
| Metric | Field | Meaning |
|---|---|---|
| Disruption-vs-oracle | `disruptionVsOracle` | 1.0 = the attacker's oracle objective was fully disrupted; 0 = attack landed |
| Attacker dwell | `attackerDwellSeconds` | seconds the attacker held its foothold |
| Defensive actions | `defensiveActions` | real actuations taken (the cost) |
| Controls | `falseDefensiveActions`, `negativeControl`, `oracleAchieved`, `skipped` | see 8c |
| Security-per-cost ($) | `roi.securityPerCostDollars` | disruption × avoided-breach-value ÷ annual defense cost |
| ROI ($ view) | `roi.*` | `gpuCount`, `dollarsPerGpuHour`, annual defense cost, avoided-breach value |
| Schwartau | `schwartau.{protection,detection,reaction}TimeSeconds` | the protection/detection/reaction time triad |
| Reusability / replay | `reuse.{replaySuccessCount,replayAttempts,staticBaselineReplaySuccess}` | does a stolen artifact replay after rotation |
| MITRE ATT&CK / ATLAS / OWASP | `atlasIds[]`, `owaspIds[]` (+ scenario `AttackTechniqueIDs`) | framework coverage, both products |
| MTD effect (honest ceiling) | `mtdEffect` | `MTD-CANNOT-HELP` / `BOUNDS-ONLY` / `NEUTRALIZES` (where PX is weak) |
| Split oracle (AI) | `splitOracle`, `inRequestAchieved`, `persistenceAchieved` | in-request leg vs persistence leg |

**recon-per-$** (the P1 recon-coverage-per-dollar advantage, the 1.62× ablation) is computed by the operator's
one-shot ablation, not the per-trial loop:
```bash
phorvex/bin/phorvex.exe --ablation --ablation-namespace amtd-attack-test --ablation-selector app=demo
```

**H1/H2/H3 hypotheses** + the $ views are computed by the Pass-B dollars pass (Section 8b).

### 8b. Regenerate the reports from the real run
```bash
# (1) the per-run report.md + provenance.json are written automatically into outDir at run completion.

# (2) ROI($) / Schwartau / reusability / H1-H2-H3 -> report-dollars.md (no cluster, no re-run):
cd build/test-harness
bin/harness.exe -dollars-from out-eks/metrics.jsonl     # writes out-eks/report-dollars.md next to the metrics

# (3) EFFECTIVENESS-PHORVEX.md (the full effectiveness benchmark, GATE #2):
cd ../../phorvex
bin/p3report.exe --metrics ../build/test-harness/out-eks/metrics.jsonl --out EFFECTIVENESS-PHORVEX.md --phase FULL
# (--phase SMOKE labels n<5 runs as directional)

# (4) COMPARISON.md (vs R6) + the out-bench/out-ai-bench reports + the frontier table are regenerated from the
#     same metrics.jsonl by the report writer; split K8s and AI into out-bench/ and out-ai-bench/ via
#     scenarioFilter (or one outDir and filter at report time).
```

### 8c. Prove the run is honest (controls + the PX arm)
Before trusting any number, confirm from the real `metrics.jsonl`:
- **Negative control:** `max(falseDefensiveActions) == 0` over all `negativeControl:true` rows — no arm acts when
  there is no attack.
- **Positive control:** `d-nomtd` (undefended) has `oracleAchieved:true` per scenario — the attacks actually land.
- **0 skips except GPU-gated:** the only `skipped:true` rows are the `CapGPU` scenarios on a non-GPU cluster.
- **PX produces REAL rows:** `d-phorvex` rows are **not** `skipped` (the prior canonical reports had PX 100%
  skipped because the toolchain was absent — on a real, built environment PX must produce real, non-skipped
  rows). Confirm `count(d-phorvex, not skipped, not negativeControl) > 0`.

### 8d. Report honestly — including where PX is weak
The evidence base is only credible if it states the ceilings. Report them explicitly:
- **Cloud-cred theft (`c3-imds-theft`, `c1-credtheft-rbac`):** a stolen cloud credential / exfiltrated token
  stays valid after the pod rotates — PX `R6CannotRespond` (rotation is pod-identity, not cloud-side).
- **AI in-request leg (`ai1-*`):** rotation cannot un-send a poisoned in-request payload — `mtdEffect =
  MTD-CANNOT-HELP`; PX bounds/evicts the persistence foothold but does not stop the in-request objective.
- The with/without-Phorvex table should show PX's disruption against `d-nomtd` (0) **and** name every cell
  where PX is `BOUNDS-ONLY` / `CANNOT-HELP`, not just the wins.

---

## 9. Reproducibility

- **`masterSeed: 1337`** — every per-trial RNG derives deterministically from it; the same seed + same config
  reproduces the run. Change the seed for an independent replication.
- **`provenance.json`** (written into `outDir`) records the run's config, seed, capabilities, and the binary
  provenance. Every number in `report.md` traces back through it.
- **Raw logs** — `outDir/raw/<scenario>_<defender>_<trial>.log` captures the exact commands and operator output
  for each trial, so any metric can be traced to the live commands that produced it.
- To trace a specific result: find the row in `metrics.jsonl` → its `rawLogPath` → the raw log → the exact
  `kubectl exec` / API calls + the operator's audit (`--audit-json`) decisions.

---

### Quick start (copy/paste skeleton)
```bash
# 1. connect + verify
aws eks update-kubeconfig --name <cluster> --region <region>
kubectl config use-context <ctx> && kubectl get nodes

# 2. sandbox + rbac
kubectl create namespace amtd-attack-test
kubectl apply -f phorvex/config/rbac/phorvex-scanner-rbac.yaml
kubectl apply -f phorvex/config/rbac/phorvex-actuator-role.yaml

# 3. build
( cd build/test-harness && go build -o bin/harness.exe ./cmd/harness )
( cd phorvex && go build -o bin/p3report.exe ./cmd/p3report )

# 4. config.eks.yaml  (context + namespace + ownedAck:true + trialsPerArm:20 + masterSeed:1337 + real ROI knobs)

# 5. validate, then run
cd build/test-harness
bin/harness.exe -config config.eks.yaml -dry-run
bin/harness.exe -config config.eks.yaml

# 6. regenerate reports
bin/harness.exe -dollars-from out-eks/metrics.jsonl
( cd ../../phorvex && bin/p3report.exe --metrics ../build/test-harness/out-eks/metrics.jsonl --out EFFECTIVENESS-PHORVEX.md --phase FULL )
```
