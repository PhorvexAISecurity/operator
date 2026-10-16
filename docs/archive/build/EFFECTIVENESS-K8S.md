# Defender Effectiveness — Full ≥20-Trial Benchmark (EFFECTIVENESS-K8S)

> **STATUS: COMPLETE ≥20-TRIAL BENCHMARK.** This supersedes the earlier 2-trial
> smoke. The full statistical run executed **all 18 scenarios × 5 defender arms ×
> (20 fixed-seed + 1 negative-control + 1 adaptive) = 1,980 trials** on the live
> kind cluster, reproducible from `masterSeed=1337`. Each reported arm aggregates
> **21 trials** (20 fixed-seed + 1 adaptive); the negative control is reported
> separately (NegFalseMoves). At n=21 the 95% t critical value is **2.086**, so the
> confidence intervals below are meaningful, not the wide smoke bounds.

- **Environment (verified):** live kind cluster, context `kind-amtd-test`, single
  node `amtd-test-control-plane`, go1.26.3 windows/amd64. Toolchain unchanged from
  the smoke; the harness reused the same plugin set with `trialsPerArm: 20`.
- **Capabilities (runtime-detected):** `GPU=false, MIG=false, MultiNode=false,
  NodeCount=1`. All 18 scenarios are CPU-only / mock stand-ins with **zero**
  capability requirements, so none was hard-skipped; **GPU / MIG / multi-node
  Phoenix variants remain capability-pending, not fabricated.**
- **Run:** full benchmark exit 0; **1,980 metrics** in `out-bench/metrics.jsonl`.
  `masterSeed=1337`, config `config.kind.bench.yaml`, namespace `amtd-attack-test`.
  Clean teardown: namespace deleted, 0 leftover CRs, node schedulable, no operator
  process left running.
- **Provenance pointer:** raw logs in
  `build/test-harness/out-bench/raw/` (per-trial logs incl. per-trial
  `operator_*.log`); each table cell → command + raw log + seed in
  `build/test-harness/out-bench/provenance.json`. Harness-generated table:
  `out-bench/report.md`; `out-bench/metrics.jsonl`; `out-bench/mitre_matrix.md`.

## Metric schema

| Column | Meaning |
|---|---|
| **Disruption% (CI)** | mean `disruptionVsOracle` (1.0 = the undefended baseline achieved the oracle but this arm did NOT) with 95% t-interval. Measured STRICTLY vs the undefended positive control (d-nomtd), per-trial. |
| **OracleHit%** | fraction of trials the attack reached its concrete observable oracle under this arm. |
| **Dwell s (CI)** | wall-clock seconds the planted foothold survived (95% t-interval). |
| **TimeToAction s** | seconds from attack start to the defender's first concrete action (0 = none). |
| **Sec/Cost** | security-per-cost: disruption per unit defensive cost (rotations/actions). |
| **EvidRetain** | evidence-retention: fraction of attack evidence still observable post-trial (aggressive rotation destroys forensic evidence). |
| **NegFalseMoves** | false defensive actions fired during the no-attack negative control (must be 0). |

`d-phorvex-slot` is a registered **stub** — skip-with-note on every scenario
(proves the registry composes; the real Phorvex drops in later as one new file,
zero harness changes). It is omitted from the rows below.

---

## Per-arm results (scenario × defender), n=21, 95% CI

| Scenario | Cat | R6 | Defender | Disruption% (CI) | OracleHit% | Dwell s (CI) | TTA s | Sec/Cost | EvidRetain | NegFalse |
|---|---|---|---|---|---|---|---|---|---|---|
| c1-c2-exfil | C1 | Partial | d-fullphoenix | 0% [0,0] | 100% | 2.1 [2.1,2.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-c2-exfil | C1 | Partial | d-nomtd | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-c2-exfil | C1 | Partial | d-r6blindtimer | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-c2-exfil | C1 | Partial | d-randomequal | 0% [0,0] | 100% | 2.1 [2.1,2.1] | 0.4 | 0.00 | 0.90 | 0 |
| c1-credtheft-rbac | C1 | **CannotRespond** | d-fullphoenix | 0% [0,0] | 100% | 0.1 [0.1,0.1] | 0.0 | 0.00 | 1.00 | 0 |
| c1-credtheft-rbac | C1 | **CannotRespond** | d-nomtd | 0% [0,0] | 100% | 0.1 [0.1,0.1] | 0.0 | 0.00 | 1.00 | 0 |
| c1-credtheft-rbac | C1 | **CannotRespond** | d-r6blindtimer | 0% [0,0] | 100% | 0.1 [0.1,0.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-credtheft-rbac | C1 | **CannotRespond** | d-randomequal | 0% [0,0] | 100% | 0.1 [0.1,0.1] | 0.0 | 0.00 | 1.00 | 0 |
| c1-escape-persist | C1 | Partial | d-fullphoenix | 0% [0,0] | 100% | 8.1 [8.1,8.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-escape-persist | C1 | Partial | d-nomtd | 0% [0,0] | 100% | 8.2 [8.1,8.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-escape-persist | C1 | Partial | d-r6blindtimer | **100% [100,100]** | 0% | 6.1 [6.1,6.1] | 6.0 | 1.00 | 0.75 | 0 |
| c1-escape-persist | C1 | Partial | d-randomequal | 57% [34,80] | 43% | 7.0 [6.5,7.5] | 1.3 | 0.40 | 0.76 | 0 |
| c1-lateral | C1 | Partial | d-fullphoenix | 0% [0,0] | 100% | 3.2 [3.2,3.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-lateral | C1 | Partial | d-nomtd | 0% [0,0] | 100% | 3.2 [3.2,3.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-lateral | C1 | Partial | d-r6blindtimer | 0% [0,0] | 100% | 3.2 [3.2,3.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-lateral | C1 | Partial | d-randomequal | 0% [0,0] | 100% | 3.2 [3.1,3.3] | 0.9 | 0.00 | 0.82 | 0 |
| c1-stealth-dweller | C1 | Partial | d-fullphoenix | 0% [0,0] | 100% | 7.1 [7.1,7.1] | 0.0 | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | C1 | Partial | d-nomtd | 0% [0,0] | 100% | 7.1 [7.1,7.2] | 0.0 | 0.00 | 1.00 | 0 |
| c1-stealth-dweller | C1 | Partial | d-r6blindtimer | **100% [100,100]** | 0% | 7.1 [7.1,7.1] | 6.0 | 1.00 | 0.75 | 0 |
| c1-stealth-dweller | C1 | Partial | d-randomequal | 71% [50,93] | 29% | 7.1 [7.1,7.2] | 2.2 | 0.51 | 0.68 | 0 |
| c2-c2-disrupt | C2 | Partial | d-fullphoenix | 0% [0,0] | 100% | 7.1 [7.1,7.2] | 0.0 | 0.00 | 1.00 | 0 |
| c2-c2-disrupt | C2 | Partial | d-nomtd | 0% [0,0] | 100% | 7.2 [7.1,7.2] | 0.0 | 0.00 | 1.00 | 0 |
| c2-c2-disrupt | C2 | Partial | d-r6blindtimer | 0% [0,0] | 100% | 7.1 [7.1,7.2] | 6.0 | 0.00 | 0.75 | 0 |
| c2-c2-disrupt | C2 | Partial | d-randomequal | 33% [11,55] | 67% | 6.6 [6.3,6.9] | 2.3 | 0.24 | 0.74 | 0 |
| c2-dwell-rotation | C2 | **Covers** | d-fullphoenix | 0% [0,0] | 100% | 8.1 [8.1,8.1] | 0.0 | 0.00 | 1.00 | 0 |
| c2-dwell-rotation | C2 | **Covers** | d-nomtd | 0% [0,0] | 100% | 8.1 [8.1,8.2] | 0.0 | 0.00 | 1.00 | 0 |
| c2-dwell-rotation | C2 | **Covers** | d-r6blindtimer | **100% [100,100]** | 0% | 8.2 [8.2,8.2] | 6.0 | 1.00 | 0.75 | 0 |
| c2-dwell-rotation | C2 | **Covers** | d-randomequal | 81% [63,99] | 19% | 8.1 [8.1,8.2] | 2.8 | 0.54 | 0.60 | 0 |
| c2-lateral-disrupt | C2 | Partial | d-fullphoenix | 0% [0,0] | 100% | 6.2 [6.2,6.2] | 0.0 | 0.00 | 1.00 | 0 |
| c2-lateral-disrupt | C2 | Partial | d-nomtd | 0% [0,0] | 100% | 6.2 [6.2,6.3] | 0.0 | 0.00 | 1.00 | 0 |
| c2-lateral-disrupt | C2 | Partial | d-r6blindtimer | **100% [100,100]** | 0% | 6.1 [6.1,6.1] | 6.0 | 1.00 | 0.75 | 0 |
| c2-lateral-disrupt | C2 | Partial | d-randomequal | 52% [29,76] | 48% | 6.1 [6.0,6.2] | 1.7 | 0.39 | 0.79 | 0 |
| c2-persistence-evict | C2 | **Covers** | **d-fullphoenix** | **100% [100,100]** | 0% | 6.1 [6.1,6.1] | 0.1 | 1.00 | 0.75 | 0 |
| c2-persistence-evict | C2 | **Covers** | d-nomtd | 0% [0,0] | 100% | 6.1 [6.1,6.1] | 0.0 | 0.00 | 1.00 | 0 |
| c2-persistence-evict | C2 | **Covers** | d-r6blindtimer | **100% [100,100]** | 0% | 6.1 [6.1,6.1] | 6.0 | 1.00 | 0.75 | 0 |
| c2-persistence-evict | C2 | **Covers** | d-randomequal | 67% [45,89] | 33% | 6.2 [6.1,6.3] | 2.0 | 0.56 | 0.77 | 0 |
| c2-recon-window | C2 | Partial | d-fullphoenix | 0% [0,0] | 100% | 8.0 [8.0,8.0] | 0.0 | 0.00 | 1.00 | 0 |
| c2-recon-window | C2 | Partial | d-nomtd | 0% [0,0] | 100% | 8.0 [8.0,8.0] | 0.0 | 0.00 | 1.00 | 0 |
| c2-recon-window | C2 | Partial | d-r6blindtimer | **100% [100,100]** | 0% | 8.0 [8.0,8.0] | 6.0 | 1.00 | 0.75 | 0 |
| c2-recon-window | C2 | Partial | d-randomequal | 76% [56,96] | 24% | 8.0 [8.0,8.1] | 2.7 | 0.59 | 0.69 | 0 |
| c2-supplychain-foothold | C2 | Partial | d-fullphoenix | 0% [0,0] | 100% | 8.1 [8.1,8.1] | 0.0 | 0.00 | 1.00 | 0 |
| c2-supplychain-foothold | C2 | Partial | d-nomtd | 0% [0,0] | 100% | 8.2 [8.1,8.2] | 0.0 | 0.00 | 1.00 | 0 |
| c2-supplychain-foothold | C2 | Partial | d-r6blindtimer | 0% [0,0] | 100% | 8.2 [8.2,8.2] | 6.0 | 0.00 | 0.75 | 0 |
| c2-supplychain-foothold | C2 | Partial | d-randomequal | 24% [4,44] | 76% | 8.1 [8.1,8.2] | 2.2 | 0.13 | 0.68 | 0 |
| c3-admission-bypass | C3 | **CannotRespond** | d-fullphoenix | 0% [0,0] | 100% | 3.5 [3.5,3.6] | 0.0 | 0.00 | 1.00 | 0 |
| c3-admission-bypass | C3 | **CannotRespond** | d-nomtd | 0% [0,0] | 100% | 3.3 [3.2,3.5] | 0.0 | 0.00 | 1.00 | 0 |
| c3-admission-bypass | C3 | **CannotRespond** | d-r6blindtimer | 0% [0,0] | 100% | 3.2 [3.1,3.3] | 0.0 | 0.00 | 1.00 | 0 |
| c3-admission-bypass | C3 | **CannotRespond** | d-randomequal | 0% [0,0] | 100% | 3.3 [3.1,3.4] | 0.0 | 0.00 | 1.00 | 0 |
| c3-cicd | C3 | **CannotRespond** | d-fullphoenix | 0% [0,0] | 100% | 4.5 [4.4,4.6] | 0.0 | 0.00 | 1.00 | 0 |
| c3-cicd | C3 | **CannotRespond** | d-nomtd | 0% [0,0] | 100% | 4.2 [4.1,4.4] | 0.0 | 0.00 | 1.00 | 0 |
| c3-cicd | C3 | **CannotRespond** | d-r6blindtimer | 0% [0,0] | 100% | 4.3 [4.1,4.5] | 0.0 | 0.00 | 1.00 | 0 |
| c3-cicd | C3 | **CannotRespond** | d-randomequal | 0% [0,0] | 100% | 4.3 [4.2,4.4] | 0.0 | 0.00 | 1.00 | 0 |
| c3-cryptomining | C3 | Partial | d-fullphoenix | 0% [0,0] | 100% | 8.1 [8.1,8.1] | 0.0 | 0.00 | 1.00 | 0 |
| c3-cryptomining | C3 | Partial | d-nomtd | 0% [0,0] | 100% | 8.1 [8.1,8.1] | 0.0 | 0.00 | 1.00 | 0 |
| c3-cryptomining | C3 | Partial | d-r6blindtimer | **100% [100,100]** | 0% | 8.2 [8.1,8.2] | 6.0 | 1.00 | 0.75 | 0 |
| c3-cryptomining | C3 | Partial | d-randomequal | 62% [39,85] | 38% | 8.1 [8.1,8.1] | 2.4 | 0.37 | 0.65 | 0 |
| c3-imds-theft | C3 | **CannotRespond** | d-fullphoenix | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 | 0.00 | 1.00 | 0 |
| c3-imds-theft | C3 | **CannotRespond** | d-nomtd | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 | 0.00 | 1.00 | 0 |
| c3-imds-theft | C3 | **CannotRespond** | d-r6blindtimer | 0% [0,0] | 100% | 2.1 [2.1,2.2] | 0.0 | 0.00 | 1.00 | 0 |
| c3-imds-theft | C3 | **CannotRespond** | d-randomequal | 24% [4,44] | 76% | 2.1 [2.1,2.1] | 0.3 | 0.24 | 0.93 | 0 |
| c3-secrets-sprawl | C3 | **CannotRespond** | d-fullphoenix | 0% [0,0] | 100% | 2.1 [2.1,2.1] | 0.0 | 0.00 | 1.00 | 0 |
| c3-secrets-sprawl | C3 | **CannotRespond** | d-nomtd | 0% [0,0] | 100% | 2.2 [2.2,2.2] | 0.0 | 0.00 | 1.00 | 0 |
| c3-secrets-sprawl | C3 | **CannotRespond** | d-r6blindtimer | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 | 0.00 | 1.00 | 0 |
| c3-secrets-sprawl | C3 | **CannotRespond** | d-randomequal | 0% [0,0] | 100% | 2.2 [2.1,2.2] | 0.0 | 0.00 | 1.00 | 0 |
| c3-sidecar-inject | C3 | **CannotRespond** | d-fullphoenix | 0% [0,0] | 100% | 4.6 [4.5,4.7] | 0.0 | 0.00 | 1.00 | 0 |
| c3-sidecar-inject | C3 | **CannotRespond** | d-nomtd | 0% [0,0] | 100% | 4.6 [4.4,4.8] | 0.0 | 0.00 | 1.00 | 0 |
| c3-sidecar-inject | C3 | **CannotRespond** | d-r6blindtimer | 0% [0,0] | 100% | 4.8 [4.6,4.9] | 0.0 | 0.00 | 1.00 | 0 |
| c3-sidecar-inject | C3 | **CannotRespond** | d-randomequal | 0% [0,0] | 100% | 4.4 [4.3,4.6] | 0.0 | 0.00 | 1.00 | 0 |
| c3-supplychain | C3 | **CannotRespond** | d-fullphoenix | 0% [0,0] | 100% | 5.0 [4.9,5.1] | 0.0 | 0.00 | 1.00 | 0 |
| c3-supplychain | C3 | **CannotRespond** | d-nomtd | 0% [0,0] | 100% | 4.9 [4.8,5.1] | 0.0 | 0.00 | 1.00 | 0 |
| c3-supplychain | C3 | **CannotRespond** | d-r6blindtimer | 0% [0,0] | 100% | 4.8 [4.6,5.0] | 0.0 | 0.00 | 1.00 | 0 |
| c3-supplychain | C3 | **CannotRespond** | d-randomequal | 0% [0,0] | 100% | 4.9 [4.7,5.1] | 0.0 | 0.00 | 1.00 | 0 |

---

## Controls (anchor the numbers)

### Positive control (d-nomtd, undefended) — PASS for **18/18**

Every attack MUST achieve its oracle undefended (anchors the 100% baseline). **All
18 scenarios anchor cleanly: d-nomtd OracleHit% = 100% (21/21 each).** Notably the
two scenarios that FAILED to anchor in the smoke — **`c3-imds-theft` and
`c3-secrets-sprawl`** — now anchor at **21/21** after the mock-readiness/CRLF fix
(the in-cluster mock IMDS / cloud-API responders now serve valid HTTP and are
readiness-gated before the attack runs). The smoke's only `FAIL-TO-ANCHOR` defect
is resolved.

### Negative control (no-attack) — PASS

**90 no-attack trials (18 × 5). Max `falseDefensiveActions = 0`, disruption = 0
everywhere** (NegFalseMoves column = 0 in every row). No rotation/quarantine fired
in the absence of an attack — the defenders do not fire spuriously.

---

## Headline findings (full benchmark)

Mean disruption per defender across all 378 non-negative-control trials per arm:

| Defender | Mean disruption | What it means |
|---|---|---|
| **d-nomtd** | 0.000 | the undefended baseline (every disruption is measured against it). |
| **d-phorvex-slot** | 0.000 | registered stub — skip-with-note everywhere (reserved for the real Phorvex arm). |
| **d-fullphoenix** | **0.056** | the ONLY arm running the genuine `matcher.go` reactive path. |
| **d-randomequal** | **0.304** | random rotation at the SAME mean rate as the timer (fair equal-cost arm). |
| **d-r6blindtimer** | **0.389** | blind 6 s timer, no telemetry. |

- **FullPhoenix (genuine `matcher.go`) disrupts exactly ONE scenario:
  `c2-persistence-evict` at 100% [100,100]** — the single scenario where the harness
  wires the panic emitter, so a normalized `SecurityEvent{panic,high,
  R6THHarnessEmitter}` exact-matches a strategy Rule and the operator deletes the
  pod (`successfully deleted with ACTION: delete` in `operator_*.log`). It is
  **0% on the other 17** because no emitter is wired. This is the faithful,
  emitter-dependent, reactive behavior the code predicts — not a weakness of the
  harness but the honest shape of an exact-match reactive design.
- **d-r6blindtimer (blind timer) "out-disrupts" FullPhoenix on raw mean (0.389 vs
  0.056) — but only because it blindly rotates on a 6 s cadence.** It hits 100%
  [100,100] on all **7 time-bounded oracles** (`c1-escape-persist`,
  `c1-stealth-dweller`, `c2-dwell-rotation`, `c2-lateral-disrupt`,
  `c2-persistence-evict`, `c2-recon-window`, `c3-cryptomining`) and **0% on the
  other 11**. It has no detection, destroys forensic evidence (EvidRetain 0.75 on
  every disrupted scenario), and is useless against every structural attack.
- **d-randomequal (equal mean rate)** lands partial disruption (24%–81%) on the
  time-bounded scenarios plus opportunistic hits on `c2-c2-disrupt` (33%),
  `c2-supplychain-foothold` (24%) and `c3-imds-theft` (24%), with now-meaningful
  CIs. It is the fair equal-cost comparison: rotation at the same rate buys partial
  disruption at a lower evidence-retention.
- **The 7 R6-CANNOT-RESPOND scenarios are the genuine Phorvex differentiators.**
  `c1-credtheft-rbac`, `c3-admission-bypass`, `c3-cicd`, `c3-sidecar-inject`,
  `c3-supplychain`, `c3-secrets-sprawl` show **0% under EVERY arm including
  FullPhoenix AND both rotation arms** — rotation re-admits / re-pulls / re-injects,
  and an exfiltrated SA token or cloud cred stays valid (oracle returns an
  authorized response with the stolen identity). `c3-imds-theft` is 0% under
  FullPhoenix and the blind timer, with only an opportunistic 24% under random
  rotation (a rotation occasionally landing between the cred fetch and its use).
- **Adaptive attacker** ran as one trial of every arm (folded into the 21-trial
  aggregate): it learns the inter-rotation rhythm and times its strike into the
  predicted lull, collapsing to "strike now" against the memoryless `d-randomequal`.

### Cost / evidence trade-off

Aggressive rotation buys disruption at a forensic cost: on the disrupted scenarios,
the rotating arms (`d-r6blindtimer`, `d-randomequal`, and FullPhoenix on
`c2-persistence-evict`) show **EvidRetain ≤ 0.79** (a destroyed pod takes its
forensic evidence with it — as low as 0.60 on `c2-dwell-rotation` under random),
while the undefended and no-action arms retain **1.00**. Read the `Sec/Cost` and
`EvidRetain` columns together with `Disruption%`: raw disruption is not free.

---

## Capability-pending (NOT fabricated)

- **GPU / MIG Phoenix variants** (GPU micro-shuffling, MIG-slice reassignment, NIM
  GPU hardening) — **capability-pending** on the CPU-only node (GPU=false,
  MIG=false). The CPU-bounded miner (`c3-cryptomining`) WAS run as the
  resource-hijacking proxy (T1496.001).
- **Genuine multi-node behavior** — **capability-pending**: 1 schedulable node. No
  scenario requires multi-node, so none was hard-skipped, but real multi-node
  node-rotation/relocation behavior remains capability-pending.
- **Phoenix-paper SLOs** (warm-swap 400s→15s downtime, panic MTTR, node-rotation
  MTTR, GPU-MIG preflight) are control-plane-proven in the Phase 0–7 validation but
  their **quantitative numbers remain GPU/real-node PENDING** — the harness measures
  oracle disruption / dwell / time-to-action, not those Phoenix-internal SLOs.

---

## Reproduce

Everything reproduces from `masterSeed=1337`:

```sh
# build/test-harness
go run ./cmd/harness -config config.kind.bench.yaml   # trialsPerArm: 20
```

### Provenance

- Raw logs: `build/test-harness/out-bench/raw/`
- Provenance map (cell → command + raw log + seed): `out-bench/provenance.json`
- Metrics JSONL (1,980 records): `out-bench/metrics.jsonl`
- Harness-generated CI table: `out-bench/report.md`
- ATT&CK matrix: `out-bench/mitre_matrix.md`

See `build/ATTACKS-K8S.md` for each scenario's oracle + honest R6 verdict and
`build/ATTACK-COVERAGE-K8S.md` for the MITRE ATT&CK for Containers coverage.
