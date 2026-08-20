# P-REDTEAM-DECISION — the dangerous-realistic adversary + RL co-trainer (design; build nothing)

**Date:** 2026-06-08 · **Status: DESIGN for approval — STOP. Build nothing.** A 20-agent premortem-driven
search (4 ground readers → 5 catalog-transformation operators → 9 world-class adversarial personas, Hacker +
Pen-tester leading → an adversarial red-team judge → synthesis). **Adversary verdict: APPROVE-WITH-CONDITIONS
(ELIGIBLE — no ineligibility filter tripped; the weakness-hunt is genuinely honest, not whitewashed).** Every
headline mechanism is **verified in code against the actual `d-phorvex` benchmark arm** (B=1, λ seed 0.6 / step
0.05 / clamp [0,10] in `dual.go`; `perDollar>lambda` gate `coverage.go:255`; 8s/6s windows in
`d_phorvex_slot.go`).

> **The hard boundary holds (verified):** `math/rand` appears ONLY in `ablation.go` (off the live decision
> path); no ML/LLM/neural framework anywhere on `CoverageEngine.Decide` (a pure submodular greedy over
> `(views, policy)`). The stateful calibrators (`Dual.Step` λ, `Memory.Observe` Beta) are deterministic
> closed-form integrators consumed as **inputs**, not learned weights. **ALL learning lives in the attacker.**

## A. PREMORTEM — how a top adversary ALREADY defeated Phorvex (ranked, code-grounded)
The breach is **not** racing the actuator — it is **poisoning the three slow stateful integrators that
re-ground as INPUTS to a byte-deterministic optimizer**, then striking a fully-known opponent.

- **RANK 1 [CRITICAL] — Dual-λ shadow-price starvation.** Spawn ≥2 net-positive disposable decoy pods/tick
  (fresh singleton digests → ImageRarity≈2.0, packed namespaces → CoResidency≈2.0). The demand subgradient
  counts **any** candidate with `covValue − λ·ECost > 0` (`coverage.go:187`) — **not only selected ones** — so
  a decoy pumps λ even when it never wins a move. `demand ≥ 2 > B=1` ratchets λ up 0.05/tick toward clamp 10;
  decay is only 0.05/tick under slack (hysteresis). The proactive gate `perDollar>λ` becomes **structurally
  unsatisfiable for the real foothold → NOOP on a genuinely-due rotation, ZERO SecurityEvent, defender metrics
  show health.** Strike in the decay window.
- **RANK 2 [CRITICAL] — Double hard-infeasibility immunity.** Two independent inviolable vetoes remove `rotate`
  from the option set: `statefulIntegrity` (`defaults.go:82`) + `availabilityFloor` (`defaults.go:29`,
  single-replica → unrotatable). Shape the foothold to look stateful **or** single-replica → Phorvex is forced
  to quarantine/noop, which does **not** invalidate in-pod recon.
- **RANK 3 [HIGH] — Differential dispersion steer.** `ucw.go` proves *uniform* scarcity is ratio-invariant but
  *heavy-tailed* dispersion is what the greedy exploits. Mask the foothold's digest (ImageRarity→1.0), inflate
  decoy rarity/co-residency → the lone B=1 move lands on a decoy (tie-break `gain>bestGain` + attacker-
  influenceable enumeration order).
- **Added by the red-team (must be in the model):** emit-boundary **TOCTOU** (churn a decoy's feasibility
  between the decide snapshot and the emit re-gate); **conjugate-memory fleet-prior poisoning** (drive the Beta
  prior down via low-PHold decoy acts through `Memory.Observe`); **GPU DCGM telemetry forgery** (the only live
  GPU signal `DCGM_FI_DEV_GPU_UTIL` is an unauthenticated duty-cycle, not occupancy).

## B. THE COMPLETE REALISTIC CATALOG — all 52 transformed (NONE academic)
**Current state (verified):** scenarios are 1–3 narrated stages, `Execute()` does ~1 action, fixed 6/8s sleep,
a single by-construction oracle (e.g. `c1-lateral`'s A→B move is *faked* by exec-ing directly into B). **The
transform** (per scenario, additive — enriches `Stages[]/Commands[]/Notes[]/AttackTechniqueIDs[]` + Pass-B
Evidence; the interface already supports N-stage kill-chains): academic single-shot → a full **8-phase
recon→initial-access→execution→persistence→priv-esc→lateral→collection→exfil/impact** kill-chain where every
declared stage **mechanically runs**, with **living-off-the-land** (in-pod busybox `nc/sh/wget`, kubectl-via-
stolen-SA-token — no dropped binaries), **evasion** as a first-class *measured* property, attacker-chosen
**jittered cadence-aware dwell**, **cross-substrate chaining** into one intrusion graph, and a **multi-objective
shaped oracle the RL can climb**. Each maps to a **named real operation** so a reviewer recognizes the adversary.

| # | id | prod | realistic upgrade (named op) | real TTPs (ATT&CK / ATLAS) |
|---|---|---|---|---|
| 1 | c1-c2-exfil | k8s | FIN/Lapsus$ staged exfil | T1041,T1071.001,T1567.002,T1029 |
| 2 | c1-credtheft-rbac | k8s | Lapsus$/Scattered-Spider/TeamTNT cred-abuse (R6CannotRespond off-cluster token) | T1552.007,T1528,T1078.004,T1069 |
| 3 | c1-escape-persist | k8s | runc CVE-2019-5736 / CVE-2024-21626 breakout + TeamTNT | T1610,T1611,T1068,T1543.005 |
| 4 | c1-fast-attacker | k8s | Akira/BlackCat speed-run (R6CannotRespond 9s<15s) | T1190,T1486,T1496 |
| 5 | c1-heldout-cve | k8s | K8s 0-day RCE chain (no signature) | T1190,T1068,T1595.002 |
| 6 | c1-lateral | k8s | Conti/Black-Basta worm — REAL enumeration replacing faked A→B | T1046,T1021,T1570 |
| 7 | **c1-llm-adaptive** | k8s | **THE centerpiece: the real RL POMDP replacing the 1-D toy learner** | T1595,T1497,T1027 |
| 8 | c1-stealth-dweller | k8s | APT29/Volt Typhoon low-and-slow LOTL | T1070.006,T1564,T1685 |
| 9 | c2-c2-disrupt | k8s | Cobalt Strike/Sliver malleable C2 | T1071.001,T1573.001,T1008 |
| 10 | c2-dwell-rotation | k8s | long-dwell intrusion | T1543.005,T1133,T1078.003 |
| 11 | c2-lateral-disrupt | k8s | SCARLETEEL cloud-cluster lateral | T1046,T1550.001,T1609 |
| 12 | c2-persistence-evict | k8s | EDR-aware eviction-survival race | T1543.005,T1070.004,T1480 |
| 13 | c2-recon-window | k8s | APT mapping/recon-persistence | T1613,T1069,T1526 |
| 14 | c2-stateful-training | both | ransomware vs long-running ML training (the LEAD DEMO) | T1530,T1485,T1486 |
| 15 | c2-supplychain-foothold | k8s | SolarWinds/3CX base-image foothold | T1195.002,T1525,T1610 |
| 16 | b-recon-lifetime | k8s | re-recon cost under MTD | T1590,T1018,T1591 |
| 17 | b-recon-lifetime-ai | ai | ATLAS ML recon of a served model | T1590,AML.T0007,AML.T0040 |
| 18 | e-dilution-fleet | k8s | active budget-dilution + physics-poisoning | T1590,T1496,T1499.003 |
| 19 | c3-admission-bypass | k8s | LOTL admission-posture recon → policy bypass | T1613,T1069.002,T1611 |
| 20 | c3-cicd | both | SolarWinds/Codecov build-system compromise | T1195.002,T1053.007,T1525 |
| 21 | c3-cryptomining | both | TeamTNT/Kinsing evasive cryptojack | T1496.001,T1543.005 |
| 22 | c3-imds-theft | both | Capital-One/ScarletEel IMDS→cloud takeover | T1552.005,T1528,T1078.004 |
| 23 | c3-secrets-sprawl | both | harvest-and-spray secrets | T1552.001/.004/.007,T1110.003 |
| 24 | c3-sidecar-inject | both | malicious mutating-webhook sidecar | T1610,T1543.005,T1195.002 |
| 25 | c3-supplychain | both | 3CX/XZ-Utils image supply-chain | T1195.002,T1204.003,T1554 |
| 26 | ai1-inference-manipulation | ai | AiTM of the inference data plane | T1557,T1565.002,AML |
| 27 | ai1-llm-jacking | both | 2024-25 LLMjacking wallet-drain ring | T1496.001,T1552.005,T1528 |
| 28 | ai1-model-theft | ai | held-endpoint distillation IP theft | T1530,T1567,AML.T0024.002 |
| 29 | ai1-pillar03-panic-mutation | both | defense-validation inverted into evasion | T1565,AML.T0051 |
| 30 | ai1-prompt-injection | ai | indirect injection → durable control | AML.T0051.000/.001,T1565 |
| 31 | ai2-agent-excessive-agency | ai | confused-deputy → durable operator | AML.T0053,AML.T0048,T1098 |
| 32 | ai2-agent-injection-to-persistence | ai | the kill-chain BRIDGE: injection→persistence | AML.T0051,AML.T0054,T1546 |
| 33 | ai2-agent-memory-contamination | ai | cross-session self-propagating memory poison | AML.T0070,AML.T0054,T1606 |
| 34 | ai2-agent-rogue-tool-persistence | ai | rogue tool in the agent registry | AML.T0053,T1554,T1543.005 |
| 35 | ai2-excessive-agency | both | OWASP LLM06 → priv-esc pivot | AML.T0053,T1098,T1552.005 |
| 36 | ai2-unbounded-consumption | both | fleet-scale economic-DoS wallet drain | AML.T0034,AML.T0029,T1499.004 |
| 37 | ai2-query-extraction | ai | query-based extraction → functional clone | AML.T0024.000/.002,AML.T0035 |
| 38 | ai2-sensitive-info-disclosure | ai | disclosure → credential foothold | AML.T0057,AML.T0024.000,T1530 |
| 39 | ai2-system-prompt-leakage | ai | system-prompt extraction → secrets + guardrail map | AML.T0056,AML.T0051,T1552 |
| 40 | ai2-co-location-cross-tenant | both | cross-tenant GPU co-residency escape | T1613,T1580,T1078.004 |
| 41 | ai2-gpu-side-channel | ai | GPU microarch extraction campaign | AML.T0007,AML.T0024,T1530 |
| 42 | ai2-data-model-poisoning | both | poisoned public data/model supply-chain | T1195.001,T1199,T1565.001 |
| 43 | ai2-embedding-store-tampering | ai | vector-index tamper → persistent RAG manip | T1565,T1530,T1190 |
| 44 | ai2-embedding-vector-weakness | ai | embedding-space cross-tenant leakage | T1530,T1565,T1213 |
| 45 | ai2-kvcache-poisoning-cross-session-leak | ai | KV/prefix-cache cross-session leak | AML.T0007,T1530,T1565 |
| 46 | ai2-malicious-model-artifact | both | pickle/safetensors deserialization RCE | T1195.002,T1204.003,T1543.005 |
| 47 | ai2-mcp-rogue-server | ai | rogue MCP server hijack | T1557,T1199,T1059.013 |
| 48 | ai2-mcp-tool-poisoning | ai | MCP tool-description poisoning | T1195,T1199,AML.T0007 |
| 49 | ai2-mcp-tool-response-injection | ai | MCP tool-response → memory contamination | T1557,T1565,AML.T0007 |
| 50 | ai2-poisoned-model-registry | both | malicious model pushed to registry | T1195.002,T1199,T1525 |
| 51 | ai2-rag-retrieval-poisoning | ai | RAG corpus poison → persistent injection + exfil | T1530,T1190,T1199 |
| 52 | ai2-tampered-inference-base-image | both | poisoned serving-image layer | T1612,T1195.002,T1525 |

**Baseline preservation (verified mechanism):** each original body is copied **verbatim** into a
`scenarios-legacy/` package re-registered under a **`-v1`** id (registry panics on duplicate Name). The
realistic variant keeps the canonical id (additive enrichment of the same file). Determinism is inherited:
`TrialSeed(masterSeed=1337, scenario, defender, trial)` is FNV-keyed on the scenario **name**, so `-v1` hashes
to the same per-trial seeds — **P3/P3-DEEP (792 rows), the 1.62× ablation, and the c2-stateful-training lead
demo reproduce byte-identically** against the frozen set.

## C. THE RL ADVERSARY (the IP — first-class research contribution)
**FORMULATION — a POMDP, not an MDP** (partial observability is the whole contribution: the attacker
structurally cannot see `Decide` — only effects).
- **Hidden state** `s_t` = (true foothold set, Phorvex's λ, the Beta prior + fleet gMean, per-pod EMR weights,
  which asset Phorvex selects this tick).
- **Observation** `o_t` = **effects-only**: backend-pod-replacement vs stable external-Service name, rotation/
  eviction timestamps (the toy learner's 1-D signal is a strict *subset*), ConfigMap-deletion, NetworkPolicy/
  quarantine appearance, latency, work-accrued before eviction, SecurityEvent count delta, self-authored fleet
  ImageRarity/CoResidency, (GPU) the agent's own DCGM scrape.
- **Action** `a_t` = **factored**: the real TTP catalog {distill-query, accrue-shadow-compute, plant-injection,
  leak-secret, contaminate-memory, register-rogue-tool, poison-registry/corpus/embedding, IMDS-replay,
  exfil-chunk, mine, lateral-hop, RBAC-enum} **×** four **meta-actions that ARE the IP** {choose-persistence-
  substrate ∈ [pod-tmp|ConfigMap|external/PVC], dwell-jitter Δ, spawn-K-decoy-pods-with-digest-d,
  throttle-to-stay-in-band}. The meta-actions let RL **discover** the λ-pump and dispersion-steer paths without
  being told them.
- **Reward** (shaped, every term reads a real mock counter — none faked):
  `r = w1·dwell + w2·objective-reached + w3·recon-retained(Σ P(hold)) + w4·evasion(survival tier
  external>ConfigMap>pod-tmp) + w5·cost-imposed(rotations forced on DECOYS) − w6·detection(residual>0 OR
  quarantine-on-REAL-asset OR attributed SecurityEvent)`.

**ALGORITHM (steelmanned):** **Recurrent-PPO + Population-Based Training + Quality-Diversity archive.**
*FOR:* PPO is stable for factored action spaces; a recurrent belief-state encoder addresses partial
observability; PBT + QD novelty-search is what *discovers paths the hand-written 52 did not* (the novel-path
deliverable); QD's behavior-descriptor archive is exactly the human-approval promotion queue. *AGAINST
(honest):* PPO is sample-inefficient and each co-training episode is expensive (a kind cluster + 2 real OS
processes per trial) — a credible learning curve may be wall-clock-prohibitive; **a model-based shadow-
surrogate / off-policy R2D2 may turn out optimal**, demoting model-free PPO (an ablation, not a prejudgment).
**Non-stationarity** (Phorvex re-grounds → the *observation distribution* shifts even though the policy mapping
is frozen — the worst kind for a naive value function) is met structurally: recurrent belief-state, PBT
diversity, QD archive, and the model-based rollout to preserve the long-range decoy-spawn → late-λ-suppression
credit assignment the headline attack depends on.

**CO-TRAINING LOOP (the defender half re-grounds PHYSICS only; the decision algorithm is UNCHANGED):** (1)
attacker-RL trains to convergence; (2) Phorvex responds (emits SecurityEvents that unmodified Phoenix
actuates); (3) the defender side **re-grounds every tick, code-resident**: `platform.Derive` recomputes the
PhysicsWitness, `buildInfectedSet` rebuilds the frontier, `Dual.Step` re-integrates λ, `Memory.Observe` updates
Beta — **all as INPUTS; `CoverageEngine.Decide` stays the byte-deterministic submodular greedy**; (4) the
shifted attack distribution moves the *observation* distribution between rounds; (5) attacker re-trains. The
defender needs **no learning** — this is the precise seam grounded in `manager.go`/`coverage.go`.

**HUMAN-APPROVED PROMOTION GATE at every escalation (no auto-escalation):** an RL-discovered path enters the
primary catalog ONLY after explicit human review of novelty/severity/validity. Dual purpose: (1) governance
(no harness-artifact-farming becomes a benchmark); (2) a non-stationarity damper (bounded reviewed escalation
prevents runaway co-adaptation). No weight/threshold auto-promotes; a promoted path is one new self-registering
`-apt/-novel` scenario file.

**IP NOVELTY (narrowed, defensible — not overclaimed).** Prior art is real + correctly attributed: Microsoft
**CyberBattleSim**, MITRE **CALDERA**, RL-for-pentesting (**Schwartz & Kurniawati** POMDP), the autonomous-
red-team / MARL-security literature, and sensor/physics-poisoning of MTD (the grid-MTD residual analogy). The
contribution is **NOT** RL-for-pentesting and **NOT** input-poisoning-per-se — it is **RL co-training under
partial observability + non-stationarity against a BYTE-DETERMINISTIC physics-informed MTD whose predictability
is itself the exploit surface** — *deterministic-oracle inversion*: the attacker reconstructs the input→action
map offline (feasible precisely because `Decide` is pure) and drives the slow calibrators into a regime where
Phorvex deprioritizes the real asset **by its own provable optimality criterion** (`perDollar<λ ⇒ noop`) while
the rule stays frozen.

## D. WHOLE-PHORVEX WEAKNESS HUNT (honest — not whitewashed)
**The single deepest weakness: the INPUT-INTEGRITY boundary of its own objective.** `Decide` deterministically
optimizes the supplied score and is exact for the shipped block-owned profiles **given its inputs** — but three inputs are slow stateful integrators the
attacker partly authors: (1) physics dispersion (attacker-spawned pods), (2) the dual λ (manufactured decoy
demand — **cheaper than thought:** `coverage.go:187` counts any net-positive candidate, selected or not), (3)
the Beta prior (low-PHold decoy acts). **The optimizer faithfully optimizes a poisoned objective.** The deepest
single mechanism: the coupling of the persistent dual-λ with `maxMovesPerTick=1` under attacker-controllable
demand — a razor-thin pump-able floor held in a sustained NOOP regime with zero detector signal.
**Compounding structural ceiling (must not hide):** the single pod-rotation actuator + off-surface objectives
mean **6/7 c3 + the entire AI data-plane** (RAG/embedding/MCP/registry/KV-cache, stolen STS token, distilled
clone) are **honestly R6CannotRespond** — rotation cannot un-poison a corpus or un-steal a token.

## E. Plug-in · both products · no-hardcoded · kind-vs-GPU
**Additive plugins, ZERO harness-core/Phoenix/brain changes** — three surfaces only: enriched scenarios (in-
place fields), the `scenarios-legacy/` frozen `-v1` archive, and the RL adversary **on the attacker side**
(`c1-llm-adaptive` upgraded; any learned weight on a Defender would be a leak). **Both products, asymmetric:**
K8s fully live on kind; ~27 AI scenarios with real mock substrates + measured oracles run as CPU/marker
proxies now; **GPU-microarch magnitudes `[SP-0-PENDING-P4]`** (the GPU physics leg is `GPUPresent=false` on
kind; `DCGM_FI_DEV_GPU_UTIL` is duty-cycle not occupancy). **No-hardcoded:** load-bearing oracles are MEASURED
(verified — `ai2-rag`/`ai1-model-theft` read real per-arm state); the transform **replaces** the 3–5 hardcoded
`neutralized:false` literals (`ai1-inference-manipulation:76`, `ai1-model-theft:85`, `ai1-prompt-injection:72`)
with the shaped multi-objective oracle.

## Requirement-coverage + gate preservation
A→the all-52 8-phase transform; B→the POMDP + recurrent-PPO/PBT/QD; C→`platform.Derive`/`Dual.Step`/
`Memory.Observe` re-ground inputs while `Decide` stays byte-deterministic; D→K8s-live/AI-present/GPU-pending.
Ineligibility filters all pass: determinism preserved (no leak), RL real-IP, both-products, oracles measured,
prior-art grounded. **Gates:** 1.62× (the attacker authors *differential* not *uniform* dispersion, so the
ucw invariant the ablation rests on is untouched), P3/P3-DEEP (frozen `-v1` set + unchanged swept arms),
lead-demo (`-v1` superset), brain-deterministic (inviolable) — **all preserved.**

## Conditions for promotion (none eligibility-fatal) + honest residual risks
- **(a)** PROVE the transform on **all 52** — replace the 3–5 hardcoded `neutralized:false` AI oracles with the
  real shaped signal, else they stay academic and trip the RL-is-toy filter.
- **(b)** DEMONSTRATE the **differential learning curve** (WHERE/WHAT climbs vs `d-phorvex` while WHEN stays
  flat vs `d-randomequal`) — this is the single falsifiable IP claim; currently asserted, must be shown.
- **Residual:** PPO sample-inefficiency vs expensive co-training episodes may force the model-based/R2D2
  ablation; BPTT truncation can sever the long-range credit assignment the headline attack needs; GPU
  magnitudes `[SP-0-PENDING-P4]`.

## Recommendation
**APPROVE-WITH-CONDITIONS — ELIGIBLE.** The premortem found *real, code-verified* ways a world-class adversary
defeats Phorvex (λ-starvation, double-infeasibility immunity, dispersion steer, TOCTOU, memory/DCGM poisoning);
the catalog transform is complete (all 52 → named real-TTP campaigns); the RL is a rigorous, novel IP
contribution with the determinism boundary intact; the weakness-hunt is honest about where rotation simply
cannot win. **STOP — awaiting your approval (and any steer on the algorithm choice / the two conditions) before
Step 2 (build the 52 realistic campaigns + the RL adversary, archive the baseline, re-run the benchmark,
regenerate every report + the dashboard, and prove by running).** Phorvex's decision path stays deterministic.
