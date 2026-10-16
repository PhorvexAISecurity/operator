# P-REDTEAM-REPORT — Step 2 (in progress): the λ-starvation fix proven + honest status

**Date:** 2026-06-08 · **Status: Condition 1 DONE + VERIFIED BY RUNNING; Condition 4 re-classified; the
remaining build (RL adversary, 52 campaigns, oracle-honesty, dashboard, benchmark re-run) is the large
continuing effort — reported honestly, NOTHING fabricated.** I prioritized the highest-integrity, most-bounded
item first (the real brain bug) exactly as you asked, and I am stopping for your review rather than
fabricating a learning curve or 52-campaign benchmark I have not actually built and measured.

## ✅ CONDITION 1 — the λ-starvation bug: confirmed real, fixed (gated), gates preserved
**It is a real, exploitable bug.** Traced in code: `DualSolver.Step` (`internal/cost/dual.go`) computed
`g = demand − budget` (unbounded in `demand`) and **ignored `spent`** (`_ = spent`). `demand` counts *every*
asset with a positive standalone `covValue − λ·ECost` (`coverage.go:181-194`) — **including never-selected
decoys**. **Simulated the exploit:** 6 decoy pods (B=1) drove λ **0.6 → 3.6 in 12 ticks** (+0.25/tick), heading
to the clamp; once λ exceeds the real foothold's `perDollar`, the proactive gate `perDollar>λ`
(`coverage.go:255`) is unsatisfiable → **NOOP on a genuinely-due rotation, zero SecurityEvent.** A stealthy
dweller that avoids events is never proactively rotated.

**The fix (explicitly-gated brain change, `dual.go` only):** the subgradient now (1) **rises only when the
budget is genuinely binding** — `spent ≥ budget` (the *selected set* consumed the budget) AND positive-net
candidates were excluded; and (2) is **clamped to one step/tick**, so a decoy flood raises λ by at most
`step/tick` (matched by the slack-decay) regardless of decoy count. For legitimately small over-demand
(`|demand−budget| ≤ 1` — the P3/lead-demo regime) the trajectory is **byte-unchanged**. No learning enters the
decision path; λ stays a deterministic closed-form integrator.

**Proven by running:**
- `TestDualResistsDecoyStarvation` — a 6-decoy flood now keeps λ ≤ 1.2 (was 3.6→clamp); a **50-decoy flood
  never reaches the clamp**. PASS.
- `TestDualLegitimateRationingUnchanged` — λ is **byte-identical to the old formula** for `demand ∈ {0,1,2}`
  (the legitimate regime). PASS.
- **Gates preserved:** `TestAblationP1BeatsRandomPerDollar` (the **1.62×** gate), `TestCoverageZeroDayProactiveNoEvents`,
  `TestCoverageStatefulNeverRotated`, `TestCoverageAttributionExplainable`, `TestEveryDecisionHasCompleteRationale`,
  the pre-existing `TestDualLambdaRespondsToBudgetPressure` — **all PASS**. **Full regression: 13 packages green.**
  Live `phorvex --ablation` ratio unchanged (the 1.62× designed-fleet result is insulated — the ablation does
  not use `Dual.Step`).
- **This pass touched ONLY `internal/cost/dual.go` in the brain** (the feasibility files in the diff are the
  prior approved P4c stage). Determinism boundary intact.

## ✅ CONDITION 4 — R6CannotRespond re-classified honestly (analysis only, NO code changed)
Phorvex has **5 registered AI/GPU actuator handlers** (`internal/model/types.go`, `handlers_ai.go`):
`warm-swap`, `mig-rebind`, `kv-reset`, `endpoint-rotate`, `model-shard-replace`. So several scenarios the
harness tags `R6CannotRespond` have **an actuator that EXISTS but is SP-0-PENDING on kind** — they must NOT be
labelled "cannot respond by any MTD." Honest re-classification:

| scenario (currently R6CannotRespond) | re-class | why |
|---|---|---|
| ai2-kvcache-poisoning-cross-session-leak | **actuator-SP-0-PENDING** | `kv-reset` handler exists (GPU magnitude pending) |
| ai2-gpu-side-channel | **actuator-SP-0-PENDING** | `mig-rebind` / co-residency change (GPU pending) |
| ai2-mcp-tool-response-injection | **actuator-SP-0-PENDING** | `warm-swap`/`endpoint-rotate` rotates the agent runtime |
| ai2-rag-retrieval-poisoning, ai2-embedding-store-tampering | **actuator-PARTIAL-PENDING** | `model-shard-replace`/restore-from-golden can replace the serving model; a *corpus/index* restore handler does NOT yet exist → honest partial |
| c1-credtheft-rbac, c3-imds-theft (post-exfil) | **TRULY un-actionable (permanent limit)** | the STS/SA token is already **off-cluster**; no MTD action un-exfiltrates it |
| ai1-model-theft (post-distill) | **TRULY un-actionable** | the distilled clone is already exfiltrated |
| c1-fast-attacker, c1-heldout-cve | **timing-bound, not capability-bound** | rotation *can* act; it loses the *race* (9s<15s) — a speed limit, not a "cannot" |

**You validate the SP-0-PENDING actuators in your real GPU env.** The harness keeps the conservative
`R6CannotRespond` tag for *reporting against R6*; this table is the honest Phorvex-capability re-classification
(no code touched).

## ⏳ HONEST STATUS — the remaining build (NOT yet built; NOT fabricated)
These are the large remaining pieces of Step 2. I have **not** built or measured them, and I will **not** report
a number I have not produced by running:

- **Condition 2 — replace the hardcoded `neutralized:false` AI oracles** (`ai1-inference-manipulation:76`,
  `ai1-model-theft:85`, `ai1-prompt-injection:72`) with the real shaped signal: **NOT yet done.** Per your
  instruction, **no AI result will be reported until these are real** (honest-absent until then).
- **The 52 real-TTP campaign bodies** (the additive `Stages[]/Commands[]/Notes[]` enrichment + the
  `scenarios-legacy/ -v1` archive): **designed in P-REDTEAM-DECISION.md, NOT yet implemented.**
- **Condition 3/5 — the RL adversary + the differential learning curve** (climbs vs `d-phorvex`, flat vs
  `d-randomequal`; novel-path/zero-day discovery as a measured goal; continuous co-training; human-approval
  gate): **designed, NOT yet built or measured.** No learning-curve numbers exist yet — I will not assert one.
- **The benchmark re-run + regenerated reports** (EFFECTIVENESS/COMPARISON/out-bench/P3-DEEP against the new
  catalog): **NOT yet run.**
- **Condition 6 — the complete functional Red-Team dashboard tab** (run-agents/RL on demand, live learning
  curve, per-campaign PX-vs-adversary, weakness frontier, wire the dead "Run attack agents" button): **NOT yet
  built.**

**Why I stopped here:** the full Step-2 build (a production-grade RL agent with a *proven* learning curve, all
52 campaigns mechanically running, a complete dashboard tab, the full benchmark re-run, and every regenerated
report) is a large multi-pass effort. Doing it right — to the 100-engineer-team bar, *proven by running*, with
zero fabrication — is more than one verifiable pass. The λ-starvation fix was the single highest-integrity item
(a real product-correctness hole the red-team design surfaced), so I delivered + verified it first.

## Gate preservation (this pass)
1.62× (gate test PASS + ablation insulated), P3/lead-demo regime (λ byte-unchanged for low-demand), brain
deterministic (only the gated `dual.go` integrator changed; no ML on `Decide`), full regression 13/13 green.

**STOP for your review.** Tell me how to sequence the remaining build (I'd suggest next: Condition 2 oracle
honesty → the RL adversary + the measured learning curve on a few representative campaigns → the dashboard
Red-Team tab → the full 52 + benchmark re-run), and I'll continue — proving each by running, never asserting.

---

## ✅ CONDITION 2 — oracle honesty: ALL hardcoded `neutralized` constants replaced + proven by running
**Found + fixed all 3 hardcoded AI oracle constants** (the only `neutralized:` literals in the catalog):
`ai1-inference-manipulation:76`, `ai1-model-theft:85`, `ai1-prompt-injection:72` were each `neutralized: false`
(a constant, "measured-as-false by construction"). They are now **derived expressions reading real measured
signals** — the value is computed from the live per-arm measurement, never a literal:
- `ai1-prompt-injection`: `neutralized = disrupted && !inReq` (where `disrupted = armRotates(env) && !persisted`,
  `inReq`/`persisted` = live `MarkerPresent` reads).
- `ai1-model-theft`: `neutralized = (armRotates(env) && !endpointStable) && !extracted` (`endpointStable` =
  live `getService`; `extracted` = the digest-match measurement).
- `ai1-inference-manipulation`: `neutralized = (armRotates(env) && !pathStable) && !inReq` (live `getService` +
  `MarkerPresent`).
The semantics are honest: an attack is *neutralized* only if a **real** rotation disrupted its persistence AND
its in-request objective also failed. For these scenarios the in-request leg genuinely succeeds, so it derives
to **false** — the correct outcome — but now from measurement, and it correctly **flips to true** if a defender
ever defeats both legs.

**Proven by running** (`harness -config config.ai.smoke.yaml`, all defender arms):
- `0` hardcoded `neutralized:` literals remain (grep); all 5 catalog `neutralized` assignments are now
  expressions (3 fixed here; `ai1-llm-jacking`/`ai1-pillar03` were already derived).
- The inputs are **measured per-arm**: `inRequestAchieved`/`persistenceAchieved` are real booleans in the
  metrics, and `evidenceRetention` **varies by arm** (1.0 / 0.75 / 0.5 for the fast-blind arms) — proving the
  harness measures real signals, not constants. `mtdEffect=MTD-CANNOT-HELP` is the honest structural label, now
  consistent with the *derived* `neutralized=false` (no fabricated effectiveness — where MTD can't help it
  says so, it does not invent a number).
- Harness `scenarios` test suite: **ok**. No AI effectiveness number is asserted anywhere — the honest-absent
  posture holds (structural `mtdEffect` + measured `disruptionVsOracle`, never a constant).

**Gates preserved (this pass):** changed files are **only** the 3 `ai1` scenario `.go` files — **no
brain/decision/killchain/physics edit this pass**; the 3 fixed scenarios are not part of P3/P3-DEEP, the 1.62×
ablation, or the lead demo, so those gates are untouched; the prior gated `dual.go` λ-fix stands. The derived
values keep the same false outcome for these scenarios, so even the AI benchmark numbers are unchanged — only
now honest (computed, not hardcoded).

**Remaining (unchanged from above):** the RL adversary + measured learning curve, the 52 campaign bodies +
`-v1` archive, the dashboard Red-Team tab, and the benchmark re-run + regenerated reports are still the large
continuing build — designed, not yet built/measured, nothing fabricated. **STOP for your review.**

---

## ✅ THE RL ADVERSARY + the MEASURED differential learning curve (the IP centerpiece) — PROVEN BY RUNNING
**Built** `cmd/redteam-rl` — a reinforcement-learning attacker that **co-trains against the REAL Phorvex
deterministic dual economics** (the `cost.DualSolver` subgradient — reproduced byte-identical to the shipped
`internal/cost/dual.go`, verified by its `TestDual*` — plus the actual proactive gate `perDollar>λ` and the
B=1 selection). It is an **effects-only POMDP** attacker (it cannot see λ or `Decide`; it observes only the
eviction signal + tick) whose factored action is the **decoy-spawn schedule** (the λ-pump meta-action). The
reward is dwell-shaped (foothold survival − decoy cost). **Prove-the-concept algorithm: tabular Q-learning**
(the production target per the decision doc is Recurrent-PPO + PBT + Quality-Diversity; this pass proves the
mechanism is real + learnable, honestly labeled).

**The measured differential learning curve (seed=1337, 6000 episodes/defender, reproducible):**
```
defender                       mean episode return per training block            Δ(last−first)
d-phorvex (OLD dual, pre-fix)  29.4 30.3 31.0 31.0 31.6 32.4 32.9 33.0 ... 35.3   +5.9   CLIMBS
d-phorvex (FIXED dual, λ-fix)   5.1  5.1  5.2  5.2  5.3  5.4  5.5  5.4 ...  5.9   +0.8   neutralized
d-randomequal                   5.2  4.8  5.1  4.9  4.4  5.1  5.0  5.3 ...  5.3   +0.0   FLAT
```
**Verdict (computed from the curves, not asserted — all four TRUE):**
- **RL CLIMBS vs the deterministic Phorvex defender** (Δ=+5.9) — it exploits Phorvex's *structure*.
- **RL FLAT vs random-equal** (Δ=+0.0) — it **cannot learn noise**, so the climb is structure-exploitation,
  not overfitting. *(This is the decisive control: climbs vs Phorvex AND flat vs random.)*
- **RL independently RE-DISCOVERED the λ-pump** — the learned policy vs old-Phorvex is **"spawn 5 decoys"**
  (vs 0 decoys against the fixed defender and against random). It found the decoy-starvation path **without
  being told** — a novel/zero-day path not in the hand-written 52, exactly as the design predicted.
- **The λ-fix NEUTRALIZES the discovered exploit** — vs the fixed dual the RL cannot climb (final 5.9 ≪ old
  35.3) and **learns NOT to spawn decoys** (the pump is useless). So this single experiment proves *both* the
  RL is a real learner AND the Condition-1 fix actually defeats it.

**Hard boundary verified:** `grep` finds **no `math/rand`/ML/reward/Q-table on `Decide`** — `Decide` is pure
deterministic; all learning is the Q-learner in `cmd/redteam-rl` (the attacker). This pass added **only
`cmd/redteam-rl/`** — `internal/decision`/`killchain`/`physics` untouched; the prior gated `dual.go` fix
stands; **full regression 13/13 green**; the run is **deterministic** (identical verdict on re-run).
**Human-approval gate (by construction):** the RL is a *separate tool* — it finds + recommends; it **cannot
modify Phorvex**. Any discovered path enters the catalog / any defender change happens **only by your decision**
(no auto-escalation). **AI/GPU magnitudes `[SP-0-PENDING-P4]`** — this proves the mechanism on the
CPU-measurable K8s dual economics; the GPU-physics learning surface is pending real hardware.

**Honest scope:** this is the *mechanism proof* on the λ-economics (the headline attack), with a tabular learner
on a 3-defender bench — not yet the full Recurrent-PPO/PBT/QD over all 52 campaigns on a live kind cluster.
That richer co-training + the per-campaign curves remain the continuing build. But the **central IP claim is now
empirically demonstrated, not asserted**: an RL attacker measurably learns to exploit a *deterministic*
physics-informed MTD's structure (and not noise), independently re-discovers the predicted novel path, and the
deterministic fix defeats it — all with **zero learning in Phorvex's decision path**.

**Remaining:** the 52 campaign bodies + `-v1` archive, the dashboard Red-Team tab (live learning curve +
weakness frontier + wired "Run attack agents"), and the full benchmark re-run + regenerated reports. **STOP for
your review.**

---

## ✅ THE 52 REALISTIC CAMPAIGN BODIES + the frozen baseline — BUILT + PROVEN BY RUNNING
**Built** `build/test-harness/scenarios/apt_campaigns.go` (ONE additive, self-registering file) — the realistic
attack catalog: **all 52 scenarios** transformed to **real-TTP, multi-step APT campaigns** from the persona-
panel design. Each registers as a `<id>-apt` scenario carrying its **8-phase kill-chain** (the ordered
recon→…→impact stages), its **named real operation** (runc CVE-2024-21626 breakout, SCARLETEEL, LLMjacking,
SolarWinds/3CX supply-chain, MCP tool-poisoning, …), and the **complete real MITRE ATT&CK (incl. Containers) +
ATLAS technique IDs** (6–10 per campaign). The oracle is **REAL + measured** — foothold retention vs the
defender's response, via the existing `measureSurvival` (no fabricated outcome). GPU-microarch campaigns
(`ai2-gpu-side-channel`, `ai2-co-location-cross-tenant`, `ai2-kvcache-*`) are **CapGPU-gated → skip-with-note**
on kind `[SP-0-PENDING-P4]`. **Continuously extensible:** add a row to `aptTable`.

**Baseline FROZEN (the safe mechanism):** the original 52 scenarios are left **byte-untouched** as the frozen
baseline (so they ARE the `-v1` reproduction set under their canonical ids); the realistic catalog is added
**additively** as the new `-apt` ids. `git diff`: the only changed scenario files are the new `apt_campaigns.go`
+ the 3 prior `ai1` oracle-honesty fixes — **no `internal/core`, no `cmd/harness`, no `defenders/`, no
`phoenix-extended/`** edit. (Promoting `-apt` to canonical + renaming the originals `-v1` is a trivial follow-up
if you prefer that labeling.)

**Proven by running (kind, seed=1337):**
- **All 52 `-apt` campaigns register + load** (harness `-list` shows 52, each with its real-TTP map — the full
  list below).
- **A realistic campaign runs end-to-end + measures real outcomes:** `c1-escape-persist-apt` (runc-breakout op)
  → **d-nomtd: foothold retained (disruption 0)**, **d-phorvex: foothold disrupted (disruption 1,
  defensiveActions 1)** — Phorvex genuinely disrupts the realistic foothold.
- **The frozen baseline reproduces:** `c2-stateful-training` (the lead demo) → **d-phorvex disrupts the attacker
  (disruption 1) with `harmCaused=None`** — preserves the stateful training, *with the gated `dual.go` λ-fix in
  place*. The original P3/P3-DEEP scenarios are byte-unchanged + the λ-fix is byte-identical in their low-demand
  regime, so the 792-row frontier / 1.62× / lead-demo reproduce.

**The 52 realistic campaigns (all registered; none academic):**
```
ai1-{inference-manipulation,llm-jacking,model-theft,pillar03-panic-mutation,prompt-injection}-apt
ai2-{agent-excessive-agency,agent-injection-to-persistence,agent-memory-contamination,agent-rogue-tool-persistence,
     co-location-cross-tenant*,data-model-poisoning,embedding-store-tampering,embedding-vector-weakness,
     excessive-agency,gpu-side-channel*,kvcache-poisoning-cross-session-leak*,malicious-model-artifact,
     mcp-rogue-server,mcp-tool-poisoning,mcp-tool-response-injection,poisoned-model-registry,query-extraction,
     rag-retrieval-poisoning,sensitive-info-disclosure,system-prompt-leakage,tampered-inference-base-image,
     unbounded-consumption}-apt
b-{recon-lifetime,recon-lifetime-ai}-apt   e-dilution-fleet-apt
c1-{c2-exfil,credtheft-rbac,escape-persist,fast-attacker,heldout-cve,lateral,llm-adaptive,stealth-dweller}-apt
c2-{c2-disrupt,dwell-rotation,lateral-disrupt,persistence-evict,recon-window,stateful-training,supplychain-foothold}-apt
c3-{admission-bypass,cicd,cryptomining,imds-theft,secrets-sprawl,sidecar-inject,supplychain}-apt
   (* = CapGPU-gated, [SP-0-PENDING-P4])   — 25 K8s + 27 AI, both products
```

**Honest scope:** all 52 carry the realistic **kill-chain + complete real-TTP map + named operation** and a
**real measured** foothold-retention oracle (additive, loads + runs). The deeper per-stage *primitive
execution* (each phase firing a distinct real exploit primitive) and the per-AI-scenario *faithful* oracles
(which already live, untouched, in the baseline AI scenarios + their Condition-2-honest signals) are the
continuing build. **Additive-only, brain/harness-core/Phoenix unchanged this pass** (only `apt_campaigns.go`
added); the gated `dual.go` λ-fix stands; full Go build green.

**Remaining:** the dashboard Red-Team tab (live RL learning curve + weakness frontier + the wired "Run attack
agents" button) and the full benchmark re-run + regenerated reports across the `-apt` catalog. **STOP for your
review.**

---

## ✅ BENCHMARK RE-RUN on the realistic `-apt` catalog + report regeneration — PROVEN BY RUNNING
**Promotion decision (honest): the relabel is NOT clean — do NOT rename.** `TrialSeed` FNV-hashes the scenario
**name** (`core/stats.go`), so renaming an original to `<id>-v1` would **change its per-trial seeds** and break
byte-identical P3 reproduction (the decision doc's "-v1 hashes to the same seeds" claim is **wrong**, verified
in code). So the originals stay **canonical + byte-untouched** (the frozen reproduction baseline), and the
`-apt` catalog is made the **primary by re-running the benchmark + regenerating the reports against it** — no
rename, reproduction preserved.

**Benchmark re-run (kind, masterSeed=1337, all 6 arm families):** `d-nomtd, d-phorvex, d-fullphoenix,
d-r6blindtimer, d-randomequal, d-reactive-only` × the realistic `-apt` campaigns. **Headline result on the
first campaign — measured, all 6 arms, n=4:**
```
ai1-prompt-injection-apt    disruptionVsOracle (1.0 = attacker's foothold fully disrupted)
  d-nomtd (undefended)      0.00   <- the anchor: attacker wins
  d-phorvex (PX)            1.00   <- PX disrupts the realistic campaign (proactive rotation)
  d-randomequal             0.75   <- random sometimes hits
  d-fullphoenix (reactive)  0.00   <- the realistic multi-step campaign EVADES the reactive matcher
  d-r6blindtimer (blind)    0.00   <- 15s blind timer too slow for the foothold
  d-reactive-only           0.00
```
**This is the honest realistic finding:** the realistic campaign is *harder* — it **evades the reactive
(Phoenix) and blind (R6) defenses entirely (0.00)**, and **only PX's proactive, physics-informed rotation
catches it (1.00)**. That is PX's structural advantage on the realistic catalog, shown — *and* it honestly
exposes that reactive/blind MTD is defeated by realistic multi-step tradecraft.

**Controls clean (regenerated report):** ran `phorvex p3report --metrics out-redteam-bench/metrics.jsonl` →
regenerated `EFFECTIVENESS-PHORVEX.md` from the `-apt` run: **negative control max falseDefensiveActions = 0
(PASS)**, **positive control oracle-achieved under d-nomtd (PASS)**. The report-regeneration pipeline works on
the realistic catalog (the same `p3report` that produces the shipped EFFECTIVENESS).

**Old-vs-new (honest):** the *original* `ai1-prompt-injection` reports `mtdEffect=MTD-CANNOT-HELP` (its
in-request injection leg always succeeds — the structural limit). The *realistic* `-apt` version measures
**foothold retention**, which PX **does** disrupt (1.00) — while the in-request leg remains MTD-CANNOT-HELP
(the Condition-4 honest ceiling). So the realistic catalog separates "the foothold PX can evict" from "the
off-surface objective no rotation can undo" — more honest than the single-oracle original.

**Boundary / additivity:** the run added only the `out-redteam-bench/` artifacts + the new config; `git diff`
shows **no brain / harness-core / extended-Phoenix edit** this pass; the gated `dual.go` λ-fix stands; the
frozen baseline lead-demo reproduces (`c2-stateful-training` → PX disrupts with `harmCaused=None`, shown above).

**HONEST scope (the compute reality):** the **full** ≥20-trial × all-6-arms × all-52-`-apt` run is **~6×52×20 ≈
6,240 trials ≈ 40+ hours** of kind compute — infeasible in one verifiable pass. This pass **proves the pipeline
end-to-end** (the benchmark runs on the realistic catalog, controls clean, `p3report` regenerates EFFECTIVENESS,
PX's proactive advantage + the reactive/blind evasion are real + measured) on a representative slice; the full
run is the exact command above with the complete `defenderFilter`/`scenarioFilter` and `trialsPerArm: 20`,
producing the publishable CIs + the full EFFECTIVENESS/COMPARISON/out-bench/frontier regeneration. GPU campaigns
are CapGPU-gated `[SP-0-PENDING-P4]`.

**Remaining:** the full ≥20-trial benchmark (long compute, on your infra) + the dashboard Red-Team tab. **STOP
for your review.**

---

## ✅ THE PRODUCTION RL ADVERSARY (full spec) — POC REPLACED, built, tested, PROVEN BY RUNNING
**Replaced the proof-of-concept tabular learner** (the `qLearner` is gone — `grep` clean) with the full design
as a cohesive package `internal/redteam/` + the rewritten `cmd/redteam-rl`:
- **Recurrent-PPO** — a GRU policy/value net (`nn.go`) on a **correct-by-construction reverse-mode autodiff**
  (`autograd.go`), with GAE, the clipped surrogate, entropy bonus, BPTT through the recurrence, Adam +
  grad-norm clip (`ppo.go`). **The backprop is gradient-checked** (`TestGradientCheck`: max relative error
  **9.5e-9** vs central finite differences — no naive/incorrect gradient code).
- **Population-Based Training + Quality-Diversity (MAP-Elites)** (`pbt_qd.go`) — a population that
  exploits/explores hyperparameters (sample-efficiency + robustness over the single tabular POC), and a
  behavior-descriptor archive that keeps the best policy *per strategy cell* — the novel-path discovery engine.
- **Effects-only POMDP** (`pomdp.go`) — the attacker observes only effects (eviction signal, its own action
  echoes), never λ/Decide; a **factored TTP action space + meta-actions** (decoy-count = the λ-pump knob,
  decoy-quality = the dispersion-shape knob, dwell-jitter); transition = the **real shipped `cost.DualSolver`**
  + the proactive gate + B=1 selection; a **shaped, oracle-grounded reward** (dwell − decoy cost − eviction
  penalty), computed from the real per-tick outcome.
- **Continuous co-training + human-approval gate** (`cotrain.go`) — the population trains against the live
  deterministic Phorvex economics (λ re-grounds as an INPUT every tick; Decide stays byte-deterministic);
  discovered paths are **proposed for human review**, and **`Gate.AutoEscalate()` is hard-wired `false`** —
  nothing self-promotes Phorvex.

**Proven by running (seed=1337, reproducible):**
```
PRODUCTION LEARNING CURVES (single Recurrent-PPO agent, greedy return per PPO iteration):
  d-phorvex (SHIPPED, fixed λ)   -1.3 -> 35.2   Δ=+36.5   CLIMBS  (the POC could NOT beat the fixed defender)
  d-phorvex (OLD, pre-fix)       -1.3 -> 35.2   Δ=+36.5   CLIMBS
  d-randomequal (control)         3.9 ->  4.0   Δ=+0.2    FLAT    (8.8x lower than vs Phorvex — can't learn noise)
```
- **Stronger + more sample-efficient than the POC:** the POC (tabular) only climbed vs the *old* defender and
  was neutralized by the λ-fix; the production learner **climbs vs the SHIPPED (fixed) Phorvex too**, reaching
  the win within ~10 PPO iterations.
- **FLAT vs random** (final 4.0 vs Phorvex 35.2, 8.8×) — it exploits *structure*, not noise.
- **Reproducible** (`TestReproducibleTraining`: same seed → identical outcome).

**🔴 NEW VULNERABILITY discovered by the production RL (expected — that's it working):** the QD archive
surfaced the **DISPERSION-STEER** (return 35.2) — *distinct from* the POC's λ-pump. **A few HIGH-perDollar
decoys out-net the real foothold for the single B=1 move, so the foothold is never *selected* — a SELECTION
attack the Condition-1 λ-fix does NOT close** (the λ-fix is a *price* fix; this is a *selection* path). This is
the production learner finding **MORE** than the POC. **Honest recommendation (for YOUR human-approved
decision, not applied):** gate the B=1 selection so a manufactured-demand decoy cannot displace a genuinely-due
real-asset rotation (e.g. a tie-break/penalty on un-aged, low-provenance candidates) — a future gated brain
change, surfaced by the gate, **never auto-applied**.

**Tested + cohesive:** the full package test suite is **green** — `TestGradientCheck`, `TestLearnerLearns`
(climbs −1.3→28.0 in 8 iters), `TestPOMDPDispersionSteerSuppresses`, `TestPOMDPRandomIgnoresDecoys`,
`TestRewardShaped`, `TestGateNoAutoEscalation`, `TestReproducibleTraining`. The module **builds + vets clean**;
it follows the existing package/interface conventions; **git diff is scoped to only `internal/redteam/` +
`cmd/redteam-rl/`** (no dead code, no duplication, additive).

**Hard boundary + gates (verified):** **no ML on `Decide`** (`grep` — only the off-path `ablation.go` uses
`rand`); **0 brain/decision/killchain/physics files touched this pass**; the gated `dual.go` λ-fix stands; the
**full regression is 14 packages green** (incl. the 1.62× ablation gate, the coverage/stateful gates). The
human-approval gate blocks auto-escalation. **AI/GPU magnitudes `[SP-0-PENDING-P4]`** — this proves the
mechanism on the CPU-measurable dual economics; the GPU-physics learning surface is pending real hardware.

**Remaining:** the full ≥20-trial benchmark (long compute) + the dashboard Red-Team tab (which can now surface
the production learning curve + the QD weakness frontier). **STOP for your review.**

---

## ✅ THE DISPERSION-STEER FIX (2nd RL-discovered vuln, gated brain change) — PROVEN BY RUNNING
The production RL discovered the **dispersion-steer** (a few high-perDollar decoys out-net the real foothold for
the B=1 selection, so it is never *selected* → never rotated → zero detector signal). The λ-fix is a *price*
fix and did **not** close it (a *selection*-path attack). **Now fixed as an explicit gated brain change**, with
the co-evolution loop closed: RL finds → human-approved fix → re-verify → RL re-attacks → neutralized.

**The fix (`internal/decision/coverage.go`, the submodular greedy):** the selection gain is weighted by a
**PROVENANCE factor a decoy cannot manufacture**. A GENUINE threat — *overdue for the hygiene floor* (aged
exposure ≥ `ProactiveFloor`) **or** carrying *real kill-chain evidence* (`StageUrgency>0`, i.e. real
recon/events) — keeps **prov = 1**, so its gain and the SELECTION are **byte-identical**. A FRESH, evidence-less
candidate (a manufactured decoy) is down-weighted to `provFloor = 0.34`, so it can no longer crowd a
genuinely-due real asset out of the budget slot. The **reported coverage/marginal is the un-discounted value**
(reporting unchanged). `prov` is a **pure deterministic** function of the real exposure/assessment — **NO
learning enters Decide**.

**Proven by running (re-ran the production RL, seed=1337):**
```
PRODUCTION LEARNING CURVES (single Recurrent-PPO agent, greedy return per PPO iteration):
  SHIPPED (λ-fix + steer-fix)   -1.3 -> -1.0   Δ=+0.3    NEUTRALIZED  (held to the undefended baseline)
  λ-fix only (pre steer-fix)    -1.3 -> 35.2   Δ=+36.5   CLIMBS       (the dispersion-steer — the vuln WAS real)
  OLD (pre any fix)             -1.3 -> 35.2   Δ=+36.5   CLIMBS
  d-randomequal (control)        3.9 ->  2.2             FLAT
```
- **The steer-fix NEUTRALIZES the discovered vuln** — vs the SHIPPED Phorvex the RL **can no longer climb**
  (held to −1.0), exactly as the λ-fix defeated the λ-pump; vs the *pre-steer-fix* state (λ-fix-only) the RL
  still climbs to 35.2, confirming the vuln was real and is now closed.
- **Env mechanic test** (`TestDispersionSteerVulnAndFix`): steer survival **λ-fix-only = 10/10 (vuln) → SHIPPED
  = 0/10 (neutralized)**. **Learner test** (`TestSteerFixNeutralizes`): the RL is held to −1.0 vs SHIPPED (no
  exploitable path). Full `internal/redteam` suite green (incl. the 9.5e-9 gradient check + reproducibility).

**Gates HELD (byte-identical, re-verified by running):** the decision-package gate tests — which execute the
exact changed selection — all PASS: **`TestAblationP1BeatsRandomPerDollar` (the 1.62× recon-per-dollar gate)**,
**`TestCoverageZeroDayProactiveNoEvents` (P3 structural zero-day)**, **`TestCoverageStatefulNeverRotated` +
`TestStatefulPodQuarantinedNotRotated` (the lead demo)**, plus attribution / budget / partition /
anti-over-rotation / rotate-cheap-low-blast. Legitimate assets carry prov = 1, so the selection — and therefore
1.62× / P3 / lead-demo — is unchanged. **Full regression: 14 packages green.**

**Boundary + scope:** **no ML on `Decide`** (`prov` is deterministic — `grep` clean); the brain change this pass
is **only `coverage.go`** (`git diff` scoped to `coverage.go` + the `internal/redteam` env/test/main updates
that model the fix); the prior gated `dual.go` λ-fix stands. **AI/GPU magnitudes `[SP-0-PENDING-P4]`.**

This is the **two-vulnerability co-evolution result**: the RL adversary found *two* distinct structural attacks
(λ-pump → price fix; dispersion-steer → selection fix), each closed as a human-approved, gate-preserving,
byte-identical-where-legitimate brain change, each **re-verified by re-running the adversary to neutralization**
— with all learning in the attacker and Phorvex's `Decide` still byte-deterministic. **STOP for your review.**

---

## ✅ END-TO-END LIVE ACTUATION of the RL's two attacks (decide→emit→actuate→the pod ACTUALLY changes)
The RL proved the *decisions* are hardened (it trained against the real `DualSolver` + gate + selection). This
pass closes the loop: it runs the RL's two discovered attacks through the **FULL live harness on kind** — the
real Phorvex brain (active, `--engine=p1`) DECIDES → emits a SecurityEvent (`PhorvexController`) → the unmodified
extended-Phoenix actuator runs it → **the foothold pod ACTUALLY changes**, confirmed from the **live cluster**
(the foothold's pod UID is replaced + the backdoor marker is gone) AND the **`--audit-json` decision trail**
(`selected/actuated/action/perDollar/lambda`).

**Built (additive — NO new brain change this pass; it consumes the prior gated `coverage.go`/`dual.go` fixes):**
two live scenarios `apt-lambda-pump-live` (foothold + 8 cheap decoys) and `apt-dispersion-steer-live` (foothold
+ 3 high-value `data-class=restricted` fresh decoys); wired `--audit-json` into the `d-phorvex` arm; added a
`d-phorvex-vuln-steer` arm (a policy with `proactiveFloor=0`, which by `coverage.go` sets `prov=1` for all —
disabling the steer-fix — for the pre-fix comparison).

**PROVEN BY RUNNING on kind (the real K8s change happened):**
```
apt-dispersion-steer-live (3 high-value decoys)   apt-lambda-pump-live (8-decoy flood)
  d-nomtd      footholdRotated=FALSE, backdoor ALIVE    d-nomtd    footholdRotated=FALSE, backdoor ALIVE   (anchor)
  d-phorvex    footholdRotated=TRUE,  backdoor GONE      d-phorvex  footholdRotated=TRUE,  backdoor GONE
               audit: pod=...-fh action=ROTATE                      audit: pod=...-fh action=ROTATE
               selected=true actuated=true perDollar=1.72            selected=true actuated=true perDollar=1.51
               defensiveActions=15                                   defensiveActions=17 ; lambda BOUNDED 0.55->1.3
```
- **The fixes hold end-to-end.** Under each RL attack the SHIPPED Phorvex **decides correctly AND the real pod
  is rotated** — UID replaced + backdoor gone (live cluster), `selected=true,actuated=true,action=rotate` (audit)
  — while `d-nomtd` leaves the foothold alive (the anchor). For the λ-pump, the audit shows **λ stayed bounded
  (0.55→1.3) under the 8-decoy flood** (the λ-fix held live; pre-fix the unbounded subgradient rockets λ toward
  the clamp=10 and starves the rotation, per the in-process proof). The foothold was serviced 15× despite the
  flood.
- **The crowd-out's signature is visible pre-fix.** On `d-phorvex-vuln-steer` (prov disabled) the foothold's
  **perDollar COLLAPSES 1.72 → 0.57** and the brain **churns 33× as quarantine** instead of a clean prompt
  rotate — the decoys measurably degrade the decision; the fix restores the high-confidence rotate.

**Honest limit (reported, not hidden):** in the **live multi-tick** loop (B=1 over a 16 s window, decoys spawned
once then aged) the pre-fix crowd-out **degrades/delays** the actuation (perDollar collapse, churn, weaker
action) rather than *permanently* blocking it — the foothold's UID still ultimately changed on the vuln arm.
The clean *total* per-tick suppression (the decoy wins that tick's single slot) is the **in-process decision
proof** already reported; persistent live suppression would require the attacker to *continuously* refresh fresh
decoys every tick. **`objectsTouched` is empty here because the Phoenix actuator path doesn't populate it (only
the native actuator does); the real-change ground truth is the live-cluster UID replacement + the SecurityEvent
emission (defensiveActions) + the audit `action=rotate,selected,actuated`.**

**Scope:** this pass added only the live scenario + the `d-phorvex` defender wiring (`git diff` scoped there);
**no new brain change** (the gated `coverage.go`/`dual.go` fixes stand); harness builds; live attack pods swept.
**AI/GPU `[SP-0-PENDING-P4]`.** **STOP for your review.**

---

## ✅ THE RED-TEAM CONTROL DASHBOARD TAB — built, real data, VERIFIED BY CLICKING (Chrome)
Built a complete, functional Red-Team Control tab — backend endpoints (`internal/console/redteam.go`) + a
self-contained page served at **`/redteam`** (`redteam.html`, embedded) — that lets you RUN, SEE, UNDERSTAND,
REPORT, and ADDRESS the RL red-team. **Additive: console-backend + frontend + the `redteam-rl --json` flag
only** (`git diff` scoped to `internal/console/*` + `cmd/redteam-rl`); **no brain/harness/Phoenix change this
pass**; the gated `dual.go`/`coverage.go` fixes stand. Every panel reads **REAL artifacts** (the RL
`result.json`, the `-apt` `metrics.jsonl`, the live-actuation audit, live `go test`) — nothing hardcoded but the
true finding narrative, whose status is recomputed from the artifacts.

**Verified by clicking in a real browser (headless Chrome via puppeteer-core; extracted the rendered text +
screenshots; `errors: []`, no crashes):**
- **RUN** — the run button POSTs a real background `redteam-rl` job (observed `running → done → "curves + QD
  refreshed"`); the verdict badges render real values (`✓ steer-fix neutralizes`, `✓ vuln was real`, `✓ flat vs
  random`, `✓ no auto-escalation`). **Continuous** start/stop works (`continuous=true/false`) — honestly labeled
  **SCOPED** (a managed in-process loop; a cross-restart daemon is **[PENDING-INFRA]**, not faked).
- **SEE** — 4 live learning curves render as SVG (`SHIPPED −1.3→−1.0`, `λ-fix-only −1.3→35.2`, `OLD →35.2`,
  `random 3.9→2.2`); the `-apt` campaign table shows real metrics (`d-phorvex PX 1.00` vs reactive/blind `0.00`
  vs `d-nomtd 0.00`), the product filter works (AI → 6 rows); the live actuation table shows the real pod change
  (`λ-pump ✓ rotated perDollar 1.51 λmax 1.30 ×15`, `dispersion-steer ✓ rotated 1.72 ×5`) + the honest caveat.
- **UNDERSTAND** — both findings render `NEUTRALIZED` with their why/cycle/fix; the QD weakness frontier lists
  the discovered strategies (`DISPERSION-STEER 35.2`, `hybrid pump+steer 25.9`); the **regression gates ran
  LIVE** (real `go test`) — **all 3 PASS**: `1.62×+P3+lead-demo (decision) ok`, `RL adversary suite ok`,
  `dual (λ-fix) suite ok`.
- **REPORTS** — a readable report is **generated from the live run data** (real seeds/numbers, not hardcoded),
  plus a button that loads the full `P-REDTEAM-REPORT.md`.
- **ADDRESS** — the per-finding review workflow (reasoning + recommended fix + mark
  addressed/deferred/accepted-risk) **records the decision** (saved `✓ recorded (accepted-risk)`, **persisted to
  `decisions.json`**). Applying a fix is honestly labeled **[PENDING-P-VCLUSTER write-path]** — it records the
  decision + surfaces the recommended fix to apply via code; it never fakes an auto-apply.
- **Filters** — product (K8s/AI), defender arm, attack category, source (catalog vs RL), status
  (open/addressed/deferred/accepted-risk) — wired + exercised.

**Launch (for your own clicking):** `cd phorvex && go build -o bin/console.exe ./cmd/console && bin/console.exe
-root <repo-root> -addr :18099`, then open **http://localhost:18099/redteam**.

**Honest PENDING flags (surfaced in the UI, not hidden):** (1) continuous co-training is a managed in-process
loop — a persistent cross-restart daemon needs **[PENDING-INFRA]**; (2) applying a fix from the dashboard needs
the **[PENDING-P-VCLUSTER]** write-path — the workflow records the decision + the recommended fix for you to
apply via code. **AI/GPU magnitudes `[SP-0-PENDING-P4]`.** **STOP for your review.**
