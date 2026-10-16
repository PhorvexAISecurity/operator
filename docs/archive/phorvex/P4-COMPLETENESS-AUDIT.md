# P4-COMPLETENESS-AUDIT — is the AI/GPU actuator SET complete + correct? (analysis only)

**Question.** A $100M product claim — "Phorvex can rotate any AI/GPU workload" — rests on the 5-handler set
{warm-swap, kv-reset, endpoint-rotate, mig-rebind, model-shard-replace}. That set was *assembled*, never
*rigorously verified for completeness*. This audit verifies it against how real serving stacks
(vLLM / Triton / TGI / TensorRT-LLM) actually work, by reasoning + code. **No handler code is written** — missing
actuators are *designed* and left for approval.

**Persona panel (leading):** AI-Engineer, GPU-expert, MLSecOps, Cloud-engineer, Pen-tester, MTD-expert,
Physics-informed-AI. **Method:** an MTD actuator set is *complete* iff, for every class of **persistable
attacker state** in the serving stack, **some** actuator can evict/perturb it. So the audit enumerates the
state classes, maps each to an actuator (or a gap), then premortems "what survives?" and steelmans both verdicts.

---

## VERDICT (up front)

**The set is substantially correct but NOT complete, and two of the five are under-built beyond
`[PENDING-GPU-VALIDATION]`.**
- **Missing — a real survival gap:** **adapter/LoRA-rotate** (an attacker's poisoned LoRA adapter survives
  *every* current move). Strong, build-it.
- **Missing — second-tier, real:** **request-drain / in-flight-abort** (request-granular eviction; also closes
  warm-swap's unimplemented drain) and **guardrail/filter-rotate** (MTD for the safety tier). Build after LoRA.
- **Watch-item — emerging:** **disaggregated KV-migrate/invalidate** (P/D-split serving). Design now, defer.
- **Correctly subsumed (NOT new handlers):** quantization-variant swap, tokenizer/template swap,
  speculative-decode reset, golden-weight reload — these are *parameters* of warm-swap/kv-reset, not mechanisms.
- **The completeness invariant does NOT prove AI coverage** — it proves "no *declared* action lacks a handler"
  over a human-curated list; it is structurally blind to a *missing* mechanism (Q2).
- **Build maturity is uneven:** endpoint-rotate is real-and-complete; kv-reset real-but-pending; warm-swap
  real-but-pending with an unimplemented drain; **model-shard-replace is partial (no TP/PP coordination);
  mig-rebind is partial — its execution transport is UNBUILT (no real `nodeRunner` exists; it always
  fail-closes).** (Q3)

---

## Q1 — Is {5} complete for modern AI/GPU serving?

### The persistable-state classes and their actuator (the completeness map)

| # | Persistable attacker state | Real stack mechanism | Actuator that evicts it | Status |
|---|---|---|---|---|
| 1 | **Serving replica** (base weights in VRAM, the running process) | pod / engine replica | **warm-swap** | ✅ covered |
| 2 | **Cross-session prefix cache** (poisoned shared prefix leaks to other users) | vLLM **APC** `--enable-prefix-caching` | **kv-reset** (`/reset_prefix_cache`) | ✅ covered (this is the dangerous one) |
| 3 | **Network route / endpoint** (learned inference URL, selector) | K8s Service / EndpointSlice | **endpoint-rotate** + route-rotate Service restitch; identity-rotate is declared-only | route path implemented; target fixture required |
| 4 | **GPU partition / co-residency** (MIG-slice neighbor, side-channel) | NVIDIA MIG geometry | **mig-rebind** | ◐ designed, transport unbuilt (Q3) |
| 5 | **Model shard** (a replica / a TP-PP rank) | TP/PP sharded serving | **model-shard-replace** | ◐ partial — independent-shard only (Q3) |
| 6 | **LoRA / adapter** (poisoned fine-tune adapter in the multi-LoRA cache) | vLLM `/v1/{load,unload}_lora_adapter`, LoRAX, Triton EXPLICIT load/unload, TGI `--lora-adapters` | **— NONE —** | ❌ **MISSING (survival gap)** |
| 7 | **In-flight / queued request** (an abusive streaming session, a mid-chain jailbreak) | vLLM continuous-batching scheduler; `AsyncLLMEngine.abort(req_id)` | **— NONE —** (warm-swap drops in-flight ungracefully, replica-granular) | ❌ **MISSING (2nd-tier)** |
| 8 | **Guardrail / safety filter** (a found jailbreak that bypasses the current filter) | Llama Guard / NeMo Guardrails as a separate model/ruleset | **— partial —** (warm-swap if it's a pod; ruleset rotation unmodeled) | ◑ **PARTIAL / MISSING (2nd-tier)** |
| 9 | **Disaggregated KV transfer** (poisoned KV migrated prefill→decode) | vLLM P/D `--kv-transfer-config`, Dynamo, Mooncake, LMCache | **— NONE —** (kv-reset is local-only) | ◔ **EMERGING (watch)** |

### The MISSING mechanisms — justified against real stack behavior

**(6) Adapter / LoRA-rotate — the strongest gap.**
Multi-LoRA serving (vLLM `--enable-lora --max-loras N`; LoRAX; Triton model-control EXPLICIT; TGI adapters) keeps
many LoRA adapters resident on ONE base model and loads/unloads them at runtime (`POST /v1/load_lora_adapter`,
`POST /v1/unload_lora_adapter`). An attacker who gets a **poisoned/backdoored adapter** loaded (LLM03 supply
chain, a malicious fine-tune, adapter-injection) persists in the **adapter weights** — which are NOT the base
replica and NOT the cache. **Why no existing handler evicts it:** warm-swap rotates the *base* replica
(expensive base reload) and a fresh replica **re-loads the same poisoned adapter from the registry** → the
attacker survives warm-swap. kv-reset flushes cache, not weights → survives. model-shard-replace targets shards,
not adapters. **There is no move that unloads/rotates a specific adapter.** Distinct API, distinct economics
(no base reload — ~100–1000× cheaper than warm-swap), distinct attack surface that is *growing fastest*
(adapter/fine-tune marketplaces, per-tenant LoRA). **This is a genuine survival gap, not a parameter.**

**(7) Request-drain / in-flight-abort — request-granular eviction.**
vLLM/TGI use continuous batching: in-flight sequences live in the scheduler's running batch; the engine can
`abort` a specific request. The current set has **no request-granular move** — to evict one abusive streaming
session you must warm-swap the whole replica (collateral on every legit request), and warm-swap's **drain is
unimplemented** (`handlers_ai.go:141` "the connection-drain window is recorded, not slept here" → the old leader
is deleted with in-flight requests still running → ungraceful drop). So this is *both* a missing standalone move
(abort one session) *and* the fix for warm-swap's drain gap.

**(8) Guardrail / filter-rotate — MTD for the safety tier.**
The #1 LLM attack class is the jailbreak that bypasses the *current* guardrail (Llama Guard, NeMo Guardrails, a
content filter). The defensive MTD move is to **rotate the guardrail** (different filter model / re-ordered or
re-keyed ruleset) so a found bypass stales. The guardrail is usually a *separate* pod/service: warm-swap could
rotate the pod *if* modeled as a swap-group, but **ruleset-level rotation is unmodeled**, and the guardrail tier
isn't a first-class target. Real, deployment-dependent — 2nd-tier.

**(9) Disaggregated KV-migrate/invalidate — emerging.**
P/D-disaggregated serving (vLLM `--kv-transfer-config`, NVIDIA Dynamo, Mooncake, LMCache) moves KV across workers
over RDMA/NVLink. kv-reset flushes the *local* cache only; it does not invalidate KV in transit / on a remote
decode worker. Niche today, growing fast — design now, defer build.

### Correctly SUBSUMED (do NOT add handlers — justified)

- **Quantization-variant swap (fp16↔int8↔awq/gptq):** a model-*artifact* swap → **warm-swap with a different
  target artifact**. A parameter, not a mechanism. (Defensive value real — break a precision-specific exploit —
  but mechanically identical to warm-swap.)
- **Tokenizer / chat-template swap:** the template ships *with* the model (HF `chat_template`/`tokenizer_config`)
  → **warm-swap** (bundled). Standalone template-only rotation is niche/low-priority.
- **Speculative-decode draft reset:** the draft model's state → **kv-reset scope** (extend the flush to the draft
  cache) or warm-swap (draft is part of the replica). Niche.
- **Golden-weight reload / re-attestation:** reload from the trusted registry → **warm-swap**; the *attestation*
  (verify the loaded hash) is a **check** belonging in feasibility/verification, not an actuator.
- **Prefix-cache vs full-KV:** NOT a new handler — a **scope clarification**. APC prefix cache (cross-session) =
  kv-reset (covered, correctly). Per-sequence in-flight KV = evicted by request-abort (item 7). So the
  distinction maps onto {kv-reset (have) + request-abort (missing)}.
- **Sampling/seed rotation:** changes output determinism, not a persistable-state eviction → out of MTD scope.
- **Agentic tool-sandbox / tool-credential rotation (MCP/agent runtimes):** these are **pods** → covered by the
  *base K8s handlers* (rotate, identity-rotate, route-rotate, quarantine) + warm-swap. The AI/GPU set is
  serving-focused by design; the agentic side leans on the K8s tier. (Boundary noted, not a gap.)

### Premortem — "what AI-rotation lets an attacker SURVIVE?"
Walking every state class: replica→warm-swap, prefix-cache→kv-reset, route→endpoint-rotate, GPU-slice→mig-rebind,
shard→model-shard-replace all evict. **What survives:** (a) a **poisoned LoRA adapter** — survives warm-swap
(re-loaded from registry), kv-reset (it's weights), model-shard-replace (not an adapter) → **clean survival**;
(b) an **abusive in-flight session** — only ungraceful whole-replica eviction, re-establishable; (c) a
**guardrail bypass** — keeps working until the filter is manually changed; (d) **in-transit KV** in
disaggregated serving. The premortem **falsifies "complete."**

### Steelman — both sides, which wins

**FOR "5 is complete":** the 5 cover the canonical classes (replica/cache/route/GPU/shard); LoRA/quant/template
are model-artifact variants subsumable by warm-swap-with-a-target; adding near-duplicate moves bloats the action
space + cover model without new physics; feasibility laws self-prune infeasible moves; disaggregated-KV/guardrail
are deployment-specific.

**AGAINST "5 is complete":** adapter state has a **distinct API** (`unload_lora_adapter`) and **distinct
economics** (no base reload) — folding it into warm-swap is *wrong* because warm-swap reloads the base AND a
fresh replica re-loads the poisoned adapter, so warm-swap **does not evict adapter poisoning**; the
physics-informed cost model *needs* the distinct cheap-targeted economics so the optimizer prefers adapter-rotate
when the threat is adapter-resident (folding it hides the cost signal the brain optimizes on); request-abort is
request-granular vs warm-swap's replica-granular (different blast radius → different cover/cost); multi-LoRA is a
*major* 2024-2025 deployment pattern and exactly where the supply-chain attack surface is growing.

**Which wins:** **AGAINST wins on adapter-rotate** (distinct API + economics + a proven survival path — not
subsumed). **FOR wins** on quant/template/seed/golden-reload (genuinely subsumed/out-of-scope). Request-abort and
guardrail-rotate are **real but 2nd-tier**; KV-migrate is **emerging**. Net: **incomplete, with one must-add.**

---

## Q2 — Does the completeness INVARIANT prove AI coverage?

**No — and the name oversells it.** `MissingHandlers()` iterates `actionset.GeneratableActions()` (=
`model.MutatingActions`, a **human-curated list**) and asserts each has a registered handler
(`handler.go:94`, `completeness_test.go`, the `zz_startup.go` startup panic). So it proves exactly:

> **"every action we DECLARED has a handler"** — *no orphan declared actions.*

It does **NOT** prove:

> "the declared set covers the AI action space" — *no missing mechanism.*

Adapter-rotate is **not in `MutatingActions`**, so the invariant is **structurally silent** about its absence —
it cannot fail on a gap it was never told to look for. The invariant is real and useful (it caught the
two-list-drift hazard, and it forces a handler per declared move), but **completeness-of-handlers ≠
completeness-of-mechanisms.** The latter is a **human design judgment** — exactly what this audit performs, and
what must be re-performed whenever the serving-stack threat surface shifts. **Recommendation:** rename the
guarantee in docs to "handler-coverage invariant" and add a periodic **mechanism-coverage review** (this doc as
the template) as the human half.

---

## Q3 — Per-handler maturity (beyond `[PENDING-GPU-VALIDATION]`)

Production uses the **package-default** clients (`native.go:45` builds `EnactCtx{Client,DryRun}` — VLLM/MIG nil →
real `httpVLLM` + `nvidiaSMIMIG{run: unconfiguredNodeRunner}`).

| Handler | Maturity | What's real | The gap beyond pending-validation |
|---|---|---|---|
| **endpoint-rotate** | **real-and-complete (K8s)** | label re-key + Service-selector restitch + rollback; no GPU dependency | none structural — only the "route-reconvergence magnitude" is a *measurement*, not a build gap |
| **kv-reset** | **real-but-pending-validation** | real HTTP POST to the reset route; pod-alive; tri-state | the **vLLM route string** (`/reset_prefix_cache`) is unconfirmed against a live vLLM version (the boundary) |
| **warm-swap** | **real-but-pending-validation; drain partially-built** | shadow-find (vLLM-ready), provision-before-retire flip, retire, **REWARM-to-N** | the **connection-drain phase is unimplemented** (`:141` "recorded, not slept") → in-flight requests dropped ungracefully on retire |
| **model-shard-replace** | **partially-built** | warm-cutover reused on the shard group (single-pod flip) | **no TP/PP coordination** — a tensor/pipeline-parallel group is a *consistency unit*; you cannot swap one rank with an independent flip. Works only for "shard = independent replica" |
| **mig-rebind** | **partially-built — transport UNBUILT** | the nvidia-smi argv sequence + ordering + error-wrap is real and unit-tested | **no real `nodeRunner` exists anywhere** (only `unconfiguredNodeRunner` + a test mock) → in production it **always fail-closes**; *and* the "drain" is **route-relabel only**, not GPU-context eviction (MIG reconfig requires zero CUDA contexts — a relabeled-but-running pod still holds the context) |

**Honest ranking (most→least mature):** endpoint-rotate ▸ kv-reset ▸ warm-swap ▸ model-shard-replace ▸
mig-rebind. The phrase "5 AI actuators built" should read **"1 complete, 2 real-pending (1 with a drain gap),
2 partially-built (shard: no TP/PP; mig: transport unbuilt)."**

---

## Proposed additions (DESIGN ONLY — not built; for approval)

| Rank | Proposed action | Mechanism (real API) | Economics / why distinct | Feasibility law |
|---|---|---|---|---|
| **1** | **`adapter-rotate`** (a.k.a. lora-evict) | vLLM `POST /v1/unload_lora_adapter` (+ reload clean / swap variant); Triton EXPLICIT unload; TGI adapter reload | cheap + targeted (no base reload); the ONLY move that evicts a poisoned adapter | `lora-enabled-required` (pod advertises `--enable-lora` / adapter labels) |
| **2** | **`request-drain`** (in-flight abort + graceful drain) | vLLM `AsyncLLMEngine.abort(req_id)` / scheduler drain; also fills warm-swap's drain phase | request-granular eviction (one abusive session, no replica collateral); availability-correct retirement | `serving-stack-reachable` |
| **3** | **`guardrail-rotate`** | swap the guardrail model variant / re-key the ruleset (Llama Guard / NeMo) | MTD for the safety tier — stales a found jailbreak bypass | `guardrail-tier-declared` |
| watch | **`kv-migrate-invalidate`** | invalidate/rekey KV across P/D workers (vLLM kv-transfer connector) | disaggregated-serving-only; emerging | `disagg-serving-declared` (design now, defer build) |

Plus **build-completion** items on the existing 5 (no new action): implement warm-swap's **drain** (shared with
request-drain), wire a **real `nodeRunner`** for mig-rebind (privileged DaemonSet exec / GPU-Operator mig-manager)
+ true GPU-context eviction, and add **TP/PP coordination** to model-shard-replace.

Each proposed move keeps the brain unchanged (opt-in via `EnabledActions`, default still {rotate,quarantine}), is
gated by a feasibility law (self-prunes where infeasible), and would ship `[PENDING-GPU-VALIDATION]` behind the
same mockable stack abstraction.

---

## Recommendation
1. **Approve `adapter-rotate`** (closes the one clean survival gap) — highest priority.
2. **Approve `request-drain`** (request-granular + fixes warm-swap's drain) and **`guardrail-rotate`** (2nd-tier).
3. **Design `kv-migrate-invalidate`** now, defer build.
4. **Close the build gaps** in mig-rebind (transport) + model-shard-replace (TP/PP) before either is called "built."
5. **Re-label** the "completeness invariant" as a *handler-coverage* invariant; institutionalize this
   mechanism-coverage review as the human complement.

**No code written this pass. STOP for review + approval of the proposed set before any handler is built.**
