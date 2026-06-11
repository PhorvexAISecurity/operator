# P-ACTUATOR-SET-COMPLETENESS — the locked AI/GPU actuator-set design

**Status: BUILT (§9.19 P-ACTUATOR-SET-COMPLETE) — real code behind the mockable stack, CI-tested,
`[PENDING-GPU-VALIDATION]` (not production-ready until GPU-run).** All 4 new actuators + the 3 build-completions
below are implemented + green in CI; the brain stays byte-identical (opt-in actions). This records the decision
from the §9.18 audit
(`P4-COMPLETENESS-AUDIT.md` holds the full reasoning, persona panel, premortem + steelman, and serving-stack
citations). No handler code exists for anything below; this is the build contract to approve before coding.

---

## What the audit established (the truth being locked against)

1. **Handler-coverage ≠ mechanism-coverage.** The "completeness invariant" (`MissingHandlers()` over
   `model.MutatingActions`) proves only that **no *declared* action lacks a handler**. It is structurally blind
   to a **missing mechanism** (an undeclared move can't fail it). Mechanism-completeness is a human judgment;
   this document is that judgment, to be re-run when the serving-stack threat surface shifts.

2. **The existing 5 are at uneven maturity** ("5 built" = **1 complete + 2 real-pending + 2 partially-built**):

   | Handler | Maturity | The gap beyond `[PENDING-GPU-VALIDATION]` |
   |---|---|---|
   | endpoint-rotate | **real-and-complete (K8s)** | none structural (only the route-reconvergence magnitude) |
   | kv-reset | **real-but-pending** | the vLLM reset route string is unconfirmed against a live version |
   | warm-swap | **real-but-pending + drain gap** | connection-drain unimplemented (`handlers_ai.go:141`) → in-flight requests dropped |
   | model-shard-replace | **partially-built** | single-pod flip only; **no TP/PP coordination** (a parallel group is a consistency unit) |
   | mig-rebind | **partially-built — transport UNBUILT** | **no real `nodeRunner` exists** → always fail-closes in production; "drain" is route-relabel, not GPU-context eviction |

3. **The LoRA-adapter survival gap.** A poisoned LoRA/adapter survives **every** current actuator (warm-swap
   reloads the base and re-pulls the same poisoned adapter from the registry; kv-reset is cache; shard-replace
   targets shards). Distinct API, ~100–1000× cheaper than warm-swap, fastest-growing surface (LLM03). **Not
   subsumable.**

---

## LOCKED design — NEW actuators (design only, not built)

Each stays **opt-in** (added to `model.MutatingActions`; default policy remains `{rotate, quarantine}` so
1.62×/P3/lead-demo decisions are byte-identical), **feasibility-law gated** (self-prunes where infeasible),
implemented **behind the mockable stack abstraction** (`gpu_stack.go` interfaces), and shipped
**`[PENDING-GPU-VALIDATION]`** until calibrated on real GPU.

| Priority | Action | Mechanism (real stack API) | Why distinct / not subsumed | Feasibility law (proposed) | Stack-interface surface |
|---|---|---|---|---|---|
| **P1** | **`adapter-rotate`** | vLLM `POST /v1/unload_lora_adapter` (+ reload-clean / swap-variant); Triton model-control EXPLICIT unload; TGI adapter reload | the ONLY evictor of a poisoned adapter; cheap + targeted (no base reload) — folding into warm-swap hides the cost signal AND re-pulls the poison | `lora-enabled-required` (pod advertises `--enable-lora` / adapter labels) | extend `vLLMClient` (`UnloadAdapter`/`LoadAdapter`) |
| **P2** | **`request-drain`** | vLLM `AsyncLLMEngine.abort(req_id)` / scheduler graceful drain | request-granular eviction (one abusive session, no replica collateral); ALSO implements warm-swap's missing drain phase | `serving-stack-reachable` | extend `vLLMClient` (`AbortRequest`/`DrainQueue`) |
| **P2** | **`guardrail-rotate`** | swap the guardrail model variant / re-key the ruleset (Llama Guard, NeMo Guardrails) | MTD for the safety tier — stales a found jailbreak bypass; the guardrail tier is otherwise unmodeled | `guardrail-tier-declared` | K8s (pod/ruleset) ± guardrail control endpoint |
| **Design now / DEFER build** | **`kv-migrate-invalidate`** | invalidate/re-key KV across P/D workers (vLLM `--kv-transfer-config` connectors, Dynamo, Mooncake, LMCache) | disaggregated-serving-only; kv-reset is local; emerging surface | `disagg-serving-declared` | new `kvTransferController` interface |

---

## LOCKED design — BUILD-COMPLETION on the existing 5 (no new action)

| Item | What to build | Closes |
|---|---|---|
| **warm-swap real drain** | implement the connection-drain phase (shared with `request-drain`): stop new admits, finish/abort in-flight with a bounded window, THEN retire | the in-flight-drop gap (`handlers_ai.go:141`) |
| **mig-rebind real `nodeRunner`** | a production node-exec transport (privileged DaemonSet exec / GPU-Operator mig-manager) **and** true GPU-context eviction (evict the pod off the GPU so reconfig has zero CUDA contexts) | the UNBUILT transport + the insufficient route-only "drain" |
| **model-shard-replace TP/PP coordination** | coordinate the replace across a tensor/pipeline-parallel group (the framework's coordinated-restart / consistent-rank-swap path), not an independent pod flip | the single-pod-flip correctness gap |

---

## Invariants this design preserves
- **Brain unchanged** — every addition is opt-in policy; the optimizer/cost/feasibility cores are not touched;
  default decisions stay byte-identical (1.62×/P3/lead-demo).
- **Fail-closed everywhere** — each new move fail-closes when its stack/device/feasibility precondition is absent
  (never fabricate a GPU/serving effect).
- **Mockable + CI-tested** — each ships behind the `gpu_stack.go` interfaces with mock-based CI tests for the
  logic + the K8s mechanics, `[PENDING-GPU-VALIDATION]` for the live stack/GPU wire.
- **Mechanism-coverage is a recurring human review** — re-run this audit (the template) on serving-stack shifts;
  the handler-coverage invariant alone cannot detect a newly-missing mechanism.

**No handler code in this pass. Build begins only on approval of this set.**
