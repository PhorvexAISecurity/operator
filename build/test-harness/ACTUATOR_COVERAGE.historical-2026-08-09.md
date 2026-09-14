# Phorvex — Actuator Coverage: the real goal of this phase

**Boss reframe (2026-08-09).** The point of deploying these workloads (voice bot + CRM + MCP + vLLM) is to write attacks that make the **brain actually CHOOSE each actuator**, so we test two things at once: (1) the brain's *selection* capability, and (2) each actuator's *effect*. **Starting point = POST-DETECTION** (after red-team/a detector notifies — the reactive path, a `SecurityEvent` has fired), NOT outside-in / assume-breach.

## Why this is the highest-value work: the existence test

Phorvex's job is to **reduce cost**. `rotate`/`quarantine` are the blunt, expensive moves (kill a pod / cut its network). The whole reason the *other* actuators exist is to **cover the same threat at lower cost** — a surgical move instead of a sledgehammer. The live engine literally optimizes **coverage-per-dollar**.

So the tests are an **existence proof for Phorvex**:
- If the brain reliably picks a **cheaper actuator that actually neutralizes the threat** → Phorvex earns its keep.
- If it always effectively falls back to rotate/quarantine, **or the cheap actuators are stubs** → you don't need a brain at all; "on detection → rotate" is a one-line controller.

Current reality (from live tests T9–T11 + code): identity-rotate is a no-op, route-rotate is relabel-only, quarantine's NP isn't enforced, the 8 GPU actuators are pending. **Right now Phorvex ≈ rotate-on-detection.** These tests either force the surgical actuators to become real (proving value) or prove they're vapor.

---

## How the live brain selects an actuator (verified in source)

**Live engine = `CoverageEngine` ("p1-coverage")** in `phorvex/internal/decision/coverage.go`, with the **`ucw-recon`** profile (`recon.Registry.SetDefault("ucw-recon")`).
⚠️ NOT `p0-greedy` (`decision/engine.go`) — that MVP engine's `actionBenefit` returns 0 for everything but rotate/quarantine, so it can only pick those two. *The `/tmp/px-redteam/PHORVEX_CODE_NOTES.md` orientation file analyzed p0-greedy for selection — wrong engine.* (Its **effect**/stub analysis is still correct.)

**Selection = maximize coverage of weighted recon "facts" per dollar.** Each pod exposes weighted facts; each actuator **covers** (invalidates) a specific fact set (`recon.AssetFacts → CoverByAction`, in `recon/profile.go` + `recon/ucw.go`). The optimizer picks the actuator covering the highest-weight exposed facts per dollar, under feasibility + SLO gates (`actionset/generator.go`).

**The fact → actuator map (the master key — to trigger actuator X, make fact_X dominate):**

| Fact | Covered by | Emitted when |
|---|---|---|
| `FactInMemory` | **rotate** only | always (in-pod) |
| `FactPodIdentity` | **rotate**, **identity-rotate** | always |
| `FactSession` | **rotate**; **kv-reset** (only if `HasGPU\|\|Stateful`) | always; kv-reset arm gated on GPU/stateful |
| `FactNetworkIdentity` | **quarantine**, **route-rotate** | always |
| `FactLateralEdge` (per neighbor) | **quarantine** only | one per blast-graph neighbor |
| `FactModelFingerprint` | **model-shard-replace** | `HasGPU \|\| ModelID≠""` |
| `FactEndpointPath` | **endpoint-rotate**, **kv-migrate-invalidate** | served-model |
| `FactGPUColocation` + `FactSideChannel` | **mig-rebind**, **warm-swap** | served-model |
| `FactInflightRequests` | **request-drain** | served-model |
| `FactGuardrailBypass` | **guardrail-rotate** | served-model |
| `FactAdapterIntegrity` | **adapter-rotate** only | served-model **AND** `Pod.SuspectAdapter≠""` (weighted to DOMINATE) |

**Nested cover sets = the cost mechanism.** `identity-rotate ⊂ rotate` (pod-identity only); `route-rotate ⊂ quarantine` (network-identity only). So the optimizer picks the **surgical, cheap** move for a narrow threat and **escalates** to the blunt one only when more facts (in-memory implant, lateral edges) are also at stake. That escalation logic *is* Phorvex's value proposition.

**How an attack shapes the facts** (all fed by the *post-detection* context/belief + workload state):
- `base = AssetValue × P(hold)`, `urg = 0.5 + 0.5×StageUrgency` → higher-stage detection = heavier facts.
- Neighbors (blast graph) → `FactLateralEdge` weight → quarantine.
- `HasGPU` / `ModelID` (annotation `phorvex.ai/model-id`, `ingest/kube.go:275`) → the 8 GPU facts.
- `Stateful` (`isStateful`: StatefulSet/Job/PVC) → kv-reset arm + rotate→quarantine veto.
- `SuspectAdapter` (annotation `phorvex.ai/lora-adapter`, `ingest/kube.go:281`) → adapter-rotate dominates.
- Physics (ImageRarity·EPSS·CoResidency·ModelRarity, `ucw.go`) sharpens cross-asset ordering.

---

## Actuator inventory + effect status (14 actions)

| Actuator | Trigger fact | Workload | Effect when enacted | Tested |
|---|---|---|---|---|
| **rotate** | in-memory/session/identity | any | **REAL** (pod delete) | ✅ T1/T4/T5/T8 |
| **quarantine** | lateral edges / net-identity | any | deny-all NP **NOT enforced** (`ENABLE_NETWORK_POLICY` unset) → cosmetic; detach→sprawl | 🟡 sel T6 / 🔴 eff T9 |
| **identity-rotate** | pod-identity (⊂ rotate) | any | relabel only — **SA-token rotate is a NO-OP** | 🔴 T10 |
| **route-rotate** | net-identity (⊂ quarantine) | any | relabel only — **never touches Service/EndpointSlice** | 🔴 T11 |
| **kv-reset** | session | GPU/Stateful | in-process KV flush — **real vLLM endpoint** `/reset_prefix_cache` | ✅ T12 + **T20 (7B VC-grade)** |
| **endpoint-rotate** | endpoint-path | served-model | restitches Service selector — *the real route-staling move* | ✅ **T17** (full K8s effect) |
| **kv-migrate-invalidate** | endpoint-path | served-model | invalidate/migrate KV across endpoints — **route absent on stock vLLM (honest 404)** | 🟡 sel **T21** / eff absent |
| **model-shard-replace** | model-fingerprint | served-model | warm-replace a model shard | ⬜ never feasible here (no warm shard pool) |
| **mig-rebind** | gpu-coloc + side-channel | served-model | move to non-co-resident MIG partition | ❌ **T4 has no MIG** |
| **warm-swap** | gpu-coloc + side-channel | served-model | rotate without cold-load (needs warm replica) | 🟡 sel **T16** / eff blocked (no pool) |
| **request-drain** | in-flight-requests | served-model | drain/abort in-flight requests — K8s label drain REAL, `/v1/drain` absent | 🟡 sel **T14** / eff fail-closed |
| **guardrail-rotate** | guardrail-bypass | served-model | rotate safety ruleset/variant | 🟡 sel **T15** / eff needs a tier |
| **adapter-rotate** | adapter-integrity (needs `SuspectAdapter`) | served-model | unload poisoned LoRA — **real vLLM endpoint** `/v1/unload_lora_adapter` | ✅ **T22** (attack-steered, full E2E) |
| debugger / custom-inject | — (not in CoverByAction) | manual | inject ephemeral container | manual/forensic only |
| disable | — | — | declared no-op | n/a |

**Verified end-to-end: `rotate`, `kv-reset`, `endpoint-rotate`, `adapter-rotate`.** All nine served-model/AI actuators exercised live (T12–T22); the remaining 🟡 are selection-proven with honest stack notes (missing tier/pool/route), and two are hardware/topology-gated (MIG, multi-node warm shard).

---

## GPU / vLLM capacity (measured live 2026-08-09)

- **1× NVIDIA Tesla T4, 15 GB usable** (`g4dn.xlarge`, us-east-2), **time-sliced ×8** (`nvidia.com/gpu: 8`; T4 = Turing → slicing, **not MIG**). ~9.4 GB used / **~6 GB free**.
- **Live vLLM** (ns `vllm`, 2 replicas, `r6th.io/rotation-target=true`, `vllm-defense` policy): `Qwen/Qwen2.5-0.5B-Instruct`, fp16, `max-model-len 4096`, `gpu-memory-utilization 0.3` (~4.6 GB/replica), prefix-caching on, `vllm/vllm-openai:v0.6.6.post1`. **Annotated for Phorvex**: `phorvex.ai/model-id` (⇒ served-model facts fire), `phorvex.ai/kv-reset-path=/reset_prefix_cache` (⇒ kv-reset has a real endpoint), `serving-port=8000`. **UPDATE 2026-08-10 PM:** the live deployment had drifted — image `v0.7.3`, `--enable-lora`+runtime-updating already on, gpu-util 0.35×2. Then the VC model swap: **1 replica × `Qwen/Qwen2.5-7B-Instruct-AWQ`, gpu-util 0.9** (2×0.45 OOMed at engine init — the card can't hold two 7B budgets; single-replica zero-downtime is the demo topology now).
- **Model fit on the T4**: ≤ **3B fp16** (~6 GB) or ≤ **7B-AWQ** (~5 GB) comfortably; 14B-AWQ tight. **0.5B already fires every served-model fact — size is ~irrelevant for actuator testing;** a 7B-AWQ only adds realism (room for KV + a LoRA adapter). T4: fp16 + int4(AWQ/GPTQ) yes; bf16 slow; no FP8.
- **A guardrail tier does NOT need a bigger GPU** — it's a classifier/proxy: run on CPU (rules proxy / Prompt Guard ~86–279M) or ~2.5 GB (Llama Guard-1B) in the T4 headroom. Only genuine hardware wall = **mig-rebind (needs A100/H100 MIG)**.

---

## Test design: every actuator gets TWO oracles

1. **SELECTION** — for the fact the attack raises, does the brain pick actuator X, and is X **cheaper than rotate/quarantine** (lower cost, positive perDollar)? *(tests the coverage optimizer = Phorvex's value)*
2. **EFFECT** — does X actually neutralize the threat? *(tests the actuator handler)*

**⭐ REALISM BAR (non-negotiable).** Each test must be a **real-world attack on a real-world agentic workload** — not "set an annotation to force fact_X." The attack must be something an actual attacker does to an actual agentic system (prompt/prefix-cache poisoning of a served LLM, a poisoned LoRA adapter from a fine-tune supply chain, a jailbreak that bypasses a guardrail, denial-of-wallet request floods, a foothold/lateral-move, stolen SA-token reuse), and the **detection/fact must arise NATURALLY from that attack** — which is precisely what should lead the brain to the surgical actuator. Realism isn't decoration: a contrived fact tests nothing; a real attack that naturally raises fact_X is the only honest test of "does the brain pick the right actuator," and it doubles as a real security finding. (This is the same 5-point realism bar from the attack catalogue, now applied to actuator coverage.) The agentic workloads we deployed are the real surfaces: the voice agent (tools + memory + MCP) and the vLLM served model.

**Honest coverage caveat:** most actuators have a *clean* realistic agentic trigger — kv-reset←prefix-cache poisoning, adapter-rotate←poisoned LoRA, guardrail-rotate←jailbreak bypass, request-drain←denial-of-wallet, rotate/quarantine←foothold/lateral, identity-rotate←token reuse, endpoint/route-rotate←endpoint-pinned attacker. A few (**mig-rebind, warm-swap, model-shard-replace**) only map to *exotic* GPU-side-channel / weight-tamper cases, and mig-rebind is hardware-blocked (no MIG on T4). So **100% realistic coverage may not be reachable** — we cover every actuator that has an honest real-world trigger and document the rest as no-clean-trigger, rather than fake it.

Split by workload:
- **Voice bot (CPU, ns `voice`)**: rotate, quarantine, identity-rotate, route-rotate — and kv-reset if we mark it `Stateful`. (Mostly documents the stubs.)
- **vLLM (GPU/served-model, ns `vllm`)**: the 8 served-model actuators. `adapter-rotate` needs a LoRA + `phorvex.ai/lora-adapter` annotation; `guardrail-rotate` needs a guardrail deployed; `mig-rebind` is hardware-blocked on T4.

### Flagship: kv-reset (the clean proof-of-value)
Inject/poison the vLLM prefix cache → detector flags it → **does the brain pick `kv-reset` over `rotate`** (covers the session fact far cheaper, no pod kill), **and does hitting `/reset_prefix_cache` actually evict the injection?** Yes to both = concrete "Phorvex beats detect→rotate." No = falsification. This is the first GPU test to build.

---
*Sources: `phorvex/internal/decision/{coverage,engine}.go`, `internal/recon/{profile,ucw,facts}.go`, `internal/actionset/generator.go`, `internal/feasibility/defaults.go`, `internal/actuator/handlers_{k8s,ai,ai_p4set}.go`, `internal/model/types.go`, `internal/ingest/kube.go`; live cluster recon; tests T1–T12 in `ATTACKS_OUTCOMES.md`.*
