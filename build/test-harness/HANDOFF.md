# Phorvex Actuator-Coverage — Engineering Handoff

*For the agent picking up this work. Read top to bottom once; then keep `ATTACKS.md` open as your working doc. Everything below is the settled, source-verified state.*

---

## 0. TL;DR (the 60-second version)

**Phorvex** is a deterministic Kubernetes moving-target-defense "brain." When an attack is detected, it doesn't blindly kill (`rotate`) the pod — it selects the **cheapest surgical actuator** that neutralizes that specific threat. It has **14 actuators**; only `rotate` is proven end-to-end. Our job this phase is **actuator coverage**: write **realistic** attacks that make the brain *choose* each actuator, and verify both that it **picks the right one** and that the actuator **actually works**.

**Why this is high-stakes:** this is the **existence proof for Phorvex**, and it's going in front of VCs for funding. If Phorvex reliably picks a *cheaper actuator that works*, it earns its keep. If it always falls back to `rotate`, or the surgical actuators are stubs, then "on detection → rotate" is a one-line controller and Phorvex is redundant. **Every test either proves value or honestly exposes a gap — both are wins.**

**Where we are:** the attack universe is finalized in **`ATTACKS.md`** (54 attacks, graded for realism, each mapped to the actuator we expect — or "None/gap"). Four actuators have a clean realistic trigger (`rotate` ✅ proven, `quarantine` 🟢 selection proven, `adapter-rotate`, `kv-reset`); the rest are honest gaps. **Next step: run Test-queue #1 — the `kv-reset` flagship.**

**Your first two tasks:** (1) **audit `ATTACKS.md`** — re-derive the predictions yourself, hunt for anything we missed (§7); (2) **build the `kv-reset` test** (§6).

---

## 1. The mental model (understand this and everything else follows)

R6/Phoenix is the "muscle" (it can delete, quarantine, and mutate pods on a blind timer). **Phorvex is the brain that decides *which* move, on *which* pod, *when* — and prefers the cheapest move that covers the threat.**

The brain models an attack as a set of **recon "facts"** the attacker has learned about a pod (its identity, its in-memory state, its KV-cache/session, its network identity, its lateral edges, its served-model fingerprint, a poisoned adapter, …). Each actuator **invalidates** ("covers") a specific set of those facts. The brain picks the actuator that covers the highest-value facts **per dollar**.

That single idea produces the whole value proposition: a narrow threat (say, a poisoned LoRA adapter) is covered by a cheap surgical move (`adapter-rotate`) that a blunt `rotate` can't even fix — so the brain should pick the surgical move, and that's *provably better* than "always rotate."

---

## 2. How the brain selects an actuator (source-verified — this is the foundation)

Live engine = **`CoverageEngine` ("p1-coverage")** in `phorvex/internal/decision/coverage.go`, with the **`ucw-recon`** profile (`phorvex/internal/recon/ucw.go`), wired in `phorvex/internal/runner/manager.go:88-92`.

**A. How a detection enters (every test starts here — the reactive/post-detection path):**
- **Door A — a Phoenix `SecurityEvent` CRD** whose `spec.targets` names the pod → `ingest/events.go:60-64` sets `TargetsPod=true`. This is the generic "red team / detector flagged this pod."
- **Door B — a detector-stamped annotation** (`ingest/kube.go:275-281`): `phorvex.ai/model-id`, `phorvex.ai/endpoint`, or **label `phorvex.ai/lora-enabled=true` + annotation `phorvex.ai/lora-adapter=<name>`** → `SuspectAdapter`.
- **Reactive-only gate (`coverage.go:227`):** a pod is actionable **only** if it has a `TargetsPod` event **OR** a `SuspectAdapter`. No detection → the brain does nothing.

**B. The objective (`coverage.go:256`):** per pod, pick the **one** move maximizing `marginal_covered_fact_weight − λ·cost`. Greedy; one move per pod; budget `B = maxMovesPerTick`. Fact weight ≈ `AssetValue × P(hold) × urgency × physics-multipliers`.

**C. The cover map (which move invalidates which fact)** — `recon/profile.go` + `recon/ucw.go`:

| Fact (what the attacker learned) | Covered by |
|---|---|
| `podIdentity` | rotate, **identity-rotate** |
| `inMemory` (implant/secrets) | **rotate only** |
| `session` (KV-cache / agent session) | rotate; **kv-reset** (GPU/stateful pods only) |
| `networkIdentity` | quarantine, **route-rotate** |
| `lateralEdge` (per reachable neighbor) | **quarantine only** |
| `modelFingerprint` | model-shard-replace |
| `endpointPath` | endpoint-rotate, kv-migrate-invalidate |
| `gpuColocation` + `sideChannel` | mig-rebind, warm-swap |
| `inflightRequests` | request-drain |
| `guardrailBypass` | guardrail-rotate |
| `adapterIntegrity` (only if `SuspectAdapter` set) | **adapter-rotate** (weighted to dominate) |

**D. The cost truth (`cost/p1cost.go:33-65`):** `rotate` has norm-cost 1.0; `quarantine` ≈ `1/(N+1)`; **every other actuator has norm-cost 0** and shares rotate's flow cost. So **all surgical/AI moves cost the same, and each is cheaper than rotate by exactly one knob (`NormSparsity`).** Consequence: **selection *among* surgical moves is 100% about which fact they cover, never cost.**

**E. Two classes of actuator (the key to predicting selection):**
- **Unique-fact actuators** (adapter-rotate, guardrail-rotate, request-drain, endpoint-rotate, model-shard-replace, warm-swap, mig-rebind, kv-migrate-invalidate): cover a fact `rotate`/`quarantine` **cannot**. They win whenever their fact is present, they're policy-enabled, and feasible.
- **Subset actuators** (identity-rotate ⊂ rotate; route-rotate ⊂ quarantine; kv-reset ⊂ rotate): the blunt move **strictly out-covers** them, so they win **only when the blunt move is infeasible** (see F) or λ is high.

**F. Feasibility levers (prune candidates *before* selection)** — `feasibility/defaults.go` + `actions_native.go`:
- `availability-floor`: gates **rotate & quarantine only** (they drop a Ready replica); surgical/AI moves are exempt. So a **single-replica** pod (or `MinAvailableReplicas == replicas`) prunes rotate/quarantine and leaves the surgical move.
- `stateful-integrity`: **rotate is infeasible on a stateful pod** (StatefulSet / Job / PVC) — it would destroy data.
- `slo-headroom`, `anti-over-rotation`: bound rotate/quarantine on hot or recently-moved pods.
- `ai-context-required`: the AI moves need `HasGPU` or `ModelID`. `mig-device-required`: mig-rebind needs a real MIG device.
- **Policy enable (`model/types.go` `ActionEnabled`):** only actuators in the policy's `actions.enabled` are candidates. **Default = rotate+quarantine only.**

**G. The one finding that shapes what's coverable:** the served-model facts are minted as a **fixed bundle** (`ucw.go:64-90`) — all of them together on any GPU/model pod, weighted by physics only. **The attack *type* does not steer which served-model fact dominates.** The single exception is `adapterIntegrity` (the LoRA path), which is attack-conditioned and dominates. Practical upshot: the brain can be steered to **adapter-rotate by the attack**, but **not** to kv-reset / request-drain / guardrail-rotate / endpoint-rotate by attack type — those need policy-scoping + blunt-move-infeasibility, and otherwise whichever surgical move covers the most physics-weight wins.

---

## 3. The deployed attack surfaces (the live cluster)

All live on the test EKS cluster; Phorvex runs in `phorvex-system` guarding the tenant namespaces.

| Workload | ns | Replicas | Stateful? | Notes |
|---|---|---|---|---|
| **voice-bot** (Pipecat agent) | `voice` | **2** | no | Public at `voicebot.phorvex.ai`. 10 tools: Chroma RAG search, 5 CRM write-tools, 2 caller-memory tools, 2 MCP tools. Policy `voice-defense` enables **`[rotate]` only**. |
| **CRM** (mock) | `crm` | 1 | no | `crm.crm:8080`; privileged writes `issue_refund`/`reset_password`/`book_appointment` with **no caller-owns-order check** (confused-deputy surface). |
| **MCP server** | `mcp` | 1 | no | `mcp-server.mcp:8000/mcp/`; the bot trusts its tool descriptions + responses. |
| **Chroma** | (data) | **1** | **yes (PVC)** | RAG collection `knowledge_base`. |
| **Mongo** | (data) | **1** | **yes (PVC)** | **no-auth**; holds transcripts, caller_memory, crm db. |
| **vLLM** | `vllm` | **2** | no | Qwen2.5-0.5B fp16, `HasGPU`. Annotated `phorvex.ai/model-id` + `phorvex.ai/kv-reset-path=/reset_prefix_cache` + `serving-port=8000`. **No LoRA, no guardrail tier.** |

**GPU:** 1× Tesla T4, time-sliced ×8, **no MIG** (so mig-rebind is hardware-blocked).

**The live `voice-defense` policy** (`phorvex-voice-agent/k8s/policy.yaml`): `actions.enabled: [rotate]`, `reactiveOnly: true`, `minAvailableReplicas: 1`, `tickInterval: 5s`, `antiOverRotationWindow: 90s`, `proactiveFloor: 15m`, `λ=0.4`, `flowDisruption=0.6`, `normSparsity=0.4`, selector `r6th.io/rotation-target=true`.

**⚠ The single most important operational fact:** because policies default to **rotate-only**, *every non-rotate test requires enabling that actuator in the relevant PhorvexPolicy first (`actions.enabled`).* This is Test-step-0 for the whole battery.

**Cluster access:** `ssh hami@87.106.63.105` — **the password is provided by the user each session, never stored here (it must be rotated).** The box has `kubectl`, `aws` (can push ECR), `docker` (needs `sudo`); **no `gh`, no `go`.** Also public: the Phorvex **console** `console.phorvex.ai` (control-plane — compromising it = controlling the defense; highest-value bridge, separate scope). All backends except the bot are ClusterIP-only.

---

## 4. Actuator inventory + effect status (14 actions; only `rotate` proven end-to-end)

| Actuator | Trigger fact | Effect when enacted | Status |
|---|---|---|---|
| **rotate** | in-memory / session / identity | pod delete + clean respawn | ✅ **REAL, proven** |
| **quarantine** | lateral edges / net-identity | deny-all NetworkPolicy + detach | 🟡 selection proven; **NP unenforced** (`ENABLE_NETWORK_POLICY` unset → cosmetic) |
| **kv-reset** | session (GPU/stateful) | in-process KV/prefix flush | ⬜ **real endpoint** `/reset_prefix_cache`; untested end-to-end |
| **adapter-rotate** | adapterIntegrity (needs `SuspectAdapter`) | unload/reload LoRA | ⬜ hits vLLM `/v1/unload_lora_adapter`+`/v1/load_lora_adapter`; **needs a LoRA-serving vLLM** |
| **identity-rotate** | pod-identity (⊂ rotate) | relabel only — **SA-token rotate is a NO-OP** | 🔴 T10 |
| **route-rotate** | net-identity (⊂ quarantine) | relabel only — **never touches Service/EndpointSlice** | 🔴 T11 |
| **endpoint-rotate** | endpoint-path | restitch Service selector (the real route-staler) | ⬜ pending |
| **kv-migrate-invalidate** | endpoint-path | invalidate/migrate KV | ⬜ pending stub |
| **model-shard-replace** | model-fingerprint | warm-replace a shard | ⬜ pending stub |
| **warm-swap** | gpu-coloc + side-channel | provision-before-retire | ⬜ pending stub |
| **request-drain** | in-flight-requests | drain/abort in-flight requests | ⬜ pending stub |
| **mig-rebind** | gpu-coloc + side-channel | move to non-co-resident MIG | ❌ **hardware-blocked (no MIG on T4)** |
| **guardrail-rotate** | guardrail-bypass | rotate safety ruleset/variant | ⬜ **needs a guardrail tier (none deployed)** |
| debugger / custom-inject / disable | — | manual / no-op | not autonomously selectable |

---

## 5. What's already proven (T1–T11, see `ATTACKS_OUTCOMES.md`)

- ✅ **T1/T4/T5/T8** — `rotate` on a foothold/implant: reactive eviction ~10s, proactive dwell-cap ~36s (no detector needed, hazard 0.00). The core MTD win, proven.
- ✅ **T6** — `quarantine`-not-`rotate` on a **stateful** canary: the brain chose quarantine to preserve data instead of deleting it. (Ran at `minAvailableReplicas:0`; note this does **not** auto-reproduce on the real single-replica stores — see `ATTACKS.md` Q3.)
- 🔴 **T2** — API-key/SA-token theft: 5/5 credentials still valid after rotate (rotate can't revoke a leaked static cred).
- 🔴 **T3** — transcript exfil: data survives bot **and** Mongo rotation (PVC persists).
- 🔴 **T7** — Chroma RAG poisoning: the poison survived rotating both Chroma and the bot.
- 🔴 **T9 / T10 / T11** — quarantine NP unenforced / identity-rotate SA-token no-op / route-rotate never touches the Service. These are the **effect** gaps behind the status table above.

The pattern: **Phorvex wins when the attacker's payload is ephemeral in-pod state; it misses on data-at-rest, static credentials, and app-semantic attacks.** That split is the honest, credible story — *specialized, not weak.*

---

## 6. The next step — build Test-queue #1: the `kv-reset` flagship

**Why this one first:** it's the cleanest *provable* "surgical beats rotate" — a real vLLM attack (prefix-cache poisoning), a **real** actuator endpoint (`/reset_prefix_cache`), and it's runnable with just a policy edit (no new infra).

**The attack (real-world):** vLLM automatic prefix caching (APC) shares KV state across requests. A crafted prefix poisons the shared cache so a later victim request inherits injected context (cross-request contamination). This is a documented, VC-credible vLLM attack.

**Setup:**
1. **Enable the actuator + prune rotate.** Find the vLLM PhorvexPolicy (`kubectl get phorvexpolicy -A`), and patch:
   - `spec.actions.enabled: [rotate, kv-reset]`
   - `spec.slo.minAvailableReplicas: 2` → on the 2-replica vLLM, `ready(2)−1 = 1 < 2` prunes `rotate`, leaving `kv-reset` as the only feasible in-pod move covering `session`.
   - Confirm the vLLM pod carries `phorvex.ai/model-id` + `phorvex.ai/kv-reset-path=/reset_prefix_cache` (it does).
2. **Poison the cache:** send the crafted prefix; verify a victim request inherits the injection.
3. **Fire the detection:** apply a `SecurityEvent` CRD targeting the vLLM pod (a non-Phorvex `Source`, e.g. `redteam`; `spec.targets: [vllm/<pod>]`). Confirm the exact CRD group/version first with `kubectl get crd | grep -i securityevent` (it's the Phoenix `v1beta1` SecurityEvent; `spec` = `{rule:{type,threatLevel,source}, targets:[…], description, anomalyScore}`).

**The two oracles:**
- **SELECTION:** does the brain emit `Action=kv-reset` (Engine `p1-coverage`) — not `rotate` (pruned), not another move (only rotate+kv-reset are enabled)? Read the Decision/audit log.
- **EFFECT:** after `/reset_prefix_cache` fires, re-run the victim request — is the injected context **gone**?

**Pass = brain picks `kv-reset` + injection evicted → concrete "Phorvex beats detect→rotate."** Fail either half → a precise, documented gap. Record it as a new `T#` in `ATTACKS_OUTCOMES.md` and update the K1 Outcome in `ATTACKS.md`.

> Cluster-touching work needs the user's go and the SSH box. Confirm before enacting.

---

## 7. VC demo framing — the "widely-used app" bar

**The boss's realism bar has a second meaning:** demos must run on **widely-used, recognizable software** — what a VC reads as real production infrastructure — not our bespoke rig. "Phorvex defended **vLLM / Llama-3**" lands; "Phorvex defended our demo bot" does not.

**Good news — the value already targets recognizable software.** Phorvex's defense lands on the **body layer** (see below), and those targets are all widely-used:
- **vLLM** — the de-facto open-source LLM inference server. `kv-reset`, `adapter-rotate`, `endpoint-rotate`, `request-drain`, `model-shard-replace` all act on vLLM.
- **Chroma** (popular vector DB), **MongoDB** (ubiquitous), **LoRA adapters / HuggingFace** (standard fine-tune + distribution).

So the flagship (`kv-reset`, §6) **is already a demo on a widely-used app** — frame it as *"a poisoned prefix cache on vLLM, surgically flushed instead of killing the server."*

**Body vs mind — demo only the body.** Phorvex defends the agent's **body** (serving/infra: KV cache, adapters, endpoints, pods), NOT its **mind** (prompts, RAG, tool descriptions, memory, conversation). The mind-layer attacks (prompt injection, RAG/MCP/memory poisoning) are **Phorvex = None by design.** **Do not build famous-app demos for the mind layer** — they'd just show Phorvex *not helping* on recognizable software, undercutting the case. The mind layer stays as the honest **gap map** (what guardrails / tool-authz / DLP are needed), never as a demo.

**Two cheap upgrades that make the flagship VC-grade** (both fit the current T4):
1. **Swap the toy model for a name-brand one** — replace Qwen2.5-**0.5B** with **Llama-3-8B or Qwen-7B (AWQ)** on the same vLLM. The demo then reads "defending a **Llama-3** deployment," not a 0.5B toy.
2. **Optionally wrap it in a recognizable agent framework** — point a **LangChain / LlamaIndex** agent at that vLLM, so the "app" is a framework the VC knows *and* the defense target (vLLM) is too.

**The honest constraint (state it proactively):** Phorvex can only *surgically* defend apps that **expose the serving-control surfaces it acts on** — vLLM's `/reset_prefix_cache`, its LoRA load/unload, its endpoints. That's *why* vLLM is the target (Ollama, for instance, doesn't expose these). The intersection "widely-used" ∩ "surgically defensible" is precisely the **vLLM-class serving stack** — and that's a **strength**, because the defense is **framework-agnostic.**

**The VC narrative line:**
> *"Phorvex protects **any** agent built on vLLM — LangChain, LlamaIndex, custom, doesn't matter — at the model-serving layer no other defense touches. We demo it on **Llama-3 running on vLLM**, the standard the industry already deploys."*

**Honesty guardrails for the demo (it will be scrutinized — never overclaim):**
- `kv-reset` **evicts the planted cache state (prefix-cache HIT→MISS)**; it does **not** "cure the injection" (plain-APC KV is a pure function of prompt tokens — see the K1 caveat in `ATTACKS.md`).
- **Only `rotate` is proven end-to-end today.** `kv-reset` and `adapter-rotate` are the two we prove next — say *"selection-provable, effect in validation,"* not "proven."
- For the served-model bundle (B1–B5), the pick is **policy-shaped** (you scope the policy), not attack-shaped — **only `adapter-rotate` is genuinely attack-steered.**

---

## 8. Your mandate: **audit `ATTACKS.md` — find what we missed**

Do **not** treat the list as final. Re-derive it adversarially. Specific angles that are most likely to surface something:

1. **Re-derive every actuator prediction** from §2 (objective + feasibility + the *actual* policy). Scrutinize hardest:
   - **Stateful cases** (V13/V14/GP10/Q2/Q3): quarantine vs None hinges on `minAvailableReplicas`. Confirm the real stores are the "single-replica stateful → None" case, and that quarantine needs `minAvail:0`.
   - **Subset actuators** (kv-reset/identity/route): confirm they only win when the blunt move is pruned. Is there a realistic condition we mislabeled?
   - **The served-model bundle** (guardrail-rotate/request-drain/endpoint-rotate): we concluded the attack *type* can't steer to a specific one (§2G). **Try to break that** — is there any policy/physics/annotation configuration where a real attack makes one of them dominate the bundle? If yes, that's a new coverable actuator.
2. **Realness audit.** Any grade of *Real* that's actually contrived? Any CVE mis-cited (verify vs NVD — this project has a standing "verify every CVE" law)? Any *None/gap* that is secretly a Phorvex win we undersold?
3. **Completeness — what's missing entirely?** Candidates we may have folded away or skipped:
   - **MCP-specific attacks** (rogue MCP server, tool-**description** poisoning, tool-**response** injection) — the bot trusts both. Currently only implicit under the confused-deputy row. Should they be explicit?
   - **Cross-call caller-memory contamination** (poison a memory note → recalled into a *future* call's system prompt).
   - Any **2026 OWASP Agentic (ASI01–10)** / **ATLAS agent (T0080–T0086)** technique not represented.
   - **Console/control-plane** attacks (`console.phorvex.ai`) — compromising the defense itself.
   - **Any of the 14 actuators with zero attack** pointed at it (a coverage hole).
4. **Effect-oracle reality-check.** For `kv-reset`, confirm the handler actually calls `/reset_prefix_cache` and that vLLM's endpoint truly evicts (read `internal/actuator/gpu_stack.go` + the AI handlers). For `adapter-rotate`, confirm the vLLM LoRA endpoints exist before planning that test.
5. **Second-order artifacts.** Does `maxMovesPerTick:1` or the 90s `antiOverRotationWindow` create any test artifact (e.g., a second move suppressed in the same tick)?

Report anything you find as edits to `ATTACKS.md` (fix predictions, add rows) + a note to the user. **Bring your own hypotheses** — the goal is the most exhaustive, honest actuator-coverage map possible.

You can re-run or extend the design→adversarial-verify workflow that generated the battery:
`Workflow({scriptPath: "…/workflows/scripts/actuator-coverage-attacks-wf_17d532fd-5f0.js"})` (edit the `LANES` to add coverage). It fans out one designer + one adversarial verifier per lane and returns structured verdicts.

---

## 9. Key files & references

**Working docs** (`operator/build/test-harness/`):
- **`ATTACKS.md`** — the working test doc (54 attacks, graded, actuator-mapped, Test queue). **Start here.**
- `ACTUATOR_COVERAGE.md` — the mechanics north-star (fact→actuator, the existence-test thesis, effect status).
- `ATTACKS_OUTCOMES.md` — the execution ledger (results table + detailed entries T1–T12, verbatim logs, findings); append a `T#` per run.
- `VOICE_AGENT_ATTACK_CATALOGUE.md` (32 voice) · `GENERAL_PURPOSE_ATTACKS.md` (GP1–10) · `ATTACK_CATALOGUE_OLD_VS_NEW.md` (old→new map) — the breadth catalogue the master list draws from.
- `attack-catalogue.html` — boss/VC-facing page (local file, not an artifact).

**Source (the brain)** — `operator/phorvex/internal/`:
- `decision/coverage.go` (selection), `recon/profile.go` + `recon/ucw.go` (fact→cover map), `cost/p1cost.go` (cost), `feasibility/{defaults,actions_native}.go` (feasibility), `ingest/{events,kube}.go` (detection entry), `model/types.go` (actions/policy/pod), `actuator/{handlers_k8s,gpu_stack}.go` (effects).

**Deployment** — `phorvex-voice-agent/` (canonical): `k8s/*.yaml` (bot/chroma/mongo/crm/mcp-server/policy), `bot.py` (the agent), `crm/`, `mcp-server/`, `webclient/`.

**Memory** (auto-loaded for the next agent): `phorvex_actuator_coverage.md` (⭐ current focus), `phorvex_attack_findings.md`, `phorvex_voice_agent_state.md`, `phorvex_catalogue_state.md`, `phorvex_user_mehrdad.md`.

---

## 10. Operating constraints (read before touching anything outward)

- **The user is an AI engineer with no security/k8s background.** Use plain language, one concept at a time, no firehose, and never overclaim — flag uncertainty honestly. They catch overclaiming.
- **Cluster/outward actions need the user's explicit go** and the SSH box. The SSH password is user-provided per session and **must not be stored** (recreate an askpass helper in scratch each turn if needed).
- **Secrets:** handle keys by SHA-256 fingerprint only, never print them. Mongo is deliberately no-auth as an attack surface — that's intended, not a bug to fix.
- **This is separate from the VOLT/trading project** (which borrows the same memory dir). Don't conflate them. If you see `persistent_agent/`, `volt/`, MNQ/MES/trading — that's the other project.
- **Realism is non-negotiable** (it's a VC deliverable): every attack must be something that genuinely happens to a real agentic workload, and the detection must arise *naturally* from it — never "set an annotation to force a fact." A contrived attack proves nothing and would embarrass us in the pitch.

**Bottom line:** the map is built and verified; the next move is to start proving actuators for real. Audit the list, then run `kv-reset`. Good hunting.
