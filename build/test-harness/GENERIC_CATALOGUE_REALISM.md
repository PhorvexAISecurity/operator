# Generic-Catalogue Realism Upgrade — companion to the voice catalogue

> **Historical design record.** This document preserves proposals from an
> earlier catalogue review. It is not an executable coverage manifest, current
> deployment inventory, CVE-applicability decision, or defense result. Every
> proposal remains unimplemented/unverified unless a current source entry and
> retained trial receipt say otherwise. Use the campaign workload benchmark
> contract and CVE applicability ledger for current acceptance decisions.

Turns the ~49 generic toy scenarios (mock servers / `/tmp` markers) into realistic attacks anchored to **real cluster workloads**, each judged against **Phorvex = protection/prevention (proactive motion), not detection.**

**This file, §A, covers the two families a sub-agent safeguard blocked** (`c1-*` classic kill-chain, `c2-*` dwell/rotation) — redesigned by hand from the existing repo files. **§B (the other 7 families → 24 redesigns from the workflow) folds in after CVE verification.**

> **Why §A matters:** the voice catalogue produced **zero `R6Covers`** — nothing Phorvex fully prevents. The `c2` family is the *opposite* end: it's where proactive rotation genuinely **works** (dwell-capping, detected eviction), plus the **feasibility** lesson (rotating a stateful pod is destructive → quarantine). A balanced catalogue needs both ends, or the boss only sees gaps.

CVE references below are historical candidates. They require fresh vendor,
package-version, runtime-configuration, reachability and precondition evidence
before they can anchor an executable case or defense claim.

---

## §A.1 — `c1-*` classic kill-chain (initial-access → persist / lateral / exfil)

Historical design goal: replace busybox+marker with a real initial-access path
whose CVE or exposed-service preconditions are qualified against the current
workload, then make persistence/lateral/exfil follow that proven prior stage.

| # | Scenario | Real anchor + entry | Phorvex | Why |
|--:|---|---|---|---|
| A1 | `c1-escape-persist` | RCE in a real workload (Chroma `45833`) → container escape (runc/kernel CVE) → **node-level** persistence | **Partial→CannotRespond** | rotation caps the in-pod stage; node persistence lives *outside* the pod (node isn't a rotation target) |
| A2 | `c1-lateral` | compromised litellm → hop to `chroma:8000`/`mongo:27017`/`nats` (flat net, no NetworkPolicy) | **Partial** | no traffic inspection; disrupted only as a side-effect of rotating source/target; a quick hop finishes within a cadence |
| A3 | `c1-credtheft-rbac` | read a real pod's projected SA token → call K8s API off-cluster | **CannotRespond** | token theft emits no signal; rotating the pod doesn't revoke an already-exfiltrated, still-valid token *(same shape as the voice key-theft)* |
| A4 | `c1-c2-exfil` | RCE foothold → jittered beacon → drip-exfil staged data | **Partial** | a rotation landing *during* transfer resets it, but can't target the pod on demand; short transfers complete between rotations |
| A5 | `c1-stealth-dweller` | quiet foothold (no shell spawns) via a held-out CVE | **Partial** | no SecurityEvent → quarantine never fires; only blind/scheduled rotation evicts — the enforcement-without-detection value *and* its limit |
| A6 | `c1-heldout-cve` | a **real unpatched CVE with no detector** (Chroma `45833` / litellm `42208`) | **CannotRespond (reactive)** | ★ the strongest case *for* the protection model: no signature → reactive matcher never fires; **only proactive motion touches an undetectable exploit** |
| A7 | `c1-fast-attacker` | a **one-shot** exploit < cadence (litellm SSRF `6587` key theft, MongoBleed `14847`) | **CannotRespond** | a fixed-cadence timer arrives too late; sub-second objectives beat any rotation — only prevention (patch/auth) works |
| A8 | `c1-llm-adaptive` | attacker measures the workload's rotation rhythm, strikes in the lull | **Partial** | a **fixed** period is learnable; a cost-weighted **variable/jittered** rate is not — motivates the "randomness" the boss talks about |
| A9 | `b-recon-lifetime` | recon a real workload's identities/topology; measure map validity | **Partial** | a re-identity move invalidates recon *without a detector*; blind keeps it valid ~its interval, proactive invalidates on rising exposure |

**Detail for the two sharpest:**

- **A6 `c1-heldout-cve` (CannotRespond, reactive):** *This is the catalogue's best argument for Phorvex.* Anchor to a real CVE that no Falco rule covers (Chroma `trust_remote_code` `45833`). Exploit → foothold → **no SecurityEvent is ever emitted**, so the reactive matcher has nothing to match. The *only* thing that evicts it is a **detection-independent proactive move** (the exposure/posture floor). Oracle: foothold established, zero SecurityEvents, evicted only on the proactive cycle. This is exactly "protection, not detection" made concrete.
- **A7 `c1-fast-attacker` (CannotRespond):** anchor to a sub-second one-shot (litellm SSRF steals the provider key in one request). Objective completes *before any rotation interval elapses*. Oracle: key exfiltrated + valid off-cluster within, say, 1s — faster than any cadence. Proves the cadence-vs-speed limit: motion can't win a race it starts after the finish line.

---

## §A.2 — `c2-*` dwell / rotation (tests rotation's *actual* protection properties)

Realism upgrade = same property-test, but the foothold lives in a **real workload** reached via a **real exploit**, not busybox+marker. **This family holds the `R6Covers` wins.**

| # | Scenario | Real anchor + entry | Phorvex | Why |
|--:|---|---|---|---|
| A10 | `c2-dwell-rotation` | in-pod foothold after Chroma RCE (`45833`) / litellm SSTI (`42203`) | **✅ Covers** | ★ the core win: an **ephemeral in-pod** foothold's dwell is capped at the rotation period *regardless of detection* — even a blind timer bounds it |
| A11 | `c2-persistence-evict` | a foothold that **does** trip a Falco rule → SecurityEvent → rotate | **✅ Covers** | the genuine reactive path (belief leg): `{panic,high}` event → matcher → delete/quarantine the matched pod, within seconds |
| A12 | `c2-recon-window` | recon a real workload; rotation staleness | **Partial** | denies *persistence-of-recon* (map goes stale at the interval), not recon itself — one full pass completes within an interval |
| A13 | `c2-lateral-disrupt` | litellm → data-store lateral | **Partial** | no NetworkPolicy/mesh actuator is wired; lateral disrupted only by rotating the moving pod — the "temporal network policy" claim overshoots the code |
| A14 | `c2-c2-disrupt` | beacon from a compromised real workload | **Partial** | identity rotation drops a *long-lived* channel each cycle, but can't kill an active channel on demand; a beacon re-establishes |
| A15 | `c2-stateful-training` | a **stateful** workload — Mongo/Chroma (PVC) or vLLM KV-cache | **Partial** | ★ the feasibility lesson: a blind rotate **destroys the running stateful job**; Phorvex's feasibility model *excludes* rotate on stateful pods and **quarantines** instead — work preserved |
| A16 | `c2-supplychain-foothold` | **merges with §B `c3-supplychain`** (ECR tampered image) | **Partial** | rotation bounds the foothold's *dwell* but **re-pulls the poisoned image** — motion re-detonates; caps dwell, not the pull/exec |

**Detail for the three that carry the message:**

- **A10 `c2-dwell-rotation` (Covers) — the headline WIN.** Anchor: after the Chroma `trust_remote_code` RCE, plant a long-lived in-pod foothold. Oracle: measured **dwell = the rotation interval** (not marketing "0ms"). This is Phorvex's honest, designed-for strength — a long-lived *ephemeral in-pod* foothold is bounded by the period whether or not anyone detects it. **Every voice-catalogue `CannotRespond` was a case where the asset was *not* an ephemeral in-pod foothold; this is the complement.**
- **A11 `c2-persistence-evict` (Covers) — the reactive path working.** A foothold noisy enough to trip Falco → the `belief` leg fires → the matcher rotates the exact pod within seconds. Shows the detector-fed 20% doing its job *when a detector exists*.
- **A15 `c2-stateful-training` (Partial) — the feasibility lesson, and the bridge to the actuator argument.** Rotating Mongo/Chroma/a training job is *destructive* (availability + corruption). Phorvex's feasibility model must exclude rotate here and **quarantine** instead. This is the same "don't rotate stateful → the right actuator is quarantine/data-layer" thread from the voice Mongo work — now a first-class scenario.

---

## §A — what these two families add to the picture

The voice catalogue said "Phorvex can't touch the realistic voice attacks." This family shows the **other half of the truth**, which the boss needs for a fair report:

- **Phorvex genuinely protects** against **ephemeral in-pod footholds** (A10, A11) — dwell-capping and detected eviction are real wins.
- **It cannot help** against **anything that leaves the pod**: node escape (A1), stolen tokens/creds (A3), one-shot exploits (A7), undetectable exploits on the reactive path (A6).
- **Its cadence is a design surface**: fixed periods are learnable (A8), and rotating stateful workloads is destructive (A15) — motivating **jittered rates** and a **feasibility-aware actuator set** (quarantine/drain, not rotate-by-default).

Net: **the wins are narrow and real; the gaps are broad and realistic.** That's the honest shape of a rotation-based defense.

---

## §B — the other 7 families (24 historical redesign candidates)

The earlier “14 of 14 real-and-match” statement was not supported by retained
version/configuration evidence and is withdrawn. The identifiers below are
research leads, not proof that the current stack is affected or that Phorvex
defends them.

**Shape of the 24:** readiness **15 realistic-now · 6 needs-infra · 3 redundant-with-voice** (drop those 3 → **21 net-new**); Phorvex **13 CannotRespond · 10 Partial · 1 Covers**; priority **13 high · 10 medium · 1 low**.

### B.1 — realistic-now (15, build against real workloads today)

| Scenario | Realistic attack | Phorvex | CVE/ref | Pri |
|---|---|---|---|---|
| `c3-imds-theft` | litellm SSRF → EKS node IMDSv2 credential theft | CannotRespond | CVE-2024-6587 | High |
| `c3-sidecar-inject` | persistent sidecar via `deployments:patch` (rotation re-injects) | CannotRespond | — | High |
| `c3-supplychain` | unsigned tampered ECR image admitted (no provenance gate) | CannotRespond | CVE-2025-24357 | High |
| `c3-admission-bypass` | privileged/hostPath pod → node takeover (no PSA) | CannotRespond | CVE-2025-1974 | High |
| `c3-secrets-sprawl` | SA-token + envFrom secret sprawl → cluster-wide creds | CannotRespond | — | High |
| `ai2-embedding-store-tampering` | Chroma embedding overwrite → silent retrieval-bias | CannotRespond | CVE-2026-45830 | High |
| `ai1-inference-manipulation` | litellm callback-hook in-path completion rewrite | Partial | CVE-2026-42271 | High |
| `ai1-llm-jacking` | `sk-noauth` LLM-jacking of the shared vLLM GPU plane | Partial | LLM10 | High |
| `ai2-agent-injection-to-persistence` | injection → Chroma `trust_remote_code` RCE | Partial | CVE-2026-45833 | High |
| `ai2-kvcache-poisoning` | Mooncake unsafe-deserialization RCE candidate; only applicable when the vLLM Mooncake integration and reachable ZeroMQ path are present | Unassessed | [CVE-2025-32444 / GHSA-hj4w-hm2g-p6w5](https://github.com/vllm-project/vllm/security/advisories/GHSA-hj4w-hm2g-p6w5) | High |
| `ai2-data-model-poisoning` | vLLM load-time RCE via poisoned weights/`prompt_embeds` | CannotRespond | CVE-2025-24357 | High |
| `ai2-malicious-model-artifact` | pickle/LoRA deserialization RCE in the vLLM loader | Partial | CVE-2025-24357 | High |
| `c3-cryptomining` | GPU/CPU cryptojacking of the inference nodegroup | Partial | — | Med |
| `ai1-pillar03-panic-mutation` | proposed vLLM foothold eviction via drain-to-clean-node | Unassessed | no qualified CVE binding | Med |
| `ai1-model-theft` | vLLM in-pod weight/adapter exfiltration | Unassessed | no qualified CVE binding | Med |

### B.2 — needs-infra (6, require deploying a target first)

| Scenario | Realistic attack | Missing target |
|---|---|---|
| `ai2-mcp-rogue-server` | malicious MCP server RCE (`mcp-remote`) | **a real MCP server + agent** |
| `ai2-mcp-tool-poisoning` | hidden directives in MCP tool schema | ″ |
| `ai2-agent-excessive-agency` | indirect-injection confused deputy | a real tool-using agent |
| `ai2-gpu-side-channel` | co-resident GPU timing + LeftoverLocals | **GPU tenant co-residency** |
| `ai2-embedding-vector-weakness` | embedding-collision cross-tenant retrieval | **multi-tenant shared Chroma** |
| `c3-cicd` | ECR `:latest` overwrite via build identity | **a real CI/CD pipeline** |

→ Two cheap unlocks cover most of this: **(a) deploy an MCP server + agent** (unblocks 3), **(b) a shared multi-tenant Chroma** (unblocks 1); GPU co-residency and CI/CD are bigger lifts.

### B.3 — redundant-with-voice (3, dropped)

`ai2-agent-memory-contamination`, `ai2-agent-rogue-tool-persistence`, `ai2-mcp-tool-response-injection` — already covered by the voice catalogue's injection / litellm-implant / indirect-injection entries.

---

## Combined picture (§A + §B)

The historical review produced 16 §A and 21 net-new §B design proposals, with
six marked as needing infrastructure and three dropped as redundant. Those
counts describe proposals, not executable or current defense coverage. The
entries remain designs until source, applicability, independent oracles,
matched controls and retained trial evidence satisfy the current contract.
