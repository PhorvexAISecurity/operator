# Attack Catalogue — Old vs. New: Realism Audit & Full Mapping

**Audience:** the boss + the team.
**Purpose:** a complete, honest accounting of (1) why every attack in the *old* catalogue was non-realistic and which *new* attack replaces it, and (2) every attack in the new catalogue — what it does and why it counts as realistic.

> **The one-sentence version:** the old catalogue was ~54 *wiring tests against fake servers* that "succeeded" when a marker string appeared in a mock; the new catalogue is a set of end-to-end attacks against the *real deployed workloads*, each starting where a real attacker starts, built on a real vulnerability or misconfiguration, and scored on real damage.

---

## 0. How to read this doc

### 0.1 What "realistic" means — the 5-point bar
An attack is **realistic** only if it clears all five. The old set failed 1–4 on essentially every entry.

1. **Real target** — the actually-deployed workload and its real dependencies (litellm, Chroma, Mongo, vLLM, NATS, the voice bot), *not* a `MockXServer` busybox stand-in.
2. **Real starting point** — the assume-breach threat model: attacker is past the firewall, on the cluster network, recon done — reaching the target from *outside* it (phone / public `/ws` / network). *Not* "attacker is already inside the pod writing to `/tmp`."
3. **Real mechanism** — anchored to a **published CVE** (verified against NVD) or a concrete misconfiguration of our stack. *Not* an abstract "imagine the model obeys."
4. **Real success** — the oracle is actual harm: keys exfiltrated and valid off-cluster, a DB dumped, the bot's real voice speaking attacker text, a poisoned doc retrieved into a live answer. *Not* "a marker file exists."
5. **Reproducible & observable** — a concrete, re-runnable outcome.

### 0.2 The four defects every old attack had
1. **Fake targets** — mock servers (`MockInferenceServer`, `MockMCPServer`, busybox), never the real services.
2. **Wrong starting point** — the "attack" begins *inside* a pod it already owns (e.g. `echo marker > /tmp/inject`). If you can write to `/tmp`, you've already won — the hard part (getting in) was skipped.
3. **Fake success** — the success oracle is "is this marker string present?" — a value the attack *planted itself*, so it is nearly tautological and never measures damage.
4. **No real chain / no real vuln** — each tested one isolated mechanic in the abstract, not an end-to-end path built on an actual known vulnerability.

> **Receipt (so no one takes this on faith):** the old `ai1-prompt-injection` deploys a busybox `MockInferenceServer`, its "injection" is `echo <marker> > /tmp/inject`, and it "succeeds" when `/tmp/inject` contains that marker. It never speaks to a language model. Source: `scenarios/ai1_prompt_injection.go` + `internal/mocks/ai_standins.go`. Every `ai*/c*` scenario follows this shape.

### 0.3 The new catalogue is three coordinated views (not one flat list)
Because Phorvex is a *general-purpose* defense but the *voice app* is our concrete target, the new work is split across three docs. This is deliberate; the overlaps are intentional.

| View | IDs | Doc | What it's for |
|---|---|---|---|
| **Voice catalogue** | **V1–V26, V28–V32** (31) | `VOICE_AGENT_ATTACK_CATALOGUE.md` | app-specific attacks on the deployed voice bot |
| **General-purpose set** | **GP1–GP10** | `GENERAL_PURPOSE_ATTACKS.md` | workload-agnostic attacks — where motion-based defense *earns its keep* |
| **Generic realism** | **A1–A16** (§A) + **§B** (21) | `GENERIC_CATALOGUE_REALISM.md` | the old k8s/GPU/AI families rebuilt against real workloads |

- **GP1–GP10 is a curated re-framing of the A-set "wins"** (the c1/c2 foothold/dwell attacks) — same attacks, boss-facing framing. They overlap on purpose.
- **The voice catalogue absorbed the ~10 voice-relevant AI toys** (`ai1-prompt-injection`, `ai2-system-prompt-leakage`, etc.) as its realistic `upgrade` entries.
- **Phorvex verdict tags:** `R6Covers` = motion fully prevents · `R6Partial` = motion only *bounds* dwell · `R6CannotRespond` = motion can't touch it (the honest gaps).

### 0.4 Inventory counts (ground truth)
`scenarios/*.go` = **62 files** = **54 attack scenarios** + 3 APT-campaign *harness* files (`apt_actuation_live`, `apt_agent`, `apt_campaigns` — orchestration, not single attacks) + 5 `_test.go`. Three of the 54 are already the *new* realistic builds (`ai3-voice-transcript-exfil`, `c2-stealth-foothold`, `ai2-embedding-tamper-reuse`).

---

# SECTION 1 — The old catalogue: why each was non-realistic + its realistic successor

Grouped by family. Each family shares a mock mechanism (stated once); the table gives the per-scenario specifics and the **new attack ID** that realistically replaces it.

## 1.1 `c1-*` — classic kill-chain (8)
**Shared defect:** busybox target + "attacker already in-pod" + a `/tmp` sleeper/marker oracle; the "initial access" stage is assumed, not performed. **Realistic successor:** §A replaces the assumed entry with a *verified CVE / exposed service* against a real workload. (Also surfaced as the GP wins.)

| Old scenario | What it claimed | Why non-realistic (beyond the shared defect) | New ID |
|---|---|---|---|
| `c1-escape-persist` | container escape → node persistence | escape was a marker write, no real runc/kernel CVE | **A1** |
| `c1-lateral` | pod → neighbor lateral movement | the "hop" was a marker, no real exploited neighbor | **A2** (= GP6) |
| `c1-credtheft-rbac` | SA-token theft + RBAC abuse | no real token read, no real K8s API call | **A3** (= GP9) |
| `c1-c2-exfil` | beacon + drip exfil | simulated beacon marker, no real channel/transfer | **A4** (= GP7) |
| `c1-stealth-dweller` | quiet foothold | marker dweller, no real stealth-CVE entry | **A5** (= GP1/GP2) |
| `c1-heldout-cve` | exploit no detector covers | "held-out CVE" was abstract, not a real CVE | **A6** ★ |
| `c1-fast-attacker` | one-shot faster than cadence | simulated timing, no real sub-second exploit | **A7** |
| `c1-llm-adaptive` | learns the rotation rhythm | abstract timing model, no real workload | **A8** |

## 1.2 `c2-*` — dwell / rotation property tests (8)
**Shared defect:** the property under test (dwell-capping, eviction, quarantine) was exercised on a busybox+marker foothold, not a real exploited pod. **Realistic successor:** §A re-anchors the foothold to a real RCE; **this family holds the `R6Covers` wins.**

| Old scenario | What it claimed | Why non-realistic | New ID |
|---|---|---|---|
| `c2-dwell-rotation` | dwell capped at interval | busybox foothold + marker, no real RCE entry | **A10** (= GP1) ★ Covers |
| `c2-persistence-evict` | detected → rotate | simulated Falco event + marker | **A11** (= GP4) ★ Covers |
| `c2-recon-window` | recon staleness | marker-based recon simulation | **A12** (= GP8) |
| `c2-lateral-disrupt` | lateral disruption | busybox, no real hop | **A13** (= GP6) |
| `c2-c2-disrupt` | beacon disruption | simulated beacon | **A14** (= GP7) |
| `c2-stateful-training` | stateful → quarantine | busybox "training job" marker | **A15** (= GP10) ★ |
| `c2-stealth-foothold` | stealth foothold | *(already rebuilt — one of the 3 real scenarios)* | **built** → A5/A10 |
| `c2-supplychain-foothold` | supply-chain foothold | busybox image + marker | **A16** (merges §B `c3-supplychain`) |

## 1.3 `c3-*` — infra / cloud / supply-chain (7)
**Shared defect:** marker oracles against synthetic k8s objects; no real cloud identity, image, or admission path exercised. **Realistic successor:** §B.1 (build-now) and §B.2 (needs-infra), anchored to real CVEs/misconfigs.

| Old scenario | What it claimed | Why non-realistic | New ID |
|---|---|---|---|
| `c3-imds-theft` | node IMDS credential theft | no real SSRF, no real IMDS call | **§B** `c3-imds-theft` (CVE-2024-6587) |
| `c3-sidecar-inject` | persistent sidecar | marker patch, no real `deployments:patch` | **§B** `c3-sidecar-inject` |
| `c3-supplychain` | tampered image admitted | marker, no real registry/admission | **§B** `c3-supplychain` (CVE-2025-24357) |
| `c3-admission-bypass` | privileged pod → node | marker, no real PSA bypass | **§B** `c3-admission-bypass` (CVE-2025-1974) |
| `c3-secrets-sprawl` | cluster-wide cred sprawl | marker, no real secret/token read | **§B** `c3-secrets-sprawl` |
| `c3-cryptomining` | GPU/CPU cryptojacking | marker "miner", no real resource burn | **§B** `c3-cryptomining` (= GP5 realistic) |
| `c3-cicd` | CI/CD pipeline compromise | no real pipeline exists | **§B.2** `c3-cicd` (needs-infra) |

## 1.4 `ai1-*` — inference-pillar attacks (5)
**Shared defect:** `MockInferenceServer` busybox + marker oracle; never touches litellm/vLLM. **Realistic successor:** the LLM-native ones fold into the **voice catalogue**; the model-server ones into **§B** against real vLLM/litellm.

| Old scenario | What it claimed | Why non-realistic | New ID |
|---|---|---|---|
| `ai1-prompt-injection` | prompt injection + persistence | `echo marker > /tmp/inject`, no real LLM | **V8** (spoken prompt injection) |
| `ai1-inference-manipulation` | completion rewrite in-path | mock server, marker | **§B** `ai1-inference-manipulation` (CVE-2026-42271) |
| `ai1-llm-jacking` | steal/abuse the model plane | mock, no real `sk-noauth` abuse | **§B** `ai1-llm-jacking` (LLM10) + **V11** |
| `ai1-model-theft` | model weight exfiltration | mock, no real weights | **§B** `ai1-model-theft` (vLLM, CVE-2025-32444) |
| `ai1-pillar03-panic-mutation` | panic → rotate | mock + marker | **§B** `ai1-pillar03-panic-mutation` ✅ **Covers** (vLLM drain, CVE-2025-32444) |

## 1.5 `ai2-*` — application/agent/data attacks (23)
**Shared defect:** mock RAG/agent/MCP servers with `*Marker` oracles (`ToolPoisonMarker`, `ConfusedDeputyMarker`, `EmbeddingTamperMarker`, `MemoryContaminationMarker`, …) — success = "marker present in the mock." **Realistic successor:** the retrieval/injection/leak ones → **voice catalogue**; the model/registry/GPU ones → **§B**; three are **dropped as redundant**.

| Old scenario | What it claimed | Why non-realistic | New ID |
|---|---|---|---|
| `ai2-system-prompt-leakage` | system-prompt extraction | mock echoes a seeded marker | **V8** |
| `ai2-query-extraction` | training/KB query extraction | mock, marker | **V9** |
| `ai2-sensitive-info-disclosure` | sensitive data leak | mock, marker | **V9** (LLM02) |
| `ai2-rag-retrieval-poisoning` | RAG poisoning | mock retriever, marker in top-k | **V3** (real Chroma) |
| `ai2-embedding-store-tampering` | embedding overwrite → bias | mock store `StoreContains(marker)` | **§B** (Chroma, CVE-2026-45830) + **V3** |
| `ai2-embedding-tamper-reuse` | tamper persists across reuse | *(already rebuilt — one of the 3 real scenarios)* | **built** (→ V3 / §B) |
| `ai2-embedding-vector-weakness` | embedding-collision cross-tenant | mock top-k marker | **§B.2** (needs multi-tenant Chroma) |
| `ai2-excessive-agency` | over-privileged tool use | mock agent `ActionLogContains(marker)` | **V24** + **§B.2** |
| `ai2-agent-excessive-agency` | confused-deputy tool abuse | mock agent, marker | **§B.2** (needs real agent) |
| `ai2-agent-injection-to-persistence` | injection → persistence | mock agent, marker | **§B.1** (Chroma RCE, CVE-2026-45833) |
| `ai2-agent-memory-contamination` | poisoned agent memory | mock ConfigMap marker | **dropped** — ≡ V3/V18 |
| `ai2-agent-rogue-tool-persistence` | rogue tool persists | mock tool manifest marker | **dropped** — ≡ V15 (litellm implant) |
| `ai2-mcp-rogue-server` | malicious MCP server RCE | no MCP server deployed | **§B.2** (needs MCP) |
| `ai2-mcp-tool-poisoning` | hidden MCP tool directives | no MCP server | **§B.2** (needs MCP) |
| `ai2-mcp-tool-response-injection` | injected MCP tool responses | no MCP server | **dropped** — ≡ voice indirect injection |
| `ai2-data-model-poisoning` | poisoned training data/weights | mock, marker | **§B.1** (vLLM, CVE-2025-24357) |
| `ai2-malicious-model-artifact` | pickle/LoRA deserialization RCE | mock loader, marker | **§B.1** (vLLM, CVE-2025-24357) |
| `ai2-poisoned-model-registry` | poisoned model registry | mock registry, marker | **§B.1** (→ `c3-supplychain`/`data-model-poisoning`) |
| `ai2-tampered-inference-base-image` | tampered base image | mock, marker | **§B** `c3-supplychain` (tampered image) |
| `ai2-kvcache-poisoning` | cross-session KV-cache leak | mock, marker | **§B.1** (vLLM, CVE-2025-32444) |
| `ai2-co-location-cross-tenant` | co-resident cross-tenant read | mock, marker | **§B.2** (needs GPU co-residency) |
| `ai2-gpu-side-channel` | GPU timing / LeftoverLocals | mock, marker | **§B.2** (needs GPU co-residency) |
| `ai2-unbounded-consumption` | resource exhaustion | mock, marker | **V11** / **V21** (denial-of-wallet) |

## 1.6 `ai3-*`, `b-*`, `e-*` (3) and the APT harness (3)

| Old scenario | What it claimed | Status | New ID |
|---|---|---|---|
| `ai3-voice-transcript-exfil` | transcript theft | *(already rebuilt — real Mongo, live-demoed)* | **built** = **V7** |
| `b-recon-lifetime` | recon map lifetime | marker recon | **A9** |
| `e-dilution-fleet` | decoy/fleet dilution | defense-eval harness, not an attack | **A9 / GP8** (recon-staleness) |
| `apt-actuation-live` · `apt-agent` · `apt-campaigns` | multi-step APT campaigns | *harness orchestration, not single attacks* | represented by the V-chains (H1–H14) + §A kill-chains |

**Section 1 coverage check:** all **54** attack scenarios accounted for → **realistic successor** (voice / GP / §A / §B), **dropped-redundant** (3), or **needs-infra** (parked, honestly). Nothing silently disappeared.

---

# SECTION 2 — The new catalogue: every attack, what it does, and why it's realistic

Each entry meets the 5-point bar (§0.1). "Why realistic" cites the specific real target + real entry + real vuln + real success that the old mock lacked.

## 2.1 Voice catalogue (V1–V26, V28–V32)

**Phorvex reality for this app:** `R6Covers = 0`. Against the voice bot, pod-rotation is *never* a full defense — its risks are semantic / data-plane / edge, which motion can't touch. That's the honest headline, and it's *why* the general-purpose set (§2.2) exists.

*(Numbering note: IDs run V1–V26 then V28–V32 — **there is no V27**. The source catalogue numbered its 26 core attacks 1–26 and its 5 framework-refresh additions 28–32; we kept those IDs stable rather than renumber. 31 voice attacks total.)*

| ID | Attack | What it does | Real vuln / origin | Phorvex |
|---|---|---|---|---|
| **V1** | Direct `/ws` pipeline hijack | raw WSS client drives the full STT→LLM→TTS pipeline with a forged `start` frame — no phone, no Twilio, no signature | novel (missing `/ws` auth) | CannotRespond |
| **V2** | Forged `callSid` → operator-credentialed hang-up | trusted caller `callSid` makes the serializer fire an authenticated Twilio hang-up of a victim's live call | **CVE-2026-54695** | CannotRespond |
| **V3** | Poisoned Chroma KB → indirect injection | upsert a poisoned doc into the KB; every future caller asking a matching question hears the attacker's script | CVE-2026-45832/45831 + LLM01/04/08 | CannotRespond |
| **V4** | litellm pre-auth SQLi | Bearer→UNION SELECT dumps provider/master keys + transcripts from litellm's DB | **CVE-2026-42208** | CannotRespond |
| **V5** | litellm `api_base` SSRF | redirect litellm's authed upstream call to steal the provider key → escalate to EKS IMDS | **CVE-2024-6587** | CannotRespond |
| **V6** | MongoBleed heap disclosure | crafted BSON over-reads mongod heap → leaks other callers' transcript PII | CVE-2025-14847 / CVE-2024-10921 | CannotRespond |
| **V7** | Plaintext transcript exfil | connect to the no-auth Mongo, dump all transcripts off-cluster *(live-demoed: T3)* | novel (`ai3`) | CannotRespond |
| **V8** | Live spoken prompt injection | spoken jailbreak leaks system prompt / tool schema, or drives off-policy TTS | upgrade `ai1`/`ai2-sysprompt`; LLM01/07 | CannotRespond |
| **V9** | KB exfil over the phone | jailbreak into "verbatim mode" + broad queries → bot reads internal KB text aloud | OWASP LLM02 | CannotRespond |
| **V10** | pipecat runner `/files` path traversal | unauth read of `/proc/1/environ` → pod secrets + SA token *(N/A unless `--folder`)* | CVE-2026-44716 | Partial |
| **V11** | Denial-of-wallet | `/ws` flood + silent holds burn STT/TTS/LLM spend on our keys | OWASP LLM10 | Partial |
| **V12** | litellm SQLi→SSTI RCE | recover master key via SQLi → template-render RCE → in-pod foothold | CVE-2026-42208/42203 | Partial |
| **V13** | Chroma `trust_remote_code` RCE | set `embedding_function` to a malicious HF repo → RCE on the KB server | CVE-2026-45833 | Partial |
| **V14** | One-packet mongod crash | one crafted BSON crashes mongod; re-crash on each restart | CVE-2026-9740 | Partial |
| **V15** | litellm data-plane implant | register a malicious route/callback → mirror/rewrite all LLM traffic; survives rotation | CVE-2026-42208 | CannotRespond |
| **V16** | Twilio-webhook credential disclosure | unvalidated webhook leaks creds | analogous (CVE-2026-4984 pattern) | Partial |
| **V17** | Supply-chain startup RCE | poisoned dep / Silero model runs code at startup; rotation *re-downloads* the poison | OWASP LLM03 | CannotRespond |
| **V18** | Forged `callSid` → transcript forgery | write attacker-authored transcripts (stored injection) under a spoofed callSid | novel (`ai2-memory`) | CannotRespond |
| **V19** | Cross-tenant Chroma authz gap | authz bypass → full KB exfil | CVE-2026-45830 | CannotRespond |
| **V20** | Deepfake → password-reset flow | voice-clone hits the "say reset password" flow; no caller identity binding | novel | CannotRespond |
| **V21** | Expensive-turn amplification | injection forces a tool loop → cost blow-up | OWASP LLM10 | Partial |
| **V22** | Rotation weaponized into availability drain | hold both replicas with silent sessions so Phorvex's own rotation drops live calls | novel (motion-as-liability) | Partial |
| **V23** | Starlette/multipart DoS | latent multipart parser DoS | CVE-2025-54121 / CVE-2024-53981 | Partial |
| **V24** | Unbounded internal Chroma querying | injection drives runaway retrieval | upgrade `ai2-agency` | Partial |
| **V25** | Livekit pickle RCE over `/ws` | deserialization RCE *(null on 0.0.94 — regression guard)* | CVE-2025-62373 | Partial |
| **V26** | h11 request smuggling | chunked-terminator smuggling *(latent config)* | CVE-2025-43859 | CannotRespond |
| **V28** | Barge-in / interruption injection ("TEAPOT") | interrupt mid-reply so the injection lands while context is half-built → bad tool calls | ASI01 · AML.T0053 · LLM01:2026 | CannotRespond |
| **V29** | Agent-config / hidden-context recon | probe by voice to fingerprint the tool, trigger phrases, hidden RAG schema | AML.T0084 · LLM08:2026 | CannotRespond |
| **V30** | RAG credential harvesting | coax the bot into reading out creds that leaked into the KB | AML.T0082 · LLM02:2026 | CannotRespond |
| **V31** | Caller-ID / ANI spoofing | spoof the phone number to beat "known caller" trust | T9 · ASI03 | CannotRespond |
| **V32** | Human manipulation of callers | weaponize the *trusted* bot to socially-engineer its own callers | T15 · ASI09 · LLM07:2026 | CannotRespond |

**Why these are realistic (vs. the ai1/ai2 mocks they replace):** every V-entry hits a **real deployed service** (the bot's `/ws`, the real litellm/Chroma/Mongo/vLLM), starts **from outside** (phone / public `/ws` / network — never in-pod), is anchored to a **verified CVE or a concrete misconfig** (0 fabricated of 19 checked; 3 mislabels corrected), and **succeeds only on real harm** (keys valid off-cluster, transcripts dumped, the *real voice* speaking attacker text). Contrast the mock they replace: fake server, in-pod start, marker-string "success."

*Excluded as genuinely N/A (so no one wastes a sprint):* DolphinAttack/NUIT ultrasonic (no mic; codec strips >20 kHz), DTMF injection (bot gathers no tones).

## 2.2 General-purpose set (GP1–GP10) — where motion *earns its keep*

**The one law:** *Phorvex wins exactly when the attacker's payload is EPHEMERAL IN-POD STATE* (a shell, implant, miner, live session). It loses when the payload is elsewhere (data-at-rest, a stable Service address, a static credential, a one-shot exfil). Same assume-breach model; target = *any* pod.

| ID | Attack | What motion does | Verdict | Tested |
|---|---|---|---|---|
| **GP1** | Interactive RCE foothold → dwell | proactive rotation caps dwell to the interval | ✅ KILL/BOUND | 🟢 T4+T5 |
| **GP2** | In-pod persistence / backdoor | a fresh pod has none of it | ✅ KILL | ⚪ by mechanism |
| **GP3** | Fileless / in-memory implant | rotation kills the process + memory | ✅ KILL | ⚪ by mechanism |
| **GP4** | Detected compromise → eviction | rotates that exact pod in seconds (belief leg) | ✅ KILL | 🟢 T4 |
| **GP5** | Cryptomining / resource hijack | miner killed each cycle → yield capped | ✅ KILL/BOUND | ⚪ by mechanism |
| **GP6** | Lateral movement | rotating source/target changes IP/identity | ⚠️ BOUND (DNS-blunted) | ⬜ |
| **GP7** | C2 beacon | channel dropped each cycle | ⚠️ BOUND | ⬜ |
| **GP8** | Recon / environment mapping | map goes stale every interval | ⚠️ BOUND | ⬜ |
| **GP9** | Stolen SA-token reuse | identity-rotate would expire it — *not enabled today* | ❌ MISS (needs actuator) | ⬜ |
| **GP10** | Stateful workload compromise | feasibility **quarantines instead of rotating** → contains without destroying data | ✅ CORRECT-BY-JUDGMENT | 🟢 T6 |

**Why realistic:** these are the classic interactive-intrusion / APT-staging pattern on real tenants (litellm, vllm, chatbot, nats), and 4 of the 10 are **verified live on the cluster** (T4/T5/T6, plus the data/cred gaps T2/T3/T7 that prove the other half of the law). The verdicts are honest — 5 clean wins, 3 bounded, 1 miss.

## 2.3 Generic realism §A (A1–A16) — the old c1/c2 families, rebuilt

Replace busybox+marker with a **real initial-access** (verified CVE / exposed service) against a real workload; the persist/lateral/exfil stage then follows a *real* prior stage. **This set holds the two `R6Covers` wins.**

| ID | Rebuilt from | Realistic attack | Phorvex |
|---|---|---|---|
| **A1** | `c1-escape-persist` | real RCE (Chroma 45833) → container escape → node-level persistence | Partial→CannotRespond |
| **A2** | `c1-lateral` | compromised litellm → hop to chroma/mongo/nats over the flat net | Partial |
| **A3** | `c1-credtheft-rbac` | read a real projected SA token → call K8s API off-cluster | CannotRespond |
| **A4** | `c1-c2-exfil` | RCE foothold → jittered beacon → drip-exfil | Partial |
| **A5** | `c1-stealth-dweller` | quiet foothold via a held-out CVE (no shell spawns) | Partial |
| **A6** ★ | `c1-heldout-cve` | real unpatched CVE **no detector covers** → only proactive motion touches it | CannotRespond (reactive) |
| **A7** | `c1-fast-attacker` | sub-second one-shot (SSRF key theft / MongoBleed) beats any cadence | CannotRespond |
| **A8** | `c1-llm-adaptive` | attacker learns a *fixed* rotation rhythm, strikes in the lull | Partial |
| **A9** | `b-recon-lifetime` | recon a real workload's identities; measure map validity | Partial |
| **A10** ★ | `c2-dwell-rotation` | in-pod foothold after real RCE — **dwell capped at the interval even with no detector** | ✅ **Covers** |
| **A11** ★ | `c2-persistence-evict` | foothold trips a real Falco rule → SecurityEvent → rotate in seconds | ✅ **Covers** |
| **A12** | `c2-recon-window` | recon staleness on a real workload | Partial |
| **A13** | `c2-lateral-disrupt` | litellm → data-store lateral | Partial |
| **A14** | `c2-c2-disrupt` | beacon from a compromised real workload | Partial |
| **A15** ★ | `c2-stateful-training` | stateful pod (Mongo/Chroma/vLLM KV) → **quarantine, not destructive rotate** | Partial |
| **A16** | `c2-supplychain-foothold` | ECR tampered image → rotation *re-pulls* the poison | Partial |

**A6 and A10 are the catalogue's best arguments *for* Phorvex:** A6 = an exploit no signature covers, evicted only by detection-independent proactive motion ("protection, not detection" made concrete); A10 = an ephemeral in-pod foothold whose dwell is bounded by the rotation period whether or not anyone detects it.

## 2.4 Generic realism §B — the other 7 families (21 net-new)

**CVE pass: 14/14 real-and-match, 0 fabricated** (several are CISA-KEV, actively exploited). Readiness: **15 realistic-now · 6 needs-infra · 3 dropped-redundant**.

**§B.1 — realistic-now (15, real workloads today):**

| Rebuilt from | Realistic attack | Phorvex | CVE |
|---|---|---|---|
| `c3-imds-theft` | litellm SSRF → EKS IMDSv2 credential theft | CannotRespond | CVE-2024-6587 |
| `c3-sidecar-inject` | persistent sidecar via `deployments:patch` (rotation re-injects) | CannotRespond | — |
| `c3-supplychain` | unsigned tampered ECR image admitted (no provenance gate) | CannotRespond | CVE-2025-24357 |
| `c3-admission-bypass` | privileged/hostPath pod → node takeover (no PSA) | CannotRespond | CVE-2025-1974 |
| `c3-secrets-sprawl` | SA-token + envFrom sprawl → cluster-wide creds | CannotRespond | — |
| `ai2-embedding-store-tampering` | Chroma embedding overwrite → silent retrieval bias | CannotRespond | CVE-2026-45830 |
| `ai1-inference-manipulation` | litellm callback-hook in-path completion rewrite | Partial | CVE-2026-42271 |
| `ai1-llm-jacking` | `sk-noauth` LLM-jacking of the shared vLLM GPU plane | Partial | LLM10 |
| `ai2-agent-injection-to-persistence` | injection → Chroma `trust_remote_code` RCE | Partial | CVE-2026-45833 |
| `ai2-kvcache-poisoning` | cross-tenant prefix-cache timing side channel | Partial | CVE-2025-32444 |
| `ai2-data-model-poisoning` | vLLM load-time RCE via poisoned weights/`prompt_embeds` | CannotRespond | CVE-2025-24357 |
| `ai2-malicious-model-artifact` | pickle/LoRA deserialization RCE in the vLLM loader | Partial | CVE-2025-24357 |
| `c3-cryptomining` | GPU/CPU cryptojacking of the inference nodegroup | Partial | — |
| `ai1-pillar03-panic-mutation` | ✅ **vLLM foothold eviction via drain-to-clean-node** | **Covers** | CVE-2025-32444 |
| `ai1-model-theft` | vLLM in-pod weight/adapter exfiltration | CannotRespond | CVE-2025-32444 |

**§B.2 — needs-infra (6, target not deployed yet):** `ai2-mcp-rogue-server`, `ai2-mcp-tool-poisoning`, `ai2-agent-excessive-agency` (need a real MCP server + agent); `ai2-gpu-side-channel`, `ai2-co-location-cross-tenant` (need GPU co-residency); `ai2-embedding-vector-weakness` (needs multi-tenant Chroma); `c3-cicd` (needs a real pipeline). *Two cheap unlocks — an MCP server+agent, and a shared multi-tenant Chroma — cover most of these.*

**§B.3 — dropped as redundant (3):** `ai2-agent-memory-contamination`, `ai2-agent-rogue-tool-persistence`, `ai2-mcp-tool-response-injection` — already covered by voice V3/V15/V18.

---

## 3. The bottom line for the boss

- **Nothing was lost, and nothing was inflated.** All 54 old scenarios map to a realistic successor, a documented drop (3 redundant), or an honestly-parked needs-infra item (6). The number went *down* because rigor went *up*: fake targets removed, real ones added.
- **The new catalogue tells the whole truth**, including where Phorvex *can't* help (every voice `CannotRespond`). That honesty is what makes the wins (`R6Covers`: A10, A11, `ai1-pillar03`; the live-verified GP1/GP4/GP10) credible.
- **Live-verified so far:** 7 runs, 4 defended / 3 not (`ATTACKS_OUTCOMES.md`) — the wins are the ephemeral-in-pod-foothold class the law predicts; the gaps are static-cred and data-at-rest, also as predicted.

---
*Sources: `VOICE_AGENT_ATTACK_CATALOGUE.md`, `GENERAL_PURPOSE_ATTACKS.md`, `GENERIC_CATALOGUE_REALISM.md`, `BUILD_PLAN.md`, `ATTACKS_OUTCOMES.md`, and the `scenarios/*.go` files themselves. All CVEs verified against nvd.nist.gov.*
