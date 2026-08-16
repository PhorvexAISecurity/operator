# Attack-Agent Build Plan v3 — assume-breach / recon-staleness model

Supersedes v2's threat model. Locked with the boss:

> **Threat model (assume-breach):** the attacker is **already past the firewall, on the cluster network**, and has done **reconnaissance** — they have *seen* the current pod IPs, identities, and topology. They do **not** yet own a pod (code-exec). Every attack starts from *"I'm on the net and I have the map."* The evaluation question for each attack is a **recon-staleness race:** does Phorvex's motion invalidate what the attacker saw *before* they act on it — **and does the attacker even depend on the thing that moves?**

## The crux that decides every verdict

Phorvex (pod-rotate enabled only) moves **pods** → new pod IP + fresh ephemeral in-pod state. What that does and doesn't stale:

| Attacker relies on… | Does rotation stale it? |
|---|---|
| a **pod IP** they memorized | ✅ yes — but almost nobody pins to pod IPs |
| the **Service DNS** (`svc.cluster.local`) | ❌ **no** — the Service is stable; a fresh pod sits behind the same name |
| **data at rest** (PVC: Chroma/Mongo, litellm DB, a Deployment spec, an ECR image) | ❌ no — survives rotation |
| a **static / external credential** (SaaS key, AWS/IMDS session, SA token until TTL) | ❌ no |
| a **one-shot objective** (dump keys / data in < 1s) | ❌ no — done before any cadence |
| an **ephemeral in-pod foothold's dwell** | ✅ **yes** — this is the one thing rotation genuinely bites |

> ### 🔑 Headline finding for the boss
> **In k8s, everything is addressed by stable Service DNS, and only pod-rotate is enabled. So Phorvex's motion is irrelevant to *reaching, exploiting, and exfiltrating* — its only real bite is capping the **dwell** of an in-pod foothold *after* exploitation.** "The attacker has seen our IP" mostly doesn't matter, because nobody targets pod IPs — they target Services, which don't move. The defenses that *would* matter against a reconned attacker — **staling identities (identity-rotate), rerouting services (route-rotate), rotating credentials, encrypting data at rest** — are **not in the enabled actuator set.**

This makes the build plan's job clear: build **Group A** to show the narrow place motion works, and **Group B** to show the broad place it structurally cannot.

---

## GROUP A — motion gets a real shot (build these to prove the defense + its edge)

All start: *attacker on-net, recon done.* The chain reaches an **in-pod foothold**, and motion races the attacker's next move.

| # | Attack | Chain from on-net | What motion stales | Verdict |
|--:|---|---|---|---|
| A1 | **Chroma `trust_remote_code` RCE → foothold** (CVE-2026-45833) | reach `chroma` svc → malicious HF repo runs → shell in Chroma pod → try to persist/pivot | the foothold (ephemeral in-pod) | ✅ **KILL/BOUND** — rotation caps dwell; kills if cadence beats the pivot |
| A2 | **vLLM model-load RCE → foothold** (CVE-2025-24357/-32444) | reach `vllm` svc → poisoned checkpoint on load → shell on GPU pod | the foothold | ✅ **KILL/BOUND** — but re-pulls the same poison on respawn |
| A3 | **litellm SSTI RCE → foothold** (CVE-2026-42203) | SQLi (42208) recovers master key → SSTI → shell in litellm pod | the foothold | ✅ **KILL/BOUND** — *but the keys were already stolen pre-RCE* |
| A4 | **Detected eviction** (the reactive leg) | any noisy foothold trips a Falco rule → SecurityEvent → matcher evicts the exact pod | the foothold | ✅ **KILL** — when an emitter exists |
| A5 | **Dwell / persistence** (the proactive leg) | foothold sits quiet → proactive floor rotates on exposure, no detector needed | the foothold's lifetime | ✅ **KILL/BOUND** — dwell capped at the interval (the honest core win) |
| A6 | **Stolen SA-token / pod-identity reuse over time** | foothold → steal projected SA token → reuse against K8s API repeatedly | the pod identity | ⚠️ **MISS today / BOUND with identity-rotate** — only rotate is enabled; token stays valid |
| A7 | **Lateral movement + C2 across cycles** | foothold in pod X → hop to Y / hold a beacon across rotations | pod IPs/identities in the path | ⚠️ **BOUND** — opportunistic only; a beacon on Service DNS re-establishes |

**Group A truth:** genuine `KILL`s are **A1–A5** and they're all the *same thing* — an **ephemeral in-pod foothold**, killed by dwell-capping or detected eviction. A6/A7 are where motion *would* help if identity/route-rotate were enabled, but aren't today.

---

## GROUP B — motion is structurally irrelevant (build these to prove the gaps)

Each routes around motion via Service DNS, data-at-rest, static creds, or one-shot speed. All `MISS`.

### B.1 — reachable from the *phone / public `/ws`* (don't even need to be on-net)
| # | Attack | Why motion misses |
|--:|---|---|
| B1 | Spoken prompt injection → sys-prompt/tool leak | one LLM turn, stateless |
| B2 | KB exfil over the phone (read-only tool) | single-turn reads; docs on PVC |
| B3 | Deepfake voice-clone → password-reset trigger | identity layer; no k8s asset moves |
| B4 | Denial-of-wallet: `/ws` connection flood | rotate can't throttle inbound; spend is at 3rd-party APIs |
| B5 | Denial-of-wallet: single-call tool-loop amplification | completes mid-call; can't interrupt |
| B6 | Unauth `/ws` pipeline hijack (free bot + forged transcript) | missing-auth is a code property; one handshake |
| B7 | Forged `callSid` → Twilio call-control hijack (CVE-2026-54695) | abuses authorized cred use; cred-rotate is a trap |
| B8 | Forged `callSid` → Mongo transcript forgery | the bot itself writes; forged record at rest on PVC |

### B.2 — reachable *on-net via Service DNS* (the reconned attacker connects by name)
| # | Attack | Why motion misses |
|--:|---|---|
| B9 | litellm pre-auth SQLi → dump provider/master keys (CVE-2026-42208) | Service DNS + one request + static keys |
| B10 | litellm SSRF → steal upstream key (CVE-2024-6587) | DNS + sub-second + static key |
| B11 | litellm SSRF → EKS IMDS → AWS cloud creds (CVE-2024-6587) | DNS + one-shot + cloud session lives ~6h off-cluster |
| B12 | litellm config implant → MITM all LLM traffic (CVE-2026-42208) | implant persists in litellm DB; rotation reloads it |
| B13 | Chroma KB poisoning → indirect injection (CVE-2026-45832/45830) | poison at rest on PVC; rotation re-queries it |
| B14 | Chroma cross-tenant authz → full KB exfil (CVE-2026-45830) | authz bypass; one-shot read; cred-rotate useless |
| B15 | Mongo no-auth transcript dump (misconfig) | DNS + data-at-rest; PVC survives *(already built as toy `ai3` → upgrade first)* |
| B16 | MongoBleed heap disclosure of transcript PII (CVE-2025-14847) | DNS + one-shot unauth read |
| B17 | Sidecar injection via `deployments:patch` | writes the Deployment spec (control plane); rotation *re-injects* |
| B18 | Container escape → node persistence | the node isn't a rotation target |
| B19 | ECR tampered image (needs B11's cloud creds) | image at rest in the registry; rotation re-pulls |
| B20 | Supply-chain poisoned dep/model | reinfects from the same artifact on every respawn |

---

## DROPPED / DEFERRED

- **Dropped (null on the real config):** path-traversal `/files` (bot runs default CMD, endpoint not registered), Livekit pickle RCE (patched in 0.0.94 + Twilio serializer), h11 smuggling (non-default parser), Starlette multipart DoS (only live after signature-checking is added).
- **Deferred (need a target deployed):** MCP family, GPU side-channel (co-residency), multi-tenant embedding-collision, CI/CD overwrite.

---

## Count (assume-breach, proper splits)

| Bucket | Count |
|---|---|
| **Group A — motion gets a shot** | **7** (5 genuine KILL/BOUND + 2 need-more-actuators) |
| **Group B — motion irrelevant (MISS)** | **20** (8 phone-reachable + 12 on-net-via-DNS) |
| **Total distinct build targets** | **27** |
| dropped (null/latent) | 4 |
| deferred (need infra) | ~6 |

**The story this tells the boss:** of 27 realistic assume-breach attacks, Phorvex's enabled motion meaningfully touches **~5** — all the same ephemeral-in-pod-foothold case. The other 22 win because the attacker addresses stable Services, targets data-at-rest, steals static/external creds, or finishes in one shot — none of which pod-rotation moves. **The gap isn't a bug in Phorvex; it's the actuator set.** Closing it means adding identity-rotate, route-rotate, proactive credential rotation, quarantine, and data-layer controls — the exact "proper actuator set" thread from the voice work.

## Recommended build order
1. **B15** — Mongo transcript dump: already built as a toy + demoed live; upgrade to real Mongo (on-net, Service DNS) → establishes the toy→real pattern.
2. **A5 + A1** — the dwell-cap win against a real Chroma-RCE foothold → the one clean place motion works (build a `KILL` so the catalogue shows both sides).
3. **B9 / B11** — litellm key theft → IMDS cloud creds: the sharpest `MISS` (one-shot, static/cloud cred, Service DNS).
4. **B1** — spoken prompt injection: the AI-native headline, phone-reachable.
5. Then the rest of Group B by priority.

---

# v3.1 — 2026 framework refresh (MITRE ATLAS v5.4.0 · OWASP LLM Top-10 2026 · Agentic ASI01–10)

We re-checked MITRE + OWASP; both moved since we mapped them. **The new material is almost all "agentic," "voice-conversation," and "telephony-identity" — exactly the class our original 27 underweighted.** Net: **+5 net-new attacks, +4 watch/conditional, and re-tags on the existing 27.** All 5 net-new are `MISS` for Phorvex (semantic / telephony / one-shot — nothing for pod-rotation to touch).

## What moved in the frameworks
- **MITRE ATLAS v5.4.0 (Feb 2026)** added an **agent-specific family AML.T0080–T0086** (Oct 2025, co-dev'd w/ Zenity). Every ID we used predates it.
- **OWASP LLM Top-10 2026** (Aug 2026): reprioritized — **Excessive Agency → #3**, **Unbounded Consumption → #6** — and **renamed** `LLM07 System Prompt Leakage` → **`LLM08:2026 Hidden Context Exposure`**, broadened to system prompt **+ RAG schema + hidden policy logic**.
- **OWASP Top-10 for Agentic Applications 2026 (ASI01–ASI10)** + the **T1–T15 Agentic Threats** taxonomy — brand-new, our bot is squarely in scope.
- Confirmed twice (ATLAS + voice research): **no audio/voice-specific technique exists** in any catalogue — audio maps to generic `AML.T0015`/`T0043` / `LLM01`.

## NET-NEW attacks to add (5) — build targets #28–#32
| # | Attack | Plain description | Framework IDs | Phorvex | Ready |
|--:|---|---|---|---|---|
| 28 | **Barge-in / interruption injection ("TEAPOT")** | Interrupt the bot mid-reply so the injected instruction lands while its context is half-built → mis-parameterized/unauthorized tool calls. **No text-chat equivalent.** | ASI01, T2, AML.T0053, LLM01:2026 | MISS | now (phone) |
| 29 | **Agent-config / hidden-context recon** | Probe by voice to fingerprint the setup — that a Chroma tool exists, its trigger phrases, the RAG schema and hidden policy — *before* injecting. | AML.T0084 / T0069, LLM08:2026 | MISS | now |
| 30 | **RAG credential harvesting** | Get the LLM to read out **credentials that leaked into the knowledge base** (distinct from dumping docs or poisoning). | AML.T0082, LLM02:2026 | MISS | now (seed a canary secret to test) |
| 31 | **Caller-ID / ANI spoofing** | Spoof the phone number to defeat any "known caller" trust; **supercharges the deepfake-reset (B3)**. STIR/SHAKEN authenticates the carrier, not the speaker. | T9 / ASI03 | MISS | now (telephony) |
| 32 | **Human manipulation — weaponize the bot against its callers** | Via injection or a poisoned KB, steer the *trusted* bot to socially-engineer callers (tell them to call a premium line, read out a card). Harm flows **outward to callers**. | T15 / ASI09, LLM07:2026 | MISS | now |

## Watch / conditional (4) — track, don't build yet
- **Transcription-layer / homophone guardrail evasion** (`AML.T0068`) — say a payload that STT normalizes past a keyword filter. **Latent for us: no guardrail exists between STT and the LLM yet** — this is the attack that defeats the guardrail we'd add.
- **Cross-call memory poisoning via a transcript→RAG feedback loop** (`AML.T0080.000` Memory) — **N/A today** (we save transcripts but don't re-ingest them); becomes live if we ever feed transcripts back into retrieval.
- **Codec-robust adversarial audio** (`CodecAttack`, arXiv 2026) — the one hidden-voice-command variant engineered to survive the VoIP codec. Emerging research, not turnkey.
- **Repudiation / untraceability** (`T8`) — test whether transcripts log tool-calls with integrity so an action can't be made non-attributable. (Audit gap, not an exploit.)

## Explicitly N/A — do NOT build (rigor, so nobody wastes a sprint)
- **DolphinAttack / NUIT** (ultrasonic voice commands) — our bot has **no microphone**; audio is a telephony stream and the codec strips >20 kHz. Famous, irrelevant here.
- **DTMF injection** — our bot gathers **no touch-tones** (pure voice), so there's nothing to inject into.

## Re-tags on the existing 27 (no new attacks — modern IDs added)
- B1 spoken injection → `ASI01`, `AML.T0053`, `LLM01:2026`
- B2 KB exfil → `ASI02`/`T2`, `AML.T0085.001`, `LLM08:2026`
- B13 KB poisoning → `ASI06`/`T1`, `AML.T0080`, `LLM05:2026`
- B3 deepfake reset → `T9`/`ASI03` (pair with #31)
- B4/B5 denial-of-wallet → `LLM06:2026` (↑#6), `T4`, `AML.T0034.002`
- Excessive Agency (our retrieval tool) → `LLM03:2026` (↑#3)
- B20 supply chain → `ASI04`, `AML.T0011.002`, `AML.T0010`

## Verification note
OWASP `ASI01–ASI10`, `T1–T15`, and the `LLM08:2026` rename are solid (multiple sources / the OWASP repo). The ATLAS **agent-era IDs (T0080–T0086, T0011.002)** were cross-checked against ATLAS's GitHub data + the co-authors' writeup, but the live `atlas.mitre.org` pages are a JS app the researcher couldn't fully render — **do a 5-minute manual click-through of those pages to confirm exact names before this goes in the boss deck.**

## Updated count
**27 → 32 buildable-now realistic attacks** (+5), plus a **4-item watch list** and a **2-item explicit-N/A list**. The additions don't change the headline: still ~5 of the now-32 are things Phorvex's pod-rotation can meaningfully touch — the new ones are all agentic/voice/telephony, which is squarely in the "motion can't reach it" column.
