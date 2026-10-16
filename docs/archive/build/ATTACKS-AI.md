# AI / LLM / Agentic Attack Scenario Catalog (ATTACKS-AI)

The **27 AI threat scenarios** exercised by the Phoenix / Phorvex attack-benchmark
harness (`build/test-harness/scenarios/ai1_*.go` x5 + `ai2_*.go` x22, one
self-registering file each). Each is scored against a **concrete observable
oracle** (most are **SPLIT** into an in-request half and a persistence half) and
carries an **honest, code-grounded R6-response verdict** plus a **MEASURED**
MTD-effect tag.

All source/R6-tag/ATLAS/OWASP IDs below are **ground truth read from the scenario
`.go` files** (the `Name`, `R6ResponseTag`, `atlas:`/`owasp:` literals), not from a
design doc. Build/vet/test verified live: `go build ./...` exit 0, `go vet ./...`
exit 0, `go test ./... -count=1` exit 0 (9 test packages ok), Go 1.26.3
windows/amd64.

---

## Legends

**R6-response tag** (honest, grounded in `build/AI-MTD-AUDIT.md` + the R6
Phoenix-for-AI product pages):

| Tag | Meaning |
|---|---|
| **R6-COVERS** | a genuine reactive matcher path can disrupt the oracle (here: via a harness-INJECTED panic/drift `SecurityEvent` through the real `matcher.go`). |
| **R6-PARTIAL** | Phoenix disrupts only opportunistically / as a side effect of rotation, not by detection — the marketing claim overshoots the implemented code. |
| **R6-CANNOT-RESPOND** | no matcher path applies; rotation cannot touch the oracle (a genuine Phorvex differentiator — e.g. data-plane / hardware / in-request semantic). |

**MTD-effect tag** (MEASURED per arm from the oracle outcome triple
`{persistenceAchieved, persistenceDisrupted, neutralized}` — **never assumed**):

| Tag | Meaning |
|---|---|
| **MTD-NEUTRALIZES** | a genuine matcher action (INJECTED panic/drift) removed the foothold. |
| **MTD-BOUNDS-ONLY** | rotation caps dwell / reduces replay but the act lands; external endpoint stays stable backend-only (audit #3). |
| **MTD-CANNOT-HELP** | rotation cannot touch the oracle (detector ABSENT/RECEIVER-ONLY, or data-plane / hardware). |

**Historical smoke output and withdrawn claims.** The 2-trial `out-ai-smoke/`
artifact reported four injected-trigger NEUTRALIZES rows. Three of those rows
(`ai2-data-model-poisoning`, `ai2-poisoned-model-registry`, and
`ai2-agent-rogue-tool-persistence`) received scenario-completed golden restoration
after event delivery. Their mitigation claims and percentages are withdrawn.
The retained artifact documents the prior run; it is not evidence that the
configured defender repaired the mock registry digest or tools ConfigMap.
The remaining `ai2-malicious-model-artifact` row is outside this correction.
The three corrected scenarios observe only synthetic served-digest or ConfigMap
membership changes. Their legacy `inRequestAchieved` field means the synthetic
attacker marker was present before response; it does not attest a model pull,
inference, or rogue tool invocation. A matching SecurityEvent proves delivery,
while effect credit requires a changed state and a defender-owned action receipt
for the same target and attempt.

**Capability-pending.** 6 scenarios carry `CapabilityRequirements` and
SKIP-WITH-NOTE on kind (single CPU-only node, `CapGPU=CapMIG=CapMultiNode=false`,
measured live): `ai1-llm-jacking`, `ai2-unbounded-consumption`,
`ai2-kvcache-poisoning-cross-session-leak` (CapGPU); `ai1-pillar03-panic-mutation`
(CapMultiNode); `ai2-gpu-side-channel`, `ai2-co-location-cross-tenant`
(CapGPU+CapMultiNode). Their CPU stand-ins are BUILT; only the headline GPU numbers
are pending for the AWS/CoreWeave run. A skip is **never** a failure.

---

## Group 1 — R6 Phoenix-for-AI product pillars (5)

| Scenario | Source | R6 tag | MTD-effect (a) in-request / (b) persistence | ATLAS | OWASP | Oracle (split) |
|---|---|---|---|---|---|---|
| **ai1-llm-jacking** | R6 Phoenix-for-AI (LLM-Jacking: hijack GPU compute); AUDIT #8 GPU-util RECEIVER-ONLY; ATLAS | R6-PARTIAL | (a) CANNOT-HELP (GPU-util RECEIVER-ONLY, no emitter) / (b) BOUNDS-ONLY via injected panic — **capability-pending (SKIPPED on kind, CapGPU)** | T0011, T0034, T0024.001, T0029 | LLM10:2025 | (a) shadow-compute accrued `work_accrued` > 0 by the shadow marker. (b) shadow foothold/accrual survived a rotation/injected-panic. Headline GPU number CAPABILITY-PENDING. |
| **ai1-model-theft** | R6 Phoenix-for-AI (Model Theft); AUDIT #3 endpoint STABLE backend-only | R6-PARTIAL | (a) CANNOT-HELP (cannot un-steal; scraping-detector ABSENT) / (b) BOUNDS-ONLY (external Service name STABLE, only backend rotates) — **(MEASURED): emitted tag MTD-CANNOT-HELP across all arms** (see note) | T0035, T0024.002, T0040, T0037 | LLM02:2025, LLM10:2025 | (a) a replica/weights blob extracted (digest `sha256:r6thmockweights` captured). (b) the captured external endpoint still serves `/v1/completions` after one backend rotation. |
| **ai1-prompt-injection** | R6 Pillar 01 (rotate AI-request pods; invalidate session; semantic filter deferred to NeMo); AUDIT #10 | R6-PARTIAL | (a) CANNOT-HELP (NeMo semantic filter ABSENT) / (b) BOUNDS-ONLY (pod rotation invalidates session/memory-persisted instruction) — **(expected)** | T0051, T0051.000, T0054, T0061 | LLM01:2025 | (a) the injected instruction fired in the same request (injection marker in mock reply). (b) the override still fires on a later request to the SAME session after one rotation. |
| **ai1-inference-manipulation** | R6 Phoenix-for-AI (Inference Manipulation: intercept static API paths; rotate API paths); AUDIT #3 URL/path rotation ABSENT | R6-PARTIAL | (a) BOUNDS-ONLY (external path STATIC, URL/path rotation ABSENT) / (b) BOUNDS-ONLY (only backend identity churns) — **(MEASURED): emitted tag MTD-CANNOT-HELP across all arms** (see note) | T0040, T0015, T0024 | LLM01:2025, LLM05:2025 | (a) the static inference path intercepted and output tampered (manipulation marker in client output). (b) the in-path proxy still tampers the SAME external path after one backend rotation. |
| **ai1-pillar03-panic-mutation** | R6 Pillar 03 (security agent observes model I/O -> panic-mutate to clean node); AUDIT #9 model-I/O ABSENT / #6 NodeRotate | R6-COVERS | (a) CANNOT-HELP autonomously (model-I/O detector ABSENT) / (b) NEUTRALIZES via INJECTED panic SecurityEvent (the c2-persistence-evict path) — **capability-pending (SKIPPED on kind, CapMultiNode)** | T0051, T0020, T0031 | LLM01:2025, LLM05:2025 | (a) the malicious payload processed (payload marker in model-I/O log). (b) workload panic-mutated to a clean node (old pod UID gone, replacement Running). True relocation MTTR capability-pending. |

> **Note on the 2 MEASURED scenarios.** In the live smoke, `ai1-model-theft` and
> `ai1-inference-manipulation` emitted a CONSTANT `MTD-CANNOT-HELP` for **every**
> arm (d-nomtd / d-r6blindtimer / d-randomequal / d-fullphoenix alike), because the
> scenario source sets `persistenceDisrupted:false` and `neutralized:false` as
> literals (audit-faithful: the external endpoint / static path is STABLE backend-only,
> so rotation genuinely cannot break it). The **BOUNDS-ONLY** foothold effect from the
> audit Model-Theft / Inference-Manipulation rows is therefore **the expected design
> verdict but is not separately measured per-arm in the current code** — an internal
> docstring-vs-emitted-tag inconsistency flagged in review (`ai1_model_theft.go:84-85`,
> `ai1_inference_manipulation.go:75-76`). Honestly reported, not papered over.

---

## Group 2 — OWASP LLM Top-10 / MCP / Agentic / Extraction / KV-cache / Supply-chain / RAG (22)

| Scenario | Source | R6 tag | MTD-effect (a) in-request / (b) persistence | ATLAS | OWASP | Oracle (split) |
|---|---|---|---|---|---|---|
| **ai2-sensitive-info-disclosure** | OWASP LLM02 Sensitive Information Disclosure | R6-PARTIAL | (a) CANNOT-HELP (no output filter) / (b) BOUNDS-ONLY (rotation invalidates session/cred substrate) — (expected) | T0057, T0024.000 | LLM02:2025 | (a) model disclosed a planted secret marker (fake API key in context). (b) the leaked secret still authenticates after a rotation (replay-success). |
| **ai2-data-model-poisoning** | OWASP LLM04 Data and Model Poisoning; mock model registry | R6-CANNOT-RESPOND | Poisoned digest is observed before and after a timed SecurityEvent. Regenerate has no supported action restoring the registry digest; event delivery receives no mitigation credit. | T0020, T0018, T0019 | LLM04:2025 | Initial and post-response served digests are retained; failed reads invalidate the trial. |
| **ai2-excessive-agency** | OWASP LLM06 Excessive Agency (confused-deputy) | R6-PARTIAL | (a) CANNOT-HELP (agency is app-layer) / (b) BOUNDS-ONLY (rotation drops the session/tool grant) — (expected) | T0053, T0048, T0054 | LLM06:2025 | (a) agent invoked a high-privilege mock tool it should not (confused-deputy marker). (b) the excessive grant persists across a rotation. |
| **ai2-system-prompt-leakage** | OWASP LLM07 System Prompt Leakage | R6-PARTIAL | (a) CANNOT-HELP (no semantic filter) / (b) BOUNDS-ONLY (rotation churns serving pod/secret) — (expected) | T0056, T0051 | LLM07:2025 | (a) system prompt (with planted secret) leaked in the completion. (b) a credential from the leaked prompt still works after a rotation. |
| **ai2-embedding-vector-weakness** | OWASP LLM08 Vector and Embedding Weaknesses | R6-PARTIAL | (a) CANNOT-HELP (data-plane store untouched by pod rotation) / (b) BOUNDS-ONLY iff store is pod-backed and rotated; else CANNOT-HELP (measured) — (expected) | T0024.001, T0048, T0020 | LLM08:2025 | (a) a crafted query retrieved cross-tenant/poisoned vectors (leak marker). (b) the tampered embedding survived a rotation (still top-k). |
| **ai2-unbounded-consumption** | OWASP LLM10 Unbounded Consumption (resource/DoS, extraction-by-volume); CPU stand-in for GPU | R6-PARTIAL | (a) CANNOT-HELP autonomously (GPU-util detector RECEIVER-ONLY) / (b) BOUNDS-ONLY via injected trigger — **capability-pending (SKIPPED on kind, CapGPU)** | T0034, T0029, T0024.002 | LLM10:2025 | (a) unbounded query volume accrued cost above budget (`work_accrued` > budget). (b) the consuming client kept its accrual channel across a rotation. Headline GPU $ CAPABILITY-PENDING. |
| **ai2-mcp-tool-poisoning** | MCP: tool-poisoning (poisoned tool description/schema) | R6-PARTIAL | (a) CANNOT-HELP (MCP content is app-layer) / (b) BOUNDS-ONLY iff tool registry is pod/ConfigMap-backed and rotated (measured) — (expected) | T0051, T0053, T0048 | LLM01:2025, LLM06:2025 | (a) a poisoned MCP tool description caused the injected agent action (poison marker in agent log). (b) the poisoned tool definition survived a rotation (still served by `/tools`). |
| **ai2-mcp-rogue-server** | MCP: rogue MCP server (untrusted impersonation/hijack); two mock MCP servers | R6-PARTIAL | (a) CANNOT-HELP (selection is app config) / (b) BOUNDS-ONLY (endpoint rotation backend-only; held rogue DNS not invalidated — measured) — (expected) | T0040, T0048, T0053 | LLM01:2025, LLM03:2025 | (a) agent connected to the rogue MCP server and ran its tool (rogue marker). (b) the rogue-server binding survived a rotation (still reaches `mock-rogue-mcp-svc`). |
| **ai2-mcp-tool-response-injection** | MCP: tool-response injection (malicious content in tool result ingested by model) | R6-CANNOT-RESPOND | (a) CANNOT-HELP (response content is in-request, no semantic filter) / (b) BOUNDS-ONLY (rotation clears agent memory) — (expected) | T0051, T0054 | LLM01:2025 | (a) an injected MCP tool RESPONSE steered the model output (injection marker in completion). (b) the injected directive persisted into agent memory across a rotation. |
| **ai2-agent-memory-contamination** | Agentic: cross-session memory contamination; `agent-memory` ConfigMap | R6-PARTIAL | (a) CANNOT-HELP / (b) BOUNDS-ONLY (rotation that deletes `agent-memory` ConfigMap clears it; external/PVC-backed survives — measured, may flip to CANNOT-HELP) — (expected) | T0051, T0054, T0061 | LLM01:2025, LLM04:2025 | (a) contaminated memory altered the agent's behavior this session. (b) the contamination crossed into a NEW session after a rotation. |
| **ai2-agent-rogue-tool-persistence** | Agentic: rogue tool persistence; `agent-tools` ConfigMap | R6-CANNOT-RESPOND | Rogue tool registration and post-response ConfigMap state are observed separately. Regenerate does not restore this ConfigMap, so a timed event has no credited repair. | T0053, T0048, T0020 | LLM06:2025, LLM03:2025 | Initial and post-response tool sets are retained; failed reads invalidate the trial. |
| **ai2-agent-excessive-agency** | Agentic: excessive agency / confused-deputy (in-depth variant) | R6-PARTIAL | (a) CANNOT-HELP / (b) BOUNDS-ONLY (rotation drops session-scoped grant) — (expected) | T0053, T0048, T0054 | LLM06:2025 | (a) agent tricked into a privileged action against a sandbox resource (confused-deputy marker). (b) the deputy capability persisted across a rotation. |
| **ai2-agent-injection-to-persistence** | Agentic: injection escalating to durable persistence (kill-chain bridge) | R6-COVERS | (a) CANNOT-HELP (no semantic filter) / (b) NEUTRALIZES via INJECTED panic/policy-violation -> Delete (c2-persistence-evict path) evicting the agent pod — (expected) | T0051, T0054, T0061 | LLM01:2025, LLM06:2025 | (a) the injection executed a persistence step (agent backdoor marker planted). (b) the planted persistence evicted by an injected panic (marker gone, old pod UID replaced). |
| **ai2-gpu-side-channel** | Model theft via GPU side-channel (timing/contention); GPU-PENDING | R6-CANNOT-RESPOND | CANNOT-HELP (hardware side-channel below the infra-MTD layer) — **capability-pending (SKIPPED on kind, CapGPU+CapMultiNode)** | T0024.001, T0035, T0040 | LLM02:2025 | (a) a side-channel observation recovered model/secret bits (MOCKED marker; REAL number capability-pending). (b) the side-channel vantage survived a rotation. |
| **ai2-co-location-cross-tenant** | Cross-tenant co-location (co-residency on shared GPU); GPU-PENDING | R6-PARTIAL | (a) CANNOT-HELP autonomously / (b) BOUNDS-ONLY via node-rotation breaking co-location; true relocation CAPABILITY-PENDING — **capability-pending (SKIPPED on kind, CapGPU+CapMultiNode)** | T0024.002, T0040, T0029 | LLM02:2025, LLM10:2025 | (a) attacker achieved co-residency with the victim (co-residency marker). (b) co-residency survived a node rotation (relocation breaks it — number pending). |
| **ai2-query-extraction** | Query-based model extraction (distillation via API queries); CPU-runnable | R6-PARTIAL | (a) CANNOT-HELP (rotation cannot un-distill) / (b) BOUNDS-ONLY (endpoint stable backend-only; rotation reduces held-session replay) — (expected) | T0024.000, T0035, T0040 | LLM02:2025, LLM10:2025 | (a) a usable replica/decision-boundary file extracted from N seeded queries (fidelity marker over threshold). (b) the extraction channel/session survived a rotation (replay-success vs static). |
| **ai2-kvcache-poisoning-cross-session-leak** | KV-cache poisoning / cross-session leak; AUDIT #11 KV-cache ABSENT/GPU-PENDING (mocked) | R6-CANNOT-RESPOND | (a) CANNOT-HELP (KV-cache isolation ABSENT) / (b) BOUNDS-ONLY (a rotation dropping the pod clears the mocked `/tmp/kv`) — **capability-pending (SKIPPED on kind, CapGPU)** | T0024.001, T0051, T0048 | LLM08:2025, LLM02:2025 | (a) a poisoned KV-cache entry leaked another session's content (leak marker; MOCKED on CPU). (b) the poisoned cache entry survived a rotation. REAL KV-cache behavior CAPABILITY-PENDING. |
| **ai2-poisoned-model-registry** | AI supply chain: poisoned model registry | R6-CANNOT-RESPOND | Poisoned digest is observed before and after a timed SecurityEvent. Regenerate repairs a workload baseline, not this registry digest; signing proves provenance, not benignity. | T0019, T0018, T0020 | LLM03:2025, LLM04:2025 | Initial and post-response served digests are retained; failed reads invalidate the trial. |
| **ai2-malicious-model-artifact** | AI supply chain: malicious model artifact (pickle/safetensors loader RCE stand-in); CPU-runnable | R6-COVERS | (a) CANNOT-HELP autonomously (model-I/O detector ABSENT) / (b) NEUTRALIZES via INJECTED panic -> Delete evicting the loader pod; payload exec itself not prevented (MISSING-TRIGGER) — (expected) | T0010.003, T0011, T0018 | LLM03:2025, LLM05:2025 | (a) a malicious deserialization stand-in executed its payload (payload marker — containment-safe busybox echo). (b) the loader foothold evicted by injected panic (marker gone, pod UID replaced). |
| **ai2-tampered-inference-base-image** | AI supply chain: tampered inference base image (poisoned serving layer); reuses MockRegistry tamper pattern | R6-PARTIAL | (a) CANNOT-HELP autonomously (admission/build-time, ModernUnsupported-class) / (b) BOUNDS-ONLY (rotation churns the pod but re-pulls the SAME tampered ref — measured; may stay CANNOT-HELP) — (expected) | T0010.001, T0018, T0020 | LLM03:2025 | (a) the tampered base image's injected layer ran (TamperedMarker written by the serving pod). (b) the tamper re-appears after a rotation because the ref is unchanged. |
| **ai2-rag-retrieval-poisoning** | RAG/data-plane: retrieval poisoning (malicious doc injected into corpus); mock retriever | R6-CANNOT-RESPOND | (a) CANNOT-HELP (data-plane corpus untouched by pod rotation) / (b) CANNOT-HELP if the store survives rotation (measured) — a genuine Phorvex data-plane differentiator — (expected) | T0051, T0020, T0048 | LLM08:2025, LLM04:2025 | (a) a poisoned retrieved document steered the model output (RAG-poison marker in completion). (b) the poisoned document persisted in the corpus across a rotation (still top-k). |
| **ai2-embedding-store-tampering** | RAG/data-plane: embedding store tampering (vector index mutation); mock embedding store | R6-CANNOT-RESPOND | (a) CANNOT-HELP / (b) CANNOT-HELP if store is PVC/external (measured); BOUNDS-ONLY only if pod-backed + rotated — data-plane differentiator — (expected) | T0020, T0048, T0024.001 | LLM08:2025 | (a) a tampered embedding biased retrieval (tamper marker doc returned for an unrelated query). (b) the tampered vector survived a rotation (present after the defensive action). |

For the three corrected registry/tool rows, `CategoryR6Claimed` retains the
historical claim cohort under test. Their `R6-CANNOT-RESPOND` tags state the
current supported response to the measured fixture objective.

---

## Split oracles, attribution, and the trigger path

- **Split oracle.** Of the 27 scenarios, all stamp `splitOracle` per the
  `scenarios/ai_common.go` `aiOracle` builder. The persistence half scores the row
  in the metrics (`splitOracle=persistence` on every measured smoke row); the
  in-request half is carried in `inRequestAchieved` / `persistenceAchieved`.
  `ai2-gpu-side-channel` scores the **in-request** half (it is purely an in-request
  recovery scenario).
- **Trigger attribution (audit honesty).** A `MISSING-TRIGGER:detector-absent` /
  `:receiver-only` / `capability-pending` row is recorded so a missing-trigger
  result is **never** read as a Phoenix defense failure. The measured smoke rows for
  `ai1-model-theft` / `ai1-inference-manipulation` carry
  `triggerAttribution = MISSING-TRIGGER:detector-absent`.
- **Genuine matcher path.** A matching `SecurityEvent` is delivery evidence. For the three registry/tool scenarios above, the mock substrate has no supported Regenerate repair; their post-state stays raw and an unattributed negative is unscored.

See `build/ATTACK-COVERAGE-AI.md` (ATLAS + OWASP coverage) and
`build/EFFECTIVENESS-AI.md` (the live smoke results + `$`/Schwartau/reusability +
H1/H2/H3 + the Pass-A-with-dollars table).
