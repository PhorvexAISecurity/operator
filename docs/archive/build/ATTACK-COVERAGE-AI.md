# MITRE ATLAS + OWASP LLM Top-10 — AI Coverage (ATTACK-COVERAGE-AI)

Coverage of **MITRE ATLAS** and the **OWASP LLM Top-10 (2025)** by the **27 AI
scenarios** (`build/test-harness/scenarios/ai1_*.go` x5 + `ai2_*.go` x22). Every
ID below is **ground truth read from the scenario `.go` sources** (the `atlas:` /
`owasp:` literals in each `SuccessOracle`), not from a design doc, and is
reproducible by enumerating those files.

Legend: ✅ COVERED — exercised by >= 1 scenario · ⬜ NOT COVERED · ◻️ MAPPED
(no dedicated scenario, covered indirectly).

> **Tested-vs-not honesty.** "COVERED" means a registered scenario exercises the
> technique/category by its oracle. The complete 2-trial smoke processed **all 27
> scenarios** (21 measured end-to-end on the CPU-only kind node; 6 are
> GPU/MIG/multi-node capability-pending and SKIP-WITH-NOTE on kind). Coverage is a
> property of the **registered scenario set** (fixed by metadata), independent of how
> many ran in any single smoke. Build/vet/test verified live (exit 0).

---

## 1. MITRE ATLAS coverage

**25 / 26 ATLAS techniques** in the harness's declared set are exercised by >= 1
scenario. The single gap is the **parent** `AML.T0010` (AI Supply Chain Compromise),
which is not directly referenced — but BOTH of its leaves ARE covered
(`AML.T0010.001` Hardware/Container Image and `AML.T0010.003` Model), so the parent
is implicitly exercised; the "gap" is a parent-not-leaf labeling artifact, not a
missing attack surface.

| ATLAS ID | Name | Status | Hits | Scenarios |
|---|---|---|---|---|
| AML.T0010 | AI Supply Chain Compromise (parent) | ◻️ MAPPED | 0 | covered via leaves .001 + .003 below |
| AML.T0010.001 | … Hardware/Container Image | ✅ | 1 | ai2-tampered-inference-base-image |
| AML.T0010.003 | … Model | ✅ | 1 | ai2-malicious-model-artifact |
| AML.T0011 | User Execution / Unsafe AI Artifacts | ✅ | 2 | ai1-llm-jacking, ai2-malicious-model-artifact |
| AML.T0015 | Evade AI Model | ✅ | 1 | ai1-inference-manipulation |
| AML.T0018 | Manipulate AI Model (backdoor/poison) | ✅ | 4 | ai2-data-model-poisoning, ai2-malicious-model-artifact, ai2-poisoned-model-registry, ai2-tampered-inference-base-image |
| AML.T0019 | Publish Poisoned Datasets | ✅ | 2 | ai2-data-model-poisoning, ai2-poisoned-model-registry |
| AML.T0020 | Poison Training Data | ✅ | 8 | ai1-pillar03-panic-mutation, ai2-agent-rogue-tool-persistence, ai2-data-model-poisoning, ai2-embedding-store-tampering, ai2-embedding-vector-weakness, ai2-poisoned-model-registry, ai2-rag-retrieval-poisoning, ai2-tampered-inference-base-image |
| AML.T0024 | Exfiltration via AI Inference API | ✅ | 1 | ai1-inference-manipulation |
| AML.T0024.000 | … Infer Training Data Membership | ✅ | 2 | ai2-query-extraction, ai2-sensitive-info-disclosure |
| AML.T0024.001 | … Invert AI Model | ✅ | 5 | ai1-llm-jacking, ai2-embedding-store-tampering, ai2-embedding-vector-weakness, ai2-gpu-side-channel, ai2-kvcache-poisoning-cross-session-leak |
| AML.T0024.002 | … Extract AI Model (replication/theft) | ✅ | 3 | ai1-model-theft, ai2-co-location-cross-tenant, ai2-unbounded-consumption |
| AML.T0029 | Denial of AI Service | ✅ | 3 | ai1-llm-jacking, ai2-co-location-cross-tenant, ai2-unbounded-consumption |
| AML.T0031 | Erode AI Model Integrity | ✅ | 1 | ai1-pillar03-panic-mutation |
| AML.T0034 | Cost Harvesting (compute hijack) | ✅ | 2 | ai1-llm-jacking, ai2-unbounded-consumption |
| AML.T0035 | AI Artifact Collection | ✅ | 3 | ai1-model-theft, ai2-gpu-side-channel, ai2-query-extraction |
| AML.T0037 | Data from Local System | ✅ | 1 | ai1-model-theft |
| AML.T0040 | AI Model Inference API Access | ✅ | 6 | ai1-inference-manipulation, ai1-model-theft, ai2-co-location-cross-tenant, ai2-gpu-side-channel, ai2-mcp-rogue-server, ai2-query-extraction |
| AML.T0048 | External Harms / agent-action harms | ✅ | 9 | ai2-agent-excessive-agency, ai2-agent-rogue-tool-persistence, ai2-embedding-store-tampering, ai2-embedding-vector-weakness, ai2-excessive-agency, ai2-kvcache-poisoning-cross-session-leak, ai2-mcp-rogue-server, ai2-mcp-tool-poisoning, ai2-rag-retrieval-poisoning |
| AML.T0051 | LLM Prompt Injection | ✅ | 9 | ai1-pillar03-panic-mutation, ai1-prompt-injection, ai2-agent-injection-to-persistence, ai2-agent-memory-contamination, ai2-kvcache-poisoning-cross-session-leak, ai2-mcp-tool-poisoning, ai2-mcp-tool-response-injection, ai2-rag-retrieval-poisoning, ai2-system-prompt-leakage |
| AML.T0051.000 | LLM Prompt Injection: Direct | ✅ | 1 | ai1-prompt-injection |
| AML.T0053 | LLM Plugin/Tool Compromise | ✅ | 5 | ai2-agent-excessive-agency, ai2-agent-rogue-tool-persistence, ai2-excessive-agency, ai2-mcp-rogue-server, ai2-mcp-tool-poisoning |
| AML.T0054 | LLM Jailbreak | ✅ | 6 | ai1-prompt-injection, ai2-agent-excessive-agency, ai2-agent-injection-to-persistence, ai2-agent-memory-contamination, ai2-excessive-agency, ai2-mcp-tool-response-injection |
| AML.T0056 | Extract LLM System Prompt | ✅ | 1 | ai2-system-prompt-leakage |
| AML.T0057 | LLM Data Leakage | ✅ | 1 | ai2-sensitive-info-disclosure |
| AML.T0061 | LLM Prompt Self-Replication / cross-session persistence | ✅ | 3 | ai1-prompt-injection, ai2-agent-injection-to-persistence, ai2-agent-memory-contamination |

**Most-leveraged techniques** (the agentic + poisoning weighting): **T0048**
(External/agent-action harms, 9), **T0051** (LLM Prompt Injection, 9), **T0020**
(Poison Training Data, 8).

### ATLAS gap

| ID | Name | Status | Why not a missing surface |
|---|---|---|---|
| AML.T0010 | AI Supply Chain Compromise (parent) | ◻️ MAPPED (0 direct) | Both leaves `.001` (container image) and `.003` (model) are directly covered; the parent is exercised implicitly. A parent-not-leaf labeling artifact. |

---

## 2. OWASP LLM Top-10 (2025) coverage

**9 / 10 categories** have a DEDICATED scenario. **LLM09 Misinformation** is a
deliberate **MAPPED (not dedicated)** entry. (Verified from the `owasp:` literals
in source + the `TestEveryOWASP2025EntryMapped` assertion in
`scenarios/ai_scenarios_test.go`, which intentionally excludes LLM09 from the
"must appear by id" list.)

| OWASP ID | Name | Status | Dedicated count | Scenarios |
|---|---|---|---|---|
| LLM01:2025 | Prompt Injection | ✅ | 8 | ai1-inference-manipulation, ai1-pillar03-panic-mutation, ai1-prompt-injection, ai2-agent-injection-to-persistence, ai2-agent-memory-contamination, ai2-mcp-rogue-server, ai2-mcp-tool-poisoning, ai2-mcp-tool-response-injection |
| LLM02:2025 | Sensitive Information Disclosure | ✅ | 6 | ai1-model-theft, ai2-co-location-cross-tenant, ai2-gpu-side-channel, ai2-kvcache-poisoning-cross-session-leak, ai2-query-extraction, ai2-sensitive-info-disclosure |
| LLM03:2025 | Supply Chain | ✅ | 5 | ai2-agent-rogue-tool-persistence, ai2-malicious-model-artifact, ai2-mcp-rogue-server, ai2-poisoned-model-registry, ai2-tampered-inference-base-image |
| LLM04:2025 | Data and Model Poisoning | ✅ | 4 | ai2-agent-memory-contamination, ai2-data-model-poisoning, ai2-poisoned-model-registry, ai2-rag-retrieval-poisoning |
| LLM05:2025 | Improper Output Handling | ✅ | 3 | ai1-inference-manipulation, ai1-pillar03-panic-mutation, ai2-malicious-model-artifact |
| LLM06:2025 | Excessive Agency | ✅ | 5 | ai2-agent-excessive-agency, ai2-agent-injection-to-persistence, ai2-agent-rogue-tool-persistence, ai2-excessive-agency, ai2-mcp-tool-poisoning |
| LLM07:2025 | System Prompt Leakage | ✅ | 1 | ai2-system-prompt-leakage |
| LLM08:2025 | Vector and Embedding Weaknesses | ✅ | 4 | ai2-embedding-store-tampering, ai2-embedding-vector-weakness, ai2-kvcache-poisoning-cross-session-leak, ai2-rag-retrieval-poisoning |
| LLM09:2025 | Misinformation | ◻️ MAPPED | 0 | mapped onto ai2-rag-retrieval-poisoning + ai2-data-model-poisoning |
| LLM10:2025 | Unbounded Consumption | ✅ | 5 | ai1-llm-jacking, ai1-model-theft, ai2-co-location-cross-tenant, ai2-query-extraction, ai2-unbounded-consumption |

### OWASP gap

| ID | Name | Status | Justification (not a failure) |
|---|---|---|---|
| LLM09:2025 | Misinformation | ◻️ MAPPED (0 dedicated) | Misinformation is an **output-quality** property with **no rotation-relevant infra control** — an MTD cannot move-target away from a wrong answer. It is mapped onto `ai2-rag-retrieval-poisoning` + `ai2-data-model-poisoning` (a poisoned retrieval/model produces misinformation). Explicit in the plan and asserted in `TestEveryOWASP2025EntryMapped` (LLM09 intentionally excluded from the "must appear by id" list). |

---

## 3. Capability-pending (kind has no GPU/MIG, single node)

Measured live on kind (`kind-amtd-test`, single node `amtd-test-control-plane`):
`CapGPU=false`, `CapMIG=false`, `CapMultiNode=false`, `NodeCount=1`. So these 6
scenarios **SKIP-WITH-NOTE** (never failures) and are marked `capabilityPending`
for the AWS/CoreWeave run — they still **count for coverage** because the CPU
stand-ins are built and the scenarios are registered:

| Scenario | Capability | Coverage role |
|---|---|---|
| ai1-llm-jacking | CapGPU | T0011/T0034/T0024.001/T0029, LLM10 |
| ai2-unbounded-consumption | CapGPU | T0034/T0029/T0024.002, LLM10 |
| ai2-kvcache-poisoning-cross-session-leak | CapGPU | T0024.001/T0051/T0048, LLM08/LLM02 |
| ai1-pillar03-panic-mutation | CapMultiNode | T0051/T0020/T0031, LLM01/LLM05 |
| ai2-gpu-side-channel | CapGPU + CapMultiNode | T0024.001/T0035/T0040, LLM02 |
| ai2-co-location-cross-tenant | CapGPU + CapMultiNode | T0024.002/T0040/T0029, LLM02/LLM10 |

The remaining 21 CPU-runnable scenarios carry **zero** capability requirements and
run on kind by config alone.

---

## 4. Coverage summary

- **MITRE ATLAS:** 25/26 declared techniques COVERED (the only gap is the
  `AML.T0010` parent, whose two leaves are both covered).
- **OWASP LLM Top-10 (2025):** 9/10 DEDICATED; LLM09 MAPPED (justified — no
  rotation-relevant infra control).
- **Most-leveraged:** ATLAS T0048 / T0051 (9 each), T0020 (8); OWASP LLM01 (8),
  LLM02 (6), LLM03 / LLM06 / LLM10 (5 each).

See `build/ATTACKS-AI.md` (per-scenario catalog) and `build/EFFECTIVENESS-AI.md`
(smoke results + `$`/Schwartau/reusability + H1/H2/H3).
