Workstream input. The architecture docx (Rev 4) is the source of truth.

# WS-7 — External SOTA Survey: Verification Loop Design

**Date:** 2026-10-07 · **Scope:** external state-of-the-art to inform a loop where multiple LLM agents generate attack scenarios and candidate defensive actuators, and a **deterministic referee** (not LLM voting) decides truth.

**Evidence tags:** `[DOC-CITED]` peer-reviewed / primary paper or document · `[DOC-CITED, vendor claim]` vendor or company blog/talk (kept distinct from peer-reviewed) · `[CODE-CITED file:line]` this repo's code · `[INFERRED]` my own reasoning · `[UNVERIFIED]` asserted without a source in this survey. Full source list with dates at the end.

**How the docx uses this survey (docx §12).** The design's central choices — agents generate, a deterministic oracle judges, and an adversarial competition hardens the defence — are drawn from the lessons below. Where a design lesson here differs from what the docx adopted, the docx wins and the difference is noted inline.

---

## 1. Multi-agent consensus / orchestration — and why LLM-majority voting is unreliable

**Key approaches.** Sampling-and-voting ensembles ("Agent Forest"), multi-agent debate (agents critique and revise over rounds), and LLM-as-judge aggregation are the dominant consensus mechanisms.

**Established.**
- `[DOC-CITED]` *More Agents Is All You Need* (Li et al., Tencent, **TMLR 10/2024**) shows raw accuracy scales with ensemble size via sampling-and-voting — but gains are largest on tasks "challenging but not overwhelmingly difficult," and the mechanism is **error cancellation that assumes errors are roughly independent**.
- `[DOC-CITED]` That independence assumption largely fails for LLMs: contemporary models share pretraining corpora, so their errors are **strongly correlated**. Recent work on "minority truth" in multi-agent debate finds the minority holds the correct answer in roughly **1 in 4 divergent cases**, meaning majority vote *systematically suppresses* correct dissent (arXiv 2511.07784, *Can LLM Agents Really Debate?*, **Nov 2025**, and related 2025 debate-diagnostic work).
- `[DOC-CITED]` Debate/consensus evaluated only by outcome proxies (consensus reached, majority vote, LLM-judge score) **hides** sycophancy, domination by an eloquent-but-wrong agent, and premature convergence (same source). Majority voting alone accounts for most of the measured "debate" gains — the deliberation adds little.
- `[DOC-CITED]` LLM-as-judge is itself biased: *Judging the Judges* (ACL/IJCNLP 2025, 150k+ instances) confirms **position bias**; structural-bias studies report **self-preference up to +73 pp** and only moderate inter-judge agreement (Fleiss' κ ≈ 0.36).

**Hype vs real.** "Add more agents / let them debate → truth" is **overstated**. Voting improves averages on benchmarks with independent errors; it does **not** reliably recover ground truth when errors are correlated or the truth is a minority view — exactly the regime of novel attack/defense reasoning.

**Design lesson.** `[INFERRED]` Our instinct to reject LLM quorum is well-supported. Use many agents for **breadth of generation** (diverse attack scenarios, candidate actuators), never for **adjudication**. Truth must be decided by executing the candidate against a grounded oracle, not by counting votes or asking a judge model. A correct minority proposal must be able to win on evidence alone.

---

## 2. Hierarchical / role-based agent architectures, A2A, MCP

**Key approaches.** Orchestrator-worker (a supervisor decomposes a task, routes sub-tasks to specialized workers, aggregates results); role-based crews (planner / red / blue / critic); interoperability substrates A2A (agent↔agent) and MCP (agent↔tools/data).

**Established / credible.**
- `[DOC-CITED, vendor claim]` Anthropic's multi-agent research system (Opus-4 orchestrator + Sonnet-4 subagents) reported **+90.2%** over a single agent on research tasks — but the same writeup stresses: establish a **strong single-agent baseline first** and add multi-agent complexity only when context dilution, specialization, or parallelism demands it; subagents multiply **token cost (~15×)** and coordination overhead.
- `[DOC-CITED]` *MAST: Why Do Multi-Agent LLM Systems Fail?* (Cemri et al., **UC Berkeley, arXiv 2503.13657, Mar 2025, rev Oct 2025**) analyzed 5 frameworks / 150+ traces, deriving 14 failure modes in **three buckets: (a) system/specification design, (b) inter-agent misalignment, (c) task verification & termination** (κ=0.88). Crucially, better prompts/role specs alone did **not** fix failures — they "require more sophisticated solutions." **Verification is a first-class failure category**, not an afterthought.
- `[DOC-CITED]` Agent-interoperability survey (arXiv 2505.02279, **May 2025**) frames MCP vs A2A as **complementary**: MCP is JSON-RPC client-server for **typed, deterministic tool invocation**; A2A (Google 2025, donated to the Linux Foundation) handles agent **discovery/delegation/streaming** via "Agent Cards."

**Hype vs real.** Multi-agent ≠ automatically better; across many benchmarks MAS gains over a strong single agent are **minimal** and failure-prone. The 90.2% figure is a vendor result on a favorable (parallel-search) task class.

**Design lesson.** `[INFERRED]` Keep the hierarchy **shallow and functional**: one orchestrator, a small bounded pool of role-specialized generators (attack / actuator / critic), and — separately — the deterministic referee *outside* the agent graph. Size the pool to the parallelism actually needed, not for "consensus." *(Docx reconciliation: the roster is sized from the scan — tens for small, low hundreds for large, never a fixed count (docx §4) — and in-team agreement is used only to order and select what is tested, never to approve (docx §9).)* Use **MCP** to give agents typed, auditable access to the referee/simulation tools (deterministic execution is MCP's sweet spot); reserve A2A-style messaging for orchestrator↔worker delegation. Treat "task verification & termination" as an explicit designed component, per MAST.

---

## 3. Automated red-team / blue-team (purple) pipelines with a deterministic judge

**Key approaches.** Autonomous red agents (recon→exploit→post-exploit), blue agents that learn defenses, and a scoring layer. The frontier question is **how the judge is grounded**.

**Established / credible.**
- `[DOC-CITED]` *PentestJudge* (Caldwell et al., **Dreadnode, arXiv 2508.02921, Aug 2025**) scores pentest-agent *trajectories* against operational rubrics using a **hierarchical rubric tree** (collapse task → sub-tasks → leaf criteria), best judge **F1 ≈ 0.83**. It is an LLM-as-judge and the authors explicitly flag reliability/consistency limits — i.e., **not ground truth**.
- `[DOC-CITED, vendor claim]` Dreadnode "Catch Me If You Can" (Black Hat 2026): red operates on shared infra; when red finishes, its **verifiable operation/infra state is auto-converted into the scoring rubric for blue** — blue is scored against **what red demonstrably did**, not a pre-written checklist. This is the **deterministic-grounding pattern** we want.
- `[DOC-CITED]`/`[DOC-CITED, vendor claim]` MITRE **CALDERA** — automated adversary emulation on ATT&CK with a C2 server and REST API; BAS platforms execute scripted TTP sequences and verify defense/detection outcomes **by observed effect**. These judge by **execution outcome**, which is inherently deterministic.

**Hype vs real.** Fully autonomous LLM red-teaming demos are compelling but noisy; the **reliable** part is outcome-grounded scoring (CALDERA/BAS, Catch-Me rubric-from-actuals). LLM judges (PentestJudge) are useful for *triage/nuance* at F1~0.8, not for deciding whether a defense actually held.

**Design lesson.** `[INFERRED]` Mirror the Catch-Me pattern: let red agents propose+attempt attacks, record **what verifiably executed**, and derive the blue/actuator success criteria **from that ground truth**, scored deterministically (did the actuator block/contain the observed technique?). Hierarchical rubric decomposition (PentestJudge) is a good structure for the referee's *criteria*, but each leaf must resolve to a **machine-checkable observable**, not an LLM opinion. *(Docx §12: the Catch-Me principle is the same as the loop's round-by-round re-attack and the G1 "defense effect confirmed" gate.)*

---

## 4. Attack-graph generation & reachability-based path analysis

**Key approaches.** Logical attack graphs from host/network config + vuln data; reachability computation of attacker-to-goal paths; mapping primitives to MITRE ATT&CK techniques.

**Established.**
- `[DOC-CITED]` **MulVAL** (Ou et al., USENIX Security 2005) — the canonical open framework: Datalog **interaction rules** over a declarative network/CVE model generate **logical attack graphs**; reachability = which goal states an attacker can derive. The MulVAL-extensions survey (**arXiv 2208.05750, 2022**) maps interaction rules to **MITRE ATT&CK techniques** to measure scenario coverage.
- `[DOC-CITED]`/`[INFERRED]` Well-known limitation: **state-space explosion** on large enterprise graphs; logical (dependency) attack graphs scale better than full state-enumeration graphs. Bayesian/probabilistic attack graphs add likelihood but need calibrated priors.

**Hype vs real.** Attack graphs are **genuinely established** (20 yrs, tool support). Caveat: output quality is bounded by **input model fidelity** (asset/vuln inventory) — garbage in, garbage out.

**Design lesson.** `[INFERRED]` Borrow MulVAL's representation directly: model each attack scenario as a **logical dependency graph** (facts → interaction rules → derived reachable states), with **ATT&CK technique IDs as node labels**. This gives the referee a **declarative, replayable** structure: a candidate actuator "passes" iff it provably removes an edge/rule that was on a reachable attack path. Reachability is deterministic and diff-able — ideal ground truth. Keep per-scenario graphs scoped to avoid state explosion. *(Docx reconciliation, §12/§6: the adopted representation is the repo's recon `Fact.Key()` plus the three reachability edge kinds (NETWORK, RBAC, CO-LOCATION) and the shipped kill-chain Stage enum; ATT&CK technique-ID labelling is not part of the docx design.)*

---

## 5. Defensive verification on digital twins / isolated replicas

**Key approaches.** Build a virtual replica of the target system; execute attacks and candidate defenses against the twin in isolation; measure effect without touching production.

**Established / credible.**
- `[DOC-CITED]` Surveys *Advancing Security with Digital Twins* (arXiv 2505.17310, **2025**) and *Digital Twins in Defence* (arXiv 2508.05717, **2025**): twins let teams **simulate attacks, validate defense mechanisms, and run red/blue exercises in a safe, isolated environment**, and can be fed malicious traffic on emulation ranges.
- `[DOC-CITED]`/`[DOC-CITED, vendor claim]` Cyber digital-twin + attack-graph simulators (e.g., automotive security assessment) couple the twin to attack-graph generation for repeatable assessment.

**Hype vs real.** The *isolation + repeatability* value is real and widely used (cyber ranges, BAS). The hype is **fidelity**: a twin only proves what it faithfully models; **twin ≠ production** behavior for timing, scale, and unmodeled dependencies.

**Design lesson.** `[INFERRED]` Run every candidate actuator against an **isolated replica** seeded with the exact attack trajectory red verifiably executed (per §3). The referee's verdict = deterministic observation on the twin (technique blocked? reachability edge gone? service still healthy?). Track a **fidelity/confidence caveat** with each verdict, and prefer **replaying real observed TTPs** over synthetic ones to narrow the sim-to-real gap. *(Docx §10.1 makes this concrete: a verdict transfers only if the twin reproduces every brain-read input the trace records; otherwise it is NON-TRANSFERABLE, not pass/fail.)*

---

## Consolidated lessons for our loop

1. **Agents generate; a deterministic oracle judges.** Strongly supported: correlated LLM errors + judge bias make LLM quorum/LLM-judge unsafe for truth. `[DOC-CITED]`
2. **Ground truth = observed execution effect**, derived from what the attack *verifiably did* (Catch-Me / CALDERA / BAS pattern), checked on an isolated replica. `[DOC-CITED]`/`[DOC-CITED, vendor claim]`
3. **Represent scenarios as MulVAL-style logical attack graphs labeled with ATT&CK IDs**; an actuator passes iff it provably cuts a reachable attack path. Replayable and diff-able. `[DOC-CITED]`
4. **Shallow functional hierarchy**, small role-specialized generator pool, verification/termination designed as a first-class component (MAST), strong single-agent baseline before adding agents. `[DOC-CITED]`/`[DOC-CITED, vendor claim]`
5. **Use MCP for typed, deterministic referee/sim tool access**; reserve agent-to-agent messaging for orchestration. `[DOC-CITED]`
6. **Let a correct minority win on evidence** — the deterministic path must override majority preference. `[INFERRED]` *(Docx §9.2: an evidence-bearing minority candidate is always tested, never voted out.)*
7. **Adversarial self-play / iterated attack-defence hardens a defence** (red/blue co-training) — the docx (§12) adopts this as the known-good pattern behind the round-by-round competition, and the repo's redteam PPO/POMDP/QD already does it against the real `DualSolver` `[CODE-CITED phorvex/internal/redteam/ppo.go:1-6, pomdp.go:1-16, pbt_qd.go:1-11 — per WS-6 §(c), docx §11.2]`. `[UNVERIFIED]` as a literature claim: the docx tags it as a peer-reviewed citation, but this survey lists no source for it.

---

## Sources
- Li et al., *More Agents Is All You Need*, TMLR 10/2024 — https://arxiv.org/abs/2402.05120
- *Can LLM Agents Really Debate? / diagnostic multi-agent debate*, Nov 2025 — https://arxiv.org/abs/2511.07784
- *Judging the Judges: Position Bias in LLM-as-a-Judge*, ACL/IJCNLP 2025 — https://aclanthology.org/2025.ijcnlp-long.18 ; self-preference study — https://arxiv.org/abs/2406.07791
- Cemri et al., *Why Do Multi-Agent LLM Systems Fail? (MAST)*, UC Berkeley, Mar 2025 (rev Oct 2025) — https://arxiv.org/abs/2503.13657
- Anthropic, *How we built our multi-agent research system*, 2025 — https://www.anthropic.com/engineering/built-multi-agent-research-system
- *A survey of agent interoperability protocols (MCP, ACP, A2A, ANP)*, May 2025 — https://arxiv.org/abs/2505.02279
- Caldwell et al., *PentestJudge*, Dreadnode, Aug 2025 — https://arxiv.org/abs/2508.02921
- Dreadnode, *Catch Me If You Can* (auto rubric-from-red), Black Hat USA 2026 — https://i.blackhat.com/BH-USA-26/Presentations/Final%20Black%20Hat%20Catch%20Me%20If%20You%20Can%20REV-01.pdf
- MITRE CALDERA — https://caldera.mitre.org ; BAS + security chaos engineering, 2025 — https://arxiv.org/abs/2508.03882
- Ou et al., MulVAL (USENIX Security 2005); *Survey of MulVAL Extensions & ATT&CK coverage*, 2022 — https://arxiv.org/abs/2208.05750
- *Advancing Security with Digital Twins*, 2025 — https://arxiv.org/abs/2505.17310 ; *Digital Twins in Defence*, 2025 — https://arxiv.org/abs/2508.05717
