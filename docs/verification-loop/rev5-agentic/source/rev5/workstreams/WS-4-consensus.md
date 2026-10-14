Workstream input. The architecture docx (Rev 4) is the source of truth.

# WS-4 — Consensus & Deliberation

**Workstream:** Verification loop · Consensus & deliberation (docx §9)
**Mode:** READ-ONLY design. No product change is authorized by this document.

**Tag legend:**
- **[CODE-CITED file:line]** — directly supported by the cited `file:line` in this repo's code.
- **[DOC-CITED]** — supported by a doc, report, markdown file or paper (incl. the architecture
  docx and WS-7's literature survey).
- **[INFERRED]** — a design choice that follows from cited facts but is not literally in the code.
- **[UNVERIFIED]** — asserted, labelled, or held as a configurable parameter (docx §14).

---

## 0. The one rule

Consensus here is the mechanism by which each team finds better solutions **faster**. Within a team
the agents propose, critique, merge and rank candidates, and agree on which to send to the brain
first; they learn from the brain's decline reasons each round and converge on the next best
candidate. **Agreement decides *what to test and in what order* — it never approves. Only the brain
and the measured gates approve.** `[DOC-CITED docx §9]`

Consensus is therefore never "a quorum of LLMs agreeing." The repository already draws the lines
this rests on:

- Attack reality is proven by correlated producer evidence, **not** a handshake or a claimed
  identifier: *"Neither a handshake nor a claimed SID establishes loss"*
  [CODE-CITED `phorvex/internal/voiceadmissionpolicy/contract.go:86-88`], cross-checked against an
  independent provider receipt [CODE-CITED `.../contract.go:236-248`].
- Actuator success is **not** dispatch: *"Dispatch is not effect confirmation"*
  [CODE-CITED `phorvex/internal/console/owner.go:74-95`]; the owner outcome flags are
  *"Deprecated: always false, confirmation unavailable"*
  [CODE-CITED `phorvex/internal/console/owner.go:46-49`].
- The brain can **reject a whole tick** rather than launder an invalid empty set into a no-op
  [CODE-CITED `phorvex/internal/decision/optimizer.go:23-28`].

---

## 1. The in-team deliberation protocol (docx §9.1)

Each team (the **attack team**; the **actuator team**) runs the same protocol independently, **per
round** of the competition (docx §3), on cheap *predicted* scores — **no brain or twin call happens
inside deliberation**, so it is fast. `[DOC-CITED docx §9.1]`

- **Roles.**
  - *Proposers* — the diverse persona specialists (WS-2 roster / WS-3 roster) emit candidate
    fragments / actuators.
  - *Critics* — peer personas adversarially read each candidate and **predict which deterministic
    check will reject it** (attack side: which of C1–C6 is weakest? actuator side: will the brain
    fail to SELECT, or a gate fail?).
  - *Aggregator* — **deterministic code** that merges, scores and ranks; it is not an agent and
    casts no opinion.
- **Rounds of critique.** A **bounded** number of critique rounds (a configurable parameter,
  docx §14 P2). Each round: every candidate collects peer critiques; candidates are merged (dedup
  by fingerprint; complementary fragments fused into cascades); each gets a **predicted-pass score
  from a deterministic rank-aggregation of its critiques (e.g. Borda / median rank)**, never a
  free-form vote.
- **How disagreement is resolved.** Disagreement over *ordering* is resolved by the deterministic
  rank-aggregation, and the spread is recorded (stated, not averaged into a false consensus).
  Disagreement over *inclusion* is resolved in favour of evidence: a candidate that carries a
  specific cited precondition/edge is **never dropped by a vote** (§2).
- **How ranking is agreed.** The agreed order is the deterministic aggregate of the diverse
  personas' predicted-pass scores — most-likely-to-pass first. Ties fall through to a fixed key
  (candidate fingerprint). The ranking is a **prior over what to test**, nothing more.
- **When to stop deliberating.** Stop at the earliest of: (a) a **fixpoint** — no new distinct
  candidate is produced; (b) a **stable top-of-queue** across two rounds; or (c) the
  **critique-round budget**. Then the ranked send-queue is handed to the gate + brain.
- **Learning from decline reasons (decline-reason memo).** When the brain/gate declines a tested
  candidate, its machine-readable reason — the closed `ExclusionKind`/`Status` vocabulary
  (`no-cover`, `slo-gate`, existential `MissingKeys`, a feasibility veto string, …) — is fed back as
  the next round's **decline memo**. The team then converges on the next best candidate that
  specifically avoids that decline: `slo-gate` → a gentler in-process actuator; `MissingKeys` → an
  actuator covering those keys; `no-reachable-path` → a different edge.

### 1.1 Deliberation pseudocode (docx §9.1)

```
function Deliberate(team, signal, declineMemo, budget):   # inside ONE team, per round; no brain/twin call
    cands = concat(persona.Propose(signal, declineMemo) for persona in team.diverse_personas)
    for r in 1..budget.critiqueRounds:
        for c in cands: c.critiques += [p.Critique(c) for p in team.peers(c)]   # predict the weakest check
        cands = Merge(cands)                       # dedup by fingerprint; fuse complementary -> cascades
        for c in cands: c.predScore = RankAggregate(c.critiques)   # Borda/median, deterministic
        if Fixpoint(cands) or TopStable(cands): break
    queue = RankDesc(cands, by=predScore)          # most-likely-to-pass FIRST (convergence speedup)
    queue = KeepAlways(queue, EvidenceBearingMinority(cands))   # a cited-evidence minority is never voted out
    return queue        # ORDER + inclusion to TEST; approval is decided ONLY by brain + measured gates
```

Deliberation chooses what to test and in what order; it never approves. The orchestrator then runs
the queue through the gate + brain (§3), early-stops on the first confirmation, and feeds the
decline reason of any reject back as `declineMemo` for the next round. `[DOC-CITED docx §9.1]`

---

## 2. Diversity decorrelates error; a minority with evidence is still tested (docx §9.2)

Majority agreement reduces random errors and hallucinations — but only to the extent agents'
errors are independent [DOC-CITED WS-7: *More Agents Is All You Need*, TMLR 2024]. So the roster
uses **diverse personas AND a mix of underlying models**, so their errors are less correlated and
the agreed ranking is a better prior — decorrelating errors is what lets agreement reduce
hallucination. Because agents can still share a blind spot, **agreement is never proof**: a minority
proposal that carries specific evidence (a concrete cited precondition, edge, or cover key) is still
sent to the brain — it is guaranteed a slot in the send-queue and is never eliminated by the vote.
The correct answer is a minority view in roughly 1-in-4 divergent cases [DOC-CITED WS-7:
minority-truth, arXiv 2511.07784, Nov 2025], so suppressing dissent would suppress truth. Ranking
only reorders; the brain and the measured gates decide. `[DOC-CITED docx §9.2]`

---

## 3. How it speeds convergence (docx §9.3)

- **Test the most promising first.** Ranking by predicted-pass means the first brain/twin
  evaluation is the one most likely to confirm — fewer expensive evaluations to the first WIN.
- **Guided, not blind, search.** Decline-reason feedback turns each round into a directed step
  (avoid *this* exclusion), collapsing the candidate space geometrically instead of linearly — the
  same reason the loop re-attacks winners with memory (docx §3).
- **No wasted evaluations.** Merge removes duplicate/equivalent candidates before they cost a brain
  call; the fixpoint/top-stable stop avoids over-deliberating.
- **A better prior from decorrelated agents.** Diverse models make the agreed order a sharper
  prior, so the ranking's top-k contains the eventual winner more often — verification stays a
  first-class, separate component, per MAST [DOC-CITED WS-7].

---

## 4. Agreement selects, never approves — the invariant (docx §9.4)

Each round's promotion is governed by one invariant — consensus is never "a quorum of LLMs
agreeing":

```
INVARIANT PromotionSource(p):
  promoted(p) ⇔ capability.Eligible(p)        # gate.go:6-43
              ∧ feasibility.Evaluate(p).Feasible # constraint.go:58-69
              ∧ reaches_real_asset(p, G0)        # reachability.go:144-165
              ∧ brain.SelectedExactly(p)         # optimizer.go:17-28
              ∧ p.Trace.Validate() == ok         # decision_trace_v3_test.go:388-416
              ∧ GroundTruthProven(p)             # evidence, §4.1

FORBIDDEN as a term of promoted(p):
  count(generators_agreeing)   count(validators_agreeing)   any(LLM_self_confidence)
  # may ONLY influence: pool size, the generation memo, early-stop of GENERATION,
  #                     and the ORDER + inclusion of what is TESTED (the §1 send-queue)
  # a minority candidate carrying cited evidence is ALWAYS tested, never voted out
```

Citations behind each term: capability gate — evaluated BEFORE scoring, closed exclusion set
`not-installable | no-cover | capability-unsupported | no-rbac` plus `code-exec` where
*"RBAC-allowed ≠ admission-verified"* [CODE-CITED `phorvex/internal/capability/gate.go:6-7,20-43`];
feasibility — *"the FIRST veto wins"*, a panicking law vetoes, *"uncertainty must never become
actuation"*, `noop` always feasible [CODE-CITED `phorvex/internal/feasibility/constraint.go:10-14,43-69`];
reachability ground truth [CODE-CITED `phorvex/internal/graph/reachability.go:144-165`]; swappable
brain + checked tick-rejection [CODE-CITED `phorvex/internal/decision/optimizer.go:17-28`]; trace
validity [CODE-CITED `phorvex/internal/decision/decision_trace_v3_test.go:388-416`].

If an implementation ever lets any FORBIDDEN quantity appear on the right-hand side of
`promoted(p)`, the consensus is broken by definition. Deliberation (§1) sets what the brain tests
first; it never promotes. Metrics (docx §8 / WS-3 §3) are computed after promotion and can only
fail/defer an actuator, never promote one. `[DOC-CITED docx §9.4]`

### 4.1 Ground truth — `GroundTruthProven(p)`

- **Attack is real** only when evidence correlates against an independently produced receipt —
  *"neither a handshake nor a claimed SID establishes loss"*
  [CODE-CITED `phorvex/internal/voiceadmissionpolicy/contract.go:86-88,236-248`]; for K8s, a
  traversed `edgeExists` path in `G0` plus an observed effect [INFERRED, from
  `phorvex/internal/graph/reachability.go:144-165`].
- **Actuator works** only when the post-actuation graph `G1` has the attack's edge removed AND the
  actuator did not return a `NoEffectRefusal` — *"Dispatch is not effect confirmation"*
  [CODE-CITED `phorvex/internal/console/owner.go:74-95`; `phorvex/internal/actuator/actuator.go:23-53`].
  The actuator contract states refusal is a *"positively established pre-mutation refusal"* and
  callers *"must never infer a refusal from Emitted=false"*
  [CODE-CITED `phorvex/internal/actuator/actuator.go:23-53`].

### 4.2 A2A / MCP transport

Agent↔orchestrator calls ride MCP tool invocations; only known-good descriptors (pinned by
`goodDescriptorSHA256`) are invocable, so an agent cannot smuggle an unknown capability into the
loop [CODE-CITED `phorvex/internal/voicemcppolicy/contract.go:33-42,76-93,103-130`]. **PROPOSE**
and **CRITIQUE** steer *generation only*; acceptance into the ledger needs a validated trace +
exactly one trusted, positive-weight event — the live acceptance predicate rejects when
`trace.Validate() != nil` and requires `trusted == 1 && matched`
[CODE-CITED `phorvex/internal/console/voice_mcp_decision.go:33-50`]; an untrusted event has
*"aging weight is 0 and the record says present=false"*
[CODE-CITED `phorvex/internal/model/types.go:745-747`].

### 4.3 K8s and AI/GPU are first-class

Both K8s and AI/GPU surfaces are first-class through the **same** pipeline: K8s moves (quarantine,
rotate) and AI/GPU moves (kv-reset, warm-swap, mig-rebind, adapter-rotate, voice MCP/admission
enforce) are all actions the capability gate already enumerates
[CODE-CITED `phorvex/internal/capability/gate.go:64-82`], and reachability edges span NETWORK,
RBAC-lateral and CO-LOCATION (the GPU co-residency path)
[CODE-CITED `phorvex/internal/graph/reachability.go:5-16,144-165`].

### 4.4 Early-stop & efficiency within a round

The round breaks as soon as the brain selects, the trace validates, and ground truth is proven; the
pool starts small, grows on non-convergence, caps at `budget.maxAgents`; `G0`, the O(1) capability
index and the shared SSAR auth cache are built once per tick; the shadow path returns
`ErrShadowCapabilityUnavailable` (treated as *defer*) rather than re-issuing SSARs
[CODE-CITED `phorvex/internal/capability/gate.go:9-13`;
`phorvex/internal/decision/optimizer.go:30-36,56-64`]. The shadow path *"evaluates the same state
and substrate without persisting dual-price or kill-chain-memory updates"*, so refereeing a
proposal never teaches production [CODE-CITED `phorvex/internal/decision/optimizer.go:30-36`].
Early-stop is a stop of *generation*, never a lowering of the promotion bar.

### 4.5 Diagram (docx D3 — in-team deliberation)

```
propose (diverse personas+models) ▶ peer critique ▶ merge ▶ rank-aggregate (deterministic)
  ▶ send-queue (most-likely-first; evidence-bearing minority kept)
  ▶ gate+brain in order ─confirmed▶ WIN (early-stop)   ─declined▶ reason feeds back ▶ next
```

---

## 5. Honest CANNOT-HELP

When nothing converges — the gate vetoed everything, the brain refused, or evidence never
correlated — the result is an explicit **CANNOT-HELP** built from the **closed** rejection
classifier; it never fabricates a confirmation and never downgrades to a silent no-op (docx §2
rail 5, §3.2):

- A refusal is logged as a distinct outcome *"without fabricating a zero-decision result"*, and the
  reason *"must come from the runner's closed classifier"*
  [CODE-CITED `phorvex/internal/audit/log.go:935-940`]; a healthy empty tick is explicitly
  distinguished from a selection refusal [CODE-CITED `phorvex/internal/audit/log.go:924-927`].
- Reactive-only / unsupported states are recorded honestly — `scored=false`,
  `exclusionKind=reactive-only` [CODE-CITED
  `phorvex/internal/decision/decision_trace_v3_test.go:240-263`]; a NaN input fails **closed** to
  `infeasible` [CODE-CITED `phorvex/internal/decision/decision_trace_v3_test.go:204-238`].
- CANNOT-HELP is an existing, accepted terminal state — made **audit-only**, not asserted away
  [DOC-CITED `PX_Reports_V1/coversets/COVERSETS-DECISION.md:41-45`].

Ordering of *confirmed* actuators is not a consensus concern: it is the docx §8.4 metric ranking
(dwell → durability → collateral → cost → actuator id), specified in WS-3 §3.4.

---

## 6. Configurable parameters (docx §14) and fixed invariants (docx §14.1)

Numeric thresholds are **configurable parameters (docx §14)** read from policy/config at run time,
each with a safe default and logged with the verdict — not hardcoded, and not routed to any external
owner. Those that touch consensus/deliberation:

| docx §14 | Parameter | Note / anchor |
|---|---|---|
| P2 | Competition max-rounds budget; per-round early-stop confidence; deliberation critique-round budget | guarantees termination (docx §3.2, §9.1) |
| P3 | Consensus `N_confirm`; false-accept vs false-reject operating point | code already fails **closed** on feasibility/NaN [CODE-CITED `phorvex/internal/feasibility/constraint.go:43-55`; `phorvex/internal/decision/decision_trace_v3_test.go:204-238`], **open** on SSAR-unknown (`RBACUnknown`, flagged) [CODE-CITED `phorvex/internal/capability/gate.go:96`] |
| P4 | Conformal quantile α and recalibration cadence | trace carries `ConformalQuantile`, `calibrated=false` on cold start [CODE-CITED `phorvex/internal/decision/decision_trace_v3_test.go:149-189`] |
| P5 | Evidence-correlation strictness (producer correlations, timing-skew tolerance) | contract uses one provider receipt within bounded skew [CODE-CITED `phorvex/internal/voiceadmissionpolicy/contract.go:236-248`] |
| P7 | Per-tenant agent/token budget | bounds CoverageEngine work and LLM spend |

**Fixed invariants — NOT configurable** (docx §14.1):
- **No quorum / LLM-agreement count as a promotion criterion** — there is no such parameter;
  agreement is not a discriminator (§4).
- **Reachability over-approximation direction and `maxHops=3`, `hopDecay=0.5`** — pinned so Phorvex
  never *under*-estimates reach [CODE-CITED `phorvex/internal/graph/reachability.go:11-16,80-83`].
- **Brain structure unchanged**; metrics never touch `Decide`.

---

## 7. Citation ledger

| Claim anchor | Source |
|---|---|
| Reachability = deterministic ground truth; over-approximate; NETWORK/RBAC/CO-LOCATION edges; `maxHops=3`,`hopDecay=0.5` | [CODE-CITED `phorvex/internal/graph/reachability.go:5-16,80-83,144-165`] |
| Swappable brain; checked tick-rejection; shadow w/o persistence; `ErrShadowCapabilityUnavailable` | [CODE-CITED `phorvex/internal/decision/optimizer.go:17-36,56-64`] |
| Hard-law veto, first-veto-wins, fail-CLOSED, noop feasible | [CODE-CITED `phorvex/internal/feasibility/constraint.go:10-14,43-69`] |
| Capability gate: before scoring, O(1) index, closed exclusion set, RBAC-unknown fail-open, AI/GPU + K8s actions | [CODE-CITED `phorvex/internal/capability/gate.go:6-13,20-43,64-82,96`] |
| Attack-real = correlated provider evidence, not a handshake/SID | [CODE-CITED `phorvex/internal/voiceadmissionpolicy/contract.go:86-88,116-117,193-219,236-248`] |
| Replayable verdict: trace carries BrainImage/GitSHA/DecisionEngine; required audit keys | [CODE-CITED `phorvex/internal/audit/decision_trace_test.go:15-23`; `phorvex/internal/audit/schema_replay_test.go:13-26`] |
| MCP tool pinning by good-descriptor SHA | [CODE-CITED `phorvex/internal/voicemcppolicy/contract.go:33-42,76-93,103-130`] |
| Acceptance needs a validated trace + exactly one trusted, positive-weight event | [CODE-CITED `phorvex/internal/console/voice_mcp_decision.go:33-50`; `phorvex/internal/model/types.go:745-747`] |
| Dispatch ≠ confirmation; outcome flags deprecated/unconfirmed | [CODE-CITED `phorvex/internal/console/owner.go:46-49,74-95`] |
| Actuator refusal is positively established; never infer from Emitted=false | [CODE-CITED `phorvex/internal/actuator/actuator.go:23-53`] |
| Trace honesty: reactive-only, NaN fail-closed, canonical ActionStatus, Validate rejects malformed | [CODE-CITED `phorvex/internal/decision/decision_trace_v3_test.go:32-71,149-189,204-263,388-416`] |
| Honest refusal logging; empty-tick ≠ refusal | [CODE-CITED `phorvex/internal/audit/log.go:924-927,935-940`] |
| CANNOT-HELP is an accepted audit-only terminal state | [DOC-CITED `PX_Reports_V1/coversets/COVERSETS-DECISION.md:41-45`] |
| Deliberation protocol, diversity, convergence, invariant | [DOC-CITED docx §9.1–§9.4] |
| Voting needs independent errors; minority-truth ~1 in 4; MAST verification as first-class | [DOC-CITED WS-7 §1–§2] |

**Zero open questions for the implementer.** The deliberation protocol, stop rules, decline-memo
learning, the promotion-source law, the ground-truth conditions, the transport discipline, the
early-stop rule, and the CANNOT-HELP contract are specified above; every undetermined quantity is a
configurable parameter (docx §14).
