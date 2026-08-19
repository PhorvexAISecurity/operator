# PHORVEXSEC-115 (PHVX-24) — items 1, 4 and 5 — report

Date: 2026-08-19 · Branches `docs/phvx-24-constants-registry` (PR #57, commit `05a5a8e`) and
`feat/phvx-24-rarity-population` (PR #56)

Items 2 and 6 belong to the ticket's math owner. Item 3 is PHORVEXSEC-104 and is reported in
`reports/phvx-14b-20260819/`. A measurement brief for item 2 is attached to the ticket itself.

## Headline

Items 1, 4 and 5 are complete. **Item 5 was already done before this work started** — λ,
`MaxMovesPerTick`, `TickInterval` and `ProactiveFloor` are all `PhorvexPolicy` fields — so the
registry records them as defaults rather than constants.

The registry turned up **two things the ticket's own table does not have**, and checking item 4
against the cluster turned up **two stale premises**.

## 1. Item 1 — the constants registry

`phorvex/CONSTANTS-REGISTRY.md`. One row per shipped constant: value, `file:line`, meaning, whether
it is a tuning dial, and **whether it has ever been validated against anything**.

The last column is the point. The answer is stark: **only two rows are backed by a recorded
measurement** — `MeasuredT4GPUEnvelopeMax` (worst observed T4 replacement) and `rarity()` (verified
formula, now pinned by test). Every row in the *Scales* table — the ones the ticket's own
portability rule says are dangerous — is unvalidated. Constants are grouped by that rule (portable
iff dimensionless) rather than by package, so the rows that break on another cluster sit together.

### The cost ceiling is ten constants, not one

The ticket records it as *"the `0.2` has no name, no comment, no derivation"*. The flow-disruption
path (`internal/cost/switching.go:71-99`) holds **ten** unnamed, underived numbers — five phase
priors, two GPU tax terms, a load coefficient and two blend weights. They set the entire rotate-cost
prior, so they decide *which* pod gets rotated as much as any weight in the objective does.

One of them is a **scale**: the `200.0` request-rate normalizer at `:97` carries units, which is
exactly what the ticket's portability rule flags. A service normally serving 2000 req/s saturates
that term permanently; a 5 req/s service never moves it. It is not listed in the ticket and not
covered by PHVX-74.

### That block saturates too

It reads as a convex combination and is not one. `sat()` bounds the GPU term at 0.9, so the
pre-clamp total peaks at `0.55·1.0 + 0.35·0.9 + 0.2 = 1.065` and `clamp01c` absorbs the overflow.
**Worst-case rotate cost is flat at 1.0 across a band of genuinely different situations** — the same
saturation complaint PHVX-24 makes about the UCW clamp, in a second place nobody has measured.

**Open question for the math owner:** does this belong inside item 2's re-fit, or should it be filed
as separate measured work? It is a clamp discarding spread, so the same class of problem; but it is
on the cost side, not the physics side, and item 2 was scoped to the UCW clamp.

### Line numbers were re-verified, not copied

| ticket says | actual |
|---|---|
| `CoResidencyCap` at `ucw.go:35` | `platform.go:46` — different **file** |
| `MaxDispersionMult` at `ucw.go:35` | `ucw.go:53` |
| `provFloor` at `coverage.go:179` | `coverage.go:160` |
| `rarity()` at `platform.go:169-176` | `platform.go:170-176` |
| `exactBruteForceAssetCap = 18` at `optimality.go:30` | **does not exist** — removed by PHVX-23 |

Worth noting alongside item 5: the default `MaxMovesPerTick = 3` against the live `1` on every
tenant policy. A policy that omits the field lands in a materially more expensive regime for the
exact-optimality arm.

## 2. Item 4 — rarity is population-relative

Settled as *keep the formula, it is correct*. The risk that leaves behind is that **the correct
answer looks like a bug**: a fleet's sole model scores 1.0, and the obvious "fix" is 2.0. That would
assert scarcity at frequency 1.0 and inflate every GPU pod on single-model fleets — the most common
deployment shape.

`TestRarityIsPopulationRelative` pins the five cases from the ticket, each with its reasoning in the
failure message. Two further tests carry the argument the settlement rests on: that ImageRarity and
ModelRarity are the *same function* differing only in population (so a model does score 2.0 when its
population makes it rare, and a live 1.0 is a statement about the fleet, not the formula), and that
occupancy and rarity move in opposite directions — an inverted sign would reverse every dispersion
ranking while still returning plausible values inside [1,2].

The comment at `platform.go:138` claimed ModelRarity is 1.0 "when no model servers in the fleet". It
is also 1.0 when every model-serving pod runs the same model — both the more common case and the one
mistaken for a bug. Corrected.

### Two stale premises found against the cluster

**`ModelRarity` is no longer ≡ 1.0.** The ticket records it as 1.0 everywhere because both
model-serving pods ran the same model. Measured 2026-08-19 they run **two distinct models**
(`Qwen2.5-7B-Instruct-AWQ`, `qwen2.5:0.5b`), so each is 1-of-2 and scores **2.0**. The term lifted on
its own once the population diversified, which is item 4's claim behaving exactly as stated. No code
consequence; the ticket's explanatory text is what is stale.

This does change item 2's inputs. The ticket warns that *"at `MaxDispersionMult = 8`, vllm sits at
5.07 unclamped"*. With ModelRarity at 2.0 the figures are:

| pod | ImageRarity | CoResidency | ModelRarity | uncapped |
|---|---|---|---|---|
| `vllm/vllm` | 1.7423 | 2.00 | 2.00 | **6.97** |
| `vllm/vllm-standin` | 2.0000 | 2.00 | 2.00 | **8.00** |

`vllm-standin` sits at **exactly 8.00**, not 5.07 — the un-clamping trap is closer than written.

**Item 4's third sub-task is not actionable as written.** It asks for
`phorvex.ai/model-id: sentence-transformers/all-MiniLM-L6-v2` on the `mock-rag-chatbot` Deployment.
That workload **no longer exists** — retired with `litellm` and `phorvex-live-demo` when ArgoCD took
that capacity (`deploy/argocd/README.md`), with `voice-bot` replacing it as the rotate target.

The annotation was **not** retargeted. The nearest candidates are `document-store/chroma` (no
`device: cuda`; embeds via ONNX) and `voice/voice-bot`, which *calls* `gpt-4o-mini` remotely through
LiteLLM rather than serving it. Annotating either would inject a model identity the pod does not
have and corrupt the very population `rarity()` measures — the opposite of the sub-task's stated
purpose ("an honest input"). Flagged for a decision rather than invented.

## 3. Item 5 — already complete

| dial | default | declared at | policy field |
|---|---|---|---|
| λ | 0.6 | `api/v1alpha1/defaults.go:16` | `spec.objective.lambda` |
| `MaxMovesPerTick` | 3 | `:20` | `spec.budget.maxMovesPerTick` |
| `TickInterval` | 20s | `:22` | `spec.budget.tickInterval` |
| `ProactiveFloor` | 1h | `:24` | `spec.budget.proactiveFloor` |
| `FlowDisruption` | 0.6 | `:18` | `spec.objective.flowDisruption` |

The λ **seed** is not a tuning target: `NewDualSolver` starts at 0.6 with step 0.05
(`internal/cost/dual.go:26`) and then self-calibrates against realized spend — the recorded trace
drives λ from 0.6 to 3.6 in 12 ticks. The seed sets where the search starts, not where it lands.

## 4. Also corrected here

**The investor demo script was false.** `overlay.tsx:18` claimed the scan derives EPSS with *"no
hardcoded inputs; it's all discovered"*. EPSS is loaded from a hand-maintained 4-entry cache
covering 2 of 71 live pods, one entry of which points at a retired workload. PHVX-14b explicitly
asked for this fix and it had not been made.

**`localsearch.go:216` still named `exactBruteForceAssetCap`**, which PHVX-23 removed.

## 5. Note on the repository

`internal/decision/scenarios_export_test.go` fails on a clean checkout because it writes to an
untracked `internal/decision/bin/` directory that git does not carry. Reproduced on pristine `main`,
so it is pre-existing — but it means `go test ./...` is red out of the box. Worth a separate fix
(`os.MkdirAll`); not touched here.

## Verification

`go build ./...`, `go vet`, full `go test ./...` green (with the `bin/` directory present).
