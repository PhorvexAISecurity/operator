# Anatomy v2 — derivation log

**Status:** derivation only. No node set proposed yet; method not yet agreed with K3.
**Rule:** every fact here comes from the code. The issue register was not opened during this pass.
**v1 (`PHORVEX_ANATOMY.md`) is untouched and stays untouched.**

Reproduce: `python3 derive.py` → `packages.json`.

---

## The two objective axes

**Static:** 28 packages under `phorvex/internal`, 28,979 non-test LOC, and the import edges between
them. Mechanically extracted, no judgement.

**Dynamic:** what `runner.Manager.tick` (`manager.go:255`) actually calls per cycle. Partially traced.

An edge in both is structural. An import with no tick call is a latent coupling and should not be
drawn the same way.

---

## Four findings that contradict v1

### 1. `internal/applier` is imported by zero Go files

```
grep -rn 'internal/applier"' --include=*.go .   →   0
```

Its own header reads *"the REAL cluster-write behind the console apply-fix."* Nothing imports it.
The console's `applierMode` is a response string and `s.applyfix.ApplierMode` is a console-local
field; neither reaches this package.

v1 places `applier` inside `ACTUATION` and counts its 126 LOC toward that node's 2,836. **126 of
those lines are unreachable.**

### 2. `belief` and `physics` are legacy-only

Both are imported by exactly one file: `internal/decision/engine.go` — which is `p0-greedy`
(`engine.go:197`, `optimizer.go:43`). The production engine is `coverage.go` / `p1-coverage`
(`coverage.go:133`).

What `coverage.go` actually references:

```
cost 17 · recon 9 · killchain 5 · actionset 5 · ctxprov 2 · feasibility 1 · metrics 1
belief 0 · physics 0
```

v1 draws `BELIEF` as a live node and `SENSING → KNOWLEDGE "physics scales facts"` as a live edge.
**Both are legacy paths.** v1's `BELIEF` node is two-thirds live (`killchain`, `ctxprov`) and
one-third dead.

This is the engine-separation rule from `brain-signal-lineage/00-scope-and-method.md` — *"engines
that must not be conflated"* — applied to package structure. It would have caught this; we did not
have it when v1 was drawn.

### 3. `model` and `registry` are infrastructure, not parts

Fan-in: **`model` 19 of 28 packages, `registry` 9.** Neither imports anything internal. They are
shared vocabulary and a lookup, present everywhere by construction.

v1 bundles `model` into a `CONTRACT` node together with the CRD, RBAC and Helm charts. Those are an
external API surface; `model` is an internal type package. Different kinds of thing, one box.

### 4. `console` is 35% of the codebase and a pure leaf

```
console   10,025 LOC   42 files   imports 5   imported by 0
```

Larger than the entire decision path. It imports `decision`, `actuator`, `actionset`, `audit`,
`model` and nothing imports it back. In v1 it shares the `SURFACE` node with `redteam` (1,065 LOC,
imports `cost` only) — two packages with nothing in common but being at the edge.

---

## Structural facts recorded, not yet interpreted

| fact | figure |
|---|---|
| `runner` fan-out | 14 internal imports — the orchestrator |
| `decision` fan-out | 10 — the hub |
| packages with **zero** test LOC | `model`, `registry`, `physics`, `belief` (`graph` has 100 and does not belong in this list) |
| `cmd/`-only packages | `pendinggate` (227 LOC, `cmd/pendingcheck`), `soak` (111 LOC, `cmd/p4b-soak`) — standalone tools, not operator path |
| largest non-console | `actuator` 2,817 · `calib` 2,178 · `runner` 1,870 · `decision` 1,755 |
| `actuator` internal branching | 3 actuators (`phoenix`, `native`, `hybrid`) → `HybridActuator.Actuate` routes on `RuleTypeFor(action) != ""` → 16 `HandlerRegistry` registrations, native only |

---

## Correction: post-action observation is implemented, and this log got it wrong

The first draft of this log said `EFFECT` "has zero LOC" and asked how a code-derived map could keep
it. **That framing was wrong, and it was my restatement that introduced the error, not v1.** v1 says
`EFFECT` "owns no packages" and names `observeReadyRotations` and `ObserveRotation` explicitly. I
dropped the qualifier and turned "owns no package" into "has no code."

The subsystem is also larger than v1's "two fragments":

| element | anchor |
|---|---|
| runs before each tick's decisions | `runner/manager.go:320` — `m.observeReadyRotations(snap)` |
| creates a controller/UID-bound pending observation | `runner/manager.go:381` `trackRotationWithFloor` |
| classifies the outcome | `runner/manager.go:449` `recordActionOutcome` |
| the observer itself | `runner/manager.go:483` `observeReadyRotations` |
| outcome taxonomy | `slo/ledger.go:40-45` — `OutcomeCompleted`, `OutcomeFailed`, `OutcomeEmitted` (`"emitted_outcome_unobserved"`) |

So the code-derived node is **post-action outcome and disruption observation** (`runner` feedback
state + the `slo` ledger), and the negative space is narrower and more precise than "no one confirms
effects":

1. Phoenix `Emitted` does not by itself prove execution.
2. `rotate` *does* have partial execution/recovery observation, via old/new controller-owned UIDs.
3. Most non-`rotate` actions have no asynchronous functional-effect confirmation.
4. A structural zero-replica-impact result is not security-goal confirmation.
5. No generic "desired security effect achieved" contract spans all actions.

The implemented observer is drawn as a code node. The absent confirmations attach to it as
action-specific negative-space annotations — never as a peer box.

## Still open

Gap nodes are admissible only in a distinct negative-space class, never as code peers, and each must
attach to an implemented boundary and carry both an evidenced intended contract and exhaustive
negative source evidence at a pinned commit. Without an evidenced intended contract it is an issue
note, not an anatomy node.
