# Phorvex — Live-Fire Defense of a NATS JetStream Broker

**Adaptive Moving Target Defense · live-fire report · with attacker dwell time**

A real attack was fired at a running NATS JetStream cluster on Amazon EKS, and Phorvex was left to
respond on its own. This covers the workload and how NATS is used, the threats that could overshadow
JetStream, the action Phorvex took, the MTD parameters that governed it — and the **attacker dwell time**,
honestly scoped to when the foothold was actually neutralized. **Every figure is captured live from the
cluster and the console's `/api/attack-results`; nothing is synthetic.**

| | |
|---|---|
| **Target** | `nats/` · cluster `phorvex-dev-eks` · operator `phorvex:0.2.3-containment` |
| **Verdict** | **DEFENDED** · containment = **contained** (the compromised node itself was isolated) |
| **Attacker dwell** | **19.06 s** — foothold on `nats-0` contained (bounded) · vs **unbounded** without a targeted defense |

## Verdict at a glance

| Metric | Value | Note |
|---|---|---|
| Verdict | **DEFENDED** | action: quarantine (not rotate — the broker is stateful) |
| Containment | **contained** | the attacked node `nats-0` itself was quarantined (network-isolated on its own node) |
| **Attacker dwell** | **19.06 s** | foothold landing → containment · **bounded** (the intruder's node is isolated) |
| Data preserved | **9 / 9** | ORDERS messages intact |
| Quorum held | **2 / 3** | RAFT — stream kept serving; a new leader was elected |
| Annual saving | **$358.34** | vs. no defense |

---

## Section 01 — The workload, how NATS is used, and the JetStream threat surface

The workload under defense is a **NATS JetStream cluster** — a three-node, RAFT-replicated message broker
(`nats-0`, `nats-1`, `nats-2`) running as a Kubernetes StatefulSet on Amazon EKS. NATS is used as the
**durable messaging backbone** an event-driven application relies on; its business payload here is the
**ORDERS stream** — replicated across all three nodes (R=3), holding 9 persisted messages. Each broker
keeps its slice of that state on its own EBS volume, so the **state, not the pod, is the asset**.

### Workload facts (live)

| Item | Value |
|---|---|
| Broker | NATS JetStream 2.10 · cluster `nats-js` · RAFT R=3 |
| Topology | StatefulSet · 3 replicas · podManagementPolicy Parallel |
| Storage | EBS gp2-csi · 1Gi/node · PVC retain (data survives pod loss) |
| Business stream | ORDERS · R=3 · **9 messages** · store `/data/jetstream` |
| Classification | `workload-class=message-broker` · `data-class=restricted` · `r6th.io/rotation-target=true` |
| Availability contract | 2 of 3 nodes = RAFT quorum → the stream keeps serving |

### Vulnerabilities & attacks that could overshadow JetStream

The attack was a **container-escape foothold** — MITRE ATT&CK **T1611** — landing on the broker node
`nats-0`, delivered as a `SecurityEvent` at threat level *critical*. On a message broker, one foothold is
disproportionately dangerous, because that node is three things at once:

- **Data — restricted stream data on disk.** `nats-0`'s volume holds ORDERS messages classed
  `restricted` (asset value 1.0) — one hop from exfiltration.
- **Lateral — a pivot into the cluster.** From `nats-0` the attacker recons and pivots to the other two
  brokers.
- **Quorum — a consensus member.** `nats-0` votes in RAFT; a compromised member can attempt to stall or
  corrupt the replicated log.

> **The stateful trap — and why containment must hit the right node.** Classic MTD answers a compromise
> by *rotating the pod away*. On a stateful broker that is destructive — rotating discards the persisted
> stream, and dropping a node can break the 2-of-3 quorum. So the containment must **isolate the
> compromised node itself** — not rotate it (data loss) and not isolate a clean neighbor (which cuts a
> path but leaves the attacker sitting on its node). Bounding the intruder's dwell without destroying
> data is the whole problem.

---

## Section 02 — What Phorvex did

Phorvex sat **calm** before the attack (`reactiveOnly` — no proactive churn of a stateful broker). When
the foothold signal arrived, the deterministic brain (`p1-coverage`) evaluated the response under its
integrity laws and **contained the compromised node in 19.06 seconds**.

### Incident timeline (dwell clock)

1. **Baseline — calm.** `reactiveOnly`: the broker is untouched; the operator is idle.
2. **00:00 — Foothold detected · dwell clock starts.** A `SecurityEvent` (T1611, critical) lands on
   `nats-0`. The attacker now holds effective access to the compromised node.
3. **+~1 s — Decision under integrity laws.** `statefulIntegrity` **vetoes rotate** (it would destroy
   stream data); the optimizer selects **quarantine of `nats-0` itself**, bounded by the 2-of-3 quorum
   floor. (Only the node carrying the *direct* foothold is actionable — a clean neighbor is not
   quarantined.)
4. **Actuation — contain, don't destroy.** A deny `NetworkPolicy` cuts `nats-0`'s network, the pod is
   held out of the StatefulSet, and a `phorvex.quarantine` audit event is recorded. RAFT elects a new
   leader among `nats-1`/`nats-2`.
5. **+19.06 s — Contained · dwell clock stops.** The intruder's node is network-isolated — its lateral
   reach and egress are cut *at the foothold*. Cluster serves on the 2-of-3 quorum; ORDERS **9 / 9**
   messages intact — zero data loss; `nats-0`'s data preserved on its PVC for forensics.

### The decision, verbatim from the operator

```
quarantine: cuts lateral recon (cov=30.78/$0.28=108.63 per-$); stage=exploit→persist lateralUrg=0.00 pHold=0.54
```

| Field | Value |
|---|---|
| action | quarantine |
| target | **`nats/nats-0`** (the compromised node — same pod the attack landed on) |
| coverage | 30.78 recon-facts |
| efficiency | 108.63 per-$ |
| stage | exploit→persist |
| pHold | 0.54 (probability the attacker still holds `nats-0`) |
| **attacker dwell** | **19.06 s (bounded — foothold contained)** |

> **A deliberate correction.** Earlier, the coverage-maximizing optimizer would isolate the highest
> lateral-coverage *neighbor* (`nats-2`, `cov=119.42/$0.28=421.49 per-$`) while the attacker still sat on
> `nats-0` — high coverage-per-$, but the real foothold was never contained. The node selection now
> requires a **direct foothold** (the attacker actually on the node) before it acts, so it quarantines
> `nats-0` itself. That trades raw coverage-per-$ (30.78 vs 119.42) for **operationally correct
> containment** — the metric that matters is the intruder's dwell on its own node, and that is what is
> now bounded.

---

## Section 03 — The MTD parameters, and the measured result

Every behaviour above is governed by one declarative policy — the live `PhorvexPolicy nats-defense`.

### PhorvexPolicy `nats-defense` (live)

| Parameter | Value | Role for the broker |
|---|---|---|
| `triggers.reactiveOnly` | `true` | Calm baseline — act only on a real signal; and act only on the node carrying the *direct* foothold. |
| `triggers.eventDriven` | `true` | React on signal arrival (~1s) — **the reason dwell is ~19s, not minutes**. |
| `slo.minAvailableReplicas` | `2` | The RAFT quorum floor — the stream stays available while `nats-0` is contained. |
| `actions.enabled` | `quarantine, rotate` | Quarantine for stateful containment; rotate present but integrity-vetoed here. |
| `objective.lambda` | `0.4` | Cost weight in `gain = marginal·prov − λ·ECost`. |
| `objective.costWeights` | `flowDisruption 0.6 / normSparsity 0.4` | A broker's connections are costly to disturb → flow weighted higher. |
| `budget.maxMovesPerTick` | `1` | At most one containment per tick. |
| `budget.tickInterval` | `10s` | Evaluation cadence. |
| `budget.antiOverRotationWindow` | `60s` | No re-actuating the same target inside 60s. |
| `assetValue.fromLabels.data-class` | `restricted 1.0 / internal 0.4 / public 0.1` | ORDERS is restricted → top protection priority. |
| `assetValue.weightSecrets` | `0.8` | Secrets on a node raise its value. |
| `assetValue.blastRadiusFromGraph` | `true` | Value includes lateral blast radius. |
| `mode` | `active` | Real actuation on the live cluster — not dry-run. |

### Actuation strategy (operator CR `phorvex-nats`)

- `rule phorvex.rotate` → `delete`  *(vetoed here by statefulIntegrity)*
- `rule phorvex.quarantine` → `quarantine`
- `matcherMode` → `Exact`

### Result — attacker dwell time (the headline security metric)

Dwell is the duration the intruder held effective access — from the foothold landing to when the foothold
was **actually neutralized** (the compromised node isolated). It is reported as *bounded* only when the
action reached the foothold pod itself.

| Approach | Attacker dwell | Basis |
|---|---|---|
| **With Phorvex** | **19.06 s** (bounded) | **Measured** — `nats-0` quarantined (isolated on its own node) |
| No defense | **unbounded** | Attacker persists until objective — the LANDED runs confirm ≥95 s and still counting |
| R6 blind timer | **unbounded in the common case** | A fixed timer rarely rotates the *exact* compromised node; even a "catch" destroys the stream |

**Phorvex bounds intruder dwell to ~19 seconds by isolating the compromised node itself — where every
alternative leaves it open-ended.**

### Result — cost (annual, real AWS on-demand pricing)

| Scenario | Annual cost | Note |
|---|---:|---|
| No defense | **$364.42** | attack lands — full value-at-risk of the compromised node |
| R6 blind timer | **$382.66** | churns constantly, catches ~20% by luck, and DELETES the stateful stream |
| **With Phorvex** | **$6.08** | operator footprint only; contained, no residual |
| **Net saving** | **$358.34 / yr** | vs. no defense |

### Result — availability

Replica availability 100% → **66.67%** (`nats-0` held in isolation, exactly on the 2-of-3 quorum floor).
The ORDERS stream kept serving on the remaining quorum and **all 9/9 messages survived** — zero data loss.
Service availability was maintained; what dropped was replica count, by design of the containment.

---

## Section 04 — Attacker dwell time · how it is measured (and why it's reliable)

- **Definition.** Dwell = seconds the attacker held effective access, from the attack landing until the
  foothold was neutralized. It is reported **bounded** only when the action reached the foothold pod
  itself — *evicted* (the pod rotated away) or *contained* (the pod network-isolated). If only a neighbor
  was isolated, or no action reached the foothold, dwell is **open-ended** (the console marks it
  `foothold-active` / `landed`, `ongoing=true`).
- **How it's measured.** The console stamps the fire time; a ground-truth watcher (real `kubectl`) marks
  the dwell the instant the compromised node is isolated (the fresh `phorvex.quarantine` event /
  NetworkPolicy on the attacked pod). Wall-clock, not an estimate.
- **This run.** Attack on `nats-0` → quarantine of `nats-0` → **containment = contained**, dwell
  **19.06 s** (`dwellOngoing = false`). Consistent with the ~19–20 s band set by the ~10 s tick + ~1 s
  event-driven reaction.
- **The honest contrast.** Before the node-selection fix, the same attack isolated a clean neighbor
  (`nats-2`) — the console correctly recorded that as `foothold-active` with an **open-ended** dwell,
  because the attacker on `nats-0` was never contained. Only isolating the compromised node yields a
  bounded dwell.
- Dwell + containment are surfaced live in the dashboard **Report tab** (per-attack + a mean
  *containment* dwell rollup) and in the CSV export (`containment`, `dwell_s`, `dwell_ongoing`).

---

## Scope & method — what is real, and what is modeled

- **The attack is a red-team detector signal** — a `SecurityEvent` representing a container-escape
  foothold — not an exploited NATS CVE. What is real and measured is Phorvex's **reaction**: the decision,
  the quarantine of the compromised node, the preserved data and quorum, the dwell, and the cost, all
  captured live on EKS.
- **Dwell for Phorvex is measured and bounded only when the foothold is neutralized.** For "no defense" it
  is unbounded (bounded below by the ≥95 s LANDED observations). The R6 dwell is a labeled qualitative
  counterfactual, not a fabricated number.
- **Quarantine is a hold, not a blip.** The contained node is isolated and kept out of the StatefulSet for
  forensics until lifted — why replica availability stays at 2/3 afterward and its data is preserved.
- **The node selection targets the compromised node** (the pod carrying the direct foothold), not the
  highest-coverage neighbor — a fix shipped as operator `phorvex:0.2.3-containment` and covered by a
  regression test.
- **Figures are live** — from the cluster and `/api/attack-results`; the cost model applies real AWS
  on-demand pricing to the measured outcome.

---

*Phorvex — Adaptive Moving Target Defense · engine p1-coverage · operator phorvex:0.2.3-containment · generated 2026-07-12*
