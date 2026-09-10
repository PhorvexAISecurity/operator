# Phoenix / Phorvex Kubernetes Attack & Benchmark Harness

A **durable, plugin-based** Kubernetes attack/benchmark harness that measures how
well Moving-Target-Defense (MTD) arms — including the **genuine extended Phoenix
operator** — disrupt concrete container attack kill-chains, each scored against a
**concrete observable oracle** with positive and negative controls.

- **Module:** `github.com/r6security/phoenix-test-harness` (own Go module, rooted
  at `build/test-harness`).
- **Reuse:** `client-go v0.34.0` + `controller-runtime v0.21.0` (matching
  phoenix-extended), importing the Phoenix CRD `api/v1beta1`
  (group `amtd.r6security.com/v1beta1`) via
  `replace github.com/r6security/phoenix => ../phoenix-extended`.
- **Build status (verified):** `go build ./...`, `go vet ./...`,
  `go test -count=1 ./...` all exit 0 (106 tests pass, Go 1.26.3 windows/amd64).
  phoenix-extended `go build ./...` exits 0, so the FullPhoenix arm builds a real
  `bin/manager.exe` and installs CRDs from `config/crd`.

---

## 1. Architecture overview

### Two interfaces, zero central switch

The entire system composes from exactly **two** interfaces, defined in
`internal/core/interfaces.go`:

```go
type Scenario interface {
    Metadata() ScenarioMeta
    Setup(ctx context.Context, env *Env) error
    Execute(ctx context.Context, env *Env) (AttackResult, error)
    SuccessOracle(ctx context.Context, env *Env) (OracleResult, error)
    Teardown(ctx context.Context, env *Env) error
}

type Defender interface {
    Metadata() DefenderMeta
    Setup(ctx context.Context, env *Env) error
    Start(ctx context.Context, env *Env) error
    Stop(ctx context.Context, env *Env) error
    Teardown(ctx context.Context, env *Env) error
}
```

Each plugin is **ONE file** containing a `func init()` that calls
`core.RegisterScenario(...)` / `core.RegisterDefender(...)`, writing into the
package-level `scenarioRegistry` / `defenderRegistry` maps
(`internal/core/registry.go`). The runner **enumerates the registries** — there is
**NO central switch, list, or dispatch table** to edit. Adding an attack or a
defender is *one new file + one register call, zero core changes*. (Independently
verified in review: a new scenario added as one file self-registered and ran with
zero core edits.)

Everything else — the runner, the metric schema, the statistics, and report
generation — is **fully generic and agnostic** to which plugin produced the data.

### Package layout

```
build/test-harness/
  go.mod / go.sum            module + replace => ../phoenix-extended
  cmd/harness/main.go        CLI: load config, safety-guard, capability-detect, run loop, emit metrics+report
  internal/core/
    interfaces.go            Scenario, Defender, ScenarioMeta, DefenderMeta, AttackResult, OracleResult; Category/R6Tag/Capability enums
    registry.go              scenarioRegistry / defenderRegistry maps; Register*/enumerators
    runner.go                scenario x defender x trial loop; seeds; positive+negative controls; adaptive-attacker hook
    metric.go                Metric struct; JSONL writer
    stats.go                 mean + t-interval confidence interval (works at n=2 and n>=20); deterministic TrialSeed
    env.go / logger.go       Env (client + kube + caps + *rand.Rand + logger); per-trial raw logger
  internal/config/           TargetConfig loader+validation; config.example.yaml
  internal/capability/       GPU/MIG/MultiNode/NodeCount probe via live cluster
  internal/safety/           guard.go (context+host+ack+namespace assertion); sandbox.go (label r6th.io/owned lifecycle, idempotent teardown)
  internal/mocks/            in-ns mock IMDS / C2-exfil sink / OCI registry / CI-CD pipeline / CPU-bounded miner / manifest builders
  internal/adaptive/         learner.go (observes inter-rotation gaps; predicts rhythm; times kill-chain into the lull)
  internal/report/           report.go (generic tables) + provenance.go (cell -> command+rawlog+seed) + mitre.go (ATT&CK matrix)
  scenarios/                 ONE self-registering file per scenario (5x c1, 6x c2, 7x c3)
  defenders/                 ONE self-registering file per defender (d-nomtd, d-r6blindtimer, d-randomequal, d-fullphoenix, d-phorvex-slot)
  config.kind.yaml           live kind smoke config (context kind-amtd-test, ns amtd-attack-test)
  out/                       (gitignored) metrics.jsonl, raw/<scenario>_<defender>_<trial>.log, provenance.json, report.md, mitre_matrix.md
```

### Run loop and metric schema

For each **scenario x defender** the runner executes `TrialsPerArm` fixed-seed
trials, plus an extra **no-attack negative-control** trial and an extra
**adaptive-attacker** trial (`internal/core/runner.go`). Every per-trial RNG is a
`math/rand.Rand` seeded deterministically as
`TrialSeed(masterSeed, scenario, defender, trial)` (FNV-1a hash), so the whole run
reproduces from the master seed alone.

Each trial emits one `Metric` JSON line (`internal/core/metric.go`) with the same
schema everywhere:

| Field | Meaning |
|---|---|
| `validity` | the **versioned measurement-validity contract** (see below). READ THIS FIRST — every field below is a measurement only when `validity` says so |
| `oracleAchieved` | the concrete observable verdict (did the attack reach its oracle?); an observation only when `validity.oracleObserved` |
| `disruptionVsOracle` | 1.0 if the undefended control OBSERVED AT THE SAME TRIAL INDEX AND KIND achieved the oracle but this arm did not, else 0.0. A measurement only when `validity.scored`; otherwise 0 means *not measured* |
| `attackerDwellSeconds` | wall-clock seconds the planted foothold survived |
| `timeToActionSeconds` | seconds from attack start to the defender's first concrete action (0 = none) |
| `securityPerCost` | disruption per unit defensive cost (rotations/actions); derived only for a scored, cost-observed trial |
| `evidenceRetention` | fraction of attack evidence still observable after the trial (rotation that destroys a pod also destroys forensic evidence) |
| `defensiveActions` / `falseDefensiveActions` | cost; false moves fired during the no-attack negative control (should be 0). **`-1` means UNOBSERVED, never zero** |
| `skipped` / `skipReason` | compatibility flag: "this row was NOT scored" (a capability skip, a stub arm, an invalid measurement, or a missing control). The precise state is `validity.status` |
| `rawLogPath` / `commands` / `seed` | provenance: exact raw log, command list, and seed for every cell |

Per arm, `internal/core/stats.go` aggregates **mean + a two-sided t-interval**
(kept even at smoke `n=2`, where the 95% t critical value is 12.706 — so the
interval is *honestly wide*; the SAME function serves the full `n>=20` benchmark).

### Measurement validity (`internal/core/validity.go`)

A value alone never implies a measurement. Every trial stamps a versioned
`validity` block so a failed operation, a missing observation or a missing
positive control can never be read as successful defense or as measured zero
cost:

| Field | Meaning |
|---|---|
| `version` / `kind` | contract version; `ordinary` \| `negative-control` \| `adaptive` |
| `status` | `valid` (lifecycle completed, outcome observed, cleanup verified) \| `invalid` (infrastructure/harness failure) \| `skipped` (REPORTED capability/stub abstention) \| `legacy-unverified` (row written before this contract) |
| `phase` | the lifecycle phase that DECIDED the outcome |
| `reasons` | every propagated phase error/abstention, in order |
| `attackExecuted` / `oracleObserved` | whether the stimulus ran and whether a verdict was actually observed |
| `observerPresent` / `costObserved` | whether the arm exposes `DefenseObserver` and whether the cost/timing were read |
| `scored` / `unscoredReason` | whether `disruptionVsOracle` is a real comparison, and why not |
| `baseline` | the positive control's **identity, observed result and usability** — or why none existed |
| `cleanup` | every owed teardown attempted and every failure retained; `complete` gates the next trial |

Rules the runner and every report enforce:

- **A failed attack stimulus never runs an oracle**, so the absence of a result
  is never scored as defense.
- **A comparison is scored only against a control that was observed, valid and
  successful** at the same trial index *and kind*. A control that errored,
  abstained or failed its own attack invalidates the comparison; it never becomes
  `baseHit=true` or a measured zero.
- **The adaptive pass (index `TrialsPerArm+1`) anchors only to the baseline arm's
  own adaptive pass.** When that control was not run (e.g. a force-included
  anchor-only baseline) the row is UNSCORED with an explicit missing-control
  reason and never borrows an ordinary baseline.
- **Unobserved cost is not zero cost.** No `securityPerCost`, `roi` or
  `schwartau` is derived when `costObserved` is false. An observer result is only
  accepted as an observation once it is self-consistent: a negative count, a
  non-finite or non-positive timestamp, or a timestamp list that disagrees with
  its own count leaves the cost UNOBSERVED with the contradiction recorded.
- **Cleanup owed by every entered phase is always attempted** — on a detached
  context, so it still runs after cancellation, and under a per-step WALL-CLOCK
  bound, because a plugin may ignore its deadline and `env.Close` never receives
  one. A cleanup that does not verify invalidates the trial, clears its derived
  values, and stops the run before another trial can reuse unverified state.
- **An unresolved cleanup is not a failed one and not a clean one.** A step that
  outlives its bound is recorded `unresolved`: it may still be running, so the
  runner keeps ownership of it (`Runner.WaitForPendingCleanup`,
  `RunOutcome.LateCleanups`) instead of abandoning it, and a late success never
  retroactively marks the already-reported trial clean. The CLI reports whether
  such a call has actually `Returned`; a call still running is never printed as
  returned.
- **Unsafe cleanup phases never overlap.** Every owed step touches the same Env —
  its logger, its client, its namespace — and `env.Close` frees the logger the
  earlier steps write through. So once a step is unresolved, the remaining steps
  are NOT started: they are recorded `blocked` with the step that blocked them.
  That is honest and just as disqualifying for reuse, whereas starting them would
  race a live callback and then claim each phase "ran".
- **Deletion accepted is not absence observed — and asynchronous deletion is not
  residue.** `Env.CleanupOwned` aggregates every API failure across every kind,
  then POLLS within its budget until the owned objects are actually gone. Ordinary
  background deletion completes and verifies; only what is still there when the
  budget expires is a problem, reported with its terminating/finalizer state. With
  `deleteNamespace=true` the namespace's own disappearance is verified the same
  way.
- **The final teardown is part of the run result.** A run whose matrix passed but
  whose final teardown did not verify is INCOMPLETE: it raises a barrier, lands in
  `provenance.json` and exits non-zero, because it leaves the cluster dirty for
  the next run.
- **Legacy rows stay legacy.** A metrics file written before this contract still
  decodes; those rows are counted and displayed as `legacy-unverified` and
  excluded from certified scores. Nothing is inferred from their zero fields and
  no historical file is rewritten.

### One contract, one implementation

The rules live in `build/metricvalidity`, a dependency-free module that the
harness and the Phorvex reporters/console both import. It is deliberately not
owned by either side: the shipped product must not depend on the test harness,
and a one-file contract should not drag a module graph behind it.

That structure exists because the alternative was tried and failed. When each
reader mirrored the wire format by hand, the mirrors quietly omitted the fields
the producer had begun checking — the baseline evidence, the retained cleanup
steps — and certified rows the harness itself refuses. There is now nothing to
keep in sync.

A shared implementation still leaves one gap: a reader can route through the
right rules and yet reach the wrong answer by failing to DECODE a field those
rules depend on. So `metricvalidity` also embeds a PARITY CORPUS — real rows
produced by `Runner.Run`, plus single-field counterexamples derived from one of
them — and every reader has a test that runs the corpus through its own struct
and its own predicates and compares against the contract's verdict. Regenerate it
with `M161_REGEN_CORPUS=1 go test ./internal/report -run TestSharedParityCorpus`.

### A decoded validity block is a CLAIM, not a verdict

A metrics file is an untrusted input: it may come from a newer or older harness,
or have been edited or truncated. `metricvalidity.Evaluate` (reached as
`Metric.Validated()` inside the harness) is the ONE place those claims are
checked — against this build's supported contract and against each other — and it
is what `IsScored`, `CostObserved`, `Kind`, every aggregator, every reader and the
provenance map use. Nothing consults `scored` directly.

A row is refused, and reported as `unverified`, when its `version`, `kind` or
`status` is not one this build understands, or when it claims `scored` while its
own fields say the status is not valid, the oracle was never observed, cleanup
did not verify or is unresolved, the positive control is unusable or unnamed, the
trial is a negative control, or `disruptionVsOracle` is outside `[0,1]`. A claimed
`costObserved` is refused against a `-1` action count or a non-finite time. A row
whose evidence contradicts itself contributes nothing at all — but it never
disappears: it is counted and its rejections are rendered.

**Cleanup and control evidence are checked on EVERY row, not only scored ones.** A
negative control is never "scored" — that is normal for the kind — so putting
those checks inside the scored-only path let a trial with a retained cleanup
failure certify a clean arm. A dirty trial is dirty whatever its kind, and a
control marked usable whose own evidence denies it is a corrupt row whatever its
kind.

The aggregate and both reports publish `emitted / scored / invalid / skipped /
unscored / unverified / cleanupFailed / costUnobserved / legacy` counts per arm
plus the negative-control census, so an arm with one valid and one invalid trial
can never look like a complete one-trial result, and an arm with nothing
measurable renders `n/a` rather than `0`.

**Negative controls are counted completely.** `not-run`, `unobserved`, `partial`
and `observed` are distinct states. Only `observed` — EVERY negative-control row
of the arm usable — publishes a measured false-move maximum; a clean maximum over
a usable subset cannot establish a clean arm, so `partial` renders
`n/a (partial: k of n observed)` and the hypothesis section carries an explicit
caveat that no verdict establishes an absence of false defensive moves.

The downstream product readers (`phorvex/cmd/p3report`, `phorvex/cmd/p3deep`,
`phorvex/internal/console`) import the same contract rather than reimplementing
it: they exclude refused rows, never average a `-1` cost, and disclose
partial-control corpora instead of publishing them as measurements.

**Legacy rows are excluded from certified means everywhere**, including those
product readers. A pre-contract row records no evidence that it measured
anything, so blending it into a current score or efficiency mean would launder
unverified history into a fresh measurement. Such rows stay readable and are
counted openly; a corpus with nothing certified left renders UNAVAILABLE, which
is not zero and not a measured result.

**Comparison scope (honest limit).** `TrialSeed` includes the defender identity,
so the baseline arm's trial *i* and a defended arm's trial *i* are seeded
differently. A scored comparison means "this arm vs the undefended arm at the
same index"; it is *not* the same trial re-run with the defense removed. The
adaptive comparison carries a further limitation: the undefended adaptive control
has no rotation rhythm to learn and therefore strikes immediately, so a scored
adaptive contrast does not isolate the value of the learned strategy.

---

## 2. How to ADD A NEW SCENARIO

Create **one new file** under `scenarios/` and implement the `Scenario` interface.
That is the entire change — no core file is touched.

```go
package scenarios

import (
    "context"

    "github.com/r6security/phoenix-test-harness/internal/core"
)

// 1) Self-register in init(). This is the ONLY wiring needed.
func init() { core.RegisterScenario(&myScenario{}) }

type myScenario struct {
    app string // private per-scenario state
}

// 2) Advertise static metadata (name, category, source, honest R6 tag,
//    ATT&CK technique IDs, and any cluster capability requirements).
func (s *myScenario) Metadata() core.ScenarioMeta {
    return core.ScenarioMeta{
        Name:               "cX-my-scenario",          // stable, unique (dup name panics at startup)
        Category:           core.CategoryModernUnsupported,
        Source:             "where this scenario was extracted from",
        R6ResponseTag:      core.R6CannotRespond,       // honest, code-grounded verdict
        AttackTechniqueIDs: []string{"T1610", "T1525"}, // MITRE ATT&CK for Containers
        CapabilityRequirements: nil,                    // e.g. []core.Capability{core.CapGPU} -> skip-with-note if absent
        R6Justification:    "honest prose explaining the tag",
    }
}

// 3) Stage the target workload IN THE SANDBOX NAMESPACE (use the shared
//    builders in scenarios/common.go + internal/mocks so every Create goes
//    through the safety guard and carries the r6th.io/owned label).
func (s *myScenario) Setup(ctx context.Context, env *core.Env) error {
    s.app = "myscn-target"
    _, err := deployTarget(ctx, env, s.app, "", nil)
    return err
}

// 4) Perform the attack kill-chain; return the stages + commands (provenance).
func (s *myScenario) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
    // ... do the attack against the OWNED target in env.Cfg.Namespace ...
    return core.AttackResult{
        Stages:   []string{"stage 1", "stage 2"},
        Commands: []string{"kubectl exec ...", "..."},
    }, nil
}

// 5) Measure a CONCRETE OBSERVABLE post-state. Achieved must be a real fact
//    (byte count, marker file, HTTP 200 + data, CPU-seconds, pod UID), never
//    a vague signal. Carry the raw evidence so the report can cite it.
func (s *myScenario) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
    achieved := /* ...concrete check... */ true
    return core.OracleResult{
        Achieved:      achieved,
        ObservedState: "human-readable observed state",
        Evidence:      map[string]string{"bytes": "4096"},
    }, nil
}

// 6) Idempotent, re-runnable cleanup (label-selector delete of owned objects).
func (s *myScenario) Teardown(ctx context.Context, env *core.Env) error {
    return teardownByApp(ctx, env, s.app)
}
```

**Optional:** to drive the genuine reactive Phoenix matcher path, have `Execute`
look up the active defender's `Emitter` (see `scenarios/c2_persistence_evict.go`)
and emit a normalized `SecurityEvent{Type,ThreatLevel,Source}`. Only the
FullPhoenix arm implements `Emitter`; against other arms the scenario simply
relies on the arm's own behavior.

That's it — the runner's `core.Scenarios()` enumerator picks it up automatically,
it runs against every registered defender, and the report/MITRE matrix include it
with **zero** changes to any core file.

---

## 3. How to ADD A NEW DEFENDER

Create **one new file** under `defenders/` and implement the `Defender`
interface. The Phorvex production defender will land exactly this way.

```go
package defenders

import (
    "context"

    "github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterDefender(&myDefender{}) }

type myDefender struct{}

func (d *myDefender) Metadata() core.DefenderMeta {
    return core.DefenderMeta{
        Name:        "d-mydefender",
        Description: "what it does and its honest limits",
        // IsNegativeControlBaseline: true,        // ONLY the undefended NoMTD anchor sets this
        // MeanRotationIntervalSeconds: 6,          // nominal rotation period; the adaptive attacker uses it
    }
}

func (d *myDefender) Setup(ctx context.Context, env *core.Env) error    { /* stand up the defense */ return nil }
func (d *myDefender) Start(ctx context.Context, env *core.Env) error    { /* activate for the trial */ return nil }
func (d *myDefender) Stop(ctx context.Context, env *core.Env) error     { return nil }
func (d *myDefender) Teardown(ctx context.Context, env *core.Env) error { /* idempotent cleanup */ return nil }

// OPTIONAL: implement DefenseObserver so the runner can attribute disruption to a
// concrete defensive action and count false moves for the negative control.
func (d *myDefender) DefensiveActions(ctx context.Context, env *core.Env) (count int, atUnix []float64, err error) {
    return 0, nil, nil
}
```

Optional capability interfaces a defender may implement (all detected by the
runner via type-assertion, no core change):

- **`DefenseObserver`** — report defensive-action count + timestamps (drives
  time-to-action, security-per-cost, and the negative-control false-move count).
- **`Emitter`** (see `scenarios/c2_persistence_evict.go`) — emit a normalized
  `SecurityEvent` so scenarios can drive the genuine matcher path; the FullPhoenix
  arm uses this to exercise the real `matcher.go`.
- **`SkipReporter`** (`SkipReason() (bool, string)`) — mark the arm
  skipped-with-note (used by the `d-phorvex-slot` stub).

The five shipped defenders are: `d-nomtd` (positive-control baseline),
`d-r6blindtimer` (blind fixed-interval rotation, no telemetry),
`d-randomequal` (same mean rate, memoryless gaps — the fair equal-cost arm),
`d-fullphoenix` (the genuine extended Phoenix operator), and `d-phorvex-slot`.

### The Phorvex slot is RESERVED

`defenders/d_phorvex_slot.go` is a **registered stub** that advertises itself and
returns skip-with-note in every metric. It exists to **prove the registry
composes**: the real Phorvex defender drops in later by replacing this one file
with a real implementation — **one new/edited file, zero harness changes**. Until
then it intentionally skips on all 18 scenarios.

---

## 4. Portability & config model

**Nothing environment-specific is hardcoded.** The same binary targets
kind / EKS / CoreWeave / vcluster purely by swapping a per-target config
(`internal/config/config.go`). `TargetConfig`:

| Key | Meaning |
|---|---|
| `kubeconfig` | path to kubeconfig (empty = standard `KUBECONFIG` / `~/.kube/config` lookup) |
| `context` | the **only** kube-context this run is authorized to target |
| `namespace` | the sandbox namespace; ALL attack behavior and every object is confined here |
| `ownedAck` | **REQUIRED** `true` — you assert you OWN / are AUTHORIZED on the target cluster; the harness refuses to run otherwise |
| `trialsPerArm` | trials per (scenario, defender) arm; smoke = 2, full benchmark >= 20 (same loop) |
| `masterSeed` | fixed master seed; every per-trial RNG derives from it (full reproducibility) |
| `phoenixSrcDir` | phoenix-extended source tree for the FullPhoenix arm (empty = that arm skips-with-note) |
| `outDir` | where `metrics.jsonl`, `raw/`, `provenance.json`, `report.md`, `mitre_matrix.md` are written |
| `defenderFilter` / `scenarioFilter` | optional subset filters (empty = run every registered plugin) |

See `config.kind.yaml` (live smoke) and `internal/config/config.example.yaml`. The
metric schema is **identical** on every environment.

### Capability detection + skip-with-note

`internal/capability/detect.go` probes the **live cluster at runtime** (no
hardcoding):

- **CapGPU** — any node advertising `nvidia.com/gpu` allocatable > 0.
- **CapMIG** — any `nvidia.com/mig-*` resource or MIG strategy label.
- **CapMultiNode** — more than one schedulable node; also reports `NodeCount`.

A scenario whose `CapabilityRequirements` the cluster lacks is
**SKIPPED-with-note** (recorded in the metric), never failed. All 18 shipped
scenarios are CPU-only/mock stand-ins with **zero** capability requirements, so
none is hard-skipped on the single-node kind cluster; **GPU/MIG-specific Phoenix
claims are reported capability-pending, not fabricated.**

---

## 5. Safety & containment model

A mandatory containment layer (`internal/safety/guard.go`) runs **before every
mutating call**. It REFUSES (hard stop, no mutation) unless **all** hold:

1. live current-context **==** `cfg.Context`,
2. the live apiserver host **==** the host declared for that context in the
   kubeconfig (catches a redirected/proxied connection),
3. `ownedAck == true`,
4. the object's target namespace **==** `cfg.Namespace`.

Verified: the guard refuses a nonexistent context (live exit 1) and refuses
wrong-context / wrong-host / missing-ack / out-of-sandbox (unit-tested). Every
`Create`/`Delete` is gated by `AssertMutationAllowed`.

**Containment guarantees (`internal/safety/sandbox.go`, `internal/mocks/`):**

- All attack behavior is confined to `cfg.Namespace`; every created object carries
  the `r6th.io/owned=true` label and teardown is an **idempotent, re-runnable**
  label-selector delete.
- **Category-3 uses MOCKS only** — an in-namespace mock IMDS (ClusterIP standing
  in for `169.254.169.254`), a mock C2/exfil sink (counts received bytes), a mock
  OCI registry serving a tampered image, a mock CI/CD pipeline runner, and **fake**
  credentials/tokens. It **NEVER** touches real cloud, registries, or credentials —
  only comment/log references to `169.254.169.254`.
- The cryptomining stand-in is a **CPU-bounded busy loop** under a CPU limit
  (~200m cgroup cap) for a fixed duration — never a real miner/pool.

> **Known portability caveat (medium, to fix before any multi-context target):**
> the FullPhoenix operator is launched as a local process. controller-runtime's
> `GetConfigOrDie()` follows the kubeconfig **current-context**, not an env var, so
> the operator is a mutating actor that runs **outside** the harness guard. On this
> single-cluster kind setup it is correct only because current-context ==
> `kind-amtd-test`. Pin the operator to the configured context (via `--kubecontext`
> / a dedicated kubeconfig) before pointing the harness at a multi-context or cloud
> kubeconfig.

---

## 6. Running: SMOKE vs full benchmark

Reproducible from the master seed alone. The **only** difference between smoke and
the full benchmark is the `trialsPerArm` knob — the run loop, controls, CI math,
report, and provenance are identical.

**SMOKE (2 fixed-seed trials per arm, the default):**

```sh
# from build/test-harness
go run ./cmd/harness -config config.kind.yaml
```

`config.kind.yaml` sets `trialsPerArm: 2`, `masterSeed: 1337`, context
`kind-amtd-test`, namespace `amtd-attack-test`. Per arm the runner produces the 2
fixed-seed trials + 1 negative-control trial + 1 adaptive trial.

**FULL >= 20-trial benchmark with confidence intervals (DEFERRED to the next
step):** bump the single knob and re-run the SAME loop:

```yaml
# config.kind.yaml (or any per-target config)
trialsPerArm: 20   # or more
```

```sh
go run ./cmd/harness -config config.kind.yaml
```

The t-interval math already in `internal/core/stats.go` tightens automatically as
`n` grows (df=19 -> t=2.093 at 95%). Before the full run, fix the mock-readiness
race noted in `out/report.md` for `c3-imds-theft` / `c3-secrets-sprawl` (their
positive control did not anchor in the smoke).

### Outputs & provenance

Written under `outDir` (default `out/`):

- `metrics.jsonl` — one Metric JSON line per (scenario, defender, trial).
- `raw/<scenario>_<defender>_<trial>.log` — a raw log per trial (plus per-trial
  `operator_*.log` for the FullPhoenix arm).
- `provenance.json` — ties **each table cell -> exact command(s) + raw log path +
  seed**. Everything reproduces from `masterSeed`.
- `report.md` — per-arm 95%-CI table.
- `mitre_matrix.md` — MITRE ATT&CK for Containers coverage matrix.

See `build/EFFECTIVENESS-K8S.md` (results), `build/ATTACKS-K8S.md` (scenario
catalog + honest R6 verdicts), and `build/ATTACK-COVERAGE-K8S.md` (ATT&CK
coverage) for the analysis of the current 2-trial smoke.

---

## 7. The AI / LLM / Agentic suite (Pass B)

Pass B adds **27 AI threat scenarios** (`scenarios/ai1_*.go` x5 + `scenarios/ai2_*.go`
x22, one self-registering file each) plus **5 CPU-only AI mock stand-ins**
(`internal/mocks/ai_standins.go`). It reuses the EXACT same two interfaces, the
same generic runner, the same 5 defender arms, the same safety guard, and the same
capability detection as the K8s suite — **ZERO core/interface changes** to add an
AI scenario, **ZERO** changes to the runner or the main report. The metric schema
gained only **additive** fields (all `omitempty`), so the 1980 Pass-A rows still
decode unchanged (verified live: the `-dollars-from out-bench/metrics.jsonl` view
reads all 1980 rows with no error).

The two scenario **groups**:

- **Group 1 — R6 Phoenix-for-AI product pillars** (5): `ai1-llm-jacking`,
  `ai1-model-theft`, `ai1-prompt-injection`, `ai1-inference-manipulation`,
  `ai1-pillar03-panic-mutation`. Each verdict traces verbatim to
  `build/AI-MTD-AUDIT.md`.
- **Group 2 — OWASP LLM Top-10 (2025) / MCP / Agentic / Extraction / KV-cache /
  Supply-chain / RAG** (22): the `ai2-*` files.

See `build/ATTACKS-AI.md` (per-scenario catalog: source, R6 tag, MTD-effect tag,
ATLAS + OWASP IDs, split oracles), `build/ATTACK-COVERAGE-AI.md` (MITRE ATLAS +
OWASP LLM Top-10 coverage with gaps visible), and `build/EFFECTIVENESS-AI.md`
(the live 2-trial smoke results + the `$`/Schwartau/reusability extension + the
H1/H2/H3 frame + the recomputed Pass-A-with-dollars table).

> **Honest scope of the live smoke (`out-ai-smoke/`):** the 2-trial smoke (which
> the runner expands to 4 rows/arm: 2 fixed-seed + 1 negative-control + 1 adaptive)
> exercised only the **4 alphabetically-first `ai1-*` scenarios** before it was cut
> short — `ai1-inference-manipulation`, `ai1-llm-jacking`, `ai1-model-theft`,
> `ai1-pillar03-panic-mutation`. Of those, only **2** measured end-to-end on the
> CPU-only kind node (`ai1-inference-manipulation`, `ai1-model-theft`); the other
> two **SKIPPED-WITH-NOTE** (`ai1-llm-jacking` needs CapGPU, `ai1-pillar03-panic-mutation`
> needs CapMultiNode). `ai1-prompt-injection` and all 22 `ai2-*` scenarios, and the
> `report.md`/`provenance.json`/`report-dollars.md` for `out-ai-smoke`, were **not
> produced** in this smoke. The trigger-supplied NEUTRALIZE / BOUNDS-ONLY paths are
> validated by the unit tests (`go test ./...` exit 0), not yet by the live smoke.
> The full benchmark (`trialsPerArm >= 20`) is **DEFERRED** and re-runs the SAME
> loop to completion.

### How to ADD A NEW AI SCENARIO

Identical to section 2 (one new file under `scenarios/` + one `init()` register),
with three AI-specific conveniences from the shared `scenarios/ai_common.go`
plumbing — used so every AI scenario stamps the split oracle, the trigger, and the
additive evidence CONSISTENTLY with zero interface changes:

1. **Deploy a stand-in** from `internal/mocks/ai_standins.go` in `Setup`
   (`mocks.DeployMockInferenceServer` / `…MCPServer` / `…ModelRegistry` /
   `…Retriever` / `…AgentRuntime`). Every object is busybox-only, sandbox-namespace
   only, and `r6th.io/owned`-labelled for idempotent teardown.
2. **Build a split-oracle result** with the `aiOracle` builder. It stamps both
   halves (`inRequestAchieved` + `persistenceAchieved`), the MEASURED MTD-effect
   inputs (`persistenceDisrupted`, `neutralized`), the audit `triggerAttribution`,
   the replay counts, and the `AtlasIDs`/`OwaspIDs` into `OracleResult.Evidence`,
   which the runner lifts onto the additive metric fields — **no interface change**.
   Capability-pending halves use `aiSkip(...)`.
3. **Drive the genuine matcher path** (only if the scenario neutralizes via a
   trigger) by calling `emitGenuineTrigger(ctx, env, targetPod, eventType)` in
   `Execute`. It is a no-op unless the active defender implements the EXISTING
   `Emitter` (only `d-fullphoenix` does), and it injects a normalized
   `SecurityEvent{Type,ThreatLevel,Source}` EXACTLY as `c2-persistence-evict` —
   `amtdv1beta1.TypePanic` (evict) or `TypeTimed` (drift/regenerate).

Stamp the target pod with `RotationTargetLabel` (`r6th.io/rotation-target=true`,
via `stampRotationTarget`) so the timer arms and the FullPhoenix AMTD `PodSelector`
churn it. That is the entire change — the runner's enumerator, the report, and the
ATLAS/OWASP coverage pick it up with zero core edits.

### The 5 AI mock stand-ins (`internal/mocks/ai_standins.go`)

All are **CPU-only busybox:1.36** (the `BusyboxImage` const), sandbox-only,
owned-labelled, reusing the SAME `internal/mocks` patterns as the K8s suite
(`httpResponderScript`, `deployServer`, `WaitHTTPReady`, marker-file oracles,
`env.Exec`). **No new images, no real LLM/registry/cloud, no GPU.**

| Stand-in | What it models | Key oracle substrate |
|---|---|---|
| `MockInferenceServer` ("the model") | HTTP responder behind a **stable external** `mock-infer-svc` whose selector is the **leader** label (`r6th.io/infer-leader`), so the backend pod rotates while the external name stays stable (audit #3). `/v1/completions`, `/healthz`, `/v1/models` (fake weights digest `sha256:r6thmockweights`). | `/tmp/work_accrued` = a CPU proxy for GPU-seconds; `/tmp/session_<id>` = per-session "memory"; `/tmp/kv_<session>` = mocked KV-cache. |
| `MockMCPServer` (trusted + rogue) | JSON-RPC-ish responder: `/tools` (tool manifest — the tool-poisoning surface) + `/call/<tool>`. Deployable as `mcp-trusted` (`mock-mcp-svc`) or `mcp-rogue` (`mock-rogue-mcp-svc`). | Tool descriptions/results writable to `/tmp` so a poisoning step is observable. |
| `MockModelRegistry` | Serves a model manifest `{name,version,digest,signature}`; `GoldenModelDigest` vs `PoisonedModelDigest`. | Writable `/tmp/manifest.json` + `/tmp/served_digest` so a poison/tamper step mutates the served digest (drift oracle); `RestoreGolden` models the BUILT Regenerate action. |
| `MockRetriever` + embedding store | Tiny vector store: `/upsert`, `/query` (top-k by seeded score), `/doc/<id>`. | Corpus + a "poisoned doc" live in `/tmp/store.jsonl` so RAG-poisoning / embedding-tamper steps are observable (the data-plane differentiator). |
| `MockAgentRuntime` | busybox tool-calling loop: per step calls retriever -> MCP `/tools`+`/call` -> inference. | Cross-session memory in an owned `agent-memory` ConfigMap (+`/tmp/agent_mem`); tool registry in an owned `agent-tools` ConfigMap; "excessive agency" = calling a high-privilege mock tool (marker). |

**GPU-fundamental stand-ins are BUILT but their headline number is
CAPABILITY-PENDING:** `work_accrued` is a CPU proxy for GPU-utilization (real
GPU-util SLO is GPU-PENDING per audit #8); KV-cache is mocked as a `/tmp/kv_<session>`
file (real KV-cache is GPU-PENDING per audit #11); GPU side-channel / co-location
are `CapGPU+CapMultiNode` and skip-with-note on kind.

### REUSE-PROOF: same harness, EKS / CoreWeave / vcluster by config alone

The AI suite is **environment-agnostic by construction** — it runs UNCHANGED on AWS
EKS / CoreWeave / vcluster purely by swapping the per-target config (section 4):

- **Config-only retarget.** Point `kubeconfig` / `context` / `namespace` /
  `ownedAck` at the target cluster (e.g. `config.ai.smoke.yaml` already pins
  context `kind-amtd-test`, namespace `amtd-ai-test`, `ownedAck: true`,
  `scenarioFilter` = exactly the 27 AI names). The same binary, same run loop, same
  metric schema, same safety guard, and same `masterSeed` reproducibility apply on
  every environment — **no code change, no recompile-per-cloud**.
- **Capability detection does the right thing automatically.**
  `internal/capability/detect.go` probes the **live** cluster: on the CPU-only kind
  node it measured `CapGPU=false`, `CapMIG=false`, `CapMultiNode=false`,
  `NodeCount=1`, so the 6 GPU/MIG/multi-node-fundamental AI scenarios
  (`ai1-llm-jacking`, `ai2-unbounded-consumption`,
  `ai2-kvcache-poisoning-cross-session-leak` [CapGPU]; `ai1-pillar03-panic-mutation`
  [CapMultiNode]; `ai2-gpu-side-channel`, `ai2-co-location-cross-tenant`
  [CapGPU+CapMultiNode]) **SKIP-WITH-NOTE** and are marked **capability-pending** —
  never failures. On a real GPU cluster (EKS/CoreWeave) those same scenarios run and
  fill in the headline GPU numbers with **zero** code change; the kind run validates
  the harness + the CPU stand-ins.
- **Same safety contract everywhere.** The required `ownedAck`, the
  refuse-non-configured-context guard, the apiserver-host match, and the sandbox
  namespace confinement (section 5) apply identically on cloud. (Note the same
  medium FullPhoenix-operator-context caveat from section 5: pin the operator to the
  configured context before pointing at a multi-context/cloud kubeconfig.)

**Phorvex plugs in as just another defender arm.** `defenders/d_phorvex_slot.go` is
a **registered stub** that skips-with-note on every AI scenario (it appears in the
`out-ai-smoke` metrics as `skipped=true` with the composition-proof reason). It
exists to **prove the slot**: the real Phorvex production defender drops in later by
replacing this one file — **one new/edited file, zero harness changes** — and the
H1/H2/H3 Phorvex comparison column (currently TO-BE-FILLED) fills automatically.
