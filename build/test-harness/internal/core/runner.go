package core

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"path/filepath"
	"sync"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/adaptive"
)

// EnvFactory builds a fresh Env for one trial. The runner is decoupled from how
// clients/loggers are constructed (the cmd wires this); that keeps the runner
// generic and unit-testable with a fake factory.
type EnvFactory func(scenarioName, defenderName string, trial int, seed int64, rawLogPath string) (*Env, func() error, error)

// DefaultCleanupTimeout bounds the cleanup owed by ONE trial. Cleanup runs on a
// detached context so it is still attempted after the trial context is
// cancelled, but it is always bounded — there is no unbounded background retry.
const DefaultCleanupTimeout = 2 * time.Minute

// RunnerOptions configures one benchmark run. Everything is generic: the runner
// never names a specific scenario or defender.
type RunnerOptions struct {
	TrialsPerArm int
	MasterSeed   int64
	OutDir       string
	// CILevel is the confidence level for per-arm aggregation (e.g. 0.95).
	CILevel float64
	// RunNegativeControl runs the extra no-attack negative-control trial per arm.
	RunNegativeControl bool
	// AdaptiveArm runs an extra adaptive-attacker pass per (scenario, defender).
	AdaptiveArm bool
	// ScenarioFilter/DefenderFilter restrict the run (empty = all).
	ScenarioFilter map[string]bool
	DefenderFilter map[string]bool
	// CleanupTimeout bounds one trial's cleanup (0 = DefaultCleanupTimeout).
	CleanupTimeout time.Duration
}

// RunOutcome describes what the matrix run ACTUALLY did, so a report can never
// present a partial run as a complete matrix.
type RunOutcome struct {
	// PlannedTrials is the number of trials the selected matrix would emit.
	PlannedTrials int `json:"plannedTrials"`
	// ExecutedTrials is the number actually run; WrittenTrials the number
	// successfully persisted by the metric writer.
	ExecutedTrials int `json:"executedTrials"`
	WrittenTrials  int `json:"writtenTrials"`
	// Complete is true iff every planned trial ran, was written, and no barrier
	// was raised.
	Complete bool `json:"complete"`
	// Aborted records that the run stopped early; AbortReason says why.
	Aborted     bool   `json:"aborted"`
	AbortReason string `json:"abortReason,omitempty"`
	// Barriers retains every stop condition raised (e.g. unverified cleanup).
	Barriers []string `json:"barriers,omitempty"`
	// BaselineDefender is the undefended positive-control arm, or "" when none is
	// registered (in which case NO ordinary comparison can be scored).
	BaselineDefender string `json:"baselineDefender,omitempty"`
	// BaselineAnchorOnly marks a baseline force-included past a DefenderFilter:
	// it runs positive trials only, so its negative control and adaptive pass are
	// NOT run and must never be reported as having passed.
	BaselineAnchorOnly bool `json:"baselineAnchorOnly,omitempty"`
	// LateCleanups retains every cleanup call that outlived its wall-clock bound,
	// with whatever it eventually returned. Their trials stay unresolved: a late
	// return is not evidence the state was clean when the run needed it to be.
	LateCleanups []LateCleanup `json:"lateCleanups,omitempty"`
}

// Runner executes the generic scenario x defender x trial matrix.
type Runner struct {
	opts    RunnerOptions
	factory EnvFactory
	metrics *MetricWriter
	// onMirror receives every run-wide log line (e.g. stdout).
	onMirror func(string)
	// learners memoizes one adaptive Learner per (scenario, defender) arm.
	learners map[string]*adaptive.Learner
	outcome  RunOutcome
	// pending tracks cleanup calls the runner still owns, including ones that
	// outlived their bound; lateMu guards outcome.LateCleanups, which those
	// goroutines write to.
	pending sync.WaitGroup
	lateMu  sync.Mutex
}

// NewRunner constructs a runner.
func NewRunner(opts RunnerOptions, factory EnvFactory, metrics *MetricWriter, onMirror func(string)) *Runner {
	if opts.CILevel == 0 {
		opts.CILevel = 0.95
	}
	if opts.CleanupTimeout <= 0 {
		opts.CleanupTimeout = DefaultCleanupTimeout
	}
	return &Runner{
		opts:     opts,
		factory:  factory,
		metrics:  metrics,
		onMirror: onMirror,
		learners: map[string]*adaptive.Learner{},
	}
}

// Outcome reports what the last Run actually executed. It is the authority on
// matrix completeness; a caller must not describe the report as a complete
// matrix when Complete is false. The LateCleanups slice is copied because
// retained cleanup goroutines keep updating it.
func (r *Runner) Outcome() RunOutcome {
	r.lateMu.Lock()
	defer r.lateMu.Unlock()
	out := r.outcome
	out.LateCleanups = append([]LateCleanup(nil), r.outcome.LateCleanups...)
	return out
}

func (r *Runner) mirror(format string, args ...any) {
	if r.onMirror != nil {
		r.onMirror(fmt.Sprintf(format, args...))
	}
}

// anchorKey identifies a positive-control observation by trial index AND trial
// kind. An adaptive pass may only anchor to an ADAPTIVE control; it never
// borrows an ordinary baseline.
type anchorKey struct {
	trial int
	kind  TrialKind
}

// anchorObservation is the OBSERVED result of the undefended control for one
// anchorKey. It is recorded only after the control trial's whole lifecycle
// (including cleanup) is known to be valid.
type anchorObservation struct {
	defender       string
	valid          bool
	oracleAchieved bool
}

// trialSpec is the fully-resolved description of one trial to run.
type trialSpec struct {
	scenario     Scenario
	defender     Defender
	trial        int
	kind         TrialKind
	isBaseline   bool
	anchorOnly   bool
	baselineName string
	learner      *adaptive.Learner
	anchors      map[anchorKey]anchorObservation
}

// Run executes the whole matrix and returns the metrics written so far. On a
// barrier or a hard error it returns the PARTIAL metrics together with the
// error, so the evidence produced before the stop is never discarded — the
// caller must then report the run as INCOMPLETE (see Outcome).
func (r *Runner) Run(ctx context.Context) ([]Metric, error) {
	r.outcome = RunOutcome{}
	scenarios := r.selectedScenarios()
	defenders := r.selectedDefenders()
	if len(scenarios) == 0 {
		return nil, fmt.Errorf("runner: no scenarios registered/selected")
	}
	if len(defenders) == 0 {
		return nil, fmt.Errorf("runner: no defenders registered/selected")
	}
	if r.metrics == nil {
		return nil, fmt.Errorf("runner: no metric writer configured; refusing to run an unrecorded matrix")
	}

	// Identify the positive-control baseline (undefended) so disruption can be
	// anchored. Search the FULL registry, not just the selected arms: the baseline
	// MUST run to anchor disruption even when a DefenderFilter excludes it. If it is
	// not among the selected arms it is FORCE-INCLUDED as an anchor-only arm
	// (positive trials only, tagged so the report omits it from the requested view).
	baseline := findBaselineDefender(Defenders())
	baselineSelected := baseline != nil && containsDefenderName(defenders, baseline.Metadata().Name)
	anchorOnlyBaseline := baseline != nil && !baselineSelected
	if anchorOnlyBaseline {
		r.mirror("baseline arm %q force-included (ANCHOR-ONLY) so disruption anchors despite DefenderFilter; its negative control and adaptive pass are NOT run and are reported as not-run, never as passed", baseline.Metadata().Name)
	}
	if baseline == nil {
		r.mirror("WARNING: no undefended positive-control defender is registered; NO ordinary comparison can be scored in this run")
	}
	r.outcome.BaselineDefender = baselineName(baseline)
	r.outcome.BaselineAnchorOnly = anchorOnlyBaseline

	ordered := orderBaselineFirst(defenders, baseline)
	r.outcome.PlannedTrials = r.plannedTrials(len(scenarios), ordered, baseline, baselineSelected)

	for _, sc := range scenarios {
		meta := sc.Metadata()
		// Positive-control observations for THIS scenario, keyed by (trial, kind)
		// and populated ONLY from control trials whose whole lifecycle was valid.
		anchors := map[anchorKey]anchorObservation{}

		for _, d := range ordered {
			dmeta := d.Metadata()
			isBaseline := baseline != nil && dmeta.Name == baseline.Metadata().Name
			anchorOnly := isBaseline && !baselineSelected
			armKey := meta.Name + "|" + dmeta.Name
			learner := r.learners[armKey]
			if learner == nil {
				learner = adaptive.NewLearner()
				r.learners[armKey] = learner
			}
			spec := trialSpec{
				scenario: sc, defender: d, kind: TrialOrdinary,
				isBaseline: isBaseline, anchorOnly: anchorOnly,
				baselineName: baselineName(baseline), learner: learner, anchors: anchors,
			}

			for trial := 0; trial < r.opts.TrialsPerArm; trial++ {
				s := spec
				s.trial, s.kind = trial, TrialOrdinary
				if stop := r.runAndRecord(ctx, s); stop != nil {
					return r.metrics.All(), stop
				}
			}

			// An anchor-only baseline only needs its positive trials (to establish
			// the anchor); its negative-control + adaptive passes are NOT run (cost
			// the DefenderFilter intentionally excluded) and are reported as not-run.
			if r.opts.RunNegativeControl && !anchorOnly {
				s := spec
				s.trial, s.kind = r.opts.TrialsPerArm, TrialNegativeControl
				if stop := r.runAndRecord(ctx, s); stop != nil {
					return r.metrics.All(), stop
				}
			}

			// Adaptive attacker arm: an extra pass that times the kill-chain into
			// the learned lull. It is anchored ONLY to the baseline arm's own
			// adaptive pass at the same index; when that control was not run (e.g.
			// an anchor-only baseline, or -adaptive=false on the baseline) the
			// adaptive row stays UNSCORED with an explicit missing-control reason.
			if r.opts.AdaptiveArm && !anchorOnly {
				s := spec
				s.trial, s.kind = r.opts.TrialsPerArm+1, TrialAdaptive
				if stop := r.runAndRecord(ctx, s); stop != nil {
					return r.metrics.All(), stop
				}
			}
		}
	}
	all := r.metrics.All()
	// A matrix that finished under an ended context cannot be certified complete,
	// even when every planned trial produced a row.
	if err := ctx.Err(); err != nil {
		reason := fmt.Sprintf("run context ended during the matrix: %v", err)
		r.abort(reason)
		return all, fmt.Errorf("runner: %s", reason)
	}
	r.outcome.Complete = !r.outcome.Aborted &&
		r.outcome.ExecutedTrials == r.outcome.PlannedTrials &&
		r.outcome.WrittenTrials == r.outcome.PlannedTrials
	return all, nil
}

// plannedTrials computes how many trials the selected matrix will emit.
func (r *Runner) plannedTrials(scenarios int, ordered []Defender, baseline Defender, baselineSelected bool) int {
	per := 0
	for _, d := range ordered {
		anchorOnly := baseline != nil && d.Metadata().Name == baseline.Metadata().Name && !baselineSelected
		per += r.opts.TrialsPerArm
		if r.opts.RunNegativeControl && !anchorOnly {
			per++
		}
		if r.opts.AdaptiveArm && !anchorOnly {
			per++
		}
	}
	return scenarios * per
}

// runAndRecord runs one trial, persists it, updates the positive-control anchor
// table and enforces the stop conditions. A non-nil result aborts the run; the
// metric has already been written, so the evidence survives the stop.
func (r *Runner) runAndRecord(ctx context.Context, s trialSpec) error {
	if err := ctx.Err(); err != nil {
		reason := fmt.Sprintf("run context ended before %s/%s trial %d: %v",
			s.scenario.Metadata().Name, s.defender.Metadata().Name, s.trial, err)
		r.abort(reason)
		return fmt.Errorf("runner: %s", reason)
	}

	m := r.runOneTrial(ctx, s)
	r.outcome.ExecutedTrials++

	if err := r.metrics.Write(m); err != nil {
		// The row could not be persisted. Cleanup has already been attempted; the
		// run stops rather than continuing to produce results that will not appear
		// in the metrics file.
		reason := fmt.Sprintf("metric write failed for %s/%s trial %d: %v",
			m.Scenario, m.Defender, m.Trial, err)
		r.abort(reason)
		return fmt.Errorf("runner: %s", reason)
	}
	r.outcome.WrittenTrials++

	// The runner reads its OWN freshly written row back through the same
	// validated interpretation every downstream consumer uses, so an anchor can
	// never rest on a claim the readers would reject.
	val := m.Validated()
	v := val.Claim
	// Record the positive-control observation only when the control trial's whole
	// lifecycle — including cleanup — is known to be valid. Only kinds that can
	// serve as a control are recorded; a negative control anchors nothing.
	if s.isBaseline && s.kind != TrialNegativeControl {
		if val.OracleUsable && v.Cleanup.Complete {
			s.anchors[anchorKey{s.trial, s.kind}] = anchorObservation{
				defender: m.Defender, valid: true, oracleAchieved: m.OracleAchieved,
			}
		} else {
			r.mirror("positive control %s/%s trial %d (%s) is NOT usable as an anchor: %s",
				m.Scenario, m.Defender, m.Trial, val.Kind(), m.SkipReason)
		}
	}

	// Unverified cleanup: no later trial may reuse potentially contaminated
	// state. This covers steps that FAILED and steps that are UNRESOLVED — a
	// call that outlived its bound may still be mutating the namespace, so it is
	// at least as disqualifying as one that returned an error.
	if !v.Cleanup.Complete {
		var steps string
		for _, f := range v.Cleanup.Unfinished() {
			if f.Unresolved {
				steps += fmt.Sprintf("; %s: UNRESOLVED after %.1fs (may still be running)", f.Step, f.Seconds)
				continue
			}
			steps += "; " + f.Step + ": " + f.Error
		}
		reason := fmt.Sprintf("cleanup did not verify for %s/%s trial %d%s",
			m.Scenario, m.Defender, m.Trial, steps)
		r.outcome.Barriers = append(r.outcome.Barriers, reason)
		r.abort(reason)
		return fmt.Errorf("runner: stopping before another trial reuses unverified state: %s", reason)
	}
	return nil
}

func (r *Runner) abort(reason string) {
	r.outcome.Aborted = true
	r.outcome.Complete = false
	if r.outcome.AbortReason == "" {
		r.outcome.AbortReason = reason
	}
	r.mirror("RUN ABORTED: %s", reason)
}

// trialRun carries one trial's mutable state across execute -> cleanup ->
// finalize. Splitting the three makes the ownership explicit: execute never
// cleans up, cleanup never scores, and NOTHING is derived until after cleanup —
// which is why no favorable derived value can survive a cleanup failure.
type trialRun struct {
	r    *Runner
	spec trialSpec
	m    Metric
	v    *MeasurementValidity
	env  *Env
	// closeEnv is the per-trial environment closer owed once the factory succeeded.
	closeEnv func() error
	// cleanup ownership: a phase that was ATTEMPTED owes its teardown, including
	// after a partial failure.
	owedDefenderTeardown bool
	owedScenarioTeardown bool
	owedDefenderStop     bool

	ar          AttackResult
	or          OracleResult
	actCount    int
	actTimes    []float64
	attackStart time.Time
	dwell       float64
}

// runOneTrial is the canonical per-trial path. It is the SAME loop for smoke (2)
// and the full (>=20) benchmark — only TrialsPerArm differs.
func (r *Runner) runOneTrial(ctx context.Context, s trialSpec) Metric {
	t := r.newTrialRun(s)
	if t.env != nil {
		t.execute(ctx)
	}
	t.cleanup(ctx)
	return t.finalize()
}

func (r *Runner) newTrialRun(s trialSpec) *trialRun {
	smeta := s.scenario.Metadata()
	dmeta := s.defender.Metadata()
	seed := TrialSeed(r.opts.MasterSeed, smeta.Name, dmeta.Name, s.trial)
	rawLog := filepath.Join(r.opts.OutDir, "raw", fmt.Sprintf("%s_%s_t%d.log", smeta.Name, dmeta.Name, s.trial))

	v := &MeasurementValidity{
		Version: MeasurementValidityVersion,
		Kind:    s.kind,
		Status:  MeasurementValid,
		Phase:   PhaseEnvFactory,
	}
	t := &trialRun{
		r:    r,
		spec: s,
		v:    v,
		m: Metric{
			Scenario:              smeta.Name,
			Defender:              dmeta.Name,
			Trial:                 s.trial,
			Seed:                  seed,
			RawLogPath:            rawLog,
			R6Tag:                 smeta.R6ResponseTag,
			Category:              smeta.Category,
			NegativeControl:       s.kind == TrialNegativeControl,
			AnchorOnly:            s.anchorOnly,
			DefensiveActions:      -1,
			FalseDefensiveActions: -1,
			Validity:              v,
		},
	}

	env, closeEnv, err := r.factory(smeta.Name, dmeta.Name, s.trial, seed, rawLog)
	t.env, t.closeEnv = env, closeEnv
	if err != nil {
		v.fail(PhaseEnvFactory, "env factory failed: "+err.Error())
		t.env = nil
		return t
	}
	if env == nil {
		v.fail(PhaseEnvFactory, "env factory returned no environment")
		return t
	}
	r.mirror("=== scenario=%s defender=%s trial=%d seed=%d kind=%s ===", smeta.Name, dmeta.Name, s.trial, seed, s.kind)
	env.Log.Logf("trial start: scenario=%s defender=%s trial=%d seed=%d kind=%s anchorOnly=%v", smeta.Name, dmeta.Name, s.trial, seed, s.kind, s.anchorOnly)
	return t
}

// execute runs the trial lifecycle. It records which phases were ENTERED (and
// therefore owe cleanup) and propagates every phase error into the validity
// block. It performs NO cleanup and derives NO score.
func (t *trialRun) execute(ctx context.Context) {
	sc, d, env, v := t.spec.scenario, t.spec.defender, t.env, t.v
	smeta, dmeta := sc.Metadata(), d.Metadata()

	// Capability gate — a REPORTED abstention, never a failure.
	v.enter(PhaseCapabilityGate)
	if miss := env.Caps.Missing(smeta.CapabilityRequirements); len(miss) > 0 {
		reason := fmt.Sprintf("cluster lacks required capabilities %v", miss)
		env.Log.Logf("SKIP: %s", reason)
		v.skip(PhaseCapabilityGate, reason)
		return
	}

	// ---- Defender Setup (+ registered-stub abstention) ----
	v.enter(PhaseDefenderSetup)
	t.owedDefenderTeardown = true
	if err := d.Setup(ctx, env); err != nil {
		env.Log.Logf("defender Setup error: %v", err)
		v.fail(PhaseDefenderSetup, "defender setup failed: "+err.Error())
		return
	}
	if skip, reason := defenderSkip(d); skip {
		env.Log.Logf("defender %s is a registered stub: %s", dmeta.Name, reason)
		v.skip(PhaseDefenderSetup, reason)
		return
	}

	// ---- Scenario Setup ----
	v.enter(PhaseScenarioSetup)
	t.owedScenarioTeardown = true
	if err := sc.Setup(ctx, env); err != nil {
		env.Log.Logf("scenario Setup error: %v", err)
		v.fail(PhaseScenarioSetup, "scenario setup failed: "+err.Error())
		return
	}

	// ---- Defender Start ----
	// A defense that failed to start was NOT under test: neither a disruption nor
	// an absence of one is attributable, so the measurement is invalid.
	v.enter(PhaseDefenderStart)
	t.owedDefenderStop = true
	if err := d.Start(ctx, env); err != nil {
		env.Log.Logf("defender Start error: %v", err)
		v.fail(PhaseDefenderStart, "defender start failed: "+err.Error())
		return
	}

	t.attackStart = time.Now()
	if t.spec.kind == TrialAdaptive {
		t.r.applyAdaptiveTiming(env, t.spec.learner)
	}

	// ---- Execute attack (or the deliberate no-op for the negative control) ----
	v.enter(PhaseAttackExecute)
	attackUsable := false
	if t.spec.kind == TrialNegativeControl {
		env.Log.Logf("NEGATIVE CONTROL: skipping attack Execute (no-op) — measuring false defensive moves")
		t.ar = AttackResult{Stages: []string{"no-op (negative control)"}}
		v.AttackExecuted = true
		attackUsable = true
	} else {
		ar, err := sc.Execute(ctx, env)
		t.ar = ar
		switch {
		case err != nil:
			// The stimulus never landed. Running an oracle now would measure the
			// absence of an attack, not the presence of a defense.
			env.Log.Logf("scenario Execute error: %v", err)
			v.fail(PhaseAttackExecute, "attack stimulus failed: "+err.Error())
		case ar.Skipped:
			env.Log.Logf("scenario reported skip: %s", ar.SkipReason)
			v.skip(PhaseAttackExecute, ar.SkipReason)
		default:
			v.AttackExecuted = true
			attackUsable = true
		}
	}

	// ---- Oracle (only when an attack actually ran) ----
	if attackUsable {
		v.enter(PhaseOracle)
		if t.spec.kind == TrialNegativeControl {
			t.or = OracleResult{Achieved: false, ObservedState: "negative control (no attack performed)"}
			v.OracleObserved = true
		} else {
			or, err := sc.SuccessOracle(ctx, env)
			t.or = or
			switch {
			case err != nil:
				env.Log.Logf("oracle error: %v", err)
				v.fail(PhaseOracle, "oracle failed: "+err.Error())
			case or.Skipped:
				env.Log.Logf("oracle reported skip: %s", or.SkipReason)
				v.skip(PhaseOracle, or.SkipReason)
			default:
				v.OracleObserved = true
			}
		}
	}
	t.dwell = time.Since(t.attackStart).Seconds()

	// ---- Read defensive actions (cost + time-to-action + adaptive learning) ----
	// This is an independent raw observation, so it is taken even when the attack
	// or oracle failed; an absent or failing observer yields UNOBSERVED cost.
	v.enter(PhaseObserver)
	t.readDefensiveActions(ctx)
}

// readDefensiveActions reads the defender's observable defensive actions when it
// implements DefenseObserver. A missing observer is UNOBSERVED cost, not zero
// actions; a failing observer is a propagated error, also leaving cost
// unobserved. Neither may be turned into a favorable efficiency or ROI number.
//
// A returned value is only accepted as an OBSERVATION once it is self-consistent
// (see validateObservation). An observer that reports a negative count, a
// non-finite or non-positive timestamp, or a timestamp list that disagrees with
// its own count has not measured anything usable, so the cost stays UNOBSERVED
// with the contradiction recorded — and the contradictory timings never reach
// the adaptive learner.
func (t *trialRun) readDefensiveActions(ctx context.Context) {
	obs, ok := t.spec.defender.(DefenseObserver)
	if !ok {
		t.v.ObserverPresent = false
		t.v.note(PhaseObserver, "defender exposes no DefenseObserver: defensive cost and timing are UNOBSERVED, not zero")
		return
	}
	t.v.ObserverPresent = true
	c, at, err := obs.DefensiveActions(ctx, t.env)
	if err != nil {
		t.env.Log.Logf("defensive-actions read error: %v", err)
		t.v.note(PhaseObserver, "defense-observer read failed: "+err.Error()+" (cost and timing UNOBSERVED)")
		return
	}
	if problem := validateObservation(c, at); problem != "" {
		t.env.Log.Logf("defensive-actions read is not a usable observation: %s", problem)
		t.v.note(PhaseObserver, "defense-observer returned an unusable observation: "+problem+" (cost and timing UNOBSERVED)")
		return
	}
	t.v.CostObserved = true
	t.actCount, t.actTimes = c, at
	t.spec.learner.ObserveRotations(at)
}

// validateObservation returns "" when the observer's report can be used as a
// measurement, or the reason it cannot. It is deliberately strict: an
// unusable-but-accepted count becomes a cost denominator and an ROI number.
func validateObservation(count int, atUnix []float64) string {
	if count < 0 {
		return fmt.Sprintf("negative defensive-action count %d", count)
	}
	for i, ts := range atUnix {
		switch {
		case math.IsNaN(ts):
			return fmt.Sprintf("action timestamp %d is NaN", i)
		case math.IsInf(ts, 0):
			return fmt.Sprintf("action timestamp %d is infinite", i)
		case ts <= 0:
			return fmt.Sprintf("action timestamp %d is %v, not a positive unix time", i, ts)
		}
	}
	if len(atUnix) > 0 && len(atUnix) != count {
		return fmt.Sprintf("%d action timestamp(s) contradict the reported count of %d", len(atUnix), count)
	}
	return ""
}

// cleanupParent returns the DETACHED parent context for a trial's cleanup. It is
// detached so the cleanup owed by the phases already entered is still attempted
// after the trial context is cancelled. Each individual step is bounded
// separately (see cleanupStep), so one slow step cannot silently consume the
// budget of the steps that follow it and make them look unresolved.
func (r *Runner) cleanupParent(ctx context.Context) context.Context {
	return context.WithoutCancel(ctx)
}

// cleanup performs, in reverse order, every teardown owed by a phase this trial
// actually entered — including after a partial setup/start failure — and retains
// EVERY attempt, failure and unresolved step. It never touches resources this
// trial did not own.
//
// The bound is enforced on WALL CLOCK, not merely by handing a plugin a context
// with a deadline. A plugin may ignore its context, and env.Close takes none at
// all, so each step is waited on with a timeout: if it does not return in time
// the step is recorded UNRESOLVED, the run is stopped, and the still-running
// call is retained (see Runner.PendingCleanup) rather than abandoned. A late
// return does NOT retroactively make the trial clean.
func (t *trialRun) cleanup(ctx context.Context) {
	parent := t.r.cleanupParent(ctx)

	if t.owedScenarioTeardown {
		t.cleanupStep(parent, "scenario.Teardown", func(c context.Context) error { return t.spec.scenario.Teardown(c, t.env) })
	}
	if t.owedDefenderStop {
		t.cleanupStep(parent, "defender.Stop", func(c context.Context) error { return t.spec.defender.Stop(c, t.env) })
	}
	if t.owedDefenderTeardown {
		t.cleanupStep(parent, "defender.Teardown", func(c context.Context) error { return t.spec.defender.Teardown(c, t.env) })
	}
	if t.closeEnv != nil {
		// env.Close is a context-free callback owned by the cmd wiring. It is
		// bounded here the only way it can be: by waiting on it, not by trusting
		// it to observe a deadline it never receives.
		t.cleanupStep(parent, "env.Close", func(context.Context) error { return t.closeEnv() })
	}

	unfinished := t.v.Cleanup.Unfinished()
	for _, s := range unfinished {
		if s.Unresolved {
			t.v.Cleanup.Unresolved = true
		}
	}
	t.v.Cleanup.Complete = len(unfinished) == 0
	// Verified is only claimed when every owed step is known to have finished
	// cleanly. The cleanup helpers themselves verify absence of owned objects
	// (see Env.CleanupOwned); an error from any of them lands above.
	t.v.Cleanup.Verified = t.v.Cleanup.Complete
	if !t.v.Cleanup.Complete {
		t.v.fail(PhaseCleanup, fmt.Sprintf(
			"%d owed cleanup step(s) did not finish cleanly (%d failed, %d unresolved past the %s per-step bound); trial state is unverified",
			len(unfinished), len(t.v.Cleanup.Failures()), len(unfinished)-len(t.v.Cleanup.Failures()), t.r.opts.CleanupTimeout))
	}
}

// cleanupStep runs one owed cleanup call under its OWN wall-clock bound.
//
// The step is given a context carrying the deadline (so a cooperative plugin can
// observe it) AND is waited on with the same bound (so an uncooperative one —
// including the context-free env.Close callback — cannot outlast it unnoticed).
// A step that does not return in time is recorded UNRESOLVED and the runner
// keeps ownership of the still-running call: the run stops, the caller can drain
// it with Runner.WaitForPendingCleanup, and its late result is retained in the
// run outcome instead of being silently discarded.
func (t *trialRun) cleanupStep(parent context.Context, name string, fn func(context.Context) error) {
	step := CleanupStep{Step: name}
	started := time.Now()
	cctx, cancel := context.WithTimeout(parent, t.r.opts.CleanupTimeout)
	// Buffered so the worker can always deliver its result and exit, even after
	// the bound has elapsed and nobody is waiting yet.
	done := make(chan error, 1)
	go func() {
		defer cancel()
		done <- fn(cctx)
	}()

	timer := time.NewTimer(t.r.opts.CleanupTimeout)
	defer timer.Stop()

	select {
	case err := <-done:
		step.Seconds = time.Since(started).Seconds()
		if err != nil {
			step.Error = err.Error()
			if t.env != nil {
				t.env.Log.Logf("%s error: %v", name, err)
			}
			t.r.mirror("CLEANUP FAILED %s/%s trial %d: %s: %v", t.m.Scenario, t.m.Defender, t.m.Trial, name, err)
		}
	case <-timer.C:
		step.Seconds = time.Since(started).Seconds()
		step.Unresolved = true
		step.Error = ""
		if t.env != nil {
			t.env.Log.Logf("%s did not return within the %s cleanup bound: UNRESOLVED, it may still be running", name, t.r.opts.CleanupTimeout)
		}
		t.r.mirror("CLEANUP UNRESOLVED %s/%s trial %d: %s exceeded the %s bound and may still be running",
			t.m.Scenario, t.m.Defender, t.m.Trial, name, t.r.opts.CleanupTimeout)
		// Ownership is retained: the runner keeps waiting on the abandoned call
		// so its eventual result is recorded rather than lost.
		t.r.retainLateCleanup(t.m, name, started, done)
	}
	t.v.Cleanup.Attempted = append(t.v.Cleanup.Attempted, step)
}

// LateCleanup records a cleanup call that outlived its bound, together with the
// result it eventually produced (if it produced one before the run reported).
type LateCleanup struct {
	Scenario string  `json:"scenario"`
	Defender string  `json:"defender"`
	Trial    int     `json:"trial"`
	Step     string  `json:"step"`
	Seconds  float64 `json:"seconds"`
	Error    string  `json:"error,omitempty"`
	// Returned is false while the call is STILL RUNNING: its resources are still
	// owned by this run and their state is unknown.
	Returned bool `json:"returned"`
}

// retainLateCleanup is called ONLY for a step that outlived its bound. It
// records the unresolved step immediately — so it is visible even if the call
// never returns — and keeps waiting on it so the eventual result is captured
// instead of abandoned. The decision is taken by the waiter, never by the
// worker, so a step that resolved in time is never mistaken for a late one.
//
// A late result NEVER upgrades the trial that already reported: that row was
// written while the state was unknown, and it stays unresolved.
func (r *Runner) retainLateCleanup(m Metric, step string, started time.Time, done <-chan error) {
	r.lateMu.Lock()
	idx := len(r.outcome.LateCleanups)
	r.outcome.LateCleanups = append(r.outcome.LateCleanups, LateCleanup{
		Scenario: m.Scenario, Defender: m.Defender, Trial: m.Trial, Step: step,
		Seconds: time.Since(started).Seconds(), Returned: false,
	})
	r.lateMu.Unlock()

	r.pending.Add(1)
	go func() {
		defer r.pending.Done()
		err := <-done
		r.lateMu.Lock()
		defer r.lateMu.Unlock()
		r.outcome.LateCleanups[idx].Returned = true
		r.outcome.LateCleanups[idx].Seconds = time.Since(started).Seconds()
		if err != nil {
			r.outcome.LateCleanups[idx].Error = err.Error()
		}
	}()
}

// WaitForPendingCleanup blocks until every cleanup call the runner still owns
// has returned, or until the timeout elapses. It returns the number of late
// cleanups recorded. Callers use it to avoid abandoning work that outlived its
// bound; it does NOT make an unresolved trial clean. A non-zero return after the
// timeout means cleanup is still running and its resources are still owned.
func (r *Runner) WaitForPendingCleanup(timeout time.Duration) int {
	drained := make(chan struct{})
	go func() {
		r.pending.Wait()
		close(drained)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
	}
	r.lateMu.Lock()
	defer r.lateMu.Unlock()
	return len(r.outcome.LateCleanups)
}

// finalize stamps the raw observations, resolves the positive control and — only
// for a fully valid, anchored trial — derives the scores. Everything derived is
// computed HERE, after cleanup, so an invalid trial never carries a favorable
// number.
func (t *trialRun) finalize() Metric {
	v, m := t.v, &t.m

	// ---- raw observations are preserved regardless of validity ----
	if t.env != nil {
		m.Commands = mergeCommands(t.env.Log.Commands(), t.ar.Commands)
	}
	m.AttackerDwellSeconds = t.dwell
	m.ObservedState = t.or.ObservedState
	if v.OracleObserved {
		m.OracleAchieved = t.or.Achieved
	}
	if v.CostObserved {
		m.DefensiveActions = t.actCount
		m.TimeToActionSeconds = t.timeToAction()
		// Raw scenario-stamped evidence is lifted whenever an oracle was observed;
		// only DERIVED values below are gated on a scored comparison.
	}
	if v.OracleObserved {
		t.liftOracleEvidence()
	}

	// Resolve the control identity for EVERY row that would need one, so an
	// invalid or unanchored row still records which control it required and what
	// was observed of it.
	usable := t.resolveBaseline(t.spec.kind != TrialNegativeControl)

	switch {
	case v.Status != MeasurementValid:
		// Not a measurement: leave every scoring field at zero and say why.
		m.Skipped = true
		m.SkipReason = v.summary()
		v.Scored = false
		v.UnscoredReason = m.SkipReason
	case t.spec.kind == TrialNegativeControl:
		v.Phase = PhaseComplete
		v.Baseline.Reason = "negative control: no disruption comparison exists"
		v.Scored = false
		v.UnscoredReason = "negative control measures false defensive moves, not disruption"
		if v.CostObserved {
			m.FalseDefensiveActions = t.actCount
			m.EvidenceRetention = 1
			t.env.Log.Logf("negative control result: falseDefensiveActions=%d (expect 0)", t.actCount)
		} else {
			m.FalseDefensiveActions = -1
			t.env.Log.Logf("negative control result: false defensive moves UNOBSERVED (no usable DefenseObserver)")
		}
	default:
		v.Phase = PhaseComplete
		if !usable {
			// A VALID observation with no usable positive control. The raw result
			// is preserved, but nothing is scored — and the compatibility flag is
			// set so an older consumer excludes it rather than reading its zero
			// disruption as a measurement.
			v.Scored = false
			v.UnscoredReason = v.Baseline.Reason
			m.Skipped = true
			m.SkipReason = "UNSCORED(no-usable-control): " + v.Baseline.Reason
			t.env.Log.Logf("trial UNSCORED: %s", v.UnscoredReason)
			break
		}
		v.Scored = true
		m.DisruptionVsOracle = disruption(v.Baseline.OracleAchieved, m.OracleAchieved)
		if v.CostObserved {
			m.SecurityPerCost = securityPerCost(m.DisruptionVsOracle, t.actCount)
			m.EvidenceRetention = evidenceRetention(t.actCount, t.or)
			t.deriveEconomics()
		} else {
			v.note(PhaseComplete, "defensive cost UNOBSERVED: securityPerCost, evidenceRetention, ROI and Schwartau are not derivable")
		}
		t.env.Log.Logf("trial result: oracleAchieved=%v disruption=%.2f dwell=%.1fs timeToAction=%.1fs actions=%d",
			m.OracleAchieved, m.DisruptionVsOracle, m.AttackerDwellSeconds, m.TimeToActionSeconds, m.DefensiveActions)
	}

	if t.env != nil {
		m.Commands = mergeCommands(m.Commands, t.env.Log.Commands())
	}
	return t.m
}

// timeToAction is the first observed defensive action after attack start.
func (t *trialRun) timeToAction() float64 {
	for _, at := range t.actTimes {
		if rel := at - float64(t.attackStart.Unix()); rel >= 0 {
			return rel
		}
	}
	return 0
}

// resolveBaseline records the IDENTITY and OBSERVED result of the positive
// control this comparison needs, and reports whether it is usable. A control
// that errored, abstained or failed its own attack is NOT usable: the comparison
// is invalidated rather than being turned into baseHit=true or a measured zero.
func (t *trialRun) resolveBaseline(required bool) bool {
	b := &t.v.Baseline
	b.Required = required
	b.Trial = t.spec.trial
	b.Kind = t.spec.kind
	b.Defender = t.spec.baselineName
	if !required {
		return false
	}

	if t.spec.isBaseline {
		// The control arm anchors to its own observation for this trial index.
		b.IsSelf = true
		b.Defender = t.m.Defender
		b.Observed = t.v.OracleObserved
		b.Valid = t.v.Status == MeasurementValid && t.v.OracleObserved
		b.OracleAchieved = t.m.OracleAchieved
		b.Usable = b.Valid && b.OracleAchieved
		if !b.Usable {
			b.Reason = fmt.Sprintf("undefended positive control %q at trial %d (%s) is not usable (validMeasurement=%v oracleAchieved=%v): nothing is attributable to defense",
				b.Defender, b.Trial, b.Kind, b.Valid, b.OracleAchieved)
		}
		return b.Usable
	}

	if b.Defender == "" {
		b.Reason = "no undefended positive-control defender is registered: no ordinary comparison can be scored"
		return false
	}
	if t.spec.anchors == nil {
		b.Reason = fmt.Sprintf("no positive-control observations were collected for this run: %s trial %d is unanchored", b.Kind, b.Trial)
		return false
	}
	obs, ok := t.spec.anchors[anchorKey{t.spec.trial, t.spec.kind}]
	if !ok {
		b.Reason = fmt.Sprintf("no VALID %s control was observed on baseline arm %q at trial index %d; the comparison is unanchored",
			b.Kind, b.Defender, b.Trial)
		if t.spec.kind == TrialAdaptive {
			b.Reason += " (the adaptive pass has no paired ordinary baseline and must never borrow one)"
		}
		return false
	}
	b.Defender = obs.defender
	b.Observed = true
	b.Valid = obs.valid
	b.OracleAchieved = obs.oracleAchieved
	b.Usable = obs.valid && obs.oracleAchieved
	if !b.Usable {
		b.Reason = fmt.Sprintf("positive control %q at trial %d (%s) is not usable (valid=%v oracleAchieved=%v)",
			b.Defender, b.Trial, b.Kind, obs.valid, obs.oracleAchieved)
	}
	return b.Usable
}

// liftOracleEvidence copies the RAW split-oracle / trigger / capability / threat-ID
// facts a scenario stamped into OracleResult.Evidence onto the additive metric
// fields. These are observations, so they are preserved for any observed oracle;
// the DERIVED MTD-effect and economics live in deriveEconomics.
func (t *trialRun) liftOracleEvidence() {
	m, ev := &t.m, t.or.Evidence
	get := func(k string) (string, bool) {
		if ev == nil {
			return "", false
		}
		v, ok := ev[k]
		return v, ok
	}
	isTrue := func(k string) bool { v, _ := get(k); return v == "true" }

	if v, ok := get(EvSplitOracle); ok {
		m.SplitOracle = v
	}
	if v, ok := get(EvTriggerAttribution); ok {
		m.TriggerAttribution = v
	}
	if v, ok := get(EvInRequestAchieved); ok {
		m.InRequestAchieved = v == "true"
	}
	if v, ok := get(EvPersistenceAchieved); ok {
		m.PersistenceAchieved = v == "true"
	}
	if v, ok := get(EvCapabilityNote); ok {
		m.CapabilityNote = v
	}
	if isTrue(EvCapabilityPending) {
		m.CapabilityPending = true
	}
	if v, ok := get(EvAtlasIDs); ok && v != "" {
		m.AtlasIDs = splitCSV(v)
	}
	if v, ok := get(EvOwaspIDs); ok && v != "" {
		m.OwaspIDs = splitCSV(v)
	}
	// Attack-reusability replay COUNTS are raw observations (the static-baseline
	// anchoring is filled by the report layer across arms).
	if rs, ok := get(EvReplaySuccess); ok {
		attempts := 0
		if a, ok2 := get(EvReplayAttempts); ok2 {
			attempts, _ = parseInt(a)
		}
		succ, _ := parseInt(rs)
		reuse := ComputeReuse(succ, attempts, 0)
		m.Reuse = &reuse
	}
}

// deriveEconomics computes the values DERIVED from a scored comparison and an
// observed cost: the MEASURED MTD-effect, ROI($) and the Schwartau timing model.
// It is reached only for a valid, anchored, cost-observed trial, so no invalid
// row can ever carry an ROI or efficiency number.
func (t *trialRun) deriveEconomics() {
	m, ev := &t.m, t.or.Evidence
	get := func(k string) (string, bool) {
		if ev == nil {
			return "", false
		}
		v, ok := ev[k]
		return v, ok
	}
	isTrue := func(k string) bool { v, _ := get(k); return v == "true" }

	// MEASURED MTD-effect (never assumed): derived from the in-request +
	// persistence outcomes the scenario stamped.
	if _, split := get(EvSplitOracle); split {
		m.MTDEffect = DeriveMTDEffect(m.InRequestAchieved, isTrue(EvPersistenceDisrupted), isTrue(EvNeutralized))
	}

	// ROI($): from the config knobs + measured disruption + observed action count.
	gpuCount, dphr, ovhd, breach, horizon := t.env.Config.ROIInputs()
	roi := ComputeROI(ROIInputs{GpuCount: gpuCount, DollarsPerGpuHour: dphr, GpuOverheadPercent: ovhd, AvoidedBreachValue: breach, HorizonYears: horizon},
		m.DisruptionVsOracle, t.actCount)
	m.ROI = &roi

	// Schwartau: P = the arm's rotation interval (the time the moving target stays
	// valid for the attacker); D from time-to-action (or absent if no detector); R
	// from the scenario's reaction estimate or time-to-action.
	detectorAbsent := isTrue(EvDetectorAbsent)
	reaction := m.TimeToActionSeconds
	if v, ok := get(EvReactionSeconds); ok {
		if f, err := parseFloat(v); err == nil {
			reaction = f
		}
	}
	// [P-AUDIT measurement-bug fix] Protection time P: the fixed-interval metadata for a periodic arm;
	// but for an EMERGENT-rate arm (PX advertises MeanRotationIntervalSeconds=0 because its rate is a
	// SOLVED decision variable) that ACTUALLY acted, use the OBSERVED time-to-first-rotation. Reporting
	// P=0 wrongly classified PX as a STATIC arm ("the target never moves") — the same fixed-interval
	// assumption that under-credited PX elsewhere. d-nomtd (no actions) correctly stays static (P=0).
	protection := t.spec.defender.Metadata().MeanRotationIntervalSeconds
	if protection <= 0 && t.actCount > 0 && m.TimeToActionSeconds > 0 {
		protection = m.TimeToActionSeconds
	}
	sch := ComputeSchwartau(protection, m.TimeToActionSeconds, reaction, detectorAbsent)
	m.Schwartau = &sch
}

// applyAdaptiveTiming consults the learner and sleeps the planned lull offset so
// the attack lands in the predicted safe window. The sleep is bounded so smoke
// runs stay fast.
//
// EXPERIMENTAL LIMITATION (unchanged by V3-M161): the adaptive pass is only
// comparable to the baseline arm's OWN adaptive pass, and that control has no
// rotation rhythm to learn, so it strikes immediately. A scored adaptive
// comparison therefore contrasts a lull-timed attack against an undefended
// immediate attack — it does not isolate the value of the learned strategy.
func (r *Runner) applyAdaptiveTiming(env *Env, learner *adaptive.Learner) {
	est := learner.EstimatedInterval()
	if est <= 0 {
		env.Log.Logf("adaptive: no learned rotation rhythm yet (observations=%d) — striking immediately", learner.Observations())
		return
	}
	reg := learner.GapRegularity()
	delay := learner.PlanDelaySeconds(0)
	// Bound the actual wall-clock delay so a long interval doesn't stall smoke.
	const maxWait = 8 * time.Second
	wait := time.Duration(delay * float64(time.Second))
	if wait > maxWait {
		wait = maxWait
	}
	env.Log.Logf("adaptive: estInterval=%.1fs regularity=%.2f plannedDelay=%.1fs (waiting %.1fs to strike in predicted lull)", est, reg, delay, wait.Seconds())
	if wait > 0 {
		time.Sleep(wait)
	}
}

func (r *Runner) selectedScenarios() []Scenario {
	all := Scenarios()
	if len(r.opts.ScenarioFilter) == 0 {
		return all
	}
	var out []Scenario
	for _, s := range all {
		if r.opts.ScenarioFilter[s.Metadata().Name] {
			out = append(out, s)
		}
	}
	return out
}

func (r *Runner) selectedDefenders() []Defender {
	all := Defenders()
	if len(r.opts.DefenderFilter) == 0 {
		return all
	}
	var out []Defender
	for _, d := range all {
		if r.opts.DefenderFilter[d.Metadata().Name] {
			out = append(out, d)
		}
	}
	return out
}

// --- pure helper functions (unit-testable) ---

// disruption is the per-trial disruption of an arm vs the undefended control
// OBSERVED at the same trial index and kind: 1.0 if that control achieved the
// oracle but this arm did NOT, else 0.0. Callers must only reach it with a
// control that was actually observed, valid and successful.
func disruption(baselineAchieved, armAchieved bool) float64 {
	if baselineAchieved && !armAchieved {
		return 1.0
	}
	return 0.0
}

// securityPerCost is disruption per OBSERVED defensive action (rotation). With
// zero observed actions, disruption-with-no-cost scores as the disruption itself
// (free disruption is maximally efficient); with actions it is
// disruption/actions. It is only ever called for a scored, cost-observed trial —
// an unobserved cost yields no efficiency number at all.
func securityPerCost(disruptionVal float64, actions int) float64 {
	if actions <= 0 {
		return disruptionVal
	}
	return disruptionVal / float64(actions)
}

// evidenceRetention models the forensic cost of aggressive rotation: each
// defensive action that destroys/replaces the pod erodes retained evidence. An
// oracle that retained explicit evidence keeps a floor. Bounded to [0,1].
func evidenceRetention(actions int, or OracleResult) float64 {
	base := 1.0
	// Each rotation erodes 25% of evidence (pods destroyed -> logs gone).
	base -= 0.25 * float64(actions)
	if base < 0 {
		base = 0
	}
	// If the oracle still captured concrete evidence, retain a floor of 0.5.
	if or.Achieved && len(or.Evidence) > 0 && base < 0.5 {
		base = 0.5
	}
	return base
}

func mergeCommands(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	out := append([]string(nil), a...)
	seen := map[string]bool{}
	for _, c := range out {
		seen[c] = true
	}
	for _, c := range b {
		if !seen[c] {
			out = append(out, c)
			seen[c] = true
		}
	}
	return out
}

// findBaselineDefender returns the defender flagged as the undefended positive
// control (IsNegativeControlBaseline), or nil.
func findBaselineDefender(ds []Defender) Defender {
	for _, d := range ds {
		if d.Metadata().IsNegativeControlBaseline {
			return d
		}
	}
	return nil
}

// containsDefenderName reports whether a defender with the given name is in ds.
func containsDefenderName(ds []Defender, name string) bool {
	for _, d := range ds {
		if d.Metadata().Name == name {
			return true
		}
	}
	return false
}

func baselineName(d Defender) string {
	if d == nil {
		return ""
	}
	return d.Metadata().Name
}

// orderBaselineFirst returns ds with the baseline defender first (so other arms
// can anchor to its per-trial oracle result).
func orderBaselineFirst(ds []Defender, baseline Defender) []Defender {
	if baseline == nil {
		return ds
	}
	out := []Defender{baseline}
	for _, d := range ds {
		if d.Metadata().Name != baseline.Metadata().Name {
			out = append(out, d)
		}
	}
	return out
}

// defenderSkip lets a stub defender (e.g. d-phorvex-slot) signal skip-with-note
// without a custom interface: it checks the SkipReporter optional interface.
func defenderSkip(d Defender) (bool, string) {
	if sr, ok := d.(SkipReporter); ok {
		return sr.SkipReason()
	}
	return false, ""
}

// SkipReporter is the OPTIONAL interface a registered stub defender implements to
// report itself as skipped-with-note (proving the registry composes for a future
// Phorvex arm with ZERO harness changes).
type SkipReporter interface {
	SkipReason() (bool, string)
}

// ensure rand import is used even if adaptive timing is compiled out by a future
// edit; the seeded RNG is the source of all determinism.
var _ = rand.New
