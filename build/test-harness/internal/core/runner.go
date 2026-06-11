package core

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/adaptive"
)

// EnvFactory builds a fresh Env for one trial. The runner is decoupled from how
// clients/loggers are constructed (the cmd wires this); that keeps the runner
// generic and unit-testable with a fake factory.
type EnvFactory func(scenarioName, defenderName string, trial int, seed int64, rawLogPath string) (*Env, func() error, error)

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
}

// NewRunner constructs a runner.
func NewRunner(opts RunnerOptions, factory EnvFactory, metrics *MetricWriter, onMirror func(string)) *Runner {
	if opts.CILevel == 0 {
		opts.CILevel = 0.95
	}
	return &Runner{
		opts:     opts,
		factory:  factory,
		metrics:  metrics,
		onMirror: onMirror,
		learners: map[string]*adaptive.Learner{},
	}
}

func (r *Runner) mirror(format string, args ...any) {
	if r.onMirror != nil {
		r.onMirror(fmt.Sprintf(format, args...))
	}
}

// Run executes the whole matrix and returns the written metrics.
func (r *Runner) Run(ctx context.Context) ([]Metric, error) {
	scenarios := r.selectedScenarios()
	defenders := r.selectedDefenders()
	if len(scenarios) == 0 {
		return nil, fmt.Errorf("runner: no scenarios registered/selected")
	}
	if len(defenders) == 0 {
		return nil, fmt.Errorf("runner: no defenders registered/selected")
	}

	// Identify the positive-control baseline (undefended) so disruption can be
	// anchored. Search the FULL registry, not just the selected arms: the baseline
	// MUST run to anchor disruption even when a DefenderFilter excludes it. If it is
	// not among the selected arms it is FORCE-INCLUDED as an anchor-only arm
	// (positive trials only, tagged so the report omits it from the requested view).
	baseline := findBaselineDefender(Defenders())
	baselineSelected := baseline != nil && containsDefenderName(defenders, baseline.Metadata().Name)
	if baseline != nil && !baselineSelected {
		r.mirror("baseline arm %q force-included (ANCHOR-ONLY) so disruption anchors despite DefenderFilter", baseline.Metadata().Name)
	}

	for _, sc := range scenarios {
		meta := sc.Metadata()
		// Baseline oracle outcome per trial, keyed by trial — populated when the
		// baseline arm runs, then consumed to anchor every other arm.
		baselineAchieved := map[int]bool{}

		// Run the baseline FIRST so other arms can anchor to it. orderBaselineFirst
		// PREPENDS the baseline even when it is not in `defenders` (the force-include).
		ordered := orderBaselineFirst(defenders, baseline)

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

			for trial := 0; trial < r.opts.TrialsPerArm; trial++ {
				m := r.runOneTrial(ctx, sc, d, trial, false, false, learner, baselineAchieved, isBaseline, anchorOnly)
				if err := r.metrics.Write(m); err != nil {
					return nil, err
				}
			}

			// An anchor-only baseline only needs its positive trials (to establish
			// the anchor); skip its negative-control + adaptive passes (cost the
			// DefenderFilter intentionally excluded).
			if r.opts.RunNegativeControl && !anchorOnly {
				m := r.runOneTrial(ctx, sc, d, r.opts.TrialsPerArm, true, false, learner, baselineAchieved, false, false)
				if err := r.metrics.Write(m); err != nil {
					return nil, err
				}
			}

			// Adaptive attacker arm: an extra pass that times the kill-chain into
			// the learned lull.
			if r.opts.AdaptiveArm && !anchorOnly {
				m := r.runOneTrial(ctx, sc, d, r.opts.TrialsPerArm+1, false, true, learner, baselineAchieved, false, false)
				if err := r.metrics.Write(m); err != nil {
					return nil, err
				}
			}
		}
	}
	return r.metrics.All(), nil
}

// runOneTrial is the canonical per-trial path. It is the SAME loop for smoke (2)
// and the full (>=20) benchmark — only TrialsPerArm differs.
func (r *Runner) runOneTrial(ctx context.Context, sc Scenario, d Defender, trial int, negativeControl, adaptiveArm bool, learner *adaptive.Learner, baselineAchieved map[int]bool, isBaseline, anchorOnly bool) Metric {
	smeta := sc.Metadata()
	dmeta := d.Metadata()
	seed := TrialSeed(r.opts.MasterSeed, smeta.Name, dmeta.Name, trial)

	rawLog := filepath.Join(r.opts.OutDir, "raw", fmt.Sprintf("%s_%s_t%d.log", smeta.Name, dmeta.Name, trial))
	env, closeEnv, err := r.factory(smeta.Name, dmeta.Name, trial, seed, rawLog)

	base := Metric{
		Scenario:              smeta.Name,
		Defender:              dmeta.Name,
		Trial:                 trial,
		Seed:                  seed,
		RawLogPath:            rawLog,
		R6Tag:                 smeta.R6ResponseTag,
		Category:              smeta.Category,
		NegativeControl:       negativeControl,
		AnchorOnly:            anchorOnly,
		FalseDefensiveActions: -1,
	}
	if err != nil {
		base.Skipped = true
		base.SkipReason = "env factory failed: " + err.Error()
		return base
	}
	defer func() {
		if closeEnv != nil {
			_ = closeEnv()
		}
	}()

	r.mirror("=== scenario=%s defender=%s trial=%d seed=%d negCtl=%v adaptive=%v ===", smeta.Name, dmeta.Name, trial, seed, negativeControl, adaptiveArm)
	env.Log.Logf("trial start: scenario=%s defender=%s trial=%d seed=%d negativeControl=%v adaptive=%v", smeta.Name, dmeta.Name, trial, seed, negativeControl, adaptiveArm)

	// Capability gate — skip-with-note (never a failure).
	if miss := env.Caps.Missing(smeta.CapabilityRequirements); len(miss) > 0 {
		reason := fmt.Sprintf("cluster lacks required capabilities %v", miss)
		env.Log.Logf("SKIP: %s", reason)
		base.Skipped = true
		base.SkipReason = reason
		base.Commands = env.Log.Commands()
		return base
	}

	// ---- Defender Setup + Start ----
	if err := d.Setup(ctx, env); err != nil {
		env.Log.Logf("defender Setup error: %v", err)
		base.Skipped = true
		base.SkipReason = "defender setup failed: " + err.Error()
		base.Commands = env.Log.Commands()
		_ = d.Teardown(ctx, env)
		return base
	}
	// If the defender reported itself a skipped stub via a sentinel, honor it.
	if skip, reason := defenderSkip(d); skip {
		env.Log.Logf("defender %s is a registered stub: %s", dmeta.Name, reason)
		base.Skipped = true
		base.SkipReason = reason
		_ = d.Stop(ctx, env)
		_ = d.Teardown(ctx, env)
		base.Commands = env.Log.Commands()
		return base
	}

	// ---- Scenario Setup ----
	if err := sc.Setup(ctx, env); err != nil {
		env.Log.Logf("scenario Setup error: %v", err)
		base.Skipped = true
		base.SkipReason = "scenario setup failed: " + err.Error()
		_ = sc.Teardown(ctx, env)
		_ = d.Stop(ctx, env)
		_ = d.Teardown(ctx, env)
		base.Commands = env.Log.Commands()
		return base
	}

	if err := d.Start(ctx, env); err != nil {
		env.Log.Logf("defender Start error: %v", err)
	}

	attackStart := time.Now()

	// ---- Adaptive timing (if adaptive arm) ----
	if adaptiveArm {
		r.applyAdaptiveTiming(env, learner)
	}

	// ---- Execute attack (or no-op for the negative control) ----
	var ar AttackResult
	if negativeControl {
		env.Log.Logf("NEGATIVE CONTROL: skipping attack Execute (no-op) — measuring false defensive moves")
		ar = AttackResult{Stages: []string{"no-op (negative control)"}}
	} else {
		ar, err = sc.Execute(ctx, env)
		if err != nil {
			env.Log.Logf("scenario Execute error: %v", err)
		}
	}

	// ---- Oracle ----
	var or OracleResult
	if negativeControl {
		// The oracle is not the point for the negative control; we record the
		// defensive-action count instead.
		or = OracleResult{Achieved: false, ObservedState: "negative control (no attack performed)"}
	} else {
		or, err = sc.SuccessOracle(ctx, env)
		if err != nil {
			env.Log.Logf("oracle error: %v", err)
		}
	}
	dwell := time.Since(attackStart).Seconds()

	// ---- Read defensive actions (cost + time-to-action + adaptive learning) ----
	actCount, actTimes := r.readDefensiveActions(ctx, env, d)
	learner.ObserveRotations(actTimes)

	timeToAction := 0.0
	for _, t := range actTimes {
		rel := t - float64(attackStart.Unix())
		if rel >= 0 {
			timeToAction = rel
			break
		}
	}

	// ---- Build the metric ----
	m := base
	m.Commands = mergeCommands(env.Log.Commands(), ar.Commands)
	m.DefensiveActions = actCount
	m.TimeToActionSeconds = timeToAction
	m.AttackerDwellSeconds = dwell
	m.ObservedState = or.ObservedState
	if ar.Skipped || or.Skipped {
		m.Skipped = true
		if ar.SkipReason != "" {
			m.SkipReason = ar.SkipReason
		} else {
			m.SkipReason = or.SkipReason
		}
	}

	if negativeControl {
		// Negative control: 0 expected disruption, count false defensive moves.
		m.FalseDefensiveActions = actCount
		m.OracleAchieved = false
		m.DisruptionVsOracle = 0
		m.SecurityPerCost = 0
		m.EvidenceRetention = 1
		env.Log.Logf("negative control result: falseDefensiveActions=%d (expect 0)", actCount)
	} else {
		m.OracleAchieved = or.Achieved
		if isBaseline {
			baselineAchieved[trial] = or.Achieved
		}
		// Anchor disruption to the undefended baseline for THIS trial.
		baseHit, haveBase := baselineAchieved[trial]
		if !haveBase {
			// No baseline anchor (baseline not run / different trial id): treat the
			// undefended expectation as oracle-achievable (positive control intent).
			baseHit = true
		}
		m.DisruptionVsOracle = disruption(baseHit, or.Achieved)
		m.SecurityPerCost = securityPerCost(m.DisruptionVsOracle, actCount)
		m.EvidenceRetention = evidenceRetention(actCount, or)
	}

	// ---- ADDITIVE Pass-B extension: lift split-oracle/MTD-effect/trigger evidence
	// into the metric, and compute ROI($)/Schwartau/reuse from the config knobs +
	// the arm's rotation interval. This is purely additive — a scenario that stamps
	// no evidence yields zero-valued Pass-B fields and the row is byte-compatible
	// with Pass A. ----
	if !negativeControl {
		r.applyPassBExtension(&m, or, dmeta, env, actCount, timeToAction)
	}

	// ---- Teardown (full, idempotent) ----
	if err := sc.Teardown(ctx, env); err != nil {
		env.Log.Logf("scenario Teardown error: %v", err)
	}
	if err := d.Stop(ctx, env); err != nil {
		env.Log.Logf("defender Stop error: %v", err)
	}
	if err := d.Teardown(ctx, env); err != nil {
		env.Log.Logf("defender Teardown error: %v", err)
	}
	m.Commands = mergeCommands(m.Commands, env.Log.Commands())
	env.Log.Logf("trial result: oracleAchieved=%v disruption=%.2f dwell=%.1fs timeToAction=%.1fs actions=%d", m.OracleAchieved, m.DisruptionVsOracle, m.AttackerDwellSeconds, m.TimeToActionSeconds, m.DefensiveActions)
	return m
}

// applyPassBExtension lifts the split-oracle / MTD-effect / trigger evidence a
// Pass-B scenario stamped into OracleResult.Evidence onto the ADDITIVE metric
// fields, then computes the ROI($), Schwartau and attack-reusability views from
// the config knobs and the arm's rotation interval. It is a no-op (zero fields)
// for a Pass-A scenario that stamps none of these keys.
func (r *Runner) applyPassBExtension(m *Metric, or OracleResult, dmeta DefenderMeta, env *Env, actCount int, timeToAction float64) {
	ev := or.Evidence
	get := func(k string) (string, bool) {
		if ev == nil {
			return "", false
		}
		v, ok := ev[k]
		return v, ok
	}
	isTrue := func(k string) bool { v, _ := get(k); return v == "true" }

	hasAny := false
	if v, ok := get(EvSplitOracle); ok {
		m.SplitOracle = v
		hasAny = true
	}
	if v, ok := get(EvTriggerAttribution); ok {
		m.TriggerAttribution = v
		hasAny = true
	}
	if v, ok := get(EvInRequestAchieved); ok {
		m.InRequestAchieved = v == "true"
	}
	if v, ok := get(EvPersistenceAchieved); ok {
		m.PersistenceAchieved = v == "true"
	}
	if v, ok := get(EvCapabilityNote); ok {
		m.CapabilityNote = v
		hasAny = true
	}
	if isTrue(EvCapabilityPending) {
		m.CapabilityPending = true
		hasAny = true
	}
	if v, ok := get(EvAtlasIDs); ok && v != "" {
		m.AtlasIDs = splitCSV(v)
		hasAny = true
	}
	if v, ok := get(EvOwaspIDs); ok && v != "" {
		m.OwaspIDs = splitCSV(v)
		hasAny = true
	}

	// MEASURED MTD-effect (never assumed): derived from the in-request + persistence
	// outcomes the scenario stamped.
	if _, split := get(EvSplitOracle); split {
		neutralized := isTrue(EvNeutralized)
		persistenceDisrupted := isTrue(EvPersistenceDisrupted)
		m.MTDEffect = DeriveMTDEffect(m.InRequestAchieved, persistenceDisrupted, neutralized)
		hasAny = true
	}

	// ROI($): from the config knobs + measured disruption + defensive-action count.
	gpuCount, dphr, ovhd, breach, horizon := env.Config.ROIInputs()
	in := ROIInputs{GpuCount: gpuCount, DollarsPerGpuHour: dphr, GpuOverheadPercent: ovhd, AvoidedBreachValue: breach, HorizonYears: horizon}
	roi := ComputeROI(in, m.DisruptionVsOracle, actCount)
	m.ROI = &roi

	// Schwartau: P = the arm's rotation interval (the time the moving target stays
	// valid for the attacker); D from time-to-action (or absent if no detector); R
	// from the scenario's reaction estimate or time-to-action.
	detectorAbsent := isTrue(EvDetectorAbsent)
	reaction := timeToAction
	if v, ok := get(EvReactionSeconds); ok {
		if f, err := parseFloat(v); err == nil {
			reaction = f
		}
	}
	detection := timeToAction
	// [P-AUDIT measurement-bug fix] Protection time P: the fixed-interval metadata for a periodic arm;
	// but for an EMERGENT-rate arm (PX advertises MeanRotationIntervalSeconds=0 because its rate is a
	// SOLVED decision variable) that ACTUALLY acted, use the OBSERVED time-to-first-rotation. Reporting
	// P=0 wrongly classified PX as a STATIC arm ("the target never moves") — the same fixed-interval
	// assumption that under-credited PX elsewhere. d-nomtd (no actions) correctly stays static (P=0).
	protection := dmeta.MeanRotationIntervalSeconds
	if protection <= 0 && actCount > 0 && timeToAction > 0 {
		protection = timeToAction
	}
	sch := ComputeSchwartau(protection, detection, reaction, detectorAbsent)
	m.Schwartau = &sch

	// Attack-reusability: replay-success counts the scenario stamped (static
	// baseline anchoring is filled by the report layer across arms).
	if rs, ok := get(EvReplaySuccess); ok {
		attempts := 0
		if a, ok2 := get(EvReplayAttempts); ok2 {
			attempts, _ = parseInt(a)
		}
		succ, _ := parseInt(rs)
		reuse := ComputeReuse(succ, attempts, 0)
		m.Reuse = &reuse
		hasAny = true
	}

	_ = hasAny
}

// applyAdaptiveTiming consults the learner and sleeps the planned lull offset so
// the attack lands in the predicted safe window. The sleep is bounded so smoke
// runs stay fast.
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

// readDefensiveActions reads a defender's observable defensive actions if it
// implements DefenseObserver; otherwise returns (0, nil).
func (r *Runner) readDefensiveActions(ctx context.Context, env *Env, d Defender) (int, []float64) {
	obs, ok := d.(DefenseObserver)
	if !ok {
		return 0, nil
	}
	c, at, err := obs.DefensiveActions(ctx, env)
	if err != nil {
		env.Log.Logf("defensive-actions read error: %v", err)
		return 0, nil
	}
	return c, at
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

// disruption is the per-trial disruption of an arm vs the undefended baseline:
// 1.0 if the baseline achieved the oracle but this arm did NOT, else 0.0.
func disruption(baselineAchieved, armAchieved bool) float64 {
	if baselineAchieved && !armAchieved {
		return 1.0
	}
	return 0.0
}

// securityPerCost is disruption per defensive action (rotation). With zero
// actions, disruption-with-no-cost scores as the disruption itself (free
// disruption is maximally efficient); with actions it is disruption/actions.
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
