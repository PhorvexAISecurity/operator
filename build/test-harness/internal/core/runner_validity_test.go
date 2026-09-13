package core

// runner_validity_test.go — PERMANENT regressions for the measurement-validity
// contract (V3-M161). Every case drives the REAL Runner.Run through the REAL
// MetricWriter; only the scenario/defender plugins and the Env factory are local
// deterministic fixtures, which are the harness's genuine extension points.
//
// The assertions prove EFFECTS (what is scored, what is derived, what cleanup
// ran, what the next trial is allowed to do), not merely the presence of a tag.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

// ------------------------------------------------------------------ fixtures

// vScenario is a phase-programmable scenario. Faults are keyed off the DEFENDER
// NAME and/or TRIAL INDEX so one registered plugin can be a clean positive
// control on the baseline arm and a broken arm elsewhere.
type vScenario struct {
	name string
	// failOn selects the arm that experiences the fault ("" = every arm).
	failOn      string
	setupErr    bool
	execErr     bool
	execSkip    bool
	oracleErr   bool
	oracleSkip  bool
	teardownErr bool
	caps        []Capability
	// oracleFalseOn / oracleFalseTrial make the attack genuinely NOT achieve its
	// oracle (a real, fully observed defensive disruption).
	oracleFalseOn    string
	oracleFalseTrial int
	// evidence is stamped into every successful OracleResult.
	evidence map[string]string

	mu        sync.Mutex
	setups    int
	executes  int
	oracles   int
	teardowns int
}

func (s *vScenario) Metadata() ScenarioMeta {
	return ScenarioMeta{Name: s.name, Category: CategoryClassicChain, R6ResponseTag: R6Partial, CapabilityRequirements: s.caps}
}

func (s *vScenario) hits(env *Env) bool { return s.failOn == "" || env.DefenderName == s.failOn }

func (s *vScenario) Setup(_ context.Context, env *Env) error {
	s.mu.Lock()
	s.setups++
	s.mu.Unlock()
	if s.setupErr && s.hits(env) {
		return errors.New("scenario setup boom")
	}
	return nil
}

func (s *vScenario) Execute(_ context.Context, env *Env) (AttackResult, error) {
	s.mu.Lock()
	s.executes++
	s.mu.Unlock()
	if s.hits(env) {
		if s.execErr {
			return AttackResult{}, errors.New("attack stimulus transport failed")
		}
		if s.execSkip {
			return AttackResult{Skipped: true, SkipReason: "scenario reports this workload is unavailable here"}, nil
		}
	}
	env.Log.Command("v-attack-stage-1")
	return AttackResult{Stages: []string{"staged"}, Commands: []string{"v-attack-stage-1"}}, nil
}

func (s *vScenario) SuccessOracle(_ context.Context, env *Env) (OracleResult, error) {
	s.mu.Lock()
	s.oracles++
	s.mu.Unlock()
	if s.hits(env) {
		if s.oracleErr {
			return OracleResult{}, errors.New("oracle transport unavailable")
		}
		if s.oracleSkip {
			return OracleResult{Skipped: true, SkipReason: "oracle cannot be evaluated on this cluster"}, nil
		}
	}
	achieved := true
	if s.oracleFalseOn != "" && env.DefenderName == s.oracleFalseOn {
		achieved = false
	}
	if s.oracleFalseTrial >= 0 && env.Trial == s.oracleFalseTrial {
		achieved = false
	}
	ev := map[string]string{"observed": "yes"}
	for k, v := range s.evidence {
		ev[k] = v
	}
	return OracleResult{Achieved: achieved, ObservedState: "measured", Evidence: ev}, nil
}

func (s *vScenario) Teardown(_ context.Context, env *Env) error {
	s.mu.Lock()
	s.teardowns++
	s.mu.Unlock()
	if s.teardownErr && s.hits(env) {
		return errors.New("cleanup failed: foothold pod still present")
	}
	return nil
}

func (s *vScenario) counts() (setups, executes, oracles, teardowns int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setups, s.executes, s.oracles, s.teardowns
}

// vDefender is a REACTIVE defender: it reports its actions only when the attack
// actually issued a command, so a no-attack negative control observes a genuine
// measured zero.
type vDefender struct {
	name        string
	baseline    bool
	interval    float64
	actions     []float64
	setupErr    bool
	startErr    bool
	stopErr     bool
	teardownErr bool
	observerErr bool
	// noObserver omits the DefenseObserver capability entirely.
	noObserver bool
	stubReason string

	mu        sync.Mutex
	stops     int
	teardowns int
	starts    int
}

func (d *vDefender) Metadata() DefenderMeta {
	return DefenderMeta{Name: d.name, IsNegativeControlBaseline: d.baseline, MeanRotationIntervalSeconds: d.interval}
}
func (d *vDefender) Setup(context.Context, *Env) error {
	if d.setupErr {
		return errors.New("defender setup boom")
	}
	return nil
}
func (d *vDefender) Start(context.Context, *Env) error {
	d.mu.Lock()
	d.starts++
	d.mu.Unlock()
	if d.startErr {
		return errors.New("defender failed to arm")
	}
	return nil
}
func (d *vDefender) Stop(context.Context, *Env) error {
	d.mu.Lock()
	d.stops++
	d.mu.Unlock()
	if d.stopErr {
		return errors.New("defender stop failed")
	}
	return nil
}
func (d *vDefender) Teardown(context.Context, *Env) error {
	d.mu.Lock()
	d.teardowns++
	d.mu.Unlock()
	if d.teardownErr {
		return errors.New("defender teardown failed")
	}
	return nil
}
func (d *vDefender) counts() (starts, stops, teardowns int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.starts, d.stops, d.teardowns
}

// vObserverDefender adds the optional DefenseObserver capability.
type vObserverDefender struct{ *vDefender }

func (d vObserverDefender) DefensiveActions(_ context.Context, env *Env) (int, []float64, error) {
	if d.observerErr {
		return 0, nil, errors.New("defensive-actions read failed")
	}
	if len(env.Log.Commands()) == 0 {
		return 0, nil, nil // nothing attacked: a genuinely measured zero
	}
	return len(d.actions), d.actions, nil
}

// vStub reports itself a registered stub arm.
type vStub struct{ *vDefender }

func (d vStub) SkipReason() (bool, string) { return true, d.stubReason }

// register wraps a *vDefender in the right optional interfaces and registers it.
func register(d *vDefender) *vDefender {
	switch {
	case d.stubReason != "":
		RegisterDefender(vStub{d})
	case d.noObserver:
		RegisterDefender(d)
	default:
		RegisterDefender(vObserverDefender{d})
	}
	return d
}

type vLogger struct {
	mu   sync.Mutex
	cmds []string
}

func (l *vLogger) Logf(string, ...any) {}
func (l *vLogger) Command(c string) {
	l.mu.Lock()
	l.cmds = append(l.cmds, c)
	l.mu.Unlock()
}
func (l *vLogger) Commands() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.cmds...)
}
func (l *vLogger) RawLogPath() string { return "" }

type vHarness struct {
	t       *testing.T
	writer  *MetricWriter
	runner  *Runner
	closes  int
	closeMu sync.Mutex
	// closeErr makes the per-trial environment closer fail.
	closeErr bool
	// factoryErr makes the Env factory fail.
	factoryErr bool
	caps       Capabilities
}

func newHarness(t *testing.T, opts RunnerOptions) *vHarness {
	t.Helper()
	resetRegistriesForTest()
	t.Cleanup(resetRegistriesForTest)
	dir := t.TempDir()
	mw, err := NewMetricWriter(filepath.Join(dir, "metrics.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mw.Close() })
	h := &vHarness{t: t, writer: mw}
	opts.OutDir = dir
	if opts.CleanupTimeout == 0 {
		opts.CleanupTimeout = 5 * time.Second
	}
	h.runner = NewRunner(opts, h.factory, mw, nil)
	return h
}

func (h *vHarness) factory(scenario, defender string, trial int, _ int64, _ string) (*Env, func() error, error) {
	if h.factoryErr {
		return nil, nil, errors.New("cannot build trial environment")
	}
	env := &Env{
		Log:          &vLogger{},
		Trial:        trial,
		ScenarioName: scenario,
		DefenderName: defender,
		Caps:         h.caps,
		Config:       config.WithDollarDefaults(config.TargetConfig{}),
	}
	closer := func() error {
		h.closeMu.Lock()
		h.closes++
		h.closeMu.Unlock()
		if h.closeErr {
			return errors.New("environment close failed")
		}
		return nil
	}
	return env, closer, nil
}

func (h *vHarness) closeCount() int {
	h.closeMu.Lock()
	defer h.closeMu.Unlock()
	return h.closes
}

func row(t *testing.T, ms []Metric, defender string, trial int) Metric {
	t.Helper()
	for _, m := range ms {
		if m.Defender == defender && m.Trial == trial {
			return m
		}
	}
	t.Fatalf("no metric row for defender=%q trial=%d in %d rows", defender, trial, len(ms))
	return Metric{}
}

func mustNotScore(t *testing.T, m Metric, wantStatus MeasurementStatus, wantPhase TrialPhase) {
	t.Helper()
	v := m.MeasurementState()
	if v.Status != wantStatus {
		t.Errorf("status = %q, want %q (reasons: %v)", v.Status, wantStatus, v.Reasons)
	}
	if wantPhase != "" && v.Phase != wantPhase {
		t.Errorf("phase = %q, want %q", v.Phase, wantPhase)
	}
	if v.Scored {
		t.Errorf("row was SCORED; a non-measurement must never be scored")
	}
	if m.DisruptionVsOracle != 0 {
		t.Errorf("disruption = %v, want 0 (nothing was measured)", m.DisruptionVsOracle)
	}
	if m.SecurityPerCost != 0 {
		t.Errorf("securityPerCost = %v, want 0 (nothing was measured)", m.SecurityPerCost)
	}
	if m.ROI != nil {
		t.Errorf("ROI derived for a non-measurement: %+v", *m.ROI)
	}
	if m.Schwartau != nil {
		t.Errorf("Schwartau derived for a non-measurement: %+v", *m.Schwartau)
	}
	if !m.Skipped {
		t.Errorf("legacy Skipped flag not set; an older consumer would score this row")
	}
	if m.SkipReason == "" {
		t.Errorf("no human-readable reason recorded")
	}
	if len(v.Reasons) == 0 {
		t.Errorf("no propagated reason retained in the validity block")
	}
}

// ------------------------------------------------------------- phase failures

func TestValidityPhaseFailuresAreInvalidNeverDefense(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*vScenario, *vDefender, *vHarness)
		status    MeasurementStatus
		phase     TrialPhase
		wantSetup int // scenario Setup calls expected on the broken arm's trial
	}{
		{name: "env-factory", mutate: func(_ *vScenario, _ *vDefender, h *vHarness) { h.factoryErr = true }, status: MeasurementInvalid, phase: PhaseEnvFactory},
		{name: "defender-setup", mutate: func(_ *vScenario, d *vDefender, _ *vHarness) { d.setupErr = true }, status: MeasurementInvalid, phase: PhaseDefenderSetup},
		{name: "defender-stub", mutate: func(_ *vScenario, d *vDefender, _ *vHarness) {
			d.stubReason = "registered stub arm: no defense implemented"
		}, status: MeasurementSkipped, phase: PhaseDefenderSetup},
		{name: "scenario-setup", mutate: func(s *vScenario, _ *vDefender, _ *vHarness) { s.setupErr = true }, status: MeasurementInvalid, phase: PhaseScenarioSetup},
		{name: "defender-start", mutate: func(_ *vScenario, d *vDefender, _ *vHarness) { d.startErr = true }, status: MeasurementInvalid, phase: PhaseDefenderStart},
		{name: "attack-execute", mutate: func(s *vScenario, _ *vDefender, _ *vHarness) { s.execErr = true }, status: MeasurementInvalid, phase: PhaseAttackExecute},
		{name: "attack-reported-skip", mutate: func(s *vScenario, _ *vDefender, _ *vHarness) { s.execSkip = true }, status: MeasurementSkipped, phase: PhaseAttackExecute},
		{name: "oracle-error", mutate: func(s *vScenario, _ *vDefender, _ *vHarness) { s.oracleErr = true }, status: MeasurementInvalid, phase: PhaseOracle},
		{name: "oracle-reported-skip", mutate: func(s *vScenario, _ *vDefender, _ *vHarness) { s.oracleSkip = true }, status: MeasurementSkipped, phase: PhaseOracle},
		{name: "capability-gate", mutate: func(s *vScenario, _ *vDefender, _ *vHarness) { s.caps = []Capability{CapGPU} }, status: MeasurementSkipped, phase: PhaseCapabilityGate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, RunnerOptions{TrialsPerArm: 1})
			sc := &vScenario{name: "v-scn", failOn: "d-broken", oracleFalseTrial: -1}
			base := register(&vDefender{name: "d-base", baseline: true})
			broken := &vDefender{name: "d-broken"}
			_ = base
			tc.mutate(sc, broken, h)
			register(broken)
			RegisterScenario(sc)

			metrics, err := h.runner.Run(context.Background())
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			// The capability gate and the env-factory fault hit EVERY arm.
			if tc.name != "capability-gate" && tc.name != "env-factory" {
				b := row(t, metrics, "d-base", 0)
				if !b.IsScored() || !b.OracleAchieved {
					t.Fatalf("fixture relevance: the undefended control must be a scored, achieved observation; got %+v", b.MeasurementState())
				}
			}
			m := row(t, metrics, "d-broken", 0)
			mustNotScore(t, m, tc.status, tc.phase)
		})
	}
}

// A failed attack stimulus must not run an oracle at all: an oracle evaluated
// after a stimulus that never landed measures the absence of an attack.
func TestValidityExecuteErrorSkipsTheOracleEntirely(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1, DefenderFilter: map[string]bool{"d-broken": true}})
	sc := &vScenario{name: "v-scn", execErr: true, oracleFalseTrial: -1}
	register(&vDefender{name: "d-base", baseline: true})
	register(&vDefender{name: "d-broken"})
	RegisterScenario(sc)

	if _, err := h.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	_, executes, oracles, _ := sc.counts()
	if executes == 0 {
		t.Fatalf("fixture relevance: Execute never ran")
	}
	if oracles != 0 {
		t.Errorf("SuccessOracle ran %d time(s) after a failed stimulus; want 0", oracles)
	}
}

// ------------------------------------------------------------ control anchors

func TestValidityScoresOnlyAgainstAnObservedUsableControl(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*vScenario, *vDefender)
		noBaseline bool
		wantScored bool
		wantUsable bool
	}{
		{name: "valid-control", mutate: func(*vScenario, *vDefender) {}, wantScored: true, wantUsable: true},
		{name: "control-oracle-error", mutate: func(s *vScenario, b *vDefender) { s.failOn = b.name; s.oracleErr = true }},
		{name: "control-skipped", mutate: func(s *vScenario, b *vDefender) { s.failOn = b.name; s.oracleSkip = true }},
		{name: "control-attack-failed", mutate: func(s *vScenario, b *vDefender) { s.oracleFalseOn = b.name }},
		{name: "control-setup-failed", mutate: func(s *vScenario, b *vDefender) { s.failOn = b.name; s.setupErr = true }},
		{name: "no-control-registered", noBaseline: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, RunnerOptions{TrialsPerArm: 1})
			sc := &vScenario{name: "v-scn", oracleFalseOn: "d-arm", oracleFalseTrial: -1}
			base := &vDefender{name: "d-base", baseline: !tc.noBaseline}
			if tc.mutate != nil {
				tc.mutate(sc, base)
			}
			register(base)
			register(&vDefender{name: "d-arm", interval: 6, actions: []float64{1, 2}})
			RegisterScenario(sc)

			metrics, err := h.runner.Run(context.Background())
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			m := row(t, metrics, "d-arm", 0)
			v := m.MeasurementState()
			if v.Status != MeasurementValid {
				t.Fatalf("the ARM's own measurement must stay valid; got %q %v", v.Status, v.Reasons)
			}
			if v.Scored != tc.wantScored {
				t.Errorf("scored = %v, want %v (reason %q)", v.Scored, tc.wantScored, v.UnscoredReason)
			}
			if v.Baseline.Usable != tc.wantUsable {
				t.Errorf("baseline.usable = %v, want %v", v.Baseline.Usable, tc.wantUsable)
			}
			if tc.wantScored {
				if m.DisruptionVsOracle != 1 {
					t.Errorf("a genuine observed disruption must score 1, got %v", m.DisruptionVsOracle)
				}
				if v.Baseline.Defender != "d-base" || !v.Baseline.Observed {
					t.Errorf("baseline identity not stored: %+v", v.Baseline)
				}
				return
			}
			// Unscored: never invented as a defense, and always explained.
			if m.DisruptionVsOracle != 0 {
				t.Errorf("unanchored comparison scored disruption=%v; want 0", m.DisruptionVsOracle)
			}
			if m.ROI != nil {
				t.Errorf("unanchored comparison derived an ROI: %+v", *m.ROI)
			}
			if v.UnscoredReason == "" || v.Baseline.Reason == "" {
				t.Errorf("no missing-control reason recorded: %+v", v)
			}
			if !m.Skipped {
				t.Errorf("unanchored row not marked unscored for legacy consumers")
			}
			// The raw attack observation survives.
			if !v.OracleObserved || m.ObservedState == "" {
				t.Errorf("raw attack observation was discarded: observed=%v state=%q", v.OracleObserved, m.ObservedState)
			}
		})
	}
}

// The undefended control's own row is self-anchored: it never claims disruption
// against itself, and when its own attack fails it is not a usable control.
func TestValidityControlArmIsSelfAnchored(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 2})
	// The undefended attack fails on trial 1 only.
	RegisterScenario(&vScenario{name: "v-scn", oracleFalseTrial: 1})
	register(&vDefender{name: "d-base", baseline: true})
	metrics, err := h.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	good := row(t, metrics, "d-base", 0)
	if !good.IsScored() || good.DisruptionVsOracle != 0 {
		t.Errorf("undefended control trial 0: scored=%v disruption=%v; want scored with 0 disruption", good.IsScored(), good.DisruptionVsOracle)
	}
	if !good.MeasurementState().Baseline.IsSelf {
		t.Errorf("control row is not marked self-anchored")
	}
	bad := row(t, metrics, "d-base", 1)
	if bad.IsScored() {
		t.Errorf("an undefended arm whose own attack failed must not be a scored comparison")
	}
	if bad.DisruptionVsOracle != 0 {
		t.Errorf("undefended arm credited disruption=%v against an invented control", bad.DisruptionVsOracle)
	}
	if !bad.OracleAchieved && bad.MeasurementState().OracleObserved != true {
		t.Errorf("the failed attack must remain an OBSERVED raw result")
	}
}

// ---------------------------------------------------------------- adaptive

func TestValidityAdaptivePassNeverBorrowsAnOrdinaryBaseline(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1, AdaptiveArm: true,
		// The DefenderFilter excludes the baseline, so it is force-included as an
		// ANCHOR-ONLY arm and runs no adaptive pass at all.
		DefenderFilter: map[string]bool{"d-arm": true}})
	RegisterScenario(&vScenario{name: "v-scn", oracleFalseOn: "d-arm", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})
	register(&vDefender{name: "d-arm", interval: 6, actions: []float64{1, 2}})

	metrics, err := h.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	ordinary := row(t, metrics, "d-arm", 0)
	if !ordinary.IsScored() {
		t.Fatalf("fixture relevance: the ORDINARY comparison must still score against the anchor-only control")
	}
	adaptive := row(t, metrics, "d-arm", 2) // TrialsPerArm+1
	v := adaptive.MeasurementState()
	if v.Kind != TrialAdaptive {
		t.Fatalf("adaptive row kind = %q, want %q", v.Kind, TrialAdaptive)
	}
	if v.Scored {
		t.Errorf("adaptive pass scored with no paired adaptive control")
	}
	if v.Baseline.Kind != TrialAdaptive {
		t.Errorf("adaptive row anchored against kind %q; it must never borrow an ordinary baseline", v.Baseline.Kind)
	}
	if v.Baseline.Observed {
		t.Errorf("adaptive row claims an observed control that was never run")
	}
	if adaptive.DisruptionVsOracle != 0 {
		t.Errorf("unpaired adaptive pass credited disruption=%v", adaptive.DisruptionVsOracle)
	}
	if v.UnscoredReason == "" {
		t.Errorf("no missing-control reason for the adaptive pass")
	}
	// The anchor-only baseline must not have emitted adaptive or negative-control rows.
	for _, m := range metrics {
		if m.Defender == "d-base" && m.Trial != 0 {
			t.Errorf("anchor-only control emitted an extra trial %d (%s); its passes are NOT run", m.Trial, m.Kind())
		}
		if m.Defender == "d-base" && !m.AnchorOnly {
			t.Errorf("force-included control row is not marked anchorOnly")
		}
	}
}

func TestValidityAdaptivePassScoresAgainstAMatchingAdaptiveControl(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1, AdaptiveArm: true})
	// The attack fails only for the defended arm, on every index.
	RegisterScenario(&vScenario{name: "v-scn", oracleFalseOn: "d-arm", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})
	register(&vDefender{name: "d-arm", interval: 6, actions: []float64{1, 2}})

	metrics, err := h.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	control := row(t, metrics, "d-base", 2)
	if control.Kind() != TrialAdaptive || !control.IsScored() {
		t.Fatalf("fixture relevance: the baseline arm must run a scored ADAPTIVE control at index 2; got kind=%s scored=%v", control.Kind(), control.IsScored())
	}
	adaptive := row(t, metrics, "d-arm", 2)
	v := adaptive.MeasurementState()
	if !v.Scored {
		t.Fatalf("adaptive pass with a matching adaptive control is unscored: %q", v.UnscoredReason)
	}
	if v.Baseline.Kind != TrialAdaptive || v.Baseline.Defender != "d-base" || !v.Baseline.Usable {
		t.Errorf("adaptive anchor identity wrong: %+v", v.Baseline)
	}
	if adaptive.DisruptionVsOracle != 1 {
		t.Errorf("anchored adaptive disruption = %v, want 1", adaptive.DisruptionVsOracle)
	}
}

// ---------------------------------------------------------------- observers

func TestValidityUnobservedCostIsNeverZeroCostOrFavorableROI(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*vDefender)
	}{
		{name: "no-observer", mutate: func(d *vDefender) { d.noObserver = true }},
		{name: "observer-error", mutate: func(d *vDefender) { d.observerErr = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, RunnerOptions{TrialsPerArm: 1, RunNegativeControl: true})
			RegisterScenario(&vScenario{name: "v-scn", oracleFalseOn: "d-arm", oracleFalseTrial: -1})
			register(&vDefender{name: "d-base", baseline: true})
			arm := &vDefender{name: "d-arm", interval: 6, actions: []float64{1, 2}}
			tc.mutate(arm)
			register(arm)

			metrics, err := h.runner.Run(context.Background())
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			m := row(t, metrics, "d-arm", 0)
			v := m.MeasurementState()
			if v.CostObserved {
				t.Fatalf("cost reported as observed for %s", tc.name)
			}
			// The disruption comparison itself is still a real measurement.
			if !v.Scored || m.DisruptionVsOracle != 1 {
				t.Errorf("the oracle comparison must survive an unobserved cost: scored=%v disruption=%v", v.Scored, m.DisruptionVsOracle)
			}
			if m.DefensiveActions != -1 {
				t.Errorf("defensiveActions = %d; unobserved cost must be -1, never 0", m.DefensiveActions)
			}
			if m.SecurityPerCost != 0 || m.ROI != nil || m.Schwartau != nil {
				t.Errorf("unknown cost produced an efficiency/ROI figure: spc=%v roi=%v sch=%v", m.SecurityPerCost, m.ROI, m.Schwartau)
			}
			if len(v.Reasons) == 0 {
				t.Errorf("observer absence/failure was not propagated into the validity block")
			}
			// The negative control must not claim a measured zero false moves.
			neg := row(t, metrics, "d-arm", 1)
			if neg.Kind() != TrialNegativeControl {
				t.Fatalf("trial 1 is not the negative control")
			}
			if neg.FalseDefensiveActions != -1 {
				t.Errorf("negative control falseDefensiveActions = %d; an unobserved control must be -1, never 0", neg.FalseDefensiveActions)
			}
		})
	}
}

func TestValidityObservedZeroActionControlIsAMeasuredZero(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1, RunNegativeControl: true})
	RegisterScenario(&vScenario{name: "v-scn", oracleFalseOn: "d-arm", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})
	register(&vDefender{name: "d-arm", interval: 6, actions: []float64{1, 2, 3}})

	metrics, err := h.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	neg := row(t, metrics, "d-arm", 1)
	v := neg.MeasurementState()
	if v.Kind != TrialNegativeControl || v.Status != MeasurementValid || !v.CostObserved {
		t.Fatalf("negative control not a valid observation: %+v", v)
	}
	if neg.FalseDefensiveActions != 0 {
		t.Errorf("observed clean negative control = %d, want a measured 0", neg.FalseDefensiveActions)
	}
	attack := row(t, metrics, "d-arm", 0)
	if attack.DefensiveActions != 3 || !attack.CostObserved() {
		t.Errorf("attack trial cost = %d observed=%v; want 3 observed", attack.DefensiveActions, attack.CostObserved())
	}
	if attack.ROI == nil || attack.Schwartau == nil {
		t.Errorf("a scored, cost-observed trial must carry ROI and Schwartau")
	}
}

// ------------------------------------------------------------------ cleanup

func TestValidityCleanupOwedByEveryEnteredPhase(t *testing.T) {
	cases := []struct {
		name         string
		mutate       func(*vScenario, *vDefender)
		wantScenario int
		wantStop     int
		wantTeardown int
	}{
		{name: "defender-setup-failed", mutate: func(_ *vScenario, d *vDefender) { d.setupErr = true },
			wantScenario: 0, wantStop: 0, wantTeardown: 1},
		{name: "scenario-setup-failed", mutate: func(s *vScenario, _ *vDefender) { s.setupErr = true },
			wantScenario: 1, wantStop: 0, wantTeardown: 1},
		{name: "defender-start-failed", mutate: func(_ *vScenario, d *vDefender) { d.startErr = true },
			wantScenario: 1, wantStop: 1, wantTeardown: 1},
		{name: "complete-trial", mutate: func(*vScenario, *vDefender) {},
			wantScenario: 1, wantStop: 1, wantTeardown: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, RunnerOptions{TrialsPerArm: 1, DefenderFilter: map[string]bool{"d-arm": true}})
			sc := &vScenario{name: "v-scn", failOn: "d-arm", oracleFalseTrial: -1}
			arm := &vDefender{name: "d-arm"}
			tc.mutate(sc, arm)
			register(&vDefender{name: "d-base", baseline: true})
			register(arm)
			RegisterScenario(sc)

			metrics, err := h.runner.Run(context.Background())
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			m := row(t, metrics, "d-arm", 0)
			v := m.MeasurementState()
			if !v.Cleanup.Complete {
				t.Errorf("cleanup marked incomplete: %+v", v.Cleanup)
			}
			_, stops, teardowns := arm.counts()
			if stops != tc.wantStop {
				t.Errorf("defender.Stop called %d time(s), want %d (cleanup owed only by entered phases)", stops, tc.wantStop)
			}
			if teardowns != tc.wantTeardown {
				t.Errorf("defender.Teardown called %d time(s), want %d", teardowns, tc.wantTeardown)
			}
			// The scenario teardown count covers BOTH arms, so compare the delta
			// against the baseline arm's single completed trial.
			_, _, _, scTeardowns := sc.counts()
			if scTeardowns != 1+tc.wantScenario {
				t.Errorf("scenario.Teardown called %d time(s) overall, want %d", scTeardowns, 1+tc.wantScenario)
			}
			if h.closeCount() == 0 {
				t.Errorf("the per-trial environment closer was never called")
			}
		})
	}
}

func TestValidityRetainsEveryCleanupFailureAndStopsTheRun(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 3})
	h.closeErr = true
	sc := &vScenario{name: "v-scn", teardownErr: true, oracleFalseTrial: -1}
	RegisterScenario(sc)
	base := register(&vDefender{name: "d-base", baseline: true, stopErr: true, teardownErr: true})
	_ = base

	metrics, err := h.runner.Run(context.Background())
	if err == nil {
		t.Fatalf("Run completed silently after unverified cleanup")
	}
	if len(metrics) != 1 {
		t.Fatalf("run emitted %d row(s); it must write the failed trial and then STOP before another trial reuses the state", len(metrics))
	}
	m := metrics[0]
	v := m.MeasurementState()
	if v.Cleanup.Complete {
		t.Errorf("cleanup reported complete despite failures")
	}
	failed := v.Cleanup.Failures()
	if len(failed) != 4 {
		t.Errorf("retained %d cleanup failure(s), want all 4 (scenario.Teardown, defender.Stop, defender.Teardown, env.Close): %+v", len(failed), v.Cleanup.Attempted)
	}
	if v.Status != MeasurementInvalid || v.Scored {
		t.Errorf("a cleanup-failed trial must be invalid and unscored, got %q scored=%v", v.Status, v.Scored)
	}
	if m.DisruptionVsOracle != 0 || m.SecurityPerCost != 0 || m.ROI != nil || m.Schwartau != nil {
		t.Errorf("stale favorable derived values survived a cleanup failure: %+v", m)
	}
	out := h.runner.Outcome()
	if !out.Aborted || out.Complete || len(out.Barriers) == 0 {
		t.Errorf("run outcome does not report the barrier: %+v", out)
	}
	if out.ExecutedTrials != 1 || out.PlannedTrials != 3 {
		t.Errorf("outcome = executed %d of planned %d; want 1 of 3", out.ExecutedTrials, out.PlannedTrials)
	}
}

func TestValidityCleanupRunsOnABoundedContextAfterCancellation(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1})
	// The scenario cancels the run context from inside Execute; the cleanup owed
	// by the phases already entered must still be attempted.
	ctx, cancel := context.WithCancel(context.Background())
	sc := &vCancelScenario{cancel: cancel}
	RegisterScenario(sc)
	base := register(&vDefender{name: "d-base", baseline: true})

	metrics, err := h.runner.Run(ctx)
	if err == nil {
		t.Fatalf("Run must report that the context ended")
	}
	if len(metrics) != 1 {
		t.Fatalf("the cancelled trial must still be written; got %d row(s)", len(metrics))
	}
	v := metrics[0].MeasurementState()
	if v.Status != MeasurementInvalid {
		t.Errorf("a cancelled trial is not a valid measurement: %q", v.Status)
	}
	if !v.Cleanup.Complete {
		t.Errorf("cleanup did not complete on the detached context: %+v", v.Cleanup)
	}
	if !sc.tornDown {
		t.Errorf("scenario.Teardown was never attempted after cancellation")
	}
	_, stops, teardowns := base.counts()
	if stops != 1 || teardowns != 1 {
		t.Errorf("defender cleanup after cancellation: stops=%d teardowns=%d, want 1/1", stops, teardowns)
	}
	if h.closeCount() != 1 {
		t.Errorf("environment closer ran %d time(s) after cancellation, want 1", h.closeCount())
	}
}

// vCancelScenario cancels the run context from inside Execute.
type vCancelScenario struct {
	cancel   context.CancelFunc
	tornDown bool
}

func (s *vCancelScenario) Metadata() ScenarioMeta {
	return ScenarioMeta{Name: "v-cancel", Category: CategoryClassicChain, R6ResponseTag: R6Partial}
}
func (s *vCancelScenario) Setup(context.Context, *Env) error { return nil }
func (s *vCancelScenario) Execute(ctx context.Context, _ *Env) (AttackResult, error) {
	s.cancel()
	return AttackResult{}, ctx.Err()
}
func (s *vCancelScenario) SuccessOracle(context.Context, *Env) (OracleResult, error) {
	return OracleResult{}, errors.New("oracle must not run after a failed stimulus")
}
func (s *vCancelScenario) Teardown(ctx context.Context, _ *Env) error {
	if ctx.Err() != nil {
		return fmt.Errorf("cleanup context was already cancelled: %w", ctx.Err())
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("cleanup context is unbounded")
	}
	s.tornDown = true
	return nil
}

// --------------------------------------------------------------- persistence

func TestValidityMetricWriteFailureStopsTheRunVisibly(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 2})
	RegisterScenario(&vScenario{name: "v-scn", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})
	// Close the writer's file so the very first Write fails.
	if err := h.writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := h.runner.Run(context.Background())
	if err == nil {
		t.Fatalf("Run ignored a metric write failure")
	}
	out := h.runner.Outcome()
	if !out.Aborted || out.Complete {
		t.Errorf("outcome does not report the aborted run: %+v", out)
	}
	if out.WrittenTrials != 0 || out.ExecutedTrials != 1 {
		t.Errorf("outcome = executed %d written %d; want 1 executed, 0 written", out.ExecutedTrials, out.WrittenTrials)
	}
}

func TestValidityRoundTripsThroughJSONAndLegacyRowsStayUnverified(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1})
	RegisterScenario(&vScenario{name: "v-scn", oracleFalseOn: "d-arm", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})
	register(&vDefender{name: "d-arm", interval: 6, actions: []float64{1}})
	if _, err := h.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := h.writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(h.writer.Path())
	if err != nil {
		t.Fatal(err)
	}
	var decoded []Metric
	for _, line := range splitLines(string(raw)) {
		var m Metric
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		decoded = append(decoded, m)
	}
	arm := row(t, decoded, "d-arm", 0)
	v := arm.MeasurementState()
	if v.Version != MeasurementValidityVersion || !v.Scored || v.Baseline.Defender != "d-base" {
		t.Errorf("validity did not survive the JSON round trip: %+v", v)
	}
	if arm.IsLegacy() {
		t.Errorf("a freshly written row must not be legacy")
	}

	// A pre-contract row decodes unchanged and is LEGACY / UNVERIFIED: its zero
	// fields are never treated as evidence of a measurement.
	legacyLine := `{"scenario":"s1","defender":"d-nomtd","trial":0,"oracleAchieved":true,"disruptionVsOracle":0,"defensiveActions":0,"falseDefensiveActions":0,"negativeControl":true,"r6Tag":"R6Partial","category":"ClassicChain"}`
	var legacy Metric
	if err := json.Unmarshal([]byte(legacyLine), &legacy); err != nil {
		t.Fatalf("legacy line must still decode: %v", err)
	}
	if !legacy.IsLegacy() || legacy.IsScored() || legacy.CostObserved() {
		t.Errorf("legacy row was treated as a measurement: legacy=%v scored=%v costObserved=%v", legacy.IsLegacy(), legacy.IsScored(), legacy.CostObserved())
	}
	if s := legacy.MeasurementState().Status; s != MeasurementLegacy {
		t.Errorf("legacy status = %q, want %q", s, MeasurementLegacy)
	}
}

func splitLines(s string) []string {
	var out []string
	for _, l := range bytesSplit(s) {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func bytesSplit(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// -------------------------------------------------------------- run outcome

func TestValidityRefusesAnUnrecordedMatrixAndReportsCompleteness(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 2, RunNegativeControl: true, AdaptiveArm: true})
	RegisterScenario(&vScenario{name: "v-scn", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})

	nilWriter := NewRunner(RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir()},
		func(string, string, int, int64, string) (*Env, func() error, error) { return nil, nil, nil }, nil, nil)
	if _, err := nilWriter.Run(context.Background()); err == nil {
		t.Errorf("a runner with no metric writer must refuse to run an unrecorded matrix")
	}

	out0 := h.runner.Outcome()
	if out0.PlannedTrials != 0 {
		t.Errorf("outcome must be empty before Run: %+v", out0)
	}
	if _, err := h.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := h.runner.Outcome()
	if !out.Complete || out.Aborted {
		t.Errorf("a clean run must report COMPLETE: %+v", out)
	}
	if out.PlannedTrials != 4 || out.ExecutedTrials != 4 || out.WrittenTrials != 4 {
		t.Errorf("outcome counts = planned %d executed %d written %d; want 4/4/4", out.PlannedTrials, out.ExecutedTrials, out.WrittenTrials)
	}
	if out.BaselineDefender != "d-base" || out.BaselineAnchorOnly {
		t.Errorf("outcome control identity wrong: %+v", out)
	}
}
