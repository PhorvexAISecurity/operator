package core

// validity_r1_test.go — PERMANENT regressions for lead review R1 (V3-M161).
//
// Findings covered here:
//   1. a decoded validity block is a CLAIM, not a verdict: unsupported markers
//      and self-contradictory evidence must stay visible but never certifiable;
//   5. cleanup is bounded on WALL CLOCK, not merely handed a deadline, and an
//      unresolved call is retained rather than abandoned;
//   6. the ACTUAL cleanup producer (Env.CleanupOwned reached through the real
//      factory closer) propagates API failures all the way to the final metric
//      and the dirty-state barrier;
//      plus observer results validated before being called observations.
//
// Every case keeps a positive control so a pass cannot mean "everything now
// fails".

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

// producerRow drives the REAL Runner.Run -> real MetricWriter -> real JSON
// decode and returns the defended arm's row exactly as a reader sees it.
func producerRow(t *testing.T) Metric {
	t.Helper()
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1})
	RegisterScenario(&vScenario{name: "r1-scn", oracleFalseOn: "d-arm", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})
	register(&vDefender{name: "d-arm", interval: 6, actions: []float64{1}})
	if _, err := h.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := h.writer.Close(); err != nil {
		t.Fatal(err)
	}
	metrics := h.writer.All()
	arm := row(t, metrics, "d-arm", 0)
	// Round-trip through JSON so the row under test is what a reader decodes.
	b, err := json.Marshal(arm)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Metric
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Validated().Scorable {
		t.Fatalf("fixture relevance: the unmodified producer row must be scorable, got %+v", decoded.Validated())
	}
	return decoded
}

// A validity block that this build cannot interpret, or whose evidence
// contradicts itself, must never be certified — no matter what `scored` claims.
func TestR1ValidatedDecodeRefusesUnsupportedOrContradictoryClaims(t *testing.T) {
	cases := []struct {
		name string
		// mutate corrupts the CLAIM while leaving `scored: true` in place.
		mutate func(*Metric)
		// unverified is true when the row cannot be interpreted at all (as
		// opposed to being interpretable but refused).
		unverified bool
	}{
		{name: "future-version", mutate: func(m *Metric) { m.Validity.Version = 999 }, unverified: true},
		{name: "past-version", mutate: func(m *Metric) { m.Validity.Version = 0 }, unverified: true},
		{name: "unknown-status", mutate: func(m *Metric) { m.Validity.Status = "unrecognized" }, unverified: true},
		{name: "unknown-kind", mutate: func(m *Metric) { m.Validity.Kind = "sideways" }, unverified: true},
		{name: "cleanup-incomplete", mutate: func(m *Metric) { m.Validity.Cleanup.Complete = false }, unverified: true},
		{name: "cleanup-unresolved", mutate: func(m *Metric) {
			m.Validity.Cleanup.Complete = false
			m.Validity.Cleanup.Unresolved = true
		}, unverified: true},
		{name: "retained-cleanup-failure", mutate: func(m *Metric) {
			m.Validity.Cleanup.Attempted = append(m.Validity.Cleanup.Attempted, CleanupStep{Step: "scenario.Teardown", Error: "boom"})
		}, unverified: true},
		{name: "missing-control", mutate: func(m *Metric) { m.Validity.Baseline = BaselineRef{Required: true} }, unverified: true},
		{name: "control-usable-but-unobserved", mutate: func(m *Metric) {
			m.Validity.Baseline.Observed = false
		}, unverified: true},
		{name: "control-usable-but-attack-failed", mutate: func(m *Metric) {
			m.Validity.Baseline.OracleAchieved = false
		}, unverified: true},
		{name: "control-without-identity", mutate: func(m *Metric) { m.Validity.Baseline.Defender = "" }, unverified: true},
		{name: "status-not-valid", mutate: func(m *Metric) { m.Validity.Status = MeasurementInvalid }, unverified: true},
		{name: "oracle-not-observed", mutate: func(m *Metric) { m.Validity.OracleObserved = false }, unverified: true},
		{name: "scored-negative-control", mutate: func(m *Metric) { m.Validity.Kind = TrialNegativeControl }, unverified: true},
		{name: "disruption-out-of-range", mutate: func(m *Metric) { m.DisruptionVsOracle = 7 }, unverified: true},
		{name: "disruption-not-finite", mutate: func(m *Metric) { m.DisruptionVsOracle = math.Inf(1) }, unverified: true},
		{name: "cost-observed-but-sentinel", mutate: func(m *Metric) { m.DefensiveActions = -1 }, unverified: true},
		{name: "cost-observed-but-nan-timing", mutate: func(m *Metric) { m.TimeToActionSeconds = math.NaN() }, unverified: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := producerRow(t)
			tc.mutate(&m)
			if !m.Validity.Scored {
				t.Fatalf("fixture relevance: the corrupted row must still CLAIM scored")
			}
			val := m.Validated()
			if val.Scorable {
				t.Errorf("a contradictory/unsupported row was certified: %+v", val)
			}
			if m.IsScored() {
				t.Errorf("IsScored trusted the row's own claim")
			}
			if tc.unverified && !val.Unverified {
				t.Errorf("row was refused but not marked UNVERIFIED, so it would vanish from the counts: %+v", val)
			}
			if len(val.Rejections) == 0 {
				t.Errorf("no rejection reason recorded; the refusal would be invisible")
			}
		})
	}
}

// POSITIVE CONTROL: a genuine, unmodified version-1 producer row still
// certifies, and its cost and oracle observations remain usable.
func TestR1ValidatedDecodeKeepsGenuineVersion1Rows(t *testing.T) {
	m := producerRow(t)
	val := m.Validated()
	if !val.Supported || val.Unverified || !val.Scorable || !val.CostUsable || !val.OracleUsable {
		t.Fatalf("a genuine producer row was refused: %+v", val)
	}
	if len(val.Rejections) != 0 {
		t.Errorf("unexpected rejections on a genuine row: %v", val.Rejections)
	}
	if m.DisruptionVsOracle != 1 {
		t.Errorf("genuine disruption = %v, want 1", m.DisruptionVsOracle)
	}
}

// A legacy (pre-contract) row stays readable and counted, never certified.
func TestR1ValidatedDecodeKeepsLegacyRowsReadable(t *testing.T) {
	line := `{"scenario":"s1","defender":"d-nomtd","trial":0,"oracleAchieved":true,"disruptionVsOracle":1,"defensiveActions":0}`
	var m Metric
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	val := m.Validated()
	if !val.Legacy || val.Scorable || val.CostUsable || val.OracleUsable {
		t.Fatalf("legacy row mis-classified: %+v", val)
	}
	if val.Unverified {
		t.Errorf("a legacy row must be reported as LEGACY, not lumped into unverified")
	}
}

// ------------------------------------------------------- observer validation

func TestR1ObserverResultsAreValidatedBeforeBeingCalledObserved(t *testing.T) {
	cases := []struct {
		name  string
		count int
		times []float64
		want  bool // want the observation accepted
	}{
		{name: "genuine-observation", count: 2, times: []float64{1e9, 1e9 + 5}, want: true},
		{name: "genuine-zero-no-timestamps", count: 0, times: nil, want: true},
		{name: "count-without-timestamps", count: 3, times: nil, want: true},
		{name: "negative-count", count: -4, times: nil},
		{name: "nan-timestamp", count: 1, times: []float64{math.NaN()}},
		{name: "inf-timestamp", count: 1, times: []float64{math.Inf(1)}},
		{name: "non-positive-timestamp", count: 1, times: []float64{0}},
		{name: "timestamps-contradict-count", count: 1, times: []float64{1e9, 1e9 + 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problem := validateObservation(tc.count, tc.times)
			if tc.want && problem != "" {
				t.Fatalf("a usable observation was rejected: %s", problem)
			}
			if !tc.want && problem == "" {
				t.Fatalf("an unusable observation was accepted as a measurement")
			}
		})
	}
}

// Through the REAL runner: an observer that contradicts itself leaves the cost
// UNOBSERVED, contributes no ROI, and never reaches the adaptive learner.
func TestR1ContradictoryObserverLeavesCostUnobserved(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1})
	RegisterScenario(&vScenario{name: "r1-obs", oracleFalseOn: "d-arm", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})
	RegisterDefender(&contradictoryObserver{name: "d-arm"})

	metrics, err := h.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	m := row(t, metrics, "d-arm", 0)
	val := m.Validated()
	if val.CostUsable || m.MeasurementState().CostObserved {
		t.Errorf("a contradictory observer result was accepted as an observation")
	}
	if m.DefensiveActions != -1 {
		t.Errorf("defensiveActions = %d, want the -1 UNOBSERVED sentinel", m.DefensiveActions)
	}
	if m.ROI != nil || m.Schwartau != nil || m.SecurityPerCost != 0 {
		t.Errorf("an unusable observation produced cost/ROI figures: %+v", m)
	}
	// The disruption comparison itself is unaffected.
	if !val.Scorable || m.DisruptionVsOracle != 1 {
		t.Errorf("the oracle comparison must survive an unusable cost read: %+v", val)
	}
	if len(m.MeasurementState().Reasons) == 0 {
		t.Errorf("the contradiction was not recorded on the row")
	}
}

// contradictoryObserver reports 5 actions but only one timestamp.
type contradictoryObserver struct{ name string }

func (d *contradictoryObserver) Metadata() DefenderMeta {
	return DefenderMeta{Name: d.name, MeanRotationIntervalSeconds: 6}
}
func (d *contradictoryObserver) Setup(context.Context, *Env) error    { return nil }
func (d *contradictoryObserver) Start(context.Context, *Env) error    { return nil }
func (d *contradictoryObserver) Stop(context.Context, *Env) error     { return nil }
func (d *contradictoryObserver) Teardown(context.Context, *Env) error { return nil }
func (d *contradictoryObserver) DefensiveActions(context.Context, *Env) (int, []float64, error) {
	return 5, []float64{1e9}, nil
}

// ------------------------------------------------------------ bounded cleanup

// slowScenario blocks in Teardown for `delay`, ignoring its context entirely —
// exactly the uncooperative callback a deadline alone cannot bound. `finished`
// is closed when it eventually returns so the test can drain it deterministically
// without leaving a goroutine behind.
type slowScenario struct {
	delay    time.Duration
	finished chan struct{}
	once     sync.Once
}

func (s *slowScenario) Metadata() ScenarioMeta {
	return ScenarioMeta{Name: "r1-slow", Category: CategoryClassicChain, R6ResponseTag: R6Partial}
}
func (s *slowScenario) Setup(context.Context, *Env) error { return nil }
func (s *slowScenario) Execute(_ context.Context, env *Env) (AttackResult, error) {
	env.Log.Command("r1-attack")
	return AttackResult{Stages: []string{"staged"}}, nil
}
func (s *slowScenario) SuccessOracle(context.Context, *Env) (OracleResult, error) {
	return OracleResult{Achieved: true, ObservedState: "measured", Evidence: map[string]string{"observed": "yes"}}, nil
}
func (s *slowScenario) Teardown(context.Context, *Env) error {
	time.Sleep(s.delay) // deliberately ignores the context
	s.once.Do(func() { close(s.finished) })
	return nil
}

// A cleanup call that outlives its WALL-CLOCK bound is UNRESOLVED: the trial is
// not clean, the run stops before another trial reuses the state, and the still
// running call is retained rather than abandoned. A late nil does not
// retroactively make the trial complete.
func TestR1CleanupExceedingItsBoundIsUnresolvedAndStopsTheRun(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 3, CleanupTimeout: 40 * time.Millisecond})
	slow := &slowScenario{delay: 400 * time.Millisecond, finished: make(chan struct{})}
	RegisterScenario(slow)
	register(&vDefender{name: "d-base", baseline: true})

	metrics, err := h.runner.Run(context.Background())
	if err == nil {
		t.Fatalf("run continued after an unresolved cleanup")
	}
	if len(metrics) != 1 {
		t.Fatalf("emitted %d row(s); the unresolved trial must be written and then STOP the run", len(metrics))
	}
	v := metrics[0].MeasurementState()
	if v.Cleanup.Complete {
		t.Errorf("cleanup reported complete despite an unresolved step")
	}
	if !v.Cleanup.Unresolved {
		t.Errorf("cleanup record does not mark the step UNRESOLVED: %+v", v.Cleanup)
	}
	if v.Cleanup.Verified {
		t.Errorf("cleanup claimed verified with an unresolved step")
	}
	var found bool
	for _, s := range v.Cleanup.Attempted {
		if s.Step == "scenario.Teardown" {
			found = true
			if !s.Unresolved {
				t.Errorf("scenario.Teardown not marked unresolved: %+v", s)
			}
			if s.Error != "" {
				t.Errorf("an unresolved step must not be reported as a failure: %q", s.Error)
			}
			if s.Seconds <= 0 {
				t.Errorf("no wall-clock duration recorded for the bounded wait")
			}
		}
	}
	if !found {
		t.Fatalf("scenario.Teardown missing from the cleanup record: %+v", v.Cleanup.Attempted)
	}
	if metrics[0].IsScored() || metrics[0].DisruptionVsOracle != 0 {
		t.Errorf("an unresolved trial kept a derived value")
	}
	out := h.runner.Outcome()
	if !out.Aborted || len(out.Barriers) == 0 {
		t.Errorf("run outcome does not report the barrier: %+v", out)
	}

	// Ownership is retained, not abandoned: drain the still-running call and
	// confirm its late result was recorded. This also guarantees the test leaves
	// no goroutine behind.
	if late := h.runner.WaitForPendingCleanup(5 * time.Second); late != 1 {
		t.Errorf("late cleanups recorded = %d, want 1", late)
	}
	select {
	case <-slow.finished:
	case <-time.After(5 * time.Second):
		t.Fatalf("the slow teardown never returned")
	}
	lc := h.runner.Outcome().LateCleanups
	if len(lc) != 1 || lc[0].Step != "scenario.Teardown" || lc[0].Error != "" {
		t.Fatalf("late cleanup not retained with its result: %+v", lc)
	}
	// The late nil must NOT have upgraded the already-reported trial.
	if metrics[0].MeasurementState().Cleanup.Complete {
		t.Errorf("a late successful return retroactively marked the trial clean")
	}
}

// POSITIVE CONTROL: a cleanup that finishes inside the bound resolves normally,
// records its duration, and leaves nothing pending.
func TestR1CleanupWithinItsBoundResolvesCleanly(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1, CleanupTimeout: 2 * time.Second})
	quick := &slowScenario{delay: 5 * time.Millisecond, finished: make(chan struct{})}
	RegisterScenario(quick)
	register(&vDefender{name: "d-base", baseline: true})

	metrics, err := h.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	v := metrics[0].MeasurementState()
	if !v.Cleanup.Complete || v.Cleanup.Unresolved || !v.Cleanup.Verified {
		t.Fatalf("a prompt cleanup was not reported clean: %+v", v.Cleanup)
	}
	if late := h.runner.WaitForPendingCleanup(2 * time.Second); late != 0 {
		t.Errorf("late cleanups = %d, want 0", late)
	}
	if !metrics[0].IsScored() {
		t.Errorf("the trial should still be scored: %q", metrics[0].SkipReason)
	}
}

// ------------------------------------------- the ACTUAL cleanup producer path

// The real Env.CleanupOwned must aggregate API failures instead of logging and
// returning nil, and must not claim absence it never observed.
func TestR1ActualCleanupOwnedPropagatesEveryAPIFailure(t *testing.T) {
	t.Run("positive-control", func(t *testing.T) {
		env := newTestEnv("sandbox", "sandbox")
		if err := env.CleanupOwned(context.Background(), false); err != nil {
			t.Fatalf("a clean namespace must verify: %v", err)
		}
	})
	t.Run("failed-api-cleanup", func(t *testing.T) {
		env := newTestEnv("sandbox", "sandbox")
		calls := 0
		env.Kube.(*fake.Clientset).PrependReactor("*", "*", func(ktest.Action) (bool, runtime.Object, error) {
			calls++
			return true, nil, errors.New("cleanup API unavailable")
		})
		err := env.CleanupOwned(context.Background(), false)
		if err == nil || calls == 0 {
			t.Fatalf("CleanupOwned suppressed API failures: calls=%d err=%v", calls, err)
		}
		// Every kind is reported, not just the first: one broken kind must not
		// mask the others.
		for _, want := range []string{"pods", "deployments", "services", "configmaps", "secrets", "roles"} {
			if !containsSubstring(err.Error(), want) {
				t.Errorf("aggregated error does not mention %q: %v", want, err)
			}
		}
	})
	t.Run("residue-survives-the-delete", func(t *testing.T) {
		env := newTestEnv("sandbox", "sandbox")
		// A pod that the API accepts a delete for but never removes: exactly the
		// finalizer/background-deletion case where an accepted delete is not
		// proof of absence.
		env.Kube.(*fake.Clientset).PrependReactor("list", "pods", func(ktest.Action) (bool, runtime.Object, error) {
			return true, stuckPodList(), nil
		})
		err := env.CleanupOwned(context.Background(), false)
		if err == nil {
			t.Fatalf("cleanup declared reusable state while an owned pod was still present")
		}
		for _, want := range []string{"still present", "stuck-pod", "terminating"} {
			if !containsSubstring(err.Error(), want) {
				t.Errorf("residue error does not disclose %q: %v", want, err)
			}
		}
	})
}

// Through the REAL factory closer -> real Env.CleanupOwned -> the final metric
// and the dirty-state barrier: an API failure in the actual producer path is a
// visible unverified cleanup, not a clean trial.
func TestR1FactoryCloserCleanupFailureReachesTheMetricAndBarrier(t *testing.T) {
	resetRegistriesForTest()
	t.Cleanup(resetRegistriesForTest)
	RegisterScenario(&vScenario{name: "r1-real-cleanup", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})

	dir := t.TempDir()
	mw, err := NewMetricWriter(filepath.Join(dir, "metrics.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mw.Close() })

	// The factory wires the REAL Env and the REAL CleanupOwned into the closer,
	// mirroring cmd/harness: a bounded, detached context and a propagated error.
	factory := func(scenario, defender string, trial int, _ int64, _ string) (*Env, func() error, error) {
		env := newTestEnv("sandbox", "sandbox")
		env.Log = &vLogger{}
		env.Trial, env.ScenarioName, env.DefenderName = trial, scenario, defender
		env.Config = config.WithDollarDefaults(env.Config)
		env.Kube.(*fake.Clientset).PrependReactor("*", "*", func(ktest.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("cleanup API unavailable")
		})
		closer := func() error {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), time.Second)
			defer cancel()
			return env.CleanupOwned(cctx, false)
		}
		return env, closer, nil
	}
	runner := NewRunner(RunnerOptions{TrialsPerArm: 2, OutDir: dir, CleanupTimeout: 2 * time.Second}, factory, mw, nil)

	metrics, runErr := runner.Run(context.Background())
	if runErr == nil {
		t.Fatalf("the run continued after the real cleanup helper failed")
	}
	if len(metrics) != 1 {
		t.Fatalf("emitted %d row(s); the failed trial must be written and then STOP the run", len(metrics))
	}
	m := metrics[0]
	v := m.MeasurementState()
	if v.Cleanup.Complete {
		t.Errorf("cleanup reported complete despite a real API failure")
	}
	var envClose CleanupStep
	for _, s := range v.Cleanup.Attempted {
		if s.Step == "env.Close" {
			envClose = s
		}
	}
	if envClose.Error == "" {
		t.Fatalf("the factory closer's failure never reached the metric: %+v", v.Cleanup.Attempted)
	}
	if !containsSubstring(envClose.Error, "cleanup API unavailable") {
		t.Errorf("the underlying API error was not propagated: %q", envClose.Error)
	}
	if m.IsScored() || m.DisruptionVsOracle != 0 || m.ROI != nil {
		t.Errorf("a dirty trial kept a derived value: %+v", m)
	}
	if !m.Skipped || m.SkipReason == "" {
		t.Errorf("the dirty trial is not marked unscored for legacy consumers")
	}
	out := runner.Outcome()
	if !out.Aborted || len(out.Barriers) == 0 {
		t.Errorf("the dirty-state barrier was not raised: %+v", out)
	}
	if late := runner.WaitForPendingCleanup(2 * time.Second); late != 0 {
		t.Errorf("unexpected late cleanups: %d", late)
	}
}

// stuckPodList is an owned pod the apiserver still reports after the delete was
// accepted, with a deletion timestamp set — the finalizer/background-deletion
// case that makes "the delete succeeded" no proof of absence.
func stuckPodList() *corev1.PodList {
	now := metav1.Now()
	return &corev1.PodList{Items: []corev1.Pod{{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "stuck-pod",
			Namespace:         "sandbox",
			Labels:            map[string]string{OwnedLabelKey: OwnedLabelValue},
			DeletionTimestamp: &now,
			Finalizers:        []string{"example.com/holds-this-pod"},
		},
	}}}
}

func containsSubstring(haystack, needle string) bool {
	return len(needle) == 0 || indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
