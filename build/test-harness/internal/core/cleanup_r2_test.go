package core

// cleanup_r2_test.go — PERMANENT regressions for lead review R2 findings 3 and 4
// (V3-M161):
//
//	3. accepted deletion is asynchronous, so verification must POLL within its
//	   budget instead of calling a normally-terminating Pod a failure; namespace
//	   deletion must be verified too; and a final teardown that does not verify
//	   is part of the RUN RESULT, not a warning;
//	4. once a cleanup step is unresolved, the remaining steps share its Env and
//	   must NOT be started — a late callback writing through the logger that
//	   env.Close would have closed is exactly the race that "each callback
//	   returned" hides.
//
// Every fixture here is drained, so no goroutine outlives its test.

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

// ---------------------------------------------------- asynchronous deletion

// ordinary background deletion completes shortly after the API accepts it. That
// is a SUCCESS, not residue: rejecting it would make every normal cleanup look
// like a dirty trial.
func TestR2CleanupWaitsForAcceptedDeletionWithinItsBudget(t *testing.T) {
	for _, delay := range []time.Duration{0, 50 * time.Millisecond, 200 * time.Millisecond} {
		t.Run(delay.String(), func(t *testing.T) {
			env := newTestEnv("sandbox", "sandbox")
			k := env.Kube.(*fake.Clientset)
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "owned-pod", Namespace: "sandbox",
				Labels: map[string]string{OwnedLabelKey: OwnedLabelValue}}}
			if err := k.Tracker().Add(pod); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			defer func() { <-done }() // drain: never leave the deleter running
			k.PrependReactor("delete-collection", "pods", func(ktest.Action) (bool, runtime.Object, error) {
				remove := func() {
					_ = k.Tracker().Delete(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, "sandbox", "owned-pod")
					close(done)
				}
				if delay == 0 {
					remove()
				} else {
					go func() { time.Sleep(delay); remove() }()
				}
				return true, nil, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := env.CleanupOwned(ctx, false); err != nil {
				t.Fatalf("an accepted deletion that completes within the budget must verify, got: %v", err)
			}
		})
	}
}

// An object a finalizer still holds when the budget expires is NOT absent, and
// its terminating state is reported rather than guessed at.
func TestR2CleanupReportsResidueThatOutlivesTheBudget(t *testing.T) {
	env := newTestEnv("sandbox", "sandbox")
	held := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "held-pod", Namespace: "sandbox",
		Labels:            map[string]string{OwnedLabelKey: OwnedLabelValue},
		DeletionTimestamp: ptrNow(), Finalizers: []string{"example.com/holds-this-pod"}}}
	env.Kube.(*fake.Clientset).PrependReactor("list", "pods", func(ktest.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{Items: []corev1.Pod{*held}}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := env.CleanupOwned(ctx, false)
	if err == nil {
		t.Fatalf("cleanup declared reusable state while a finalizer still held an owned pod")
	}
	for _, want := range []string{"held-pod", "terminating", "budget expired"} {
		if !containsSubstring(err.Error(), want) {
			t.Errorf("residue error does not disclose %q: %v", want, err)
		}
	}
}

func ptrNow() *metav1.Time { n := metav1.Now(); return &n }

// deleteNamespace=true must VERIFY the namespace actually disappeared. An
// accepted namespace delete is not absence: a namespace routinely sits in
// Terminating, and a finalizer can hold it indefinitely.
func TestR2CleanupVerifiesNamespaceDisappearance(t *testing.T) {
	t.Run("namespace-goes-away", func(t *testing.T) {
		env := newTestEnv("sandbox", "sandbox")
		if err := env.EnsureNamespace(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := env.CleanupOwned(ctx, true); err != nil {
			t.Fatalf("a namespace that is actually deleted must verify: %v", err)
		}
	})
	t.Run("namespace-stuck-terminating", func(t *testing.T) {
		env := newTestEnv("sandbox", "sandbox")
		k := env.Kube.(*fake.Clientset)
		// The delete is accepted, but the namespace stays Terminating: the exact
		// case where "the API said yes" is not proof of absence.
		k.PrependReactor("get", "namespaces", func(ktest.Action) (bool, runtime.Object, error) {
			return true, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name: "sandbox", DeletionTimestamp: ptrNow(),
				Finalizers: []string{"kubernetes"}}}, nil
		})
		k.PrependReactor("delete", "namespaces", func(ktest.Action) (bool, runtime.Object, error) {
			return true, nil, nil
		})
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		err := env.CleanupOwned(ctx, true)
		if err == nil {
			t.Fatalf("an accepted namespace delete was treated as absence")
		}
		for _, want := range []string{"namespace sandbox still present", "terminating", "finalizer"} {
			if !containsSubstring(err.Error(), want) {
				t.Errorf("namespace residue error does not disclose %q: %v", want, err)
			}
		}
	})
}

// ------------------------------------------------------- final teardown chain

// A final teardown that does not verify is part of the RUN RESULT: it raises a
// barrier, makes the run INCOMPLETE and is recorded for provenance. A warning
// followed by a successful exit would report a clean run that did not happen.
func TestR2FinalTeardownFailureMakesTheRunIncomplete(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1})
	RegisterScenario(&vScenario{name: "r2-final", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})
	if _, err := h.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out := h.runner.Outcome(); !out.Complete {
		t.Fatalf("fixture relevance: the matrix itself must complete cleanly, got %+v", out)
	}

	// The REAL chain: build an Env, run the REAL CleanupOwned against a failing
	// API, and record the result the way cmd/harness does.
	env := newTestEnv("sandbox", "sandbox")
	env.Kube.(*fake.Clientset).PrependReactor("*", "*", func(ktest.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("final teardown API unavailable")
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	finalErr := env.CleanupOwned(ctx, true)
	if finalErr == nil {
		t.Fatalf("fixture relevance: the final teardown must actually fail")
	}
	h.runner.RecordFinalTeardown(finalErr)

	out := h.runner.Outcome()
	if out.Complete {
		t.Errorf("a run whose final teardown did not verify still reported COMPLETE")
	}
	if out.FinalTeardown == nil || !out.FinalTeardown.Attempted || out.FinalTeardown.Verified {
		t.Fatalf("final teardown not recorded as unverified: %+v", out.FinalTeardown)
	}
	if !containsSubstring(out.FinalTeardown.Error, "final teardown API unavailable") {
		t.Errorf("the underlying error was not retained: %q", out.FinalTeardown.Error)
	}
	var sawBarrier bool
	for _, b := range out.Barriers {
		if containsSubstring(b, "final teardown did not verify") {
			sawBarrier = true
		}
	}
	if !sawBarrier {
		t.Errorf("no barrier raised for the unverified final teardown: %v", out.Barriers)
	}
}

// POSITIVE CONTROL: a verified final teardown leaves the run complete.
func TestR2VerifiedFinalTeardownKeepsTheRunComplete(t *testing.T) {
	h := newHarness(t, RunnerOptions{TrialsPerArm: 1})
	RegisterScenario(&vScenario{name: "r2-final-ok", oracleFalseTrial: -1})
	register(&vDefender{name: "d-base", baseline: true})
	if _, err := h.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	h.runner.RecordFinalTeardown(nil)
	out := h.runner.Outcome()
	if !out.Complete {
		t.Fatalf("a clean run with a verified final teardown must stay COMPLETE: %+v", out)
	}
	if out.FinalTeardown == nil || !out.FinalTeardown.Verified {
		t.Fatalf("verified final teardown not recorded: %+v", out.FinalTeardown)
	}
}

// -------------------------------------------------- cleanup phase overlap

// ownedLogger is a trial logger that OWNS a resource the way the real one owns
// its file: once Close runs, any later write is a use-after-close. It records
// those instead of hiding them.
type ownedLogger struct {
	mu              sync.Mutex
	closed          bool
	writesAfterFree int
	cmds            []string
}

func (l *ownedLogger) Logf(string, ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		l.writesAfterFree++
	}
}
func (l *ownedLogger) Command(c string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		l.writesAfterFree++
		return
	}
	l.cmds = append(l.cmds, c)
}
func (l *ownedLogger) Commands() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.cmds...)
}
func (l *ownedLogger) RawLogPath() string { return "" }
func (l *ownedLogger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
}
func (l *ownedLogger) afterFree() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.writesAfterFree
}

// lateWriterScenario keeps hold of the Env past its cleanup bound and then
// WRITES THROUGH IT — the real hazard, not a bare sleep.
type lateWriterScenario struct {
	release  chan struct{}
	finished chan struct{}
	once     sync.Once
}

func (s *lateWriterScenario) Metadata() ScenarioMeta {
	return ScenarioMeta{Name: "r2-late-writer", Category: CategoryClassicChain, R6ResponseTag: R6Partial}
}
func (s *lateWriterScenario) Setup(context.Context, *Env) error { return nil }
func (s *lateWriterScenario) Execute(_ context.Context, env *Env) (AttackResult, error) {
	env.Log.Command("r2-attack")
	return AttackResult{Stages: []string{"staged"}}, nil
}
func (s *lateWriterScenario) SuccessOracle(context.Context, *Env) (OracleResult, error) {
	return OracleResult{Achieved: true, ObservedState: "measured", Evidence: map[string]string{"observed": "yes"}}, nil
}
func (s *lateWriterScenario) Teardown(_ context.Context, env *Env) error {
	<-s.release
	// Still using the Env the later cleanup steps would have torn down.
	env.Log.Logf("late teardown still writing through the trial logger")
	env.Log.Command("late-teardown-command")
	s.once.Do(func() { close(s.finished) })
	return nil
}

// Once scenario.Teardown is unresolved, the steps that share its Env must NOT
// start. Otherwise env.Close frees the logger the late callback is still
// writing to, and the harness would claim each phase "ran" when it merely raced.
func TestR2UnresolvedCleanupBlocksTheStepsThatShareItsEnv(t *testing.T) {
	resetRegistriesForTest()
	t.Cleanup(resetRegistriesForTest)

	logger := &ownedLogger{}
	late := &lateWriterScenario{release: make(chan struct{}), finished: make(chan struct{})}
	RegisterScenario(late)
	arm := register(&vDefender{name: "d-base", baseline: true})

	dir := t.TempDir()
	mw, err := NewMetricWriter(filepath.Join(dir, "metrics.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mw.Close() })

	var closerCalls int
	factory := func(scenario, defender string, trial int, _ int64, _ string) (*Env, func() error, error) {
		env := &Env{Log: logger, Trial: trial, ScenarioName: scenario, DefenderName: defender,
			Config: config.WithDollarDefaults(config.TargetConfig{})}
		closer := func() error {
			closerCalls++
			logger.close() // exactly what the real closer does: frees the logger
			return nil
		}
		return env, closer, nil
	}
	runner := NewRunner(RunnerOptions{TrialsPerArm: 2, OutDir: dir, CleanupTimeout: 40 * time.Millisecond},
		factory, mw, nil)

	metrics, runErr := runner.Run(context.Background())
	if runErr == nil {
		t.Fatalf("the run continued past an unresolved cleanup")
	}
	if len(metrics) != 1 {
		t.Fatalf("emitted %d row(s); the unresolved trial must be written and then STOP the run", len(metrics))
	}

	v := metrics[0].MeasurementState()
	byStep := map[string]CleanupStep{}
	for _, s := range v.Cleanup.Attempted {
		byStep[s.Step] = s
	}
	if td := byStep["scenario.Teardown"]; !td.Unresolved {
		t.Fatalf("scenario.Teardown not recorded unresolved: %+v", v.Cleanup.Attempted)
	}
	for _, name := range []string{"defender.Stop", "defender.Teardown", "env.Close"} {
		s, ok := byStep[name]
		if !ok {
			t.Fatalf("%s missing from the cleanup record entirely; a blocked step must still be recorded: %+v",
				name, v.Cleanup.Attempted)
		}
		if !s.Blocked {
			t.Errorf("%s ran while scenario.Teardown still held the Env (blocked=%v unresolved=%v err=%q)",
				name, s.Blocked, s.Unresolved, s.Error)
		}
	}
	if closerCalls != 0 {
		t.Errorf("env.Close ran %d time(s) while the teardown still held the logger", closerCalls)
	}
	if _, stops, teardowns := arm.counts(); stops != 0 || teardowns != 0 {
		t.Errorf("defender cleanup ran during an unresolved step: stops=%d teardowns=%d", stops, teardowns)
	}
	if v.Cleanup.Complete || !v.Cleanup.Unresolved || v.Cleanup.Verified {
		t.Errorf("cleanup record claims too much: %+v", v.Cleanup)
	}
	if metrics[0].IsScored() {
		t.Errorf("a trial with unresolved cleanup was scored")
	}

	// Release the late callback and DRAIN it, so the test leaves nothing behind
	// and we can prove the logger was never freed underneath it.
	close(late.release)
	if n := runner.WaitForPendingCleanup(5 * time.Second); n != 1 {
		t.Errorf("late cleanups recorded = %d, want 1", n)
	}
	select {
	case <-late.finished:
	case <-time.After(5 * time.Second):
		t.Fatalf("the late teardown never returned")
	}
	if n := logger.afterFree(); n != 0 {
		t.Errorf("%d write(s) landed on a freed logger: the blocked ordering did not hold", n)
	}
	lc := runner.Outcome().LateCleanups
	if len(lc) != 1 || lc[0].Step != "scenario.Teardown" || !lc[0].Returned {
		t.Fatalf("late cleanup not retained with its real state: %+v", lc)
	}
}

// A late record that has NOT returned must say so. The CLI prints this verbatim,
// and "returned" for a call still running is the opposite of the truth.
func TestR2LateCleanupReportsWhetherItActuallyReturned(t *testing.T) {
	r := NewRunner(RunnerOptions{TrialsPerArm: 1, OutDir: t.TempDir()}, nil, nil, nil)
	done := make(chan error, 1)
	r.retainLateCleanup(Metric{Scenario: "s", Defender: "d", Trial: 0}, "env.Close", time.Now(), done)

	out := r.Outcome()
	if len(out.LateCleanups) != 1 {
		t.Fatalf("late cleanup not recorded: %+v", out.LateCleanups)
	}
	if out.LateCleanups[0].Returned {
		t.Fatalf("a call that has not returned was reported as returned: %+v", out.LateCleanups[0])
	}

	done <- fmt.Errorf("eventually failed")
	if n := r.WaitForPendingCleanup(5 * time.Second); n != 1 {
		t.Fatalf("drain reported %d late cleanup(s), want 1", n)
	}
	got := r.Outcome().LateCleanups[0]
	if !got.Returned || got.Error != "eventually failed" {
		t.Fatalf("late result not retained after it returned: %+v", got)
	}
}
