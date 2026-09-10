package main

// finalize_test.go — the RUN-LEVEL teardown honours the same ownership barrier
// the per-trial cleanup enforces (V3-M161).
//
// The per-trial fix stopped later cleanup steps from starting while an earlier
// one still held the Env. The run-level path had the same hole: after a bounded
// drain it printed "STILL RUNNING" for a call that had not returned and then
// deleted that call's namespace anyway. Deleting the namespace under a live
// callback races it, and a teardown that merely collided with one is not a
// verified teardown.
//
// Both controls go through the ACTUAL helper the command calls.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktest "k8s.io/client-go/testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

// allowSandbox is the safety gate; the real one refuses anything but the
// configured namespace, and so does this.
type allowSandbox struct{}

func (allowSandbox) AssertMutationAllowed(ns string) error {
	if ns != "sandbox" {
		return errors.New("REFUSED: " + ns + " is not the sandbox namespace")
	}
	return nil
}

type quietLogger struct{ cmds []string }

func (l *quietLogger) Logf(string, ...any) {}
func (l *quietLogger) Command(c string)    { l.cmds = append(l.cmds, c) }
func (l *quietLogger) Commands() []string  { return l.cmds }
func (l *quietLogger) RawLogPath() string  { return "" }

// countingFactory reports whether the run-level teardown actually reached the
// cluster, and whether its closer ran.
type countingFactory struct {
	built  int
	closed int
	// deleteErr makes the API refuse every call, so the teardown cannot verify.
	deleteErr bool
	// hangClose makes the context-free closer never return.
	hangClose bool
}

func (f *countingFactory) build(scenario, defender string, trial int, _ int64, _ string) (*core.Env, func() error, error) {
	f.built++
	kube := fake.NewSimpleClientset()
	if f.deleteErr {
		kube.PrependReactor("*", "*", func(ktest.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("final teardown API unavailable")
		})
	}
	env := &core.Env{
		Kube:   kube,
		Config: config.WithDollarDefaults(config.TargetConfig{Namespace: "sandbox", Context: "kind-test", OwnedAck: true}),
		Log:    &quietLogger{},
		Guard:  allowSandbox{},
		Trial:  trial, ScenarioName: scenario, DefenderName: defender,
	}
	closer := func() error {
		f.closed++
		if f.hangClose {
			select {} // never returns: the context-free closer that must be bounded
		}
		return nil
	}
	return env, closer, nil
}

// liveLate is a cleanup call this run still owns: it has NOT returned.
func liveLate() []core.LateCleanup {
	return []core.LateCleanup{{
		Scenario: "s1", Defender: "d-arm", Trial: 0, Step: "scenario.Teardown",
		Seconds: 120.0, Returned: false,
	}}
}

// drainedLate is a call that outlived its bound but HAS since returned, so it no
// longer owns anything.
func drainedLate() []core.LateCleanup {
	return []core.LateCleanup{{
		Scenario: "s1", Defender: "d-arm", Trial: 0, Step: "scenario.Teardown",
		Seconds: 120.0, Returned: true,
	}}
}

// LIVE-LATE: the namespace is still owned, so the teardown must be REFUSED —
// not attempted, not verified — and the reason must name the call that holds it.
func TestFinalizeRunIsBlockedWhileCleanupIsStillRunning(t *testing.T) {
	f := &countingFactory{}
	err, attempted := finalizeRun(context.Background(), liveLate(), f.build, t.TempDir())
	if attempted {
		t.Fatalf("the final teardown ran while a cleanup call still owned the namespace")
	}
	if err == nil {
		t.Fatalf("a refused teardown must explain itself")
	}
	if f.built != 0 || f.closed != 0 {
		t.Errorf("the teardown reached the cluster anyway: built=%d closed=%d", f.built, f.closed)
	}
	for _, want := range []string{"have not returned", "still hold the sandbox namespace", "scenario.Teardown"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not disclose %q: %v", want, err)
		}
	}
}

// DRAINED-LATE (positive control): the same call, now returned, owns nothing —
// so the teardown proceeds and verifies.
func TestFinalizeRunProceedsOnceLateCleanupHasReturned(t *testing.T) {
	for _, tc := range []struct {
		name string
		late []core.LateCleanup
	}{
		{"no-late-cleanup", nil},
		{"late-but-drained", drainedLate()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &countingFactory{}
			err, attempted := finalizeRun(context.Background(), tc.late, f.build, t.TempDir())
			if !attempted {
				t.Fatalf("the teardown was refused although nothing was still running: %v", err)
			}
			if err != nil {
				t.Fatalf("a clean final teardown must verify: %v", err)
			}
			if f.built != 1 || f.closed != 1 {
				t.Errorf("the real chain did not run: built=%d closed=%d", f.built, f.closed)
			}
		})
	}
}

// An attempted teardown that fails is still ATTEMPTED, and reports the failure.
func TestFinalizeRunReportsAnAttemptedTeardownThatFails(t *testing.T) {
	f := &countingFactory{deleteErr: true}
	err, attempted := finalizeRun(context.Background(), nil, f.build, t.TempDir())
	if !attempted {
		t.Fatalf("a teardown blocked by nothing must be attempted")
	}
	if err == nil {
		t.Fatalf("a failing teardown must not verify")
	}
	if !strings.Contains(err.Error(), "final teardown API unavailable") {
		t.Errorf("the underlying API failure was not propagated: %v", err)
	}
}

// The closer takes no context, so the only way it cannot hang the command
// forever is for the wait itself to be bounded.
func TestBoundedCloseDoesNotHangOnAContextFreeCloser(t *testing.T) {
	t.Run("prompt-closer", func(t *testing.T) {
		if err := boundedClose(func() error { return nil }); err != nil {
			t.Fatalf("a prompt closer must succeed: %v", err)
		}
	})
	t.Run("failing-closer", func(t *testing.T) {
		err := boundedClose(func() error { return errors.New("logger close failed") })
		if err == nil || !strings.Contains(err.Error(), "logger close failed") {
			t.Fatalf("a closer error must propagate: %v", err)
		}
	})
	t.Run("hanging-closer", func(t *testing.T) {
		// boundedClose delegates to boundedCloseWithin under the shared cleanup
		// budget, which is minutes — far too long for a test. Drive the same
		// function with a short bound instead of duplicating its logic.
		//
		// The closer blocks on a RELEASE CHANNEL rather than `select {}`: a test
		// must not leave an immortal goroutine behind, and draining it afterwards
		// also proves the buffered hand-off lets the abandoned call finish
		// without blocking.
		release := make(chan struct{})
		closerReturned := make(chan struct{})
		closer := func() error {
			<-release
			close(closerReturned)
			return nil
		}

		done := make(chan error, 1)
		go func() { done <- boundedCloseWithin(closer, 40*time.Millisecond) }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "did not return within") {
				t.Fatalf("a hanging closer must be reported UNRESOLVED, got %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("boundedClose hung on a context-free closer")
		}

		// Release and drain: nothing outlives the test.
		close(release)
		select {
		case <-closerReturned:
		case <-time.After(5 * time.Second):
			t.Fatalf("the released closer never returned")
		}
	})
}
