package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	v1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/inprocess"
)

// actuated_window_test.go — PHORVEXSEC-176 / M-11.
//
// Status.Actuated was a write-once latch (true forever after the first emit) and
// Status.MovesThisWindow was the number of decisions SELECTED this tick, not the number
// ENACTED in the AntiOverRotationWindow the field is documented against. Both must be
// rolling: they describe the trailing window, count only emitted moves, and return to
// zero/false once the window passes without an emit.

type statusHarness struct {
	m *Manager
	e *policyEntry
}

func newStatusHarness(t *testing.T, window time.Duration) statusHarness {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "win", Name: "policy"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.PhorvexPolicy{}).WithObjects(policy).Build()
	e := &policyEntry{key: types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}, tenant: "tenant-a"}
	e.spec.Budget.AntiOverRotationWindow = metav1.Duration{Duration: window}
	return statusHarness{m: &Manager{Local: &inprocess.Services{}, Client: c, Log: logr.Discard()}, e: e}
}

func (h statusHarness) tick(t *testing.T, moves, actuated int, now time.Time) v1.PhorvexPolicyStatus {
	t.Helper()
	h.m.updateStatus(context.Background(), h.e, 3, moves, actuated, false, now)
	var got v1.PhorvexPolicy
	if err := h.m.Client.Get(context.Background(), h.e.key, &got); err != nil {
		t.Fatal(err)
	}
	return got.Status
}

func TestActuatedIsRollingWindowNotLatch(t *testing.T) {
	const window = 5 * time.Minute
	h := newStatusHarness(t, window)
	t0 := time.Unix(1_000_000, 0)

	st := h.tick(t, 1, 1, t0)
	if !st.Actuated || st.MovesThisWindow != 1 {
		t.Fatalf("after one emit: actuated=%v moves=%d, want true/1", st.Actuated, st.MovesThisWindow)
	}
	st = h.tick(t, 0, 0, t0.Add(window/2))
	if !st.Actuated || st.MovesThisWindow != 1 {
		t.Fatalf("inside the window with no new emit: actuated=%v moves=%d, want true/1 (the emit is still in the window)", st.Actuated, st.MovesThisWindow)
	}
	st = h.tick(t, 0, 0, t0.Add(window+time.Second))
	if st.Actuated || st.MovesThisWindow != 0 {
		t.Fatalf("window elapsed without an emit: actuated=%v moves=%d, want false/0 (old behavior: write-once latch)", st.Actuated, st.MovesThisWindow)
	}
}

func TestMovesThisWindowCountsEnactedNotSelected(t *testing.T) {
	h := newStatusHarness(t, 5*time.Minute)
	st := h.tick(t, 3, 1, time.Unix(1_000_000, 0))
	if st.MovesThisWindow != 1 {
		t.Fatalf("3 selected / 1 enacted: movesThisWindow=%d, want 1 (old behavior counted selected)", st.MovesThisWindow)
	}
	if st.DecisionsTotal != 3 {
		t.Fatalf("decisionsTotal must keep counting DECIDED moves: got %d, want 3", st.DecisionsTotal)
	}
	if !st.Actuated {
		t.Fatalf("one enacted move must report actuated=true")
	}
}

func TestSelectedButNotEnactedNeverReportsActuated(t *testing.T) {
	h := newStatusHarness(t, 5*time.Minute)
	st := h.tick(t, 4, 0, time.Unix(1_000_000, 0))
	if st.Actuated || st.MovesThisWindow != 0 {
		t.Fatalf("dry-run/kill-switch/failed actuation (selected=4, enacted=0): actuated=%v moves=%d, want false/0", st.Actuated, st.MovesThisWindow)
	}
}

func TestMovesThisWindowAccumulatesAcrossTicksInsideWindow(t *testing.T) {
	const window = 5 * time.Minute
	h := newStatusHarness(t, window)
	t0 := time.Unix(1_000_000, 0)
	h.tick(t, 1, 1, t0)
	h.tick(t, 2, 2, t0.Add(time.Minute))
	st := h.tick(t, 1, 1, t0.Add(2*time.Minute))
	if st.MovesThisWindow != 4 {
		t.Fatalf("three ticks inside one window (1+2+1 enacted): movesThisWindow=%d, want 4", st.MovesThisWindow)
	}
	// The first tick's emit ages out; the later three remain.
	st = h.tick(t, 0, 0, t0.Add(window+time.Second))
	if st.MovesThisWindow != 3 || !st.Actuated {
		t.Fatalf("after the first emit aged out: moves=%d actuated=%v, want 3/true", st.MovesThisWindow, st.Actuated)
	}
	st = h.tick(t, 0, 0, t0.Add(2*window+3*time.Minute))
	if st.MovesThisWindow != 0 || st.Actuated {
		t.Fatalf("after every emit aged out: moves=%d actuated=%v, want 0/false", st.MovesThisWindow, st.Actuated)
	}
}

func TestActuatedDoesNotSurviveARestartAsALatch(t *testing.T) {
	h := newStatusHarness(t, 5*time.Minute)
	t0 := time.Unix(1_000_000, 0)
	h.tick(t, 1, 1, t0)
	// A new Manager (restart / leadership change) has no ledger. It must not inherit
	// the persisted latch: it can only under-report, never claim an emit it did not see.
	fresh := &Manager{Local: &inprocess.Services{}, Client: h.m.Client, Log: logr.Discard()}
	fresh.updateStatus(context.Background(), h.e, 3, 0, 0, false, t0.Add(time.Second))
	var got v1.PhorvexPolicy
	if err := h.m.Client.Get(context.Background(), h.e.key, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Actuated || got.Status.MovesThisWindow != 0 {
		t.Fatalf("restarted manager inherited the latch: actuated=%v moves=%d, want false/0", got.Status.Actuated, got.Status.MovesThisWindow)
	}
}

func TestStatusConflictRetryDoesNotDoubleCountEmits(t *testing.T) {
	// The status write is retried on conflict and the closure re-runs; the emit ledger must
	// be written exactly once per tick regardless of how many attempts the write takes.
	scheme := runtime.NewScheme()
	if err := v1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	policy := &v1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "win", Name: "conflict"}}
	attempts := 0
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&v1.PhorvexPolicy{}).WithObjects(policy).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, delegate client.Client, subresource string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				attempts++
				if attempts == 1 {
					return apierrors.NewConflict(schema.GroupResource{Group: "phorvex.ai", Resource: "phorvexpolicies"}, obj.GetName(), errors.New("injected conflict"))
				}
				return delegate.SubResource(subresource).Update(ctx, obj, opts...)
			},
		}).Build()
	m := &Manager{Local: &inprocess.Services{}, Client: c, Log: logr.Discard()}
	e := &policyEntry{key: types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}}
	t0 := time.Unix(1_000_000, 0)
	m.updateStatus(context.Background(), e, 3, 2, 2, false, t0)
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	var got v1.PhorvexPolicy
	if err := c.Get(context.Background(), e.key, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.MovesThisWindow != 2 || !got.Status.Actuated {
		t.Fatalf("after one conflict retry: moves=%d actuated=%v, want 2/true (not double-counted)", got.Status.MovesThisWindow, got.Status.Actuated)
	}
	m.updateStatus(context.Background(), e, 3, 0, 0, false, t0.Add(time.Second))
	if err := c.Get(context.Background(), e.key, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.MovesThisWindow != 2 {
		t.Fatalf("a no-emit tick changed the count: %d, want 2", got.Status.MovesThisWindow)
	}
}
