/*
 * M-140 R2.3 — real blocked-tick coverage.
 *
 * The earlier lifecycle tests called ownerEpoch/Remove/ownerCurrent/DrainLifecycle in
 * sequence. They never ran a tick and never blocked a producer, so they proved ordering by
 * construction rather than by observation. These do: a real tick is held inside
 * MetricsSource.PodMetrics — an actual per-tick producer call — while the controller
 * goroutine issues a Remove or a replacement Upsert, and only then is the tick released.
 */

package runner

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// blockingSource holds the tick inside a genuine producer call until released.
type blockingSource struct {
	entered  chan struct{}
	release  chan struct{}
	onceDone bool
}

func (*blockingSource) Name() string { return "m140-blocking-source" }

func (b *blockingSource) PodMetrics(ctx context.Context, ns string, pods []string) (map[string]model.Telemetry, error) {
	if !b.onceDone {
		b.onceDone = true
		close(b.entered)
		<-b.release
	}
	return map[string]model.Telemetry{}, nil
}

func m140BlockedTickManager(t *testing.T, src ingest.MetricsSource, policies ...*v1alpha1.PhorvexPolicy) (*Manager, *decision.CoverageEngine) {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		v1alpha1.AddToScheme, corev1.AddToScheme, networkingv1.AddToScheme, rbacv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "crown", UID: "u-crown"},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	objects := []client.Object{pod}
	for _, p := range policies {
		objects = append(objects, p)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).WithObjects(objects...).Build()
	e := decision.NewCoverageEngine()
	m := NewManager(c, logr.Discard())
	m.Optimizer = e
	m.MetricsSource = src
	m.Clock = exposure.NewClock()
	m.Intents = exposure.NewIntents()
	return m, e
}

// A Remove that lands WHILE a real tick is blocked inside a producer must not be lost, must
// not take effect before the tick finishes, and must be completed by the following drain.
func TestM140_RemoveDuringBlockedRealTick(t *testing.T) {
	src := &blockingSource{entered: make(chan struct{}), release: make(chan struct{})}
	policy := m140Policy("policy", "pxv1t", "uid-A")
	m, e := m140BlockedTickManager(t, src, policy)

	if err := m.Upsert(policy); err != nil {
		t.Fatal(err)
	}
	owner := ownerOfUID("uid-A")
	m140TrainOwner(e, owner, 5)

	done := make(chan struct{})
	go func() { defer close(done); m.tick(context.Background()) }()

	select {
	case <-src.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("tick never reached the blocking producer")
	}

	// Controller goroutine acts while the tick is genuinely mid-flight.
	m.Remove(types.NamespacedName{Namespace: "ns", Name: "policy"})
	if got := m140Updates(t, e, owner); got != 5 {
		t.Fatalf("Remove pruned engine state from the controller goroutine mid-tick: %d", got)
	}

	close(src.release)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("tick did not complete after release")
	}

	// The event survived the in-flight tick and completes at the next drain.
	m.DrainLifecycle()
	if got := m140Updates(t, e, owner); got != 0 {
		t.Fatalf("state survived a Remove issued during a blocked tick: %d", got)
	}
	if m.ownerCurrent(owner, 1) {
		t.Fatal("a removed owner still validated at its original generation")
	}
}

// A replacement Upsert during a blocked tick must retire the predecessor and must not let
// the replacement inherit its state or its captured generation.
func TestM140_ReplacementDuringBlockedRealTick(t *testing.T) {
	src := &blockingSource{entered: make(chan struct{}), release: make(chan struct{})}
	first := m140Policy("policy", "pxv1t", "uid-A")
	m, e := m140BlockedTickManager(t, src, first)

	if err := m.Upsert(first); err != nil {
		t.Fatal(err)
	}
	oldOwner := ownerOfUID("uid-A")
	m140TrainOwner(e, oldOwner, 4)
	oldEpoch := m.ownerEpoch(oldOwner)

	done := make(chan struct{})
	go func() { defer close(done); m.tick(context.Background()) }()
	select {
	case <-src.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("tick never reached the blocking producer")
	}

	// Replacement with no intervening Remove, mid-tick.
	if err := m.Upsert(m140Policy("policy", "pxv1t", "uid-B")); err != nil {
		t.Fatal(err)
	}
	close(src.release)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("tick did not complete after release")
	}
	m.DrainLifecycle()

	newOwner := ownerOfUID("uid-B")
	if got := m140Updates(t, e, oldOwner); got != 0 {
		t.Fatalf("predecessor state survived a mid-tick replacement: %d", got)
	}
	if got := m140Updates(t, e, newOwner); got != 0 {
		t.Fatalf("replacement inherited learned state: %d", got)
	}
	// Late feedback stamped with the predecessor's captured identity AND generation must be
	// refused. Note the stamp carries both: generations are per-owner, so the replacement
	// legitimately starts at its own generation 1, and comparing that number across two
	// different owner keys would be meaningless.
	if m.ownerCurrent(oldOwner, oldEpoch) {
		t.Fatal("feedback captured under the retired identity was accepted after replacement")
	}
	if _, stale := m.epochs[oldOwner]; stale {
		t.Fatal("the retired identity kept a generation entry after cleanup")
	}
	if m.ownerEpoch(newOwner) == 0 {
		t.Fatal("the replacement was not given its own generation")
	}
}

// Late rotation feedback emitted before a removal must be dropped by the generation guard
// once the removal completes — through the real pending-rotation path.
func TestM140_LateRotationFeedbackAfterRemovalIsDropped(t *testing.T) {
	src := &blockingSource{entered: make(chan struct{}), release: make(chan struct{})}
	third := m140Policy("policy", "pxv1t", "uid-A")
	m, e := m140BlockedTickManager(t, src, third)
	if err := m.Upsert(third); err != nil {
		t.Fatal(err)
	}
	owner := ownerOfUID("uid-A")
	m140TrainOwner(e, owner, 2)

	view := m140View("crown")
	// trackRotationWithFloor needs controller-owned identity to match a replacement.
	view.Pod.OwnerKind, view.Pod.OwnerName = "ReplicaSet", "api-rs"
	started := time.Unix(1_700_000_000, 0).UTC()
	if !m.trackRotationWithFloor(owner, "pxv1t", view,
		map[string]*model.WorkloadView{"ns/crown": view}, 1, started) {
		t.Fatal("rotation was not tracked")
	}
	pending := m.pendingRotations[rotationObservationKey(owner, view)]
	if pending.epoch == 0 {
		t.Fatal("pending rotation was not stamped with a generation")
	}

	m.Remove(types.NamespacedName{Namespace: "ns", Name: "policy"})
	m.DrainLifecycle()

	if m.ownerCurrent(pending.owner, pending.epoch) {
		t.Fatal("feedback emitted before removal was still accepted afterwards")
	}
	if got := m140Updates(t, e, owner); got != 0 {
		t.Fatalf("late feedback trained a removed owner: %d", got)
	}
	close(src.release)
}
