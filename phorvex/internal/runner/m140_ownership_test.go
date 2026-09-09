/*
 * M-140 head regressions (manager side). Each test asserts the FIXED behaviour and fails
 * against the pinned baseline aa5cfeffbe2348f2fea53bd5bacb5f350858df2d. The baseline
 * characterization forms are retained under
 * workflow/fixes/M-140/evidence/baseline/claude-baseline-runner_test.go.txt.
 */

package runner

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/slo"
)

func m140Policy(name, tenant, uid string) *v1alpha1.PhorvexPolicy {
	p := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: name, UID: types.UID(uid), Generation: 1,
	}}
	p.Spec.Tenant = tenant
	return p
}

func m140Manager(e *decision.CoverageEngine) *Manager {
	return &Manager{
		policies: map[string]*policyEntry{}, emits: map[string][]time.Time{},
		Optimizer: e, Clock: exposure.NewClock(), Intents: exposure.NewIntents(),
		Log: logr.Discard(),
	}
}

func m140View(pod string) *model.WorkloadView {
	return &model.WorkloadView{
		Pod:   model.Pod{Namespace: "ns", Name: pod, UID: "u-" + pod, DesiredReplicas: 3, ReadyReplicas: 3, Ready: true},
		Phase: model.PhaseWarm,
	}
}

func m140Updates(t *testing.T, e *decision.CoverageEngine, owner string) int {
	t.Helper()
	return e.CalibrationState()[owner].Updates
}

func m140TrainOwner(e *decision.CoverageEngine, owner string, n int) {
	e.SetOwnerLive(owner, true)
	for i := 0; i < n; i++ {
		e.ObserveRotation(owner, m140View("crown"), 0.5)
	}
}

func ownerOfUID(uid string) string { return model.OwnerKey(model.OwnerKindUID, uid) }

// Remove enqueues; the DRAIN completes the removal. Nothing may be reported as pruned at
// enqueue, and every store must be gone once the drain has run.
func TestM140_RemoveCompletesAtDrainNotAtEnqueue(t *testing.T) {
	e := decision.NewCoverageEngine()
	m := m140Manager(e)
	if err := m.Upsert(m140Policy("policy", "pxv1t", "uid-A")); err != nil {
		t.Fatal(err)
	}
	owner := ownerOfUID("uid-A")
	m140TrainOwner(e, owner, 5)

	now := time.Unix(1_700_000_000, 0).UTC()
	m.Clock.Observe(exposure.Observation{
		Owner: owner, Namespace: "ns", Pod: "crown", StartedAt: now.Add(-time.Hour),
		Fingerprints: map[string]string{model.VarPodIdentity: "fp"},
	}, now)

	m.Remove(types.NamespacedName{Namespace: "ns", Name: "policy"})

	// Enqueued only: the learned state is still present because the tick owns the engine.
	if m140Updates(t, e, owner) != 5 {
		t.Fatal("Remove pruned engine state on the controller goroutine; that races the tick loop")
	}
	if len(m.lifecycle) != 1 {
		t.Fatalf("lifecycle queue = %d events, want 1", len(m.lifecycle))
	}

	m.DrainLifecycle()

	if got := m140Updates(t, e, owner); got != 0 {
		t.Fatalf("cost bucket survived the drain: RLS updates = %d", got)
	}
	if m.Clock.Len() != 0 {
		t.Fatalf("exposure clock survived the drain: %d slots", m.Clock.Len())
	}
	if len(m.lifecycle) != 0 {
		t.Fatal("drain did not consume the queue")
	}
	if _, ok := m.epochs[owner]; ok {
		t.Fatal("epoch tombstone left behind after completed cleanup")
	}
}

// The coalesced recreate: one reconcile sees the NEW object, so Remove never runs. Upsert
// must detect the identity change and enqueue the predecessor's cleanup, or the new policy
// inherits the old one's economics and the old owner's stores leak forever.
func TestM140_CoalescedUpsertReplacementPrunesPredecessor(t *testing.T) {
	e := decision.NewCoverageEngine()
	m := m140Manager(e)
	if err := m.Upsert(m140Policy("policy", "pxv1t", "uid-A")); err != nil {
		t.Fatal(err)
	}
	oldOwner := ownerOfUID("uid-A")
	m140TrainOwner(e, oldOwner, 5)

	// No Remove in between: exactly the workqueue-coalesced sequence.
	if err := m.Upsert(m140Policy("policy", "pxv1t", "uid-B")); err != nil {
		t.Fatal(err)
	}
	m.DrainLifecycle()

	if got := m140Updates(t, e, oldOwner); got != 0 {
		t.Fatalf("predecessor state leaked after identity change: RLS updates = %d", got)
	}
	newOwner := ownerOfUID("uid-B")
	if got := m140Updates(t, e, newOwner); got != 0 {
		t.Fatalf("replacement inherited learned state: RLS updates = %d", got)
	}
	if m.policies[types.NamespacedName{Namespace: "ns", Name: "policy"}.String()].uid != "uid-B" {
		t.Fatal("registry did not take the new identity")
	}
}

// A same-UID PATCH is not a lifecycle event: no cleanup, no epoch bump, learning continues.
func TestM140_SameUIDPatchIsNotALifecycleEvent(t *testing.T) {
	e := decision.NewCoverageEngine()
	m := m140Manager(e)
	if err := m.Upsert(m140Policy("policy", "pxv1t", "uid-A")); err != nil {
		t.Fatal(err)
	}
	owner := ownerOfUID("uid-A")
	m140TrainOwner(e, owner, 4)
	epochBefore := m.epochs[owner]

	patched := m140Policy("policy", "pxv1t", "uid-A")
	patched.Generation = 2
	if err := m.Upsert(patched); err != nil {
		t.Fatal(err)
	}

	if len(m.lifecycle) != 0 {
		t.Fatal("a same-UID PATCH enqueued a lifecycle event")
	}
	if m.epochs[owner] != epochBefore {
		t.Fatalf("a same-UID PATCH bumped the epoch: %d -> %d", epochBefore, m.epochs[owner])
	}
	m.DrainLifecycle()
	if got := m140Updates(t, e, owner); got != 4 {
		t.Fatalf("PATCH destroyed continuous learning: RLS updates = %d, want 4", got)
	}
}

// Production identity is the UID. An object without one must be refused rather than silently
// falling back to the display name and reacquiring shared-bucket semantics.
func TestM140_UpsertRejectsPolicyWithoutUID(t *testing.T) {
	m := m140Manager(decision.NewCoverageEngine())
	p := m140Policy("policy", "pxv1t", "")
	if err := m.Upsert(p); err == nil {
		t.Fatal("Upsert accepted a policy with no UID")
	}
	if len(m.policies) != 0 {
		t.Fatal("a rejected policy was still registered")
	}
}

// Owner isolation, the R1 counterexample inverted: two policies sharing a display name in
// different namespaces, and two overlapping policies in ONE namespace. Removing either must
// leave the survivor's clocks and intents untouched.
func TestM140_RemovalDoesNotDisturbSurvivorSharingDisplayName(t *testing.T) {
	for _, tc := range []struct{ name, nsA, nsB string }{
		{"across namespaces", "a", "b"},
		{"same namespace overlap", "ns", "ns"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := decision.NewCoverageEngine()
			m := m140Manager(e)
			ownerA, ownerB := ownerOfUID("uid-A"), ownerOfUID("uid-B")
			now := time.Unix(1_700_000_000, 0).UTC()
			started := now.Add(-2 * time.Hour)

			obs := func(owner, ns, pod, fp string, at time.Time) {
				m.Clock.Observe(exposure.Observation{
					Owner: owner, Namespace: ns, Pod: pod, StartedAt: started,
					Fingerprints: map[string]string{model.VarPodIdentity: fp},
				}, at)
			}
			obs(ownerA, tc.nsA, "pa", "fp-a", started)
			obs(ownerB, tc.nsB, "pb", "fp-b1", started)
			obs(ownerB, tc.nsB, "pb", "fp-b2", now.Add(-5*time.Minute)) // real rotation 5m ago
			m.Intents.Mark(ownerB, tc.nsB, "pb", model.VarPodIdentity, now.Add(-5*time.Minute))

			before := m.Clock.Since(ownerB, tc.nsB, "pb", now)[model.VarPodIdentity]
			if before != 5*time.Minute {
				t.Fatalf("precondition: survivor age = %v, want 5m", before)
			}

			m.lifecycle = append(m.lifecycle, lifecycleEvent{owner: ownerA, tenant: "shared"})
			m.DrainLifecycle()

			obs(ownerB, tc.nsB, "pb", "fp-b2", now) // survivor's next tick
			if got := m.Clock.Since(ownerB, tc.nsB, "pb", now)[model.VarPodIdentity]; got != before {
				t.Fatalf("survivor exposure age changed: %v -> %v", before, got)
			}
			if got := m.Intents.Since(ownerB, tc.nsB, "pb", now)[model.VarPodIdentity]; got == 0 {
				t.Fatal("survivor emit intent was deleted with the other owner")
			}
		})
	}
}

// Ledger arm 1: nothing recorded yet, so exactly one honest unmeasured close.
func TestM140_PendingCloseWritesOneUnmeasuredEntryWhenNothingRecorded(t *testing.T) {
	e := decision.NewCoverageEngine()
	m := m140Manager(e)
	ledger := slo.NewLedger(30 * 24 * time.Hour)
	m.Disruption = ledger
	owner := ownerOfUID("uid-A")
	view := m140View("crown")
	m.pendingRotations = map[string]pendingRotation{
		rotationObservationKey(owner, view): {
			owner: owner, tenant: "pxv1t", ledgerID: rotationLedgerID("pxv1t", view),
			startedAt: time.Unix(1_700_000_000, 0).UTC(), view: *view, ledgerRecorded: false,
		},
	}

	m.lifecycle = append(m.lifecycle, lifecycleEvent{owner: owner, tenant: "pxv1t"})
	m.DrainLifecycle()

	entries := ledger.Entries("pxv1t", time.Time{})
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want exactly 1", len(entries))
	}
	if entries[0].Outcome != slo.OutcomeEmitted {
		t.Fatalf("outcome = %q, want %q", entries[0].Outcome, slo.OutcomeEmitted)
	}
	if entries[0].ReplicaImpact != slo.ImpactUnmeasured {
		t.Fatalf("impact = %q, want unmeasured", entries[0].ReplicaImpact)
	}
	if len(m.pendingRotations) != 0 {
		t.Fatal("pending entry was not dropped")
	}
	// Repeated removal writes nothing further.
	m.lifecycle = append(m.lifecycle, lifecycleEvent{owner: owner, tenant: "pxv1t"})
	m.DrainLifecycle()
	if got := len(ledger.Entries("pxv1t", time.Time{})); got != 1 {
		t.Fatalf("repeated removal wrote more entries: %d", got)
	}
}

// Ledger arm 2, the sharp one: an entry already exists, so the close must not touch the
// ledger at all. Record REPLACES on an ID match, so a same-ID unmeasured close would erase
// the measured floor, and a new ID would double-count the same event.
func TestM140_PendingCloseNeverOverwritesMeasuredHistory(t *testing.T) {
	e := decision.NewCoverageEngine()
	m := m140Manager(e)
	ledger := slo.NewLedger(30 * 24 * time.Hour)
	m.Disruption = ledger
	owner := ownerOfUID("uid-A")
	view := m140View("crown")
	started := time.Unix(1_700_000_000, 0).UTC()
	id := rotationLedgerID("pxv1t", view)

	measured := slo.Entry{
		ID: id, Tenant: "pxv1t", Namespace: "ns", Pod: "crown",
		Action: model.ActionRotate, Cause: slo.CausePhorvex,
		Replicas: 1, Duration: 100 * time.Second,
		StartedAt: started, ObservedAt: started.Add(100 * time.Second),
		Censored: true, Outcome: slo.OutcomeRightCensored, ReplicaImpact: slo.ImpactMeasured,
	}
	ledger.Record(measured)
	before := ledger.Entries("pxv1t", time.Time{})[0]

	m.pendingRotations = map[string]pendingRotation{
		rotationObservationKey(owner, view): {
			owner: owner, tenant: "pxv1t", ledgerID: id,
			startedAt: started, view: *view, ledgerRecorded: true,
		},
	}
	m.lifecycle = append(m.lifecycle, lifecycleEvent{owner: owner, tenant: "pxv1t"})
	m.DrainLifecycle()

	entries := ledger.Entries("pxv1t", time.Time{})
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1 (no duplicate under a new ID)", len(entries))
	}
	got := entries[0]
	if got.Duration != before.Duration || got.Outcome != before.Outcome ||
		got.ReplicaImpact != before.ReplicaImpact || !got.ObservedAt.Equal(before.ObservedAt) ||
		got.Censored != before.Censored {
		t.Fatalf("measured history was overwritten:\n before %+v\n after  %+v", before, got)
	}
	if len(m.pendingRotations) != 0 {
		t.Fatal("pending entry was not dropped")
	}
}

// Display-name collisions are reported, not silently merged, and the count clears when the
// name becomes unique again.
func TestM140_OwnerCountTracksDisplayNameCollisions(t *testing.T) {
	m := m140Manager(decision.NewCoverageEngine())
	if err := m.Upsert(m140Policy("first", "shared", "uid-A")); err != nil {
		t.Fatal(err)
	}
	if !m.uniqueOwnerOf("shared") {
		t.Fatal("one policy should be the unique owner of its display name")
	}
	if err := m.Upsert(m140Policy("second", "shared", "uid-B")); err != nil {
		t.Fatal(err)
	}
	if m.uniqueOwnerOf("shared") {
		t.Fatal("two policies sharing a display name were reported as unique")
	}
	if got := m.ownersOf("shared"); got != 2 {
		t.Fatalf("owner count = %d, want 2", got)
	}
	m.Remove(types.NamespacedName{Namespace: "ns", Name: "second"})
	m.DrainLifecycle()
	if !m.uniqueOwnerOf("shared") {
		t.Fatal("uniqueness did not return after the collision was resolved")
	}
}

// Concurrency: lifecycle events arriving from the controller goroutine WHILE the tick loop
// is inside decision work must not race, must not be lost, and must not prune anything
// before the drain. Run under -race; the contract's "no stale allocation after completion"
// is asserted after the drain completes.
func TestM140_LifecycleEventsDuringInFlightProcessingAreSafe(t *testing.T) {
	e := decision.NewCoverageEngine()
	m := m140Manager(e)

	const owners = 24
	for i := 0; i < owners; i++ {
		uid := "uid-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		if err := m.Upsert(m140Policy("policy-"+uid, "shared", uid)); err != nil {
			t.Fatal(err)
		}
		m140TrainOwner(e, ownerOfUID(uid), 2)
	}

	// The controller goroutine churns identities while the tick goroutine drains and reads.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < owners; i++ {
			uid := "uid-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
			name := "policy-" + uid
			if i%2 == 0 {
				m.Remove(types.NamespacedName{Namespace: "ns", Name: name})
				continue
			}
			// Replacement without a preceding NotFound reconcile.
			if err := m.Upsert(m140Policy(name, "shared", uid+"-next")); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 50; i++ {
		m.DrainLifecycle()
		m.publishOwnership()
		_ = m.uniqueOwnerOf("shared")
	}
	<-done
	m.DrainLifecycle()

	// Every retired identity is gone from both the engine and the epoch table: churn must
	// not trade a bucket leak for a tombstone leak.
	for i := 0; i < owners; i++ {
		uid := "uid-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		if got := m140Updates(t, e, ownerOfUID(uid)); got != 0 {
			t.Fatalf("owner %s survived churn with %d RLS updates", uid, got)
		}
	}
	m.mu.RLock()
	epochs, policies := len(m.epochs), len(m.policies)
	m.mu.RUnlock()
	if epochs != policies {
		t.Fatalf("epoch table did not track live policies: %d epochs for %d policies", epochs, policies)
	}
	if len(m.lifecycle) != 0 {
		t.Fatalf("lifecycle queue not drained: %d events", len(m.lifecycle))
	}
}
