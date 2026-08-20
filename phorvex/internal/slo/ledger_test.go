/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package slo

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func at(base time.Time, d time.Duration) time.Time { return base.Add(d) }

func TestConsumedIsReplicasTimesDuration(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: 30 * time.Second, ObservedAt: base})
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 2, Duration: 10 * time.Second, ObservedAt: at(base, time.Minute)})

	if got, want := l.Consumed("t1", base.Add(-time.Hour)), 50.0; got != want {
		t.Fatalf("consumed = %v replica-seconds, want %v", got, want)
	}
	// A different tenant's disruption is not this tenant's problem.
	if got := l.Consumed("t2", base.Add(-time.Hour)); got != 0 {
		t.Fatalf("tenant isolation broken: t2 consumed %v", got)
	}
}

// `since` is what makes the ledger honest about the SLO window: consumption from
// before the window must not count towards it.
func TestConsumedRespectsTheWindowStart(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: time.Minute, ObservedAt: base})
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: time.Minute, ObservedAt: at(base, 48*time.Hour)})

	if got, want := l.Consumed("t1", at(base, 24*time.Hour)), 60.0; got != want {
		t.Fatalf("only in-window consumption counts: got %v want %v", got, want)
	}
}

func TestConsumedCountsOnlyDurationOverlappingWindow(t *testing.T) {
	boundary := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{
		Tenant: "t1", Action: model.ActionRotate, Replicas: 1,
		StartedAt: boundary.Add(-10 * time.Second), ObservedAt: boundary.Add(10 * time.Second),
		Duration: 20 * time.Second,
	})

	if got, want := l.Consumed("t1", boundary), 10.0; got != want {
		t.Fatalf("boundary-crossing consumption = %v, want only %v in-window replica-seconds", got, want)
	}
}

// A censored reading is a floor on how bad recovery was, not a reason to forget
// it. Dropping censored entries would understate consumption exactly when
// recovery went worst.
func TestCensoredEntriesStillConsumeBudget(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: 800 * time.Second, ObservedAt: base, Censored: true})

	if got, want := l.Consumed("t1", base.Add(-800*time.Second)), 800.0; got != want {
		t.Fatalf("censored entry must still count: got %v want %v", got, want)
	}
	e := l.Entries("t1", base)
	if len(e) != 1 || !e[0].Censored {
		t.Fatalf("censored flag lost on read back: %+v", e)
	}
}

func TestCensoredEntryIsUpdatedInsteadOfPermanentlyUndercounted(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{ID: "rotation-1", Tenant: "t1", Action: model.ActionRotate, Replicas: 1,
		StartedAt: base, ObservedAt: base.Add(800 * time.Second), Duration: 800 * time.Second, Censored: true})
	l.Record(Entry{ID: "rotation-1", Tenant: "t1", Action: model.ActionRotate, Replicas: 1,
		StartedAt: base, ObservedAt: base.Add(1200 * time.Second), Duration: 1200 * time.Second, Censored: true})

	if got, want := l.Consumed("t1", base), 1200.0; got != want {
		t.Fatalf("updated censored consumption = %v, want %v", got, want)
	}
	entries := l.Entries("t1", base)
	if len(entries) != 1 || entries[0].Duration != 1200*time.Second {
		t.Fatalf("censored upsert produced %+v, want one extended entry", entries)
	}

	l.Record(Entry{ID: "rotation-1", Tenant: "t1", Action: model.ActionRotate, Replicas: 1,
		StartedAt: base, ObservedAt: base.Add(1300 * time.Second), Duration: 1300 * time.Second})
	entries = l.Entries("t1", base)
	if len(entries) != 1 || entries[0].Censored || entries[0].Duration != 1300*time.Second {
		t.Fatalf("final recovery did not replace censored floor: %+v", entries)
	}
}

// Nothing removed or nothing measured means nothing consumed.
func TestZeroImpactEntriesAreNotRecorded(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{Tenant: "t1", Action: model.ActionKVReset, Replicas: 0, Duration: time.Minute, ObservedAt: base})
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: 0, ObservedAt: base})

	if got := l.Consumed("t1", base.Add(-time.Hour)); got != 0 {
		t.Fatalf("expected nothing recorded, consumed %v", got)
	}
	if n := len(l.Entries("t1", base.Add(-time.Hour))); n != 0 {
		t.Fatalf("expected no entries, got %d", n)
	}
}

func TestPerActionBreakdown(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: 20 * time.Second, ObservedAt: base})
	l.Record(Entry{Tenant: "t1", Action: model.ActionQuarantine, Replicas: 1, Duration: 5 * time.Second, ObservedAt: base})
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: 10 * time.Second, ObservedAt: base})

	by := l.ConsumedByAction("t1", base.Add(-time.Hour))
	if by[model.ActionRotate] != 30 {
		t.Fatalf("rotate = %v, want 30", by[model.ActionRotate])
	}
	if by[model.ActionQuarantine] != 5 {
		t.Fatalf("quarantine = %v, want 5", by[model.ActionQuarantine])
	}
}

func TestRetentionEvictsBeyondTheWindow(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(24 * time.Hour)
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: time.Minute, ObservedAt: base})
	// A later write moves the clock forward and evicts what fell out of retention.
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: time.Minute, ObservedAt: at(base, 48*time.Hour)})

	if n := len(l.Entries("t1", time.Time{})); n != 1 {
		t.Fatalf("expected the stale entry evicted, %d remain", n)
	}
}

// Default cause: an entry written without one is Phorvex's own doing, because
// this ledger only ever observes Phorvex's actuations.
func TestCauseDefaultsToPhorvex(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: time.Second, ObservedAt: base})
	e := l.Entries("t1", base)
	if len(e) != 1 || e[0].Cause != CausePhorvex {
		t.Fatalf("expected cause=%s, got %+v", CausePhorvex, e)
	}
}

func TestReplicaDisruptionAndAvailabilityBreachAreSeparate(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	// One replica is unavailable for 30s, but the service stays at its floor.
	l.Record(Entry{
		ID: "headroom", Tenant: "t1", Action: model.ActionRotate,
		Replicas: 1, Duration: 30 * time.Second, StartedAt: base, ObservedAt: base.Add(30 * time.Second),
		ReadyReplicasBefore: 3, MinAvailableReplicas: 2, AvailabilityMeasured: true,
	})
	// The same disruption on a one-replica service breaches availability throughout.
	l.Record(Entry{
		ID: "breach", Tenant: "t1", Action: model.ActionRotate,
		Replicas: 1, Duration: 20 * time.Second,
		StartedAt: base.Add(time.Minute), ObservedAt: base.Add(80 * time.Second),
		ReadyReplicasBefore: 1, MinAvailableReplicas: 1, AvailabilityMeasured: true,
		AvailabilityBreachDuration:  20 * time.Second,
		AvailabilityBreachStartedAt: base.Add(time.Minute), AvailabilityBreachObservedAt: base.Add(80 * time.Second),
	})

	got := l.ConsumedImpact("t1", base)
	if got.ReplicaSeconds != 50 || got.AvailabilityBreachSeconds != 20 {
		t.Fatalf("consumption mixed dimensions: %+v", got)
	}
	if got.AvailabilityMeasuredEntries != 2 || got.AvailabilityUnmeasuredEntries != 0 {
		t.Fatalf("availability evidence counts = %+v", got)
	}
}

func TestAvailabilityWindowCountsOnlyOverlappingBreach(t *testing.T) {
	boundary := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{
		Tenant: "t1", Action: model.ActionRotate,
		Replicas: 1, Duration: 20 * time.Second,
		StartedAt: boundary.Add(-10 * time.Second), ObservedAt: boundary.Add(10 * time.Second),
		AvailabilityMeasured: true, AvailabilityBreachDuration: 20 * time.Second,
		AvailabilityBreachStartedAt:  boundary.Add(-10 * time.Second),
		AvailabilityBreachObservedAt: boundary.Add(10 * time.Second),
	})
	got := l.ConsumedImpact("t1", boundary)
	if got.ReplicaSeconds != 10 || got.AvailabilityBreachSeconds != 10 {
		t.Fatalf("window overlap = %+v, want 10 replica-seconds and 10 breach-seconds", got)
	}
}

func TestMissingAvailabilityEvidenceIsNotReportedAsMeasuredZero(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{
		Tenant: "t1", Action: model.ActionRotate, Replicas: 1,
		Duration: 10 * time.Second, StartedAt: base, ObservedAt: base.Add(10 * time.Second),
	})
	got := l.ConsumedImpact("t1", base)
	if got.AvailabilityMeasuredEntries != 0 || got.AvailabilityUnmeasuredEntries != 1 {
		t.Fatalf("missing availability evidence was laundered to zero: %+v", got)
	}
	entry := l.Entries("t1", base)[0]
	if value, measured := entry.AvailabilityBreachSeconds(); measured || value != 0 {
		t.Fatalf("entry availability = %v, %v; want explicit unavailable", value, measured)
	}
}

func TestCompletedStructuralZeroIsRetainedAsMeasuredZero(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{
		ID: "identity-zero", Tenant: "t1", Namespace: "ns", Pod: "api", Action: model.ActionIdentityRotate,
		Outcome: OutcomeCompleted, ReplicaImpact: ImpactMeasured,
		StartedAt: base, ObservedAt: base.Add(time.Second), Duration: time.Second,
		AvailabilityMeasured: true,
		SelectionBoundStatus: StatusZero, SelectionBoundFinite: true,
		SelectionBoundReplicaSeconds: 0, SelectionBoundEvidence: "structural zero",
	})
	entries := l.Entries("t1", base)
	if len(entries) != 1 {
		t.Fatalf("completed zero-impact action was dropped: %+v", entries)
	}
	if value, measured := entries[0].MeasuredReplicaSeconds(); !measured || value != 0 {
		t.Fatalf("zero impact = %v, %v; want measured zero", value, measured)
	}
	got := l.ConsumedImpact("t1", base)
	if got.ReplicaMeasuredEntries != 1 || got.ReplicaUnmeasuredEntries != 0 || got.ReplicaSeconds != 0 {
		t.Fatalf("zero-impact consumption provenance = %+v", got)
	}
}

func TestUnknownImpactAndUnknownBoundAreNeverLaunderedToZero(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{
		ID: "unknown", Tenant: "t1", Namespace: "ns", Pod: "api", Action: model.ActionQuarantine,
		Outcome: OutcomeEmitted, ReplicaImpact: ImpactUnmeasured,
		StartedAt: base, ObservedAt: base.Add(time.Second), Duration: time.Second,
		SelectionBoundStatus: StatusUnknown, SelectionBoundFinite: false,
		SelectionBoundEvidence: "no bounded rollback deadline",
	})
	entries := l.Entries("t1", base)
	if len(entries) != 1 {
		t.Fatalf("unknown-impact action was dropped: %+v", entries)
	}
	if value, measured := entries[0].MeasuredReplicaSeconds(); measured || value != 0 {
		t.Fatalf("unknown impact = %v, %v; want unavailable, not numeric zero", value, measured)
	}
	if entries[0].SelectionBoundFinite || entries[0].SelectionBoundStatus != StatusUnknown {
		t.Fatalf("unknown selection bound was changed: %+v", entries[0])
	}
	got := l.ConsumedImpact("t1", base)
	if got.ReplicaMeasuredEntries != 0 || got.ReplicaUnmeasuredEntries != 1 {
		t.Fatalf("unknown impact missing from evidence counts: %+v", got)
	}
}
