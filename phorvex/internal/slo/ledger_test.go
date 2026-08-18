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

// A censored reading is a floor on how bad recovery was, not a reason to forget
// it. Dropping censored entries would understate consumption exactly when
// recovery went worst.
func TestCensoredEntriesStillConsumeBudget(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	l := NewLedger(0)
	l.Record(Entry{Tenant: "t1", Action: model.ActionRotate, Replicas: 1, Duration: 800 * time.Second, ObservedAt: base, Censored: true})

	if got, want := l.Consumed("t1", base), 800.0; got != want {
		t.Fatalf("censored entry must still count: got %v want %v", got, want)
	}
	e := l.Entries("t1", base)
	if len(e) != 1 || !e[0].Censored {
		t.Fatalf("censored flag lost on read back: %+v", e)
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
