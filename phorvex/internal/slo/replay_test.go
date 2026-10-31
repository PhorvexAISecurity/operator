package slo

import (
	"strings"
	"testing"
	"time"
)

func TestReplayHistoryRealLedgerReplacementIsolationAndImmutability(t *testing.T) {
	at := time.Now().UTC()
	l := NewLedger(24 * time.Hour)
	row := Entry{ID: "move", Tenant: "tenant", Namespace: "ns", PolicyOwner: "uid\x00policy", PodUID: "pod", WorkloadUID: "workload", Replicas: 1, Duration: time.Second, StartedAt: at.Add(-time.Second), ObservedAt: at, Outcome: OutcomeRightCensored, Censored: true}
	l.Record(row)
	first := l.SnapshotForReplay("tenant", "ns", row.PolicyOwner, at, 20)
	row.Outcome = OutcomeCompleted
	row.Censored = false
	row.ObservedAt = at.Add(time.Second)
	row.Duration = 2 * time.Second
	l.Record(row)
	for i := 0; i < 4; i++ {
		other := row
		other.ID = string(rune('a' + i))
		switch i {
		case 0:
			other.Namespace = "elsewhere"
		case 1:
			other.PolicyOwner = "uid\x00different"
		case 2:
			other.PolicyOwner = ""
		case 3:
			other.ObservedAt = at.Add(10 * time.Second)
		}
		l.Record(other)
	}
	second := l.SnapshotForReplay("tenant", "ns", row.PolicyOwner, at.Add(time.Second), 20)
	if !second.Available || second.Source != "replica-readiness" || second.HistoryComplete || second.ProcessObservedSince.IsZero() || second.RetentionSeconds != 86400 || len(second.Entries) != 1 || second.UnattributedEntries != 1 || second.FutureEntries != 1 || second.MatchedEntries != 1 || second.Truncated {
		t.Fatalf("invalid evidence: %+v", second)
	}
	if first.Entries[0].Outcome != OutcomeRightCensored || !first.Entries[0].Censored || second.Entries[0].Outcome != OutcomeCompleted || second.Entries[0].Censored {
		t.Fatalf("open/settled observations not frozen: %+v / %+v", first, second)
	}
	first.Entries[0].ID = "mutated"
	if l.SnapshotForReplay("tenant", "ns", row.PolicyOwner, at.Add(time.Second), 20).Entries[0].ID != "move" {
		t.Fatal("export mutated ledger")
	}
	e := &ReplayCostEvidence{Workloads: []ReplayWorkloadSpec{{PodUID: "p"}}, ReplicaHistory: second, Missing: []string{"endpoint unavailable"}}
	clone := e.Clone()
	clone.Workloads[0].PodUID = "bad"
	clone.ReplicaHistory.Entries[0].ID = "bad"
	clone.Missing[0] = "bad"
	if e.Workloads[0].PodUID != "p" || e.ReplicaHistory.Entries[0].ID != "move" || e.Missing[0] != "endpoint unavailable" {
		t.Fatal("clone shares mutable data")
	}
}
func TestReplayHistoryBoundsAndMissingLedger(t *testing.T) {
	at := time.Now().UTC()
	var missing *Ledger
	if got := missing.SnapshotForReplay("t", "ns", "p", at, 1); got.Available || got.HistoryComplete {
		t.Fatal(got)
	}
	l := NewLedger(time.Hour)
	for i := 0; i < 5; i++ {
		l.Record(Entry{ID: string(rune('a' + i)), Tenant: "t", Namespace: "ns", PolicyOwner: "p", Outcome: OutcomeEmitted, ObservedAt: at.Add(time.Duration(i) * time.Second)})
	}
	got := l.SnapshotForReplay("t", "ns", "p", at.Add(time.Minute), 2)
	if !got.Truncated || got.MatchedEntries != 5 || len(got.Entries) != 2 || got.Entries[0].ID != "d" || got.Entries[1].ID != "e" {
		t.Fatal(got)
	}
	l.Record(Entry{ID: "huge", Tenant: "t", Namespace: "ns", PolicyOwner: "p", Outcome: OutcomeEmitted, ObservedAt: at.Add(9 * time.Second), SelectionBoundEvidence: strings.Repeat("x", MaxReplayEvidenceBytes+1)})
	got = l.SnapshotForReplay("t", "ns", "p", at.Add(time.Minute), 20)
	if !got.Truncated || got.MatchedEntries != 6 || len(got.Entries) != 5 {
		t.Fatal(got)
	}
}
