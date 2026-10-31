package slo

import (
	"container/heap"
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

type recentEntries []Entry

func (h recentEntries) Len() int { return len(h) }
func earlier(a, b Entry) bool {
	if a.ObservedAt.Equal(b.ObservedAt) {
		return a.ID < b.ID
	}
	return a.ObservedAt.Before(b.ObservedAt)
}
func (h recentEntries) Less(i, j int) bool { return earlier(h[i], h[j]) }
func (h recentEntries) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *recentEntries) Push(v any)        { *h = append(*h, v.(Entry)) }
func (h *recentEntries) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

// SnapshotForReplay takes a coherent copy under the ledger lock. Memory is
// bounded even if the retained ledger is large. Rows without exact policy
// identity are counted as unavailable, never joined by display name.
func (l *Ledger) SnapshotForReplay(tenant, namespace, owner string, at time.Time, limit int) model.ReplicaHistorySnapshot {
	out := model.ReplicaHistorySnapshot{Source: "replica-readiness", CapturedAt: at, Entries: []model.ReplicaHistoryEntry{}}
	if l == nil || owner == "" || namespace == "" {
		return out
	}
	if limit <= 0 || limit > model.MaxReplayHistoryEntries {
		limit = model.MaxReplayHistoryEntries
	}
	selected := recentEntries{}
	l.mu.RLock()
	out.Available, out.ProcessObservedSince, out.RetentionSeconds = true, l.createdAt, l.Retain.Seconds()
	for _, e := range l.byOwner[tenant] {
		if e.Namespace != namespace {
			continue
		}
		if e.PolicyOwner == "" {
			out.UnattributedEntries++
			continue
		}
		if e.PolicyOwner != owner {
			continue
		}
		if e.ObservedAt.After(at) {
			out.FutureEntries++
			continue
		}
		out.MatchedEntries++
		if len(selected) < limit {
			heap.Push(&selected, e)
		} else if earlier(selected[0], e) {
			selected[0] = e
			heap.Fix(&selected, 0)
		}
	}
	l.mu.RUnlock()
	sort.Slice(selected, func(i, j int) bool { return earlier(selected[i], selected[j]) })
	used := 0
	for i := len(selected) - 1; i >= 0; i-- {
		if entryTextBytes(selected[i]) > model.MaxReplayEvidenceBytes {
			out.Truncated = true
			continue
		}
		entry := replayHistoryEntry(selected[i])
		raw, err := json.Marshal(entry)
		if err != nil || used+len(raw) > model.MaxReplayEvidenceBytes {
			out.Truncated = true
			continue
		}
		out.Entries = append(out.Entries, entry)
		used += len(raw)
	}
	slices.Reverse(out.Entries)
	out.Truncated = out.Truncated || len(out.Entries) != out.MatchedEntries
	return out
}

// Bound allocation before JSON escaping as well as the final encoded size.
func entryTextBytes(e Entry) int {
	return len(e.ID) + len(e.Tenant) + len(e.Namespace) + len(e.Pod) + len(e.Action) + len(e.Cause) + len(e.Outcome) + len(e.PolicyOwner) + len(e.PodUID) + len(e.WorkloadUID) + len(e.ReplicaImpact) + len(e.SelectionBoundStatus) + len(e.SelectionBoundEvidence)
}

// Convert the value copied under the ledger lock into the shared wire contract.
// No mutable ledger object or dispatcher behavior crosses the service boundary.
func replayHistoryEntry(e Entry) model.ReplicaHistoryEntry {
	return model.ReplicaHistoryEntry{
		ID: e.ID, Tenant: e.Tenant, Namespace: e.Namespace, Pod: e.Pod,
		Action: e.Action, Cause: string(e.Cause), Outcome: string(e.Outcome),
		PolicyOwner: e.PolicyOwner, PodUID: e.PodUID, WorkloadUID: e.WorkloadUID,
		Replicas: e.Replicas, Duration: e.Duration, StartedAt: e.StartedAt, ObservedAt: e.ObservedAt,
		Censored: e.Censored, ReplicaImpact: string(e.ReplicaImpact),
		SelectionBoundStatus: string(e.SelectionBoundStatus), SelectionBoundFinite: e.SelectionBoundFinite,
		SelectionBoundReplicaSeconds: e.SelectionBoundReplicaSeconds, SelectionBoundEvidence: e.SelectionBoundEvidence,
		ReadyReplicasBefore: e.ReadyReplicasBefore, MinAvailableReplicas: e.MinAvailableReplicas,
		AvailabilityMeasured: e.AvailabilityMeasured, AvailabilityBreachDuration: e.AvailabilityBreachDuration,
		AvailabilityBreachStartedAt: e.AvailabilityBreachStartedAt, AvailabilityBreachObservedAt: e.AvailabilityBreachObservedAt,
	}
}
