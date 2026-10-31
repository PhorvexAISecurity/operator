package slo

import (
	"container/heap"
	"encoding/json"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	ReplayCostEvidenceSchema = "phorvex.endpoint-cost-evidence.v1"
	MaxReplayHistoryEntries  = 2000
	MaxReplayEvidenceBytes   = 1 << 20
)

// ReplicaHistorySnapshot is an immutable, policy-bound copy of what this
// process observed. It is not an endpoint-loss ledger or an admission budget.
// HistoryComplete is always false for this in-memory, partial-action producer.
type ReplicaHistorySnapshot struct {
	Available            bool      `json:"available"`
	Source               string    `json:"source"`
	CapturedAt           time.Time `json:"captured_at"`
	ProcessObservedSince time.Time `json:"process_observed_since"`
	RetentionSeconds     float64   `json:"retention_seconds"`
	HistoryComplete      bool      `json:"history_complete"`
	Entries              []Entry   `json:"entries"`
	MatchedEntries       int       `json:"matched_entries"`
	UnattributedEntries  int       `json:"unattributed_entries"`
	FutureEntries        int       `json:"future_entries"`
	Truncated            bool      `json:"truncated"`
}

type ReplayWorkloadSpec struct {
	PodUID      string                        `json:"pod_uid"`
	Observation model.WorkloadSpecObservation `json:"observation"`
}

// ReplayCostEvidence is diagnostic input capture, not a pricing authorization.
// In particular, replica readiness is never relabelled endpoint loss.
type ReplayCostEvidence struct {
	Schema                string                 `json:"schema"`
	CapturedAt            time.Time              `json:"captured_at"`
	PolicyOwner           string                 `json:"policy_owner"`
	PolicyUID             string                 `json:"policy_uid"`
	Workloads             []ReplayWorkloadSpec   `json:"workloads"`
	ReplicaHistory        ReplicaHistorySnapshot `json:"replica_history"`
	EndpointLossStatus    string                 `json:"endpoint_loss_status"`
	AdmissionLedgerStatus string                 `json:"admission_ledger_status"`
	WorkloadsTruncated    bool                   `json:"workloads_truncated"`
	CaptureByteLimit      bool                   `json:"capture_byte_limit"`
	Missing               []string               `json:"missing"`
}

// Clone owns every mutable member; callers cannot mutate a retained snapshot
// by reusing a request or the live ledger after capture.
func (e *ReplayCostEvidence) Clone() *ReplayCostEvidence {
	if e == nil {
		return nil
	}
	out := *e
	out.Workloads = append([]ReplayWorkloadSpec(nil), e.Workloads...)
	out.ReplicaHistory.Entries = append([]Entry(nil), e.ReplicaHistory.Entries...)
	out.Missing = append([]string(nil), e.Missing...)
	return &out
}

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
func (l *Ledger) SnapshotForReplay(tenant, namespace, owner string, at time.Time, limit int) ReplicaHistorySnapshot {
	out := ReplicaHistorySnapshot{Source: "replica-readiness", CapturedAt: at, Entries: []Entry{}}
	if l == nil || owner == "" || namespace == "" {
		return out
	}
	if limit <= 0 || limit > MaxReplayHistoryEntries {
		limit = MaxReplayHistoryEntries
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
		if entryTextBytes(selected[i]) > MaxReplayEvidenceBytes {
			out.Truncated = true
			continue
		}
		raw, err := json.Marshal(selected[i])
		if err != nil || used+len(raw) > MaxReplayEvidenceBytes {
			out.Truncated = true
			continue
		}
		out.Entries = append(out.Entries, selected[i])
		used += len(raw)
	}
	sort.Slice(out.Entries, func(i, j int) bool { return earlier(out.Entries[i], out.Entries[j]) })
	out.Truncated = out.Truncated || len(out.Entries) != out.MatchedEntries
	return out
}

// Bound allocation before JSON escaping as well as the final encoded size.
func entryTextBytes(e Entry) int {
	return len(e.ID) + len(e.Tenant) + len(e.Namespace) + len(e.Pod) + len(e.Action) + len(e.Cause) + len(e.Outcome) + len(e.PolicyOwner) + len(e.PodUID) + len(e.WorkloadUID) + len(e.ReplicaImpact) + len(e.SelectionBoundStatus) + len(e.SelectionBoundEvidence)
}
