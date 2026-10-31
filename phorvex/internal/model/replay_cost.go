package model

import "time"

// ReplicaHistoryEntry is a frozen observation value shared across service
// boundaries. It carries no dispatcher accounting or admission behavior. Status
// labels retain their recorded strings; absence remains absence.
type ReplicaHistoryEntry struct {
	ID                           string
	Tenant                       string
	Namespace                    string
	Pod                          string
	Action                       Action
	Cause                        string
	Outcome                      string
	PolicyOwner                  string
	PodUID                       string
	WorkloadUID                  string
	Replicas                     int
	Duration                     time.Duration
	StartedAt                    time.Time
	ObservedAt                   time.Time
	Censored                     bool
	ReplicaImpact                string
	SelectionBoundStatus         string
	SelectionBoundFinite         bool
	SelectionBoundReplicaSeconds float64
	SelectionBoundEvidence       string
	ReadyReplicasBefore          int
	MinAvailableReplicas         int
	AvailabilityMeasured         bool
	AvailabilityBreachDuration   time.Duration
	AvailabilityBreachStartedAt  time.Time
	AvailabilityBreachObservedAt time.Time
}

const (
	ReplayCostEvidenceSchema = "phorvex.endpoint-cost-evidence.v1"
	MaxReplayHistoryEntries  = 2000
	MaxReplayEvidenceBytes   = 1 << 20
)

// ReplicaHistorySnapshot is an immutable, policy-bound copy of what this
// process observed. It is not an endpoint-loss ledger or an admission budget.
// HistoryComplete is always false for this in-memory, partial-action producer.
type ReplicaHistorySnapshot struct {
	Available            bool                  `json:"available"`
	Source               string                `json:"source"`
	CapturedAt           time.Time             `json:"captured_at"`
	ProcessObservedSince time.Time             `json:"process_observed_since"`
	RetentionSeconds     float64               `json:"retention_seconds"`
	HistoryComplete      bool                  `json:"history_complete"`
	Entries              []ReplicaHistoryEntry `json:"entries"`
	MatchedEntries       int                   `json:"matched_entries"`
	UnattributedEntries  int                   `json:"unattributed_entries"`
	FutureEntries        int                   `json:"future_entries"`
	Truncated            bool                  `json:"truncated"`
}

type ReplayWorkloadSpec struct {
	PodUID      string                  `json:"pod_uid"`
	Observation WorkloadSpecObservation `json:"observation"`
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
	out.ReplicaHistory.Entries = append([]ReplicaHistoryEntry(nil), e.ReplicaHistory.Entries...)
	out.Missing = append([]string(nil), e.Missing...)
	return &out
}
