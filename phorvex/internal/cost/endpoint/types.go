// Package endpoint implements an offline paired endpoint-cost experiment.
// It has no Kubernetes client or actuator and never changes the production brain.
package endpoint

import "math"

const TraceSchema = "phorvex-bench.endpoint-trace.v1"
const ResultSchema = "phorvex-bench.endpoint-result.v1"

type Trace struct {
	Schema         string `json:"schema"`
	Evidence       string `json:"evidence"` // synthetic or recorded; provenance remains visible
	SourceRevision string `json:"source_revision"`
	Ticks          []Tick `json:"ticks"`
}

type Tick struct {
	ID                   string      `json:"id"`
	At                   float64     `json:"at"` // recorded Unix seconds, never wall-clock substitution
	WorkloadUID          string      `json:"workload_uid"`
	PolicyUID            string      `json:"policy_uid"`
	SpecReplicas         *int        `json:"spec_replicas"`
	SLO                  *SLO        `json:"slo"`
	Ledger               *Ledger     `json:"ledger"`
	Candidates           []Candidate `json:"candidates"`
	CandidateSetComplete bool        `json:"candidate_set_complete"`
	MandatoryID          string      `json:"mandatory_id,omitempty"` // original deterministic containment winner
}

type SLO struct {
	Target          float64 `json:"target"`
	Window          float64 `json:"window"`
	Accepted        bool    `json:"accepted"`
	StudyAssumption bool    `json:"study_assumption"`
}

type Ledger struct {
	At            float64  `json:"at"`
	CompleteFrom  *float64 `json:"complete_from"`
	Authoritative bool     `json:"authoritative"`
	Measurement   string   `json:"measurement"` // measured intervals or explicitly labelled watch-observed Service readiness
	Moves         []Move   `json:"moves"`
}

type Interval struct {
	EndpointUID string  `json:"endpoint_uid"`
	Start       float64 `json:"start"`
	End         float64 `json:"end"`
}

type Move struct {
	ID          string     `json:"id"`
	Revision    int        `json:"revision"`
	WorkloadUID string     `json:"workload_uid"`
	PolicyUID   string     `json:"policy_uid"`
	Action      string     `json:"action"`
	Containment bool       `json:"containment"`
	State       string     `json:"state"` // open or settled
	ObservedAt  float64    `json:"observed_at"`
	Attributed  bool       `json:"attributed"`
	Measured    bool       `json:"measured"` // explicit measured zero is distinct from missing
	Intervals   []Interval `json:"intervals"`
	Reservation *float64   `json:"reservation"`
	Overdue     bool       `json:"overdue"`
}

type Sample struct {
	ID          string   `json:"id"`
	WorkloadUID string   `json:"workload_uid"`
	Action      string   `json:"action"`
	At          float64  `json:"at"`
	Duration    *float64 `json:"duration"` // null + censored means a retained right-censored outcome
	Censored    bool     `json:"censored"`
	Overdue     bool     `json:"overdue"`
	Suspect     bool     `json:"suspect"`
}

type Fact struct {
	ID     string  `json:"id"`
	Weight float64 `json:"weight"` // grounded provenance-adjusted security points
}

type Candidate struct {
	ID             string   `json:"id"`
	PodUID         string   `json:"pod_uid"`
	Action         string   `json:"action"`
	Facts          []Fact   `json:"facts"`
	FactsKnown     bool     `json:"facts_known"`
	Gates          []string `json:"gates"` // real non-cost veto reasons from the pinned generator
	GatesKnown     bool     `json:"gates_known"`
	WorthThreshold *float64 `json:"worth_threshold"`
	Containment    bool     `json:"containment"`
	K              *int     `json:"k"`
	Class          string   `json:"class"`
	HistoryKnown   bool     `json:"history_known"`
	Samples        []Sample `json:"samples"`
	HoldCap        *float64 `json:"hold_cap"`
	// Additional actions may only use a specifically approved documented bound.
	DocumentedBound *Bound `json:"documented_bound,omitempty"`
}

type Bound struct {
	Source       string  `json:"source"`
	Approved     bool    `json:"approved"`
	Mid          float64 `json:"mid"`
	Upper        float64 `json:"upper"`
	FailureUpper float64 `json:"failure_upper"`
}

type Cost struct {
	E            *float64 `json:"E"`
	Rho          *float64 `json:"rho"`
	Mid          *float64 `json:"T_mid"`
	Upper        *float64 `json:"T_upper"`
	FailureUpper *float64 `json:"p_f"`
	Flow         *float64 `json:"C_flow"`
	Norm         *float64 `json:"C_norm"`
	SampleCount  int      `json:"sample_count"`
	Hold         *float64 `json:"H_eff,omitempty"`
	Refusal      string   `json:"refusal,omitempty"`
	Rollback     string   `json:"rollback"`
}

type Budget struct {
	R               *float64 `json:"R"`
	Used            *float64 `json:"used"`
	Held            *float64 `json:"held"`
	Left            *float64 `json:"R_left"`
	Spend           *float64 `json:"S"`
	Refusal         string   `json:"refusal,omitempty"`
	TelemetryReason string   `json:"telemetry_reason,omitempty"`
	ActingAdmission string   `json:"acting_admission"`
}

type Config struct {
	Lookback float64 `json:"lookback"`
	Min      float64 `json:"min"`
	Max      float64 `json:"max"`
	Eta      float64 `json:"eta"`
	GMax     float64 `json:"g_max"`
	MaxDT    float64 `json:"max_dt"`
	Delta    float64 `json:"delta"`
}

func Defaults() Config {
	return Config{Lookback: 86400, Min: .0001, Max: 1000, Eta: math.Log(1e7) / 3600, GMax: 1, MaxDT: 30, Delta: 30}
}

func finite(v float64) bool           { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func ptr(v float64) *float64          { return &v }
func nonnegative(v *float64) bool     { return v != nil && finite(*v) && *v >= 0 }
func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(v, hi)) }
