package core

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Metric is the ONE metric struct emitted per (scenario, defender, trial). It is
// the SAME schema on every environment. It is written as JSON lines and rendered
// into tables by internal/report.
type Metric struct {
	Scenario string `json:"scenario"`
	Defender string `json:"defender"`
	Trial    int    `json:"trial"`
	Seed     int64  `json:"seed"`

	// OracleAchieved is the concrete observable verdict (defense effect is
	// measured strictly against this).
	OracleAchieved bool `json:"oracleAchieved"`

	// DisruptionVsOracle is the per-trial disruption of THIS arm relative to the
	// undefended baseline oracle: 1.0 if the undefended baseline achieved the
	// oracle but this arm did not, 0.0 if this arm still achieved it. Aggregated
	// per arm into a mean (a disruption PERCENT).
	DisruptionVsOracle float64 `json:"disruptionVsOracle"`

	// AttackerDwellSeconds is how long the planted foothold survived.
	AttackerDwellSeconds float64 `json:"attackerDwellSeconds"`

	// TimeToActionSeconds is how long after attack start the defender took its
	// first concrete defensive action (0 = no action observed).
	TimeToActionSeconds float64 `json:"timeToActionSeconds"`

	// SecurityPerCost is disruption per unit defensive cost (defensive actions);
	// higher = more disruption for fewer rotations.
	SecurityPerCost float64 `json:"securityPerCost"`

	// EvidenceRetention is the fraction of attack evidence still observable after
	// the trial (a rotation that destroys the pod also destroys forensic
	// evidence; lower retention is a real cost of aggressive rotation).
	EvidenceRetention float64 `json:"evidenceRetention"`

	// Skipped marks a capability-skipped or stub arm; SkipReason explains it.
	Skipped    bool   `json:"skipped"`
	SkipReason string `json:"skipReason,omitempty"`

	// DefensiveActions is the count of concrete defensive actions taken (cost).
	DefensiveActions int `json:"defensiveActions"`

	// FalseDefensiveActions counts defensive actions fired during the no-attack
	// negative control (should be 0). -1 means "not a negative-control trial".
	FalseDefensiveActions int `json:"falseDefensiveActions"`

	// NegativeControl marks the no-attack negative-control trial.
	NegativeControl bool `json:"negativeControl"`

	// AnchorOnly marks a baseline (positive-control) arm that was FORCE-INCLUDED
	// solely to anchor disruption when a DefenderFilter excluded it. These metrics
	// establish the anchor but are OMITTED from the requested-arm report so the
	// filter's intent is honored.
	AnchorOnly bool `json:"anchorOnly,omitempty"`

	// ObservedState/Notes carry the oracle's human-readable observable state.
	ObservedState string `json:"observedState,omitempty"`

	// RawLogPath ties this metric to the exact raw log that produced it.
	RawLogPath string `json:"rawLogPath"`

	// Commands is the exact command list issued during the trial (provenance).
	Commands []string `json:"commands"`

	// R6Tag mirrors the scenario's honest R6 verdict (carried for reporting).
	R6Tag R6Tag `json:"r6Tag"`
	// Category mirrors the scenario category (carried for reporting).
	Category Category `json:"category"`

	// ---- PASS-B ADDITIVE FIELDS (all omitempty / zero-valued so the 1980 Pass-A
	// rows decode UNCHANGED; the SAME struct is emitted on every environment) ----

	// SplitOracle identifies which half of a split-oracle (in-request vs
	// persistence) scenario this row scores. "" for single-oracle Pass-A rows.
	SplitOracle string `json:"splitOracle,omitempty"`

	// MTDEffect is the MEASURED MTD-effect tag for this arm, DERIVED from the
	// oracle/disruption + persistence outcome (never assumed): one of
	// MTDNeutralizes / MTDBoundsOnly / MTDCannotHelp.
	MTDEffect string `json:"mtdEffect,omitempty"`

	// TriggerAttribution records WHY a missing-trigger result is not a Phoenix
	// failure (audit honesty): "" | "harness-injected" |
	// "MISSING-TRIGGER:detector-absent" | "MISSING-TRIGGER:receiver-only" |
	// "capability-pending".
	TriggerAttribution string `json:"triggerAttribution,omitempty"`

	// CapabilityPending marks a GPU/MIG/multi-node headline number carried to the
	// AWS/CoreWeave run; CapabilityNote explains it.
	CapabilityPending bool   `json:"capabilityPending,omitempty"`
	CapabilityNote    string `json:"capabilityNote,omitempty"`

	// InRequestAchieved / PersistenceAchieved record the two split-oracle halves
	// explicitly (a convenience mirror of OracleAchieved per half).
	InRequestAchieved   bool `json:"inRequestAchieved,omitempty"`
	PersistenceAchieved bool `json:"persistenceAchieved,omitempty"`

	// ROI carries the per-scenario/arm dollar economics (omitempty: a zero struct
	// is omitted, so Pass-A rows that never set it decode unchanged).
	ROI *ROIMetric `json:"roi,omitempty"`

	// Schwartau carries the Protection vs (Detection+Reaction) timing model.
	Schwartau *SchwartauMetric `json:"schwartau,omitempty"`

	// Reuse carries the attack-reusability (replay-success) measurement.
	Reuse *ReuseMetric `json:"reuse,omitempty"`

	// AtlasIDs / OwaspIDs carry the AI threat-model IDs for reporting parity with
	// R6Tag/Category (AttackTechniqueIDs still carries ATT&CK-for-Containers IDs).
	AtlasIDs []string `json:"atlasIds,omitempty"`
	OwaspIDs []string `json:"owaspIds,omitempty"`
}

// ROIMetric is the dollar economics for one (scenario, arm). Every field is
// transparent and recomputable from the config knobs (see internal/config).
type ROIMetric struct {
	// GpuCount / DollarsPerGpuHour are the swappable inputs (echoed for audit).
	GpuCount         int     `json:"gpuCount"`
	DollarsPerGpuHour float64 `json:"dollarsPerGpuHour"`
	// GpuOverheadDollarsPerYearSaved is the GPU-overhead $/yr the MTD avoids vs a
	// static-but-unprotected baseline (GpuCount*$/hr*8760*overheadPercent).
	GpuOverheadDollarsPerYearSaved float64 `json:"gpuOverheadDollarsPerYearSaved"`
	// AvoidedBreachValueDollars is the swappable breach-value input ($).
	AvoidedBreachValueDollars float64 `json:"avoidedBreachValueDollars"`
	// AnnualDefenseCostDollars is the modeled annual defense cost (rotation churn
	// priced at the GPU-hour rate) used as the denominator of security-per-cost.
	AnnualDefenseCostDollars float64 `json:"annualDefenseCostDollars"`
	// SecurityPerCostDollars = disruption * AvoidedBreachValue / AnnualDefenseCost.
	SecurityPerCostDollars float64 `json:"securityPerCostDollars"`
}

// SchwartauMetric models Schwartau's time-based-security inequality P > D + R.
type SchwartauMetric struct {
	// ProtectionTimeSeconds (P) is how long the moving target stays valid for the
	// attacker (the rotation interval; 0/Inf-class for a static arm).
	ProtectionTimeSeconds float64 `json:"protectionTimeSeconds"`
	// DetectionTimeSeconds (D) is derived from time-to-action / oracle timing; -1
	// when the detector is RECEIVER-ONLY/ABSENT (see DetectionAbsent).
	DetectionTimeSeconds float64 `json:"detectionTimeSeconds"`
	// ReactionTimeSeconds (R) is the action latency after the trigger.
	ReactionTimeSeconds float64 `json:"reactionTimeSeconds"`
	// SchwartauPositive is true iff P > D + R (and D is defined).
	SchwartauPositive bool `json:"schwartauPositive"`
	// DetectionAbsent is true when no detector exists (D undefined); the note
	// explains it.
	DetectionAbsent     bool   `json:"detectionAbsent,omitempty"`
	DetectionAbsentNote string `json:"detectionAbsentNote,omitempty"`
}

// ReuseMetric measures attack-reusability: how many captured-exploit replays
// still succeed against THIS arm vs the static (no-MTD) baseline.
type ReuseMetric struct {
	ReplaySuccessCount          int     `json:"replaySuccessCount"`
	ReplayAttempts              int     `json:"replayAttempts"`
	StaticBaselineReplaySuccess int     `json:"staticBaselineReplaySuccess"`
	ReuseReductionVsStatic      float64 `json:"reuseReductionVsStatic"`
}

// MTD-effect tag constants (MEASURED, never assumed).
const (
	MTDNeutralizes = "MTD-NEUTRALIZES"
	MTDBoundsOnly  = "MTD-BOUNDS-ONLY"
	MTDCannotHelp  = "MTD-CANNOT-HELP"
)

// Split-oracle half constants.
const (
	SplitInRequest   = "in-request"
	SplitPersistence = "persistence"
)

// Trigger-attribution constants.
const (
	TriggerHarnessInjected   = "harness-injected"
	TriggerDetectorAbsent    = "MISSING-TRIGGER:detector-absent"
	TriggerReceiverOnly      = "MISSING-TRIGGER:receiver-only"
	TriggerCapabilityPending = "capability-pending"
)

// Evidence-map keys a SPLIT-ORACLE AI scenario stamps into OracleResult.Evidence
// so the runner can lift them into the ADDITIVE metric fields WITHOUT any change
// to the Scenario/Defender interface. A scenario that does not set them yields
// the zero values (Pass-A behavior unchanged).
const (
	// EvSplitOracle marks which half this oracle scored (in-request|persistence).
	EvSplitOracle = "r6th.splitOracle"
	// EvInRequestAchieved / EvPersistenceAchieved carry the two halves ("true"/"false").
	EvInRequestAchieved   = "r6th.inRequestAchieved"
	EvPersistenceAchieved = "r6th.persistenceAchieved"
	// EvPersistenceDisrupted is "true" when the persistence foothold was bounded/reduced.
	EvPersistenceDisrupted = "r6th.persistenceDisrupted"
	// EvNeutralized is "true" when a genuine matcher action removed the foothold.
	EvNeutralized = "r6th.neutralized"
	// EvTriggerAttribution carries the audit attribution string.
	EvTriggerAttribution = "r6th.triggerAttribution"
	// EvDetectorAbsent is "true" when no detector exists (Schwartau D undefined).
	EvDetectorAbsent = "r6th.detectorAbsent"
	// EvCapabilityPending / EvCapabilityNote mark a GPU/MIG/multi-node headline pending.
	EvCapabilityPending = "r6th.capabilityPending"
	EvCapabilityNote    = "r6th.capabilityNote"
	// EvReactionSeconds overrides the measured reaction latency (seconds) when the
	// scenario has a better estimate than time-to-action.
	EvReactionSeconds = "r6th.reactionSeconds"
	// EvReplaySuccess / EvReplayAttempts carry the attack-reusability counts.
	EvReplaySuccess  = "r6th.replaySuccess"
	EvReplayAttempts = "r6th.replayAttempts"
	// EvAtlasIDs / EvOwaspIDs carry comma-joined AI threat IDs.
	EvAtlasIDs = "r6th.atlasIDs"
	EvOwaspIDs = "r6th.owaspIDs"
)

// MetricWriter appends Metric records as JSON lines to a file, concurrency-safe.
type MetricWriter struct {
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	all  []Metric
	path string
}

// NewMetricWriter opens (truncating) the JSONL metrics file at path.
func NewMetricWriter(path string) (*MetricWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &MetricWriter{f: f, w: bufio.NewWriter(f), path: path}, nil
}

// NewMetricWriterResume opens the JSONL metrics file in APPEND mode (it does NOT
// truncate) and preloads `preload` into the in-memory aggregate, so a batched run
// accumulates into the SAME file: the prior rows stay on disk, this batch's rows are
// appended, and All() (hence the regenerated report) covers the running total. A
// nil/empty preload + a missing file behaves like a fresh run.
func NewMetricWriterResume(path string, preload []Metric) (*MetricWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	all := make([]Metric, len(preload))
	copy(all, preload)
	return &MetricWriter{f: f, w: bufio.NewWriter(f), path: path, all: all}, nil
}

// Write appends one metric as a JSON line and retains it in memory for aggregation.
func (m *MetricWriter) Write(rec Metric) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := m.w.Write(b); err != nil {
		return err
	}
	if err := m.w.WriteByte('\n'); err != nil {
		return err
	}
	m.all = append(m.all, rec)
	return m.w.Flush()
}

// All returns a copy of every metric written so far.
func (m *MetricWriter) All() []Metric {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Metric, len(m.all))
	copy(out, m.all)
	return out
}

// Path returns the JSONL file path.
func (m *MetricWriter) Path() string { return m.path }

// Close flushes and closes the file.
func (m *MetricWriter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.w.Flush(); err != nil {
		return err
	}
	return m.f.Close()
}
