package core

import (
	"fmt"
	"strings"
)

// validity.go defines the EXPLICIT, VERSIONED measurement-validity contract that
// every trial stamps onto its Metric.
//
// The invariant this file exists to enforce: a value alone never implies a
// measurement. A failed operation, a missing observation or a missing positive
// control must be representable as such, and must never be indistinguishable
// from "the defense worked" or "the cost was zero". Consumers (aggregation,
// reports, ROI) MUST consult Validity before treating any scoring field as
// measured; the numeric fields of an unscored row are left at their zero values
// precisely so that a consumer which ignores this block under-reports rather
// than over-claims.
//
// Compatibility: Metric.Validity is a pointer with `omitempty`, so a metrics
// JSONL file written before this contract existed still decodes — it simply
// decodes with Validity == nil, which is reported as LEGACY / UNVERIFIED.
// Legacy rows are never re-interpreted from their old zero fields and are never
// rewritten; they are excluded from newly certified scores and counted openly.

// MeasurementValidityVersion is the version of the validity contract stamped
// into every metric this harness emits. Bump it when the SEMANTICS of the block
// change so a consumer can tell which rules produced a row.
const MeasurementValidityVersion = 1

// TrialKind is the explicit kind of a trial. It is persisted so an adaptive or
// negative-control observation can never be silently aggregated as if it were an
// ordinary comparison.
type TrialKind string

const (
	// TrialOrdinary is a normal attack trial that is comparable against the
	// undefended positive control observed at the SAME trial index.
	TrialOrdinary TrialKind = "ordinary"
	// TrialNegativeControl is the no-attack trial that measures false defensive
	// moves. It has no disruption comparison at all.
	TrialNegativeControl TrialKind = "negative-control"
	// TrialAdaptive is the adaptive-attacker pass. It is comparable ONLY against
	// an adaptive control observed at the same index on the baseline arm.
	TrialAdaptive TrialKind = "adaptive"
)

// MeasurementStatus is the outcome of the MEASUREMENT (not of the attack).
type MeasurementStatus string

const (
	// MeasurementValid means every phase the trial entered completed, the
	// outcome was actually observed, and all owed cleanup succeeded. A valid
	// measurement may still be UNSCORED if no usable control exists.
	MeasurementValid MeasurementStatus = "valid"
	// MeasurementInvalid means an infrastructure/harness failure prevented a
	// trustworthy measurement (factory, defender setup/start, scenario setup,
	// attack stimulus, oracle transport, cleanup). It is NOT an attack result.
	MeasurementInvalid MeasurementStatus = "invalid"
	// MeasurementSkipped means the trial REPORTED that it could not run: an unmet
	// capability requirement or a registered stub arm. It is a deliberate
	// abstention, distinct from an infrastructure failure and from a valid
	// failed attack.
	MeasurementSkipped MeasurementStatus = "skipped"
	// MeasurementLegacy marks a row decoded from a pre-contract metrics file. Its
	// validity was never recorded, so it is unverified: it is displayed and
	// counted, never scored.
	MeasurementLegacy MeasurementStatus = "legacy-unverified"
)

// TrialPhase names the lifecycle phase a trial reached.
type TrialPhase string

const (
	PhaseEnvFactory     TrialPhase = "env-factory"
	PhaseCapabilityGate TrialPhase = "capability-gate"
	PhaseDefenderSetup  TrialPhase = "defender-setup"
	PhaseScenarioSetup  TrialPhase = "scenario-setup"
	PhaseDefenderStart  TrialPhase = "defender-start"
	PhaseAttackExecute  TrialPhase = "attack-execute"
	PhaseOracle         TrialPhase = "oracle"
	PhaseObserver       TrialPhase = "defense-observer"
	PhaseCleanup        TrialPhase = "cleanup"
	PhaseComplete       TrialPhase = "complete"
)

// BaselineRef records the IDENTITY and OBSERVED RESULT of the positive control a
// comparison was anchored to — or precisely why no usable control existed.
//
// HONEST SCOPE: the anchor is the control OBSERVED AT THE SAME TRIAL INDEX AND
// KIND on the undefended arm. It is NOT an identical-randomness counterfactual:
// TrialSeed hashes the defender name, so the baseline arm's trial i and a
// defended arm's trial i are seeded differently. Read a scored comparison as
// "this arm vs the undefended arm at the same index", never as "the same trial
// re-run with the defense removed".
type BaselineRef struct {
	// Required is true for kinds that need a positive control to be scored.
	Required bool `json:"required"`
	// Defender is the identity of the control arm (empty when none exists).
	Defender string `json:"defender,omitempty"`
	// Trial/Kind identify the exact control observation.
	Trial int       `json:"trial"`
	Kind  TrialKind `json:"kind,omitempty"`
	// Observed is true when a control row for that (trial, kind) was recorded.
	Observed bool `json:"observed"`
	// Valid is true when that control row was itself a valid measurement.
	Valid bool `json:"valid"`
	// OracleAchieved is the control's OBSERVED oracle result. It is only
	// meaningful when Observed && Valid.
	OracleAchieved bool `json:"oracleAchieved"`
	// Usable is true iff the control was observed, valid AND achieved its oracle
	// undefended — the only case in which disruption is attributable.
	Usable bool `json:"usable"`
	// IsSelf is true when this row IS the control arm (self-anchored).
	IsSelf bool `json:"isSelf,omitempty"`
	// Reason explains an unusable/absent control.
	Reason string `json:"reason,omitempty"`
}

// CleanupStep is one attempted cleanup action and its result.
type CleanupStep struct {
	Step string `json:"step"`
	// Error is empty when the step succeeded.
	Error string `json:"error,omitempty"`
}

// CleanupRecord retains EVERY cleanup/close attempt owed by the phases this
// trial actually entered, together with every failure. Cleanup is attempted even
// when the trial context was cancelled (on a bounded, detached context), because
// a trial that stops before attempted cleanup leaves state no later trial may
// safely reuse.
type CleanupRecord struct {
	Attempted []CleanupStep `json:"attempted,omitempty"`
	// Complete is true iff every owed step was attempted AND succeeded.
	Complete bool `json:"complete"`
}

// Failures returns the cleanup steps that failed.
func (c CleanupRecord) Failures() []CleanupStep {
	var out []CleanupStep
	for _, s := range c.Attempted {
		if s.Error != "" {
			out = append(out, s)
		}
	}
	return out
}

// MeasurementValidity is the versioned validity block stamped on every metric.
type MeasurementValidity struct {
	// Version is MeasurementValidityVersion at the time the row was written.
	Version int `json:"version"`
	// Kind is the explicit trial kind (ordinary / negative-control / adaptive).
	Kind TrialKind `json:"kind"`
	// Status is the measurement outcome.
	Status MeasurementStatus `json:"status"`
	// Phase is the last lifecycle phase entered.
	Phase TrialPhase `json:"phase"`
	// Reasons retains every propagated error/abstention, phase-prefixed, in the
	// order encountered. It is never emptied by a later success.
	Reasons []string `json:"reasons,omitempty"`

	// AttackExecuted is true when the attack stimulus ran without error (or, for
	// a negative control, when the deliberate no-op was performed).
	AttackExecuted bool `json:"attackExecuted"`
	// OracleObserved is true when the success oracle actually produced a verdict.
	// It is false when the oracle errored, was skipped, or was never run because
	// an earlier phase failed.
	OracleObserved bool `json:"oracleObserved"`
	// ObserverPresent is true when the defender implements DefenseObserver.
	ObserverPresent bool `json:"observerPresent"`
	// CostObserved is true when the defensive-action count and timings were
	// actually read. When false the cost is UNOBSERVED — not zero — and no
	// efficiency or ROI number may be derived.
	CostObserved bool `json:"costObserved"`

	// Scored is true iff DisruptionVsOracle (and anything derived from it) is a
	// real measured comparison against an observed usable control.
	Scored bool `json:"scored"`
	// UnscoredReason explains a valid-but-unscored row.
	UnscoredReason string `json:"unscoredReason,omitempty"`

	Baseline BaselineRef   `json:"baseline"`
	Cleanup  CleanupRecord `json:"cleanup"`
}

// note appends a phase-prefixed reason, preserving order and earlier entries.
func (v *MeasurementValidity) note(phase TrialPhase, msg string) {
	v.Reasons = append(v.Reasons, string(phase)+": "+msg)
}

// enter advances the recorded phase only while the measurement is still valid,
// so Phase always names the phase that DECIDED the outcome rather than the last
// phase the lifecycle happened to touch afterwards.
func (v *MeasurementValidity) enter(phase TrialPhase) {
	if v.Status == MeasurementValid {
		v.Phase = phase
	}
}

// fail marks the measurement invalid at a phase and retains the reason. An
// earlier failure phase is never overwritten by a later one.
func (v *MeasurementValidity) fail(phase TrialPhase, msg string) {
	v.note(phase, msg)
	if v.Status != MeasurementInvalid {
		v.Status = MeasurementInvalid
		v.Phase = phase
	}
}

// skip marks the measurement as a REPORTED abstention (capability/stub), which
// is distinct from an infrastructure failure. An already-invalid measurement
// stays invalid.
func (v *MeasurementValidity) skip(phase TrialPhase, msg string) {
	v.note(phase, msg)
	if v.Status == MeasurementValid {
		v.Status = MeasurementSkipped
		v.Phase = phase
	}
}

// summary renders the compatibility SkipReason for a non-scored row: the tag
// distinguishes a REPORTED abstention from an infrastructure failure, the phase
// says where it happened, and any cleanup failures are counted so a dirty trial
// is never mistaken for a clean skip.
func (v MeasurementValidity) summary() string {
	tag := "SKIP"
	if v.Status == MeasurementInvalid {
		tag = "INVALID"
	}
	body := ""
	prefix := string(v.Phase) + ": "
	for _, r := range v.Reasons {
		if strings.HasPrefix(r, prefix) {
			body = strings.TrimPrefix(r, prefix)
			break
		}
	}
	if body == "" && len(v.Reasons) > 0 {
		body = v.Reasons[0]
	}
	out := tag + "(" + string(v.Phase) + "): " + body
	if n := len(v.Cleanup.Failures()); n > 0 {
		out += fmt.Sprintf(" [cleanupFailures=%d]", n)
	}
	return out
}

// legacyValidity is the block reported for a row that predates this contract.
func legacyValidity() MeasurementValidity {
	return MeasurementValidity{
		Version: 0,
		Kind:    TrialOrdinary,
		Status:  MeasurementLegacy,
		Phase:   PhaseComplete,
		Reasons: []string{"legacy: row carries no measurement-validity evidence; its zero fields are not evidence of a measurement"},
	}
}

// MeasurementState returns the row's validity block, or the LEGACY/UNVERIFIED
// block for a pre-contract row. It never infers validity from old zero fields.
func (m Metric) MeasurementState() MeasurementValidity {
	if m.Validity == nil {
		return legacyValidity()
	}
	return *m.Validity
}

// IsLegacy reports whether the row predates the validity contract.
func (m Metric) IsLegacy() bool { return m.Validity == nil }

// IsScored reports whether this row's disruption comparison is a real measured
// comparison that may enter a certified score. Legacy rows are never scored.
func (m Metric) IsScored() bool { return m.Validity != nil && m.Validity.Scored }

// Kind returns the explicit trial kind, falling back to the legacy markers for a
// pre-contract row (which never recorded the adaptive pass at all).
func (m Metric) Kind() TrialKind {
	if m.Validity != nil {
		return m.Validity.Kind
	}
	if m.NegativeControl {
		return TrialNegativeControl
	}
	return TrialOrdinary
}

// CostObserved reports whether the defensive-action count on this row is an
// observation rather than an absence. Legacy rows are never treated as observed.
func (m Metric) CostObserved() bool { return m.Validity != nil && m.Validity.CostObserved }

// CleanupFailed reports whether any owed cleanup step failed or was not
// attempted. Legacy rows never recorded cleanup, so they report false and are
// excluded from certified scores on the legacy ground instead.
func (m Metric) CleanupFailed() bool {
	return m.Validity != nil && !m.Validity.Cleanup.Complete
}
