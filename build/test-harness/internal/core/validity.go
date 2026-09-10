package core

import (
	"fmt"
	"math"
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
	// Unresolved is true when the step did not return within its bound. The work
	// may still be running: the harness does not claim the state is clean, and it
	// does not claim the step failed either. It is simply not known to be done.
	Unresolved bool `json:"unresolved,omitempty"`
	// Seconds is the wall-clock time the step was waited on.
	Seconds float64 `json:"seconds,omitempty"`
}

// Resolved reports whether the step is known to have finished successfully.
func (s CleanupStep) Resolved() bool { return s.Error == "" && !s.Unresolved }

// CleanupRecord retains EVERY cleanup/close attempt owed by the phases this
// trial actually entered, together with every failure. Cleanup is attempted even
// when the trial context was cancelled (on a bounded, detached context), because
// a trial that stops before attempted cleanup leaves state no later trial may
// safely reuse.
type CleanupRecord struct {
	Attempted []CleanupStep `json:"attempted,omitempty"`
	// Complete is true iff every owed step was attempted AND is known to have
	// succeeded within its bound. An unresolved step never makes it true.
	Complete bool `json:"complete"`
	// Unresolved is true when at least one step outlived its bound and may still
	// be running. The harness keeps ownership of it (see Runner.PendingCleanup)
	// and refuses to reuse the state.
	Unresolved bool `json:"unresolved,omitempty"`
	// Verified is true when the owned resources were observed to be GONE after
	// the deletes, rather than merely requested. Accepted background deletion is
	// not proof of absence.
	Verified bool `json:"verified,omitempty"`
}

// Failures returns the cleanup steps that returned an error.
func (c CleanupRecord) Failures() []CleanupStep {
	var out []CleanupStep
	for _, s := range c.Attempted {
		if s.Error != "" {
			out = append(out, s)
		}
	}
	return out
}

// Unfinished returns every step that is not known to have finished cleanly —
// failures AND unresolved steps.
func (c CleanupRecord) Unfinished() []CleanupStep {
	var out []CleanupStep
	for _, s := range c.Attempted {
		if !s.Resolved() {
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
	if v.Cleanup.Unresolved {
		out += " [cleanupUNRESOLVED]"
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

// MeasurementState returns the row's validity block as WRITTEN (the claim), or
// the LEGACY/UNVERIFIED block for a pre-contract row. It is the raw decoded
// evidence and is NOT a verdict: `scored: true` here is only an assertion by
// whatever produced the row. Every consumer that decides whether a number may be
// used must go through Validated().
func (m Metric) MeasurementState() MeasurementValidity {
	if m.Validity == nil {
		return legacyValidity()
	}
	return *m.Validity
}

// IsLegacy reports whether the row predates the validity contract.
func (m Metric) IsLegacy() bool { return m.Validity == nil }

// ---------------------------------------------------------------------------
// The ONE validated interpretation.
//
// A metrics file is an untrusted input: it may have been written by a newer or
// older harness, hand-edited, truncated or replayed. Decoding a validity block
// therefore proves only what the row CLAIMS. Validated() is the single place
// where those claims are checked against each other and against this build's
// supported contract, and it is what IsScored/CostObserved/Kind, every
// aggregator and every reader use. Nothing else may consult `Scored` directly.
//
// A row whose claims do not validate is never silently dropped and never
// re-interpreted: it stays visible as UNVERIFIED, is counted, carries the exact
// rejections, and is excluded from certified scores.
// ---------------------------------------------------------------------------

// SupportedTrialKinds / SupportedStatuses are the values THIS build understands.
// Anything else is unverifiable rather than assumed benign.
func supportedKind(k TrialKind) bool {
	switch k {
	case TrialOrdinary, TrialNegativeControl, TrialAdaptive:
		return true
	}
	return false
}

func supportedStatus(s MeasurementStatus) bool {
	switch s {
	case MeasurementValid, MeasurementInvalid, MeasurementSkipped, MeasurementLegacy:
		return true
	}
	return false
}

// ValidatedMeasurement is the verdict on one row: what it claimed, whether this
// build can interpret the claim at all, and what may actually be used.
type ValidatedMeasurement struct {
	// Claim is the block exactly as decoded (or the legacy stub).
	Claim MeasurementValidity
	// Supported is false when the version, kind or status is not one this build
	// understands. An unsupported row is readable but never certifiable.
	Supported bool
	// Legacy marks a pre-contract row (no validity block at all).
	Legacy bool
	// Unverified is true when the row is neither legacy nor interpretable as a
	// consistent claim: an unsupported marker, or evidence that contradicts
	// itself. Such rows still appear in every count.
	Unverified bool
	// Scorable is the ONLY authority for letting DisruptionVsOracle and anything
	// derived from it enter a certified score.
	Scorable bool
	// CostUsable is the ONLY authority for using DefensiveActions /
	// TimeToActionSeconds / SecurityPerCost / ROI / Schwartau from this row.
	CostUsable bool
	// OracleUsable is the ONLY authority for counting OracleAchieved as an
	// observation.
	OracleUsable bool
	// Rejections lists every reason a claim was refused, in a stable order.
	Rejections []string
}

// Kind is the validated trial kind; an unsupported kind reports ordinary so the
// row still appears in the default view rather than vanishing from every bucket.
func (v ValidatedMeasurement) Kind() TrialKind {
	if supportedKind(v.Claim.Kind) {
		return v.Claim.Kind
	}
	return TrialOrdinary
}

// Status is the validated status; an unsupported status reports invalid, which
// is the conservative bucket (visible, counted, never scored).
func (v ValidatedMeasurement) Status() MeasurementStatus {
	if supportedStatus(v.Claim.Status) {
		return v.Claim.Status
	}
	return MeasurementInvalid
}

// Reasons are the row's own recorded reasons followed by this build's
// rejections, so a report shows both what the producer said and why the claim
// was refused.
func (v ValidatedMeasurement) Reasons() []string {
	out := append([]string(nil), v.Claim.Reasons...)
	return append(out, v.Rejections...)
}

func (v *ValidatedMeasurement) reject(format string, args ...any) {
	v.Rejections = append(v.Rejections, fmt.Sprintf(format, args...))
	v.Unverified = true
}

// Validated checks the row's claims against this build's contract and against
// each other. It is deliberately strict: any claim it cannot corroborate is
// refused rather than trusted.
func (m Metric) Validated() ValidatedMeasurement {
	v := ValidatedMeasurement{Claim: m.MeasurementState()}

	if m.Validity == nil {
		// Pre-contract row: readable, counted, never scored, nothing inferred
		// from its zero fields.
		v.Legacy = true
		v.Supported = true
		return v
	}

	c := v.Claim
	v.Supported = c.Version == MeasurementValidityVersion && supportedKind(c.Kind) && supportedStatus(c.Status)
	if c.Version != MeasurementValidityVersion {
		v.reject("validity version %d is not the supported contract version %d: this row cannot be interpreted or certified by this build",
			c.Version, MeasurementValidityVersion)
	}
	if !supportedKind(c.Kind) {
		v.reject("unknown trial kind %q: this row cannot be attributed to a comparison, a control or an adaptive pass", c.Kind)
	}
	if !supportedStatus(c.Status) {
		v.reject("unknown measurement status %q: treated as invalid", c.Status)
	}

	// Independent, self-consistent evidence for the individual observations. A
	// consumer may use these even on a row whose comparison is not scorable.
	v.OracleUsable = v.Supported && c.Status == MeasurementValid && c.OracleObserved
	v.CostUsable = v.Supported && c.Status == MeasurementValid && c.CostObserved
	if c.CostObserved && m.DefensiveActions < 0 {
		v.reject("costObserved is claimed but defensiveActions=%d is the UNOBSERVED sentinel", m.DefensiveActions)
		v.CostUsable = false
	}
	if c.CostObserved && !isFiniteNonNegative(m.TimeToActionSeconds) {
		v.reject("costObserved is claimed but timeToActionSeconds=%v is not a finite, non-negative measurement", m.TimeToActionSeconds)
		v.CostUsable = false
	}
	if !isFiniteNonNegative(m.AttackerDwellSeconds) {
		v.reject("attackerDwellSeconds=%v is not a finite, non-negative measurement", m.AttackerDwellSeconds)
		v.OracleUsable = false
	}

	// The comparison itself. Every one of these must hold; `scored: true` alone
	// is never sufficient.
	switch {
	case !c.Scored:
		// Nothing claimed, nothing to contradict.
	case !v.Supported:
		v.Rejections = append(v.Rejections, "scored is claimed on a row this build cannot interpret")
	default:
		v.Scorable = true
		if c.Status != MeasurementValid {
			v.reject("scored is claimed but the measurement status is %q", c.Status)
			v.Scorable = false
		}
		if c.Kind == TrialNegativeControl {
			v.reject("scored is claimed on a negative control, which has no disruption comparison")
			v.Scorable = false
		}
		if !c.OracleObserved {
			v.reject("scored is claimed but no oracle verdict was observed")
			v.Scorable = false
		}
		if !c.Cleanup.Complete {
			v.reject("scored is claimed but the owed cleanup did not verify: the trial state is unresolved")
			v.Scorable = false
		}
		if n := len(c.Cleanup.Failures()); n > 0 {
			v.reject("scored is claimed alongside %d retained cleanup failure(s)", n)
			v.Scorable = false
		}
		if !c.Baseline.Usable {
			v.reject("scored is claimed but the positive control is not usable (required=%v observed=%v valid=%v oracleAchieved=%v)",
				c.Baseline.Required, c.Baseline.Observed, c.Baseline.Valid, c.Baseline.OracleAchieved)
			v.Scorable = false
		} else if !c.Baseline.Observed || !c.Baseline.Valid || !c.Baseline.OracleAchieved {
			v.reject("the positive control is marked usable but its own evidence contradicts that (observed=%v valid=%v oracleAchieved=%v)",
				c.Baseline.Observed, c.Baseline.Valid, c.Baseline.OracleAchieved)
			v.Scorable = false
		} else if c.Baseline.Defender == "" {
			v.reject("the positive control has no recorded identity, so the comparison cannot be traced to a control arm")
			v.Scorable = false
		}
		if !isFiniteInUnitRange(m.DisruptionVsOracle) {
			v.reject("scored is claimed but disruptionVsOracle=%v is outside the measurable range [0,1]", m.DisruptionVsOracle)
			v.Scorable = false
		}
	}

	// A row whose evidence contradicts ITSELF is not partially trustworthy. If
	// the producer asserted something this build can disprove from the row's own
	// fields, its remaining assertions carry no weight either: the row stays
	// visible and counted as UNVERIFIED, and contributes to nothing.
	if v.Unverified {
		v.Scorable, v.CostUsable, v.OracleUsable = false, false, false
	}
	return v
}

// isFiniteNonNegative rejects NaN, +/-Inf and negative sentinels where a real
// measurement is required.
func isFiniteNonNegative(x float64) bool {
	return !math.IsNaN(x) && !math.IsInf(x, 0) && x >= 0
}

func isFiniteInUnitRange(x float64) bool {
	return isFiniteNonNegative(x) && x <= 1
}

// IsScored reports whether this row's disruption comparison may enter a
// certified score. It is the VALIDATED verdict, never the row's own claim.
func (m Metric) IsScored() bool { return m.Validated().Scorable }

// Kind returns the validated trial kind, falling back to the legacy markers for
// a pre-contract row (which never recorded the adaptive pass at all).
func (m Metric) Kind() TrialKind {
	if m.Validity == nil {
		if m.NegativeControl {
			return TrialNegativeControl
		}
		return TrialOrdinary
	}
	return m.Validated().Kind()
}

// CostObserved reports whether the defensive-action count and timing on this row
// may be used as observations. It is the VALIDATED verdict.
func (m Metric) CostObserved() bool { return m.Validated().CostUsable }

// CleanupFailed reports whether any owed cleanup step failed, was not attempted
// or is unresolved. Legacy rows never recorded cleanup, so they report false and
// are excluded from certified scores on the legacy ground instead.
func (m Metric) CleanupFailed() bool {
	return m.Validity != nil && !m.Validity.Cleanup.Complete
}
