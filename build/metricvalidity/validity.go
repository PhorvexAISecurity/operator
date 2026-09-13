// Package metricvalidity is the SHARED, VERSIONED measurement-validity contract
// for the benchmark metric stream.
//
// It exists so there is exactly ONE implementation of "may this row be used as a
// measurement?". The harness writes the block; the harness's own reports and
// every downstream product reader import this package and call Evaluate. A
// reader that mirrored the wire format by hand inevitably omitted the fields the
// producer had started checking, and silently certified rows the producer would
// refuse — that class of bug is what this package removes.
//
// The invariant it enforces: a value alone never implies a measurement. A failed
// operation, a missing observation or a missing positive control must be
// representable as such, and must never be indistinguishable from "the defense
// worked" or "the cost was zero".
//
// A decoded block is a CLAIM, not a verdict. A metrics file is untrusted input:
// it may come from a newer or older harness, or have been edited, replayed or
// truncated. Evaluate is the single place those claims are checked against this
// build's supported contract AND against each other. Nothing may consult
// Validity.Scored directly.
//
// Compatibility: the block is carried as a pointer with `omitempty`, so a metrics
// file written before the contract existed still decodes — it decodes with a nil
// block, which is reported as LEGACY / UNVERIFIED. Legacy rows are never
// re-interpreted from their old zero fields and never rewritten; they are
// counted openly and excluded from certified scores.
//
// The package depends only on the standard library so that any consumer, in any
// module, can import it without pulling in the harness runtime.
package metricvalidity

import (
	"fmt"
	"math"
	"strings"
)

// Version is the version of the validity contract this build understands and
// stamps into every metric it emits. Bump it when the SEMANTICS of the block
// change, so a consumer can tell which rules produced a row — and so a consumer
// built against different rules refuses the row instead of guessing.
const Version = 1

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

// SupportedKind reports whether this build understands the trial kind.
func SupportedKind(k TrialKind) bool {
	switch k {
	case TrialOrdinary, TrialNegativeControl, TrialAdaptive:
		return true
	}
	return false
}

// Status is the outcome of the MEASUREMENT (not of the attack).
type Status string

const (
	// StatusValid means every phase the trial entered completed, the outcome was
	// actually observed, and all owed cleanup succeeded. A valid measurement may
	// still be UNSCORED if no usable control exists.
	StatusValid Status = "valid"
	// StatusInvalid means an infrastructure/harness failure prevented a
	// trustworthy measurement (factory, defender setup/start, scenario setup,
	// attack stimulus, oracle transport, cleanup). It is NOT an attack result.
	StatusInvalid Status = "invalid"
	// StatusSkipped means the trial REPORTED that it could not run: an unmet
	// capability requirement or a registered stub arm. It is a deliberate
	// abstention, distinct from an infrastructure failure and from a valid
	// failed attack.
	StatusSkipped Status = "skipped"
	// StatusLegacy marks a row decoded from a pre-contract file. Its validity was
	// never recorded, so it is unverified: displayed and counted, never scored.
	StatusLegacy Status = "legacy-unverified"
)

// SupportedStatus reports whether this build understands the status.
func SupportedStatus(s Status) bool {
	switch s {
	case StatusValid, StatusInvalid, StatusSkipped, StatusLegacy:
		return true
	}
	return false
}

// Phase names the lifecycle phase a trial reached.
type Phase string

const (
	PhaseEnvFactory     Phase = "env-factory"
	PhaseCapabilityGate Phase = "capability-gate"
	PhaseDefenderSetup  Phase = "defender-setup"
	PhaseScenarioSetup  Phase = "scenario-setup"
	PhaseDefenderStart  Phase = "defender-start"
	PhaseAttackExecute  Phase = "attack-execute"
	PhaseOracle         Phase = "oracle"
	PhaseObserver       Phase = "defense-observer"
	PhaseCleanup        Phase = "cleanup"
	PhaseComplete       Phase = "complete"
)

// BaselineRef records the IDENTITY and OBSERVED RESULT of the positive control a
// comparison was anchored to — or precisely why no usable control existed.
//
// HONEST SCOPE: the anchor is the control OBSERVED AT THE SAME TRIAL INDEX AND
// KIND on the undefended arm. It is NOT an identical-randomness counterfactual:
// the trial seed hashes the defender name, so the baseline arm's trial i and a
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
	// Blocked is true when the step was NOT ATTEMPTED because a previous step
	// that shares the same environment is still running. Starting it anyway
	// would race the unresolved callback over the same Env, logger and objects.
	Blocked bool `json:"blocked,omitempty"`
	// Seconds is the wall-clock time the step was waited on.
	Seconds float64 `json:"seconds,omitempty"`
}

// Resolved reports whether the step is known to have finished successfully.
func (s CleanupStep) Resolved() bool { return s.Error == "" && !s.Unresolved && !s.Blocked }

// CleanupRecord retains EVERY cleanup/close attempt owed by the phases a trial
// actually entered, together with every failure. Cleanup is attempted even when
// the trial context was cancelled (on a bounded, detached context), because a
// trial that stops before attempted cleanup leaves state no later trial may
// safely reuse.
type CleanupRecord struct {
	Attempted []CleanupStep `json:"attempted,omitempty"`
	// Complete is true iff every owed step was attempted AND is known to have
	// succeeded within its bound. An unresolved or blocked step never makes it
	// true.
	Complete bool `json:"complete"`
	// Unresolved is true when at least one step outlived its bound and may still
	// be running. The harness keeps ownership of it and refuses to reuse the
	// state.
	Unresolved bool `json:"unresolved,omitempty"`
	// Verified is true when the owned resources were observed to be GONE after
	// the deletes, rather than merely requested. Accepted deletion is not proof
	// of absence.
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
// failures, unresolved steps AND steps blocked by an unresolved predecessor.
func (c CleanupRecord) Unfinished() []CleanupStep {
	var out []CleanupStep
	for _, s := range c.Attempted {
		if !s.Resolved() {
			out = append(out, s)
		}
	}
	return out
}

// Sound reports whether the cleanup evidence is internally consistent AND clean.
// It is deliberately independent of Scored: a retained cleanup failure on an
// UNSCORED row (a negative control, say) is still a dirty trial, and must not
// yield a clean verdict merely because that kind never carries a comparison.
func (c CleanupRecord) Sound() bool {
	return c.Complete && !c.Unresolved && len(c.Unfinished()) == 0
}

// Validity is the versioned validity block stamped on every metric.
type Validity struct {
	// Version is the contract version at the time the row was written.
	Version int `json:"version"`
	// Kind is the explicit trial kind (ordinary / negative-control / adaptive).
	Kind TrialKind `json:"kind"`
	// Status is the measurement outcome.
	Status Status `json:"status"`
	// Phase is the last lifecycle phase entered.
	Phase Phase `json:"phase"`
	// Reasons retains every propagated error/abstention, phase-prefixed, in the
	// order encountered. It is never emptied by a later success.
	Reasons []string `json:"reasons,omitempty"`

	// AttackExecuted is true when the attack stimulus ran without error (or, for
	// a negative control, when the deliberate no-op was performed).
	AttackExecuted bool `json:"attackExecuted"`
	// OracleObserved is true when the success oracle actually produced a verdict.
	OracleObserved bool `json:"oracleObserved"`
	// ObserverPresent is true when the defender implements the observer hook.
	ObserverPresent bool `json:"observerPresent"`
	// CostObserved is true when the defensive-action count and timings were
	// actually read. When false the cost is UNOBSERVED — not zero — and no
	// efficiency or ROI number may be derived.
	CostObserved bool `json:"costObserved"`

	// Scored is the producer's CLAIM that DisruptionVsOracle is a real measured
	// comparison. It is never authoritative on its own; see Evaluate.
	Scored bool `json:"scored"`
	// UnscoredReason explains a valid-but-unscored row.
	UnscoredReason string `json:"unscoredReason,omitempty"`

	Baseline BaselineRef   `json:"baseline"`
	Cleanup  CleanupRecord `json:"cleanup"`
}

// Note appends a phase-prefixed reason, preserving order and earlier entries.
func (v *Validity) Note(phase Phase, msg string) {
	v.Reasons = append(v.Reasons, string(phase)+": "+msg)
}

// Enter advances the recorded phase only while the measurement is still valid,
// so Phase always names the phase that DECIDED the outcome rather than the last
// phase the lifecycle happened to touch afterwards.
func (v *Validity) Enter(phase Phase) {
	if v.Status == StatusValid {
		v.Phase = phase
	}
}

// Fail marks the measurement invalid at a phase and retains the reason. An
// earlier failure phase is never overwritten by a later one.
func (v *Validity) Fail(phase Phase, msg string) {
	v.Note(phase, msg)
	if v.Status != StatusInvalid {
		v.Status = StatusInvalid
		v.Phase = phase
	}
}

// Skip marks the measurement as a REPORTED abstention (capability/stub), which
// is distinct from an infrastructure failure. An already-invalid measurement
// stays invalid.
func (v *Validity) Skip(phase Phase, msg string) {
	v.Note(phase, msg)
	if v.Status == StatusValid {
		v.Status = StatusSkipped
		v.Phase = phase
	}
}

// Summary renders the compatibility skip-reason for a non-scored row: the tag
// distinguishes a REPORTED abstention from an infrastructure failure, the phase
// says where it happened, and cleanup problems are counted so a dirty trial is
// never mistaken for a clean skip.
func (v Validity) Summary() string {
	tag := "SKIP"
	if v.Status == StatusInvalid {
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

// Legacy returns the block reported for a row that predates this contract.
func Legacy() Validity {
	return Validity{
		Version: 0,
		Kind:    TrialOrdinary,
		Status:  StatusLegacy,
		Phase:   PhaseComplete,
		Reasons: []string{"legacy: row carries no measurement-validity evidence; its zero fields are not evidence of a measurement"},
	}
}

// Observations are the row's cross-field values. Evaluate corroborates the
// validity block against them, because a claim contradicted by the very numbers
// it describes is not a claim worth trusting.
//
// A reader that decodes only a subset of the metric schema still supplies these
// five, so it gets exactly the verdict the producer would give.
type Observations struct {
	// Trial is the row's own trial index. The anchor must be the control
	// observed at the SAME index, so the block's claimed baseline trial is
	// checked against this.
	Trial int
	// Disruption is DisruptionVsOracle.
	Disruption float64
	// DefensiveActions is the observed action count; negative means UNOBSERVED.
	DefensiveActions int
	// FalseDefensiveActions is the negative control's count; negative means
	// UNOBSERVED. Pass -1 on a non-negative-control row.
	FalseDefensiveActions int
	// TimeToActionSeconds / AttackerDwellSeconds are the measured timings.
	TimeToActionSeconds  float64
	AttackerDwellSeconds float64
}

// Verdict is the decision on one row: what it claimed, whether this build can
// interpret the claim at all, and what may actually be used.
type Verdict struct {
	// Claim is the block exactly as decoded (or the legacy stub).
	Claim Validity
	// Supported is false when the version, kind or status is not one this build
	// understands. An unsupported row is readable but never certifiable.
	Supported bool
	// Legacy marks a pre-contract row (no validity block at all).
	Legacy bool
	// Unverified is true when the row is neither legacy nor interpretable as a
	// consistent claim: an unsupported marker, or evidence that contradicts
	// itself. Such rows still appear in every count.
	Unverified bool
	// Scorable is the ONLY authority for letting the disruption value and
	// anything derived from it enter a certified score.
	Scorable bool
	// CostUsable is the ONLY authority for using the action count, timings,
	// security-per-cost, ROI or Schwartau figures from this row.
	CostUsable bool
	// OracleUsable is the ONLY authority for counting the oracle result as an
	// observation.
	OracleUsable bool
	// NegControlUsable is the ONLY authority for letting this row establish a
	// MEASURED false-defensive-move result.
	NegControlUsable bool
	// Rejections lists every reason a claim was refused, in a stable order.
	Rejections []string
}

// Kind is the validated trial kind; an unsupported kind reports ordinary so the
// row still appears in the default view rather than vanishing from every bucket.
func (v Verdict) Kind() TrialKind {
	if SupportedKind(v.Claim.Kind) {
		return v.Claim.Kind
	}
	return TrialOrdinary
}

// Status is the validated status; an unsupported status reports invalid, which
// is the conservative bucket (visible, counted, never scored).
func (v Verdict) Status() Status {
	if SupportedStatus(v.Claim.Status) {
		return v.Claim.Status
	}
	return StatusInvalid
}

// Reasons are the row's own recorded reasons followed by this build's
// rejections, so a report shows both what the producer said and why the claim
// was refused.
func (v Verdict) Reasons() []string {
	out := append([]string(nil), v.Claim.Reasons...)
	return append(out, v.Rejections...)
}

// UnscoredReason prefers the producer's own explanation and falls back to this
// build's first rejection, so a row refused on decode still says why.
func (v Verdict) UnscoredReason() string {
	if v.Scorable {
		return ""
	}
	if r := v.Claim.UnscoredReason; r != "" {
		return r
	}
	for _, r := range v.Rejections {
		if r != "" {
			return r
		}
	}
	return ""
}

func (v *Verdict) reject(format string, args ...any) {
	v.Rejections = append(v.Rejections, fmt.Sprintf(format, args...))
	v.Unverified = true
}

// Evaluate is THE validated interpretation. Every consumer — the harness's own
// aggregation and reports, and every downstream reader — goes through it.
//
// It is deliberately strict: any claim it cannot corroborate is refused rather
// than trusted. Refusal never hides a row; the caller keeps counting it and
// rendering its rejections.
func Evaluate(claim *Validity, obs Observations) Verdict {
	if claim == nil {
		// Pre-contract row: readable, counted, never scored, nothing inferred
		// from its zero fields.
		return Verdict{Claim: Legacy(), Legacy: true, Supported: true}
	}
	v := Verdict{Claim: *claim}
	c := *claim

	v.Supported = c.Version == Version && SupportedKind(c.Kind) && SupportedStatus(c.Status)
	if c.Version != Version {
		v.reject("validity version %d is not the supported contract version %d: this row cannot be interpreted or certified by this build",
			c.Version, Version)
	}
	if !SupportedKind(c.Kind) {
		v.reject("unknown trial kind %q: this row cannot be attributed to a comparison, a control or an adaptive pass", c.Kind)
	}
	if !SupportedStatus(c.Status) {
		v.reject("unknown measurement status %q: treated as invalid", c.Status)
	}

	// ---- Cleanup integrity is checked for EVERY row, not only scored ones.
	// A trial whose cleanup failed, is unresolved or was blocked left state
	// nobody verified; that is true of a negative control (which is never
	// "scored") exactly as it is of an ordinary comparison.
	cleanupSound := c.Cleanup.Sound()
	if c.Status == StatusValid && !cleanupSound {
		v.reject("status is claimed valid but the owed cleanup is not sound (complete=%v unresolved=%v unfinished=%d): the trial left unverified state",
			c.Cleanup.Complete, c.Cleanup.Unresolved, len(c.Cleanup.Unfinished()))
	}

	// ---- Baseline self-consistency is checked for EVERY row too. A control
	// marked usable whose own evidence denies it is a corrupt row whatever its
	// kind.
	b := c.Baseline
	if b.Usable && (!b.Observed || !b.Valid || !b.OracleAchieved) {
		v.reject("the positive control is marked usable but its own evidence contradicts that (observed=%v valid=%v oracleAchieved=%v)",
			b.Observed, b.Valid, b.OracleAchieved)
	}
	if b.Usable && b.Defender == "" {
		v.reject("the positive control is marked usable but has no recorded identity, so the comparison cannot be traced to a control arm")
	}
	// The anchor must be the control observed at the SAME trial index AND kind.
	// A cross-kind or cross-index anchor is a different experiment: an adaptive
	// control cannot anchor an ordinary comparison, and trial i cannot be
	// anchored to trial i+10. A row that references a control at all must say
	// which one, consistently.
	if b.Required || b.Usable {
		if b.Kind != c.Kind {
			v.reject("the positive control is a %q observation but this is a %q trial: a comparison may only anchor to a control of its own kind",
				b.Kind, c.Kind)
		}
		if b.Trial != obs.Trial {
			v.reject("the positive control is recorded at trial index %d but this is trial %d: a comparison may only anchor to the control observed at its own index",
				b.Trial, obs.Trial)
		}
	}

	// ---- Lifecycle self-consistency.
	// The oracle only runs once an attack has run — a negative control's
	// deliberate no-op counts as executed, so this does not penalise it.
	if c.OracleObserved && !c.AttackExecuted {
		v.reject("an oracle verdict is claimed without an executed attack: the oracle is only evaluated after a stimulus (or a negative control's deliberate no-op)")
	}
	// The defensive cost can only come from the observer hook.
	if c.CostObserved && !c.ObserverPresent {
		v.reject("a defensive cost is claimed observed while the arm exposes no observer: there is nothing that could have measured it")
	}
	// A measurement that reports itself VALID must have reached the terminal
	// phase. A row that stopped at setup is a partial-setup failure, which is a
	// legitimate and distinct state — but its status is not `valid`.
	if c.Status == StatusValid && c.Phase != PhaseComplete {
		v.reject("status is claimed valid at phase %q: a valid measurement must have reached %q", c.Phase, PhaseComplete)
	}

	// ---- Independent, self-consistent evidence for the individual
	// observations. A consumer may use these even on a row whose comparison is
	// not scorable.
	usableBase := v.Supported && c.Status == StatusValid && cleanupSound
	v.OracleUsable = usableBase && c.OracleObserved
	v.CostUsable = usableBase && c.CostObserved
	if c.CostObserved && obs.DefensiveActions < 0 {
		v.reject("costObserved is claimed but defensiveActions=%d is the UNOBSERVED sentinel", obs.DefensiveActions)
		v.CostUsable = false
	}
	if c.CostObserved && !finiteNonNegative(obs.TimeToActionSeconds) {
		v.reject("costObserved is claimed but timeToActionSeconds=%v is not a finite, non-negative measurement", obs.TimeToActionSeconds)
		v.CostUsable = false
	}
	if !finiteNonNegative(obs.AttackerDwellSeconds) {
		v.reject("attackerDwellSeconds=%v is not a finite, non-negative measurement", obs.AttackerDwellSeconds)
		v.OracleUsable = false
	}

	// ---- A negative control establishes a MEASURED false-move result only when
	// its own cost was observed on an interpretable, sound, valid row.
	v.NegControlUsable = v.Kind() == TrialNegativeControl && v.CostUsable && obs.FalseDefensiveActions >= 0
	if v.Kind() == TrialNegativeControl && c.CostObserved && obs.FalseDefensiveActions < 0 {
		v.reject("costObserved is claimed on a negative control but falseDefensiveActions=%d is the UNOBSERVED sentinel", obs.FalseDefensiveActions)
		v.NegControlUsable = false
	}

	// ---- The comparison itself. Every one of these must hold; `scored: true`
	// alone is never sufficient.
	switch {
	case !c.Scored:
		// Nothing claimed, nothing to contradict.
	case !v.Supported:
		v.Rejections = append(v.Rejections, "scored is claimed on a row this build cannot interpret")
	default:
		v.Scorable = true
		if c.Status != StatusValid {
			v.reject("scored is claimed but the measurement status is %q", c.Status)
			v.Scorable = false
		}
		if !c.AttackExecuted {
			v.reject("scored is claimed but no attack was executed: there is no stimulus to attribute a disruption to")
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
		if !cleanupSound {
			v.reject("scored is claimed but the owed cleanup did not verify: the trial state is unresolved")
			v.Scorable = false
		}
		if !b.Usable {
			v.reject("scored is claimed but the positive control is not usable (required=%v observed=%v valid=%v oracleAchieved=%v)",
				b.Required, b.Observed, b.Valid, b.OracleAchieved)
			v.Scorable = false
		}
		if !finiteInUnitRange(obs.Disruption) {
			v.reject("scored is claimed but disruptionVsOracle=%v is outside the measurable range [0,1]", obs.Disruption)
			v.Scorable = false
		}
	}

	// A row whose evidence contradicts ITSELF is not partially trustworthy. If
	// the producer asserted something this build can disprove from the row's own
	// fields, its remaining assertions carry no weight either: the row stays
	// visible and counted as UNVERIFIED, and contributes to nothing.
	if v.Unverified {
		v.Scorable, v.CostUsable, v.OracleUsable, v.NegControlUsable = false, false, false, false
	}
	return v
}

// finiteNonNegative rejects NaN, +/-Inf and negative sentinels where a real
// measurement is required.
func finiteNonNegative(x float64) bool {
	return !math.IsNaN(x) && !math.IsInf(x, 0) && x >= 0
}

func finiteInUnitRange(x float64) bool { return finiteNonNegative(x) && x <= 1 }
