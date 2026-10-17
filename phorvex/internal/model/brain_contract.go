package model

// Types the dispatcher and the brain exchange (ADR-0001). They live here, in the
// shared domain, so the brain contract (internal/brainapi) needs no brain package.

// Eligibility is the capability gate's verdict for one (asset, action). nil means
// eligible and clean.
type Eligibility struct {
	Excluded    bool   // true = drop from ranking with Kind/Detail
	Kind        string // capability Reason* class (only when Excluded)
	Detail      string // exclusion detail, or the rbac-unknown note
	RBACUnknown bool   // SSAR errored — NOT excluded, flagged (fail-open, P-NO-FREEZE)
}

// Alternative is selected from the exact action set and runtime price used by
// the original production pass. Other selected assets, including earlier
// same-tick exchanges, stay reserved; the failed target exchanges one slot.
type Alternative struct {
	ObjectivePenalty               OptionalFloat
	Action                         Action
	Coverage, Marginal, Cost, Gain float64
	CoverKeys                      []string
	Attribution                    []AttributionTerm
	Resources                      []ResourceConsumption
	CounterfactualNote             string
}

// CostCalibrationState reports whether a tenant's rotation-cost learner has left
// the shipped prior and how many observations it has folded in.
type CostCalibrationState struct {
	Primed  bool
	Updates int
}

// PersistenceObservationAuthority resolves immutable retained operation state.
// AuthorizeObservation must authenticate the complete categorical result and
// evidence hashes; knowing an operation ID or source name is insufficient.
type PersistenceObservationAuthority interface {
	Source() string
	AuthorizeObservation(PersistenceObservation) (PersistenceOperationBinding, bool)
}

// PersistenceObservationResult reports whether one authenticated observation
// entered the reporting-only cohort store. Applied never means mitigation or
// attacker-state learning.
type PersistenceObservationResult struct {
	Disposition string
	Applied     bool
	Reason      string
	Status      ScopedOutcomeReport
}
