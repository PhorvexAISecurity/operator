package actionset

// Candidate gate identifiers, in the order Generate evaluates them for one (asset,
// action). Every exclusion carries exactly one, the first veto. A candidate excluded at
// gate k actually passed every per-candidate gate before k and never reached any gate
// after it, so later gates are NOT_EVALUATED, never an implicit pass.
const (
	// GateReconAbsent is asset-level: a non-finite recon input minted no fact, so every
	// enabled action on the asset is excluded before any per-candidate gate runs.
	GateReconAbsent        = "G0-recon-absent"
	GatePolicyBinding      = "G1-policy-binding"
	GateUnsupportedAction  = "G2-unsupported-action"
	GateQuarantineCapacity = "G3-quarantine-capacity"
	GateCapability         = "G4-capability"
	GateSharedResources    = "G5-shared-resources"
	GateFeasibility        = "G6-feasibility"
	GateCostNaN            = "G7-cost-nan"
	// G8 is the set-level objective pricing check in the decision engine (an invalid
	// economics configuration rejects the whole set); it never excludes one candidate.
	GateObjectivePricing = "G8-objective-pricing"
	GateCHiCeiling       = "G9-chi-ceiling"
)

// CandidateGateOrder is the per-candidate evaluation order used by Generate.
var CandidateGateOrder = []string{
	GatePolicyBinding, GateUnsupportedAction, GateQuarantineCapacity, GateCapability,
	GateSharedResources, GateFeasibility, GateCostNaN, GateCHiCeiling,
}
