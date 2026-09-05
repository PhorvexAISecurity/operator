/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package cost

import "github.com/phorvex/phorvex/internal/model"

// phase_encoding.go is the SINGLE SPEC for the WorkloadPhase cost vocabulary (T1-D).
// Before T1-D the phase→cost mapping was restated THREE times by hand — flowCost's
// heuristic switch, Features' one-hot switch, and priorTheta's positional literal —
// with nothing to stop them drifting. All three now derive from phaseFlowEncoding, and
// phase_vocabulary_test.go binds it to model.AllWorkloadPhases (the source of truth).
//
// Math gate for T1-D is NO: every number here is byte-identical to the pre-T1-D source
// (v0.4.84 / 5fe1c8e). Moving an existing parameter into a table chooses nothing.

// Non-phase RLS prior weights — the theta positions that carry no phase bit. Named
// constants, NOT table rows: phaseFlowEncoding is phase-keyed only.
const (
	biasPrior = 0.15 // priorTheta[0] — the idle floor
	gpuPrior  = 0.45 // priorTheta[4]
	loadPrior = 0.20 // priorTheta[5]
)

// phaseEnc is one phase's full cost encoding across both C_flow paths.
type phaseEnc struct {
	switchPrior float64 // flowCost heuristic phase prior (pre gpu/load), the rotate path
	featureBit  int     // RLS one-hot feature index; -1 = no bit (bias-only encoding)
	priorWeight float64 // priorTheta[featureBit]; meaningful only when featureBit >= 0
}

// phaseFlowEncoding: one row per model.AllWorkloadPhases member (enforced by the
// completeness test). Values are byte-identical to the pre-T1-D source.
var phaseFlowEncoding = map[model.WorkloadPhase]phaseEnc{
	model.PhaseColdStarting: {switchPrior: 1.0, featureBit: 1, priorWeight: 0.85}, // worst case to rotate
	model.PhaseWarm:         {switchPrior: 0.7, featureBit: 2, priorWeight: 0.55},
	model.PhaseIdle:         {switchPrior: 0.15, featureBit: 3, priorWeight: 0.0}, // cheapest to rotate
	model.PhaseDraining:     {switchPrior: 0.2, featureBit: -1, priorWeight: 0},
	// M-156 (ECONOMICS · Math-gate, xref M-139): the learned path prices Unknown at the
	// bias floor 0.15 (featureBit -1) while the heuristic prices it 0.5 — latent while
	// λ=0, a cheapest-rotate regression once λ>0. Do NOT reprice this row without a Math
	// ruling; T1-D's Math gate is NO.
	model.PhaseUnknown: {switchPrior: 0.5, featureBit: -1, priorWeight: 0},
}

// phaseEncoding returns a phase's encoding, falling back to the Unknown row for any
// out-of-vocabulary WorkloadPhase string. The fallback is EXPLICIT, not a zero-value
// map read: an unrecognized phase must encode exactly as Unknown (switchPrior 0.5, no
// feature bit) — matching the pre-T1-D fall-through. A zero-value row would instead
// make it free-to-rotate (switchPrior 0.0) AND set the bias bit (featureBit 0),
// strictly worse on both axes.
func phaseEncoding(p model.WorkloadPhase) phaseEnc {
	if enc, ok := phaseFlowEncoding[p]; ok {
		return enc
	}
	return phaseFlowEncoding[model.PhaseUnknown]
}
