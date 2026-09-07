/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package physics is the swappable PHYSICS surface: a PhysicsProfile turns a pod's
// NO LIVE CONSUMER SINCE M-107 (PHORVEXSEC-195): the p0 greedy engine was the only caller of
// Residual (it weighted it at 0.35 of baseRisk); with p0 retired the profile is computed by
// nothing on the decision path. It is kept — the T1-M115 ruling (PHORVEXSEC-198) fixed its
// mathematics — but giving it a P1 consumer is a Math-first decision, not a side effect of a
// deletion. Until then it is dead on the live path; see also PHORVEXSEC-75.
//
// live telemetry into a residual r_i(t) in [0,1] — how far the pod is behaving from
// its healthy model. High residual = behaving unlike itself = elevated risk, even
// with no detector alert (the detection-independent signal, PRD §5.1/§4.1).
//
// Add a profile = add ONE file with an init() that calls Registry.Register. The
// decision engine reads it back via Registry.Default()/Get(); no core change.
package physics

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/registry"
)

// PhysicsProfile is the governing-behavior model of a healthy workload and the
// measured deviation from it.
type PhysicsProfile interface {
	registry.Named
	// Residual returns r_i in [0,1]. It MUST be honest about missing telemetry:
	// when view.Telemetry.Present is false it returns 0 (no fabricated anomaly).
	Residual(view *model.WorkloadView, pol model.Policy) float64
}

// Registry holds the registered PhysicsProfiles.
var Registry = registry.New[PhysicsProfile]()
