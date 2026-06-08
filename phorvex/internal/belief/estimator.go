/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package belief is the swappable BELIEF / RECON-INVALIDATION surface (PRD §5.2
// kill-chain belief + §4.1 exposure). A BeliefEstimator consumes the SecurityEvent
// stream + the exposure clock as EVIDENCE updating a kill-chain/recon belief — NOT
// as exact-match triggers. This is where "the longer a pod stays unchanged, the more
// recon an attacker has done" becomes a number, and the detection-independent
// proactive floor lives.
//
// Add an estimator = add ONE file with an init() that calls Registry.Register.
package belief

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/registry"
)

// BeliefEstimator returns a kill-chain / recon-invalidation risk contribution.
type BeliefEstimator interface {
	registry.Named
	// Belief returns a value in [0,1]: the belief that this pod is compromised /
	// has been sufficiently reconnoitred to warrant a proactive move, from event
	// evidence + exposure. It is detector-INDEPENDENT for the exposure component.
	Belief(view *model.WorkloadView, pol model.Policy) float64
}

// Registry holds the registered BeliefEstimators.
var Registry = registry.New[BeliefEstimator]()
