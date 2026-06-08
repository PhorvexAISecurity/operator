/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package ctxprov is the swappable CONTEXT surface (PRD §5.2 / §4.2: the five sensed
// signals that condition the decision but are not physical laws). A ContextProvider
// turns a WorkloadView into ContextSignals {assetValue, phase, threatPosture,
// exposure, sloHeadroom}.
//
// Add a provider = add ONE file with an init() that calls Registry.Register.
package ctxprov

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/registry"
)

// ContextProvider computes the per-pod conditioning signals.
type ContextProvider interface {
	registry.Named
	Context(view *model.WorkloadView, pol model.Policy) model.ContextSignals
}

// Registry holds the registered ContextProviders.
var Registry = registry.New[ContextProvider]()
