/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package ctxprov is the swappable CONTEXT surface (PRD §5.2 / §4.2). A
// ContextProvider records five sensed signals in ContextSignals {assetValue, phase,
// threatPosture, exposure, sloHeadroom}; not every recorded scalar is an independent
// targeting input. In the default P1 engine ThreatPosture is audit/explainability
// only. Raw SecurityEvents and their severity enter targeting once, through
// killchain.Assess -> P(hold)/stage urgency -> recon-fact weights (PHORVEXSEC-58).
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
