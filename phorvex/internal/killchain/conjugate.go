/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

// Package killchain is the P1 BELIEF + RECON-INVALIDATION layer: a deterministic
// semi-Markov kill-chain model whose explicit per-stage SOJOURN HAZARD is the
// PREDICTIVE BELIEF HORIZON (it rises before the attacker transitions to the next,
// higher-consequence stage), plus a Beta-Bernoulli P(hold) estimator and a per-tenant
// CONJUGATE MEMORY of learned priors (the context-memory layer). No LLM; every output
// is a closed-form, explainable number.
package killchain

import (
	"math"
	"sync"
)

// ConjugateMemory is the per-tenant context-MEMORY: a Beta(alpha,beta) belief that
// accumulates evidence of whether this tenant's footholds tend to persist (held) or
// not, used as the PRIOR the per-asset P(hold) is corrected from. It is a tunable
// (the global defaults are flagged proposals, never paper values). In-memory and
// restart-rebuilt from telemetry (NFR3); persistence to PhorvexPolicy.status is a
// later refinement.
type ConjugateMemory struct {
	mu       sync.Mutex
	tenants  map[string]*tenantState
	defAlpha float64
	defBeta  float64
	// maxMass caps accumulated pseudo-counts so the memory stays adaptive (a
	// forgetting bound), not frozen by old evidence.
	maxMass float64
	// --- P-CONTEXT hierarchical empirical-Bayes prior: a fleet-wide Beta(gAlpha,gBeta)
	// updated alongside every per-tenant Observe. A COLD or thin tenant inherits the
	// FLEET base-rate instead of the fixed defAlpha/defBeta. Seeded TO the defaults, so
	// at nil-data (no Observe yet) a new tenant is byte-identical to the old constant. ---
	gAlpha float64
	gBeta  float64
}

type tenantState struct {
	alpha float64
	beta  float64
}

// NewConjugateMemory returns a memory with a low-ish prior mean (alpha=1,beta=4 ->
// mean 0.2: absent evidence, assume a foothold is probably NOT still held).
func NewConjugateMemory() *ConjugateMemory {
	return &ConjugateMemory{
		tenants:  map[string]*tenantState{},
		defAlpha: 1,
		defBeta:  4,
		maxMass:  200,
		gAlpha:   1, // fleet prior seeded TO the defaults => cold = old constant exactly
		gBeta:    4,
	}
}

// get lazily seeds a new tenant from the FLEET base-rate (hierarchical prior) at the
// default mass, instead of the fixed constant. At nil-data the fleet equals the
// defaults, so a new tenant is byte-identical to the pre-P-CONTEXT behavior.
func (m *ConjugateMemory) get(tenant string) *tenantState {
	s := m.tenants[tenant]
	if s == nil {
		mass := m.defAlpha + m.defBeta
		gMean := 0.2
		if m.gAlpha+m.gBeta > 0 {
			gMean = m.gAlpha / (m.gAlpha + m.gBeta)
		}
		s = &tenantState{alpha: gMean * mass, beta: (1 - gMean) * mass}
		m.tenants[tenant] = s
	}
	return s
}

// Prior returns the tenant's learned Beta prior (alpha, beta).
func (m *ConjugateMemory) Prior(tenant string) (float64, float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.get(tenant)
	return s.alpha, s.beta
}

// Observe accumulates evidence: heldEvidence > 0 adds to alpha (foothold tended to
// persist), < 0 adds |.| to beta (it did not). Pseudo-counts are capped at maxMass so
// the prior keeps adapting.
func (m *ConjugateMemory) Observe(tenant string, heldEvidence float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.get(tenant)
	if heldEvidence > 0 {
		s.alpha += heldEvidence
		m.gAlpha += heldEvidence // feed the fleet prior
	} else if heldEvidence < 0 {
		s.beta += -heldEvidence
		m.gBeta += -heldEvidence
	}
	if total := s.alpha + s.beta; total > m.maxMass {
		scale := m.maxMass / total
		s.alpha *= scale
		s.beta *= scale
	}
	if gt := m.gAlpha + m.gBeta; gt > m.maxMass {
		scale := m.maxMass / gt
		m.gAlpha *= scale
		m.gBeta *= scale
	}
}

// PriorMean is the tenant's prior P(hold) before per-asset evidence.
func (m *ConjugateMemory) PriorMean(tenant string) float64 {
	a, b := m.Prior(tenant)
	if a+b <= 0 {
		return 0
	}
	return a / (a + b)
}

// PHoldWithEvidence returns the Beta posterior mean after adding eventAlpha
// per-asset held-evidence pseudo-counts to the tenant prior.
func (m *ConjugateMemory) PHoldWithEvidence(tenant string, eventAlpha float64) float64 {
	a, b := m.Prior(tenant)
	a += eventAlpha
	if a+b <= 0 {
		return 0
	}
	return a / (a + b)
}

// PHoldUCBWithEvidence returns the posterior mean PLUS a confidence bonus k * stderr,
// where stderr = sqrt(mean*(1-mean)/mass) recovers the (a+b) evidence MASS the plain
// mean discards. A THIN-evidence asset (small mass) is treated as UNCERTAIN -> a higher
// upper bound -> act sooner under uncertainty. k=0 returns the plain mean exactly
// (byte-identical), so the confidence channel is an opt-in Model-flagged knob.
func (m *ConjugateMemory) PHoldUCBWithEvidence(tenant string, eventAlpha, k float64) float64 {
	a, b := m.Prior(tenant)
	a += eventAlpha
	mass := a + b
	if mass <= 0 {
		return 0
	}
	mean := a / mass
	if k <= 0 {
		return mean
	}
	stderr := math.Sqrt(mean * (1 - mean) / mass)
	v := mean + k*stderr
	if v > 1 {
		v = 1
	}
	return v
}
