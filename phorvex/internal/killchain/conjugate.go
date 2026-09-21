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
	// [P-VCLUSTER O3] crossTenantPrior gates the hierarchical fleet prior. DEFAULT OFF (zero value):
	// no tenant's evidence ever feeds another's prior, and a cold tenant seeds from the fixed default
	// base-rate (byte-identical to the pre-P-VCLUSTER nil-data behavior). Opt-in per trusted group.
	crossTenantPrior bool
}

// SetCrossTenantPrior opts a (trusted) memory into the hierarchical fleet prior (cross-tenant
// evidence sharing). Default OFF — tenants are isolated. Returns the memory for chaining.
func (m *ConjugateMemory) SetCrossTenantPrior(on bool) *ConjugateMemory {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crossTenantPrior = on
	return m
}

type tenantState struct {
	alpha float64
	beta  float64
}

const (
	DefaultPersistenceAlpha = 1.0
	DefaultPersistenceBeta  = 4.0
	PersistenceMassCap      = 200.0
)

// NewConjugateMemory returns a memory with a low-ish prior mean (alpha=1,beta=4 ->
// mean 0.2: absent evidence, assume a foothold is probably NOT still held).
func NewConjugateMemory() *ConjugateMemory {
	return &ConjugateMemory{
		tenants:  map[string]*tenantState{},
		defAlpha: DefaultPersistenceAlpha,
		defBeta:  DefaultPersistenceBeta,
		maxMass:  PersistenceMassCap,
		gAlpha:   DefaultPersistenceAlpha, // fleet prior seeded TO the defaults => cold = old constant exactly
		gBeta:    DefaultPersistenceBeta,
	}
}

// seedState computes the prior a not-yet-seen tenant starts from, WITHOUT storing it.
// [P-VCLUSTER O3] DEFAULT: seed from the fixed default base-rate (no cross-tenant inheritance).
// At nil-data the fleet equals the defaults, so this is byte-identical to the prior behavior;
// the hierarchical fleet seed is used ONLY when crossTenantPrior is opted in for a trusted group.
// Callers hold m.mu.
func (m *ConjugateMemory) seedState() tenantState {
	mass := m.defAlpha + m.defBeta
	gMean := m.defAlpha / mass
	if m.crossTenantPrior && m.gAlpha+m.gBeta > 0 {
		gMean = m.gAlpha / (m.gAlpha + m.gBeta)
	}
	return tenantState{alpha: gMean * mass, beta: (1 - gMean) * mass}
}

// get lazily seeds a new tenant from the FLEET base-rate (hierarchical prior) at the
// default mass, instead of the fixed constant. At nil-data the fleet equals the
// defaults, so a new tenant is byte-identical to the pre-P-CONTEXT behavior.
func (m *ConjugateMemory) get(tenant string) *tenantState {
	s := m.tenants[tenant]
	if s == nil {
		seeded := m.seedState()
		s = &seeded
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

// PriorPeek returns the SAME (alpha, beta) Prior would return, but never allocates a
// tenant entry (M-163). A counterfactual reader must not be the event that brings an
// owner's learned belief into existence: a tenant this memory has already learned about
// is read exactly as-is, and an unseen one reports the seed it WOULD get without taking
// it, so the first real production assessment still performs that seeding itself.
func (m *ConjugateMemory) PriorPeek(tenant string) (float64, float64) {
	if m == nil {
		return 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.tenants[tenant]; s != nil {
		return s.alpha, s.beta
	}
	seeded := m.seedState()
	return seeded.alpha, seeded.beta
}

// priorFor selects the committing or read-only prior read for an evaluation mode.
func (m *ConjugateMemory) priorFor(tenant string, mode EvalMode) (float64, float64) {
	if mode.Commits() {
		return m.Prior(tenant)
	}
	return m.PriorPeek(tenant)
}

// Tracked reports whether this memory already holds learned state for an owner. It is the
// observability seam for the M-163 isolation assertion (a shadow pass must not create one)
// and for lifecycle checks; it allocates nothing.
func (m *ConjugateMemory) Tracked(tenant string) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.tenants[tenant]
	return ok
}

// Observe is the low-level pseudo-count primitive retained for deterministic model
// fixtures. Production outcome learning enters through the decision package's typed
// observed-persistence boundary and calls ObserveBernoulli exactly once.
func (m *ConjugateMemory) Observe(tenant string, heldEvidence float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.get(tenant)
	// per-tenant belief (already isolated, keyed by tenant) — unchanged.
	if heldEvidence > 0 {
		s.alpha += heldEvidence
	} else if heldEvidence < 0 {
		s.beta += -heldEvidence
	}
	if total := s.alpha + s.beta; total > m.maxMass {
		scale := m.maxMass / total
		s.alpha *= scale
		s.beta *= scale
	}
	// [P-VCLUSTER O3/G3] The fleet hyperprior cross-feed is a SHARED WRITE across tenants — a cold
	// tenant would inherit another tenant's evidence. It is GATED OFF by default: gAlpha/gBeta (and
	// their rescale, G3) update ONLY when an operator opts a TRUSTED tenant-group into the hierarchical
	// prior. With it off, a cold tenant seeds from the fixed default base-rate (see get) — byte-identical.
	if m.crossTenantPrior {
		if heldEvidence > 0 {
			m.gAlpha += heldEvidence
		} else if heldEvidence < 0 {
			m.gBeta += -heldEvidence
		}
		if gt := m.gAlpha + m.gBeta; gt > m.maxMass {
			scale := m.maxMass / gt
			m.gAlpha *= scale
			m.gBeta *= scale
		}
	}
}

// ObserveBernoulli submits one unit of qualified categorical evidence: held to
// alpha and revoked to beta. Observe then applies the existing maxMass rescaling,
// so effective alpha/beta mass is bounded and is not the raw qualified-label count.
func (m *ConjugateMemory) ObserveBernoulli(tenant string, held bool) {
	if held {
		m.Observe(tenant, 1)
		return
	}
	m.Observe(tenant, -1)
}

// PriorMean is the tenant's prior P(hold) before per-asset evidence.
func (m *ConjugateMemory) PriorMean(tenant string) float64 {
	return m.PriorMeanMode(tenant, EvalProduction)
}

// PriorMeanMode is PriorMean for an explicit evaluation mode: a shadow read reports the
// identical number without seeding an unseen tenant (M-163).
func (m *ConjugateMemory) PriorMeanMode(tenant string, mode EvalMode) float64 {
	a, b := m.priorFor(tenant, mode)
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
	return m.PHoldUCBWithEvidenceMode(tenant, eventAlpha, k, EvalProduction)
}

// PHoldUCBWithEvidenceMode is PHoldUCBWithEvidence for an explicit evaluation mode. The
// arithmetic is shared, so a shadow assessment reads the SAME learned prior and returns the
// same posterior; only the lazy seeding of an unseen tenant is withheld (M-163).
func (m *ConjugateMemory) PHoldUCBWithEvidenceMode(tenant string, eventAlpha, k float64, mode EvalMode) float64 {
	a, b := m.priorFor(tenant, mode)
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

// Forget drops one owner's accumulated belief state (M-140). A recreated policy is a new
// economic unit, so it must start from the shipped default prior rather than inheriting the
// previous occupant's evidence. The fleet hyperprior is intentionally NOT rewound: it is
// gated off by default (crossTenantPrior), has no non-test production caller, and evidence
// already mixed into it cannot be honestly un-mixed for one contributor.
func (m *ConjugateMemory) Forget(owner string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tenants, owner)
}
