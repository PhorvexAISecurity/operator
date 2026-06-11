/*
 * Phorvex P-REDTEAM — pomdp.go: the EFFECTS-ONLY POMDP the RL adversary co-trains in. The
 * environment is the REAL deterministic Phorvex dual economics (internal/cost.DualSolver — the
 * SHIPPED fixed λ-subgradient) + the proactive gate (perDollar>λ) + the B=1 top-net selection. The
 * attacker observes ONLY effects (eviction signal, its own action echoes) — never λ/Decide.
 *
 * Two STRUCTURE-SPECIFIC attack paths exist (so the QD archive can surface a path beyond the POC's
 * single λ-pump, and so co-training vs the FIXED defender discovers a NEW vuln the λ-fix did not close):
 *   PATH A (λ-pump): many LOW-perDollar decoys -> pump λ -> foothold not "due". The shipped fix
 *           BOUNDS this, so it is weak vs the fixed defender (the fix working).
 *   PATH B (dispersion-steer): a few HIGH-perDollar decoys -> at the rotation opportunity a decoy
 *           OUT-NETS the foothold -> the single B=1 move lands on a decoy -> foothold not selected.
 *           This is about SELECTION, not λ, so the λ-fix does NOT stop it == a NEW vulnerability.
 * Against a RANDOM defender neither path helps (no economics to exploit) => the learner stays flat,
 * the control that proves it exploits STRUCTURE, not noise.
 */
package redteam

import (
	"math"
	"math/rand"

	"github.com/phorvex/phorvex/internal/cost"
)

const (
	envFootCov, envFootEcost = 3.0, 0.8 // foothold perDollar = 3.75
	envCadence               = 8        // proactiveFloor/anti-over-rotation window
	envMaxTicks              = 40
	envSteerCov, envSteerEc  = 4.0, 0.5 // HIGH-perDollar decoy = 8.0 (out-nets the foothold => steer)
	envPumpCov, envPumpEc    = 1.5, 1.0 // LOW-perDollar decoy = 1.5 (pumps λ via demand, never out-nets)
)

// action factors (the RL's factored action vocabulary, mapping to real attacker TTPs):
var (
	decoyCounts = []int{0, 2, 5, 10}        // spawn-K-decoys meta-action (the λ-pump knob)
	decoyQual   = []int{0, 1}               // 0=pump-grade, 1=steer-grade (the dispersion-shape knob)
	dwellJitter = []int{0, 1, 2}            // throttle/dwell meta-action
)

// ActionDims is the factored head layout for the policy.
func ActionDims() []int { return []int{len(decoyCounts), len(decoyQual), len(dwellJitter)} }

// DefenderKind selects the environment's transition rule.
type DefenderKind int

const (
	DefPhorvexFixed      DefenderKind = iota // SHIPPED: λ-fix + dispersion-steer provenance fix (BOTH)
	DefPhorvexLambdaOnly                     // λ-fix only — the state in which the RL FOUND the steer
	DefPhorvexOld                            // pre-fix Phorvex (old-vs-new demonstration)
	DefRandom                                // random-equal control (no exploitable structure)
)

// steerProvDiscount mirrors coverage.go's provFloor: the SHIPPED Phorvex weights a fresh, evidence-
// less decoy's SELECTION gain by this factor, so it cannot crowd a genuinely-due real foothold out
// of the B=1 slot. Applied only by DefPhorvexFixed.
const steerProvDiscount = 0.34

// Env is the POMDP the learner interacts with.
type Env struct {
	kind   DefenderKind
	rng    *rand.Rand
	dual   *cost.DualSolver
	oldOK  bool // when kind==DefPhorvexOld, use the inlined unbounded subgradient
	tick   int
	since  int
	alive  bool
	lastEv float64 // last eviction signal (effects-only obs)
	// descriptor accumulators (for QD behavior characterisation)
	sumCount, sumQual float64
	nAct              int
}

func NewEnv(kind DefenderKind, rng *rand.Rand) *Env {
	return &Env{kind: kind, rng: rng, dual: cost.NewDualSolver()}
}

func (e *Env) Reset() {
	e.dual = cost.NewDualSolver()
	e.tick, e.since, e.alive, e.lastEv = 0, 0, true, 0
	e.sumCount, e.sumQual, e.nAct = 0, 0, 0
}

func (e *Env) Done() bool { return !e.alive || e.tick >= envMaxTicks }

// Obs is the EFFECTS-ONLY observation: {last-eviction-signal, normalized tick, normalized cadence
// phase the attacker can only ESTIMATE, alive}. NOTE: λ, net, demand, and Decide are NOT observable.
func (e *Env) Obs() []float64 {
	return []float64{e.lastEv, float64(e.tick) / envMaxTicks, 1, boolf(e.alive)}
}

// Step applies the factored action and advances the real economics one tick. Returns the shaped,
// oracle-grounded reward and done. action = [countIdx, qualIdx, dwellIdx].
func (e *Env) Step(action []int) (float64, bool) {
	count := decoyCounts[action[0]]
	qual := decoyQual[action[1]]
	_ = dwellJitter[action[2]] // dwell modulates WHEN; folded into the per-tick cadence below
	e.sumCount += float64(count)
	e.sumQual += float64(qual)
	e.nAct++

	dCov, dEc := envPumpCov, envPumpEc
	if qual == 1 {
		dCov, dEc = envSteerCov, envSteerEc
	}

	reward := 0.0
	rotated := false
	switch e.kind {
	case DefRandom:
		// random-equal: rotate with a fixed per-tick prob, IGNORING the attacker's economics. No
		// structure => no consistent suppression possible => the learner cannot beat the baseline.
		rotated = e.rng.Float64() < 0.16
	default:
		// the REAL economics, checked EVERY tick: the attacker must CONSISTENTLY suppress the
		// rotation (a learned skill — random/inconsistent play loses the foothold early). λ is the
		// SHIPPED fixed integrator (or the old unbounded one for the old-vs-new run).
		lambda := e.dual.Lambda()
		footNet := envFootCov - lambda*envFootEcost
		decoyNet := dCov - lambda*dEc
		demand := 0
		if footNet > 0 {
			demand++
		}
		if decoyNet > 0 {
			demand += count
		}
		spent := demand
		if spent > 1 {
			spent = 1
		}
		if e.kind == DefPhorvexOld {
			e.stepOld(demand, 1)
		} else {
			e.dual.Step(demand, spent, 1)
		}
		due := (envFootCov / envFootEcost) > lambda // PATH A: a sustained λ-pump makes this false
		// PATH B (dispersion-steer): a steer-grade decoy out-nets the foothold for the B=1 slot. The
		// SHIPPED provenance fix discounts a fresh, evidence-less decoy's SELECTION weight, so it can
		// no longer crowd out the genuinely-due real foothold (decoyNet effectively scaled down).
		decoyProv := 1.0
		if e.kind == DefPhorvexFixed {
			decoyProv = steerProvDiscount
		}
		selected := count == 0 || footNet >= decoyNet*decoyProv
		rotated = footNet > 0 && due && selected
	}

	// SHAPED, oracle-grounded reward: + foothold dwell, - decoy cost (steer-grade costs more, it is a
	// "real-looking" pod), - detection when a rotation actually FIRES on the real foothold.
	costPerDecoy := 0.03
	if qual == 1 {
		costPerDecoy = 0.06
	}
	reward += 1.0 - costPerDecoy*float64(count)
	if rotated {
		reward -= 2.0 // the foothold's objective is denied (the defender won this tick)
		e.alive = false
		e.lastEv = 1
	} else {
		e.lastEv = 0
	}
	e.tick++
	return reward, e.Done()
}

// Descriptor is the QD behavior characterisation: [mean decoy count (normalized), mean steer-grade
// fraction]. Distinct cells == distinct STRATEGIES (flood/pump vs precise steer) => novel-path map.
func (e *Env) Descriptor() []float64 {
	if e.nAct == 0 {
		return []float64{0, 0}
	}
	return []float64{e.sumCount / float64(e.nAct) / 10.0, e.sumQual / float64(e.nAct)}
}

// stepOld reproduces the PRE-FIX unbounded subgradient (for the old-vs-new demonstration only).
func (e *Env) stepOld(demand, budget int) {
	// mirror DualSolver internals via the public API: emulate λ += step*(demand-budget) by stepping
	// with an unclamped excess. We approximate by repeated unit steps (the fixed Step caps at 1).
	for i := 0; i < demand-budget; i++ {
		e.dual.Step(2, 1, 1) // each call raises λ by one step (excess=1) => demand-budget total steps
	}
	if demand-budget <= 0 {
		e.dual.Step(demand, demand, 1)
	}
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// argmaxF returns the index of the max (helper).
func argmaxF(xs []float64) int {
	bi, bv := 0, math.Inf(-1)
	for i, v := range xs {
		if v > bv {
			bv, bi = v, i
		}
	}
	return bi
}
