/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package killchain

import (
	"math"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
)

// Stage is a kill-chain stage (ordinal; consequence increases with the ordinal).
type Stage int

const (
	StageRecon   Stage = iota // 0 attacker is mapping
	StageExploit              // 1 gained execution
	StagePersist              // 2 established a foothold
	StageLateral              // 3 moving to neighbors
	StageImpact               // 4 exfiltration / damage

	// --- AI/inference kill-chain (P-CONTEXT). A PARALLEL chain classified by AI
	// signature in Assess; honest-absent (never fires) when ModelID=="" && !HasGPU, so
	// the generic 5-stage path is byte-identical. Magnitudes are [SP-0-PENDING]. ---
	StageGPUSideChannel      // 5 B2 recon-class leakage primitive (co-resident GPU)
	StageModelTheft          // 6 B2 near-impact: weights reconstructed via side-channel
	StageLLMJacking          // 7 B1 persist-class: compute/endpoint hijack
	StagePromptInjectPersist // 8 B3 persist-class: injected agent state survives a wipe
)

var stageNames = []string{"recon", "exploit", "persist", "lateral", "impact",
	"gpu-side-channel", "model-theft", "llm-jacking", "prompt-inject-persist"}

// aiNextStage is the parallel-chain successor MAP (the AI stages have no linear +1
// successor — the structural defect the baseline next=stage+1 cannot absorb). Generic
// stages fall through to next=stage+1.
var aiNextStage = map[Stage]Stage{
	StageGPUSideChannel:      StageModelTheft,
	StageModelTheft:          StageImpact,
	StageLLMJacking:          StageImpact,
	StagePromptInjectPersist: StageLateral,
}

// successorOf returns the next stage: the AI successor map for AI stages, else stage+1
// (capped at Impact for generic stages).
func successorOf(s Stage) Stage {
	if n, ok := aiNextStage[s]; ok {
		return n
	}
	next := s + 1
	if next > StageImpact {
		next = StageImpact
	}
	return next
}

// String returns the stage name.
func (s Stage) String() string {
	if int(s) >= 0 && int(s) < len(stageNames) {
		return stageNames[s]
	}
	return "unknown"
}

// consequence is the normalized cost-if-this-stage-completes (0..1, increasing).
// minConsequence is the floor every stage's consequence shares — consequence() never returns less,
// including its default arm. It is exported through BaselineStageUrgency below because callers need
// to know what "no evidence at all" actually scores.
const minConsequence = 0.1

// BaselineStageUrgency is the StageUrgency of an asset carrying NO kill-chain evidence: earliest
// stage, zero hazard. Since StageUrgency = 0.5*consequence(stage) + 0.5*hazard*consequence(next)
// and consequence() floors at minConsequence, StageUrgency can never be 0 — its minimum is this.
//
// This matters because a caller testing `StageUrgency > 0` to mean "has evidence" is testing a
// condition that is ALWAYS true, i.e. testing nothing. Compare against this baseline instead.
// Derived from the model rather than hardcoded so it cannot drift if consequence() changes.
const BaselineStageUrgency = 0.5 * minConsequence

func consequence(s Stage) float64 {
	switch s {
	case StageRecon:
		return 0.1
	case StageExploit:
		return 0.35
	case StagePersist:
		return 0.6
	case StageLateral:
		return 0.85
	case StageImpact:
		return 1.0
	case StageGPUSideChannel:
		return 0.15 // leakage primitive; low until it reconstructs the model
	case StageModelTheft:
		return 0.9 // stolen proprietary weights = highest AI cost
	case StageLLMJacking:
		return 0.6 // your GPU/endpoint serving the attacker
	case StagePromptInjectPersist:
		return 0.65 // injected agent state, survives a wipe
	}
	return minConsequence
}

// Assessment is the per-asset kill-chain belief output.
type Assessment struct {
	Stage          Stage
	StageName      string
	NextStage      Stage
	NextStageName  string
	Hazard         float64 // h_s(age) in [0,1]: prob of imminent transition to NextStage
	PHold          float64 // P(attacker still holds the foothold) in [0,1]
	StageUrgency   float64 // [0,1] current-consequence blended with predictive (hazard*next)
	LateralUrgency float64 // [0,1] specifically the about-to-pivot-here pressure

	// --- P-CONTEXT predictive-horizon: the MOVED-BEFORE-NEXT-STAGE measurable. ---
	// PreemptMargin = P(stage has NOT transitioned to its successor by the time our move
	// lands) = survival prob = 1 - weibullCDF(exposure + moveLatency). High = we are
	// comfortably ahead of the attacker; low = we are about to be too late.
	PreemptMargin float64
	// ProjectedNextStageSec = seconds until the median next-stage transition (inverse
	// Weibull), minus accrued dwell. <=0 means the transition is already overdue.
	ProjectedNextStageSec float64
	// AIClassified is true when an AI-stage signature matched (vs the generic chain).
	AIClassified bool
}

// Model is the deterministic semi-Markov hazard model + memory. All knobs are FLAGGED
// design proposals (never paper values).
type Model struct {
	// SojournScale is the characteristic dwell (seconds) before a stage transitions;
	// the hazard is a Weibull CDF with this scale and the Shape below.
	SojournScale map[Stage]float64
	// Shape > 1 makes the hazard INCREASING (the longer the dwell, the more imminent
	// the next-stage transition) — an increasing-failure-rate (IFR) model.
	Shape float64
	// RecoverScale (seconds): right after a move (exposure~0) P(hold) is damped toward
	// 0 (the foothold was just wiped); it recovers over this scale as exposure accrues.
	RecoverScale float64
	// ConfidenceK is the UCB confidence-bonus weight on P(hold) (act sooner under thin
	// evidence). 0 = off => the plain posterior mean (byte-identical to P1). Flagged knob.
	ConfidenceK float64
	// Memory is the per-tenant conjugate prior (context-memory layer).
	Memory *ConjugateMemory
}

// NewModel returns a Model with default sojourn scales (seconds) and shape.
func NewModel() *Model {
	return &Model{
		SojournScale: map[Stage]float64{
			StageRecon:   1800, // ~30m of recon before exploit attempt
			StageExploit: 600,
			StagePersist: 3600,
			StageLateral: 1200,
			StageImpact:  600,
			// AI sojourns [SP-0-PENDING] — flagged proposals, calibrate on a real GPU fleet.
			StageGPUSideChannel:      300,
			StageModelTheft:          180,
			StageLLMJacking:          900,
			StagePromptInjectPersist: 3600,
		},
		Shape:        2.0, // Weibull k=2 => linearly-increasing hazard rate
		RecoverScale: 30,  // P(hold) recovers ~30s after a wipe (generic)
		Memory:       NewConjugateMemory(),
	}
}

// weibullCDF = 1 - exp(-(t/scale)^k): the prob the stage has transitioned by dwell t.
func weibullCDF(t, scale, k float64) float64 {
	if t <= 0 || scale <= 0 {
		return 0
	}
	x := math.Pow(t/scale, k)
	return 1 - math.Exp(-x)
}

// stageFromEvent maps a (canonical) SecurityEvent to the kill-chain stage it implies.
func stageFromEvent(e model.SecurityEventInfo) Stage {
	switch e.Type {
	case v1beta1.TypePanic: // container escape / breakout
		return StagePersist
	case v1beta1.TypeDrift: // image/baseline drift => implant established
		return StagePersist
	case v1beta1.TypePolicyViolation:
		return StageExploit
	case v1beta1.TypeDisable:
		return StageExploit
	}
	// Fall back on severity: a critical/high event implies at least exploit.
	if r := v1beta1.ThreatLevelRank(e.ThreatLevel); r >= 3 {
		return StageExploit
	}
	return StageRecon
}

// aiStageFromView classifies the AI/inference kill-chain stage from the pod's AI
// signals + the event stream — sensed off EXISTING fields, NEVER a new SecurityEvent
// type. Returns (stage, true) on a match. HONEST-ABSENT: returns false when the pod is
// not an AI workload (ModelID=="" && !HasGPU), so the generic chain is byte-identical.
// Precedence is by consequence/specificity (theft > side-channel > persist > jacking).
// GPU-leakage stages need HasGPU (so they stay [SP-0-PENDING] on a CPU-only cluster);
// ModelID/EndpointPath stages fire on a model-annotated pod + the event stream (live).
func aiStageFromView(view *model.WorkloadView) (Stage, bool) {
	p := view.Pod
	ph := view.Physics
	if p.ModelID == "" && !p.HasGPU {
		return 0, false
	}
	// strongest event class targeting this pod
	persistEvent, exploitEvent := false, false
	for _, e := range view.Events {
		if !e.TargetsPod {
			continue
		}
		switch stageFromEvent(e) {
		case StagePersist:
			persistEvent = true
		case StageExploit:
			exploitEvent = true
		}
		if v1beta1.ThreatLevelRank(e.ThreatLevel) >= 3 {
			exploitEvent = true
		}
	}
	leakage := ph.SMOccupancy + ph.VRAMFraction // [0,2]; 0 on kind ([SP-0-PENDING])

	// (1) model theft in progress: co-resident GPU reconstructing a rare model.
	if p.HasGPU && ph.CoResidency > 1 && ph.ModelRarity > 1.3 && leakage > 0.8 {
		return StageModelTheft, true
	}
	// (2) GPU side-channel recon primitive: co-resident on a shared GPU, no theft yet.
	if p.HasGPU && ph.CoResidency > 1 && ph.ModelRarity > 1 {
		return StageGPUSideChannel, true
	}
	// (3) prompt-injection persistence: a served model + a persist-class event (the
	// injected agent state survives a wipe). KVRebuildSec only gates the recover scale.
	if p.ModelID != "" && persistEvent {
		return StagePromptInjectPersist, true
	}
	// (4) LLM-jacking: an exposed endpoint + a compute-abuse / exploit signal.
	if p.EndpointPath != "" && (exploitEvent || (view.Telemetry.Present && view.Telemetry.GPUUtil > 0.8)) {
		return StageLLMJacking, true
	}
	return 0, false
}

// Assess computes the kill-chain assessment for an asset. exposureSec is the
// pod-identity exposure clock; proactiveFloorSec is the policy's proactive floor.
func (m *Model) Assess(view *model.WorkloadView, pol model.Policy, exposureSec, proactiveFloorSec float64) Assessment {
	// --- stage belief from events (this pod) + neighbor pressure ---
	stage := StageRecon
	eventAlpha := 0.0 // held-evidence pseudo-counts for the Beta posterior
	lateralPressure := 0.0
	for _, e := range view.Events {
		sev := float64(maxInt(v1beta1.ThreatLevelRank(e.ThreatLevel), 0)) / 4.0
		if e.TargetsPod {
			if s := stageFromEvent(e); s > stage {
				stage = s
			}
			eventAlpha += 1.0 + 2.0*sev // stronger events => stronger held-evidence
		} else {
			// A compromised NEIGHBOR means the attacker is about to pivot HERE.
			lateralPressure = math.Max(lateralPressure, 0.5+0.5*sev)
		}
	}

	// --- AI/inference stage classification (P-CONTEXT). Takes precedence over the
	// generic stage when an AI signature matches; honest-absent for non-AI workloads. ---
	aiClassified := false
	if ai, ok := aiStageFromView(view); ok {
		stage = ai
		aiClassified = true
	}

	// --- predictive belief horizon: hazard of imminent next-stage transition ---
	scale := m.SojournScale[stage]
	if scale <= 0 {
		scale = 1800
	}
	hazard := weibullCDF(exposureSec, scale, m.Shape)

	next := successorOf(stage)
	// Neighbor pressure forward-projects a LATERAL transition (generic chain only; the
	// AI successor map already encodes the AI escalation path).
	if !aiClassified && lateralPressure > 0 && StageLateral > next {
		next = StageLateral
	}

	// StageUrgency = blend(current consequence, hazard * next consequence): we invalidate
	// the recon the attacker is ABOUT TO exploit, not only what they hold now.
	stageUrg := clamp01(0.5*consequence(stage) + 0.5*hazard*consequence(next))
	// Lateral urgency rises with neighbor pressure and an imminent lateral transition.
	latUrg := clamp01(math.Max(lateralPressure, hazard*boolf(next == StageLateral)))

	// --- P(hold): Beta posterior (tenant prior + per-asset event evidence), with an
	// exposure-pressure floor and a just-moved damping. ---
	betaMean := m.Memory.PHoldUCBWithEvidence(pol.Tenant, eventAlpha, m.ConfidenceK)
	exposurePressure := 0.0
	if proactiveFloorSec > 0 {
		exposurePressure = clamp01(exposureSec / proactiveFloorSec)
	}
	pHoldRaw := betaMean + exposurePressure*(1-betaMean) // noisy-OR

	// AI-GATED damping. The generic K8s path stays BYTE-IDENTICAL to the P1 baseline
	// (shape=1 exponential just-moved damping); AI workloads use the survival form
	// (shape k) that unifies P(hold) with the same Weibull hazard the horizon uses.
	// SPECIAL CASE — prompt-injection persistence: the injected KV/agent state SURVIVES a
	// rotation, so the just-moved wipe does NOT clear it => no damping (P(hold) does not
	// collapse after a move). This is the one place the generic 30s wipe-damping is wrong.
	var damping float64
	switch {
	case stage == StagePromptInjectPersist:
		damping = 1.0 // persisted implant survives the wipe
	case aiClassified || view.Pod.ModelID != "" || view.Pod.HasGPU:
		damping = 1 - math.Exp(-math.Pow(exposureSec/math.Max(m.RecoverScale, 1), m.Shape))
	default:
		damping = 1 - math.Exp(-exposureSec/math.Max(m.RecoverScale, 1)) // P1 baseline, unchanged
	}
	pHold := clamp01(pHoldRaw * damping)

	// --- predictive horizon: the MOVED-BEFORE-NEXT-STAGE measurable (closed-form) ---
	preempt := 1 - weibullCDF(exposureSec, scale, m.Shape) // survival; moveLatency=0 (flagged)
	projNext := projectedNextStageSec(scale, m.Shape, exposureSec)

	return Assessment{
		Stage:                 stage,
		StageName:             stage.String(),
		NextStage:             next,
		NextStageName:         next.String(),
		Hazard:                hazard,
		PHold:                 pHold,
		StageUrgency:          stageUrg,
		LateralUrgency:        latUrg,
		PreemptMargin:         preempt,
		ProjectedNextStageSec: projNext,
		AIClassified:          aiClassified,
	}
}

// projectedNextStageSec = SojournScale*(-ln(1-pTarget))^(1/shape) - exposure: the
// seconds until the MEDIAN (pTarget=0.5) next-stage transition, minus accrued dwell.
// <=0 means the transition is already overdue (we are late).
func projectedNextStageSec(scale, shape, exposureSec float64) float64 {
	if scale <= 0 || shape <= 0 {
		return 0
	}
	median := scale * math.Pow(-math.Log(0.5), 1/shape)
	return median - exposureSec
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
