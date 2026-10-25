/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package killchain

import (
	"math"
	"time"

	"github.com/phorvex/phorvex/internal/metrics"
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
	// the generic 5-stage path is byte-identical. Magnitude calibration is tracked by
	// PHORVEXSEC-115. ---
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
const BaselineStageUrgency = StageUrgencyCurrentWeight * minConsequence

const (
	AIEndpointGPUUtilThreshold = 0.8
	EventSeverityMaximumRank   = 4.0
	EventHeldEvidenceBase      = 1.0
	EventHeldEvidenceSpan      = 2.0
	LateralPressureBase        = 0.5
	LateralPressureSpan        = 0.5
	StageUrgencyCurrentWeight  = 0.5
	StageUrgencyNextWeight     = 0.5
	ProjectedTransitionTarget  = 0.5
)

// NOTE (PHVX-72): a scalar StageUrgency threshold was evaluated for the anti-decoy gate and
// REJECTED. Measurement showed it cannot discriminate evidence: a low- or medium-severity event on
// the pod leaves the stage at Recon, so its urgency is identical to an asset with no evidence at
// all (0.0504 at 90s), and a compromised neighbour only reaches 0.0511. Any threshold able to
// discount a fresh decoy would therefore also discount a genuinely-attacked pod. The gate uses
// Assessment.HasEvidence instead. See PhorvexSecurity/operator@65af1c99:
// reports/phvx-fixes-20260809/PHORVEXSEC-128-*.

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
	Stage Stage
	// Leakage is the ACTIVITY signal the model-theft gate actually tested (T1-A): SMOccupancy
	// only. Recorded so the decision trace can show the gate input beside its raw sources;
	// 0 with Physics.SMSource=="" means unmeasured, not idle.
	Leakage       float64
	StageName     string
	NextStage     Stage
	NextStageName string
	Hazard        float64 // h_s(age) in [0,1]: prob of imminent transition to NextStage
	// InStageSec is time-in-current-stage (T1-B): the dwell the Weibull hazard/preempt/projNext
	// read, distinct from the pod identity clock. Recorded so the trace can show which clock fed them.
	InStageSec float64
	PHold      float64 // P(attacker still holds the foothold) in [0,1]
	// PHoldInputs are the audited terms behind PHold (M-143): betaMean, capped pressure,
	// cap, scale, raw and final. Lets a reader verify the posterior survived the clock.
	PHoldInputs model.PHoldInputs
	// EventStageName is the evidence-following event-derived stage (M-27 ruling Q2); ""
	// when no event with a positive aging weight targets this pod. The final Stage is this
	// merged with the AI classifier (the T1-M025 merge point).
	EventStageName string
	// AIStageName is the AI/inference-derived stage before the merge ("" when the AI arm was
	// silent); StageMergeRule names how Stage was produced from EventStageName + AIStageName
	// ("max-consequence"). Both are recorded so a diff can attribute the merged stage (M-25).
	AIStageName    string
	StageMergeRule string
	// EventEvidence is Σ_e w(age_e)·severity_e over targeting events (M-27 ruling Q1).
	EventEvidence float64
	// Events lists every event the assessment saw with its age and aging weight.
	Events       []model.EventEvidence
	StageUrgency float64 // [0,1] current-consequence blended with predictive (hazard*next)
	// HasEvidence is TRUE when this assessment rests on a REAL observation rather than on the
	// passage of time: a SecurityEvent on this pod, a compromised graph neighbour, an AI kill-chain
	// signature, or a poisoned adapter. It is broad inference/context; selection provenance uses
	// HasEventEvidence, whose trusted observation contract excludes topology-only context. StageUrgency
	// CANNOT substitute for observation presence, because a low/medium direct event and a compromised neighbour both
	// leave the stage at Recon, giving them the SAME urgency as an asset with no evidence at all.
	HasEvidence bool
	// HasEventEvidence is the STRICTER, event-only discriminator (M-28): TRUE only when a
	// TRUSTED, RECENT (age-weighted) SecurityEvent bears on this pod — a targeting event
	// (eventAlpha>0) or a compromised neighbour (lateralPressure>0). Unlike HasEvidence it
	// EXCLUDES contextual AI classification (aiClassified) and the SuspectAdapter detector flag.
	// The proactive-cadence cap keys on THIS so an event-less pod is still capped. Selection
	// provenance also uses this strict observation signal; broad
	// HasEvidence remains available for contextual assessment. Also age-weighted, so an EXPIRED
	// event does not keep it true.
	HasEventEvidence bool
	LateralUrgency   float64 // [0,1] specifically the about-to-pivot-here pressure

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
	// StageClock tracks time-in-current-stage per pod (T1-B): the Weibull dwell reads it,
	// not the pod identity/lifecycle clock. nil => dwell falls back to the identity clock.
	StageClock *StageClock
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
			// AI sojourns are provisional; PHORVEXSEC-115 owns real-fleet calibration.
			StageGPUSideChannel:      300,
			StageModelTheft:          180,
			StageLLMJacking:          900,
			StagePromptInjectPersist: 3600,
		},
		Shape:        2.0, // Weibull k=2 => linearly-increasing hazard rate
		RecoverScale: 30,  // P(hold) recovers ~30s after a wipe (generic)
		Memory:       NewConjugateMemory(),
		StageClock:   NewStageClock(),
	}
}

// DefaultExposurePressureCap is the runtime backstop for an unset/invalid policy cap
// (M-143 form A). INSUFFICIENT EVIDENCE — provisional 0.5, fit in T3-D.
const DefaultExposurePressureCap = 0.5

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
	case model.AttackVectorKV, model.AttackVectorGuardrail, model.AttackVectorInflight, model.AttackVectorAdapter,
		model.AttackVectorPodBoundAPIAuth, model.AttackVectorSensitiveOutput, model.AttackVectorVoiceMemory, model.AttackVectorVoiceRefund, model.AttackVectorVoiceOutput,
		model.AttackVectorEndpointLeaseReuse, model.AttackVectorServingCostHarvest:
		// A named attack vector is an actionable observed capability — same persist-stage
		// weight as Panic. The vector also steers the relevant fact in recon (ucw);
		// it does not by itself establish an on-Pod exploit or select an actuator.
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

// maxByConsequence returns the higher-consequence of two stages, ties keeping a (the
// event-incorporating current stage). Rank is the EXISTING consequence() ordinal — no new table
// is invented (both the event and AI chains are the same Stage enum). This makes the
// detector-derived stage a floor physics can raise but never lower (M-25 / P-BELIEF / P-ORDER).
func maxByConsequence(a, b Stage) Stage {
	if consequence(b) > consequence(a) {
		return b
	}
	return a
}

// aiStageFromView classifies the AI/inference kill-chain stage from the pod's AI
// signals + the event stream — sensed off EXISTING fields, NEVER a new SecurityEvent
// type. Returns (stage, true) on a match. HONEST-ABSENT: returns false when the pod is
// not an AI workload (ModelID=="" && !HasGPU), so the generic chain is byte-identical.
// GPU model-theft and side-channel stages are deliberately unavailable: the current snapshot
// has no validated target/device-bound evidence contract for either threat. In particular, the
// historical CoResidency field is only a running-namespace count and cannot activate them.
// ModelID/EndpointPath stages fire on a model-annotated pod + the event stream (live).
// leakageOf is the model-theft gate's activity term (T1-A). Allocation (VRAMFraction) is
// deliberately NOT a summand: residency is eligibility/context, never activity. Weights on
// LinkBandwidth/PCIe are 0 — INSUFFICIENT EVIDENCE to set them (Tier 3). Range [0,1].
func leakageOf(ph model.PhysicsWitness) float64 {
	return ph.SMOccupancy
}

func aiStageFromView(view *model.WorkloadView, eventHorizon time.Duration) (Stage, bool) {
	p := view.Pod
	if p.ModelID == "" && !p.HasGPU {
		return 0, false
	}
	// strongest event class targeting this pod
	persistEvent, exploitEvent := false, false
	for _, e := range view.Events {
		if !e.TargetsPod {
			continue
		}
		if e.Type == model.AttackVectorPodBoundAPIAuth &&
			!model.PodBoundAPIAuthEventEligible(e, p, eventHorizon) {
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
	// (1) prompt-injection persistence: a served model + a persist-class event (the
	// injected agent state survives a wipe). KVRebuildSec only gates the recover scale.
	if p.ModelID != "" && persistEvent {
		return StagePromptInjectPersist, true
	}
	// (2) LLM-jacking: an exposed endpoint + a compute-abuse / exploit signal.
	if p.EndpointPath != "" && (exploitEvent || (view.Telemetry.GPUUtil.Usable() && view.Telemetry.GPUUtil.Value > AIEndpointGPUUtilThreshold)) {
		return StageLLMJacking, true
	}
	return 0, false
}

// Assess computes the kill-chain assessment for an asset. exposureSec is the
// pod-identity exposure clock; proactiveFloorSec is the policy's proactive floor.
//
// This is the production entrypoint and keeps its signature: it is the real evaluation of
// the tick, so it folds the stage clock, seeds the owner's prior and counts aged-out events.
func (m *Model) Assess(view *model.WorkloadView, pol model.Policy, exposureSec, proactiveFloorSec float64) Assessment {
	return m.AssessMode(view, pol, exposureSec, proactiveFloorSec, EvalProduction)
}

// AssessMode computes the same assessment under an explicit evaluation mode (M-163). Every
// input — the events, the AI/topology classification, the learned prior, the dwell the stage
// clock already holds — is read identically in both modes, so the shadow arm's belief is the
// belief production would form from that hypothetical stage. Under EvalShadow no stage entry
// is folded, no owner prior is seeded and no operational counter moves.
func (m *Model) AssessMode(view *model.WorkloadView, pol model.Policy, exposureSec, proactiveFloorSec float64, mode EvalMode) Assessment {
	// --- stage belief from events (this pod) + neighbor pressure ---
	//
	// PHORVEXSEC-186 / M-27: every event is weighted by its age, w = 1 − clamp01(age/τ_ev)
	// (ruling Q1, the same function ctxprov uses), and the event-derived stage follows the
	// evidence (ruling Q2): only events with w > 0 can set it, so a stale alert cannot hold
	// a stage. τ_ev is the policy proactive floor — T1-B's initialization; its value is
	// INSUFFICIENT EVIDENCE (M-29). Aging applies to every ingested event (T1-M094 is not
	// merged). A CR without a timestamp is present=false and weighs 0.
	stage := StageRecon
	eventStage := Stage(0)
	eventStageSet := false
	eventAlpha := 0.0 // held-evidence pseudo-counts for the Beta posterior
	evidence := 0.0   // Σ_e w(age_e)·severity_e over events targeting this pod
	lateralPressure := 0.0
	var eventRecords []model.EventEvidence
	if len(view.Events) > 0 {
		eventRecords = make([]model.EventEvidence, 0, len(view.Events))
	}
	for _, e := range view.Events {
		sev := float64(maxInt(v1beta1.ThreatLevelRank(e.ThreatLevel), 0)) / EventSeverityMaximumRank
		w := 0.0
		if !e.TimestampMissing {
			w = model.EventAgeWeight(e.Age, eventAgeHorizon(pol))
		}
		if e.Type == model.AttackVectorPodBoundAPIAuth &&
			!model.PodBoundAPIAuthEventEligible(e, view.Pod, eventAgeHorizon(pol)) {
			w = 0
		}
		targetPodUID := ""
		if e.TargetsPod {
			targetPodUID = view.Pod.UID
		}
		eventRecords = append(eventRecords, model.EventEvidence{
			Name: e.Name, EventUID: e.UID, Source: e.Source, Type: e.Type, ThreatLevel: e.ThreatLevel,
			TrustVerdict: e.Trust, CreatorIdentity: e.CreatorIdentity, TargetPodUID: targetPodUID,
			TargetsPod: e.TargetsPod, AgeSec: e.Age.Seconds(), Weight: w, TimestampPresent: !e.TimestampMissing,
		})
		if w <= 0 {
			// M-163: an aged-out event is an operational observation of the REAL tick. A
			// counterfactual re-reading of the same event stream must not count it again.
			if mode.Commits() && (e.Type != model.AttackVectorPodBoundAPIAuth ||
				e.Age >= eventAgeHorizon(pol)) {
				metrics.RecordEventAgedOut(pol.Tenant)
			}
			continue
		}
		if e.TargetsPod {
			if s := stageFromEvent(e); !eventStageSet || s > eventStage {
				eventStage, eventStageSet = s, true
			}
			eventAlpha += w * (EventHeldEvidenceBase + EventHeldEvidenceSpan*sev) // stronger AND fresher events => stronger held-evidence
			evidence += w * sev
		} else {
			// A compromised NEIGHBOR means the attacker is about to pivot HERE.
			lateralPressure = math.Max(lateralPressure, w*(LateralPressureBase+LateralPressureSpan*sev))
		}
	}
	if eventStageSet && eventStage > stage {
		stage = eventStage
	}

	// --- AI/inference stage classification (P-CONTEXT). Takes precedence over the
	// generic stage when an AI signature matches; honest-absent for non-AI workloads. ---
	aiClassified := false
	aiStageName := ""
	if ai, ok := aiStageFromView(view, eventAgeHorizon(pol)); ok {
		// M-25: the AI/topology chain may RAISE the stage, never lower it. A detector-derived
		// (event) stage is a floor (P-BELIEF); the merge is max-consequence over the shared Stage
		// ordinal, symmetric with the eventStage merge just above (:347). This is the merge ONLY —
		// arm (1) still fires on physics (the M-26 evidence gate is a separate ticket).
		stage = maxByConsequence(stage, ai)
		aiClassified = true
		aiStageName = ai.String()
	}

	// T1-B: the Weibull dwell family reads time-IN-STAGE, not the pod identity clock. On a
	// non-transitioning pod dwellSec == exposureSec (byte-identical); it restarts on a stage change.
	//
	// M-163: the stage clock is the ONLY origin of stage-entry time, so only the real
	// evaluation may fold into it. A shadow arm whose physics witness lands on the other side
	// of a stage predicate (a stale calibration snapshot against a fresher platform witness)
	// used to record its hypothetical transition here and hand the following production pass a
	// dwell of 0 — losing the pod's accrued dwell and, with it, hazard, urgency, preempt margin
	// and coverage. Peek returns the same hypothetical dwell without taking the entry.
	var dwellSec float64
	if mode.Commits() {
		dwellSec = m.StageClock.Observe(pol.Owner(), view.Pod.Namespace, view.Pod.Name, view.Pod.UID, stage, exposureSec)
	} else {
		dwellSec = m.StageClock.Peek(pol.Owner(), view.Pod.Namespace, view.Pod.Name, view.Pod.UID, stage, exposureSec)
	}

	// --- predictive belief horizon: hazard of imminent next-stage transition ---
	scale := m.SojournScale[stage]
	if configured := pol.KillChainSojournScaleSeconds[stage.String()]; configured > 0 {
		scale = configured
	}
	if scale <= 0 {
		scale = 1800
	}
	shape := pol.KillChainShape
	if shape <= 0 || math.IsNaN(shape) || math.IsInf(shape, 0) {
		shape = m.Shape
	}
	hazard := weibullCDF(dwellSec, scale, shape) // T1-B: dwell = time in stage

	next := successorOf(stage)
	// Neighbor pressure forward-projects a LATERAL transition (generic chain only; the
	// AI successor map already encodes the AI escalation path).
	if !aiClassified && lateralPressure > 0 && StageLateral > next {
		next = StageLateral
	}

	// StageUrgency = blend(current consequence, hazard * next consequence): we invalidate
	// the recon the attacker is ABOUT TO exploit, not only what they hold now.
	stageUrg := clamp01(StageUrgencyCurrentWeight*consequence(stage) + StageUrgencyNextWeight*hazard*consequence(next))
	// Evidence is the PRESENCE of a real observation, independent of how severe it is or how much
	// urgency it happens to produce. eventAlpha>0 covers every event targeting this pod (any
	// severity); lateralPressure>0 covers a compromised neighbour; aiClassified covers an AI
	// signature; SuspectAdapter covers a poisoned adapter.
	hasEvidence := eventAlpha > 0 || lateralPressure > 0 || aiClassified || view.Pod.SuspectAdapter != ""
	// M-28: the event-only, age-weighted subset — a trusted RECENT event on this pod or a
	// compromised neighbour. Excludes aiClassified/SuspectAdapter (true for an event-less busy
	// GPU/model server), so the cadence cap still fires on the physics-pinned churn pod.
	hasEventEvidence := eventAlpha > 0 || lateralPressure > 0
	// Lateral urgency rises with neighbor pressure and an imminent lateral transition.
	latUrg := clamp01(math.Max(lateralPressure, hazard*boolf(next == StageLateral)))

	// --- P(hold): Beta posterior (tenant prior + per-asset event evidence), with an
	// exposure-pressure PRIOR FLOOR (not an annihilator) and a just-moved damping. ---
	//
	// PHORVEXSEC-189 / M-143 (form A, capped noisy-OR). The old term
	// clamp01(exposure/floor) reached 1 for every pod older than the floor, and then
	// pHoldRaw = betaMean + 1*(1-betaMean) = 1 for EVERY betaMean: the posterior, the tenant
	// prior and any qualified observed-outcome learning had zero effect (84.6% of live records pinned >= 0.999).
	// Now p(t) = cap*min(1, t/T_exp) with 0 < cap < 1, so d pHold/d betaMean = 1-p >= 1-cap > 0
	// at every age, pHold(t=0) = betaMean exactly as before, and pHold reaches 1 only when
	// betaMean does. cap is INSUFFICIENT EVIDENCE — provisional 0.5, fit in T3-D. T_exp is the
	// policy proactive floor today; T1-B substitutes its dedicated constant without changing
	// this formula.
	// M-163: the SAME learned conjugate prior feeds both modes — a shadow must never be
	// priced against a fresh belief model — but a shadow read does not seed an owner the
	// memory has not learned about yet.
	betaMean := m.Memory.PHoldUCBWithEvidenceMode(pol.Owner(), eventAlpha, m.ConfidenceK, mode)
	cap := pol.ExposurePressureCap
	if cap <= 0 || cap >= 1 {
		cap = DefaultExposurePressureCap
	}
	// T1-B: T_exp is its own horizon (initialised = ProactiveFloor). exposureSec here is the
	// move clock (SinceIdentityChangeSec) — unchanged. Only the SCALE gets its dedicated field.
	tExpSec := proactiveFloorSec
	if s := pol.ExposurePressureScale.Seconds(); s > 0 {
		tExpSec = s
	}
	exposurePressure := 0.0
	if tExpSec > 0 {
		exposurePressure = cap * math.Min(1, math.Max(0, exposureSec)/tExpSec)
	}
	pHoldRaw := betaMean + exposurePressure*(1-betaMean) // capped noisy-OR: range [betaMean, betaMean+cap*(1-betaMean)]

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
		damping = 1 - math.Exp(-math.Pow(exposureSec/math.Max(m.RecoverScale, 1), shape))
	default:
		damping = 1 - math.Exp(-exposureSec/math.Max(m.RecoverScale, 1)) // P1 baseline, unchanged
	}
	pHold := clamp01(pHoldRaw * damping)

	// --- predictive horizon: the MOVED-BEFORE-NEXT-STAGE measurable (closed-form) ---
	preempt := 1 - weibullCDF(dwellSec, scale, shape) // T1-B: same dwell clock as hazard
	projNext := projectedNextStageSec(scale, shape, dwellSec)

	eventStageName := ""
	if eventStageSet {
		eventStageName = eventStage.String()
	}
	return Assessment{
		Stage:          stage,
		StageName:      stage.String(),
		EventStageName: eventStageName,
		AIStageName:    aiStageName,
		StageMergeRule: "max-consequence",
		EventEvidence:  evidence,
		Events:         eventRecords,
		NextStage:      next,
		NextStageName:  next.String(),
		Hazard:         hazard,
		InStageSec:     dwellSec,
		PHold:          pHold,
		PHoldInputs: model.PHoldInputs{
			BetaMean: betaMean, Pressure: exposurePressure, Cap: cap, ScaleSec: tExpSec, // T1-B: the scale actually consumed (T_exp), not the cadence floor
			Raw: pHoldRaw, Final: pHold,
		},
		StageUrgency:          stageUrg,
		HasEvidence:           hasEvidence,
		HasEventEvidence:      hasEventEvidence,
		Leakage:               leakageOf(view.Physics),
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
	median := scale * math.Pow(-math.Log(1-ProjectedTransitionTarget), 1/shape)
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

// eventAgeHorizon shares the one effective rule with every event consumer.
func eventAgeHorizon(pol model.Policy) time.Duration {
	return pol.EffectiveEventAgeHorizon()
}
