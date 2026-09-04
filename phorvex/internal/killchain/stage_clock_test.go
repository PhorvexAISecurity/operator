package killchain

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
)

// T1-B · old-fails / new-passes at a NAMED assertion, against the EXISTING Assess signature.
//
// The Weibull "stage dwell" must be time IN the current stage, not the pod's identity clock.
// A pod that has sat in recon for an hour and then receives a fresh exploit-class event has
// been in the exploit stage for ~0 s: its next-stage hazard must restart near zero, not read
// weibull(3600 s, exploit scale 600 s) ≈ 1.0 as if it had been exploited for an hour.
func TestStageDwellRestartsOnStageTransition(t *testing.T) {
	m := NewModel()
	pol := kcPolicy()
	const floor = 3600.0
	pod := model.Pod{Namespace: "ns", Name: "p", UID: "uid-1"}

	// (1) an hour in recon, no events: the identity clock and the stage dwell coincide.
	quiet := m.Assess(&model.WorkloadView{Pod: pod}, pol, 3600, floor)
	if quiet.Stage != StageRecon {
		t.Fatalf("precondition: quiet pod must be recon, got %s", quiet.StageName)
	}
	if quiet.Hazard < 0.9 {
		t.Fatalf("precondition (both trees): recon hazard after 1 h must be near saturation, got %.3f", quiet.Hazard)
	}

	// (2) the SAME pod, same identity clock (3600 s), now with a fresh exploit-class event:
	// stage transitions recon -> exploit at this tick, so time-in-stage is ~0.
	hot := m.Assess(&model.WorkloadView{
		Pod:    pod,
		Events: []model.SecurityEventInfo{{Type: v1beta1.TypePolicyViolation, ThreatLevel: "high", TargetsPod: true, Age: time.Second}},
	}, pol, 3600, floor)
	if hot.Stage != StageExploit {
		t.Fatalf("precondition (both trees): a fresh policy-violation event must set stage exploit, got %s", hot.StageName)
	}
	// THE NAMED ASSERTION — RED on the pre-fix tree (reads weibull(3600, 600, 2) ≈ 1.0).
	if hot.Hazard >= 0.05 {
		t.Errorf("stage-exit hazard must restart on a stage transition (time-in-stage ~0 s): got %.3f, want < 0.05 — the Weibull dwell is reading the pod identity clock, not time in stage", hot.Hazard)
	}

	// (3) positive control for the clock itself: 300 s later in the SAME stage the hazard
	// must have grown from its restart value (weibull(300, 600, 2) ≈ 0.22).
	later := m.Assess(&model.WorkloadView{
		Pod:    pod,
		Events: []model.SecurityEventInfo{{Type: v1beta1.TypePolicyViolation, ThreatLevel: "high", TargetsPod: true, Age: 301 * time.Second}},
	}, pol, 3900, floor)
	if later.Stage != StageExploit {
		t.Fatalf("precondition: still exploit, got %s", later.StageName)
	}
	if !(later.Hazard > hot.Hazard) {
		t.Errorf("positive control: hazard must grow with time in stage: at entry %.3f, 300 s later %.3f", hot.Hazard, later.Hazard)
	}
}

// T1-B decoupling + idempotence (03 §5, §B.6.1).

// A policy whose dedicated horizons are UNSET (0) must be byte-identical to one whose horizons
// are set equal to the floor — the "inherited, not chosen" equal-value initialisation.
func TestBeliefHorizonsUnsetEqualsFloorInitialised(t *testing.T) {
	view := &model.WorkloadView{
		Pod:    model.Pod{Namespace: "ns", Name: "p", UID: "u"},
		Events: []model.SecurityEventInfo{{Type: "Anomaly", ThreatLevel: "high", TargetsPod: true, Age: 5 * time.Minute}},
	}
	base := model.Policy{Tenant: "t", ProactiveFloor: 15 * time.Minute} // horizons unset => fall back to floor
	init := base
	init.EventAgeHorizon = 15 * time.Minute
	init.ExposurePressureScale = 15 * time.Minute

	a := NewModel().Assess(view, base, 600, 900)
	b := NewModel().Assess(view, init, 600, 900)
	if a.Hazard != b.Hazard || a.PHold != b.PHold || a.StageUrgency != b.StageUrgency ||
		a.EventEvidence != b.EventEvidence || a.InStageSec != b.InStageSec {
		t.Errorf("unset horizons must equal floor-initialised: unset{h=%.4f p=%.4f u=%.4f e=%.4f} init{h=%.4f p=%.4f u=%.4f e=%.4f}",
			a.Hazard, a.PHold, a.StageUrgency, a.EventEvidence, b.Hazard, b.PHold, b.StageUrgency, b.EventEvidence)
	}
}

// A dedicated event-age horizon shorter than the floor must age events faster than the floor
// would — proving τ_ev is genuinely decoupled from the cadence knob.
func TestEventAgeHorizonDecouplesFromFloor(t *testing.T) {
	view := &model.WorkloadView{
		Pod:    model.Pod{Namespace: "ns", Name: "p", UID: "u"},
		Events: []model.SecurityEventInfo{{Type: "Anomaly", ThreatLevel: "high", TargetsPod: true, Age: 8 * time.Minute}},
	}
	wide := model.Policy{Tenant: "t", ProactiveFloor: 15 * time.Minute, EventAgeHorizon: 15 * time.Minute}
	narrow := wide
	narrow.EventAgeHorizon = 10 * time.Minute // 8m event: weight 1-8/15=0.47 vs 1-8/10=0.20
	w := NewModel().Assess(view, wide, 600, 900)
	n := NewModel().Assess(view, narrow, 600, 900)
	if !(n.EventEvidence < w.EventEvidence) {
		t.Errorf("a shorter τ_ev must age the event more: wide=%.4f narrow=%.4f", w.EventEvidence, n.EventEvidence)
	}
}

// The stage clock must be idempotent within a tick: two Assess calls for the same pod at the same
// exposure and stage return the same dwell (the ablation arm calls Assess twice on the same views).
func TestStageClockIdempotentWithinTick(t *testing.T) {
	m := NewModel()
	pol := kcPolicy()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p", UID: "u"}}
	a1 := m.Assess(v, pol, 1200, 3600)
	a2 := m.Assess(v, pol, 1200, 3600)
	if a1.InStageSec != a2.InStageSec || a1.Hazard != a2.Hazard {
		t.Errorf("stage clock must be idempotent within a tick: call1{dwell=%.1f h=%.4f} call2{dwell=%.1f h=%.4f}",
			a1.InStageSec, a1.Hazard, a2.InStageSec, a2.Hazard)
	}
	// next tick, same stage, more exposure: dwell accrues == exposure delta (no spurious reset).
	a3 := m.Assess(v, pol, 1500, 3600)
	if d := a3.InStageSec - a1.InStageSec; d < 299 || d > 301 {
		t.Errorf("unchanged stage must accrue dwell with exposure: Δdwell=%.1f want ~300", d)
	}
}
