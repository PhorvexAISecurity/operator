/*
 * Phorvex — P-VCLUSTER Pass 2: the SERVER-SIDE policy safety gate for apply-fix. A candidate policy is
 * run on a SHADOW engine over a canonical safety fixture; if it would regress efficacy (1.62× ratio>1),
 * proactivity (P3), or no-harm (stateful never rotated), apply-fix REJECTS it before any cluster write.
 *
 * Uses ONLY the exported decision API (NewCoverageEngine / Ablate / Decide) — the brain decision logic
 * is untouched; this is a runtime guard in the console.
 */

package console

import (
	"fmt"
	"time"

	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

// canonicalGateFleet — a fixed safety fixture (independent of the test fixtures by design). crown/cheap
// drive efficacy; the secret crowns are the long-exposed proactivity probe; stateful-db is the no-harm
// (never-rotate) probe.
func canonicalGateFleet() []*model.WorkloadView {
	mk := func(name string, secrets bool, exposure time.Duration, stateful bool) *model.WorkloadView {
		v := &model.WorkloadView{
			Pod: model.Pod{
				Namespace: "gate", Name: name, UID: "u-" + name,
				DesiredReplicas: 3, ReadyReplicas: 3, Ready: true, Stateful: stateful,
			},
			Phase:              model.PhaseWarm,
			BlastRadius:        0.6,
			Neighbors:          []model.NeighborRef{{Key: "gate/crown1", Value: 5.0}},
			ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: exposure},
		}
		if secrets {
			v.Pod.MountedSecrets = []string{"creds"}
		}
		return v
	}
	return []*model.WorkloadView{
		mk("crown1", true, 3*time.Hour, false),
		mk("crown2", true, 3*time.Hour, false),
		mk("cheap1", false, 2*time.Hour, false),
		mk("cheap2", false, 2*time.Hour, false),
		mk("stateful-db", true, 3*time.Hour, true), // must NEVER be rotated (no-harm)
	}
}

// PolicySafetyGate returns nil iff the candidate policy preserves efficacy + proactivity + no-harm on
// the canonical fixture. Any regression => a descriptive error (apply-fix rejects the delta).
func PolicySafetyGate(candidate model.Policy) error {
	views := canonicalGateFleet()

	// (1) EFFICACY (1.62× gate): the policy must still beat equal-budget random per-dollar (ratio>1).
	e1 := decision.NewCoverageEngine()
	seeds := make([]int64, 20)
	for i := range seeds {
		seeds[i] = int64(i + 1)
	}
	res := e1.Ablate(views, candidate, seeds)
	if res.P1PerDollar <= 0 {
		return fmt.Errorf("efficacy: the policy invalidates nothing (per-$=%.3f) — it starves targeting", res.P1PerDollar)
	}
	if res.RandomPerDollar > 0 && res.Ratio <= 1.0 {
		return fmt.Errorf("efficacy: recon-per-$ ratio %.3f <= 1.0 (no better than random)", res.Ratio)
	}

	// (2) PROACTIVITY (P3) + (3) NO-HARM (lead-demo), from one Decide pass on a fresh engine.
	e2 := decision.NewCoverageEngine()
	decs := e2.Decide(views, candidate)
	longExposedFired, statefulRotated := false, false
	for _, d := range decs {
		if d.Pod == "crown1" && d.Selected && d.Action != model.ActionNoop {
			longExposedFired = true
		}
		if d.Pod == "stateful-db" && d.Selected && d.Action == model.ActionRotate {
			statefulRotated = true
		}
	}
	if statefulRotated {
		return fmt.Errorf("no-harm: the policy would ROTATE a stateful pod (destroys state)")
	}
	if !longExposedFired {
		return fmt.Errorf("proactivity (P3): a long-exposed secret pod gets NO proactive move — proactivity disabled")
	}
	return nil
}
