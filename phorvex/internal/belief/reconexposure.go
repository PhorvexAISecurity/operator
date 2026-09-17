/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package belief

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
	"time"
)

// reconExposure is the DEFAULT BeliefEstimator. It blends two evidence streams:
//
//   - Event evidence (the SAME SecurityEvent feed Phoenix ingests): recent events
//     targeting this pod raise belief by their threat-level rank (info..critical),
//     decayed by age. Events on graph NEIGHBORS contribute at a discount (a foothold
//     next door raises this pod's compromise belief). This is EVIDENCE, never an
//     exact-match trigger — it nudges a continuous belief.
//   - Recon-invalidation / exposure (DETECTION-INDEPENDENT): the pod-identity
//     exposure clock vs the policy's ProactiveFloor. A pod unchanged for longer than
//     the floor has had more time to be reconnoitred; belief rises toward 1 as
//     exposure approaches and exceeds the floor. This is the thesis signal — it fires
//     with NO detector at all.
//
// It reuses Phoenix's canonical ThreatLevelRank so Phorvex and Phoenix rank severity
// identically (no parallel vocabulary).
type reconExposure struct{}

func (reconExposure) Name() string { return "recon-exposure" }

func (reconExposure) Belief(view *model.WorkloadView, pol model.Policy) float64 {
	evidence := 0.0
	if pol.EventDriven {
		for _, e := range view.Events {
			rank := v1beta1.ThreatLevelRank(e.ThreatLevel)
			if rank < 0 {
				rank = 0
			}
			sev := float64(rank) / 4.0 // info..critical -> 0..1

			// Age decay: full weight when fresh, ->0 over the EVENT-AGE horizon (T1-B's τ_ev,
			// PHORVEXSEC-188 / M-29) — the same linear model.EventAgeWeight ctxprov and killchain
			// use, so the three event-decay sites turn on one screw and the hygiene-cadence knob
			// (ProactiveFloor) no longer stretches how long an alert stays believed. The inherited
			// one-hour horizon is independent of cadence and remains uncalibrated.
			decay := 0.0
			if !e.TimestampMissing {
				decay = model.EventAgeWeight(e.Age, eventAgeHorizonBelief(pol))
			}

			w := sev * decay
			if !e.TargetsPod {
				w *= 0.4 // neighbor evidence is discounted
			}
			// Combine independently (noisy-OR): each piece of evidence can only raise belief.
			evidence = evidence + w*(1.0-evidence)
		}
	}

	// Recon-invalidation / exposure pressure (detection-independent).
	exposure := 0.0
	if since, ok := view.ExposureByVariable[model.VarPodIdentity]; ok && pol.ProactiveFloor > 0 {
		exposure = clampB(since.Seconds()/pol.ProactiveFloor.Seconds(), 0, 1.5) / 1.5
	}

	// Noisy-OR the two streams: either strong evidence OR long exposure raises belief.
	return clampB(evidence+exposure*(1.0-evidence), 0, 1)
}

func clampB(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func init() { Registry.Register(reconExposure{}) }

// eventAgeHorizonBelief shares the one effective rule with every event consumer.
func eventAgeHorizonBelief(pol model.Policy) time.Duration {
	return pol.EffectiveEventAgeHorizon()
}
