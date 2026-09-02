/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package model

import "time"

// EventAgeWeight is THE event-aging weight (PHORVEXSEC-186 / M-27, ruling Q1): the
// linear decay w(a) = 1 − clamp01(a/τ_ev) = max(0, 1 − a/τ_ev) that ctxprov already
// applied to the sensed posture, now shared with the kill-chain evidence sum so the two
// halves of belief agree that time passes. Invariants: w ∈ [0,1], w(0) = 1, monotone
// non-increasing in age, exactly 0 at a ≥ τ_ev (a stale event becomes inactive without
// a second cutoff parameter).
//
// τ_ev ≤ 0 disables aging (w = 1), preserving the pre-M-27 behaviour of a policy with no
// proactive floor. The VALUE of τ_ev is not chosen here: it is T1-B's initialization
// (= the deployed proactiveFloor) and is INSUFFICIENT EVIDENCE until M-29 / T3.
func EventAgeWeight(age, tau time.Duration) float64 {
	if tau <= 0 {
		return 1
	}
	if age <= 0 {
		return 1
	}
	r := age.Seconds() / tau.Seconds()
	if r >= 1 {
		return 0
	}
	return 1 - r
}

// EventEvidence is the audited per-event contribution to an asset's kill-chain belief
// (M-27): what the event was, how old it was at this tick, and the weight it carried.
type EventEvidence struct {
	Name             string  `json:"name,omitempty"`
	Source           string  `json:"source,omitempty"`
	Type             string  `json:"type,omitempty"`
	ThreatLevel      string  `json:"threatLevel,omitempty"`
	TargetsPod       bool    `json:"targetsPod"`
	AgeSec           float64 `json:"ageSec"`
	Weight           float64 `json:"weight"`
	TimestampPresent bool    `json:"present"` // false: the CR had no usable CreationTimestamp → weight 0
}
