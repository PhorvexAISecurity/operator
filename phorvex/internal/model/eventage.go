/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package model

import (
	"strings"
	"time"
	"unicode/utf8"
)

const maxEventEvidenceStringBytes = 1024

// DefaultEventAgeHorizon is the inherited, uncalibrated migration default for
// SecurityEvent evidence memory. It is intentionally independent of actuation
// cadence and exposure pressure.
const DefaultEventAgeHorizon = time.Hour

// EffectiveEventAgeHorizon returns the positive linear evidence horizon used by
// every internal consumer. Zero is retained as a legacy/internal omission signal.
func (p Policy) EffectiveEventAgeHorizon() time.Duration {
	if p.EventAgeHorizon <= 0 {
		return DefaultEventAgeHorizon
	}
	return p.EventAgeHorizon
}

// EventAgeWeight is THE event-aging weight (PHORVEXSEC-186 / M-27, ruling Q1): the
// linear decay w(a) = 1 − clamp01(a/τ_ev) = max(0, 1 − a/τ_ev) for non-negative
// observed ages. It is shared with the kill-chain evidence sum so the two halves of
// belief agree that time passes. Invariants: w ∈ [0,1], w(0) = 1, monotone
// non-increasing in age, exactly 0 at a ≥ τ_ev (a stale event becomes inactive without
// a second cutoff parameter). A negative age is invalid/future evidence and contributes 0.
//
// τ_ev ≤ 0 disables aging (w = 1) for direct low-level callers. Policy consumers
// use EffectiveEventAgeHorizon, whose inherited one-hour default remains
// INSUFFICIENT EVIDENCE pending calibration.
func EventAgeWeight(age, tau time.Duration) float64 {
	if age < 0 {
		return 0
	}
	if tau <= 0 {
		return 1
	}
	if age == 0 {
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
	EventUID         string  `json:"eventUID,omitempty"`
	Source           string  `json:"source,omitempty"`
	Type             string  `json:"type,omitempty"`
	ThreatLevel      string  `json:"threatLevel,omitempty"`
	TrustVerdict     string  `json:"trustVerdict,omitempty"`
	CreatorIdentity  string  `json:"creatorIdentity,omitempty"`
	TargetPodUID     string  `json:"targetPodUID,omitempty"`
	TargetsPod       bool    `json:"targetsPod"`
	AgeSec           float64 `json:"ageSec"`
	Weight           float64 `json:"weight"`
	TimestampPresent bool    `json:"present"` // false: the CR had no usable CreationTimestamp → weight 0
}

// Canonical returns the public audit projection of event identity. It applies the
// same credential redaction as DecisionTrace steering references without changing
// immutable Kubernetes identity or any numeric assessment input.
func (e EventEvidence) Canonical() EventEvidence {
	e.Name = boundedEventEvidenceString(e.Name)
	e.EventUID = boundedEventEvidenceString(e.EventUID)
	e.Source = boundedEventEvidenceString(e.Source)
	e.Type = boundedEventEvidenceString(e.Type)
	e.ThreatLevel = boundedEventEvidenceString(e.ThreatLevel)
	e.TrustVerdict = boundedEventEvidenceString(e.TrustVerdict)
	e.CreatorIdentity = boundedEventEvidenceString(e.CreatorIdentity)
	e.TargetPodUID = boundedEventEvidenceString(e.TargetPodUID)
	return e
}

func boundedEventEvidenceString(value string) string {
	value = strings.ToValidUTF8(redactTraceString(value), "�")
	if len(value) > maxEventEvidenceStringBytes {
		value = value[:maxEventEvidenceStringBytes]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}
