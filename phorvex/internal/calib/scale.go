/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import "time"

// Source records where a scale's value came from. It is part of the value, not a sidecar,
// because the failure this whole ticket is about is a number whose origin got lost: a constant
// fitted to one cluster was shipped everywhere and nothing in the system could say so.
//
// A Scale must never be readable without its Source. That is why there is no bare float64
// accessor that drops it.
type Source string

const (
	// SourceMeasured means the value was derived from this cluster's own observations.
	SourceMeasured Source = "measured"
	// SourceFallbackDefault means the shipped constant is still in force because the signal
	// was missing or insufficient. The value is honest, but it is not about this cluster.
	SourceFallbackDefault Source = "fallback_default"
)

// Scale is a calibrated denominator/cap together with everything needed to judge it.
type Scale struct {
	// Name identifies the constant this scale would replace (e.g. "co_residency").
	Name string
	// Value is the scale in force. With SourceFallbackDefault this is the shipped constant.
	Value float64
	// Source distinguishes a measurement from a fallback. Never drop this.
	Source Source
	// Reason is set when Source is SourceFallbackDefault: why the measurement was not usable.
	// Empty for a measured scale.
	Reason string
	// Percentile is the configured quantile, echoed so a stored result is self-describing.
	Percentile float64
	// Floor is the safety floor applied. A scale below its floor is not merely odd, it
	// inverts the term it divides, so the floor is enforced rather than warned about.
	Floor float64
	// FlooredUp is true when the raw percentile fell below Floor and was raised to it. This is
	// a real event worth seeing: it means the measurement disagreed with the model's premise.
	FlooredUp bool
	// Clip describes how Value sits against the raw observations.
	Clip ClipReport
	// ComputedAt is the observation time (from the snapshot clock, never wall time, so a
	// replayed snapshot reproduces exactly).
	ComputedAt time.Time
}

// Measured builds a measured Scale from raw observations, applying the safety floor.
//
// minObservations guards the case the spec cares about most: a percentile computed from a
// handful of samples is a number, but it is not an estimate. Below the threshold this returns
// a fallback carrying the shipped constant and the reason, rather than a confident-looking
// value derived from three data points.
func Measured(name string, raw []float64, p, floor, fallback float64, minObservations int, at time.Time) Scale {
	s := Scale{Name: name, Percentile: p, Floor: floor, ComputedAt: at}

	if len(raw) < minObservations {
		s.Value, s.Source = fallback, SourceFallbackDefault
		s.Reason = "insufficient observations"
		s.Clip = Clipping(raw, fallback)
		return s
	}
	q, ok := Percentile(raw, p)
	if !ok {
		s.Value, s.Source = fallback, SourceFallbackDefault
		s.Reason = "no observations"
		return s
	}

	s.Value, s.Source = q, SourceMeasured
	if s.Value < floor {
		s.Value, s.FlooredUp = floor, true
	}
	s.Clip = Clipping(raw, s.Value)
	return s
}

// Fallback builds a Scale that is explicitly the shipped constant, with a stated reason.
func Fallback(name string, value float64, reason string, at time.Time) Scale {
	return Scale{
		Name: name, Value: value, Source: SourceFallbackDefault,
		Reason: reason, ComputedAt: at,
	}
}

// IsMeasured reports whether this scale describes the cluster it is running on.
func (s Scale) IsMeasured() bool { return s.Source == SourceMeasured }

// Saturated reports whether the at-ceiling ratio exceeds threshold — the invariant the ticket
// asks for as a monitored alarm. A scale that pins a large share of the fleet at its cap has
// stopped discriminating, and the term it feeds has degenerated into a constant factor.
//
// This is the check that would have surfaced the current state instead of an audit finding it.
func (s Scale) Saturated(threshold float64) bool {
	return s.Clip.N > 0 && s.Clip.AtCeilingRatio() > threshold
}
