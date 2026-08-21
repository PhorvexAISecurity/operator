/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"sort"
	"time"
)

// readydelay.go calibrates ReadyDelayReference from observed pod-ready latency (PHVX-74 §4).
//
// This scale is different in kind from the other two, and the difference is the whole reason this
// file is long. Co-residency and dispersion are read off a snapshot: every asset's value is known
// at the instant you look. Ready-delay is a DURATION, and a rotation that has not finished yet has
// no duration — only a lower bound on one.
//
// Ignoring that is the classic way to produce a confidently wrong number. If a replacement has not
// become Ready after 800 s, recording 800 s is not a measurement, it is a floor: the true value is
// somewhere above it. Averaging floors in with real observations biases every statistic downward,
// and biases it MOST when the fleet is slowest — precisely when the scale matters. So every record
// carries whether it is an observation or a bound, and the estimator is censoring-aware.

// ReadyDelayFloor is the safety floor from the spec: a reference below one second would make the
// normalized value explode for any real rotation.
const ReadyDelayFloor = time.Second

// ShippedReadyDelayReference mirrors cost.ReadyDelayReference. Duplicated to keep this package free
// of the cost path; pinned by TestReadyDelayReferenceAgreesWithCost.
const ShippedReadyDelayReference = 400 * time.Second

// MinReadyDelayObservations is the spec's activation gate. Below this the learned reference is not
// activated and the shipped constant stands with a stated reason.
const MinReadyDelayObservations = 100

// Outcome classifies one rotation observation. The three values are the spec's, kept verbatim so
// an exported record means the same thing to a reader of the ticket.
type Outcome string

const (
	// OutcomeObserved: the replacement became Ready and the latency is known exactly.
	OutcomeObserved Outcome = "event_observed"
	// OutcomeCensored: the replacement was not Ready by the deadline. The true latency is
	// strictly GREATER than Elapsed — this is a lower bound, not a measurement.
	OutcomeCensored Outcome = "right_censored"
	// OutcomeInvalid: unusable, with a reason. Excluded from the distribution entirely rather
	// than folded in as either an observation or a bound.
	OutcomeInvalid Outcome = "invalid_or_cancelled"
)

// RotationRecord is one observation, carrying every field the spec requires for export.
type RotationRecord struct {
	ID        string
	Tenant    string
	Namespace string
	Pod       string
	Action    string

	StartedAt time.Time
	// RecordedAt is when the outcome became known. It drives the seven-day lookback;
	// StartedAt alone would retain a long-running censored observation for the wrong window.
	RecordedAt time.Time
	// ReadyAt is zero unless Outcome is OutcomeObserved.
	ReadyAt time.Time
	// Elapsed is the actual latency when observed, or the censoring time when censored.
	Elapsed time.Duration

	Outcome Outcome
	// InvalidReason is required when Outcome is OutcomeInvalid — an unexplained exclusion is
	// indistinguishable from a silently dropped inconvenient result.
	InvalidReason string

	// ReferenceAtStart and CensorDeadline are FROZEN when the rotation begins.
	//
	// The spec is explicit that a later scale refresh must not move the deadline of an
	// already-pending rotation, and the reason is that it would rewrite history: a rotation
	// judged against a 400 s reference would silently become one judged against 600 s, so the
	// same physical event would change classification depending on when the calibrator happened
	// to run. Freezing them makes each record self-describing and the whole set reproducible.
	ReferenceAtStart time.Duration
	CensorDeadline   time.Time
}

// Normalized reproduces cost.NormalizeReadyDelay against the reference frozen at start:
// min(L/ref, 2). For a censored record this is a lower bound like Elapsed itself.
func (r RotationRecord) Normalized() float64 {
	ref := r.ReferenceAtStart
	if ref <= 0 {
		ref = ShippedReadyDelayReference
	}
	v := r.Elapsed.Seconds() / ref.Seconds()
	if v > 2 {
		return 2
	}
	if v < 0 {
		return 0
	}
	return v
}

// ReadyDelayReport is the shadow result plus the ratios the spec asks to report separately.
type ReadyDelayReport struct {
	Reference Scale

	// Eligible counts records that entered the estimate (observed + censored).
	Eligible int
	Observed int
	Censored int
	Invalid  int

	// ExceedanceRatio is the share with L >= the reference in force — NOT the same as hard
	// saturation, and the spec asks for both because the normalizer only pins at 2x.
	ExceedanceRatio float64
	// HardSaturationRatio is the share with L >= 2x reference, i.e. actually pinned at the
	// normalizer's ceiling of 2.0.
	HardSaturationRatio float64
	// CensoringRatio is censored / eligible. High censoring is what makes a percentile
	// unidentifiable, so it is reported next to the estimate rather than buried.
	CensoringRatio float64

	// Percentiles holds the censoring-aware estimate per requested quantile. A quantile the data
	// cannot identify is ABSENT from this map rather than present with a guessed value.
	Percentiles map[float64]time.Duration
	// Unidentifiable lists the requested quantiles that could not be estimated honestly.
	Unidentifiable []float64
}

// kmPoint is one step of the Kaplan-Meier survival curve.
type kmPoint struct {
	t        time.Duration
	survival float64
}

// kaplanMeier builds the survival curve S(t) = P(L > t) from observed and censored records.
//
// WHY THIS ESTIMATOR. The naive alternative — sort every Elapsed and take a rank — treats a
// censored record as if the pod became Ready at exactly the deadline. That is the one thing the
// spec explicitly forbids, and it biases every percentile downward in proportion to how much
// censoring there is. Kaplan-Meier instead lets a censored record contribute what it actually
// knows: it was still pending up to its censoring time, and nothing after.
//
// At each distinct event time the curve multiplies by (1 - d/n): d failures among n still at risk.
// Censored records leave the risk set without ever counting as a failure.
func kaplanMeier(records []RotationRecord) []kmPoint {
	type ev struct {
		t        time.Duration
		censored bool
	}
	var evs []ev
	for _, r := range records {
		switch r.Outcome {
		case OutcomeObserved:
			evs = append(evs, ev{r.Elapsed, false})
		case OutcomeCensored:
			evs = append(evs, ev{r.Elapsed, true})
		}
	}
	if len(evs) == 0 {
		return nil
	}
	// Ties: events are processed BEFORE censorings at the same instant, the standard convention.
	// A pod that became Ready exactly at the deadline is an observation, not a bound.
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].t != evs[j].t {
			return evs[i].t < evs[j].t
		}
		return !evs[i].censored && evs[j].censored
	})

	var out []kmPoint
	atRisk := len(evs)
	survival := 1.0
	for i := 0; i < len(evs); {
		t := evs[i].t
		deaths, leaving := 0, 0
		for i < len(evs) && evs[i].t == t {
			if !evs[i].censored {
				deaths++
			}
			leaving++
			i++
		}
		if deaths > 0 && atRisk > 0 {
			survival *= 1 - float64(deaths)/float64(atRisk)
			out = append(out, kmPoint{t: t, survival: survival})
		}
		atRisk -= leaving
	}
	return out
}

// kmQuantile returns the smallest t with S(t) <= 1-p, and whether the data identifies it.
//
// Identifiability is the honest part. If the curve never falls to 1-p — because the largest
// records are censored and the estimator simply does not know what happens beyond them — then the
// quantile is NOT estimable, and returning the largest observed value would be presenting a lower
// bound as an answer. It reports false instead.
func kmQuantile(curve []kmPoint, p float64) (time.Duration, bool) {
	if len(curve) == 0 || p <= 0 || p >= 1 {
		return 0, false
	}
	target := 1 - p
	for _, pt := range curve {
		if pt.survival <= target+1e-12 {
			return pt.t, true
		}
	}
	return 0, false
}

// CalibrateReadyDelay produces the shadow ready-delay report.
//
// quantiles are the candidates to evaluate. activateAt is the percentile whose value would become
// the reference if the gate passes; the spec sets the gate at MinReadyDelayObservations eligible
// outcomes AND that percentile being identifiable.
func CalibrateReadyDelay(records []RotationRecord, quantiles []float64, activateAt float64, at time.Time) ReadyDelayReport {
	rep := ReadyDelayReport{Percentiles: map[float64]time.Duration{}}

	var eligible []RotationRecord
	for _, r := range records {
		switch r.Outcome {
		case OutcomeObserved:
			rep.Observed++
			eligible = append(eligible, r)
		case OutcomeCensored:
			rep.Censored++
			eligible = append(eligible, r)
		default:
			rep.Invalid++
		}
	}
	rep.Eligible = len(eligible)

	if rep.Eligible == 0 {
		rep.Reference = Fallback("ready_delay", ShippedReadyDelayReference.Seconds(), "no eligible rotations", at)
		return rep
	}
	rep.CensoringRatio = float64(rep.Censored) / float64(rep.Eligible)

	// Exceedance and hard saturation are measured against each record's OWN frozen reference, so
	// a set spanning a reference change stays interpretable.
	exceed, saturated := 0, 0
	for _, r := range eligible {
		ref := r.ReferenceAtStart
		if ref <= 0 {
			ref = ShippedReadyDelayReference
		}
		if r.Elapsed >= ref {
			exceed++
		}
		if r.Elapsed >= 2*ref {
			saturated++
		}
	}
	rep.ExceedanceRatio = float64(exceed) / float64(rep.Eligible)
	rep.HardSaturationRatio = float64(saturated) / float64(rep.Eligible)

	curve := kaplanMeier(eligible)
	for _, q := range quantiles {
		if v, ok := kmQuantile(curve, q); ok {
			rep.Percentiles[q] = v
		} else {
			rep.Unidentifiable = append(rep.Unidentifiable, q)
		}
	}

	// The activation gate. Both conditions are required, and the reason names which one failed —
	// "not enough data" and "the data cannot resolve this quantile" call for different responses.
	target, identifiable := kmQuantile(curve, activateAt)
	switch {
	case rep.Eligible < MinReadyDelayObservations:
		rep.Reference = Fallback("ready_delay", ShippedReadyDelayReference.Seconds(),
			"insufficient eligible outcomes", at)
	case !identifiable:
		rep.Reference = Fallback("ready_delay", ShippedReadyDelayReference.Seconds(),
			"requested percentile not identifiable under censoring", at)
	default:
		v := target
		if v < ReadyDelayFloor {
			v = ReadyDelayFloor
		}
		rep.Reference = Scale{
			Name: "ready_delay", Value: v.Seconds(), Source: SourceMeasured,
			Percentile: activateAt, Floor: ReadyDelayFloor.Seconds(),
			FlooredUp: target < ReadyDelayFloor, ComputedAt: at,
		}
	}
	return rep
}
