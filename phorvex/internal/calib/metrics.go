/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// metrics.go publishes the shadow calibration series (PHVX-74 §6).
//
// WHY THESE LIVE HERE rather than in internal/metrics with the rest. This package's defining
// property is that nothing on the decision path can reach it, and that property is currently
// enforced by a dependency check. Publishing from internal/metrics would invert the import
// (metrics -> calib) and make the guarantee conditional on nobody ever adding a metric to the
// decision packages — an implicit constraint that would break silently and long after the fact.
// The series names still follow the phorvex_ convention, so the split is invisible to Prometheus.
//
// WHAT THE SERIES ARE FOR. A shadow calibration nobody can see is indistinguishable from one that
// is not running, so the point of this file is to make the proposal, its provenance and its
// disagreement with production all observable BEFORE anything is switched over.

var (
	scaleValue = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_scale_value",
		Help: "Candidate calibrated scale currently in force in shadow (shipped constant when source=fallback_default).",
	}, []string{"scale"})

	// scaleSource is an info-style series: exactly one source label is 1 per scale. It is a
	// separate series rather than a label on the value because the value's meaning DEPENDS on it
	// — a fallback and a measurement are different claims that happen to be the same float.
	scaleSource = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_scale_source",
		Help: "1 for the active provenance of each scale (measured | fallback_default).",
	}, []string{"scale", "source"})

	scalePercentile = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_scale_percentile",
		Help: "Configured quantile used to derive the scale, echoed so a stored sample is self-describing.",
	}, []string{"scale"})

	scaleObservations = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_observations",
		Help: "Observations the scale was derived from.",
	}, []string{"scale"})

	scaleInvalid = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_observations_invalid",
		Help: "Observations excluded as missing or invalid.",
	}, []string{"scale"})

	atCeilingCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_at_ceiling_count",
		Help: "Observations at or above the candidate scale.",
	}, []string{"scale"})

	atCeilingRatio = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_at_ceiling_ratio",
		Help: "Fraction at or above the candidate scale — the saturation invariant's source series.",
	}, []string{"scale"})

	strictlyClippedCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_strictly_clipped_count",
		Help: "Observations strictly above the candidate scale, whose magnitude it discards.",
	}, []string{"scale"})

	strictlyClippedRatio = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_strictly_clipped_ratio",
		Help: "Fraction whose magnitude the candidate scale discards. Differs from at-ceiling on ties.",
	}, []string{"scale"})

	refreshTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "phorvex_calib_refresh_total",
		Help: "Calibration refresh attempts by outcome.",
	}, []string{"scale", "result"})

	scaleAge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_scale_age_seconds",
		Help: "Age of the value in force. Keeps rising while refreshes fail, which is the signal a stalled calibrator gives.",
	}, []string{"scale"})

	lastSuccessfulRefresh = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_last_successful_refresh_timestamp_seconds",
		Help: "Unix timestamp of the last measured refresh. Zero means this process has never produced a measured value for the scale.",
	}, []string{"scale"})

	scaleChangeRatio = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_scale_change_ratio",
		Help: "Relative change from the previous refresh, |new-old|/old — the churn a shorter cadence buys.",
	}, []string{"scale"})

	fallbackActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_fallback_active",
		Help: "1 when the shipped constant is in force because the signal was missing or insufficient.",
	}, []string{"scale"})

	fallbackReason = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_fallback_reason",
		Help: "1 for the active fallback reason. Absent for a measured scale.",
	}, []string{"scale", "reason"})

	saturationWarning = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_saturation_warning",
		Help: "1 when at-ceiling has exceeded the threshold for the configured number of CONSECUTIVE refreshes.",
	}, []string{"scale"})

	saturationStreak = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "phorvex_calib_saturation_streak",
		Help: "Consecutive refreshes over the saturation threshold. Visible so a warning about to fire is not a surprise.",
	}, []string{"scale"})

	readyDelayCensoring = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "phorvex_calib_ready_delay_censoring_ratio",
		Help: "Fraction of rotations still pending at their deadline. High values are why a percentile can be unavailable.",
	})

	readyDelayExceedance = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "phorvex_calib_ready_delay_exceedance_ratio",
		Help: "Fraction of rotations at or past the reference in force (normalized >= 1.0).",
	})

	readyDelayHardSaturation = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "phorvex_calib_ready_delay_hard_saturation_ratio",
		Help: "Fraction at or past 2x the reference, i.e. pinned at the normalizer's ceiling.",
	})

	readyDelayUnidentifiable = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "phorvex_calib_ready_delay_unidentifiable_quantiles",
		Help: "Requested quantiles censoring made unestimable. Non-zero means the data cannot answer what was asked.",
	})
)

var registerOnce sync.Once

// Register publishes the series onto the controller-runtime registry. Safe to call more than once.
func Register() {
	registerOnce.Do(func() {
		crmetrics.Registry.MustRegister(
			scaleValue, scaleSource, scalePercentile, scaleObservations, scaleInvalid,
			atCeilingCount, atCeilingRatio, strictlyClippedCount, strictlyClippedRatio,
			refreshTotal, scaleAge, lastSuccessfulRefresh, scaleChangeRatio,
			fallbackActive, fallbackReason,
			saturationWarning, saturationStreak,
			readyDelayCensoring, readyDelayExceedance, readyDelayHardSaturation, readyDelayUnidentifiable,
		)
	})
}

// Tracker carries the state a single refresh cannot know: what the previous value was, how long the
// current one has stood, and how many consecutive refreshes have been over the saturation
// threshold.
//
// The streak is the reason this type exists. The spec asks for a warning only after a configured
// number of CONSECUTIVE saturated refreshes, and a stateless publisher would flap: one noisy
// interval would raise an alarm that the next interval silently clears, which trains everyone to
// ignore it. Persistence is what makes the alarm mean something.
type Tracker struct {
	mu sync.Mutex

	// Persistence is the number of consecutive over-threshold refreshes required before the
	// warning is raised.
	Persistence int
	// Threshold is the at-ceiling ratio above which a refresh counts as saturated.
	Threshold float64

	prev      map[string]float64
	lastFresh map[string]time.Time
	firstSeen map[string]time.Time
	streak    map[string]int
	reason    map[string]string
}

// NewTracker builds a Tracker with the given saturation rule.
func NewTracker(threshold float64, persistence int) *Tracker {
	if persistence < 1 {
		persistence = 1
	}
	return &Tracker{
		Persistence: persistence, Threshold: threshold,
		prev: map[string]float64{}, lastFresh: map[string]time.Time{}, firstSeen: map[string]time.Time{},
		streak: map[string]int{}, reason: map[string]string{},
	}
}

// ObserveScale publishes one scale's refresh result and advances the tracker's state.
//
// now is the observation clock, passed rather than read so a replayed history reproduces exactly.
func (t *Tracker) ObserveScale(s Scale, now time.Time) {
	t.ObserveScaleWithInvalid(s, now, 0)
}

// ObserveScaleWithInvalid publishes a scale plus observations excluded before its raw
// distribution was built (for example unschedulable nodes or pods without a physics witness).
func (t *Tracker) ObserveScaleWithInvalid(s Scale, now time.Time, invalid int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	name := s.Name
	scaleValue.WithLabelValues(name).Set(s.Value)
	scalePercentile.WithLabelValues(name).Set(s.Percentile)
	scaleObservations.WithLabelValues(name).Set(float64(s.Clip.N))
	scaleInvalid.WithLabelValues(name).Set(float64(invalid))
	atCeilingCount.WithLabelValues(name).Set(float64(s.Clip.AtCeiling))
	atCeilingRatio.WithLabelValues(name).Set(s.Clip.AtCeilingRatio())
	strictlyClippedCount.WithLabelValues(name).Set(float64(s.Clip.StrictlyClipped))
	strictlyClippedRatio.WithLabelValues(name).Set(s.Clip.StrictlyClippedRatio())

	// Exactly one source is 1. Both are written every time so a transition cannot leave the old
	// label stuck at 1 and the scale looking simultaneously measured and fallen back.
	measured := 0.0
	if s.IsMeasured() {
		measured = 1
	}
	scaleSource.WithLabelValues(name, string(SourceMeasured)).Set(measured)
	scaleSource.WithLabelValues(name, string(SourceFallbackDefault)).Set(1 - measured)
	fallbackActive.WithLabelValues(name).Set(1 - measured)

	// Clear a previous reason before setting the current one, for the same reason.
	if old, ok := t.reason[name]; ok && old != s.Reason {
		fallbackReason.WithLabelValues(name, old).Set(0)
	}
	if s.Reason != "" {
		fallbackReason.WithLabelValues(name, s.Reason).Set(1)
		t.reason[name] = s.Reason
	} else {
		delete(t.reason, name)
	}

	// A fallback is a FAILED refresh for counting purposes: the calibrator ran but could not
	// produce a measurement. Counting it as success would make a permanently-unmeasurable scale
	// look healthy.
	result := "success"
	if !s.IsMeasured() {
		result = "failure"
	}
	refreshTotal.WithLabelValues(name, result).Inc()

	if p, ok := t.prev[name]; ok && p != 0 {
		d := (s.Value - p) / p
		if d < 0 {
			d = -d
		}
		scaleChangeRatio.WithLabelValues(name).Set(d)
	} else {
		scaleChangeRatio.WithLabelValues(name).Set(0)
	}
	t.prev[name] = s.Value

	// Age counts from the last SUCCESSFUL refresh, so it keeps rising while the calibrator falls
	// back — which is precisely the situation a freshness alert should catch.
	if s.IsMeasured() {
		t.lastFresh[name] = now
		lastSuccessfulRefresh.WithLabelValues(name).Set(float64(now.Unix()))
	}
	if _, ok := t.firstSeen[name]; !ok {
		t.firstSeen[name] = now
	}
	if last, ok := t.lastFresh[name]; ok {
		scaleAge.WithLabelValues(name).Set(now.Sub(last).Seconds())
	} else {
		scaleAge.WithLabelValues(name).Set(now.Sub(t.firstSeen[name]).Seconds())
		lastSuccessfulRefresh.WithLabelValues(name).Set(0)
	}

	// Saturation streak and the persisted warning.
	if s.Clip.N > 0 && s.Clip.AtCeilingRatio() > t.Threshold {
		t.streak[name]++
	} else {
		t.streak[name] = 0
	}
	saturationStreak.WithLabelValues(name).Set(float64(t.streak[name]))
	warn := 0.0
	if t.streak[name] >= t.Persistence {
		warn = 1
	}
	saturationWarning.WithLabelValues(name).Set(warn)
}

// ObserveReadyDelay publishes the ready-delay specific series.
func (t *Tracker) ObserveReadyDelay(rep ReadyDelayReport, now time.Time) {
	readyDelayCensoring.Set(rep.CensoringRatio)
	readyDelayExceedance.Set(rep.ExceedanceRatio)
	readyDelayHardSaturation.Set(rep.HardSaturationRatio)
	readyDelayUnidentifiable.Set(float64(len(rep.Unidentifiable)))

	t.ObserveScaleWithInvalid(rep.Reference, now, rep.Invalid)
	// Snapshot-derived scales carry their population in Scale.Clip.N. Ready-delay does not:
	// its population contains observed plus right-censored outcomes and is evaluated by the
	// Kaplan-Meier estimator, so Clip is intentionally empty. Publish the estimator's eligible
	// count after the generic scale metrics to avoid reporting zero at the activation gate.
	scaleObservations.WithLabelValues(rep.Reference.Name).Set(float64(rep.Eligible))
}

// SaturationStreak reports the current consecutive-over-threshold count, for tests and for the
// console.
func (t *Tracker) SaturationStreak(scale string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streak[scale]
}

// WarningActive reports whether the persisted warning is currently raised.
func (t *Tracker) WarningActive(scale string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streak[scale] >= t.Persistence
}
