/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func gaugeValue(t *testing.T, g *prometheus.GaugeVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := g.WithLabelValues(labels...).Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}

func counterValue(t *testing.T, c *prometheus.CounterVec, labels ...string) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.WithLabelValues(labels...).Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

func measuredScale(name string, value float64, n, atCeiling int) Scale {
	return Scale{
		Name: name, Value: value, Source: SourceMeasured, Percentile: 0.95,
		Clip: ClipReport{N: n, AtCeiling: atCeiling, StrictlyClipped: atCeiling},
	}
}

// The warning must not fire on a single noisy interval. A stateless publisher would raise an alarm
// that the next refresh silently clears, which trains everyone to ignore it — persistence is what
// makes the alarm mean something.
func TestSaturationWarningRequiresConsecutiveRefreshes(t *testing.T) {
	tr := NewTracker(0.10, 3)
	now := at0()
	saturated := measuredScale("t_persist", 4, 100, 25) // 25% at ceiling, over the 10% threshold

	for i := 1; i <= 2; i++ {
		tr.ObserveScale(saturated, now.Add(time.Duration(i)*time.Minute))
		if tr.WarningActive("t_persist") {
			t.Fatalf("warning fired after %d consecutive saturated refreshes, want 3", i)
		}
		if got := tr.SaturationStreak("t_persist"); got != i {
			t.Fatalf("streak = %d after %d refreshes", got, i)
		}
	}
	tr.ObserveScale(saturated, now.Add(3*time.Minute))
	if !tr.WarningActive("t_persist") {
		t.Fatal("warning did not fire on the third consecutive saturated refresh")
	}
	if got := gaugeValue(t, saturationWarning, "t_persist"); got != 1 {
		t.Fatalf("warning gauge = %v, want 1", got)
	}
}

// One clean refresh resets the streak. A warning that survives the condition clearing is a warning
// nobody can act on.
func TestOneCleanRefreshResetsTheStreak(t *testing.T) {
	tr := NewTracker(0.10, 3)
	now := at0()
	saturated := measuredScale("t_reset", 4, 100, 25)
	clean := measuredScale("t_reset", 6, 100, 2) // 2% at ceiling

	tr.ObserveScale(saturated, now)
	tr.ObserveScale(saturated, now.Add(time.Minute))
	tr.ObserveScale(clean, now.Add(2*time.Minute))

	if got := tr.SaturationStreak("t_reset"); got != 0 {
		t.Fatalf("streak = %d after a clean refresh, want 0", got)
	}
	tr.ObserveScale(saturated, now.Add(3*time.Minute))
	if tr.WarningActive("t_reset") {
		t.Fatal("warning fired one refresh after a reset; the streak did not actually clear")
	}
}

// A fallback and a measurement can be the same float. The series that distinguishes them must never
// show both at once, or a dashboard reads a fallen-back scale as measured.
func TestSourceLabelsAreMutuallyExclusiveAcrossTransitions(t *testing.T) {
	tr := NewTracker(0.10, 3)
	now := at0()

	tr.ObserveScale(measuredScale("t_src", 8, 71, 2), now)
	if m, f := gaugeValue(t, scaleSource, "t_src", "measured"), gaugeValue(t, scaleSource, "t_src", "fallback_default"); m != 1 || f != 0 {
		t.Fatalf("measured refresh: measured=%v fallback=%v, want 1 and 0", m, f)
	}

	tr.ObserveScale(Fallback("t_src", 4, "insufficient observations", now), now.Add(time.Minute))
	if m, f := gaugeValue(t, scaleSource, "t_src", "measured"), gaugeValue(t, scaleSource, "t_src", "fallback_default"); m != 0 || f != 1 {
		t.Fatalf("after falling back: measured=%v fallback=%v, want 0 and 1 — the old label stayed set", m, f)
	}
	if got := gaugeValue(t, fallbackActive, "t_src"); got != 1 {
		t.Fatalf("fallback_active = %v, want 1", got)
	}
}

// A stale reason left at 1 alongside a new one would report two simultaneous causes for a single
// fallback.
func TestOnlyTheCurrentFallbackReasonIsSet(t *testing.T) {
	tr := NewTracker(0.10, 3)
	now := at0()

	tr.ObserveScale(Fallback("t_reason", 4, "insufficient observations", now), now)
	tr.ObserveScale(Fallback("t_reason", 4, "no observations", now), now.Add(time.Minute))

	if old := gaugeValue(t, fallbackReason, "t_reason", "insufficient observations"); old != 0 {
		t.Fatalf("previous reason still set to %v; two causes would be reported at once", old)
	}
	if cur := gaugeValue(t, fallbackReason, "t_reason", "no observations"); cur != 1 {
		t.Fatalf("current reason = %v, want 1", cur)
	}
}

// Age counts from the last SUCCESSFUL refresh, so it keeps rising while the calibrator falls back.
// Resetting it on a fallback would make a permanently-unmeasurable scale look freshly calibrated.
func TestAgeKeepsRisingWhileRefreshesFallBack(t *testing.T) {
	tr := NewTracker(0.10, 3)
	now := at0()

	tr.ObserveScale(measuredScale("t_age", 8, 71, 2), now)
	if got := gaugeValue(t, scaleAge, "t_age"); got != 0 {
		t.Fatalf("age right after a measurement = %v, want 0", got)
	}

	tr.ObserveScale(Fallback("t_age", 4, "insufficient observations", now), now.Add(10*time.Minute))
	if got := gaugeValue(t, scaleAge, "t_age"); got != 600 {
		t.Fatalf("age after a fallback 10 minutes later = %v, want 600 — the fallback reset the freshness clock", got)
	}
	tr.ObserveScale(Fallback("t_age", 4, "insufficient observations", now), now.Add(30*time.Minute))
	if got := gaugeValue(t, scaleAge, "t_age"); got != 1800 {
		t.Fatalf("age = %v, want 1800", got)
	}
}

// A fallback is a failed refresh for counting purposes: the calibrator ran and could not produce a
// measurement. Counting it as success would make a permanently-unmeasurable scale look healthy.
func TestFallbackCountsAsAFailedRefreshNotASuccess(t *testing.T) {
	tr := NewTracker(0.10, 3)
	now := at0()

	before := counterValue(t, refreshTotal, "t_count", "success")
	tr.ObserveScale(Fallback("t_count", 4, "no observations", now), now)

	if got := counterValue(t, refreshTotal, "t_count", "success"); got != before {
		t.Fatalf("success counter moved from %v to %v on a fallback", before, got)
	}
	if got := counterValue(t, refreshTotal, "t_count", "failure"); got != 1 {
		t.Fatalf("failure counter = %v, want 1", got)
	}
}

func TestFallbackOnlyScaleAgeRisesAndLastSuccessStaysZero(t *testing.T) {
	tr := NewTracker(0.10, 3)
	now := at0()
	tr.ObserveScale(Fallback("t_only_fallback", 4, "no observations", now), now)
	tr.ObserveScale(Fallback("t_only_fallback", 4, "no observations", now), now.Add(7*time.Minute))

	if got := gaugeValue(t, scaleAge, "t_only_fallback"); got != 420 {
		t.Fatalf("fallback-only age = %v, want 420", got)
	}
	if got := gaugeValue(t, lastSuccessfulRefresh, "t_only_fallback"); got != 0 {
		t.Fatalf("fallback-only last success = %v, want 0", got)
	}
}

func TestInvalidCountIsPublishedForSnapshotScales(t *testing.T) {
	tr := NewTracker(0.10, 3)
	tr.ObserveScaleWithInvalid(measuredScale("t_invalid", 4, 5, 1), at0(), 3)
	if got := gaugeValue(t, scaleInvalid, "t_invalid"); got != 3 {
		t.Fatalf("invalid count = %v, want 3", got)
	}
}

// Ready-delay is estimated from observed and right-censored outcomes, not from the snapshot-style
// Clip distribution. Its Scale therefore legitimately has Clip.N == 0 even when the estimator has
// enough eligible outcomes. Publishing Clip.N made the live metric report zero at the 100-outcome
// activation gate while the raw exporter and estimator correctly reported 101.
func TestReadyDelayPublishesEligibleObservationCount(t *testing.T) {
	tr := NewTracker(0.10, 3)
	rep := ReadyDelayReport{
		Reference: Scale{
			Name: "t_ready_count", Value: 14.7, Source: SourceMeasured,
			Percentile: 0.95, ComputedAt: at0(),
		},
		Eligible: 101,
		Observed: 101,
		Invalid:  2,
	}

	tr.ObserveReadyDelay(rep, at0())

	if got := gaugeValue(t, scaleObservations, "t_ready_count"); got != 101 {
		t.Fatalf("ready-delay observations = %v, want eligible count 101", got)
	}
	if got := gaugeValue(t, scaleInvalid, "t_ready_count"); got != 2 {
		t.Fatalf("ready-delay invalid observations = %v, want 2", got)
	}
}

// Change ratio is what makes the cost of a short cadence visible.
func TestChangeRatioReportsRelativeMovement(t *testing.T) {
	tr := NewTracker(0.10, 3)
	now := at0()

	tr.ObserveScale(measuredScale("t_drift", 4, 71, 2), now)
	if got := gaugeValue(t, scaleChangeRatio, "t_drift"); got != 0 {
		t.Fatalf("first refresh reported change %v, want 0 — there was nothing to change from", got)
	}
	tr.ObserveScale(measuredScale("t_drift", 5, 71, 2), now.Add(time.Minute))
	if got := gaugeValue(t, scaleChangeRatio, "t_drift"); got != 0.25 {
		t.Fatalf("change ratio = %v, want 0.25 (4 -> 5)", got)
	}
	// Direction is not the point; magnitude is.
	tr.ObserveScale(measuredScale("t_drift", 4, 71, 2), now.Add(2*time.Minute))
	if got := gaugeValue(t, scaleChangeRatio, "t_drift"); got != 0.2 {
		t.Fatalf("change ratio = %v, want 0.2 (5 -> 4, reported as magnitude)", got)
	}
}

// The ready-delay series must carry the censoring context, because that is what explains a missing
// percentile. A dashboard showing "no estimate" with no censoring ratio beside it is unreadable.
func TestReadyDelaySeriesCarryTheCensoringContext(t *testing.T) {
	tr := NewTracker(0.10, 3)
	rep := CalibrateReadyDelay(
		observations([]time.Duration{100 * time.Second, 120 * time.Second, 140 * time.Second,
			160 * time.Second, 180 * time.Second, 200 * time.Second}, 800*time.Second, 4),
		[]float64{0.50, 0.75, 0.90, 0.95}, 0.95, at0())

	tr.ObserveReadyDelay(rep, at0())

	m := &dto.Metric{}
	if err := readyDelayCensoring.Write(m); err != nil {
		t.Fatal(err)
	}
	if got := m.GetGauge().GetValue(); got != 0.4 {
		t.Fatalf("censoring ratio = %v, want 0.4", got)
	}
	if err := readyDelayUnidentifiable.Write(m); err != nil {
		t.Fatal(err)
	}
	if got := m.GetGauge().GetValue(); got != 3 {
		t.Fatalf("unidentifiable quantiles = %v, want 3 (P75, P90, P95)", got)
	}
	if got := gaugeValue(t, fallbackActive, "ready_delay"); got != 1 {
		t.Fatalf("ready_delay fallback_active = %v, want 1 — the reference could not be measured", got)
	}
}

// Registration must be idempotent: a second call would otherwise panic on duplicate collectors.
func TestRegisterIsIdempotent(t *testing.T) {
	Register()
	Register()
}
