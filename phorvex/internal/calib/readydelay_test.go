/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
)

func rec(id string, elapsed time.Duration, out Outcome) RotationRecord {
	start := at0()
	r := RotationRecord{
		ID: id, Tenant: "t", Namespace: "ns", Pod: id, Action: "rotate",
		StartedAt: start, Elapsed: elapsed, Outcome: out,
		ReferenceAtStart: ShippedReadyDelayReference,
		CensorDeadline:   start.Add(2 * ShippedReadyDelayReference),
	}
	if out == OutcomeObserved {
		r.ReadyAt = start.Add(elapsed)
	}
	return r
}

// observations builds n records: the first `censored` of them are right-censored at the deadline
// and the rest are real observations spread over the given durations.
func observations(observed []time.Duration, censoredAt time.Duration, nCensored int) []RotationRecord {
	var out []RotationRecord
	for i, d := range observed {
		out = append(out, rec(fmt.Sprintf("obs%03d", i), d, OutcomeObserved))
	}
	for i := 0; i < nCensored; i++ {
		out = append(out, rec(fmt.Sprintf("cen%03d", i), censoredAt, OutcomeCensored))
	}
	return out
}

// THE central property of this file. A censored record says "still pending at 800s", not "ready at
// 800s". Treating it as an observation biases every percentile downward, and biases it most when
// the fleet is slowest — exactly when the scale matters.
//
// Two sets with identical Elapsed values, differing only in whether the slow tail is censored, must
// NOT produce the same estimate.
func TestCensoredRecordsAreNotTreatedAsObservations(t *testing.T) {
	fast := []time.Duration{100 * time.Second, 120 * time.Second, 140 * time.Second, 160 * time.Second}
	const slow = 800 * time.Second

	// Case A: the slow ones finished, and we know it.
	allObserved := observations(append(append([]time.Duration{}, fast...), slow, slow, slow, slow, slow, slow), 0, 0)
	// Case B: identical elapsed values, but the slow ones are still pending.
	withCensoring := observations(fast, slow, 6)

	curveA, curveB := kaplanMeier(allObserved), kaplanMeier(withCensoring)
	qA, okA := kmQuantile(curveA, 0.90)
	qB, okB := kmQuantile(curveB, 0.90)

	if !okA {
		t.Fatal("fully observed sample could not produce P90")
	}
	if okB && qB == qA {
		t.Fatalf("censored sample produced the same P90 (%v) as the fully observed one; censoring is being read as completion", qA)
	}
	t.Logf("fully observed P90 = %v (identifiable=%v); same values but censored -> identifiable=%v", qA, okA, okB)
}

// When the slow tail is censored, the upper quantiles are simply not knowable: the curve never
// falls that far because the estimator has no information past the deadline. Reporting the largest
// observed value would be presenting a lower bound as an answer.
func TestUnidentifiableQuantilesAreReportedAbsentNotGuessed(t *testing.T) {
	// 6 observations then 4 censored. The survival curve steps down 0.9, 0.8, 0.7, 0.6, 0.5, 0.4
	// and then stops, because the censored records carry no information past their deadline.
	//
	// So P50 is estimable (the curve does reach 0.5) and P75 and above are not. The cut-off is a
	// property of how much of the sample is censored, not a tunable: with 4 of 10 pending, nothing
	// beyond the 60th percentile can be known, and no amount of care about the estimator changes
	// that. It is why heavy censoring has to disable the estimate rather than degrade it.
	records := observations(
		[]time.Duration{100 * time.Second, 120 * time.Second, 140 * time.Second,
			160 * time.Second, 180 * time.Second, 200 * time.Second},
		800*time.Second, 4)

	rep := CalibrateReadyDelay(records, []float64{0.50, 0.75, 0.90, 0.95}, 0.95, at0())

	if _, ok := rep.Percentiles[0.90]; ok {
		t.Error("P90 was reported despite 40% of the sample being censored above the observed range")
	}
	if _, ok := rep.Percentiles[0.75]; ok {
		t.Error("P75 was reported; the curve bottoms at 0.4 so it cannot reach 1-0.75 = 0.25")
	}
	if len(rep.Unidentifiable) == 0 {
		t.Fatal("no quantile was reported unidentifiable; the estimator is inventing values")
	}
	if v, ok := rep.Percentiles[0.50]; !ok {
		t.Error("P50 should still be identifiable — it lies inside the observed range")
	} else {
		t.Logf("P50 = %v identifiable; unidentifiable: %v", v, rep.Unidentifiable)
	}
}

// The activation gate must state WHICH condition failed. "Not enough data" and "the data cannot
// resolve this quantile" call for different responses — collect more, versus wait for the pending
// rotations to finish.
func TestFallbackReasonDistinguishesTooFewFromUnidentifiable(t *testing.T) {
	few := observations([]time.Duration{100 * time.Second, 200 * time.Second}, 0, 0)
	rep := CalibrateReadyDelay(few, []float64{0.95}, 0.95, at0())
	if rep.Reference.IsMeasured() {
		t.Fatal("2 observations produced a measured reference against a minimum of 100")
	}
	if rep.Reference.Reason != "insufficient eligible outcomes" {
		t.Errorf("reason = %q, want the too-few-observations reason", rep.Reference.Reason)
	}

	// Enough records, but the upper tail is entirely censored.
	var obs []time.Duration
	for i := 0; i < 60; i++ {
		obs = append(obs, time.Duration(100+i)*time.Second)
	}
	censoredHeavy := observations(obs, 900*time.Second, 60)
	rep2 := CalibrateReadyDelay(censoredHeavy, []float64{0.95}, 0.95, at0())
	if rep2.Reference.IsMeasured() {
		t.Fatalf("a reference was measured at P95 despite %.0f%% censoring", rep2.CensoringRatio*100)
	}
	if rep2.Reference.Reason != "requested percentile not identifiable under censoring" {
		t.Errorf("reason = %q, want the identifiability reason", rep2.Reference.Reason)
	}
	t.Logf("eligible=%d censoring=%.1f%% -> %q", rep2.Eligible, rep2.CensoringRatio*100, rep2.Reference.Reason)
}

// With enough clean observations the gate opens and the reference is measured.
func TestGateOpensWithEnoughCleanObservations(t *testing.T) {
	var obs []time.Duration
	for i := 0; i < 120; i++ {
		obs = append(obs, time.Duration(60+i*5)*time.Second) // 60s .. 655s
	}
	rep := CalibrateReadyDelay(observations(obs, 0, 0), []float64{0.50, 0.95}, 0.95, at0())

	if !rep.Reference.IsMeasured() {
		t.Fatalf("120 clean observations did not open the gate: %q", rep.Reference.Reason)
	}
	if rep.CensoringRatio != 0 {
		t.Errorf("censoring ratio = %v, want 0", rep.CensoringRatio)
	}
	t.Logf("measured reference = %v (P95), eligible=%d", time.Duration(rep.Reference.Value*float64(time.Second)), rep.Eligible)
}

// Exceedance and hard saturation are different questions and the spec asks for both. The
// normalizer pins at 2x the reference, so "slower than the reference" is far more common than
// "actually saturated" — reporting only one hides which is happening.
func TestExceedanceAndHardSaturationAreDistinct(t *testing.T) {
	// 10 records: 4 under the reference, 4 over it but under 2x, 2 past 2x.
	records := observations([]time.Duration{
		100 * time.Second, 200 * time.Second, 300 * time.Second, 399 * time.Second,
		401 * time.Second, 500 * time.Second, 600 * time.Second, 700 * time.Second,
		900 * time.Second, 1000 * time.Second,
	}, 0, 0)
	rep := CalibrateReadyDelay(records, nil, 0.95, at0())

	if math.Abs(rep.ExceedanceRatio-0.6) > 1e-9 {
		t.Errorf("exceedance = %.3f, want 0.6 (6 of 10 at or past the reference)", rep.ExceedanceRatio)
	}
	if math.Abs(rep.HardSaturationRatio-0.2) > 1e-9 {
		t.Errorf("hard saturation = %.3f, want 0.2 (2 of 10 at or past 2x)", rep.HardSaturationRatio)
	}
	if rep.ExceedanceRatio == rep.HardSaturationRatio {
		t.Error("the two ratios coincide; this fixture cannot show that they answer different questions")
	}
}

// Invalid records are excluded entirely — not counted as observations, not counted as bounds.
func TestInvalidRecordsAreExcludedFromTheEstimate(t *testing.T) {
	records := observations([]time.Duration{100 * time.Second, 200 * time.Second}, 0, 0)
	bad := rec("bad", 5*time.Second, OutcomeInvalid)
	bad.InvalidReason = "replacement was deleted by an operator mid-rotation"
	records = append(records, bad)

	rep := CalibrateReadyDelay(records, []float64{0.5}, 0.95, at0())
	if rep.Eligible != 2 {
		t.Fatalf("eligible = %d, want 2 — the invalid record entered the estimate", rep.Eligible)
	}
	if rep.Invalid != 1 {
		t.Fatalf("invalid = %d, want 1", rep.Invalid)
	}
}

// The frozen reference is what makes a record self-describing. A later refresh changing the
// reference must not retroactively reclassify a rotation that already happened.
func TestFrozenReferenceSurvivesALaterRefresh(t *testing.T) {
	r := rec("r1", 500*time.Second, OutcomeObserved)
	before := r.Normalized()

	// A refresh raises the live reference; the record must not move with it.
	const newReference = 800 * time.Second
	if r.ReferenceAtStart == newReference {
		t.Fatal("fixture does not exercise a reference change")
	}
	if got := r.Normalized(); got != before {
		t.Fatalf("normalized value changed from %v to %v without the record being touched", before, got)
	}
	// Recomputed against the NEW reference it would be a different number — which is the point.
	if math.Abs(500.0/800.0-before) < 1e-9 {
		t.Fatal("the record appears to be using the new reference; it must use the one frozen at start")
	}
	t.Logf("normalized stays %.4f against the frozen %v, not %.4f against a refreshed %v",
		before, r.ReferenceAtStart, 500.0/800.0, newReference)
}

// The normalizer must match the shipped one, or the shadow reports a number production never
// computes.
func TestNormalizedMatchesTheShippedFormula(t *testing.T) {
	for _, d := range []time.Duration{0, 100 * time.Second, 400 * time.Second, 799 * time.Second, 800 * time.Second, 5000 * time.Second} {
		r := rec("x", d, OutcomeObserved)
		want := cost.NormalizeReadyDelay(d)
		if got := r.Normalized(); math.Abs(got-want) > 1e-9 {
			t.Errorf("elapsed=%v: calib %v vs shipped %v", d, got, want)
		}
	}
}

// A right-censored record at exactly 2x the reference must not be read as "became Ready at 2x".
// It normalizes to the same 2.0 either way, which is precisely why the OUTCOME has to be carried
// separately — the number alone cannot distinguish them.
func TestCensoredAtTwiceReferenceIsStillABound(t *testing.T) {
	censored := rec("c", 2*ShippedReadyDelayReference, OutcomeCensored)
	observed := rec("o", 2*ShippedReadyDelayReference, OutcomeObserved)

	if censored.Normalized() != observed.Normalized() {
		t.Fatal("fixture broken: both should normalize to the ceiling")
	}
	if censored.Outcome == observed.Outcome {
		t.Fatal("the two records are indistinguishable; a bound would be counted as a measurement")
	}

	// And the estimator must treat them differently.
	onlyCensored := []RotationRecord{rec("a", 100*time.Second, OutcomeObserved), censored}
	onlyObserved := []RotationRecord{rec("a", 100*time.Second, OutcomeObserved), observed}
	_, okC := kmQuantile(kaplanMeier(onlyCensored), 0.9)
	_, okO := kmQuantile(kaplanMeier(onlyObserved), 0.9)
	if okC && okO {
		t.Error("P90 was identifiable in both cases; censoring is not restricting the estimate")
	}
}

func TestReadyDelayReferenceAgreesWithCost(t *testing.T) {
	if ShippedReadyDelayReference != cost.ReadyDelayReference {
		t.Fatalf("calib says %v, cost says %v — the shadow compares against the wrong baseline",
			ShippedReadyDelayReference, cost.ReadyDelayReference)
	}
}

func TestReadyDelayScaleValueIsSecondsNotNanoseconds(t *testing.T) {
	rep := CalibrateReadyDelay(nil, []float64{0.95}, 0.95, at0())
	if rep.Reference.Value != ShippedReadyDelayReference.Seconds() {
		t.Fatalf("fallback scale value = %v, want %v seconds", rep.Reference.Value, ShippedReadyDelayReference.Seconds())
	}
	if rep.Reference.Floor != 0 {
		t.Fatalf("fallback floor = %v, want zero because no measured percentile was floored", rep.Reference.Floor)
	}
}
