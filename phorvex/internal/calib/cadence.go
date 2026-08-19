/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"sort"
	"time"
)

// cadence.go answers how often the scales should be recalculated (PHVX-74 §5).
//
// The question looks like tuning and is not. A scale fitted to a snapshot and then FROZEN until
// the next refresh is, for the whole of that interval, a claim about a cluster that has since
// moved. The cadence decides how wrong that claim is allowed to get.
//
// WALK-FORWARD, and why the spec insists on it. The tempting evaluation is to fit a scale on all
// the data and check that it fits — which it will, because it was fitted to it. That measures
// nothing: it cannot distinguish a scale that generalises from one that memorised the sample it
// came from. So every scale here is fitted on observations STRICTLY BEFORE a boundary and scored
// on observations STRICTLY AFTER it. The two sets never intersect, and cadenceWindows makes that
// a structural property rather than a discipline.

// CadenceSample is one observation of the fleet at a point in time.
type CadenceSample struct {
	At     time.Time
	Nodes  []NodeObservation
	Assets []AssetObservation
}

// CadenceRow is one candidate interval's held-out result.
type CadenceRow struct {
	Interval time.Duration

	// Windows is how many fit/evaluate pairs the history supported at this interval. A long
	// interval yields fewer windows from the same history, which is itself information: an
	// interval that can only be evaluated once has not really been evaluated.
	Windows int
	// Skipped counts boundaries where one side was empty, so nothing could be tested.
	Skipped int

	// MaxAtCeiling and MeanAtCeiling are saturation measured on HELD-OUT data — the fraction of
	// assets pinned at a cap that was fitted before they were observed.
	MaxAtCeiling  float64
	MeanAtCeiling float64

	// MaxScaleDrift is the largest relative change between the scale fitted at consecutive
	// refreshes: |new-old|/old. It is the churn side of the trade-off. A cadence that keeps
	// saturation low by re-fitting constantly is moving the ground under the optimizer.
	MaxScaleDrift float64

	// ClearsThreshold is true when MaxAtCeiling stayed within the saturation threshold across
	// every evaluated window — not merely on average, because an average hides the interval in
	// which the alarm actually fired.
	ClearsThreshold bool
}

// cadenceWindows splits a time-ordered history into (fit, evaluate) pairs at the given interval.
//
// The two slices returned per boundary are disjoint by construction: fit is everything strictly
// before the boundary, evaluate is everything in [boundary, boundary+interval). There is no
// argument to get wrong and no flag that could let them overlap.
func cadenceWindows(samples []CadenceSample, interval time.Duration) (fits, evals [][]CadenceSample) {
	if len(samples) == 0 || interval <= 0 {
		return nil, nil
	}
	s := append([]CadenceSample(nil), samples...)
	sort.Slice(s, func(i, j int) bool { return s[i].At.Before(s[j].At) })

	start, end := s[0].At, s[len(s)-1].At
	for b := start.Add(interval); !b.After(end); b = b.Add(interval) {
		var fit, eval []CadenceSample
		for _, x := range s {
			switch {
			case x.At.Before(b):
				fit = append(fit, x)
			case x.At.Before(b.Add(interval)):
				eval = append(eval, x)
			}
		}
		fits = append(fits, fit)
		evals = append(evals, eval)
	}
	return fits, evals
}

// EvaluateCadence walk-forward tests each candidate interval and returns one row per interval, in
// the order given.
//
// At every boundary the scales are fitted on the history before it, frozen, and then scored on the
// samples that arrive during the following interval. Nothing observed in the evaluation window
// influences the scale it is scored against.
func EvaluateCadence(
	samples []CadenceSample,
	intervals []time.Duration,
	coResidencyP, dispersionP float64,
	minObservations int,
	threshold float64,
) []CadenceRow {
	out := make([]CadenceRow, 0, len(intervals))

	for _, iv := range intervals {
		row := CadenceRow{Interval: iv, ClearsThreshold: true}
		fits, evals := cadenceWindows(samples, iv)

		sum := 0.0
		prevScale := 0.0
		for i := range fits {
			fit, eval := fits[i], evals[i]
			if len(fit) == 0 || len(eval) == 0 {
				row.Skipped++
				continue
			}
			// Fit on the past only. The most recent sample before the boundary stands for the
			// state the refresh would have seen.
			last := fit[len(fit)-1]
			j := CalibrateJoint(last.Nodes, last.Assets, coResidencyP, dispersionP, minObservations, last.At)

			if prevScale > 0 {
				drift := (j.Dispersion.Value - prevScale) / prevScale
				if drift < 0 {
					drift = -drift
				}
				if drift > row.MaxScaleDrift {
					row.MaxScaleDrift = drift
				}
			}
			prevScale = j.Dispersion.Value

			// Score on the future only: apply the FROZEN scales to assets observed after the fit.
			pinned, total := 0, 0
			for _, e := range eval {
				for _, a := range e.Assets {
					total++
					if a.Uncapped(j.CoResidency.Value) >= j.Dispersion.Value-1e-9 {
						pinned++
					}
				}
			}
			if total == 0 {
				row.Skipped++
				continue
			}
			ratio := float64(pinned) / float64(total)
			if ratio > row.MaxAtCeiling {
				row.MaxAtCeiling = ratio
			}
			sum += ratio
			row.Windows++
		}
		if row.Windows > 0 {
			row.MeanAtCeiling = sum / float64(row.Windows)
			row.ClearsThreshold = row.MaxAtCeiling <= threshold
		} else {
			// No window could be evaluated. That is not a pass: an interval the history cannot
			// test has no evidence either way, and reporting it as clearing would be the same
			// mistake as reporting an unmeasured optimality ratio as 1.0 (PHVX-23).
			row.ClearsThreshold = false
		}
		out = append(out, row)
	}
	return out
}

// SelectCadence applies the spec's rule: the LARGEST interval that stays valid between refreshes.
//
// Largest rather than safest, because a shorter interval is not free — it re-fits the scales more
// often, and every re-fit moves the ground the optimizer is ranking on. The rule trades staleness
// against churn and the spec resolves it toward fewer, larger steps.
//
// Returns the chosen row and whether any candidate qualified.
func SelectCadence(rows []CadenceRow) (CadenceRow, bool) {
	var best CadenceRow
	found := false
	for _, r := range rows {
		if !r.ClearsThreshold || r.Windows == 0 {
			continue
		}
		if !found || r.Interval > best.Interval {
			best, found = r, true
		}
	}
	return best, found
}
