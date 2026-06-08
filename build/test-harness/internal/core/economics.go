package core

import (
	"math"
	"strconv"
	"strings"
)

// economics.go holds the PURE, unit-testable Pass-B metric math: ROI in dollars,
// the Schwartau time-based-security inequality, and attack-reusability. These
// functions are the single source of truth for both the live runner and the
// Pass-A-with-dollars post-processing renderer (internal/report/dollars.go), so
// the two passes are computed identically on the SAME extended schema.

// ROIInputs are the swappable dollar knobs (mirrors the config.TargetConfig ROI
// fields; passed in so core stays import-cycle-free from config).
type ROIInputs struct {
	GpuCount             int
	DollarsPerGpuHour    float64
	GpuOverheadPercent   float64
	AvoidedBreachValue   float64
	HorizonYears         float64
}

// HoursPerYear is the transparent constant used by the GPU-overhead $/yr math.
const HoursPerYear = 8760.0

// GpuOverheadDollarsPerYearSaved is the GPU-overhead dollars/year an MTD avoids
// vs a static-but-unprotected baseline:
//
//	GpuCount * $/GPU-hr * 8760 * overheadPercent * horizonYears
//
// It is fully recomputable from the inputs (no hidden state).
func GpuOverheadDollarsPerYearSaved(in ROIInputs) float64 {
	h := in.HorizonYears
	if h <= 0 {
		h = 1.0
	}
	return float64(in.GpuCount) * in.DollarsPerGpuHour * HoursPerYear * in.GpuOverheadPercent * h
}

// AnnualDefenseCostDollars prices the defensive churn for the horizon: each
// defensive action (rotation/quarantine/delete) is charged a small fraction of a
// GPU-hour (the recompute/reschedule cost), plus a tiny fixed operator-overhead
// floor so the denominator is never zero. defensiveActions is the per-trial
// action count; trialsPerYearScale extrapolates one trial's churn to a year via
// the horizon (kept transparent and swappable).
func AnnualDefenseCostDollars(in ROIInputs, defensiveActions int) float64 {
	h := in.HorizonYears
	if h <= 0 {
		h = 1.0
	}
	// Each action costs ~1 GPU-minute of reschedule compute (1/60 GPU-hour),
	// scaled by the configured GPU count (a rotation reschedules the whole serving
	// set). A fixed $1/yr-per-GPU operator floor keeps the denominator positive.
	perActionDollars := in.DollarsPerGpuHour * (1.0 / 60.0) * float64(maxInt(in.GpuCount, 1))
	floor := 1.0 * float64(maxInt(in.GpuCount, 1))
	return floor + perActionDollars*float64(defensiveActions)*h
}

// SecurityPerCostDollars is the dollar security-per-cost:
//
//	disruption * AvoidedBreachValue / max(AnnualDefenseCost, eps)
//
// i.e. the breach-value avoided per defense dollar spent. disruption is the
// measured DisruptionVsOracle for the arm (0..1).
func SecurityPerCostDollars(disruption, avoidedBreachValue, annualDefenseCost float64) float64 {
	const eps = 1e-9
	denom := annualDefenseCost
	if denom < eps {
		denom = eps
	}
	return disruption * avoidedBreachValue / denom
}

// ComputeROI assembles the full ROIMetric for one (scenario, arm) from the
// inputs, the measured disruption, and the measured defensive-action count.
func ComputeROI(in ROIInputs, disruption float64, defensiveActions int) ROIMetric {
	annual := AnnualDefenseCostDollars(in, defensiveActions)
	return ROIMetric{
		GpuCount:                       in.GpuCount,
		DollarsPerGpuHour:              in.DollarsPerGpuHour,
		GpuOverheadDollarsPerYearSaved: GpuOverheadDollarsPerYearSaved(in),
		AvoidedBreachValueDollars:      in.AvoidedBreachValue,
		AnnualDefenseCostDollars:       annual,
		SecurityPerCostDollars:         SecurityPerCostDollars(disruption, in.AvoidedBreachValue, annual),
	}
}

// ComputeSchwartau builds the Schwartau metric. protectionSeconds (P) is the
// rotation interval (the time the moving target stays valid for the attacker);
// detectionSeconds (D) and reactionSeconds (R) are derived from the measured
// time-to-action / oracle timing. When detectorAbsent is true, D is undefined
// (-1) and SchwartauPositive is forced false with an explanatory note.
func ComputeSchwartau(protectionSeconds, detectionSeconds, reactionSeconds float64, detectorAbsent bool) SchwartauMetric {
	m := SchwartauMetric{
		ProtectionTimeSeconds: protectionSeconds,
		ReactionTimeSeconds:   reactionSeconds,
	}
	if detectorAbsent {
		m.DetectionTimeSeconds = -1
		m.DetectionAbsent = true
		m.DetectionAbsentNote = "detector RECEIVER-ONLY/ABSENT: D undefined, Schwartau P>D+R not evaluable (MTD-CANNOT-HELP autonomously)"
		m.SchwartauPositive = false
		return m
	}
	m.DetectionTimeSeconds = detectionSeconds
	// P>D+R is meaningful only when P is finite-positive (a rotating arm). A static
	// arm (P<=0) never satisfies the inequality (the target never moves).
	if protectionSeconds > 0 {
		m.SchwartauPositive = protectionSeconds > (detectionSeconds + reactionSeconds)
	}
	return m
}

// ComputeReuse builds the attack-reusability metric. replaySuccess is the number
// of captured-exploit replays that still succeed against THIS arm out of
// replayAttempts; staticBaselineSuccess anchors the static (no-MTD) arm.
// ReuseReductionVsStatic is the fractional reduction in successful reuse vs the
// static baseline, in [0,1] (0 = no reduction / not measured against a baseline).
func ComputeReuse(replaySuccess, replayAttempts, staticBaselineSuccess int) ReuseMetric {
	m := ReuseMetric{
		ReplaySuccessCount:          replaySuccess,
		ReplayAttempts:              replayAttempts,
		StaticBaselineReplaySuccess: staticBaselineSuccess,
	}
	if staticBaselineSuccess > 0 {
		red := 1.0 - float64(replaySuccess)/float64(staticBaselineSuccess)
		if red < 0 {
			red = 0
		}
		if red > 1 {
			red = 1
		}
		m.ReuseReductionVsStatic = red
	}
	return m
}

// DeriveMTDEffect MEASURES the MTD-effect tag from outcomes (never assumes it):
//   - inRequestAchieved: did the in-request half still succeed under this arm?
//   - persistenceDisrupted: did the arm bound/destroy the persistence foothold?
//   - neutralized: did a genuine matcher action (injected trigger) remove the
//     foothold entirely (old UID gone AND marker absent)?
//
// MTD-NEUTRALIZES   when neutralized (the reactive matcher removed it).
// MTD-BOUNDS-ONLY   when persistence was reduced/bounded but the in-request
//                   attack still landed (rotation caps dwell, not the act).
// MTD-CANNOT-HELP   when neither the in-request nor the persistence outcome moved.
func DeriveMTDEffect(inRequestAchieved, persistenceDisrupted, neutralized bool) string {
	switch {
	case neutralized:
		return MTDNeutralizes
	case persistenceDisrupted:
		return MTDBoundsOnly
	default:
		return MTDCannotHelp
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// splitCSV splits a comma-joined string into trimmed, non-empty parts.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseFloat(s string) (float64, error) { return strconv.ParseFloat(strings.TrimSpace(s), 64) }
func parseInt(s string) (int, error)       { return strconv.Atoi(strings.TrimSpace(s)) }

// roundCents rounds a dollar value to whole cents (used in reporting/tests so
// floating-point noise does not leak into golden comparisons).
func roundCents(x float64) float64 {
	return math.Round(x*100) / 100
}
