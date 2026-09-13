/*
 * Phorvex Console (P-DASHBOARD) — the READ-ONLY data layer.
 *
 * Parses the harness metrics.jsonl + the [key=value] ObservedState markers into the stats
 * the dashboard shows, with 95% CIs (Wilson on proportions, t(df) on continuous). Every
 * number the console renders flows through here from a REAL on-disk file — nothing is
 * hardcoded. The console NEVER changes the brain/actuator/harness; it only reads their
 * outputs and (in runs.go) triggers their existing entrypoints.
 */

package console

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/phorvex/metricvalidity"
)

// metricRow mirrors the harness core.Metric fields the console needs (a permissive subset;
// unknown fields are ignored by encoding/json).
type metricRow struct {
	Scenario             string   `json:"scenario"`
	Defender             string   `json:"defender"`
	Trial                int      `json:"trial"`
	OracleAchieved       bool     `json:"oracleAchieved"`
	DisruptionVsOracle   float64  `json:"disruptionVsOracle"`
	DefensiveActions     int      `json:"defensiveActions"`
	FalseDefensiveActions int     `json:"falseDefensiveActions"`
	NegativeControl      bool     `json:"negativeControl"`
	Skipped              bool     `json:"skipped"`
	ObservedState        string   `json:"observedState"`
	MeanRotationInterval float64  `json:"meanRotationIntervalSeconds"`
	AttackerDwellSeconds float64  `json:"attackerDwellSeconds"`
	// TimeToActionSeconds is decoded because the shared contract corroborates a
	// claimed cost observation against it: a "measured" cost with a non-finite
	// time-to-action is a contradiction, not a measurement.
	TimeToActionSeconds float64 `json:"timeToActionSeconds"`
	// AI attack-surface decode (attack-surface, NOT PX defense efficacy):
	AtlasIDs    []string `json:"atlasIds"`
	OwaspIDs    []string `json:"owaspIds"`
	SplitOracle string   `json:"splitOracle"` // "in-request" | "persistence"
	MTDEffect   string   `json:"mtdEffect"`   // "MTD-CANNOT-HELP" | "NEUTRALIZES" | "BOUNDS-ONLY"
	Schwartau   *struct {
		ProtectionTimeSeconds float64 `json:"protectionTimeSeconds"`
		DetectionTimeSeconds  float64 `json:"detectionTimeSeconds"`
		ReactionTimeSeconds   float64 `json:"reactionTimeSeconds"`
	} `json:"schwartau"`
	Reuse *struct {
		ReplaySuccessCount         int `json:"replaySuccessCount"`
		ReplayAttempts             int `json:"replayAttempts"`
		StaticBaselineReplaySuccess int `json:"staticBaselineReplaySuccess"`
	} `json:"reuse"`
	// Validity is the SHARED harness measurement-validity contract, decoded whole.
	// It is nil for rows written before the contract existed (LEGACY/UNVERIFIED).
	//
	// This is the real type, not a local mirror of it. A hand-written mirror
	// silently omitted the fields the producer had begun checking — the baseline
	// evidence, the retained cleanup steps — and certified rows the harness
	// refuses. There is nothing left to keep in sync.
	Validity *metricvalidity.Validity `json:"validity"`
}

// verdict is THE validated interpretation, identical to the one the harness and
// every other reader apply, corroborated against this row's own numbers.
func (m metricRow) verdict() metricvalidity.Verdict {
	return metricvalidity.Evaluate(m.Validity, metricvalidity.Observations{
		Trial:                 m.Trial,
		Disruption:            m.DisruptionVsOracle,
		DefensiveActions:      m.DefensiveActions,
		FalseDefensiveActions: m.FalseDefensiveActions,
		TimeToActionSeconds:   m.TimeToActionSeconds,
		AttackerDwellSeconds:  m.AttackerDwellSeconds,
	})
}

// legacy reports a row written before the validity contract.
func (m metricRow) legacy() bool { return m.Validity == nil }

// scorable reports whether this row's comparison may be published.
func (m metricRow) scorable() bool { return m.verdict().Scorable }

// excluded reports a row that must not reach a CERTIFIED aggregate. That is
// every row the contract refuses AND every legacy row: a pre-contract row
// carries no evidence that it measured anything, so blending it into a current
// score or efficiency mean would launder unverified history into a fresh
// measurement. Legacy rows stay readable and counted (see legacy()); they are
// simply not certified.
func (m metricRow) excluded() bool { return !m.scorable() }

// costUsable reports whether DefensiveActions is an observation. `-1` is the
// harness's UNOBSERVED sentinel and must never be averaged as a cost.
func (m metricRow) costUsable() bool { return m.verdict().CostUsable }

// negControlUsable reports whether this negative-control row establishes a
// MEASURED false-move count.
func (m metricRow) negControlUsable() bool { return m.verdict().NegControlUsable }

// NegControlCensus is the complete negative-control accounting for one arm, so a
// panel can report `partial` rather than implying a clean arm from a subset.
type NegControlCensus struct {
	Total  int    `json:"total"`
	Usable int    `json:"usable"`
	State  string `json:"state"` // not-run | unobserved | partial | observed
	// MaxFalseMoves is -1 unless State == "observed".
	MaxFalseMoves int `json:"maxFalseMoves"`
}

// negControlCensus builds the census for one (scenario, defender) arm.
func negControlCensus(rows []metricRow, scenario, defender string) NegControlCensus {
	c := NegControlCensus{MaxFalseMoves: -1}
	best := -1
	for _, m := range rows {
		if m.Scenario != scenario || m.Defender != defender || !m.NegativeControl {
			continue
		}
		c.Total++
		if !m.negControlUsable() {
			continue
		}
		c.Usable++
		if m.FalseDefensiveActions > best {
			best = m.FalseDefensiveActions
		}
	}
	switch {
	case c.Total == 0:
		c.State = "not-run"
	case c.Usable == 0:
		c.State = "unobserved"
	case c.Usable < c.Total:
		c.State = "partial"
	default:
		c.State = "observed"
		c.MaxFalseMoves = best
	}
	return c
}

var markerRe = regexp.MustCompile(`\[([a-z0-9-]+)=?([^\]]*)\]`)

func markers(s string) map[string]string {
	m := map[string]string{}
	for _, x := range markerRe.FindAllStringSubmatch(s, -1) {
		m[x[1]] = x[2]
	}
	return m
}

// readMetrics streams a metrics.jsonl file (read-only). Missing file => (nil, false).
func readMetrics(path string) ([]metricRow, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var out []metricRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" {
			continue
		}
		var m metricRow
		if json.Unmarshal([]byte(t), &m) == nil {
			out = append(out, m)
		}
	}
	return out, true
}

// fixedTrials drops negative-control + adaptive rows, keeping the headline
// trials per arm, and drops every row that is not a CERTIFIED measurement. A
// refused row is an infrastructure failure, an unanchored comparison or an
// unresolved cleanup; a legacy row predates the contract entirely. Publishing
// either as a current score would present something that was never measured as
// a defensive result.
func fixedTrials(rows []metricRow, scenario, defender string) []metricRow {
	maxFixed := -1
	for _, m := range rows {
		if m.Scenario == scenario && m.Defender == defender && m.NegativeControl && m.Trial > maxFixed {
			maxFixed = m.Trial
		}
	}
	var out []metricRow
	for _, m := range rows {
		if m.Scenario != scenario || m.Defender != defender || m.Skipped || m.NegativeControl {
			continue
		}
		if maxFixed >= 0 && m.Trial > maxFixed {
			continue // adaptive row
		}
		if m.excluded() {
			continue // refused by the validity contract
		}
		out = append(out, m)
	}
	return out
}

// costObservedTrials narrows a trial set to the rows whose defensive-action
// count is an OBSERVATION, so an unobserved cost never enters a cost mean or a
// favorable efficiency ratio.
func costObservedTrials(rows []metricRow) []metricRow {
	var out []metricRow
	for _, m := range rows {
		if m.costUsable() {
			out = append(out, m)
		}
	}
	return out
}

// --- statistics ---

// ci is a measured value with a 95% interval + provenance.
type ci struct {
	Mean float64 `json:"mean"`
	Lo   float64 `json:"lo"`
	Hi   float64 `json:"hi"`
	N    int     `json:"n"`
}

// wilson is the 95% Wilson score interval for a Bernoulli sample (proportions/rates).
func wilson(successes, n int) ci {
	if n == 0 {
		return ci{}
	}
	p := float64(successes) / float64(n)
	z := 1.96
	den := 1 + z*z/float64(n)
	center := (p + z*z/(2*float64(n))) / den
	half := z * math.Sqrt(p*(1-p)/float64(n)+z*z/(4*float64(n*n))) / den
	return ci{Mean: p, Lo: clamp01(center - half), Hi: clamp01(center + half), N: n}
}

// tci is the 95% interval on a continuous mean (t(df=19)=2.093 for n>=20; widened for small n).
func tci(xs []float64) ci {
	n := len(xs)
	if n == 0 {
		return ci{}
	}
	m := meanf(xs)
	if n < 2 {
		return ci{Mean: m, Lo: m, Hi: m, N: n}
	}
	var ss float64
	for _, x := range xs {
		ss += (x - m) * (x - m)
	}
	sd := math.Sqrt(ss / float64(n-1))
	t := 2.093
	if n < 20 {
		t = 2.262 // ~df=9; conservative for small samples
	}
	h := t * sd / math.Sqrt(float64(n))
	return ci{Mean: m, Lo: m - h, Hi: m + h, N: n}
}

func meanf(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func clamp01(x float64) float64 {
	if math.IsNaN(x) { // NaN compares false against everything and would pass straight through
		return 0
	}
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// atof parses a harness/report number. ParseFloat accepts "NaN"/"Inf" WITHOUT error, and this
// helper already discards the error, so an unusable field would silently become NaN and
// propagate into every downstream mean/ratio. Unparseable or non-finite reads as 0.
func atof(s string) float64 {
	f, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(s), "s"), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
}
