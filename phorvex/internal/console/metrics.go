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

// fixedTrials drops negative-control + adaptive rows, keeping the headline trials per arm.
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
		out = append(out, m)
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
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func atof(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(s), "s"), 64)
	return f
}
