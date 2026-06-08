/*
 * Phorvex Console (P-DASHBOARD-3 · increment 2) — analytics endpoints, all COMPUTED from
 * real harness rows / a live /metrics scrape. Nothing hardcoded:
 *   Matrix      <- scenario×arm disruption + learnability + false-positive (real rows)
 *   AISurface   <- AI attack-surface decode (ATLAS/OWASP/split-oracle/Schwartau/reuse/mtdEffect)
 *                  + the HONEST BOUNDARY: d-phorvex-slot disruption ≡ 0 (no AI defense claimed)
 *   MetricsScrape <- live operator Prometheus /metrics (risk heatmap) OR honest [PENDING]
 */

package console

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// --- 52×N matrix + learnability + false-positive (GET /api/matrix) ----------------------

type MatrixCell struct {
	Scenario   string  `json:"scenario"`
	Arm        string  `json:"arm"`
	Disruption float64 `json:"disruption"`
	N          int     `json:"n"`
}
type LearnArm struct {
	Arm        string  `json:"arm"`
	Mean       float64 `json:"mean"`
	FirstHalf  float64 `json:"firstHalf"`
	SecondHalf float64 `json:"secondHalf"`
	N          int     `json:"n"`
}
type MatrixResult struct {
	Source      string       `json:"source"`
	Arms        []string     `json:"arms"`
	Scenarios   []string     `json:"scenarios"`
	Cells       []MatrixCell `json:"cells"`
	FPRows      int          `json:"fpRows"`
	FPViolations int         `json:"fpViolations"`
	FPRate      float64      `json:"fpRate"`
	Learnability []LearnArm  `json:"learnability"`
	LearnScenario string      `json:"learnScenario"`
	Note        string       `json:"note"`
}

func meanOf(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

// Matrix builds the scenario×arm disruption matrix from the richest real corpus, plus the
// false-positive rate (negative-control rows across the whole corpus) and the learnability
// trend on the adaptive scenario.
func (c *Config) Matrix() MatrixResult {
	rows, ok := readMetrics(c.harnessOut("out-bench"))
	src := "out-bench"
	if !ok || len(rows) == 0 {
		rows, ok = readMetrics(c.harnessOut("out-p3-full"))
		src = "out-p3-full"
	}
	res := MatrixResult{Source: src, Cells: []MatrixCell{}, Arms: []string{}, Scenarios: []string{}, Learnability: []LearnArm{},
		Note: "scenario×arm disruptionVsOracle (real harness rows); cells = mean over trials"}
	if !ok {
		return res
	}
	type key struct{ s, a string }
	agg := map[key][]float64{}
	armSet, scnSet := map[string]bool{}, map[string]bool{}
	for _, r := range rows {
		if r.Skipped || r.NegativeControl {
			continue
		}
		agg[key{r.Scenario, r.Defender}] = append(agg[key{r.Scenario, r.Defender}], r.DisruptionVsOracle)
		armSet[r.Defender] = true
		scnSet[r.Scenario] = true
	}
	for k, v := range agg {
		res.Cells = append(res.Cells, MatrixCell{Scenario: k.s, Arm: k.a, Disruption: meanOf(v), N: len(v)})
	}
	for a := range armSet {
		res.Arms = append(res.Arms, a)
	}
	for s := range scnSet {
		res.Scenarios = append(res.Scenarios, s)
	}
	sort.Strings(res.Arms)
	sort.Strings(res.Scenarios)

	// false-positive rate: negative-control (no-attack) rows that took a defensive action.
	for dir := range map[string]bool{"out-fpprobe": true, "out-bench": true, "out-p3-full": true, src: true} {
		fr, fok := readMetrics(c.harnessOut(dir))
		if !fok {
			continue
		}
		for _, r := range fr {
			if !r.NegativeControl {
				continue
			}
			res.FPRows++
			if r.FalseDefensiveActions > 0 {
				res.FPViolations++
			}
		}
	}
	if res.FPRows > 0 {
		res.FPRate = float64(res.FPViolations) / float64(res.FPRows)
	}

	// learnability: per-arm disruption on the adaptive scenario, split first-half vs second-half
	// of trials (does the arm STAY high as the attacker adapts, or degrade?).
	full, fok := readMetrics(c.harnessOut("out-p3-full"))
	if fok {
		var scen string
		for _, r := range full {
			if strings.Contains(r.Scenario, "adaptive") {
				scen = r.Scenario
				break
			}
		}
		if scen != "" {
			res.LearnScenario = scen
			byArm := map[string][]metricRow{}
			for _, r := range full {
				if r.Scenario == scen && !r.Skipped {
					byArm[r.Defender] = append(byArm[r.Defender], r)
				}
			}
			for arm, rs := range byArm {
				sort.SliceStable(rs, func(i, j int) bool { return rs[i].Trial < rs[j].Trial })
				var all, fh, sh []float64
				for i, r := range rs {
					all = append(all, r.DisruptionVsOracle)
					if i < len(rs)/2 {
						fh = append(fh, r.DisruptionVsOracle)
					} else {
						sh = append(sh, r.DisruptionVsOracle)
					}
				}
				res.Learnability = append(res.Learnability, LearnArm{Arm: arm, Mean: meanOf(all), FirstHalf: meanOf(fh), SecondHalf: meanOf(sh), N: len(rs)})
			}
			sort.SliceStable(res.Learnability, func(i, j int) bool { return res.Learnability[i].Mean > res.Learnability[j].Mean })
		}
	}
	return res
}

// --- AI attack-surface decode + HONEST BOUNDARY (GET /api/ai-surface) --------------------

type AISurface struct {
	TotalRows     int            `json:"totalRows"`
	Scenarios     int            `json:"scenarios"`
	SlotRows      int            `json:"slotRows"`       // d-phorvex-slot rows (the AI defense slot)
	SlotDisruptMax float64       `json:"slotDisruptMax"` // MUST be 0 — the stub never disrupts
	AtlasIDs      []string       `json:"atlasIds"`
	OwaspIDs      []string       `json:"owaspIds"`
	MTDEffect     map[string]int `json:"mtdEffect"`   // CANNOT-HELP / NEUTRALIZES / BOUNDS-ONLY counts
	SplitOracle   map[string]int `json:"splitOracle"` // in-request / persistence counts
	SchwartauRows int            `json:"schwartauRows"`
	ReuseRows     int            `json:"reuseRows"`
	ReplayReduced string         `json:"replayReduced"`
	Note          string         `json:"note"`
}

func (c *Config) AISurfaceDecode() AISurface {
	rows, ok := readMetrics(c.harnessOut("out-ai-bench"))
	a := AISurface{MTDEffect: map[string]int{}, SplitOracle: map[string]int{}, AtlasIDs: []string{}, OwaspIDs: []string{},
		Note: "AI ATTACK-SURFACE decode (ATLAS/OWASP, split-oracle, Schwartau timing, reuse). These describe the THREAT, never PX defense efficacy — AI defense is [SP-0-PENDING-P4]."}
	if !ok {
		return a
	}
	a.TotalRows = len(rows)
	scn := map[string]bool{}
	atl, owp := map[string]bool{}, map[string]bool{}
	var replaySucc, replayBase int
	for _, r := range rows {
		scn[r.Scenario] = true
		if r.Defender == "d-phorvex-slot" {
			a.SlotRows++
			if r.DisruptionVsOracle > a.SlotDisruptMax {
				a.SlotDisruptMax = r.DisruptionVsOracle
			}
		}
		for _, x := range r.AtlasIDs {
			atl[x] = true
		}
		for _, x := range r.OwaspIDs {
			owp[x] = true
		}
		if r.MTDEffect != "" {
			a.MTDEffect[r.MTDEffect]++
		}
		if r.SplitOracle != "" {
			a.SplitOracle[r.SplitOracle]++
		}
		if r.Schwartau != nil {
			a.SchwartauRows++
		}
		if r.Reuse != nil {
			a.ReuseRows++
			replaySucc += r.Reuse.ReplaySuccessCount
			replayBase += r.Reuse.StaticBaselineReplaySuccess
		}
	}
	a.Scenarios = len(scn)
	for x := range atl {
		a.AtlasIDs = append(a.AtlasIDs, x)
	}
	for x := range owp {
		a.OwaspIDs = append(a.OwaspIDs, x)
	}
	sort.Strings(a.AtlasIDs)
	sort.Strings(a.OwaspIDs)
	a.ReplayReduced = fmt.Sprintf("%d vs %d static-baseline (attack-surface replay; not a PX result)", replaySucc, replayBase)
	return a
}

// --- live Prometheus /metrics scrape for the risk heatmap (GET /api/metrics) -------------

type PodRisk struct {
	Namespace string  `json:"namespace"`
	Pod       string  `json:"pod"`
	Risk      float64 `json:"risk"`
	Blast     float64 `json:"blast"`
	PerDollar float64 `json:"perDollar"`
}
type MetricsResult struct {
	Available bool      `json:"available"`
	Source    string    `json:"source"`
	Pods      []PodRisk `json:"pods"`
	Note      string    `json:"note"`
}

// matches: phorvex_pod_risk_score{namespace="x",pod="y",...} 0.42
var rePromGauge = regexp.MustCompile(`^(phorvex_pod_\w+)\{([^}]*)\}\s+([\d.eE+-]+)`)
var rePromLabel = regexp.MustCompile(`(\w+)="([^"]*)"`)

func (c *Config) MetricsScrape(url string) MetricsResult {
	if url == "" {
		url = "http://localhost:18080/metrics"
	}
	res := MetricsResult{Source: url, Pods: []PodRisk{}, Note: "live operator Prometheus scrape (phorvex_pod_* gauges)"}
	cl := &http.Client{Timeout: 3 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		res.Note = "[PENDING-wire] no operator /metrics reachable at " + url + " — start a Phorvex operator with --metrics-bind-address :18080. The audit stream is the live alternative."
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	byPod := map[string]*PodRisk{}
	for _, ln := range strings.Split(string(body), "\n") {
		m := rePromGauge.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		labels := map[string]string{}
		for _, lm := range rePromLabel.FindAllStringSubmatch(m[2], -1) {
			labels[lm[1]] = lm[2]
		}
		ns, pod := labels["namespace"], labels["pod"]
		if pod == "" {
			continue
		}
		key := ns + "/" + pod
		pr := byPod[key]
		if pr == nil {
			pr = &PodRisk{Namespace: ns, Pod: pod}
			byPod[key] = pr
		}
		v := atof(m[3])
		switch m[1] {
		case "phorvex_pod_risk_score":
			pr.Risk = v
		case "phorvex_pod_blast_radius":
			pr.Blast = v
		case "phorvex_pod_per_dollar":
			pr.PerDollar = v
		}
	}
	for _, pr := range byPod {
		res.Pods = append(res.Pods, *pr)
	}
	sort.SliceStable(res.Pods, func(i, j int) bool { return res.Pods[i].Risk > res.Pods[j].Risk })
	res.Available = len(res.Pods) > 0
	if !res.Available {
		res.Note = "[PENDING-data] operator /metrics reachable but no phorvex_pod_* gauges yet (no managed pods / no decisions)."
	}
	return res
}
