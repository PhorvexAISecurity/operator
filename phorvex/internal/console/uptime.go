/*
 * Phorvex Console (P-UPTIME) — MEASURED service-uptime impact of the live actuators.
 *
 * The question this answers: "what do Phorvex's actuators DO to service availability?" The signal
 * is REAL, sourced ENTIRELY from the Kubernetes API (no synthesized number):
 *
 *   - quarantine DETACHES the target pod from its ReplicaSet (relabel-out + ownerRef-strip), so the
 *     pod leaves the Deployment's readyReplicas and the RS spawns a replacement => a brief dip in
 *     available/desired until the replacement is Ready, then recovery.
 *   - rotate DELETES the pod => the same dip-then-recover.
 *   - kv-reset is an in-process vLLM flush that does NOT kill the pod => NO dip at all (its defining
 *     property — and the whole point: AI defense with zero uptime cost).
 *
 * A background sampler records available/desired per defended workload every few seconds; /api/uptime
 * returns those time series overlaid with the MOMENTS Phorvex acted (from the live decision audit).
 * The chart literally shows each actuator's true cost to uptime — and that most cost nothing.
 */

package console

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	uptimeInterval = 5 * time.Second // sample cadence (catches a 10–60s replacement dip)
	uptimeCapBytes = 48 << 20        // soft cap: keep the JSONL bounded (rotate-keep-last-half)
)

// uptimeSample is one workload-availability reading at one instant — all from the K8s API.
type uptimeSample struct {
	T         string `json:"t"`
	NS        string `json:"ns"`
	Workload  string `json:"workload"`
	Kind      string `json:"kind"` // Deployment | StatefulSet
	Desired   int    `json:"desired"`
	Ready     int    `json:"ready"`
	Available int    `json:"available"`
}

// uptimePath stores the samples next to the decision audit (or a temp dir if none).
func uptimePath(cfg Config) string {
	if cfg.AuditPath != "" {
		return filepath.Join(filepath.Dir(cfg.AuditPath), "phorvex-uptime.jsonl")
	}
	return filepath.Join(os.TempDir(), "phorvex-uptime.jsonl")
}

// StartUptimeSampler launches the background availability sampler (read-only K8s list calls). Safe
// to call once at startup; it stops when ctx is cancelled.
func (s *Server) StartUptimeSampler(ctx context.Context) {
	go func() {
		t := time.NewTicker(uptimeInterval)
		defer t.Stop()
		s.sampleUptimeOnce(ctx) // one immediate sample so the file exists promptly
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sampleUptimeOnce(ctx)
			}
		}
	}()
}

// sampleUptimeOnce lists Deployments + StatefulSets on the operator's current-context cluster and
// appends one availability sample per non-system workload. One list call each — cheap.
func (s *Server) sampleUptimeOnce(ctx context.Context) {
	cs, err := clientForContext("") // current-context = the operator's cluster (EKS here)
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	var samples []uptimeSample
	if deps, e := cs.AppsV1().Deployments("").List(cctx, metav1.ListOptions{}); e == nil {
		for i := range deps.Items {
			d := &deps.Items[i]
			if systemNS[d.Namespace] {
				continue
			}
			desired := int(d.Status.Replicas)
			if d.Spec.Replicas != nil {
				desired = int(*d.Spec.Replicas)
			}
			if desired == 0 {
				continue
			}
			samples = append(samples, uptimeSample{
				T: now, NS: d.Namespace, Workload: d.Name, Kind: "Deployment",
				Desired: desired, Ready: int(d.Status.ReadyReplicas), Available: int(d.Status.AvailableReplicas),
			})
		}
	}
	if sts, e := cs.AppsV1().StatefulSets("").List(cctx, metav1.ListOptions{}); e == nil {
		for i := range sts.Items {
			d := &sts.Items[i]
			if systemNS[d.Namespace] {
				continue
			}
			desired := int(d.Status.Replicas)
			if d.Spec.Replicas != nil {
				desired = int(*d.Spec.Replicas)
			}
			if desired == 0 {
				continue
			}
			samples = append(samples, uptimeSample{
				T: now, NS: d.Namespace, Workload: d.Name, Kind: "StatefulSet",
				Desired: desired, Ready: int(d.Status.ReadyReplicas), Available: int(d.Status.ReadyReplicas),
			})
		}
	}
	if len(samples) == 0 {
		return
	}
	path := uptimePath(s.cfg)
	rotateIfLarge(path, uptimeCapBytes)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := range samples {
		_ = enc.Encode(&samples[i])
	}
}

// rotateIfLarge keeps the JSONL bounded: when it exceeds cap, rewrite it with only its last half.
func rotateIfLarge(path string, cap int64) {
	st, err := os.Stat(path)
	if err != nil || st.Size() < cap {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	buf := make([]byte, cap/2)
	n, _ := f.ReadAt(buf, st.Size()-cap/2)
	f.Close()
	if n <= 0 {
		return
	}
	// drop the first (partial) line so we start on a record boundary.
	b := buf[:n]
	if i := strings.IndexByte(string(b), '\n'); i >= 0 && i+1 < len(b) {
		b = b[i+1:]
	}
	_ = os.WriteFile(path, b, 0o644)
}

// --- /api/uptime ---

type uptimePoint struct {
	T   string  `json:"t"`
	Pct float64 `json:"pct"` // available/desired * 100
}

type uptimeMarker struct {
	T      string `json:"t"`
	Action string `json:"action"` // quarantine | rotate | kv-reset | ...
}

type uptimeWorkload struct {
	NS          string         `json:"ns"`
	Workload    string         `json:"workload"`
	Kind        string         `json:"kind"`
	Series      []uptimePoint  `json:"series"`
	Markers     []uptimeMarker `json:"markers"`
	UptimePct   float64        `json:"uptimePct"`   // mean availability over the window
	MinPct      float64        `json:"minPct"`      // worst dip in the window
	Actuations  int            `json:"actuations"`  // # of Phorvex actions on this workload in the window
	KillingActs int            `json:"killingActs"` // # of those that are pod-killing (rotate/quarantine)
}

// uptime returns, per defended workload, the MEASURED availability series + the moments Phorvex
// acted — the real "actuator impact on uptime" chart. window defaults to 1h (?window=30m|2h|…).
func (s *Server) uptime(w http.ResponseWriter, r *http.Request) {
	window := 60 * time.Minute
	if q := r.URL.Query().Get("window"); q != "" {
		if d, err := time.ParseDuration(q); err == nil && d > 0 && d <= 24*time.Hour {
			window = d
		}
	}
	cutoff := time.Now().Add(-window)

	// 1) availability samples, grouped by (ns, workload).
	type key struct{ ns, wl string }
	series := map[key]*uptimeWorkload{}
	order := []key{}
	for _, sm := range readUptimeSamples(uptimePath(s.cfg)) {
		ts, err := time.Parse(time.RFC3339Nano, sm.T)
		if err != nil || ts.Before(cutoff) {
			continue
		}
		k := key{sm.NS, sm.Workload}
		wl := series[k]
		if wl == nil {
			wl = &uptimeWorkload{NS: sm.NS, Workload: sm.Workload, Kind: sm.Kind, MinPct: 100}
			series[k] = wl
			order = append(order, k)
		}
		pct := 0.0
		if sm.Desired > 0 {
			pct = clampUnitC(float64(sm.Available)/float64(sm.Desired)) * 100
		}
		wl.Series = append(wl.Series, uptimePoint{T: sm.T, Pct: round2(pct)})
		if pct < wl.MinPct {
			wl.MinPct = round2(pct)
		}
	}

	// 2) actuation markers from the live decision audit (the moments Phorvex committed to a move).
	//    Mapped pod -> workload by name prefix (deploy/sts owns name-<hash>-<hash> / name-<ordinal>).
	for _, mk := range readActuationMarkers(s.cfg.AuditPath, cutoff) {
		// attach to the workload whose name is the longest prefix of the acted pod.
		var best *uptimeWorkload
		bestLen := 0
		for k := range series {
			if k.ns == mk.ns && strings.HasPrefix(mk.pod, k.wl) && len(k.wl) > bestLen {
				best, bestLen = series[k], len(k.wl)
			}
		}
		if best == nil {
			continue
		}
		best.Markers = append(best.Markers, uptimeMarker{T: mk.t, Action: mk.action})
		best.Actuations++
		if mk.action == "rotate" || mk.action == "quarantine" {
			best.KillingActs++
		}
	}

	// 3) summarize + keep only workloads Phorvex actually acted on (the "actuator impact" view).
	out := make([]uptimeWorkload, 0, len(order))
	for _, k := range order {
		wl := series[k]
		if wl.Actuations == 0 {
			continue // not a defended/acted workload — not part of the actuator-impact story
		}
		var sum float64
		for _, p := range wl.Series {
			sum += p.Pct
		}
		if n := len(wl.Series); n > 0 {
			wl.UptimePct = round2(sum / float64(n))
		}
		sort.Slice(wl.Markers, func(i, j int) bool { return wl.Markers[i].T < wl.Markers[j].T })
		out = append(out, *wl)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].NS != out[j].NS {
			return out[i].NS < out[j].NS
		}
		return out[i].Workload < out[j].Workload
	})
	_, stratSource, stratRun := s.cfg.comparisonMetricsPath()
	writeJSON(w, 200, map[string]any{
		"windowSeconds":    int(window.Seconds()),
		"workloads":        out,
		"strategies":       benchStrategies(s.cfg),
		"strategiesSource": stratSource, // "latest run" | "benchmark"
		"strategiesRun":    stratRun,     // run id when sourced from a live run
		"note":             "availability = readyReplicas/desired from the K8s API; markers = moments Phorvex acted (live decision audit). kv-reset does not kill the pod, so it never dents availability.",
	})
}

// uptimeStrategy is one defender strategy's MEASURED attack outcome (benchmark arm), used to show
// the third "what if there were NO defense" case alongside Phorvex and the blind R6 timer.
type uptimeStrategy struct {
	Key              string  `json:"key"`              // none | blind | phorvex
	Label            string  `json:"label"`            //
	AttackSuccess    float64 `json:"attackSuccess"`    // % of attacks that reached their objective (measured oracleAchieved)
	Disrupted        float64 `json:"disrupted"`        // mean fraction of the attack disrupted (measured disruptionVsOracle)
	DefensiveActions float64 `json:"defensiveActions"` // mean self-inflicted defensive actions per attack (measured)
	Trials           int     `json:"trials"`
}

// benchStrategies reads the MEASURED benchmark arms and returns the No-defense / Blind-R6 / Phorvex
// attack outcomes — the third "no defense, attack lands" baseline for the uptime view. The defining
// number is AttackSuccess (oracleAchieved): with no defense the attack lands every time; the blind
// timer barely helps; Phorvex cuts it most — all measured, none synthesized.
func benchStrategies(cfg Config) []uptimeStrategy {
	// DYNAMIC: the latest live 3-way run if one exists, else the static benchmark.
	path, _, _ := cfg.comparisonMetricsPath()
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	type acc struct {
		disr, acts   float64
		ach, n, actN int
	}
	arms := map[string]*acc{"d-nomtd": {}, "d-r6blindtimer": {}, "d-phorvex": {}}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		var r costParse
		if json.Unmarshal([]byte(strings.TrimSpace(sc.Text())), &r) != nil || r.Skipped || r.NegativeControl {
			continue
		}
		a := arms[r.Defender]
		if a == nil {
			continue
		}
		a.disr += r.Disruption
		a.n++
		if r.OracleAchieved {
			a.ach++
		}
		if r.Defender != "d-nomtd" {
			a.acts += r.DefensiveActions
			a.actN++
		}
	}
	mk := func(key, label, arm string) uptimeStrategy {
		a := arms[arm]
		if a == nil || a.n == 0 {
			return uptimeStrategy{Key: key, Label: label}
		}
		acts := 0.0
		if a.actN > 0 {
			acts = a.acts / float64(a.actN)
		}
		return uptimeStrategy{
			Key: key, Label: label, Trials: a.n,
			AttackSuccess:    round2(100 * float64(a.ach) / float64(a.n)),
			Disrupted:        round2(100 * a.disr / float64(a.n)),
			DefensiveActions: round2(acts),
		}
	}
	return []uptimeStrategy{
		mk("none", "No defense", "d-nomtd"),
		mk("blind", "Blind R6 timer", "d-r6blindtimer"),
		mk("phorvex", "Phorvex", "d-phorvex"),
	}
}

func readUptimeSamples(path string) []uptimeSample {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	// read only the tail (bounded) so a long run stays fast.
	if st, e := f.Stat(); e == nil {
		chunk := int64(16 << 20)
		if st.Size() > chunk {
			_, _ = f.Seek(st.Size()-chunk, 0)
		}
	}
	var out []uptimeSample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	first := true
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" {
			continue
		}
		if first { // the tail-seek may land mid-line; skip the first partial
			first = false
			if !strings.HasPrefix(ln, "{") {
				continue
			}
		}
		var sm uptimeSample
		if json.Unmarshal([]byte(ln), &sm) == nil && sm.Workload != "" {
			out = append(out, sm)
		}
	}
	return out
}

type actMarker struct {
	t, ns, pod, action string
}

// readActuationMarkers extracts the moments Phorvex committed to a non-noop move from the live
// decision audit (selected + action != noop). The jump-server operator runs the same brain on the
// same cluster as the in-cluster actuator, so its selected decisions are a faithful marker of when
// the enacting operator acts.
func readActuationMarkers(auditPath string, cutoff time.Time) []actMarker {
	if auditPath == "" {
		return nil
	}
	f, err := os.Open(auditPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	if st, e := f.Stat(); e == nil {
		chunk := int64(24 << 20)
		if st.Size() > chunk {
			_, _ = f.Seek(st.Size()-chunk, 0)
		}
	}
	var out []actMarker
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" || !strings.HasPrefix(ln, "{") {
			continue
		}
		var rec struct {
			Time      string `json:"time"`
			Kind      string `json:"kind"`
			Namespace string `json:"namespace"`
			Pod       string `json:"pod"`
			Action    string `json:"action"`
			Selected  bool   `json:"selected"`
		}
		if json.Unmarshal([]byte(ln), &rec) != nil || rec.Kind != "phorvex.decision" {
			continue
		}
		if !rec.Selected || rec.Action == "" || rec.Action == "noop" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, rec.Time)
		if err != nil || ts.Before(cutoff) {
			continue
		}
		out = append(out, actMarker{t: rec.Time, ns: rec.Namespace, pod: rec.Pod, action: rec.Action})
	}
	return out
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }
