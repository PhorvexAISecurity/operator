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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/phorvex/phorvex/internal/audittransport"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	uptimeInterval = 5 * time.Second // sample cadence (catches a 10–60s replacement dip)
)

// uptimeSample is one workload-availability reading at one instant — all from the K8s API.
type uptimeSample struct {
	T         string `json:"t"`
	Ctx       string `json:"ctx"` // kubeconfig context this sample came from — for per-provider scoping
	NS        string `json:"ns"`
	Workload  string `json:"workload"`
	Kind      string `json:"kind"` // Deployment | StatefulSet
	Desired   int    `json:"desired"`
	Ready     int    `json:"ready"`
	Available int    `json:"available"`
}

// uptimePath stores the samples next to the decision audit (or a temp dir if none).
func uptimePath(cfg Config) string {
	return cfg.statePath("phorvex-uptime.jsonl")
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

// sampleUptimeOnce samples EVERY kubeconfig context (EKS + vCluster + …) so the dashboard can scope
// availability per provider. Each sample is tagged with the context it came from. Unreachable
// contexts are skipped (short per-context timeout) — never blocks the loop.
func (s *Server) sampleUptimeOnce(ctx context.Context) {
	contexts := kubeContexts()
	if len(contexts) == 0 {
		contexts = []string{""} // dev fallback: the single current-context
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var samples []uptimeSample
	for _, ctxName := range contexts {
		samples = append(samples, sampleContextWorkloads(ctx, ctxName, now)...)
	}
	if len(samples) == 0 {
		return
	}
	if err := s.persistUptimeSamples(samples); err != nil {
		s.recordStateError(fmt.Errorf("persist uptime sample: %w", err))
	}
}

func (s *Server) persistUptimeSamples(samples []uptimeSample) error {
	path := uptimePath(s.cfg)
	for i := range samples {
		b, err := json.Marshal(&samples[i])
		if err == nil {
			err = s.cfg.appendState(path, b)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// sampleContextWorkloads lists Deployments + StatefulSets on ONE cluster context, tagging each
// availability sample with that context. Returns nil if the context is unreachable.
func sampleContextWorkloads(ctx context.Context, ctxName, now string) []uptimeSample {
	cs, err := clientForContext(ctxName)
	if err != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
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
				T: now, Ctx: ctxName, NS: d.Namespace, Workload: d.Name, Kind: "Deployment",
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
				T: now, Ctx: ctxName, NS: d.Namespace, Workload: d.Name, Kind: "StatefulSet",
				Desired: desired, Ready: int(d.Status.ReadyReplicas), Available: int(d.Status.ReadyReplicas),
			})
		}
	}
	return samples
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
	// SCOPED per provider: ?context= selects which cluster's samples/markers/strategies to return.
	reqCtx := r.URL.Query().Get("context")

	// 1) availability samples, grouped by (ns, workload) — only the selected provider's cluster.
	type key struct{ ns, wl string }
	series := map[key]*uptimeWorkload{}
	order := []key{}
	samples, sampleErr := readUptimeSamples(uptimePath(s.cfg))
	if sampleErr != nil {
		writeJSON(w, 503, map[string]any{"available": false, "error": sampleErr.Error()})
		return
	}
	for _, sm := range samples {
		if reqCtx != "" && sm.Ctx != reqCtx {
			continue // a different provider's sample
		}
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

	// 2) actuation markers from the SELECTED provider's decision audit (moments Phorvex acted).
	//    Mapped pod -> workload by name prefix (deploy/sts owns name-<hash>-<hash> / name-<ordinal>).
	markers, markerPartial, auditErr := readActuationMarkers(r.Context(), s.cfg.auditPathForContext(reqCtx), s.cfg.AuditSource, cutoff)
	if auditErr != nil && s.cfg.AuditSource != nil {
		writeJSON(w, 503, map[string]string{"error": "remote uptime audit source unavailable: " + auditErr.Error()})
		return
	}
	for _, mk := range markers {
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

	// 3) summarize + keep only workloads Phorvex actually acted on (the "actuator impact" view),
	//    confined to the namespaces this identity is granted. [M-136] The samples file is
	//    cluster-wide, so without this filter any read grant could see every customer's
	//    availability and actuation history regardless of its tenant scope.
	p := principalOf(r)
	out := make([]uptimeWorkload, 0, len(order))
	for _, k := range order {
		wl := series[k]
		if wl.Actuations == 0 {
			continue // not a defended/acted workload — not part of the actuator-impact story
		}
		if !p.TenantWildcard() && !p.AllowsTenant(wl.NS) {
			continue
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
	_, stratSource, stratRun := s.cfg.comparisonMetricsPath(reqCtx)
	writeJSON(w, 200, map[string]any{
		"windowSeconds":    int(window.Seconds()),
		"workloads":        out,
		"markerPartial":    markerPartial,
		"strategies":       benchStrategies(s.cfg, reqCtx),
		"scenarios":        benchScenarios(s.cfg, reqCtx), // per-app three-way breakdown (attack landed / Phorvex / R6Blind)
		"strategiesSource": stratSource,                   // "latest run" | "benchmark"
		"strategiesRun":    stratRun,                      // run id when sourced from a live run
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
func benchStrategies(cfg Config, context string) []uptimeStrategy {
	// DYNAMIC + per-provider: the latest live 3-way run for this provider if one exists, else benchmark.
	path, _, _ := cfg.comparisonMetricsPath(context)
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

// uptimeScenarioArm is one defender's MEASURED outcome for ONE attacked app/scenario — the building
// block of the per-app three-way breakdown (attack landed / Phorvex / R6 blind).
type uptimeScenarioArm struct {
	Key              string  `json:"key"`              // none | phorvex | blind
	Label            string  `json:"label"`            // "Attack landed" | "Defense by Phorvex" | "Defense by R6Blind"
	AttackSuccess    float64 `json:"attackSuccess"`    // % of attacks that reached their objective (measured oracleAchieved)
	Disrupted        float64 `json:"disrupted"`        // mean % of the attack disrupted (measured disruptionVsOracle)
	Dwell            float64 `json:"dwell"`            // mean attacker dwell seconds (measured attackerDwellSeconds)
	DefensiveActions float64 `json:"defensiveActions"` // mean self-inflicted defensive actions per attack (measured)
	Trials           int     `json:"trials"`
}

// uptimeScenario is one attacked app/scenario with all three defender arms side-by-side — what the
// dashboard renders as a per-app card, MEASURED entirely from the 3-way run's metrics.jsonl.
type uptimeScenario struct {
	Scenario string              `json:"scenario"`
	Category string              `json:"category"`
	Arms     []uptimeScenarioArm `json:"arms"` // ordered: none (attack landed), phorvex, blind
}

// benchScenarios returns, FOR EACH attacked app/scenario, the MEASURED three-way outcome split into
// "attack landed" (d-nomtd), "defense by Phorvex" (d-phorvex) and "defense by R6Blind"
// (d-r6blindtimer) — the per-app breakdown the uptime view shows. Only scenarios that measured all
// three arms are returned (an honest 3-way), reading the SAME per-provider run as benchStrategies.
func benchScenarios(cfg Config, context string) []uptimeScenario {
	path, _, _ := cfg.comparisonMetricsPath(context)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	type acc struct {
		disr, dwell, acts float64
		ach, n, actN      int
		category          string
	}
	defToKey := map[string]string{"d-nomtd": "none", "d-phorvex": "phorvex", "d-r6blindtimer": "blind"}
	scen := map[string]map[string]*acc{}
	order := []string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		var r costParse
		if json.Unmarshal([]byte(strings.TrimSpace(sc.Text())), &r) != nil || r.Skipped || r.NegativeControl {
			continue
		}
		key, ok := defToKey[r.Defender]
		if !ok || r.Scenario == "" {
			continue
		}
		arms := scen[r.Scenario]
		if arms == nil {
			arms = map[string]*acc{}
			scen[r.Scenario] = arms
			order = append(order, r.Scenario)
		}
		a := arms[key]
		if a == nil {
			a = &acc{}
			arms[key] = a
		}
		a.disr += r.Disruption
		a.dwell += r.Dwell
		a.n++
		if r.OracleAchieved {
			a.ach++
		}
		if r.Category != "" {
			a.category = r.Category
		}
		if key != "none" { // no-defense takes no actions by definition
			a.acts += r.DefensiveActions
			a.actN++
		}
	}

	// labels mirror the user-facing terms; order is attack-landed → Phorvex → R6 blind.
	armSpec := []struct{ key, label string }{
		{"none", "Attack landed"},
		{"phorvex", "Defense by Phorvex"},
		{"blind", "Defense by R6Blind"},
	}
	out := make([]uptimeScenario, 0, len(order))
	for _, name := range order {
		arms := scen[name]
		if arms["none"] == nil || arms["phorvex"] == nil || arms["blind"] == nil {
			continue // not a complete 3-way for this app — skip rather than show a partial story
		}
		us := uptimeScenario{Scenario: name}
		for _, spec := range armSpec {
			a := arms[spec.key]
			arm := uptimeScenarioArm{Key: spec.key, Label: spec.label, Trials: a.n}
			if a.n > 0 {
				arm.AttackSuccess = round2(100 * float64(a.ach) / float64(a.n))
				arm.Disrupted = round2(100 * a.disr / float64(a.n))
				arm.Dwell = round2(a.dwell / float64(a.n))
				if us.Category == "" {
					us.Category = a.category
				}
			}
			if a.actN > 0 {
				arm.DefensiveActions = round2(a.acts / float64(a.actN))
			}
			us.Arms = append(us.Arms, arm)
		}
		out = append(out, us)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Scenario < out[j].Scenario
	})
	return out
}

func readUptimeSamples(path string) ([]uptimeSample, error) {
	b, err := readStateLedger(path)
	if err != nil {
		return nil, fmt.Errorf("read retained uptime: %w", err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	var out []uptimeSample
	sc := bufio.NewScanner(bytes.NewReader(b))
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
		if err := json.Unmarshal([]byte(ln), &sm); err != nil {
			return nil, fmt.Errorf("malformed retained uptime record: %w", err)
		}
		if sm.Workload == "" {
			return nil, fmt.Errorf("malformed retained uptime record: missing workload")
		}
		out = append(out, sm)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read retained uptime: %w", err)
	}
	return out, nil
}

type actMarker struct {
	t, ns, pod, action string
}

// readActuationMarkers extracts the moments Phorvex committed to a non-noop move from the live
// decision audit (selected + action != noop). The jump-server operator runs the same brain on the
// same cluster as the in-cluster actuator, so its selected decisions are a faithful marker of when
// the enacting operator acts.
func readActuationMarkers(ctx context.Context, auditPath string, source *audittransport.Client, cutoff time.Time) ([]actMarker, bool, error) {
	if auditPath == "" {
		return nil, false, nil
	}
	f, err := openDecisionSource(ctx, auditPath, source)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	partial := false
	if st, e := f.Stat(); e == nil {
		chunk := int64(24 << 20)
		if st.Size() > chunk {
			partial = true
			if _, e = f.Seek(st.Size()-chunk, 0); e != nil {
				return nil, true, e
			}
			var skip [1]byte
			for {
				if _, e = f.Read(skip[:]); e != nil || skip[0] == '\n' {
					break
				}
			}
			if e != nil {
				return nil, true, e
			}
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
	if e := sc.Err(); e != nil {
		return nil, partial, e
	}
	if remote, ok := f.(interface{ Verify() error }); ok {
		if e := remote.Verify(); e != nil {
			return nil, partial, e
		}
	}
	return out, partial, nil
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }
