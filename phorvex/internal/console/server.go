/*
 * Phorvex Console (P-DASHBOARD) — the HTTP API (read-only data + safe triggers).
 *
 * THREE auth scopes, enforced server-side (the lens is not a CSS toggle):
 *   - vendor   (Investor): the full moat — effectiveness, frontier, the IP internals.
 *   - operator (Operator): effectiveness, frontier, run-attack-agents — customer-safe.
 *   - owner    (Customer-Owner): ONLY the IP-walled OwnerEvent list. The owner scope is
 *     physically barred from the vendor/operator handlers and the trigger endpoints it may
 *     not invoke. The owner payload is the whitelist DTO (owner.go) — never a Record.
 */

package console

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
)

// Server is the console API.
type Server struct {
	cfg  Config
	runs *RunManager
	// [P-VCLUSTER Pass 2] optional multi-tenant write-path components (nil => demo-trust dev mode):
	oidc     *OIDCVerifier    // verified identity (replaces demo-trust as the authz boundary)
	quota    *TenantQuota     // per-tenant DoS limiter on tenant-facing surfaces
	applyfix *ApplyFixManager // the safe apply-fix write-path
}

func NewServer(cfg Config) *Server { return &Server{cfg: cfg, runs: NewRunManager(cfg)} }

// EnableVCluster wires the Pass-2 production components (OIDC identity, per-tenant quota, safe apply-fix
// write-path). Called by the deployment with a configured OIDC IdP; absent it, the console runs in
// demo-trust dev mode (single-tenant, no write-path).
func (s *Server) EnableVCluster(oidc *OIDCVerifier, quota *TenantQuota, applyfix *ApplyFixManager) {
	s.oidc, s.quota, s.applyfix = oidc, quota, applyfix
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// vendor + operator scope (full data).
	mux.HandleFunc("/api/health", s.withCORS(s.health))
	mux.HandleFunc("/api/version", s.withCORS(s.version))
	mux.HandleFunc("/api/effectiveness", s.withCORS(s.scoped("operator", s.effectiveness)))
	mux.HandleFunc("/api/frontier", s.withCORS(s.scoped("operator", s.frontier)))
	mux.HandleFunc("/api/suites", s.withCORS(s.scoped("operator", s.suites)))
	mux.HandleFunc("/api/runs/start", s.withCORS(s.scoped("operator", s.startRun)))
	mux.HandleFunc("/api/runs/scenario", s.withCORS(s.scoped("operator", s.startScenario)))
	mux.HandleFunc("/api/vllm/attack", s.withCORS(s.scoped("operator", s.vllmAttack)))
	mux.HandleFunc("/api/workload/attack", s.withCORS(s.scoped("operator", s.workloadAttack)))
	mux.HandleFunc("/api/attack-results", s.withCORS(s.scoped("operator", s.attackResults)))
	mux.HandleFunc("/api/runs/status", s.withCORS(s.scoped("operator", s.runStatus)))
	mux.HandleFunc("/api/runs/stream", s.withCORS(s.scoped("operator", s.runStream)))
	mux.HandleFunc("/api/runs/list", s.withCORS(s.scoped("operator", s.runsList)))
	mux.HandleFunc("/api/runs/stop", s.withCORS(s.scoped("operator", s.runStop)))
	mux.HandleFunc("/api/runs/evidence", s.withCORS(s.scoped("operator", s.runEvidence)))
	mux.HandleFunc("/api/targets", s.withCORS(s.scoped("operator", s.targets)))
	// LIVE WORKLOADS (P-DASHBOARD-LIVE) — enumerate the real workloads on the selected cluster.
	mux.HandleFunc("/api/workloads", s.withCORS(s.scoped("operator", s.workloads)))
	mux.HandleFunc("/api/capabilities", s.withCORS(s.scoped("operator", s.capabilities)))
	// EVIDENCE group (Wave 1) — operator/investor scope.
	mux.HandleFunc("/api/catalog", s.withCORS(s.scoped("operator", s.catalog)))
	mux.HandleFunc("/api/benchmarks", s.withCORS(s.scoped("operator", s.benchmarks)))
	mux.HandleFunc("/api/threat-matrix", s.withCORS(s.scoped("operator", s.threatMatrix)))
	mux.HandleFunc("/api/posture", s.withCORS(s.scoped("operator", s.posture)))
	mux.HandleFunc("/api/rawlog", s.withCORS(s.scoped("operator", s.rawlog)))
	// SUBSYSTEMS (Wave 3) — operator/investor scope (IP); exec EXISTING entrypoints read-only.
	mux.HandleFunc("/api/scan", s.withCORS(s.scoped("operator", s.scan)))
	mux.HandleFunc("/api/ablation", s.withCORS(s.scoped("operator", s.ablation)))
	mux.HandleFunc("/api/cluster", s.withCORS(s.scoped("operator", s.cluster)))
	mux.HandleFunc("/api/handlers", s.withCORS(s.scoped("operator", s.handlers)))
	mux.HandleFunc("/api/matrix", s.withCORS(s.scoped("operator", s.matrix)))
	mux.HandleFunc("/api/ai-surface", s.withCORS(s.scoped("operator", s.aiSurface)))
	mux.HandleFunc("/api/metrics", s.withCORS(s.scoped("operator", s.metricsScrape)))
	// LIVE group (Wave 2) — SSE, per-lens projected at the stream boundary.
	mux.HandleFunc("/api/live", s.withCORS(s.live))
	// clear the live decision audit (operator-only write; truncates the JSONL the SSE replays).
	mux.HandleFunc("/api/live/clear", s.withCORS(s.scoped("operator", s.liveClear)))
	// owner scope (IP-walled — ONLY OwnerEvents + the owner-safe rollup).
	mux.HandleFunc("/api/owner/events", s.withCORS(s.scoped("owner", s.ownerEvents)))
	mux.HandleFunc("/api/owner/tenants", s.withCORS(s.scoped("owner", s.ownerTenants)))
	mux.HandleFunc("/api/reports", s.withCORS(s.scoped("operator", s.reports)))
	mux.HandleFunc("/api/cost", s.withCORS(s.scoped("operator", s.cost)))
	mux.HandleFunc("/api/cost-timeseries", s.withCORS(s.scoped("operator", s.costTimeseries)))
	// UPTIME (P-UPTIME) — MEASURED actuator impact on service availability (K8s API + audit markers).
	mux.HandleFunc("/api/uptime", s.withCORS(s.scoped("operator", s.uptime)))
	mux.HandleFunc("/api/pricing", s.withCORS(s.scoped("operator", s.pricing)))
	// RED-TEAM CONTROL group (P-REDTEAM) — additive; reads real artifacts + execs the attacker tool.
	mux.HandleFunc("/api/redteam/curves", s.withCORS(s.scoped("operator", s.redteamCurves)))
	mux.HandleFunc("/api/redteam/campaigns", s.withCORS(s.scoped("operator", s.redteamCampaigns)))
	mux.HandleFunc("/api/redteam/live", s.withCORS(s.scoped("operator", s.redteamLive)))
	mux.HandleFunc("/api/redteam/findings", s.withCORS(s.scoped("operator", s.redteamFindings)))
	mux.HandleFunc("/api/redteam/decision", s.withCORS(s.scoped("operator", s.redteamDecision)))
	mux.HandleFunc("/api/redteam/gates", s.withCORS(s.scoped("operator", s.redteamGates)))
	mux.HandleFunc("/api/redteam/run", s.withCORS(s.scoped("operator", s.redteamRun)))
	mux.HandleFunc("/api/redteam/run-status", s.withCORS(s.scoped("operator", s.redteamRunStatus)))
	mux.HandleFunc("/api/redteam/continuous", s.withCORS(s.scoped("operator", s.redteamContinuous)))
	mux.HandleFunc("/redteam", s.withCORS(s.redteamPage))
	// [P-VCLUSTER Pass 2] the safe apply-fix write-path (submit/approve) behind verified identity + quota.
	s.registerVCluster(mux)
	// Static SPA (the built Next.js export) served at / on the SAME port as /api — one
	// process, one port, no proxy. SPA fallback to index.html for client-side routes.
	mux.HandleFunc("/", s.spa)
	return mux
}

// spa serves the built dashboard (cfg.Web). Unknown non-/api paths fall back to index.html
// (client routing). If the build is absent, it returns a clear instruction (never a blank).
func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Web == "" || !fileExists(filepath.Join(s.cfg.Web, "index.html")) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body style="font-family:system-ui;background:#0a0d12;color:#dfe6ee;padding:48px;max-width:720px;margin:auto"><h2>Phorvex Console — API is up, web build not found</h2><p>The data API is serving on this port, but the built dashboard was not found at <code>dashboard-web/out</code>.</p><p>Build it once:</p><pre style="background:#11161d;padding:14px;border-radius:8px">cd dashboard-web
npm install
npm run build</pre><p>then restart this binary. (Or pass <code>--web &lt;path-to-out&gt;</code>.)</p></body></html>`))
		return
	}
	p := filepath.Clean(r.URL.Path)
	full := filepath.Join(s.cfg.Web, p)
	if p == "/" || !fileExists(full) {
		http.ServeFile(w, r, filepath.Join(s.cfg.Web, "index.html"))
		return
	}
	http.ServeFile(w, r, full)
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.cfg.Catalog()})
}
func (s *Server) benchmarks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"groups": s.cfg.Benchmarks()})
}
func (s *Server) threatMatrix(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"techniques": s.cfg.ThreatMatrix()})
}
func (s *Server) posture(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.cfg.PostureScore())
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prom := q.Get("prometheus-url")
	if prom == "" {
		prom = os.Getenv("PHORVEX_PROM_URL") // console-default DCGM/GPU telemetry feed (live GPU physics)
	}
	writeJSON(w, 200, s.cfg.Scan(q.Get("ns"), q.Get("context"), prom))
}
func (s *Server) ablation(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.cfg.Ablation(r.URL.Query().Get("ns")))
}
func (s *Server) handlers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, HandlerRegistryView())
}
func (s *Server) matrix(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.cfg.Matrix())
}
func (s *Server) aiSurface(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.cfg.AISurfaceDecode())
}
func (s *Server) metricsScrape(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.cfg.MetricsScrape(r.URL.Query().Get("url")))
}
func (s *Server) cluster(w http.ResponseWriter, r *http.Request) {
	pols, ok := s.cfg.ClusterPolicies()
	writeJSON(w, 200, map[string]any{"policies": pols, "available": ok,
		"note": "live PhorvexPolicy CRD spec + Status (operator control-plane). Editing from the UI is [PENDING-wire · write path]."})
}

func (s *Server) rawlog(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cfg.RawLog(r.URL.Query().Get("path"))
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "log not found or outside the evidence corpus"})
		return
	}
	writeJSON(w, 200, map[string]string{"log": body})
}

// lensOf reads the request lens (header, then query for EventSource). Missing/unknown maps
// to the LEAST-privileged lens ("owner") — default-deny, never "operator".
func lensOf(r *http.Request) string {
	l := r.Header.Get("X-Phorvex-Lens")
	if l == "" {
		l = r.URL.Query().Get("lens")
	}
	switch l {
	case "investor", "operator", "owner":
		return l
	default:
		return "owner" // DEFAULT-DENY: an unknown/missing lens cannot reach vendor data
	}
}

// scoped enforces the auth scope SERVER-SIDE with DEFAULT-DENY. A vendor/operator endpoint
// admits ONLY the investor/operator lens; a missing/unknown/owner lens is rejected (403) —
// so vendor IP can never reach the owner path by an absent header. Owner endpoints are
// reachable by any valid lens but ALWAYS return the redacted ToOwnerEvent DTO (they never
// marshal a Record). (Real authn/SSO is [PENDING-P-VCLUSTER]; this is the redaction boundary.)
func (s *Server) scoped(required string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		lens := lensOf(r)
		if required == "operator" && lens != "investor" && lens != "operator" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "this data requires the investor or operator lens; the customer-owner lens is IP-walled"})
			return
		}
		h(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"ok": true, "root": s.cfg.Root,
		"hasP3Deep":    fileExists(s.harnessOutCfg("out-p3deep")),
		"hasPactuator": fileExists(s.harnessOutCfg("out-pactuator")),
		"phorvexBin":   fileExists(s.cfg.PhorvexBin),
		"harnessBin":   fileExists(s.cfg.HarnessBin),
	})
}

func (s *Server) effectiveness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"stats": s.cfg.Effectiveness()})
}

func (s *Server) cost(w http.ResponseWriter, r *http.Request) {
	// SCOPED per provider: ?context=<kubeconfig-context> (the SPA's header selection). Our target IDs
	// ARE the kubeconfig contexts, so the same value prices the cluster AND picks the provider's run.
	target := r.URL.Query().Get("context")
	if target == "" {
		target = r.URL.Query().Get("target")
	}
	if target == "" {
		for _, t := range s.runs.ClusterTargets() {
			if t.Runnable {
				target = t.ID
				break
			}
		}
	}
	// DYNAMIC + AWS-GROUNDED: both numbers come from the live cluster, NOT fabricated knobs.
	//   valueAtRisk      = the cluster's real on-demand infrastructure cost ($/yr) the attack exposes.
	//   defense overhead = the REAL cost of the running Phorvex operator (its measured CPU/memory
	//                      footprint × the on-demand price of the node it runs on). No magic %.
	pricing := s.clusterPricing(target)
	valueAtRisk := pricing.TotalPerYear
	// (a) operator footprint — what the Phorvex operator POD reserves on real AWS hardware (always-on).
	operatorCost, overheadBasis := s.phorvexOperatorCost(target)
	if overheadBasis == "" {
		overheadBasis = "no live Phorvex operator pod found on this cluster"
	}
	// (b) actuation compute — what Phorvex's RESPONSES cost: each action ≈ perActionSeconds of
	// compute (MEASURED kv-reset re-encode) at the workload node rate; × the live measured actuation
	// rate from the audit = the real annual "doing the work" cost the operator-pod figure omits.
	nodeRate := pricing.GPUPricePerHr
	if nodeRate <= 0 {
		nodeRate = pricing.TotalPerHr // no GPU → use the cluster's blended node rate
	}
	perActionCost := perActionSeconds / 3600.0 * nodeRate
	actuationCost, actuationRatePerHr := s.cfg.actuationCostPerYear(perActionCost)
	defenseCost := operatorCost + actuationCost
	scen, totWithout, totBlind, totWith, totSavings, ok := s.cfg.CostComparison(valueAtRisk, defenseCost, perActionCost, target)
	_, costSource, costRun := s.cfg.comparisonMetricsPath(target)
	writeJSON(w, 200, map[string]any{
		"available": ok, "scenarios": scen, "source": costSource, "runId": costRun,
		"totalWithout": totWithout, "totalBlind": totBlind, "totalWith": totWith, "totalSavings": totSavings,
		"pricing": pricing, "valueAtRisk": valueAtRisk,
		"defenseOverhead": defenseCost, "operatorCost": operatorCost, "actuationCost": actuationCost,
		"actuationRatePerHr": actuationRatePerHr, "perActionCost": perActionCost, "overheadBasis": overheadBasis,
		"note": "All figures are live AWS on-demand prices (" + pricing.Provider + " · " + pricing.Region + "). Value at risk = your cluster's real infrastructure cost/yr; Phorvex OFF = that infra fully exposed (attack lands); ON = residual after the measured disruption + the real cost of running Phorvex = operator footprint (" + overheadBasis + ") + actuation compute (measured action rate × per-action AWS compute). Per attack, 'defensive actions' shows how hard Phorvex worked. Nothing is a fabricated figure.",
	})
}

// CostTimePoint is one cumulative sample for the cost-over-time chart: at time T, the running
// total Phorvex has incurred vs the running total a blind R6 fixed-timer would have incurred
// (always-rotate). Savings = blind − phorvex — the controlled gap that widens while Phorvex runs.
type CostTimePoint struct {
	Time       time.Time `json:"time"`
	UnixMillis int64     `json:"unixMillis"`
	Phorvex    float64   `json:"phorvexCost"` // cumulative sum of decision Cost
	Blind      float64   `json:"blindCost"`   // cumulative sum of decision BlindCost (R6 always-rotate)
	Savings    float64   `json:"savings"`     // Blind − Phorvex (cumulative)
	Decisions  int       `json:"decisions"`   // count of decisions folded into this point
}

// costTimeseries builds the cumulative Phorvex-vs-blind-R6 cost series from the live decision
// audit. Read-only. readAudit already filters kind=="phorvex.decision". We include BOTH dry-run
// and active decisions: each record carries its MODELED cost (Cost) and the blind R6 per-cycle
// rotate cost (BlindCost) — the comparison is the decision-implied cost, valid whether or not the
// action was actuated. Downsampled to <=120 points so the chart stays sane.
func (s *Server) costTimeseries(w http.ResponseWriter, r *http.Request) {
	const maxPoints = 120
	live := s.readAudit()
	// defensive: the file is append-only/chronological, but resilient to clock skew / merged files.
	sort.Slice(live, func(i, j int) bool { return live[i].Time.Before(live[j].Time) })

	points := make([]CostTimePoint, 0, maxPoints)
	if len(live) == 0 {
		writeJSON(w, 200, map[string]any{
			"available": false, "points": points,
			"totalPhorvex": 0.0, "totalBlind": 0.0, "totalSavings": 0.0, "decisions": 0,
			"note": "No live operator decisions in the audit yet — run a live operator (or an Attack Lab scenario) to populate the cost-over-time trend.",
		})
		return
	}

	bucketSize := 1
	if len(live) > maxPoints {
		bucketSize = (len(live) + maxPoints - 1) / maxPoints // ceil division → <=120 points
	}
	var cumP, cumB float64
	bucketCount := 0
	for i, rec := range live {
		cumP += rec.Cost
		cumB += rec.BlindCost
		bucketCount++
		// emit at every bucket boundary AND at the final record (so the last point == grand total).
		if (i+1)%bucketSize == 0 || i == len(live)-1 {
			points = append(points, CostTimePoint{
				Time: rec.Time, UnixMillis: rec.Time.UnixMilli(),
				Phorvex: cumP, Blind: cumB, Savings: cumB - cumP, Decisions: bucketCount,
			})
			bucketCount = 0
		}
	}
	writeJSON(w, 200, map[string]any{
		"available": true, "points": points,
		"totalPhorvex": cumP, "totalBlind": cumB, "totalSavings": cumB - cumP, "decisions": len(live),
		"note": "Cumulative cost from the live decision audit: each decision's actual Phorvex cost vs the blind R6 fixed-timer's per-cycle rotate cost, summed over time. The blind line climbs every cycle; Phorvex pays only when net-positive.",
	})
}

func (s *Server) frontier(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"rows": s.cfg.Frontier()})
}

func (s *Server) suites(w http.ResponseWriter, r *http.Request) {
	type item struct{ Name, Desc string }
	var out []item
	for name, su := range allowedConfigs {
		out = append(out, item{name, su.Desc})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, 200, map[string]any{"suites": out})
}

func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Config         string `json:"config"`
		NativeActuator bool   `json:"nativeActuator"`
		StartedAt      string `json:"startedAt"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	id, err := s.runs.Start(body.Config, body.NativeActuator, body.StartedAt)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"id": id})
}

func (s *Server) startScenario(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scenario  string   `json:"scenario"`  // single (back-compat)
		Scenarios []string `json:"scenarios"` // BATCH: run all of these in one sweep
		WithPX    bool     `json:"withPX"`
		Compare3  bool     `json:"compare3"` // run all three strategies (no-defense/blind/Phorvex) in one live run
		Target    string   `json:"target"`
		Namespace string   `json:"namespace"`
		StartedAt string   `json:"startedAt"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	scenarios := body.Scenarios
	if len(scenarios) == 0 && body.Scenario != "" {
		scenarios = []string{body.Scenario}
	}
	id, err := s.runs.StartScenario(scenarios, body.WithPX, body.Compare3, body.Target, body.Namespace, body.StartedAt)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"id": id})
}

func (s *Server) targets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"targets": s.runs.ClusterTargets()})
}

// runsList returns the post-attack report history (every triggered run, newest first, with
// date + per-arm with/without-Phorvex metrics). Updates after each live attack finishes.
func (s *Server) runsList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"runs": s.runs.List()})
}

// runEvidence returns the full per-arm + per-trial metric ledger for one run (evidence view).
func (s *Server) runEvidence(w http.ResponseWriter, r *http.Request) {
	arms, trials, st, ok := s.runs.RunEvidence(r.URL.Query().Get("id"))
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "run not found"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"id": st.ID, "scenario": st.Config, "date": st.Date, "finished": st.Finished,
		"namespace": st.Namespace, "state": st.State, "arms": arms, "trials": trials,
		"note": "Full measured evidence for this attack. Disruption/dwell carry a 95% CI; $ figures use the swappable ROI knobs; AI in-request legs are honestly MTD-CANNOT-HELP.",
	})
}

func (s *Server) runStop(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.ID == "" {
		body.ID = r.URL.Query().Get("id")
	}
	if err := s.runs.Stop(body.ID); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "stopping", "id": body.ID})
}

func (s *Server) runStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	st, ok := s.runs.Status(id)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "run not found"})
		return
	}
	writeJSON(w, 200, st)
}

// ownerEvents returns the IP-walled OwnerEvent list. It reads a real decision audit JSONL
// (audit.Record), projects EACH through ToOwnerEvent (the whitelist), and returns ONLY that.
// It NEVER marshals a Record. If no audit trail exists yet, it returns an honest empty state.
func (s *Server) ownerEvents(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	recs := s.readAudit()
	var events []OwnerEvent
	for _, rec := range recs {
		if !rec.Selected && !rec.Actuated {
			continue // owners see ACTIONS, not every evaluated candidate
		}
		// [P4c D7/F4 cross-tenant FIX] FAIL-CLOSED: an owner sees ONLY their own tenant. An
		// empty/absent ?tenant= previously skipped the filter and returned ALL tenants; now it
		// returns NOTHING. (Tenant identity is demo-trust until P-VCLUSTER; this stops the leak.)
		if tenant == "" || rec.Tenant != tenant {
			continue
		}
		events = append(events, ToOwnerEvent(rec)) // <- the ONLY owner projection
	}
	prevented, preserved, sloKept := 0, 0, 0
	for _, e := range events {
		if e.AttackPrevented {
			prevented++
		}
		if e.WorkPreserved {
			preserved++
		}
		if e.SLOKept {
			sloKept++
		}
	}
	writeJSON(w, 200, map[string]any{
		"events": events,
		"empty":  len(events) == 0,
		"rollup": map[string]int{"actions": len(events), "attacksPrevented": prevented, "workPreserved": preserved, "sloKept": sloKept},
		"note":   "kind-scale demo data; live real-cluster streaming is [PENDING-P4a]. Tenant scoping is by request param (demo-trust) until real authn [PENDING-P-VCLUSTER].",
	})
}

// ownerTenants lists the DISTINCT tenants present in the decision audit (demo-trust: the owner
// view selects which customer's platform to show; real per-tenant authn is [PENDING-P-VCLUSTER]).
// Lets the owner lens pass a concrete ?tenant= so its panels populate (the fail-closed empty-tenant
// guard in ownerEvents otherwise returns nothing).
func (s *Server) ownerTenants(w http.ResponseWriter, r *http.Request) {
	recs := s.readAudit()
	seen := map[string]bool{}
	tenants := []string{}
	for _, rec := range recs {
		if (rec.Selected || rec.Actuated) && rec.Tenant != "" && !seen[rec.Tenant] {
			seen[rec.Tenant] = true
			tenants = append(tenants, rec.Tenant)
		}
	}
	writeJSON(w, 200, map[string]any{"tenants": tenants})
}

// reports lists the curated evidence reports, or (with ?id=) returns one's live markdown.
func (s *Server) reports(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, 200, map[string]any{"reports": s.cfg.Reports()})
		return
	}
	title, content, ok := s.cfg.ReportContent(id)
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "report not found or unreadable: " + id})
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "title": title, "content": content})
}

// readAudit loads decision Records from the configured audit JSONL (or the newest one found
// under the harness out dirs / a console-data dir). Read-only.
func (s *Server) readAudit() []audit.Record {
	path := s.cfg.AuditPath
	if path == "" {
		path = s.newestAudit()
	}
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []audit.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" {
			continue
		}
		var rec audit.Record
		if json.Unmarshal([]byte(t), &rec) == nil && rec.Kind == "phorvex.decision" {
			out = append(out, rec)
		}
	}
	return out
}

func (s *Server) newestAudit() string {
	// look for a console audit trail first, then any audit*.jsonl under the harness tree.
	candidates := []string{
		filepath.Join(s.cfg.Root, "phorvex", "bin", "console-audit.jsonl"),
		filepath.Join(s.cfg.HarnessDir, "console-audit.jsonl"),
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c
		}
	}
	return ""
}

func (s *Server) harnessOutCfg(name string) string {
	return filepath.Join(s.cfg.HarnessDir, name, "metrics.jsonl")
}

// --- helpers ---

func (s *Server) withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Phorvex-Lens")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
