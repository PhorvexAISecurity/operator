/*
 * Phorvex Console (P-DASHBOARD) — the HTTP API (data, streams and controls).
 *
 * THREE authorization roles, granted server-side per verified subject (auth_grants.go) and
 * enforced at the request boundary (auth_middleware.go) before any handler runs:
 *   - investor: read-only. Never a control.
 *   - operator: reads plus the controls, confined to its granted tenant/target scope.
 *   - owner   : ONLY the IP-walled OwnerEvent projection, for its own granted tenants.
 *
 * The role says WHAT KIND of call is allowed; the grant's tenant/target scope says WHERE. Both
 * are enforced, and one never substitutes for the other. Data falls into three classes, declared
 * per route in routes.go:
 *   - shared product metadata (catalogue, registry, version): any read grant;
 *   - tenant-attributable data (the decision audit and live cluster state): filtered to the
 *     tenants the grant covers, so an omitted or mismatched scope yields nothing, not everything;
 *   - the private evidence corpus (benchmarks, effectiveness, reports, raw logs, red-team
 *     artifacts): indivisible and attributable to no tenant, so it takes an explicit
 *     cross-tenant grant rather than being readable by any tenant-limited identity.
 *
 * The lens is not an identity and never was a credential: X-Phorvex-Lens / ?lens= may narrow a
 * caller's projection below its grant, and can never widen it. The routing contract lives in
 * routes.go — Handler() is built from that table so no route can be added outside the boundary.
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
	// auth is the identity/authorization boundary. Nil means the console has NO trust boundary,
	// and in that state every API route answers 503 rather than serving anything.
	auth *Authenticator
	// [P-VCLUSTER Pass 2] multi-tenant write-path components:
	quota    *TenantQuota     // per-tenant DoS limiter on tenant-facing surfaces
	applyfix *ApplyFixManager // the safe apply-fix write-path
}

func NewServer(cfg Config) *Server { return &Server{cfg: cfg, runs: NewRunManager(cfg)} }

// EnableAuth installs the verified-identity boundary. Without it the API is closed: there is no
// "demo trust" construction path, so a deployment cannot forget to configure authentication and
// still serve data.
func (s *Server) EnableAuth(a *Authenticator) { s.auth = a }

// EnableVCluster wires the per-tenant quota and the safe apply-fix write-path. Identity is NOT a
// parameter here any more — it belongs to EnableAuth and applies to every route, not just this
// write-path.
func (s *Server) EnableVCluster(quota *TenantQuota, applyfix *ApplyFixManager) {
	s.quota, s.applyfix = quota, applyfix
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

// metricsScrape reports per-pod risk from a Prometheus scrape. The scrape is cluster-wide, so
// the per-pod rows are filtered to the granted tenants; the aggregate metadata stays intact.
func (s *Server) metricsScrape(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	res := s.cfg.MetricsScrape(r.URL.Query().Get("url"))
	if !p.TenantWildcard() {
		pods := make([]PodRisk, 0, len(res.Pods))
		for _, pod := range res.Pods {
			if p.AllowsTenant(pod.Namespace) {
				pods = append(pods, pod)
			}
		}
		res.Pods = pods
	}
	writeJSON(w, 200, res)
}

// cluster lists the live PhorvexPolicy control-plane state. The CRD is cluster-scoped and the
// list is unfiltered at the API server, so the response is filtered HERE to the tenants and
// namespaces this identity is granted — a limited operator sees its own policies, not the whole
// customer estate. A cross-tenant grant sees everything.
func (s *Server) cluster(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	pols, ok := s.cfg.ClusterPolicies()
	visible := make([]PolicyView, 0, len(pols))
	for _, pol := range pols {
		if p.TenantWildcard() || p.AllowsTenant(pol.Namespace) || (pol.Tenant != "" && p.AllowsTenant(pol.Tenant)) {
			visible = append(visible, pol)
		}
	}
	writeJSON(w, 200, map[string]any{"policies": visible, "available": ok,
		"note": "live PhorvexPolicy CRD spec + Status (operator control-plane), filtered to this identity's granted tenants. Editing from the UI is [PENDING-wire · write path]."})
}

func (s *Server) rawlog(w http.ResponseWriter, r *http.Request) {
	body, ok := s.cfg.RawLog(r.URL.Query().Get("path"))
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "log not found or outside the evidence corpus"})
		return
	}
	writeJSON(w, 200, map[string]string{"log": body})
}

// health is the ONLY public API route: a liveness answer and nothing else. It used to return
// s.cfg.Root and the resolved harness/binary paths, which handed an unauthenticated caller the
// deployment's filesystem layout. Those moved to /api/diagnostics behind the auth boundary.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// diagnostics is the authenticated form of what /api/health used to disclose: whether the
// harness corpora and binaries this console reads are actually present.
func (s *Server) diagnostics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"ok":           true,
		"root":         s.cfg.Root,
		"hasP3Deep":    fileExists(s.harnessOutCfg("out-p3deep")),
		"hasPactuator": fileExists(s.harnessOutCfg("out-pactuator")),
		"phorvexBin":   fileExists(s.cfg.PhorvexBin),
		"harnessBin":   fileExists(s.cfg.HarnessBin),
	})
}

func (s *Server) effectiveness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"stats": s.cfg.Effectiveness()})
}

// effectiveCostTarget resolves the ONE cluster /api/cost prices and reports on, including the
// fallback to the first runnable target when no context/target is named.
//
// [M-136] The auth boundary calls this too, so the cluster it authorizes is the cluster the
// handler then uses. Authorizing an omitted parameter as "default" and afterwards selecting some
// other runnable cluster would check a different destination from the one being read.
func (s *Server) effectiveCostTarget(r *http.Request) string {
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
	return target
}

func (s *Server) cost(w http.ResponseWriter, r *http.Request) {
	// SCOPED per provider: ?context=<kubeconfig-context> (the SPA's header selection). Our target IDs
	// ARE the kubeconfig contexts, so the same value prices the cluster AND picks the provider's run.
	target := s.effectiveCostTarget(r)
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
	// [M-136] The actuation rate is measured from the TENANT decision audit, so it is counted only
	// over the tenants this identity is granted. Without the filter a tenant-limited operator's
	// "cost of running Phorvex" was really every tenant's actuation volume.
	actuationCost, actuationRatePerHr := s.cfg.actuationCostPerYear(perActionCost, tenantFilterFor(r))
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
	// [M-136] Decision records are TENANT data. Summing the whole audit handed a tenant-limited
	// operator another tenant's cost and decision count, so the series is built only from the
	// tenants this identity is granted.
	live := s.readScopedAudit(r)
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
	// The boundary already authorized this suite's REAL destination (its own config's context and
	// namespace, plus the host that runs the subprocess). Record that same target on the run, so
	// a later run-id lookup is authorized against what the run actually touches.
	dest, err := s.runs.SuiteDestination(body.Config)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	id, err := s.runs.Start(body.Config, body.NativeActuator, body.StartedAt, principalKey(principalOf(r)), dest)
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
	id, err := s.runs.StartScenario(scenarios, body.WithPX, body.Compare3, body.Target, body.Namespace, body.StartedAt, principalKey(principalOf(r)))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"id": id})
}

// targets lists the cluster targets this identity may select — filtered by the target scope in
// its grant, so the selector never advertises a cluster the caller cannot reach.
func (s *Server) targets(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	all := s.runs.ClusterTargets()
	out := make([]ClusterTarget, 0, len(all))
	for _, t := range all {
		if p.AllowsTarget(t.ID) || (t.ID == "" && p.AllowsTarget(defaultTargetID)) {
			out = append(out, t)
		}
	}
	writeJSON(w, 200, map[string]any{"targets": out})
}

// runsList returns the post-attack report history, confined to the runs this identity may see
// under the grant it holds NOW — the same rule the boundary applies to a run id, so the list
// cannot advertise a run that /api/runs/status would then refuse. A run on an out-of-scope
// cluster, or in an out-of-scope namespace, is simply absent rather than redacted.
func (s *Server) runsList(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	all := s.runs.List()
	out := make([]RunStatus, 0, len(all))
	for _, st := range all {
		if runVisibleTo(p, runOwnership{Owner: st.Owner, Target: st.ScopeTarget, Tenant: st.ScopeTenant}) {
			out = append(out, st)
		}
	}
	writeJSON(w, 200, map[string]any{"runs": out})
}

// runEvidence returns the full per-arm + per-trial metric ledger for one run (evidence view).
// The boundary has already resolved the id to a run inside this identity's scope.
func (s *Server) runEvidence(w http.ResponseWriter, r *http.Request) {
	arms, trials, st, ok := s.runs.RunEvidence(runIDOf(r))
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

// runStop stops the run the BOUNDARY resolved and authorized. It deliberately does not read the
// id again: this handler used to prefer the body id while the boundary preferred the query id, so
// a request could be authorized for one run and stop another.
func (s *Server) runStop(w http.ResponseWriter, r *http.Request) {
	id := runIDOf(r)
	if err := s.runs.Stop(id); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]string{"status": "stopping", "id": id})
}

func (s *Server) runStatus(w http.ResponseWriter, r *http.Request) {
	st, ok := s.runs.Status(runIDOf(r))
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "run not found"})
		return
	}
	writeJSON(w, 200, st)
}

// ownerEvents returns the IP-walled OwnerEvent list. It reads a real decision audit JSONL
// (audit.Record), projects EACH through ToOwnerEvent (the whitelist), and returns ONLY that.
// It NEVER marshals a Record. If no audit trail exists yet, it returns an honest empty state.
//
// The ?tenant= is now checked against the caller's GRANT by the auth boundary before this runs,
// so it selects among the tenants this identity owns rather than asserting one. The filter below
// is retained as the data-level control: an empty or unmatched tenant returns nothing.
func (s *Server) ownerEvents(w http.ResponseWriter, r *http.Request) {
	tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
	if !principalOf(r).AllowsTenant(tenant) { // defence in depth; the boundary already checked
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "tenant is outside this identity's scope"})
		return
	}
	recs := s.readAudit()
	var events []OwnerEvent
	for _, rec := range recs {
		if !rec.Selected && !rec.Actuated {
			continue // owners see ACTIONS, not every evaluated candidate
		}
		// [P4c D7/F4 cross-tenant FIX] FAIL-CLOSED: an owner sees ONLY their own tenant. An
		// empty/absent ?tenant= returns NOTHING rather than every tenant.
		if tenant == "" || rec.Tenant != tenant {
			continue
		}
		events = append(events, ToOwnerEvent(rec)) // <- the ONLY owner projection
	}
	prevented, preserved, sloKept := 0, 0, 0
	dispatched, isolationAttempts := 0, 0
	for _, e := range events {
		if e.OutcomeEvidence == "emitted-unconfirmed" {
			dispatched++
			if e.Action == "quarantine" {
				isolationAttempts++
			}
		}
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
		"rollup": map[string]int{"actions": len(events), "attacksPrevented": prevented, "workPreserved": preserved, "sloKept": sloKept, "dispatched": dispatched, "isolationAttempts": isolationAttempts},
		"note":   "Tenant scoping is enforced against this identity's server-side grant; only granted tenants are selectable.",
	})
}

// ownerTenants lists the tenants this identity may actually select. It is a SELECTOR, so it is
// filtered by the grant: a tenant the caller is not granted never appears, and its presence or
// absence in the audit is not disclosed. Previously it enumerated every tenant in the decision
// audit, which leaked the customer list to anyone who could ask.
func (s *Server) ownerTenants(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	recs := s.readAudit()
	seen := map[string]bool{}
	tenants := []string{}
	for _, rec := range recs {
		if !rec.Selected && !rec.Actuated {
			continue
		}
		if rec.Tenant == "" || seen[rec.Tenant] || !p.AllowsTenant(rec.Tenant) {
			continue
		}
		seen[rec.Tenant] = true
		tenants = append(tenants, rec.Tenant)
	}
	sort.Strings(tenants)
	// A wildcard grant sees whatever the audit holds; a scoped grant additionally gets its
	// granted-but-idle tenants listed, so a tenant with no decisions yet is still selectable.
	if !p.TenantWildcard() {
		for _, t := range p.Tenants {
			if t != wildcardScope && !seen[t] {
				seen[t] = true
				tenants = append(tenants, t)
			}
		}
		sort.Strings(tenants)
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

// tenantFilterFor returns the predicate that decides whether a tenant's records may be counted
// for this request. It is the single definition of "tenant-attributable data is grant-scoped",
// shared by every reader of the decision audit.
func tenantFilterFor(r *http.Request) func(string) bool {
	p := principalOf(r)
	if p.TenantWildcard() {
		return func(string) bool { return true }
	}
	return func(tenant string) bool { return p.AllowsTenant(tenant) }
}

// readScopedAudit is readAudit confined to the tenants this request is granted. Every aggregate
// built from the decision audit uses it; readAudit itself stays unscoped for the handlers that
// apply their own per-tenant projection (the owner surfaces).
func (s *Server) readScopedAudit(r *http.Request) []audit.Record {
	allowed := tenantFilterFor(r)
	all := s.readAudit()
	out := make([]audit.Record, 0, len(all))
	for _, rec := range all {
		if allowed(rec.Tenant) {
			out = append(out, rec)
		}
	}
	return out
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
