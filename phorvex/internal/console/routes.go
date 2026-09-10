/*
 * Phorvex Console — the route table (M-136).
 *
 * This table IS the router. Handler() builds the mux from it and wraps every entry with the auth
 * boundary, so "a new route silently bypassed the middleware" is not a mistake that can be made:
 * a route that is not in the table is not served, and a route in the table is always guarded.
 * routes_coverage_test.go asserts both directions.
 *
 * Each entry declares its method contract, the role class that may call it, and which request
 * parameters carry a tenant/namespace, a cluster target or a run id. Several routes changed
 * method here: /api/runs/start, /api/runs/scenario and /api/runs/stop launch and stop real
 * harness runs against a cluster, so they are POST-only now rather than GET-triggerable. The
 * dashboard client already posts to all three.
 *
 * PUBLIC surface, deliberately minimal:
 *   GET /api/health  — liveness only ({"ok":true}); it no longer discloses filesystem layout.
 *   /                — the built SPA and its static assets.
 * Everything else under /api/ requires a verified identity, and an unknown /api/ path answers
 * 404 JSON instead of falling through to index.html.
 */

package console

import (
	"fmt"
	"net/http"
	"strings"
)

var (
	getOnly  = []string{http.MethodGet}
	postOnly = []string{http.MethodPost}
)

// apiRoutes returns every guarded route with its declared contract.
func (s *Server) apiRoutes() []route {
	read := func(path string, h http.HandlerFunc, spec routeSpec) route {
		spec.access = accessRead
		if len(spec.methods) == 0 {
			spec.methods = getOnly
		}
		return route{path: path, spec: spec, h: h}
	}
	control := func(path string, h http.HandlerFunc, spec routeSpec) route {
		spec.access = accessControl
		if len(spec.methods) == 0 {
			spec.methods = postOnly
		}
		return route{path: path, spec: spec, h: h}
	}

	return []route{
		// ── session ───────────────────────────────────────────────────────────────────────
		// What this identity may actually do. The SPA reads it to render only the controls the
		// grant supports; server enforcement above remains the authority.
		{path: "/api/session", spec: routeSpec{methods: getOnly, access: accessAny}, h: s.session},

		// ── version ───────────────────────────────────────────────────────────────────────
		read("/api/version", s.version, routeSpec{}),

		// ── evidence / aggregates (investor + operator) ───────────────────────────────────
		read("/api/effectiveness", s.effectiveness, routeSpec{}),
		read("/api/frontier", s.frontier, routeSpec{}),
		read("/api/suites", s.suites, routeSpec{}),
		read("/api/catalog", s.catalog, routeSpec{}),
		read("/api/benchmarks", s.benchmarks, routeSpec{}),
		read("/api/threat-matrix", s.threatMatrix, routeSpec{}),
		read("/api/posture", s.posture, routeSpec{}),
		read("/api/rawlog", s.rawlog, routeSpec{}),
		read("/api/handlers", s.handlers, routeSpec{}),
		read("/api/matrix", s.matrix, routeSpec{}),
		read("/api/ai-surface", s.aiSurface, routeSpec{}),
		read("/api/metrics", s.metricsScrape, routeSpec{fixedTarget: defaultTargetID}),
		read("/api/reports", s.reports, routeSpec{}),
		read("/api/cost-timeseries", s.costTimeseries, routeSpec{}),
		read("/api/attack-results", s.attackResults, routeSpec{}),
		read("/api/attack-monitoring", s.attackMonitoringHandler, routeSpec{}),
		read("/api/benchmark-sim", s.benchmarkSim, routeSpec{methods: postOnly}),
		read("/api/diagnostics", s.diagnostics, routeSpec{fixedTarget: defaultTargetID}),

		// ── target-scoped reads ───────────────────────────────────────────────────────────
		read("/api/targets", s.targets, routeSpec{}),
		read("/api/cost", s.cost, routeSpec{targetQ: []string{"context", "target"}}),
		read("/api/uptime", s.uptime, routeSpec{targetQ: []string{"context"}}),
		read("/api/pricing", s.pricing, routeSpec{targetQ: []string{"target"}}),
		read("/api/workloads", s.workloads, routeSpec{targetQ: []string{"target"}}),
		read("/api/capabilities", s.capabilities, routeSpec{targetQ: []string{"target"}}),
		read("/api/cluster", s.cluster, routeSpec{fixedTarget: defaultTargetID}),
		// scan and ablation exec the analyzer over a namespace. Omitting ns makes them
		// CLUSTER-WIDE, so the unscoped form needs a cross-tenant grant; naming a granted
		// namespace stays available to a limited one.
		read("/api/scan", s.scan, routeSpec{targetQ: []string{"context"}, tenantQ: []string{"ns"}, tenantOptional: true, wildcardWhenUnscoped: true}),
		read("/api/ablation", s.ablation, routeSpec{fixedTarget: defaultTargetID, tenantQ: []string{"ns"}, tenantOptional: true, wildcardWhenUnscoped: true}),
		read("/api/availability-arms", s.availabilityArms, routeSpec{fixedTarget: defaultTargetID, tenantQ: []string{"ns"}, tenantOptional: true}),
		read("/api/workload/attacks", s.workloadAttacks, routeSpec{fixedTarget: defaultTargetID, tenantQ: []string{"namespace"}}),

		// ── live decision stream + history ────────────────────────────────────────────────
		// Any granted role may connect; the projection and the tenant filter are resolved from
		// the grant inside the handler, so an omitted or mismatched ?tenant= yields nothing
		// rather than everything. SSE authenticates through the signed ALB header (browsers) or
		// a bearer header (CLI) — never a token in the query string.
		{path: "/api/live", spec: routeSpec{methods: getOnly, access: accessOwnerData, targetQ: []string{"context"}}, h: s.live},
		{path: "/api/live/history", spec: routeSpec{methods: getOnly, access: accessOwnerData, targetQ: []string{"context"}}, h: s.liveHistory},
		// live/clear TRUNCATES the whole decision-audit file for a context. That is one
		// indivisible operation over every tenant's records — there is no way to clear only
		// tenant-a's — so it takes a cross-tenant grant, not merely the operator role.
		control("/api/live/clear", s.liveClear, routeSpec{targetQ: []string{"context"}, requireTenantWildcard: true}),

		// ── owner surfaces ────────────────────────────────────────────────────────────────
		{path: "/api/owner/events", spec: routeSpec{methods: getOnly, access: accessOwnerData, tenantQ: []string{"tenant"}}, h: s.ownerEvents},
		{path: "/api/owner/tenants", spec: routeSpec{methods: getOnly, access: accessOwnerData}, h: s.ownerTenants},

		// ── controls: harness runs ────────────────────────────────────────────────────────
		// Both launch a subprocess on THIS host and then drive a cluster. The destination hooks
		// resolve what each will actually touch — the suite's own config for /start, and
		// StartScenario's substituted context and forced sandbox namespace for /scenario — so an
		// omitted or unknown target cannot slip past the grant.
		control("/api/runs/start", s.startRun, routeSpec{destination: suiteRunDestination}),
		control("/api/runs/scenario", s.startScenario, routeSpec{targetBody: []string{"target"}, destination: scenarioRunDestination}),
		control("/api/runs/stop", s.runStop, routeSpec{runQ: "id", runBody: true}),
		read("/api/runs/list", s.runsList, routeSpec{}),
		read("/api/runs/status", s.runStatus, routeSpec{runQ: "id"}),
		read("/api/runs/stream", s.runStream, routeSpec{runQ: "id"}),
		read("/api/runs/evidence", s.runEvidence, routeSpec{runQ: "id"}),

		// ── controls: live cluster writes ─────────────────────────────────────────────────
		control("/api/policy/edit", s.policyEdit, routeSpec{fixedTarget: defaultTargetID, tenantBody: true}),
		control("/api/vllm/attack", s.vllmAttack, routeSpec{fixedTarget: defaultTargetID, fixedTenant: vllmAttackNS}),
		control("/api/workload/attack", s.workloadAttack, routeSpec{fixedTarget: defaultTargetID, tenantBody: true}),
		control("/api/workload/fire-scenario", s.fireScenarioLive, routeSpec{fixedTarget: defaultTargetID, tenantBody: true}),
		control("/api/availability-arms/run", s.runArmsExperiment, routeSpec{fixedTarget: defaultTargetID, tenantBody: true}),

		// ── red team ──────────────────────────────────────────────────────────────────────
		// The red-team state is GLOBAL console state: one artifact set, one decisions file, one
		// background job. None of it is attributable to a tenant, so the writes take a
		// cross-tenant grant and run on this host's target.
		read("/api/redteam/curves", s.redteamCurves, routeSpec{}),
		read("/api/redteam/campaigns", s.redteamCampaigns, routeSpec{}),
		read("/api/redteam/live", s.redteamLive, routeSpec{}),
		read("/api/redteam/findings", s.redteamFindings, routeSpec{}),
		read("/api/redteam/gates", s.redteamGates, routeSpec{fixedTarget: defaultTargetID}),
		read("/api/redteam/run-status", s.redteamRunStatus, routeSpec{}),
		control("/api/redteam/decision", s.redteamDecision, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		control("/api/redteam/run", s.redteamRun, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		control("/api/redteam/continuous", s.redteamContinuous, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/redteam", s.redteamPage, routeSpec{}),

		// ── apply-fix write path ──────────────────────────────────────────────────────────
		// The tenant is resolved from the grant (requestTenant), never from the body, and the
		// applier acts on this console's own cluster.
		control("/api/apply-fix/submit", s.applyFixSubmit, routeSpec{fixedTarget: defaultTargetID}),
		control("/api/apply-fix/approve", s.applyFixApprove, routeSpec{fixedTarget: defaultTargetID}),
		control("/api/apply-fix/gate-preview", s.applyFixGatePreview, routeSpec{fixedTarget: defaultTargetID}),
		control("/api/apply-fix/pending", s.applyFixPending, routeSpec{methods: getOnly}),
		control("/api/apply-fix/audit", s.applyFixAudit, routeSpec{methods: getOnly}),
	}
}

// suiteRunDestination resolves what POST /api/runs/start will touch: the harness subprocess on
// THIS host, plus whatever cluster context and namespace the named suite's own config declares.
func suiteRunDestination(s *Server, _ *http.Request, body scopedBody) (runDestination, error) {
	name := body.Config
	if name == "" {
		return runDestination{}, fmt.Errorf("config is required and must name an allowed attack-agent suite")
	}
	return s.runs.SuiteDestination(name)
}

// scenarioRunDestination resolves what POST /api/runs/scenario will touch. StartScenario
// substitutes its own context for an unknown target and forces the disposable sandbox namespace,
// so those substituted values are what gets authorized.
func scenarioRunDestination(s *Server, _ *http.Request, body scopedBody) (runDestination, error) {
	return s.runs.ScenarioDestination(body.Target["target"]), nil
}

// Handler builds the mux from the route table. Every /api route is guarded; only the health
// probe and the static SPA are public.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Liveness only: no root path, no harness layout, no binary locations.
	mux.HandleFunc("/api/health", s.health)
	for _, rt := range s.apiRoutes() {
		mux.HandleFunc(rt.path, s.guard(rt))
	}
	// Static SPA at /. An unmatched /api/ path is an API 404, never SPA HTML.
	mux.HandleFunc("/", s.rootOrAPINotFound)
	return mux
}

// rootOrAPINotFound keeps the API and the SPA namespaces separate. Serving index.html for an
// unknown /api/ path makes a typo look like a 200 and hides removed or renamed endpoints.
func (s *Server) rootOrAPINotFound(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown API endpoint: " + r.URL.Path})
		return
	}
	s.spa(w, r)
}
