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
	"net/url"
	"strings"

	"github.com/phorvex/phorvex/internal/cataloguev1"
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
		read("/api/version", s.version, routeSpec{fixedTarget: defaultTargetID}),

		// ── shared product metadata (any read grant) ──────────────────────────────────────
		// Catalogue and registry facts that describe the PRODUCT, not a customer: no tenant is
		// attributable to them and nothing private is disclosed by sharing them.
		read("/api/suites", s.suites, routeSpec{}),
		read("/api/catalog", s.catalog, routeSpec{}),
		read("/api/threat-matrix", s.threatMatrix, routeSpec{}),
		read("/api/handlers", s.handlers, routeSpec{}),

		// ── private evidence corpus (indivisible; needs an explicit cross-tenant grant) ────
		// The benchmark/effectiveness corpus, the retained evidence reports and their raw logs,
		// and the red-team artifacts are the vendor-side moat. They are not attributable to any
		// tenant, so they cannot be filtered down to one: an identity limited to some tenants
		// gets none of it, and a vendor-side identity holds the wildcard that does. This is the
		// "indivisible unattributable private evidence" case, not shared catalogue metadata.
		read("/api/effectiveness", s.effectiveness, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/frontier", s.frontier, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/benchmarks", s.benchmarks, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/posture", s.posture, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/rawlog", s.rawlog, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/matrix", s.matrix, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/ai-surface", s.aiSurface, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/reports", s.reports, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/benchmark-sim", s.benchmarkSim, routeSpec{methods: postOnly, fixedTarget: defaultTargetID, requireTenantWildcard: true}),

		// ── tenant-attributable data (filtered to the granted tenants in the handler) ──────
		read("/api/metrics", s.metricsScrape, routeSpec{fixedTarget: defaultTargetID}),
		read("/api/cost-timeseries", s.costTimeseries, routeSpec{fixedTarget: defaultTargetID}),
		// Math Lab: read-only relay of recorded decision snapshots, one granted namespace at a
		// time. The bytes are immutable and content-addressed; the console stores nothing.
		read("/api/math-lab/snapshots", s.mathLabSnapshots, routeSpec{tenantQ: []string{"namespace"}, fixedTarget: defaultTargetID}),
		read("/api/math-lab/snapshot", s.mathLabSnapshot, routeSpec{tenantQ: []string{"namespace"}, fixedTarget: defaultTargetID}),
		read("/api/attack-results", s.attackResults, routeSpec{fixedTarget: defaultTargetID}),
		read("/api/attack-monitoring", s.attackMonitoringHandler, routeSpec{fixedTarget: defaultTargetID}),
		read("/api/diagnostics", s.diagnostics, routeSpec{fixedTarget: defaultTargetID}),

		// ── target-scoped reads ───────────────────────────────────────────────────────────
		read("/api/targets", s.targets, routeSpec{}),
		// /api/cost falls back to the first runnable cluster when no context/target is named, so
		// the destination hook authorizes THAT cluster rather than the "default" sentinel an
		// omitted parameter would otherwise stand for.
		read("/api/cost", s.cost, routeSpec{destination: costDestination}),
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
		{path: "/api/owner/events", spec: routeSpec{methods: getOnly, access: accessOwnerData, fixedTarget: defaultTargetID, tenantQ: []string{"tenant"}}, h: s.ownerEvents},
		{path: "/api/owner/tenants", spec: routeSpec{methods: getOnly, access: accessOwnerData, fixedTarget: defaultTargetID}, h: s.ownerTenants},

		// ── controls: harness runs ────────────────────────────────────────────────────────
		// Both launch a subprocess on THIS host and then drive a cluster. The destination hooks
		// resolve what each will actually touch — the suite's own config for /start, and
		// StartScenario's substituted context and forced sandbox namespace for /scenario — so an
		// omitted or unknown target cannot slip past the grant.
		control("/api/runs/start", s.startRun, routeSpec{destination: suiteRunDestination}),
		control("/api/runs/scenario", s.startScenario, routeSpec{targetBody: []string{"target"}, destination: scenarioRunDestination}),
		control("/api/runs/functional", s.startFunctional, routeSpec{destination: functionalRunDestination}),
		control("/api/runs/functional/admission", s.functionalAdmission, routeSpec{methods: getOnly, destination: functionalAdmissionDestination}),
		control("/api/runs/stop", s.runStop, routeSpec{runQ: "id", runBody: true}),
		control("/api/runs/nats-reconcile", s.runNATSReconcile, routeSpec{runQ: "id", runBody: true}),
		control("/api/runs/voice-cleanup-reconcile", s.runVoiceCleanupReconcile, routeSpec{runQ: "id", runBody: true}),
		read("/api/runs/list", s.runsList, routeSpec{}),
		read("/api/runs/status", s.runStatus, routeSpec{runQ: "id"}),
		read("/api/runs/stream", s.runStream, routeSpec{runQ: "id"}),
		read("/api/runs/evidence", s.runEvidence, routeSpec{runQ: "id"}),

		// ── controls: live cluster writes ─────────────────────────────────────────────────
		control("/api/policy/edit", s.policyEdit, routeSpec{fixedTarget: defaultTargetID, tenantBody: true}),
		// Runtime optimizer parameters (read-only): the economic knobs of every visible app
		// policy, verified against the brain's own decision records, and their change log.
		read("/api/optimizer/runtime", s.optimizerRuntime, routeSpec{fixedTarget: defaultTargetID}),
		read("/api/optimizer/parameter-log", s.optimizerParameterLog, routeSpec{fixedTarget: defaultTargetID}),
		control("/api/vllm/attack", s.vllmAttack, routeSpec{fixedTarget: defaultTargetID, fixedTenant: vllmAttackNS}),
		control("/api/voice/live/fire", s.voiceMemoryLiveFire, routeSpec{fixedTarget: defaultTargetID, fixedTenant: "voice"}),
		control("/api/voice/agency/live/fire", s.voiceAgencyLiveFire, routeSpec{fixedTarget: defaultTargetID, fixedTenant: "voice"}),
		control(voiceOutputRoute, s.voiceOutputLiveFire, routeSpec{fixedTarget: defaultTargetID, fixedTenant: "voice"}),
		control(voiceAdmissionRoute, s.voiceAdmissionLiveFire, routeSpec{fixedTarget: defaultTargetID, fixedTenant: "voice"}),
		control("/api/voice/mcp/live/fire", s.voiceMCPLiveFire, routeSpec{fixedTarget: defaultTargetID, fixedTenant: "voice"}),
		control("/api/litellm/live/fire", s.liteLLMLiveFire, routeSpec{fixedTarget: defaultTargetID, fixedTenant: "litellm"}),
		control("/api/litellm/output/fire", s.liteLLMOutputFire, routeSpec{fixedTarget: defaultTargetID, fixedTenant: "litellm"}),
		control(crmLiveRoute, s.crmRefundLiveFire, routeSpec{fixedTarget: defaultTargetID, fixedTenant: "crm"}),
		control("/api/workload/attack", s.workloadAttack, routeSpec{fixedTarget: defaultTargetID, tenantBody: true}),
		control("/api/workload/fire-scenario", s.fireScenarioLive, routeSpec{fixedTarget: defaultTargetID, tenantBody: true}),
		control("/api/availability-arms/run", s.runArmsExperiment, routeSpec{fixedTarget: defaultTargetID, tenantBody: true}),

		// ── red team ──────────────────────────────────────────────────────────────────────
		// The red-team state is GLOBAL console state: one artifact set, one decisions file, one
		// background job. None of it is attributable to a tenant, so the writes take a
		// cross-tenant grant and run on this host's target.
		read("/api/redteam/curves", s.redteamCurves, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/redteam/campaigns", s.redteamCampaigns, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/redteam/live", s.redteamLive, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/redteam/findings", s.redteamFindings, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/redteam/gates", s.redteamGates, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/api/redteam/run-status", s.redteamRunStatus, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		control("/api/redteam/decision", s.redteamDecision, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		control("/api/redteam/run", s.redteamRun, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		control("/api/redteam/continuous", s.redteamContinuous, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),
		read("/redteam", s.redteamPage, routeSpec{fixedTarget: defaultTargetID, requireTenantWildcard: true}),

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

func functionalRunDestination(s *Server, _ *http.Request, body scopedBody) (runDestination, error) {
	if body.Profile == "" {
		return runDestination{}, fmt.Errorf("profile is required")
	}
	return s.runs.FunctionalDestination(cataloguev1.ProfileID(body.Profile))
}

func functionalAdmissionProfile(r *http.Request) (cataloguev1.ProfileID, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		return "", fmt.Errorf("one exact fixed-suite profile is required")
	}
	values := query["profile"]
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", fmt.Errorf("one exact fixed-suite profile is required")
	}
	profile := cataloguev1.ProfileID(values[0])
	if _, err := cataloguev1.DefinitionFor(profile); err != nil {
		return "", fmt.Errorf("unknown fixed-suite profile")
	}
	return profile, nil
}

func functionalAdmissionDestination(s *Server, r *http.Request, body scopedBody) (runDestination, error) {
	if body.Profile != "" {
		return runDestination{}, fmt.Errorf("one exact fixed-suite profile is required in the query")
	}
	profile, err := functionalAdmissionProfile(r)
	if err != nil {
		return runDestination{}, err
	}
	return s.runs.FunctionalDestination(profile)
}

// costDestination resolves the ONE cluster /api/cost will actually price and read, so the
// boundary authorizes that cluster instead of the sentinel an omitted parameter stands for.
func costDestination(s *Server, r *http.Request, _ scopedBody) (runDestination, error) {
	return runDestination{Targets: []string{s.effectiveCostTarget(r)}}, nil
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
