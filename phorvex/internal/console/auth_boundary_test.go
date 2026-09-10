/*
 * Phorvex Console — the request trust boundary, through the REAL router (M-136).
 *
 * These are the incident controls. Each one drives Server.Handler() with a real signed
 * credential (or none) and asserts what the boundary does BEFORE a handler runs — including,
 * where a mutation is involved, that the real dispatcher was called zero times for a rejected
 * request and exactly once for a legitimate operator.
 */

package console

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── the reported incident ──────────────────────────────────────────────────────────────────
//
// M-136 as filed: "GET /api/live with no header at all connects and replays the complete
// decision audit; a self-asserted X-Phorvex-Lens: operator on /api/posture returns 200 with
// full data." Both are asserted closed here, against the real router.

func TestIncident_SelfAssertedLensNoLongerReachesData(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}))
	for _, path := range []string{"/api/posture", "/api/effectiveness", "/api/cluster", "/api/live"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Phorvex-Lens", "operator") // the exact probe from the incident report
		w := f.do(req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s with a self-asserted operator lens: got %d, want 401\n%s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "grade") || strings.Contains(w.Body.String(), "stats") {
			t.Fatalf("%s leaked payload data in its denial: %s", path, w.Body.String())
		}
	}
}

func TestIncident_UnauthenticatedLiveStreamIsRefused(t *testing.T) {
	path := writeDecisionAudit(t, decisionRec("acme", "acme-pod"), decisionRec("other", "other-secret-pod"))
	f := newAuthFixture(t, Config{AuditPath: path}, ownerGrant("own", []string{"acme"}))

	// (a) no credential at all — the exact "SSE connects with no header" case.
	w := f.do(httptest.NewRequest(http.MethodGet, "/api/live?lens=investor&tail=all", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/live: got %d, want 401", w.Code)
	}
	if strings.Contains(w.Body.String(), "acme-pod") || strings.Contains(w.Body.String(), "other-secret-pod") {
		t.Fatalf("unauthenticated /api/live emitted audit data: %s", w.Body.String())
	}

	// (b) authenticated, but the grant is owner-on-acme: the investor lens does not widen it and
	//     another tenant's records never appear.
	ctx, cancel := context.WithCancel(context.Background())
	req := f.albReqAs(t, http.MethodGet, "/api/live?lens=investor&tenant=acme&tail=all", "", "own").WithContext(ctx)
	rec := httptest.NewRecorder()
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	f.h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "acme-pod") {
		t.Fatalf("the owner's own tenant must still stream: %s", body)
	}
	if strings.Contains(body, "other-secret-pod") || strings.Contains(body, "perDollar") {
		t.Fatalf("an owner grant asking for lens=investor must NOT receive another tenant or IP internals: %s", body)
	}
}

// ── credential handling ────────────────────────────────────────────────────────────────────

// Presenting two credentials is refused rather than resolved. Silently preferring one is how an
// invalid bearer becomes a more privileged proxy identity.
func TestAmbiguousCredentialsRefused(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."},
		operatorGrant("alb-subject-1", []string{wildcardScope}, []string{wildcardScope}),
		bearerOperatorGrant("cli", []string{wildcardScope}, []string{wildcardScope}),
	)
	req := f.albReq(t, http.MethodGet, "/api/effectiveness", "")
	req.Header.Set("Authorization", "Bearer "+f.bearer.mint(t, bearerTok{Sub: "cli"}))
	w := f.do(req)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "exactly one") {
		t.Fatalf("two credentials must be refused: got %d %s", w.Code, w.Body.String())
	}
}

// An INVALID bearer token must not fall through to the ALB proxy headers.
func TestInvalidBearerNeverFallsBackToProxyIdentity(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("alb-subject-1", []string{wildcardScope}, []string{wildcardScope}))
	req := httptest.NewRequest(http.MethodGet, "/api/effectiveness", nil)
	req.Header.Set("Authorization", "Bearer not.a.token")
	req.Header.Set("x-amzn-oidc-identity", "alb-subject-1")
	req.Header.Set("x-amzn-oidc-accesstoken", "opaque")
	if w := f.do(req); w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bearer + unsigned proxy headers: got %d, want 401\n%s", w.Code, w.Body.String())
	}
}

// The unsigned ALB headers are refused explicitly, not merely ignored.
func TestUnsignedALBHeadersAreNotIdentity(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("cognito-user-42", []string{wildcardScope}, []string{wildcardScope}))
	req := httptest.NewRequest(http.MethodGet, "/api/effectiveness", nil)
	req.Header.Set("x-amzn-oidc-identity", "cognito-user-42")
	w := f.do(req)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "not proof of identity") {
		t.Fatalf("x-amzn-oidc-identity alone: got %d %s", w.Code, w.Body.String())
	}
}

// Both credential types reach the same authorization outcome for the same grant shape.
func TestBothCredentialTypesAreSupported(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."},
		operatorGrant("alb-op", []string{wildcardScope}, []string{wildcardScope}),
		bearerOperatorGrant("cli-op", []string{wildcardScope}, []string{wildcardScope}),
	)
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/effectiveness", "", "alb-op")); w.Code != 200 {
		t.Fatalf("ALB operator read: %d %s", w.Code, w.Body.String())
	}
	if w := f.do(f.bearerReq(t, http.MethodGet, "/api/effectiveness", "", "cli-op")); w.Code != 200 {
		t.Fatalf("bearer operator read: %d %s", w.Code, w.Body.String())
	}
}

// ── grants ─────────────────────────────────────────────────────────────────────────────────

// The fail-closed rollout state: a console with NO grant table authenticates callers and
// authorizes none of them. No signed user is silently an operator.
func TestNoGrantsConfigured_EveryAuthenticatedCallerIsDenied(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}) // no subjects at all
	if f.auth.GrantCount() != 0 {
		t.Fatal("fixture must start with no bindings")
	}
	for _, path := range []string{"/api/effectiveness", "/api/owner/events?tenant=acme", "/api/policy/edit"} {
		method := http.MethodGet
		if strings.Contains(path, "policy") {
			method = http.MethodPost
		}
		w := f.do(f.albReq(t, method, path, `{"namespace":"vllm","name":"x","mode":"active"}`))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "no authorization grant") {
			t.Fatalf("%s with no grants: got %d %s", path, w.Code, w.Body.String())
		}
	}
}

// ── roles ──────────────────────────────────────────────────────────────────────────────────

// Investor is read-only: it reads the evidence group and cannot reach a control, and the real
// mutation dispatcher is never called for it.
func TestInvestorIsReadOnly(t *testing.T) {
	var calls []string
	f := newAuthFixture(t, execRecordingConfig(&calls),
		investorGrant("inv", []string{wildcardScope}, []string{wildcardScope}),
	)
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/effectiveness", "", "inv")); w.Code != 200 {
		t.Fatalf("investor read: %d %s", w.Code, w.Body.String())
	}
	controls := []struct{ path, body string }{
		{"/api/policy/edit", `{"namespace":"vllm","name":"vllm-defense","mode":"active"}`},
		{"/api/workload/attack", `{"namespace":"vllm","action":"foothold"}`},
		{"/api/workload/fire-scenario", `{"namespace":"vllm","scenario":"kv-poison"}`},
		{"/api/vllm/attack", `{"action":"poison"}`},
		{"/api/live/clear", `{}`},
		{"/api/runs/start", `{"config":"p3-v3"}`},
	}
	for _, c := range controls {
		w := f.do(f.albReqAs(t, http.MethodPost, c.path, c.body, "inv"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("investor POST %s: got %d, want 403\n%s", c.path, w.Code, w.Body.String())
		}
	}
	if len(calls) != 0 {
		t.Fatalf("a rejected investor request reached the kubectl dispatcher: %v", calls)
	}
}

// A legitimate operator's cluster write reaches the dispatcher EXACTLY once.
func TestOperatorMutationDispatchesExactlyOnce(t *testing.T) {
	var calls []string
	f := newAuthFixture(t, execRecordingConfig(&calls),
		operatorGrant("op", []string{"vllm"}, []string{defaultTargetID}),
	)
	w := f.do(f.albReqAs(t, http.MethodPost, "/api/policy/edit", `{"namespace":"vllm","name":"vllm-defense","mode":"dryRun"}`, "op"))
	if w.Code != 200 {
		t.Fatalf("legitimate operator edit: %d %s", w.Code, w.Body.String())
	}
	if len(calls) != 1 || !strings.Contains(calls[0], "patch phorvexpolicy vllm-defense") {
		t.Fatalf("expected exactly one kubectl patch, got %v", calls)
	}
}

// ── tenant scope ───────────────────────────────────────────────────────────────────────────

// An operator confined to one tenant cannot write to another, and the dispatcher never runs.
func TestCrossTenantMutationRefusedBeforeDispatch(t *testing.T) {
	var calls []string
	f := newAuthFixture(t, execRecordingConfig(&calls),
		operatorGrant("op", []string{"vllm"}, []string{defaultTargetID}),
	)
	cases := []struct{ path, body string }{
		{"/api/policy/edit", `{"namespace":"litellm","name":"litellm-defense","mode":"active"}`},
		{"/api/workload/attack", `{"namespace":"litellm","action":"foothold"}`},
		{"/api/workload/fire-scenario", `{"namespace":"litellm","scenario":"kv-poison"}`},
		{"/api/availability-arms/run", `{"namespace":"litellm","attack":"foothold"}`},
	}
	for _, c := range cases {
		w := f.do(f.albReqAs(t, http.MethodPost, c.path, c.body, "op"))
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "outside this identity's tenant scope") {
			t.Fatalf("cross-tenant %s: got %d %s", c.path, w.Code, w.Body.String())
		}
	}
	if len(calls) != 0 {
		t.Fatalf("a cross-tenant request reached the kubectl dispatcher: %v", calls)
	}
}

// A namespace omitted from the body is not "any namespace".
func TestOmittedNamespaceIsNotUnscoped(t *testing.T) {
	var calls []string
	f := newAuthFixture(t, execRecordingConfig(&calls), operatorGrant("op", []string{"vllm"}, []string{defaultTargetID}))
	w := f.do(f.albReqAs(t, http.MethodPost, "/api/policy/edit", `{"name":"vllm-defense","mode":"active"}`, "op"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("omitted namespace: got %d, want 400\n%s", w.Code, w.Body.String())
	}
	if len(calls) != 0 {
		t.Fatalf("an unscoped request reached the dispatcher: %v", calls)
	}
}

// The fixed-namespace control (the vLLM attack surface) is scoped like any other.
func TestFixedNamespaceControlIsScoped(t *testing.T) {
	var calls []string
	f := newAuthFixture(t, execRecordingConfig(&calls),
		operatorGrant("nonvllm", []string{"litellm"}, []string{defaultTargetID}),
	)
	w := f.do(f.albReqAs(t, http.MethodPost, "/api/vllm/attack", `{"action":"poison"}`, "nonvllm"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("/api/vllm/attack without the vllm tenant: got %d, want 403\n%s", w.Code, w.Body.String())
	}
	if len(calls) != 0 {
		t.Fatalf("a refused attack reached the dispatcher: %v", calls)
	}
}

// An actor spoofed in the body is ignored: the audit records the VERIFIED subject.
func TestBodySpoofedActorIsIgnored(t *testing.T) {
	var calls []string
	cfg := execRecordingConfig(&calls)
	cfg.MutationAuditPath = fmt.Sprintf("%s/console-mutations.jsonl", t.TempDir())
	f := newAuthFixture(t, cfg, operatorGrant("real-op", []string{"vllm"}, []string{defaultTargetID}))

	body := `{"namespace":"vllm","name":"vllm-defense","mode":"dryRun","user":"root","actor":"admin","requester":"someone-else"}`
	if w := f.do(f.albReqAs(t, http.MethodPost, "/api/policy/edit", body, "real-op")); w.Code != 200 {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	entries := auditEntries(t, cfg.MutationAuditPath)
	if len(entries) != 1 {
		t.Fatalf("expected one audited mutation, got %d", len(entries))
	}
	want := testALBIssuer + "#real-op"
	if entries[0].Actor != want {
		t.Fatalf("audit actor = %q, want the verified subject %q", entries[0].Actor, want)
	}
	for _, spoof := range []string{"root", "admin", "someone-else"} {
		if strings.Contains(entries[0].Actor, spoof) {
			t.Fatalf("the audit actor absorbed a body field: %q", entries[0].Actor)
		}
	}
}

// Owner reads are confined to the granted tenants on both the events list and the selector.
func TestOwnerSurfacesAreTenantConfined(t *testing.T) {
	path := writeDecisionAudit(t, decisionRec("acme", "acme-pod"), decisionRec("globex", "globex-pod"))
	f := newAuthFixture(t, Config{AuditPath: path}, ownerGrant("own", []string{"acme"}))

	w := f.do(f.albReqAs(t, http.MethodGet, "/api/owner/events?tenant=acme", "", "own"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "acme-pod") {
		t.Fatalf("own tenant: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("cross-tenant leak: %s", w.Body.String())
	}
	// The selector lists only what the grant covers, so the customer list is not disclosed.
	w = f.do(f.albReqAs(t, http.MethodGet, "/api/owner/tenants", "", "own"))
	var sel struct {
		Tenants []string `json:"tenants"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &sel)
	if len(sel.Tenants) != 1 || sel.Tenants[0] != "acme" {
		t.Fatalf("tenant selector must list only granted tenants, got %v", sel.Tenants)
	}
}

// The history page applies the same tenant control for every lens, including an omitted tenant.
func TestHistoryIsTenantConfinedForEveryLens(t *testing.T) {
	path := writeDecisionAudit(t, decisionRec("acme", "acme-pod"), decisionRec("globex", "globex-pod"))
	f := newAuthFixture(t, Config{AuditPath: path}, operatorGrant("scoped-op", []string{"acme"}, []string{defaultTargetID}))

	w := f.do(f.albReqAs(t, http.MethodGet, "/api/live/history", "", "scoped-op"))
	if w.Code != 200 {
		t.Fatalf("history: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "acme-pod") {
		t.Fatalf("the granted tenant must be readable: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("an omitted ?tenant= must not widen the page to every tenant: %s", w.Body.String())
	}
	// Naming a tenant outside the grant is refused outright.
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/live/history?tenant=globex", "", "scoped-op")); w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant history: got %d, want 403", w.Code)
	}
}

// ── target scope ───────────────────────────────────────────────────────────────────────────

func TestClusterTargetScopeIsEnforced(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}))
	// The default target (an omitted ?target=) is granted.
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/pricing", "", "op")); w.Code != 200 {
		t.Fatalf("default target: %d %s", w.Code, w.Body.String())
	}
	// Another cluster is not.
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/pricing?target=prod-eks", "", "op")); w.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope target: got %d, want 403\n%s", w.Code, w.Body.String())
	}
	// A wildcard target grant reaches it.
	f2 := newAuthFixture(t, Config{Root: "."}, operatorGrant("wide", []string{wildcardScope}, []string{wildcardScope}))
	if w := f2.do(f2.albReqAs(t, http.MethodGet, "/api/pricing?target=prod-eks", "", "wide")); w.Code != 200 {
		t.Fatalf("wildcard target: %d %s", w.Code, w.Body.String())
	}
}

// A run id belonging to another operator on an out-of-scope target is not readable, and probing
// ids discloses nothing beyond "not found".
func TestRunLookupHonoursOwnerAndTarget(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."},
		operatorGrant("owner-op", []string{wildcardScope}, []string{"cluster-a"}),
		operatorGrant("other-op", []string{wildcardScope}, []string{"cluster-b"}),
	)
	// Register a run directly on the manager, as StartScenario would.
	f.srv.runs.mu.Lock()
	f.srv.runs.runs["scn-1"] = &RunStatus{
		ID: "scn-1", State: "running", Owner: testALBIssuer + "#owner-op", ScopeTarget: "cluster-a",
	}
	f.srv.runs.runOut["scn-1"] = "out-console-scn-1"
	f.srv.runs.mu.Unlock()

	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/runs/status?id=scn-1", "", "owner-op")); w.Code != 200 {
		t.Fatalf("the run's own operator must read it: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/runs/status?id=scn-1", "/api/runs/evidence?id=scn-1", "/api/runs/stream?id=scn-1"} {
		w := f.do(f.albReqAs(t, http.MethodGet, path, "", "other-op"))
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s as an out-of-scope operator: got %d, want 404\n%s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "cluster-a") || strings.Contains(w.Body.String(), "owner-op") {
			t.Fatalf("the denial disclosed the run's owner/target: %s", w.Body.String())
		}
	}
	// Stopping someone else's run is refused too.
	if w := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/stop", `{"id":"scn-1"}`, "other-op")); w.Code != http.StatusNotFound {
		t.Fatalf("cross-scope stop: got %d, want 404", w.Code)
	}
	// The list is filtered rather than redacted.
	w := f.do(f.albReqAs(t, http.MethodGet, "/api/runs/list", "", "other-op"))
	if strings.Contains(w.Body.String(), "scn-1") {
		t.Fatalf("the run list leaked an out-of-scope run: %s", w.Body.String())
	}
}

// ── CORS / CSRF ────────────────────────────────────────────────────────────────────────────

func TestCORSHasNoWildcardGrant(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}))

	// An attacker origin gets no CORS grant at all.
	req := f.albReqAs(t, http.MethodGet, "/api/effectiveness", "", "op")
	req.Header.Set("Origin", "https://evil.example")
	w := f.do(req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("an untrusted origin received a CORS grant: %q", got)
	}
	// The configured origin is reflected exactly, never "*".
	req = f.albReqAs(t, http.MethodGet, "/api/effectiveness", "", "op")
	req.Header.Set("Origin", testOrigin)
	w = f.do(req)
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Fatalf("trusted origin reflection = %q, want %q", got, testOrigin)
	}
	if strings.Contains(w.Header().Get("Vary"), "Origin") == false {
		t.Fatal("a per-origin response must Vary: Origin")
	}
}

func TestPreflightOnlyForTrustedOrigins(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}))
	req := httptest.NewRequest(http.MethodOptions, "/api/policy/edit", nil)
	req.Header.Set("Origin", "https://evil.example")
	if w := f.do(req); w.Code != http.StatusForbidden {
		t.Fatalf("preflight from an attacker origin: got %d, want 403", w.Code)
	}
	req = httptest.NewRequest(http.MethodOptions, "/api/policy/edit", nil)
	req.Header.Set("Origin", testOrigin)
	if w := f.do(req); w.Code != http.StatusNoContent {
		t.Fatalf("preflight from the trusted origin: got %d, want 204", w.Code)
	}
}

// The CSRF boundary: an ALB-authenticated (cookie-driven) state change from an attacker origin
// is refused whatever lens it sends; the same request from the trusted origin succeeds.
func TestCSRFBoundaryForBrowserAuthenticatedMutations(t *testing.T) {
	var calls []string
	f := newAuthFixture(t, execRecordingConfig(&calls), operatorGrant("op", []string{"vllm"}, []string{defaultTargetID}))
	body := `{"namespace":"vllm","name":"vllm-defense","mode":"dryRun"}`

	for _, origin := range []string{"https://evil.example", "http://console.phorvex.test", ""} {
		req := f.albReqAs(t, http.MethodPost, "/api/policy/edit", body, "op")
		if origin == "" {
			req.Header.Del("Origin")
		} else {
			req.Header.Set("Origin", origin)
		}
		req.Header.Set("X-Phorvex-Lens", "operator")
		w := f.do(req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-origin mutation from %q: got %d, want 403\n%s", origin, w.Code, w.Body.String())
		}
	}
	if len(calls) != 0 {
		t.Fatalf("a CSRF-refused request reached the dispatcher: %v", calls)
	}

	// Same-origin succeeds, and dispatches exactly once.
	if w := f.do(f.albReqAs(t, http.MethodPost, "/api/policy/edit", body, "op")); w.Code != 200 {
		t.Fatalf("same-origin mutation: %d %s", w.Code, w.Body.String())
	}
	if len(calls) != 1 {
		t.Fatalf("expected exactly one dispatch after the legitimate request, got %v", calls)
	}
}

// A bearer (CLI) caller is not subject to Origin, because Origin is not an authentication factor.
func TestBearerMutationsDoNotRequireAnOrigin(t *testing.T) {
	var calls []string
	f := newAuthFixture(t, execRecordingConfig(&calls), bearerOperatorGrant("cli", []string{"vllm"}, []string{defaultTargetID}))
	req := f.bearerReq(t, http.MethodPost, "/api/policy/edit", `{"namespace":"vllm","name":"vllm-defense","mode":"dryRun"}`, "cli")
	if w := f.do(req); w.Code != 200 {
		t.Fatalf("bearer mutation with no Origin: %d %s", w.Code, w.Body.String())
	}
	if len(calls) != 1 {
		t.Fatalf("expected one dispatch, got %v", calls)
	}
}

// ── method contract ────────────────────────────────────────────────────────────────────────

// Run triggers are POST-only now: a GET cannot launch or stop a harness run.
func TestRunTriggersAreNotGETReachable(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}))
	for _, path := range []string{"/api/runs/start", "/api/runs/scenario", "/api/runs/stop", "/api/live/clear"} {
		w := f.do(f.albReqAs(t, http.MethodGet, path, "", "op"))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s: got %d, want 405\n%s", path, w.Code, w.Body.String())
		}
		if w.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("GET %s must advertise Allow: POST, got %q", path, w.Header().Get("Allow"))
		}
	}
}

// ── public surface ─────────────────────────────────────────────────────────────────────────

// Health is public but discloses nothing about the deployment's filesystem layout.
func TestPublicHealthDisclosesNoLayout(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "/srv/phorvex", HarnessBin: "/srv/phorvex/bin/harness.exe"},
		operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}))
	w := f.do(httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if w.Code != 200 {
		t.Fatalf("health must stay public for probes: %d", w.Code)
	}
	for _, leak := range []string{"/srv/phorvex", "harness", "root", "phorvexBin"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Fatalf("public health disclosed %q: %s", leak, w.Body.String())
		}
	}
	// The same facts remain available to an authorized caller.
	w = f.do(f.albReqAs(t, http.MethodGet, "/api/diagnostics", "", "op"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/srv/phorvex") {
		t.Fatalf("diagnostics must serve the layout to an authorized caller: %d %s", w.Code, w.Body.String())
	}
	// ...and to nobody else.
	if w := f.do(httptest.NewRequest(http.MethodGet, "/api/diagnostics", nil)); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated diagnostics: got %d, want 401", w.Code)
	}
}

// An unknown /api path is an API 404, not SPA HTML that makes a typo look like success.
func TestUnknownAPIPathIs404JSON(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}))
	w := f.do(httptest.NewRequest(http.MethodGet, "/api/does-not-exist", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown API path: got %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "<!doctype") || strings.Contains(w.Body.String(), "<html") {
		t.Fatalf("unknown API path fell through to the SPA: %s", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("unknown API path content type = %q", ct)
	}
}

// ── session ────────────────────────────────────────────────────────────────────────────────

// The session endpoint reports the effective grant and never a credential.
func TestSessionReportsEffectiveGrant(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{"vllm"}, []string{defaultTargetID}))
	w := f.do(f.albReqAs(t, http.MethodGet, "/api/session", "", "op"))
	if w.Code != 200 {
		t.Fatalf("session: %d %s", w.Code, w.Body.String())
	}
	var s sessionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Subject != "op" || !s.CanEdit || !s.CanRead || len(s.Tenants) != 1 || s.Tenants[0] != "vllm" {
		t.Fatalf("session = %+v", s)
	}
	if !s.GrantsConfigured {
		t.Fatal("grantsConfigured must be true when bindings exist")
	}
	body := w.Body.String()
	for _, secret := range []string{"Bearer", "x-amzn-oidc", "eyJ"} {
		if strings.Contains(body, secret) {
			t.Fatalf("the session response echoed credential material (%q): %s", secret, body)
		}
	}
	// An investor sees canEdit=false, which is what the SPA renders controls from.
	f2 := newAuthFixture(t, Config{Root: "."}, investorGrant("inv", []string{"vllm"}, []string{defaultTargetID}))
	w = f2.do(f2.albReqAs(t, http.MethodGet, "/api/session", "", "inv"))
	_ = json.Unmarshal(w.Body.Bytes(), &s)
	if s.CanEdit || !s.CanRead {
		t.Fatalf("investor session = %+v", s)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────────────────────

// execRecordingConfig returns a Config whose kubectl/harness launcher records every invocation
// instead of running it — the dispatch spy the mutation controls assert on.
func execRecordingConfig(calls *[]string) Config {
	return Config{
		Root: ".",
		Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
			*calls = append(*calls, bin+" "+strings.Join(args, " "))
			return "phorvexpolicy.phorvex.ai/vllm-defense patched", nil
		},
	}
}
