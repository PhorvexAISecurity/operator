package cataloguev1

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const authTestToken = "limited-v1-scoped-token-material-0123456789abcdef"

type authTestServer struct {
	t                 *testing.T
	server            *httptest.Server
	mu                sync.Mutex
	requests          []string
	mutations         int
	change            bool
	allowDeniedTenant bool
}

func newAuthTestServer(t *testing.T) *authTestServer {
	t.Helper()
	fixture := &authTestServer{t: t}
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(fixture.serveHTTP))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture.server.Listener = listener
	fixture.server.Start()
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *authTestServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	if r.Method != http.MethodGet {
		f.mutations++
	}
	requestNumber := len(f.requests)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	write := func(status int, body any) {
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(body); err != nil {
			f.t.Errorf("encode response: %v", err)
		}
	}
	auth := r.Header.Get("Authorization")
	switch {
	case r.URL.Path == "/redirect":
		http.Redirect(w, r, "/api/session", http.StatusFound)
	case r.URL.Path == "/api/session" && auth == "":
		if r.Header.Get("x-amzn-oidc-identity") != "" {
			write(http.StatusUnauthorized, map[string]any{"error": "unsigned ALB identity is not proof"})
			return
		}
		write(http.StatusUnauthorized, map[string]any{"error": "authentication required"})
	case auth != "Bearer "+authTestToken:
		write(http.StatusUnauthorized, map[string]any{"error": "authentication required"})
	case r.URL.Path == "/api/session":
		body := map[string]any{
			"authModes": []string{"bearer"}, "canEdit": true, "canRead": true,
			"grantsConfigured": true, "issuer": "fixture", "lens": "operator",
			"roles": []string{"operator"}, "source": "bearer", "subject": "fixture-subject",
			"targets": []string{"default"}, "tenants": []string{"vllm"},
		}
		if f.change && requestNumber > 3 {
			body["note"] = "changed"
		}
		write(http.StatusOK, body)
	case r.URL.Path == "/api/owner/events" && r.URL.Query().Get("tenant") == "vllm":
		body := map[string]any{"empty": true, "events": []any{}, "note": "bounded", "partial": false, "rollup": map[string]any{}}
		if f.change && requestNumber > 3 {
			body["empty"] = false
		}
		write(http.StatusOK, body)
	case r.URL.Path == "/api/owner/events" && f.allowDeniedTenant:
		write(http.StatusOK, map[string]any{"empty": true, "events": []any{}, "note": "wrongly allowed", "partial": false, "rollup": map[string]any{}})
	case r.URL.Path == "/api/owner/events":
		write(http.StatusForbidden, map[string]any{"error": "tenant outside grant"})
	case r.URL.Path == "/api/workloads":
		write(http.StatusForbidden, map[string]any{"error": "target outside grant"})
	default:
		write(http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func authTestConfig(t *testing.T, fixture *authTestServer) authHTTPConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scoped-token")
	if err := os.WriteFile(path, []byte(authTestToken), 0o600); err != nil {
		t.Fatal(err)
	}
	return authHTTPConfig{
		FixedLoopback: fixture.server.URL, ScopedTokenFile: path,
		ExpectedSubject: "fixture-subject",
		AllowedTenant:   "vllm", DeniedTenant: "document-store", DeniedTarget: "ungranted-cluster",
	}
}

func TestAuthUnauthenticatedControlUsesOnlyFixedReads(t *testing.T) {
	fixture := newAuthTestServer(t)
	result, err := runAuthUnauthenticatedControl(context.Background(), nil, authTestConfig(t, fixture), authProbeHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Observations) != 4 || result.BeforeSHA256 == "" || result.BeforeSHA256 != result.AfterSHA256 {
		t.Fatalf("result = %+v", result)
	}
	if fixture.mutations != 0 {
		t.Fatalf("mutation requests = %d", fixture.mutations)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), authTestToken) || strings.Contains(string(raw), "Authorization") {
		t.Fatalf("result exposed credential material: %s", raw)
	}
}

func TestAuthScopedControlProvesAllowAndBothDenials(t *testing.T) {
	fixture := newAuthTestServer(t)
	result, err := runAuthScopedControl(context.Background(), nil, authTestConfig(t, fixture), authProbeHooks{})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{http.StatusOK, http.StatusOK, http.StatusForbidden, http.StatusForbidden, http.StatusOK}
	if len(result.Observations) != len(want) {
		t.Fatalf("observations = %+v", result.Observations)
	}
	for i := range want {
		if result.Observations[i].Status != want[i] {
			t.Fatalf("observation[%d] = %+v", i, result.Observations[i])
		}
	}
	if result.BeforeSHA256 == "" || result.AfterSHA256 == "" || fixture.mutations != 0 {
		t.Fatalf("read-only fingerprints/mutations = %q %q / %d", result.BeforeSHA256, result.AfterSHA256, fixture.mutations)
	}
}

func TestAuthControlsRejectChangedReadProjection(t *testing.T) {
	fixture := newAuthTestServer(t)
	fixture.change = true
	if _, err := runAuthUnauthenticatedControl(context.Background(), nil, authTestConfig(t, fixture), authProbeHooks{}); err == nil || !strings.Contains(err.Error(), "changed across") {
		t.Fatalf("error = %v", err)
	}
}

func TestAuthControlsRefuseUnsafeRuntimeBeforeRequest(t *testing.T) {
	fixture := newAuthTestServer(t)
	valid := authTestConfig(t, fixture)
	cases := []authHTTPConfig{
		func() authHTTPConfig { c := valid; c.FixedLoopback = "http://example.com:8090"; return c }(),
		func() authHTTPConfig { c := valid; c.FixedLoopback += "/api"; return c }(),
		func() authHTTPConfig { c := valid; c.ScopedTokenFile = "relative-token"; return c }(),
		func() authHTTPConfig { c := valid; c.DeniedTenant = c.AllowedTenant; return c }(),
	}
	for i, candidate := range cases {
		before := len(fixture.requests)
		if _, err := runAuthScopedControl(context.Background(), nil, candidate, authProbeHooks{}); err == nil {
			t.Fatalf("case %d accepted", i)
		}
		if len(fixture.requests) != before {
			t.Fatalf("case %d sent a request before refusing", i)
		}
	}
}

func TestAuthProbeRejectsRedirectWithoutFollowing(t *testing.T) {
	fixture := newAuthTestServer(t)
	client := authProbeClient(nil)
	_, err := runAuthProbeSteps(context.Background(), client, fixture.server.URL, []byte(authTestToken), []authProbeStep{{
		name: "redirect", path: "/redirect", want: http.StatusOK, schema: []string{"subject"}, bearer: true,
	}}, authProbeHooks{})
	if err == nil || !strings.Contains(err.Error(), "redirects are forbidden") {
		t.Fatalf("error = %v", err)
	}
	if len(fixture.requests) != 1 {
		t.Fatalf("requests = %v", fixture.requests)
	}
}

func TestAuthControlDoesNotUseExpiredOrMalformedToken(t *testing.T) {
	fixture := newAuthTestServer(t)
	cfg := authTestConfig(t, fixture)
	if err := os.WriteFile(cfg.ScopedTokenFile, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runAuthUnauthenticatedControl(context.Background(), nil, cfg, authProbeHooks{}); err == nil || !strings.Contains(err.Error(), "32..16384") {
		t.Fatalf("error = %v", err)
	}
	if len(fixture.requests) != 0 {
		t.Fatalf("requests = %v", fixture.requests)
	}
}

func TestAuthScopeRetainsPositiveAfterDeniedTenantUnexpectedlySucceeds(t *testing.T) {
	fixture := newAuthTestServer(t)
	fixture.allowDeniedTenant = true
	result, err := runAuthScopedControl(context.Background(), nil, authTestConfig(t, fixture), authProbeHooks{})
	if err == nil {
		t.Fatal("unexpectedly allowed tenant must fail the control")
	}
	if len(result.Observations) != 5 || result.Observations[4].Step != "allowed-tenant-after" || result.Observations[4].Status != http.StatusOK {
		t.Fatalf("the final positive control was not retained: %+v", result.Observations)
	}
	outcome, _ := classifyAuthProbeFailure(err, result)
	if outcome != OutcomeFunctionalFail {
		t.Fatalf("outcome = %s, want %s", outcome, OutcomeFunctionalFail)
	}
}

func TestAuthScopeBindsExpectedSubjectBeforeDenials(t *testing.T) {
	fixture := newAuthTestServer(t)
	cfg := authTestConfig(t, fixture)
	cfg.ExpectedSubject = "different-subject"
	result, err := runAuthScopedControl(context.Background(), nil, cfg, authProbeHooks{})
	if err == nil || !strings.Contains(err.Error(), "subject authority differs") {
		t.Fatalf("error = %v", err)
	}
	if len(result.Observations) != 1 || result.Observations[0].Step != "legitimate-session" {
		t.Fatalf("denials ran without exact subject authority: %+v", result.Observations)
	}
}
