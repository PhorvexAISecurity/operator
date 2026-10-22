package console

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

// attackRoutes is every route the attacks service serves (ADR-0001, phase 6): attack
// firing, the harness runs, and the evidence and records they produce. A route moves
// between the services only by changing this list together with the table.
var attackRoutes = []string{
	"/api/suites", "/api/catalog", "/api/threat-matrix",
	"/api/effectiveness", "/api/frontier", "/api/benchmarks", "/api/posture", "/api/rawlog", "/api/matrix",
	"/api/ai-surface", "/api/reports", "/api/benchmark-sim",
	"/api/attack-results", "/api/attack-monitoring", "/api/availability-arms", "/api/workload/attacks",
	"/api/runs/start", "/api/runs/scenario", "/api/runs/functional", "/api/runs/functional/admission", "/api/runs/stop",
	"/api/runs/nats-reconcile", "/api/runs/voice-cleanup-reconcile", "/api/runs/list", "/api/runs/status",
	"/api/runs/stream", "/api/runs/evidence",
	"/api/vllm/attack", "/api/voice/live/fire", "/api/voice/agency/live/fire", voiceOutputRoute, voiceAdmissionRoute,
	"/api/voice/mcp/live/fire", "/api/litellm/live/fire", "/api/litellm/output/fire", crmLiveRoute,
	"/api/workload/attack", "/api/workload/fire-scenario", "/api/availability-arms/run",
}

func TestTheAttacksServiceOwnsExactlyTheAttackRoutes(t *testing.T) {
	var got []string
	for _, rt := range NewServer(Config{Root: ".", StateDir: t.TempDir()}).apiRoutes() {
		if rt.spec.attacks {
			got = append(got, rt.path)
		}
	}
	want := append([]string(nil), attackRoutes...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("attack routes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// attacksUpstream stands in for the attacks service and records what reached it.
type attacksUpstream struct {
	*httptest.Server
	calls         atomic.Int32
	method, path  string
	identity, org string
	body          string
}

func newAttacksUpstream(t *testing.T) *attacksUpstream {
	u := &attacksUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		u.method, u.path, u.body = r.Method, r.URL.RequestURI(), string(raw)
		u.identity, u.org = r.Header.Get(ALBDataHeader), r.Header.Get("Origin")
		u.calls.Add(1)
		writeJSON(w, http.StatusAccepted, map[string]string{"from": "attacks"})
	}))
	t.Cleanup(u.Close)
	return u
}

func TestAForwardingConsoleSendsTheAttackRoutesToTheAttacksService(t *testing.T) {
	upstream := newAttacksUpstream(t)
	f := newAuthFixture(t, Config{Root: ".", Service: ServiceConsole, AttacksURL: upstream.URL},
		operatorGrant("alb-subject-1", []string{wildcardScope}, []string{wildcardScope}))

	req := f.albReq(t, http.MethodPost, "/api/runs/stop?id=run-1", `{"id":"run-1"}`)
	w := f.do(req)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), "attacks") {
		t.Fatalf("forwarded control answered %d %s", w.Code, w.Body.String())
	}
	if upstream.method != http.MethodPost || upstream.path != "/api/runs/stop?id=run-1" || upstream.body != `{"id":"run-1"}` {
		t.Fatalf("the attacks service received %s %s %q", upstream.method, upstream.path, upstream.body)
	}
	// The attacks service authenticates the caller itself, from the same signed identity.
	if upstream.identity != req.Header.Get(ALBDataHeader) || upstream.org != testOrigin {
		t.Fatalf("the caller's identity or origin did not reach the attacks service")
	}

	// The console still refuses what it would refuse for its own routes, before forwarding.
	unauthenticated := httptest.NewRequest(http.MethodGet, "/api/runs/list", nil)
	if w := f.do(unauthenticated); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated attack route answered %d", w.Code)
	}
	if w := f.do(f.albReq(t, http.MethodGet, "/api/runs/stop", "")); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method answered %d", w.Code)
	}
	if upstream.calls.Load() != 1 {
		t.Fatalf("the attacks service saw %d requests, want only the admitted one", upstream.calls.Load())
	}

	// The console's own routes stay here.
	if w := f.do(f.albReq(t, http.MethodGet, "/api/version", "")); w.Code != http.StatusOK || upstream.calls.Load() != 1 {
		t.Fatalf("console route answered %d, attacks service calls %d", w.Code, upstream.calls.Load())
	}
}

func TestAConsoleReportsAnUnavailableAttacksService(t *testing.T) {
	upstream := newAttacksUpstream(t)
	upstream.Close()
	f := newAuthFixture(t, Config{Root: ".", Service: ServiceConsole, AttacksURL: upstream.URL},
		operatorGrant("alb-subject-1", []string{wildcardScope}, []string{wildcardScope}))
	if w := f.do(f.albReq(t, http.MethodGet, "/api/runs/list", "")); w.Code != http.StatusBadGateway {
		t.Fatalf("unreachable attacks service answered %d %s", w.Code, w.Body.String())
	}
}

func TestTheAttacksServiceServesOnlyTheAttackRoutes(t *testing.T) {
	f := newAuthFixture(t, Config{Root: ".", Service: ServiceAttacks},
		operatorGrant("alb-subject-1", []string{wildcardScope}, []string{wildcardScope}))
	if w := f.do(f.albReq(t, http.MethodGet, "/api/runs/list", "")); w.Code != http.StatusOK {
		t.Fatalf("attack route answered %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/version", "/api/live", "/", "/index.html"} {
		if w := f.do(f.albReq(t, http.MethodGet, path, "")); w.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d from the attacks service", path, w.Code)
		}
	}
	// Unauthenticated callers meet the full boundary here too.
	if w := f.do(httptest.NewRequest(http.MethodGet, "/api/runs/list", nil)); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated attack route answered %d", w.Code)
	}
}

func TestValidateService(t *testing.T) {
	for _, c := range []struct {
		cfg Config
		ok  bool
	}{
		{Config{}, true},
		{Config{Service: ServiceAttacks}, true},
		{Config{Service: ServiceConsole, AttacksURL: "http://staging-attacks:8090"}, true},
		{Config{Service: ServiceConsole, AttacksURL: "https://attacks.example/"}, true},
		{Config{Service: ServiceConsole}, false},
		{Config{Service: ServiceConsole, AttacksURL: "staging-attacks:8090"}, false},
		{Config{Service: ServiceConsole, AttacksURL: "http://attacks/api"}, false},
		{Config{Service: ServiceConsole, AttacksURL: "http://user@attacks"}, false},
		{Config{Service: ServiceAttacks, AttacksURL: "http://attacks"}, false},
		{Config{AttacksURL: "http://attacks"}, false},
		{Config{Service: "dispatcher"}, false},
	} {
		if err := c.cfg.ValidateService(); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v, want ok=%v", c.cfg, err, c.ok)
		}
	}
}
