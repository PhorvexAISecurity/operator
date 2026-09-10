/*
 * Phorvex Console — route coverage (M-136).
 *
 * The defect this fix repairs was partly a routing defect: handlers were registered one by one
 * and each had to remember to wrap itself in a gate. These tests hold the new invariant from
 * both directions, so a route added later cannot silently bypass the boundary:
 *
 *   1. every route in the table refuses an unauthenticated request;
 *   2. every registered path is either the declared-public surface or in the table;
 *   3. the declared contracts are internally consistent (control routes are POST-shaped, the
 *      access levels are the ones the route's effect requires).
 */

package console

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// publicPaths is the ENTIRE public surface. Adding to this list is a deliberate act and shows up
// in review as a change to the trust boundary.
var publicPaths = map[string]bool{
	"/api/health": true,
	"/":           true,
}

// Every route in the table refuses an unauthenticated caller, with no payload in the denial.
func TestEveryRouteRefusesUnauthenticated(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}))
	for _, rt := range f.srv.apiRoutes() {
		for _, method := range rt.spec.methods {
			var req *http.Request
			if method == http.MethodGet {
				req = httptest.NewRequest(method, rt.path, nil)
			} else {
				req = httptest.NewRequest(method, rt.path, strings.NewReader(`{"namespace":"vllm","id":"x"}`))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", testOrigin)
			}
			// A self-asserted lens must not change the answer.
			req.Header.Set("X-Phorvex-Lens", "operator")
			w := f.do(req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s unauthenticated: got %d, want 401\n%s", method, rt.path, w.Code, w.Body.String())
			}
		}
	}
}

// Every path the mux serves is either declared public or guarded by the table.
//
// To make this bite rather than assert its own assumptions, the probe set is derived from the
// PACKAGE SOURCE: every "/api/..."-shaped path literal anywhere in the non-test files. A stray
// `mux.HandleFunc("/api/backdoor", …)` puts that literal in the source, so it gets probed, the
// mux answers with its own pattern rather than the catch-all, and this test fails.
func TestNoRouteIsServedOutsideTheTable(t *testing.T) {
	srv := NewServer(Config{Root: "."})
	declared := map[string]bool{}
	for _, rt := range srv.apiRoutes() {
		if declared[rt.path] {
			t.Fatalf("route %s is declared twice", rt.path)
		}
		declared[rt.path] = true
	}
	mux, ok := srv.Handler().(*http.ServeMux)
	if !ok {
		t.Fatalf("Handler() must build a *http.ServeMux so its registrations can be probed; got %T", srv.Handler())
	}

	probe := pathLiteralsInPackageSource(t)
	if len(probe) < len(declared) {
		t.Fatalf("the source scan found %d path literals but %d routes are declared; the scan is not seeing the package", len(probe), len(declared))
	}
	// Positive control: a path that is registered nowhere must resolve to the catch-all, so a
	// pattern equal to the probed path really does mean "something registered this".
	if _, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/api/never-registered-control", nil)); pattern == "/api/never-registered-control" {
		t.Fatal("probe is not discriminating: an unregistered path reported itself as a pattern")
	}

	var undeclared []string
	for _, p := range probe {
		if publicPaths[p] || declared[p] {
			continue
		}
		if _, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, p, nil)); pattern == p {
			undeclared = append(undeclared, p)
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Fatalf("these paths are served outside the guarded route table (add them to apiRoutes, or to publicPaths deliberately): %v", undeclared)
	}
}

// pathLiteralsInPackageSource collects every "/api/…" or "/redteam" string literal in the
// package's non-test Go files.
func pathLiteralsInPackageSource(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`"(/api/[A-Za-z0-9._/-]*|/redteam)"`)
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			if p := m[1]; !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// The declared contracts have to be coherent: anything that changes cluster or console state is
// operator-only and not GET-reachable, and nothing is left at the permissive default by accident.
func TestRouteContractsAreCoherent(t *testing.T) {
	srv := NewServer(Config{Root: "."})
	// Routes whose effect is a cluster write, a process launch or a console state change.
	stateChanging := map[string]bool{
		"/api/policy/edit":            true,
		"/api/vllm/attack":            true,
		"/api/workload/attack":        true,
		"/api/workload/fire-scenario": true,
		"/api/availability-arms/run":  true,
		"/api/live/clear":             true,
		"/api/runs/start":             true,
		"/api/runs/scenario":          true,
		"/api/runs/stop":              true,
		"/api/redteam/decision":       true,
		"/api/redteam/run":            true,
		"/api/redteam/continuous":     true,
		"/api/apply-fix/submit":       true,
		"/api/apply-fix/approve":      true,
	}
	seen := map[string]bool{}
	for _, rt := range srv.apiRoutes() {
		seen[rt.path] = true
		if len(rt.spec.methods) == 0 {
			t.Errorf("%s declares no method contract", rt.path)
		}
		for _, m := range rt.spec.methods {
			if m != http.MethodGet && m != http.MethodPost {
				t.Errorf("%s declares an unexpected method %q", rt.path, m)
			}
		}
		if rt.h == nil {
			t.Errorf("%s has no handler", rt.path)
		}
		if !stateChanging[rt.path] {
			continue
		}
		if rt.spec.access != accessControl {
			t.Errorf("%s changes state and must be accessControl (operator only)", rt.path)
		}
		for _, m := range rt.spec.methods {
			if m == http.MethodGet {
				t.Errorf("%s changes state and must not be GET-reachable", rt.path)
			}
		}
		// A control that changes state does so SOMEWHERE. It must say where — a fixed cluster, a
		// target parameter, a resolved destination, or a run whose own target is checked —
		// because a grant that holds a tenant does not thereby hold the cluster it lives in.
		hasTargetScope := rt.spec.fixedTarget != "" || len(rt.spec.targetQ) > 0 ||
			len(rt.spec.targetBody) > 0 || rt.spec.destination != nil ||
			rt.spec.runQ != "" || rt.spec.runBody
		if !hasTargetScope {
			t.Errorf("%s changes state but declares no target scope: add fixedTarget, targetQ, "+
				"targetBody, a destination resolver, or a run-id check", rt.path)
		}
	}
	for path := range stateChanging {
		if !seen[path] {
			t.Errorf("state-changing route %s is no longer registered; update this list deliberately", path)
		}
	}
}

// Owner-projected surfaces must never be declared as the vendor read group by mistake.
func TestOwnerSurfacesDeclareOwnerAccess(t *testing.T) {
	srv := NewServer(Config{Root: "."})
	want := map[string]bool{"/api/owner/events": true, "/api/owner/tenants": true, "/api/live": true, "/api/live/history": true}
	for _, rt := range srv.apiRoutes() {
		if want[rt.path] && rt.spec.access != accessOwnerData {
			t.Errorf("%s must be declared accessOwnerData so an owner grant can reach its own tenant", rt.path)
		}
	}
}
