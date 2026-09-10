/*
 * Phorvex Console — effective-destination and indivisible-effect scope controls (M-136).
 *
 * The declared scope of a route has to match what its handler ACTUALLY does, not what the
 * request names. Three shapes of mismatch are covered here, each with a real producer driving a
 * real effect through the real router, and each with a positive control:
 *
 *   1. an effect that is indivisible across tenants (truncating one shared audit file) must not
 *      be reachable by a tenant-limited grant at all;
 *   2. a control that launches a subprocess and then reads its own config for a destination must
 *      be authorized against THAT destination, including the host it launches on;
 *   3. an omitted scope parameter that silently widens a request to the whole cluster must
 *      require the cross-tenant grant that widening implies.
 *
 * Effects stay inside t.TempDir; the "harness" is a local shell script, never a cluster tool.
 */

package console

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// (1) A tenant-limited operator cannot clear an audit that holds every tenant's records.
func TestAuditClearIsIndivisibleAcrossTenants(t *testing.T) {
	cases := []struct {
		name    string
		tenants []string
		want    int
		cleared bool
	}{
		{"tenant-limited operator", []string{"tenant-a"}, http.StatusForbidden, false},
		{"cross-tenant operator (positive control)", []string{wildcardScope}, http.StatusOK, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			auditPath := filepath.Join(dir, "audit.jsonl")
			before := []byte(`{"kind":"phorvex.decision","tenant":"tenant-b","pod":"other-tenant-pod"}` + "\n")
			if err := os.WriteFile(auditPath, before, 0o600); err != nil {
				t.Fatal(err)
			}
			f := newAuthFixture(t, Config{Root: dir, HarnessDir: dir, AuditPath: auditPath},
				operatorGrant("op", c.tenants, []string{defaultTargetID}))

			w := f.do(f.albReqAs(t, http.MethodPost, "/api/live/clear", "{}", "op"))
			after, err := os.ReadFile(auditPath)
			if err != nil {
				t.Fatal(err)
			}
			if w.Code != c.want {
				t.Fatalf("status %d, want %d: %s", w.Code, c.want, w.Body.String())
			}
			if c.cleared && len(after) != 0 {
				t.Fatalf("the authorized clear did not truncate the audit (%d bytes left)", len(after))
			}
			if !c.cleared && string(after) != string(before) {
				t.Fatalf("a refused clear still destroyed another tenant's records: %d -> %d bytes", len(before), len(after))
			}
		})
	}
}

// (2) A suite run launches a subprocess on THIS host and then drives whatever cluster its own
// config names. Both have to be inside the grant before anything starts.
func TestSuiteRunAuthorizesItsEffectiveDestination(t *testing.T) {
	cases := []struct {
		name         string
		targets      []string
		tenants      []string
		writeConfig  bool
		wantStatus   int
		wantLaunched bool
	}{
		{"no target grant at all", []string{}, []string{wildcardScope}, false, http.StatusForbidden, false},
		{"host granted, no config to read (positive control)", []string{defaultTargetID}, []string{wildcardScope}, false, http.StatusOK, true},
		{"config names a cluster the grant excludes", []string{defaultTargetID}, []string{wildcardScope}, true, http.StatusForbidden, false},
		{"config's cluster and namespace granted (positive control)", []string{defaultTargetID, "kind-amtd-test"}, []string{"amtd-attack-test"}, true, http.StatusOK, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := scratchDir(t)
			marker := filepath.Join(dir, "started")
			bin := filepath.Join(dir, "local-harness")
			if err := os.WriteFile(bin, []byte("#!/bin/sh\necho local-only > started\nexit 1\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			suiteName := ""
			for name := range allowedConfigs {
				suiteName = name
				break
			}
			if suiteName == "" {
				t.Fatal("no attack-agent suite is registered")
			}
			if c.writeConfig {
				cfg := "context: \"kind-amtd-test\"\nnamespace: \"amtd-attack-test\"\nownedAck: true\n"
				if err := os.WriteFile(filepath.Join(dir, allowedConfigs[suiteName].File), []byte(cfg), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			f := newAuthFixture(t, Config{Root: dir, HarnessDir: dir, HarnessBin: bin},
				operatorGrant("op", c.tenants, c.targets))

			w := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"`+suiteName+`"}`, "op"))
			if w.Code != c.wantStatus {
				t.Fatalf("status %d, want %d: %s", w.Code, c.wantStatus, strings.TrimSpace(w.Body.String()))
			}
			if launched := waitForFile(marker, time.Second); launched != c.wantLaunched {
				t.Fatalf("subprocess launched=%v, want %v (body %s)", launched, c.wantLaunched, strings.TrimSpace(w.Body.String()))
			}
		})
	}
}

// A scenario run substitutes its own context for an unknown target and FORCES the sandbox
// namespace. Authorization must follow that substitution, not the target the caller named.
func TestScenarioRunAuthorizesTheSubstitutedDestination(t *testing.T) {
	dir := scratchDir(t)
	marker := filepath.Join(dir, "started")
	bin := filepath.Join(dir, "local-harness")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho local-only > started\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// This grant covers the default target and every tenant, but NOT the kind sandbox context
	// StartScenario silently falls back to when the target is unknown.
	f := newAuthFixture(t, Config{Root: dir, HarnessDir: dir, HarnessBin: bin},
		operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}))
	w := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/scenario", `{"scenarios":["c1-heldout-cve"]}`, "op"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("an omitted target that falls back to %s must be refused: %d %s", scenarioFallbackContext, w.Code, w.Body.String())
	}
	if waitForFile(marker, 300*time.Millisecond) {
		t.Fatal("a refused scenario still launched the harness")
	}

	// Positive control: granting the substituted context AND the forced sandbox namespace works.
	f2 := newAuthFixture(t, Config{Root: dir, HarnessDir: dir, HarnessBin: bin},
		operatorGrant("op", []string{scenarioSandboxNamespace}, []string{defaultTargetID, scenarioFallbackContext}))
	if w := f2.do(f2.albReqAs(t, http.MethodPost, "/api/runs/scenario", `{"scenarios":["c1-heldout-cve"]}`, "op")); w.Code != http.StatusOK {
		t.Fatalf("positive control: %d %s", w.Code, w.Body.String())
	}
}

// (3) An omitted namespace turns scan/ablation into a cluster-wide request.
func TestUnscopedClusterWideReadsRequireTheWildcard(t *testing.T) {
	limited := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{"vllm"}, []string{defaultTargetID, wildcardScope}))
	wide := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}))

	for _, path := range []string{"/api/scan", "/api/ablation"} {
		if w := limited.do(limited.albReqAs(t, http.MethodGet, path, "", "op")); w.Code != http.StatusForbidden {
			t.Fatalf("unscoped %s for a tenant-limited grant: got %d, want 403\n%s", path, w.Code, w.Body.String())
		}
		// The NARROW form stays available to the same limited grant.
		if w := limited.do(limited.albReqAs(t, http.MethodGet, path+"?ns=vllm", "", "op")); w.Code == http.StatusForbidden {
			t.Fatalf("%s?ns=vllm must remain available to a grant that holds vllm: %s", path, w.Body.String())
		}
		// And the unscoped form is available to a cross-tenant grant (positive control).
		if w := wide.do(wide.albReqAs(t, http.MethodGet, path, "", "op")); w.Code == http.StatusForbidden {
			t.Fatalf("unscoped %s must be available to a cross-tenant grant: %s", path, w.Body.String())
		}
	}
}

// The cluster-wide policy listing is filtered to the granted tenants rather than returned whole.
func TestClusterPolicyListingIsFilteredByGrant(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{"vllm"}, []string{defaultTargetID}))
	w := f.do(f.albReqAs(t, http.MethodGet, "/api/cluster", "", "op"))
	if w.Code != http.StatusOK {
		t.Fatalf("cluster: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Policies []PolicyView `json:"policies"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// No cluster is reachable in the unit environment, so the list is empty; what matters is that
	// the handler applies the filter rather than marshalling whatever the API server returned.
	for _, p := range resp.Policies {
		if p.Namespace != "vllm" && p.Tenant != "vllm" {
			t.Fatalf("an out-of-scope policy reached a tenant-limited caller: %+v", p)
		}
	}
	if !strings.Contains(w.Body.String(), "filtered to this identity's granted tenants") {
		t.Fatalf("the response must state that it is scope-filtered: %s", w.Body.String())
	}
}

// The cluster-wide live-data reads are filtered to the grant, not returned whole. Each endpoint
// is driven through the real router over REAL producer files that hold two tenants' records, and
// each has a cross-tenant positive control proving the fixture genuinely contains the record the
// limited grant must not see.
func TestClusterWideReadsAreFilteredToTheGrant(t *testing.T) {
	dir := t.TempDir()
	// The decision audit is the producer /api/uptime reads its actuation markers from: a workload
	// with no marker is not part of the actuator-impact view at all, so both tenants need one.
	auditPath := filepath.Join(dir, "audit.jsonl")
	mineRec, theirsRec := decisionRec("vllm", "vllm-0"), decisionRec("other-tenant", "secret-0")
	mineRec.Time, theirsRec.Time = time.Now().UTC(), time.Now().UTC()
	if got := writeDecisionAudit(t, mineRec, theirsRec); got != "" {
		raw, err := os.ReadFile(got)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(auditPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The attack ledger the console reads (attacksPath: beside the decision audit).
	mine := `{"id":"a1","namespace":"vllm","pod":"vllm-0","service":"vllm","deploy":"vllm","firedAt":"2026-09-10T10:00:00Z","attack":"foothold"}`
	theirs := `{"id":"a2","namespace":"other-tenant","pod":"secret-0","service":"secret","deploy":"secret","firedAt":"2026-09-10T10:00:00Z","attack":"foothold"}`
	if err := os.WriteFile(filepath.Join(dir, "phorvex-attacks.jsonl"), []byte(mine+"\n"+theirs+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The availability sampler's output (uptimePath: beside the decision audit).
	now := time.Now().UTC().Format(time.RFC3339Nano)
	samples := `{"t":"` + now + `","ns":"vllm","workload":"vllm","kind":"Deployment","available":1,"desired":1}` + "\n" +
		`{"t":"` + now + `","ns":"other-tenant","workload":"secret","kind":"Deployment","available":1,"desired":1}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "phorvex-uptime.jsonl"), []byte(samples), 0o600); err != nil {
		t.Fatal(err)
	}
	// The three-arm experiment log.
	arms := `{"namespace":"vllm","deploy":"vllm","attack":"foothold","runAt":"` + now + `","arms":[]}` + "\n" +
		`{"namespace":"other-tenant","deploy":"secret","attack":"foothold","runAt":"` + now + `","arms":[]}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "three-arm-runs.jsonl"), []byte(arms), 0o600); err != nil {
		t.Fatal(err)
	}

	// loadAttacks caches into package state on first read; reset it so this fixture is the one
	// under test rather than whatever an earlier test loaded.
	attackMu.Lock()
	attackList, attackLoaded = nil, false
	attackMu.Unlock()
	t.Cleanup(func() {
		attackMu.Lock()
		attackList, attackLoaded = nil, false
		attackMu.Unlock()
	})

	cfg := Config{Root: dir, HarnessDir: dir, AuditPath: auditPath}
	paths := []string{"/api/attack-results", "/api/attack-monitoring", "/api/uptime", "/api/availability-arms"}

	// Positive control FIRST: a cross-tenant grant sees the other tenant, proving the producers
	// really do carry it and the negative case below is not passing vacuously.
	wide := newAuthFixture(t, cfg, operatorGrant("op", []string{wildcardScope}, []string{wildcardScope}))
	sawOther := map[string]bool{}
	for _, path := range paths {
		w := wide.do(wide.albReqAs(t, http.MethodGet, path, "", "op"))
		if w.Code != http.StatusOK {
			t.Fatalf("%s (cross-tenant): %d %s", path, w.Code, w.Body.String())
		}
		sawOther[path] = strings.Contains(w.Body.String(), "other-tenant")
	}
	for _, path := range paths {
		if !sawOther[path] {
			t.Fatalf("%s: the fixture did not reach this endpoint even with a cross-tenant grant; "+
				"the filtered assertion below would be vacuous", path)
		}
	}

	attackMu.Lock()
	attackList, attackLoaded = nil, false
	attackMu.Unlock()

	limited := newAuthFixture(t, cfg, operatorGrant("op", []string{"vllm"}, []string{wildcardScope}))
	for _, path := range paths {
		w := limited.do(limited.albReqAs(t, http.MethodGet, path, "", "op"))
		if w.Code != http.StatusOK {
			t.Fatalf("%s (tenant-limited): %d %s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "other-tenant") || strings.Contains(w.Body.String(), "secret-0") {
			t.Fatalf("%s leaked another tenant's records to a tenant-limited grant:\n%s", path, w.Body.String())
		}
	}
}

// Holding a TENANT is not the same as being allowed to reach the CLUSTER that tenant lives in.
// Every control that drives this console's own cluster requires the default target explicitly.
func TestClusterWritesRequireTheClusterTarget(t *testing.T) {
	controls := []struct{ path, body string }{
		{"/api/policy/edit", `{"namespace":"vllm","name":"vllm-defense","mode":"dryRun"}`},
		{"/api/workload/attack", `{"namespace":"vllm","action":"foothold"}`},
		{"/api/workload/fire-scenario", `{"namespace":"vllm","scenario":"kv-poison"}`},
		{"/api/vllm/attack", `{"action":"poison"}`},
		{"/api/availability-arms/run", `{"namespace":"vllm","attack":"foothold"}`},
	}
	// The grant holds the tenant but NO cluster target.
	var denied []string
	noTarget := newAuthFixture(t, execRecordingConfig(&denied), operatorGrant("op", []string{"vllm"}, []string{}))
	for _, c := range controls {
		w := noTarget.do(noTarget.albReqAs(t, http.MethodPost, c.path, c.body, "op"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s with a tenant but no target grant: got %d, want 403\n%s", c.path, w.Code, w.Body.String())
		}
	}
	if len(denied) != 0 {
		t.Fatalf("a target-refused control still reached the kubectl dispatcher: %v", denied)
	}

	// Positive control: the same grant plus the default target reaches the dispatcher.
	var allowed []string
	withTarget := newAuthFixture(t, execRecordingConfig(&allowed), operatorGrant("op", []string{"vllm"}, []string{defaultTargetID}))
	if w := withTarget.do(withTarget.albReqAs(t, http.MethodPost, "/api/policy/edit", controls[0].body, "op")); w.Code != http.StatusOK {
		t.Fatalf("positive control: %d %s", w.Code, w.Body.String())
	}
	if len(allowed) != 1 {
		t.Fatalf("the authorized edit must dispatch exactly once, got %v", allowed)
	}
}

// The global red-team controls write shared state that belongs to no tenant.
func TestGlobalRedteamControlsRequireCrossTenantGrant(t *testing.T) {
	limited := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{"vllm"}, []string{wildcardScope}))
	for _, c := range []struct{ path, body string }{
		{"/api/redteam/decision", `{"ID":"f1","Status":"addressed"}`},
		{"/api/redteam/run", `{}`},
		{"/api/redteam/continuous", `{"Action":"start"}`},
	} {
		w := limited.do(limited.albReqAs(t, http.MethodPost, c.path, c.body, "op"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s for a tenant-limited grant: got %d, want 403\n%s", c.path, w.Code, w.Body.String())
		}
	}
}

// scratchDir is a temp dir for tests that launch the run manager. t.TempDir would FAIL the test
// when the launched run's own goroutine is still writing its config/out dir at cleanup time;
// that race is about teardown, not about the authorization behaviour under test.
func scratchDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "phorvex-console-scope-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func waitForFile(path string, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, err := os.Stat(path)
	return err == nil
}
