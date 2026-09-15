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
	"net/http/httptest"
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
		{"host granted, no config to read is refused before launch", []string{defaultTargetID}, []string{wildcardScope}, false, http.StatusBadRequest, false},
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

// Aggregates built from the decision audit are TENANT data. Summing the whole audit handed a
// tenant-limited operator another tenant's cost and decision count.
func TestAuditDerivedAggregatesAreTenantScoped(t *testing.T) {
	mine := decisionRec("tenant-a", "mine-pod")
	mine.Cost = 11
	theirs := decisionRec("tenant-b", "private-pod")
	theirs.Cost = 1729
	cfg := Config{Root: t.TempDir(), AuditPath: writeDecisionAudit(t, mine, theirs)}

	read := func(f *authFixture, subject string) (int, float64, int) {
		t.Helper()
		w := f.do(f.albReqAs(t, http.MethodGet, "/api/cost-timeseries", "", subject))
		var body struct {
			Total     float64 `json:"totalPhorvex"`
			Decisions int     `json:"decisions"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body.Total, body.Decisions
	}

	// Positive control first: a cross-tenant grant sees BOTH records, so the fixture really does
	// carry the foreign cost the scoped cases below must not receive.
	wide := newAuthFixture(t, cfg, operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}))
	if code, total, n := read(wide, "op"); code != http.StatusOK || total != 1740 || n != 2 {
		t.Fatalf("cross-tenant control: %d total=%v decisions=%d", code, total, n)
	}

	// A tenant-a operator sees only tenant-a's cost — never tenant-b's 1729.
	scoped := newAuthFixture(t, cfg, operatorGrant("op", []string{"tenant-a"}, []string{defaultTargetID}))
	code, total, n := read(scoped, "op")
	if code != http.StatusOK || total != 11 || n != 1 {
		t.Fatalf("tenant-a operator: %d total=%v decisions=%d (must be 11 over 1 decision)", code, total, n)
	}

	// An empty target grant reaches the endpoint at all.
	noTarget := newAuthFixture(t, cfg, operatorGrant("op", []string{wildcardScope}, []string{}))
	if code, _, _ := read(noTarget, "op"); code != http.StatusForbidden {
		t.Fatalf("empty target grant: got %d, want 403", code)
	}
}

// Sharing a cluster does not make one tenant's run readable by another, and "I started it" is
// not authorization: the check is the grant held NOW.
func TestRunIDHonoursTenantAndCurrentScope(t *testing.T) {
	dir := scratchDir(t)
	bin := filepath.Join(dir, "local-harness")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A real suite config naming tenant-b on the default cluster.
	if err := os.WriteFile(filepath.Join(dir, allowedConfigs["fpprobe"].File),
		[]byte("namespace: tenant-b\ncontext: default\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Root: dir, HarnessDir: dir, HarnessBin: bin}
	f := newAuthFixture(t, cfg,
		operatorGrant("creator", []string{"tenant-b"}, []string{defaultTargetID}),
		operatorGrant("stranger", []string{"tenant-a"}, []string{defaultTargetID}),
	)
	w := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"fpprobe"}`, "creator"))
	if w.Code != http.StatusOK {
		t.Fatalf("producer start: %d %s", w.Code, w.Body.String())
	}
	var started struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil || started.ID == "" {
		t.Fatalf("producer id: %s", w.Body.String())
	}
	time.Sleep(50 * time.Millisecond)

	// Positive control: the tenant-b operator reads its own run on every id-scoped route.
	idRoutes := []string{"/api/runs/status?id=", "/api/runs/evidence?id="}
	for _, base := range idRoutes {
		if w := f.do(f.albReqAs(t, http.MethodGet, base+started.ID, "", "creator")); w.Code != http.StatusOK {
			t.Fatalf("creator %s: %d %s", base, w.Code, w.Body.String())
		}
	}
	// A tenant-a operator on the SAME cluster gets nothing, on every id-scoped route.
	for _, base := range append(idRoutes, "/api/runs/stream?id=") {
		w := f.do(f.albReqAs(t, http.MethodGet, base+started.ID, "", "stranger"))
		if w.Code != http.StatusNotFound {
			t.Fatalf("stranger %s: got %d, want 404\n%s", base, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "tenant-b") || strings.Contains(w.Body.String(), "creator") {
			t.Fatalf("the denial disclosed the run's owner or namespace: %s", w.Body.String())
		}
	}
	if w := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/stop", `{"id":"`+started.ID+`"}`, "stranger")); w.Code != http.StatusNotFound {
		t.Fatalf("stranger stop: got %d, want 404", w.Code)
	}
	// The listing agrees with the id check rather than advertising what status would refuse.
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/runs/list", "", "stranger")); strings.Contains(w.Body.String(), started.ID) {
		t.Fatalf("the run list leaked another tenant's run: %s", w.Body.String())
	}

	// The creator's OWN grant, narrowed to a tenant it no longer holds, loses the run with it —
	// there is no standing creator bypass.
	narrowed := newAuthFixture(t, cfg, operatorGrant("creator", []string{"tenant-a"}, []string{defaultTargetID}))
	narrowed.srv.runs = f.srv.runs // same run manager, a differently-scoped identity
	if w := narrowed.do(narrowed.albReqAs(t, http.MethodGet, "/api/runs/status?id="+started.ID, "", "creator")); w.Code != http.StatusNotFound {
		t.Fatalf("creator whose grant no longer covers the run: got %d, want 404\n%s", w.Code, w.Body.String())
	}
}

// A run whose namespace could not be recorded (legacy, or a config that named none) is not
// readable by a tenant-limited grant just because it has no tenant to compare.
func TestRunWithoutRecordedNamespaceFailsClosed(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."},
		operatorGrant("scoped", []string{"tenant-a"}, []string{defaultTargetID}),
		operatorGrant("wide", []string{wildcardScope}, []string{defaultTargetID}),
	)
	f.srv.runs.mu.Lock()
	f.srv.runs.runs["run-legacy"] = &RunStatus{ID: "run-legacy", State: "done", ScopeTarget: defaultTargetID}
	f.srv.runs.runOut["run-legacy"] = "out-legacy"
	f.srv.runs.mu.Unlock()

	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/runs/status?id=run-legacy", "", "scoped")); w.Code != http.StatusNotFound {
		t.Fatalf("legacy run for a tenant-limited grant: got %d, want 404", w.Code)
	}
	// Positive control: an explicit cross-tenant grant may still reach it.
	if w := f.do(f.albReqAs(t, http.MethodGet, "/api/runs/status?id=run-legacy", "", "wide")); w.Code != http.StatusOK {
		t.Fatalf("cross-tenant grant: got %d, want 200\n%s", w.Code, w.Body.String())
	}
}

// A suite config that names no namespace does not mean "no tenant effect".
func TestSuiteWithNoNamespaceNeedsACrossTenantGrant(t *testing.T) {
	dir := scratchDir(t)
	bin := filepath.Join(dir, "local-harness")
	marker := filepath.Join(dir, "started")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho x > started\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, allowedConfigs["fpprobe"].File), []byte("context: default\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Root: dir, HarnessDir: dir, HarnessBin: bin}

	scoped := newAuthFixture(t, cfg, operatorGrant("op", []string{"tenant-a"}, []string{defaultTargetID}))
	if w := scoped.do(scoped.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"fpprobe"}`, "op")); w.Code != http.StatusForbidden {
		t.Fatalf("suite with an undetermined namespace: got %d, want 403\n%s", w.Code, w.Body.String())
	}
	if waitForFile(marker, 200*time.Millisecond) {
		t.Fatal("a refused suite still launched the harness")
	}
	// Positive control: a cross-tenant grant may launch it.
	wide := newAuthFixture(t, cfg, operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}))
	if w := wide.do(wide.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"fpprobe"}`, "op")); w.Code != http.StatusOK {
		t.Fatalf("cross-tenant control: %d %s", w.Code, w.Body.String())
	}
}

// The private evidence corpus is not attributable to a tenant, so it cannot be filtered down to
// one: a tenant-limited grant gets none of it, a cross-tenant grant gets it.
func TestPrivateEvidenceCorpusNeedsACrossTenantGrant(t *testing.T) {
	corpus := []string{
		"/api/effectiveness", "/api/frontier", "/api/benchmarks", "/api/posture",
		"/api/rawlog", "/api/matrix", "/api/ai-surface", "/api/reports",
		"/api/redteam/curves", "/api/redteam/campaigns", "/api/redteam/findings", "/api/redteam/run-status",
	}
	scoped := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{"tenant-a"}, []string{wildcardScope}))
	wide := newAuthFixture(t, Config{Root: "."}, investorGrant("inv", []string{wildcardScope}, []string{wildcardScope}))
	for _, path := range corpus {
		if w := scoped.do(scoped.albReqAs(t, http.MethodGet, path, "", "op")); w.Code != http.StatusForbidden {
			t.Errorf("%s for a tenant-limited grant: got %d, want 403\n%s", path, w.Code, w.Body.String())
		}
		if w := wide.do(wide.albReqAs(t, http.MethodGet, path, "", "inv")); w.Code == http.StatusForbidden {
			t.Errorf("%s must remain available to a cross-tenant grant: %s", path, w.Body.String())
		}
	}
	// Shared product metadata stays available to a tenant-limited read grant.
	for _, path := range []string{"/api/catalog", "/api/suites", "/api/threat-matrix", "/api/handlers", "/api/version"} {
		if w := scoped.do(scoped.albReqAs(t, http.MethodGet, path, "", "op")); w.Code == http.StatusForbidden {
			t.Errorf("%s is shared product metadata and must stay available: %s", path, w.Body.String())
		}
	}
}

// /api/cost falls back to the first runnable cluster; the boundary must authorize THAT cluster,
// not the sentinel an omitted parameter stands for.
func TestCostAuthorizesTheClusterItActuallyReads(t *testing.T) {
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}))
	// The handler and the boundary must agree on one destination.
	req := f.albReqAs(t, http.MethodGet, "/api/cost", "", "op")
	if got := f.srv.effectiveCostTarget(req); !principalOf(withTestPrincipal(req, testOperatorPrincipal())).AllowsTarget(got) {
		t.Fatalf("effectiveCostTarget resolved %q, which a wildcard-target principal must allow", got)
	}
	// Naming a cluster outside the grant is refused whichever parameter carries it.
	for _, q := range []string{"?target=prod-eks", "?context=prod-eks"} {
		if w := f.do(f.albReqAs(t, http.MethodGet, "/api/cost"+q, "", "op")); w.Code != http.StatusForbidden {
			t.Fatalf("/api/cost%s: got %d, want 403\n%s", q, w.Code, w.Body.String())
		}
	}
}

// A request that names a resource in two places must not be authorized on one and executed on
// the other. The boundary and the handler resolve the run id ONCE.
//
// The launcher serializes runs (maxConcurrentRuns) and rate-limits back-to-back starts, so the
// two real runs are created in sequence rather than concurrently.
func TestRunStopResolvesOneIdentifier(t *testing.T) {
	dir := scratchDir(t)
	bin := filepath.Join(dir, "local-harness")
	cfgFile := filepath.Join(dir, allowedConfigs["fpprobe"].File)
	cfg := Config{Root: dir, HarnessDir: dir, HarnessBin: bin}
	f := newAuthFixture(t, cfg,
		operatorGrant("creator", []string{wildcardScope}, []string{defaultTargetID}),
		operatorGrant("stranger", []string{"tenant-a"}, []string{defaultTargetID}),
	)
	start := func(ns string) string {
		t.Helper()
		if err := os.WriteFile(cfgFile, []byte("namespace: "+ns+"\ncontext: default\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		w := f.do(f.albReqAs(t, http.MethodPost, "/api/runs/start", `{"config":"fpprobe"}`, "creator"))
		var b struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &b)
		if w.Code != http.StatusOK || b.ID == "" {
			t.Fatalf("start(%s): %d %s", ns, w.Code, w.Body.String())
		}
		t.Cleanup(func() { _ = f.srv.runs.Stop(b.ID) })
		return b.ID
	}
	stop := func(query, body, subject string) *httptest.ResponseRecorder {
		t.Helper()
		path := "/api/runs/stop"
		if query != "" {
			path += "?id=" + query
		}
		payload := "{}"
		if body != "" {
			payload = `{"id":"` + body + `"}`
		}
		return f.do(f.albReqAs(t, http.MethodPost, path, payload, subject))
	}
	running := func(id string) bool {
		t.Helper()
		st, ok := f.srv.runs.Status(id)
		return ok && st.State == "running"
	}

	// A tenant-a run the stranger IS granted. Query-only stop is the first positive control.
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	mine := start("tenant-a")
	// RunManager.Stop is a no-op until the launcher has registered the process, so wait for that
	// before stopping. (That race is a run-lifecycle limit this fix deliberately does not touch.)
	waitForRunProcess(t, f.srv.runs, mine, 10*time.Second)
	if w := stop(mine, "", "stranger"); w.Code != http.StatusOK {
		t.Fatalf("query-only authorized stop: %d %s", w.Code, w.Body.String())
	}

	// A tenant-b run the stranger is NOT granted. The launcher serializes runs and rate-limits
	// back-to-back starts, so wait for the slot to be released rather than guessing at a delay —
	// otherwise a slow release would fail this test for a reason unrelated to authorization.
	waitForRunToLeaveRunning(t, f.srv.runs, mine, 10*time.Second)
	time.Sleep(minStartInterval + 200*time.Millisecond)
	foreign := start("tenant-b")
	waitForRunProcess(t, f.srv.runs, foreign, 10*time.Second)

	// The counterexample: authorize the id in the query, act on a different id in the body.
	if w := stop(mine, foreign, "stranger"); w.Code == http.StatusOK {
		t.Fatalf("authorized %s in the query but acted on %s in the body: %s", mine, foreign, w.Body.String())
	}
	if !running(foreign) {
		t.Fatal("the foreign run was stopped by a request authorized for a different run")
	}
	// Conflicting ids are rejected outright rather than resolved by precedence — even for an
	// identity granted BOTH runs, because the request has no single meaning.
	if w := stop(mine, foreign, "creator"); w.Code != http.StatusBadRequest {
		t.Fatalf("conflicting ids: got %d, want 400\n%s", w.Code, w.Body.String())
	}
	if !running(foreign) {
		t.Fatal("a rejected conflicting-id request still stopped the run")
	}
	// The foreign id alone stays hidden from the stranger.
	if w := stop(foreign, foreign, "stranger"); w.Code != http.StatusNotFound {
		t.Fatalf("foreign id: got %d, want 404\n%s", w.Code, w.Body.String())
	}
	if !running(foreign) {
		t.Fatal("a 404'd request still stopped the run")
	}
	// Body-only stop by an authorized identity is the second positive control.
	if w := stop("", foreign, "creator"); w.Code != http.StatusOK {
		t.Fatalf("body-only authorized stop: %d %s", w.Code, w.Body.String())
	}
}

// Local readers of the console's own audit, attack ledger and evidence corpus name the source
// they read, so a grant with no cluster target cannot read them.
func TestLocalSourceReadsRequireTheSourceTarget(t *testing.T) {
	rec := decisionRec("tenant-a", "private-pod")
	cfg := Config{Root: t.TempDir(), AuditPath: writeDecisionAudit(t, rec)}

	ownerNoTarget := ownerGrant("owner", []string{"tenant-a"})
	ownerNoTarget.Targets = nil
	noTarget := newAuthFixture(t, cfg, ownerNoTarget,
		operatorGrant("op", []string{wildcardScope}, []string{}),
	)
	granted := newAuthFixture(t, cfg,
		ownerGrant("owner", []string{"tenant-a"}),
		operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}),
	)

	// Owner surfaces read the default decision-audit source.
	for _, path := range []string{"/api/owner/events?tenant=tenant-a", "/api/owner/tenants"} {
		w := noTarget.do(noTarget.albReqAs(t, http.MethodGet, path, "", "owner"))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s with no target grant: got %d, want 403\n%s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "private-pod") {
			t.Fatalf("%s disclosed audit data in its denial: %s", path, w.Body.String())
		}
		// Positive control: the same owner WITH the default target reads its own tenant.
		if w := granted.do(granted.albReqAs(t, http.MethodGet, path, "", "owner")); w.Code != http.StatusOK {
			t.Fatalf("%s with the default target: %d %s", path, w.Code, w.Body.String())
		}
	}

	// The attack ledger, the audit aggregates and the private corpus read the same local source.
	local := []string{
		"/api/attack-results", "/api/attack-monitoring", "/api/cost-timeseries",
		"/api/effectiveness", "/api/reports", "/api/rawlog", "/api/redteam/findings", "/api/version",
	}
	for _, path := range local {
		if w := noTarget.do(noTarget.albReqAs(t, http.MethodGet, path, "", "op")); w.Code != http.StatusForbidden {
			t.Errorf("%s with no target grant: got %d, want 403\n%s", path, w.Code, w.Body.String())
		}
		if w := granted.do(granted.albReqAs(t, http.MethodGet, path, "", "op")); w.Code == http.StatusForbidden {
			t.Errorf("%s must stay available with the source's target granted: %s", path, w.Body.String())
		}
	}

	// Shared catalogue metadata describes the product, not a source, and stays available.
	for _, path := range []string{"/api/catalog", "/api/suites", "/api/threat-matrix", "/api/handlers"} {
		if w := noTarget.do(noTarget.albReqAs(t, http.MethodGet, path, "", "op")); w.Code == http.StatusForbidden {
			t.Errorf("%s is shared product metadata and must stay available: %s", path, w.Body.String())
		}
	}
}

// Query aliases for one cluster target resolve ONCE. Checking each alias separately made an
// omitted alias mean "default", so an identity granted only a remote cluster was refused for
// naming that cluster explicitly.
func TestTargetAliasesResolveOnce(t *testing.T) {
	// This grant holds ONE remote cluster and deliberately NOT the default.
	remoteOnly := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{"remote-eks"}))
	for _, path := range []string{"/api/cost?target=remote-eks", "/api/cost?context=remote-eks"} {
		if w := remoteOnly.do(remoteOnly.albReqAs(t, http.MethodGet, path, "", "op")); w.Code == http.StatusForbidden {
			t.Fatalf("%s: a grant for remote-eks must not additionally require the default target: %s", path, w.Body.String())
		}
	}
	// Naming a cluster outside the grant is still refused through either alias.
	for _, path := range []string{"/api/cost?target=other-eks", "/api/cost?context=other-eks"} {
		if w := remoteOnly.do(remoteOnly.albReqAs(t, http.MethodGet, path, "", "op")); w.Code != http.StatusForbidden {
			t.Fatalf("%s: got %d, want 403\n%s", path, w.Code, w.Body.String())
		}
	}
	// And a default-only grant still reaches the default cluster (positive control).
	defaultOnly := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}))
	if w := defaultOnly.do(defaultOnly.albReqAs(t, http.MethodGet, "/api/cost", "", "op")); w.Code == http.StatusForbidden {
		t.Fatalf("default-only grant on the default cluster: %s", w.Body.String())
	}
}

// /api/cost is a COMPOSITE of three sources with different owners. A grant for a remote cluster
// authorizes that cluster's pricing and nothing else: it must not pull in this console's own
// decision audit or its local benchmark corpus.
func TestCompositeCostSourcesAreAuthorizedSeparately(t *testing.T) {
	// Two real audit records an hour apart => a measurable actuation rate of 2/hr.
	first := decisionRec("tenant-a", "private-pod")
	second := decisionRec("tenant-a", "private-pod")
	first.Time = time.Date(2026, 9, 10, 20, 0, 0, 0, time.UTC)
	second.Time = first.Time.Add(time.Hour)
	cfg := Config{Root: t.TempDir(), AuditPath: writeDecisionAudit(t, first, second)}

	read := func(f *authFixture, subject, target string) (int, map[string]any) {
		t.Helper()
		w := f.do(f.albReqAs(t, http.MethodGet, "/api/cost?target="+target, "", subject))
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("cost body: %v (%s)", err, w.Body.String())
		}
		return w.Code, body
	}

	// Positive control FIRST: a grant on this console's own cluster measures the real rate, so
	// the fixture genuinely produces the figure the remote case below must not receive.
	local := newAuthFixture(t, cfg, operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}))
	code, body := read(local, "op", defaultTargetID)
	if code != http.StatusOK || body["actuationRatePerHr"] != float64(2) {
		t.Fatalf("local-source positive control: %d rate=%v", code, body["actuationRatePerHr"])
	}

	// A remote-only grant reads the remote cluster's pricing and NOTHING local.
	remote := newAuthFixture(t, cfg, operatorGrant("op", []string{wildcardScope}, []string{"remote-eks"}))
	code, body = read(remote, "op", "remote-eks")
	if code != http.StatusOK {
		t.Fatalf("a remote-only grant must still read its own cluster's pricing: %d", code)
	}
	if _, present := body["actuationRatePerHr"]; present {
		t.Fatalf("remote-only grant received the local audit's actuation rate: %v", body["actuationRatePerHr"])
	}
	if _, present := body["pricing"]; !present {
		t.Fatal("the remote cluster's pricing must still be served to a grant that holds it")
	}
	// Withholding is stated, not silently zeroed.
	withheld, _ := body["withheld"].([]any)
	if len(withheld) == 0 {
		t.Fatalf("withheld figures must be named in the response: %v", body)
	}

	// A tenant-limited grant on the local cluster gets the audit rate (tenant-filtered) but NOT
	// the unattributable benchmark corpus.
	scoped := newAuthFixture(t, cfg, operatorGrant("op", []string{"tenant-a"}, []string{defaultTargetID}))
	code, body = read(scoped, "op", defaultTargetID)
	if code != http.StatusOK || body["actuationRatePerHr"] != float64(2) {
		t.Fatalf("tenant-limited local grant: %d rate=%v", code, body["actuationRatePerHr"])
	}
	if _, present := body["totalSavings"]; present {
		t.Fatalf("the private benchmark corpus reached a tenant-limited grant: %v", body)
	}
}

// A request that NAMES a cluster must never be served from a different one. The in-cluster
// fallback is legitimate only for the spellings that mean "this console's own cluster".
func TestNamedClusterIsNeverSubstitutedByTheDefault(t *testing.T) {
	// No kubeconfig and no in-cluster environment: nothing can resolve.
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	if _, err := restConfigFor("remote-eks"); err == nil {
		t.Fatal("an explicitly named, unreachable cluster must be an error")
	} else if !strings.Contains(err.Error(), "remote-eks") {
		t.Fatalf("the error must name the cluster that could not be reached: %v", err)
	}
	// The local aliases mean "this pod's own cluster" — a legitimate default. With nothing
	// configured at all they fail for the ordinary reason rather than substituting a cluster.
	for _, name := range []string{"", inClusterTargetID, defaultTargetID} {
		if _, err := restConfigFor(name); err == nil {
			t.Fatalf("restConfigFor(%q) unexpectedly resolved with no configuration at all", name)
		}
	}
}

// The three spellings of "this console's own cluster" are ONE resource everywhere: in a grant, in
// the effective destination, and in the credential resolver. A documented ["default"] grant has
// to cover the id the dashboard's selector actually sends, which in a deployed pod is
// "in-cluster".
func TestLocalClusterAliasesAreOneResource(t *testing.T) {
	for _, spelling := range []string{"", inClusterTargetID, defaultTargetID} {
		if got := normalizeTargetID(spelling); got != defaultTargetID {
			t.Fatalf("normalizeTargetID(%q) = %q, want %q", spelling, got, defaultTargetID)
		}
	}
	if normalizeTargetID("remote-eks") != "remote-eks" {
		t.Fatal("a real cluster name must not be collapsed into the local alias")
	}

	// A grant written the documented way reaches all three spellings, and nothing else.
	granted := testPrincipal([]Role{RoleOperator}, []string{wildcardScope}, []string{defaultTargetID})
	for _, spelling := range []string{"", inClusterTargetID, defaultTargetID} {
		if !granted.AllowsTarget(spelling) {
			t.Fatalf("a [\"default\"] grant must cover the %q spelling of its own cluster", spelling)
		}
	}
	if granted.AllowsTarget("remote-eks") {
		t.Fatal("a local-cluster grant must not reach a remote cluster")
	}

	// End to end: the selector's "in-cluster" id is served to a documented default grant.
	f := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{defaultTargetID}))
	for _, q := range []string{"", "?target=" + inClusterTargetID, "?target=" + defaultTargetID} {
		if w := f.do(f.albReqAs(t, http.MethodGet, "/api/pricing"+q, "", "op")); w.Code == http.StatusForbidden {
			t.Fatalf("/api/pricing%s for a [\"default\"] grant: %s", q, w.Body.String())
		}
	}
	// And a grant for ONLY the in-cluster spelling reaches the same cluster under any spelling.
	f2 := newAuthFixture(t, Config{Root: "."}, operatorGrant("op", []string{wildcardScope}, []string{inClusterTargetID}))
	if w := f2.do(f2.albReqAs(t, http.MethodGet, "/api/pricing?target="+defaultTargetID, "", "op")); w.Code == http.StatusForbidden {
		t.Fatalf("an [\"in-cluster\"] grant must reach the same cluster spelled \"default\": %s", w.Body.String())
	}
	if w := f2.do(f2.albReqAs(t, http.MethodGet, "/api/pricing?target=remote-eks", "", "op")); w.Code != http.StatusForbidden {
		t.Fatalf("a local-cluster grant reached remote-eks: %d", w.Code)
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

// waitForRunProcess blocks until the launcher has registered the run's process, which is when
// RunManager.Stop can actually signal it.
func waitForRunProcess(t *testing.T, rm *RunManager, id string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		rm.mu.Lock()
		cmd := rm.procs[id]
		rm.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("run %s never registered a process within %s", id, within)
}

// waitForRunToLeaveRunning blocks until the launcher has released the run's concurrency slot.
func waitForRunToLeaveRunning(t *testing.T, rm *RunManager, id string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if st, ok := rm.Status(id); ok && st.State != "running" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	st, _ := rm.Status(id)
	t.Fatalf("run %s did not leave the running state within %s (state=%v)", id, within, st)
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
