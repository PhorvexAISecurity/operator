package console

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func natsBaselineEvidenceFixture(t *testing.T) (string, map[string]any) {
	t.Helper()
	dir := t.TempDir()
	nonce := "0123456789abcdef01234567"
	payloadHash := hashNATSBytes([]byte("phorvex-owned-nats-exposure:" + nonce))
	serverID := "N" + strings.Repeat("A", 55)
	artifact := map[string]any{"schema": "nats-baseline-v1", "runId": "run-4", "nonce": nonce, "namespace": "phorvex-nats-exposure-fixture", "namespaceUID": "ns-uid", "observerPodUID": "obs-uid", "observerConfigMapUID": "cm-uid", "observerContainerID": "container://one", "observerImageID": "console@sha256:" + strings.Repeat("b", 64), "route": map[string]any{"clusterUID": "cluster-uid", "serviceUID": "service-uid", "statefulSetUID": "sts-uid", "configMapUID": "nats-cm-uid", "endpointSliceUID": "slice-uid", "nodeUID": "node-uid", "configSHA256": strings.Repeat("a", 64), "configSourceAttestation": "DECLARED_CM_ONLY", "brokers": []any{map[string]any{"uid": "broker-uid", "serverID": serverID}}}, "subscription": map[string]any{"kind": "subscription", "status": "READY", "subject": "cat.exposure." + nonce, "nonce": nonce, "serverID": serverID, "flushed": true}, "observation": map[string]any{"kind": "observation", "status": "EXACT_PAYLOAD_RECEIVED", "subject": "cat.exposure." + nonce, "nonce": nonce, "serverID": serverID, "payloadSHA256": payloadHash, "nonceHeaderMatches": true, "payloadHashMatches": true}, "protocol": map[string]any{"nonce": nonce, "stream": "CAT_" + nonce, "subject": "cat.exposure." + nonce, "consumer": "CAT_" + nonce + "_C", "publishAttempted": true, "pubAckSequence": 1, "payloadSHA256": payloadHash, "storedPayloadSHA256": payloadHash, "legitimateAcked": true, "cleanup": "CONFIRMED_ABSENT"}, "configurationFinding": "EXPOSED", "validity": "MEASUREMENT_COMPLETE", "cleanup": "OBSERVER_AND_STREAM_CONFIRMED_ABSENT", "brainMode": "NO_SIGNAL", "securityEfficacy": "NOT_EVALUATED"}
	writeNATSReaderFixtures(t, dir, artifact, true)
	return dir, artifact
}
func writeNATSReaderFixtures(t *testing.T, dir string, a map[string]any, terminal bool) {
	t.Helper()
	raw, _ := json.Marshal(a)
	if err := os.WriteFile(filepath.Join(dir, "nats-baseline.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	terminalReceipt := map[string]any{"schema": "nats-baseline-terminal-v1", "runId": a["runId"], "nonce": a["nonce"], "namespace": a["namespace"], "namespaceUID": a["namespaceUID"], "artifactSHA256": hashNATSBytes(raw), "fixtureResourcesAbsent": terminal, "namespacePreserved": terminal}
	tr, _ := json.Marshal(terminalReceipt)
	if err := os.WriteFile(filepath.Join(dir, "nats-baseline-terminal.json"), tr, 0600); err != nil {
		t.Fatal(err)
	}
	metric := map[string]any{"scenario": "c2-nats-uncredentialed-exposure", "defender": "d-nomtd", "trial": 1, "scenarioBenignControl": true, "benchmarkEvidence": map[string]string{"nats_baseline_artifact_sha256": hashNATSBytes(raw)}}
	mr, _ := json.Marshal(metric)
	if err := os.WriteFile(filepath.Join(dir, "metrics.jsonl"), append(mr, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	provenance := map[string]any{"namespace": a["namespace"], "run": map[string]any{"complete": terminal, "finalTeardown": map[string]any{"attempted": true, "verified": terminal}}}
	pr, _ := json.Marshal(provenance)
	if err := os.WriteFile(filepath.Join(dir, "provenance.json"), pr, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestNATSConfigurationResultJoinsRemoteMetricAndTerminalCleanup(t *testing.T) {
	dir, a := natsBaselineEvidenceFixture(t)
	got, err := readNATSConfigurationResult(dir, "run-4", a["namespace"].(string))
	if err != nil || !got.Accepted || got.Finding != "EXPOSED" || got.BrokerPodUID != "broker-uid" || got.SecurityEfficacy != "NOT_EVALUATED" {
		t.Fatalf("valid synthetic control rejected: %+v %v", got, err)
	}
	writeNATSReaderFixtures(t, dir, a, false)
	got, err = readNATSConfigurationResult(dir, "run-4", a["namespace"].(string))
	if err != nil || got.Accepted || got.Finding != "UNKNOWN" || got.ObservedFinding != "EXPOSED" || got.FixtureResourcesCleanup != "UNVERIFIED" {
		t.Fatalf("raw exposure should remain visible but unaccepted after terminal failure: %+v %v", got, err)
	}
	writeNATSReaderFixtures(t, dir, a, true)
	a["runId"] = "run-5"
	writeNATSReaderFixtures(t, dir, a, true)
	got, err = readNATSConfigurationResult(dir, "run-4", a["namespace"].(string))
	if err != nil || got.Accepted {
		t.Fatalf("another run artifact accepted: %+v %v", got, err)
	}
}
func TestNATSConfigurationResultRejectsForgedFindingAndMetricDigest(t *testing.T) {
	dir, a := natsBaselineEvidenceFixture(t)
	route := a["route"].(map[string]any)
	route["endpointSliceUID"] = ""
	writeNATSReaderFixtures(t, dir, a, true)
	if got, _ := readNATSConfigurationResult(dir, "run-4", a["namespace"].(string)); got.Accepted {
		t.Fatal("missing exact serving route identity accepted")
	}
	route["endpointSliceUID"] = "slice-uid"
	a["configurationFinding"] = "NOT_EXPOSED_IN_THIS_CONTROL"
	writeNATSReaderFixtures(t, dir, a, true)
	got, _ := readNATSConfigurationResult(dir, "run-4", a["namespace"].(string))
	if got.Accepted || got.Finding != "UNKNOWN" {
		t.Fatal("contradictory finding accepted")
	}
	a["configurationFinding"] = "EXPOSED"
	writeNATSReaderFixtures(t, dir, a, true)
	metricPath := filepath.Join(dir, "metrics.jsonl")
	raw, _ := os.ReadFile(metricPath)
	var metric map[string]any
	_ = json.Unmarshal(raw, &metric)
	metric["benchmarkEvidence"] = map[string]string{"nats_baseline_artifact_sha256": strings.Repeat("0", 64)}
	raw, _ = json.Marshal(metric)
	_ = os.WriteFile(metricPath, append(raw, '\n'), 0600)
	got, _ = readNATSConfigurationResult(dir, "run-4", a["namespace"].(string))
	if got.Accepted || got.Finding != "UNKNOWN" {
		t.Fatal("wrong metric artifact digest accepted")
	}
}

func TestNATSConfigurationReaderRejectsDuplicateAndDefenseFields(t *testing.T) {
	for _, raw := range []string{
		`{"nonce":"first","nonce":"second"}`,
		`{"protocol":{"decisionID":"fabricated"}}`,
		`{"eventUID":"fabricated"}`,
	} {
		if err := rejectAmbiguousNATSJSON([]byte(raw)); err == nil {
			t.Errorf("ambiguous or invented defense field accepted: %s", raw)
		}
	}
}

func TestNATSRunScopeRequiresBrokerAndFixtureTenantAfterGrantRevocation(t *testing.T) {
	own := runOwnership{Target: "reviewed-dev-cluster", Tenant: "nats", FixtureTenant: "phorvex-nats-exposure-fixture", Config: natsBaselineConfig}
	principal := &Principal{Targets: []string{"reviewed-dev-cluster"}, Tenants: []string{"nats", "phorvex-nats-exposure-fixture"}}
	if !runVisibleTo(principal, own) {
		t.Fatal("both granted scopes rejected")
	}
	if runVisibleTo(&Principal{Targets: []string{"unrelated-cluster"}, Tenants: []string{"nats", "phorvex-nats-exposure-fixture"}}, own) {
		t.Fatal("unrelated cluster grant accepted")
	}
	principal.Tenants = []string{"nats"}
	if runVisibleTo(principal, own) {
		t.Fatal("run remained visible after fixture grant revocation")
	}
	principal.Tenants = []string{"phorvex-nats-exposure-fixture"}
	if runVisibleTo(principal, own) {
		t.Fatal("run remained visible after broker grant revocation")
	}
	principal.Tenants = []string{"nats", "phorvex-nats-exposure-fixture"}
	own.FixtureTenant = ""
	if runVisibleTo(principal, own) {
		t.Fatal("incomplete persisted NATS scope accepted")
	}
	own.Config = "fpprobe"
	if !runVisibleTo(&Principal{Targets: []string{"reviewed-dev-cluster"}, Tenants: []string{"nats"}}, own) {
		t.Fatal("ordinary suite scope changed")
	}
}

func TestNATSSuiteDestinationBindsBothTenantsAndExplicitInClusterMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, allowedConfigs[natsBaselineConfig].File)
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("context: reviewed-dev-cluster\nnamespace: phorvex-nats-exposure-fixture\nkubeconfig: ''\nnatsExposureFixture:\n  transport: in-cluster\n")
	rm := NewRunManager(Config{HarnessDir: dir, StateDir: t.TempDir(), NATSExposureEnabled: true, NATSExposureProfileSHA256: profileDigest([]byte("context: reviewed-dev-cluster\nnamespace: phorvex-nats-exposure-fixture\nkubeconfig: ''\nnatsExposureFixture:\n  transport: in-cluster\n"))})
	dest, err := rm.SuiteDestination(natsBaselineConfig)
	if err != nil || len(dest.Tenants) != 2 || dest.Tenants[0] != "nats" || dest.Tenants[1] != "phorvex-nats-exposure-fixture" || len(dest.Targets) != 2 || dest.Targets[1] != "reviewed-dev-cluster" || dest.ScopeTenant != "nats" || dest.SuiteSHA256 == "" {
		t.Fatalf("destination did not bind broker and fixture: %+v %v", dest, err)
	}
	write("context: in-cluster\nnamespace: phorvex-nats-exposure-fixture\nnatsExposureFixture:\n  transport: in-cluster\n")
	rm.cfg.NATSExposureProfileSHA256 = profileDigest([]byte("context: in-cluster\nnamespace: phorvex-nats-exposure-fixture\nnatsExposureFixture:\n  transport: in-cluster\n"))
	if _, err := rm.SuiteDestination(natsBaselineConfig); err == nil {
		t.Fatal("other context accepted for explicit NATS suite")
	}
	write("context: reviewed-dev-cluster\nnamespace: unrelated\nnatsExposureFixture:\n  transport: in-cluster\n")
	rm.cfg.NATSExposureProfileSHA256 = profileDigest([]byte("context: reviewed-dev-cluster\nnamespace: unrelated\nnatsExposureFixture:\n  transport: in-cluster\n"))
	if _, err := rm.SuiteDestination(natsBaselineConfig); err == nil {
		t.Fatal("other fixture namespace accepted")
	}
}

func TestNATSNoEffectRequiresExactProducerPhaseAndGeneratedConfig(t *testing.T) {
	out := t.TempDir()
	configPath := filepath.Join(out, "generated.yaml")
	configBytes := []byte("namespace: phorvex-nats-exposure-fixture\nnatsExposureFixture:\n  runID: run-4\n  nonce: 0123456789abcdef01234567\n  clusterUID: cluster-uid\n")
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	receipt := map[string]any{"schema": "nats-baseline-no-effect-v1", "runId": "run-4", "nonce": "0123456789abcdef01234567", "namespace": "phorvex-nats-exposure-fixture", "namespaceUID": "ns-uid", "clusterUID": "cluster-uid", "phase": "SCENARIO_PRE_EFFECT_EXIT", "effectStarted": false}
	write := func() {
		t.Helper()
		raw, _ := json.Marshal(receipt)
		if err := os.WriteFile(filepath.Join(out, "nats-baseline-no-effect.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if !readNATSNoEffect(out, "run-4", "phorvex-nats-exposure-fixture", configPath) {
		t.Fatal("exact pre-effect terminal refused")
	}
	receipt["effectStarted"] = true
	write()
	if readNATSNoEffect(out, "run-4", "phorvex-nats-exposure-fixture", configPath) {
		t.Fatal("started effect accepted as no-effect")
	}
	receipt["effectStarted"] = false
	receipt["namespaceUID"] = ""
	write()
	if readNATSNoEffect(out, "run-4", "phorvex-nats-exposure-fixture", configPath) {
		t.Fatal("missing exact fixture namespace UID accepted")
	}
	receipt["phase"] = "PRE_MATRIX_REFUSED"
	write()
	if !readNATSNoEffect(out, "run-4", "phorvex-nats-exposure-fixture", configPath) {
		t.Fatal("pre-matrix refusal rejected")
	}
	receipt["clusterUID"] = "other-cluster"
	write()
	if readNATSNoEffect(out, "run-4", "phorvex-nats-exposure-fixture", configPath) {
		t.Fatal("wrong cluster accepted as no-effect")
	}
}

func TestNATSRunRetrySafetySeparatesMeasurementFromCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, script           string
		completeEvidence       bool
		wantState, wantCleanup string
		wantUnsafe             bool
	}{
		{name: "launch-failure", script: "", wantState: "error", wantCleanup: "NO_EFFECT"},
		{name: "incomplete-clean-measurement", script: "#!/bin/sh\nexit 1\n", completeEvidence: true, wantState: "partial", wantCleanup: "VERIFIED"},
		{name: "unknown-cleanup", script: "#!/bin/sh\nexit 1\n", wantState: "partial", wantCleanup: "UNVERIFIED", wantUnsafe: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			harnessDir := t.TempDir()
			harnessBin := filepath.Join(harnessDir, "harness")
			if tc.script != "" {
				if err := os.WriteFile(harnessBin, []byte(tc.script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			rm := NewRunManager(Config{HarnessDir: harnessDir, StateDir: state, HarnessBin: harnessBin})
			const id = "run-4"
			const outName = "out-nats-run-4"
			rm.runs[id] = &RunStatus{ID: id, Config: natsBaselineConfig, State: "running", Namespace: "phorvex-nats-exposure-fixture"}
			rm.runOut[id] = outName
			rm.active = 1
			if tc.completeEvidence {
				fixture, _ := natsBaselineEvidenceFixture(t)
				out := rm.cfg.runOutputPath(outName)
				if err := os.MkdirAll(out, 0750); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"nats-baseline.json", "nats-baseline-terminal.json", "metrics.jsonl", "provenance.json"} {
					raw, err := os.ReadFile(filepath.Join(fixture, name))
					if err != nil {
						t.Fatal(err)
					}
					if name == "provenance.json" {
						var p map[string]any
						_ = json.Unmarshal(raw, &p)
						p["run"].(map[string]any)["complete"] = false
						raw, _ = json.Marshal(p)
					}
					if err := os.WriteFile(filepath.Join(out, name), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			rm.run(id, suite{File: "irrelevant.yaml", OutDir: outName}, false)
			st := rm.runs[id]
			if st.State != tc.wantState || st.CleanupStatus != tc.wantCleanup || st.UnsafeToRetry != tc.wantUnsafe {
				t.Fatalf("wrong retry classification: %+v", st)
			}
		})
	}
}

func TestNATSCatalogRoutesOnlyThroughNamedSuite(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "harness")
	listing := "#!/bin/sh\nprintf '%s\\n' 'Registered scenarios:' ' - c2-nats-uncredentialed-exposure [ModernUnsupported] R6=R6CannotRespond realism=executable benign=true declared=[] exercised=[] caps=[] limits=synthetic'\n"
	if err := os.WriteFile(bin, []byte(listing), 0700); err != nil {
		t.Fatal(err)
	}
	profile := []byte("context: reviewed-dev-cluster\nnamespace: phorvex-nats-exposure-fixture\nkubeconfig: ''\nnatsExposureFixture:\n  transport: in-cluster\n")
	if err := os.WriteFile(filepath.Join(dir, allowedConfigs[natsBaselineConfig].File), profile, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{HarnessDir: dir, HarnessBin: bin, StateDir: t.TempDir(), NATSExposureEnabled: true, NATSExposureProfileSHA256: profileDigest(profile)}
	items := cfg.Catalog()
	found := false
	for _, it := range items {
		if it.Name == "c2-nats-uncredentialed-exposure" {
			found = true
			if it.LaunchKind != "named-suite" || it.Profile != natsBaselineConfig || !it.Available || it.ClaimClass != "functional" || it.Product != "application" {
				t.Fatalf("generic or misclassified NATS catalogue entry: %+v", it)
			}
		}
	}
	if !found {
		t.Fatal("NATS registry entry missing from catalogue")
	}
	rm := NewRunManager(cfg)
	if _, err := rm.StartScenario([]string{"c2-nats-uncredentialed-exposure"}, false, false, "target", "", "", "actor"); err == nil || !strings.Contains(err.Error(), "named suite") {
		t.Fatalf("generic scenario bypassed fixed NATS suite: %v", err)
	}
}

func TestNATSReconciliationReaderRejectsStaleAttemptAndChangedIdentity(t *testing.T) {
	out := t.TempDir()
	configPath := filepath.Join(out, "generated.yaml")
	configBytes := []byte("namespace: phorvex-nats-exposure-fixture\nnatsExposureFixture:\n  runID: run-4\n  nonce: 0123456789abcdef01234567\n  clusterUID: cluster-uid\n")
	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		t.Fatal(err)
	}
	route := map[string]any{"clusterUID": "cluster-uid", "serviceUID": "service-uid"}
	anchor := map[string]any{"schema": "nats-baseline-anchor-v1", "runId": "run-4", "nonce": "0123456789abcdef01234567", "namespace": "phorvex-nats-exposure-fixture", "namespaceUID": "ns-uid", "clusterUID": "cluster-uid", "route": route, "observerName": "nats-observer-0123456789abcdef01234567", "stream": "CAT_0123456789abcdef01234567", "pid": 99999999, "processStartTicks": "123", "fenceIdentity": "flock-v1:1:2:0123456789abcdef0123456789abcdef"}
	anchorRaw, _ := json.Marshal(anchor)
	if err := os.WriteFile(filepath.Join(out, "nats-baseline-anchor.json"), anchorRaw, 0600); err != nil {
		t.Fatal(err)
	}
	routeRaw, _ := json.Marshal(route)
	const attempt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	receipt := map[string]any{"schema": "nats-baseline-reconciliation-v1", "runId": "run-4", "attemptId": attempt, "nonce": "0123456789abcdef01234567", "namespace": "phorvex-nats-exposure-fixture", "namespaceUID": "ns-uid", "clusterUID": "cluster-uid", "anchorSHA256": hashNATSBytes(anchorRaw), "routeSHA256": hashNATSBytes(routeRaw), "fixtureResourcesAbsent": true, "streamAbsent": true, "originalProcessGone": true, "safeToRetry": true}
	write := func() {
		t.Helper()
		raw, _ := json.Marshal(receipt)
		if err := os.WriteFile(filepath.Join(out, "nats-baseline-reconciliation.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if !readNATSReconciliation(out, "run-4", "phorvex-nats-exposure-fixture", configPath, attempt) {
		t.Fatal("exact reconciliation receipt rejected")
	}
	if readNATSReconciliation(out, "run-4", "phorvex-nats-exposure-fixture", configPath, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatal("stale reconciliation attempt accepted")
	}
	receipt["streamAbsent"] = false
	write()
	if readNATSReconciliation(out, "run-4", "phorvex-nats-exposure-fixture", configPath, attempt) {
		t.Fatal("unverified stream absence accepted")
	}
	receipt["streamAbsent"] = true
	receipt["namespaceUID"] = "replacement"
	write()
	if readNATSReconciliation(out, "run-4", "phorvex-nats-exposure-fixture", configPath, attempt) {
		t.Fatal("replacement namespace accepted")
	}
}

func TestNATSReconcileRetainsPartialOutcomeAndOnlyClearsVerifiedCleanup(t *testing.T) {
	for _, verified := range []bool{true, false} {
		t.Run(map[bool]string{true: "exact-absence", false: "unknown-cleanup"}[verified], func(t *testing.T) {
			state := t.TempDir()
			rm := NewRunManager(Config{StateDir: state, HarnessDir: t.TempDir()})
			const id = "run-4"
			const namespace = "phorvex-nats-exposure-fixture"
			rm.runs[id] = &RunStatus{ID: id, Config: natsBaselineConfig, State: "partial", Namespace: namespace, UnsafeToRetry: true, Outcome: "INCONCLUSIVE"}
			rm.runOut[id] = "out-nats-run-4"
			out := rm.cfg.runOutputPath(rm.runOut[id])
			if err := os.MkdirAll(out, 0750); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(rm.cfg.runsDir(), "configs", id+".yaml")
			if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, []byte("namespace: "+namespace+"\nnatsExposureFixture:\n  runID: run-4\n  nonce: 0123456789abcdef01234567\n  clusterUID: cluster-uid\n"), 0600); err != nil {
				t.Fatal(err)
			}
			route := map[string]any{"clusterUID": "cluster-uid", "serviceUID": "service-uid"}
			anchor := map[string]any{"schema": "nats-baseline-anchor-v1", "runId": id, "nonce": "0123456789abcdef01234567", "namespace": namespace, "namespaceUID": "ns-uid", "clusterUID": "cluster-uid", "route": route, "observerName": "nats-observer-0123456789abcdef01234567", "stream": "CAT_0123456789abcdef01234567", "pid": 99999999, "processStartTicks": "123", "fenceIdentity": "flock-v1:1:2:0123456789abcdef0123456789abcdef"}
			anchorRaw, _ := json.Marshal(anchor)
			if err := os.WriteFile(filepath.Join(out, "nats-baseline-anchor.json"), anchorRaw, 0600); err != nil {
				t.Fatal(err)
			}
			routeRaw, _ := json.Marshal(route)
			called := false
			err := rm.reconcileNATSWithRunner(id, "actor", func(ctx context.Context, gotConfig, gotOut, gotID, attempt string) error {
				called = true
				if gotConfig != configPath || gotOut != out || gotID != id || len(attempt) != 32 {
					t.Fatalf("reconciler dispatched wrong identity: %q %q %q %q", gotConfig, gotOut, gotID, attempt)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("reconciliation lacks finite timeout")
				}
				if !verified {
					return nil
				}
				receipt := map[string]any{"schema": "nats-baseline-reconciliation-v1", "runId": id, "attemptId": attempt, "nonce": "0123456789abcdef01234567", "namespace": namespace, "namespaceUID": "ns-uid", "clusterUID": "cluster-uid", "anchorSHA256": hashNATSBytes(anchorRaw), "routeSHA256": hashNATSBytes(routeRaw), "fixtureResourcesAbsent": true, "streamAbsent": true, "originalProcessGone": true, "safeToRetry": true}
				raw, _ := json.Marshal(receipt)
				return os.WriteFile(filepath.Join(out, "nats-baseline-reconciliation.json"), raw, 0600)
			})
			if !called {
				t.Fatal("read-only reconciliation runner not invoked")
			}
			st := rm.runs[id]
			if verified && (err != nil || st.UnsafeToRetry || st.CleanupStatus != "VERIFIED_READ_ONLY") {
				t.Fatalf("verified cleanup not retained: %+v %v", st, err)
			}
			if !verified && (err == nil || !st.UnsafeToRetry || st.CleanupStatus != "UNVERIFIED") {
				t.Fatalf("unknown cleanup admitted: %+v %v", st, err)
			}
			if st.State != "partial" || st.Outcome != "INCONCLUSIVE" {
				t.Fatalf("original outcome promoted: %+v", st)
			}
			if rm.active != 0 {
				t.Fatal("reconciliation did not release run slot")
			}
		})
	}
}
