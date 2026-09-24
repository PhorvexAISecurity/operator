package console

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
)

func mongoTestWrite(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func mongoTestJSON(t *testing.T, path string, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	mongoTestWrite(t, path, raw)
	return raw
}

func mongoTestDecision(at time.Time, source mongoSourceEvidence) audit.Record {
	trace := caseTraceValidTrace(at, false, false)
	trace.DecisionID = "mongo-decision"
	trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID = mongoExposureNamespace, "mongo-policy", source.PolicyUID
	trace.AssetNamespace, trace.AssetName, trace.AssetUID = mongoExposureNamespace, source.PodName, source.PodUID
	trace.TenantName = "mongo"
	trace.NoopReason = "reactive-only: no direct foothold"
	trace.DispatchOutcome = model.DispatchNotAttempted
	for _, action := range model.MutatingActions {
		trace.ActionStatus = append(trace.ActionStatus, model.DecisionActionStatusV3{Action: string(action), Status: model.ActionStatusNotEnabled, ExclusionKind: model.ExclusionNotEnabled})
	}
	return audit.Record{Kind: "phorvex.decision", Time: at, Tenant: "mongo", Namespace: mongoExposureNamespace, Pod: source.PodName,
		Action: string(model.ActionNoop), DispatchOutcome: model.DispatchNotAttempted, Reason: trace.NoopReason, DecisionTrace: trace}
}

// The artifact, terminal and original mongosh line begin as bytes emitted by
// runMongoExposureWith's fake API/store lifecycle test in the harness module.
func mongoTestProducerArtifact(t *testing.T, out string, started time.Time) mongoArtifactEvidence {
	t.Helper()
	base := filepath.Join("testdata", "mongo_producer")
	raw, err := os.ReadFile(filepath.Join(base, "mongo-exposure.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a mongoArtifactEvidence
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	a.StartedAt = started.UTC().Format(time.RFC3339Nano)
	a.ObservationEndedAt = started.Add(2 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	a.FinishedAt = started.Add(3 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	artifactRaw := mongoTestJSON(t, filepath.Join(out, "mongo-exposure.json"), a)
	terminalRaw, err := os.ReadFile(filepath.Join(base, "mongo-exposure-terminal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var terminal mongoTerminalEvidence
	if err := json.Unmarshal(terminalRaw, &terminal); err != nil {
		t.Fatal(err)
	}
	terminal.ArtifactSHA256 = mongoHash(artifactRaw)
	mongoTestJSON(t, filepath.Join(out, "mongo-exposure-terminal.json"), terminal)
	reply, err := os.ReadFile(filepath.Join(base, "mongo-exposure-original-reply.log"))
	if err != nil {
		t.Fatal(err)
	}
	mongoTestWrite(t, filepath.Join(out, "mongo-exposure-original-reply.log"), reply)
	phaseRaw, err := os.ReadFile(filepath.Join(base, "mongo-exposure-phases.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var phases bytes.Buffer
	for i, line := range bytes.Split(bytes.TrimSuffix(phaseRaw, []byte{'\n'}), []byte{'\n'}) {
		var phase mongoPhaseEvidence
		if err := json.Unmarshal(line, &phase); err != nil {
			t.Fatal(err)
		}
		at := started.Add(time.Duration(i+1) * 100 * time.Microsecond)
		if i >= 7 {
			at = started.Add(2*time.Millisecond + time.Duration(i-6)*100*time.Microsecond)
		}
		phase.At = at.Format(time.RFC3339Nano)
		encoded, err := json.Marshal(phase)
		if err != nil {
			t.Fatal(err)
		}
		phases.Write(encoded)
		phases.WriteByte('\n')
	}
	mongoTestWrite(t, filepath.Join(out, "mongo-exposure-phases.jsonl"), phases.Bytes())
	return a
}

func TestMongoExposureAuthenticatedSealAndImmutableResult(t *testing.T) {
	dir := t.TempDir()
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	auditPath := filepath.Join(dir, "audit.jsonl")
	mongoTestWrite(t, auditPath, []byte(strings.Repeat("{\"kind\":\"heartbeat\"}\n", 20)))
	sourceServer := audittransport.ServerConfig{AuditPath: auditPath, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test", MaxBackups: 2}
	ts := httptest.NewUnstartedServer(sourceServer.Handler())
	ts.TLS = sourceServer.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: filepath.Join(dir, "state"), AuditSource: client, AuditSourceIdentity: ts.URL + "#audit-source.test", MongoExposureEnabled: true}
	rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{}, runOut: map[string]string{}}
	id, outName := "run-1", "out-mongo-test"
	out := cfg.runOutputPath(outName)
	runtime := mongoRuntimeConfig{Context: "reviewed-dev-cluster", Namespace: mongoExposureNamespace, OutDir: out}
	runtime.MongoExposureFixture.RunID, runtime.MongoExposureFixture.Nonce, runtime.MongoExposureFixture.ClusterUID = id, strings.Repeat("e", 32), "11111111-1111-4111-8111-111111111111"
	runtime.MongoExposureFixture.MongoImageID, runtime.MongoExposureFixture.ManagerImageID = "mongo-image", "manager-image"
	mongoTestJSON(t, filepath.Join(cfg.runsDir(), "configs", id+".yaml"), runtime)
	if err := rm.captureMongoAuditStart(id, outName); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	a := mongoTestProducerArtifact(t, out, started)
	decision := mongoTestDecision(started.Add(time.Millisecond), a.Source)
	if err := decision.DecisionTrace.Validate(); err != nil {
		t.Fatalf("audit producer trace invalid: %v", err)
	}
	wrongPod := decision
	wrongPod.Pod = "other-pod"
	wrongPolicy := decision
	traceCopy := *decision.DecisionTrace
	wrongPolicy.DecisionTrace = &traceCopy
	wrongPolicy.DecisionTrace.PolicyUID = "other-policy"
	wrongPolicy.DecisionTrace.DecisionID = "other-policy-decision"
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range []audit.Record{wrongPod, wrongPolicy, decision} {
		row, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(row, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond) // the authenticated manifest must follow the producer's final receipt
	startRaw, err := os.ReadFile(filepath.Join(out, "mongo-exposure-audit-start.json"))
	if err != nil {
		t.Fatal(err)
	}
	var start mongoAuditStart
	if err := json.Unmarshal(startRaw, &start); err != nil {
		t.Fatal(err)
	}
	observationEnd, err := time.Parse(time.RFC3339Nano, a.ObservationEndedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, state, _, _, _, err := rm.readMongoAuditWindow(context.Background(), start, a.Source, observationEnd); err != nil {
		t.Fatalf("authenticated audit fixture %s: %v", state, err)
	}
	if err := rm.sealMongoAudit(id, out); err != nil {
		t.Fatal(err)
	}
	rm.runs[id], rm.runOut[id] = &RunStatus{ID: id, Config: mongoExposureConfig, State: "done"}, outName
	result, err := rm.MongoExposureResult(id)
	if err != nil || result == nil || !result.Accepted || result.Finding != "EXPOSED" || result.BrainTrace != "JOINED" || len(result.BrainDecisions) != 1 || result.BrainDecisions[0].PolicyGeneration != 3 || len(result.BrainDecisions[0].CandidateStatuses) != len(model.MutatingActions) {
		t.Fatalf("producer/audit join failed: %+v %v", result, err)
	}
	if err := rm.sealMongoAudit(id, out); err == nil {
		t.Fatal("audit terminal resealed")
	}
	if err := os.Rename(auditPath, auditPath+".1"); err != nil {
		t.Fatal(err)
	}
	mongoTestWrite(t, auditPath, []byte("{\"kind\":\"rotated\"}\n"))
	later, err := rm.MongoExposureResult(id)
	if err != nil || !reflect.DeepEqual(result, later) {
		t.Fatalf("historical projection changed after audit rotation: %+v %v", later, err)
	}
	// A self-consistent replacement terminal still cannot substitute for the
	// original authenticated bytes or their exact source/decision projection.
	originalPath := filepath.Join(out, "mongo-exposure-audit-original.jsonl")
	original, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	mongoTestWrite(t, originalPath, []byte("{\"kind\":\"other\"}\n"))
	if _, err := rm.MongoExposureResult(id); err == nil {
		t.Fatal("changed original audit accepted")
	}
	mongoTestWrite(t, originalPath, original)
	artifactPath := filepath.Join(out, "mongo-exposure.json")
	terminalPath := filepath.Join(out, "mongo-exposure-terminal.json")
	auditTerminalPath := filepath.Join(out, "mongo-exposure-audit-terminal.json")
	replyPath := filepath.Join(out, "mongo-exposure-original-reply.log")
	phasePath := filepath.Join(out, "mongo-exposure-phases.jsonl")
	baselineArtifact, _ := os.ReadFile(artifactPath)
	baselineTerminal, _ := os.ReadFile(terminalPath)
	baselineAudit, _ := os.ReadFile(auditTerminalPath)
	baselineReply, _ := os.ReadFile(replyPath)
	baselinePhases, _ := os.ReadFile(phasePath)
	var baseTerminal mongoTerminalEvidence
	var baseAudit mongoAuditTerminal
	if json.Unmarshal(baselineTerminal, &baseTerminal) != nil || json.Unmarshal(baselineAudit, &baseAudit) != nil {
		t.Fatal("baseline receipts invalid")
	}
	restore := func() {
		mongoTestWrite(t, artifactPath, baselineArtifact)
		mongoTestWrite(t, terminalPath, baselineTerminal)
		mongoTestWrite(t, auditTerminalPath, baselineAudit)
		mongoTestWrite(t, replyPath, baselineReply)
		mongoTestWrite(t, phasePath, baselinePhases)
	}
	set := func(artifact mongoArtifactEvidence, terminal mongoTerminalEvidence, seal mongoAuditTerminal, reply []byte) {
		artifact.RawReplySHA256, artifact.RawReplyBytes = mongoHash(reply), len(reply)
		raw := mongoTestJSON(t, artifactPath, artifact)
		terminal.ArtifactSHA256, seal.ArtifactSHA256 = mongoHash(raw), mongoHash(raw)
		mongoTestJSON(t, terminalPath, terminal)
		mongoTestJSON(t, auditTerminalPath, seal)
		mongoTestWrite(t, replyPath, reply)
	}
	for _, tc := range []struct {
		name      string
		mutate    func(*mongoArtifactEvidence, *mongoTerminalEvidence, *mongoAuditTerminal)
		reply     []byte
		wantError bool
	}{
		{"wrong source UID", func(a *mongoArtifactEvidence, _ *mongoTerminalEvidence, _ *mongoAuditTerminal) {
			a.Source.PodUID = "other-pod-uid"
		}, baselineReply, true},
		{"wrong collection UUID", func(a *mongoArtifactEvidence, _ *mongoTerminalEvidence, _ *mongoAuditTerminal) {
			a.CollectionUUID = strings.Repeat("b", 32)
		}, baselineReply, false},
		{"unconfirmed cleanup", func(_ *mongoArtifactEvidence, term *mongoTerminalEvidence, _ *mongoAuditTerminal) {
			term.CollectionAbsent = false
		}, baselineReply, false},
		{"raw code 13 contradicts exposed artifact", func(_ *mongoArtifactEvidence, _ *mongoTerminalEvidence, _ *mongoAuditTerminal) {}, []byte("CAT_MONGO_JSON={\"ok\":false,\"code\":13,\"codeName\":\"Unauthorized\",\"rows\":[]}\n"), true},
		{"audit gap", func(_ *mongoArtifactEvidence, _ *mongoTerminalEvidence, seal *mongoAuditTerminal) {
			seal.BrainTrace, seal.BrainDecisions, seal.IssueCode = "GAP", nil, "AUDIT_GAP"
		}, baselineReply, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer restore()
			artifact, terminal, seal := a, baseTerminal, baseAudit
			tc.mutate(&artifact, &terminal, &seal)
			set(artifact, terminal, seal, tc.reply)
			got, err := rm.MongoExposureResult(id)
			if tc.wantError {
				if err == nil {
					t.Fatalf("contradictory producer/receipt accepted: %+v", got)
				}
			} else if err != nil || got == nil || got.Accepted || got.Finding != "UNKNOWN" {
				t.Fatalf("contradictory producer/receipt became accepted: %+v %v", got, err)
			}
		})
	}
	if err := os.Remove(phasePath); err != nil {
		t.Fatal(err)
	}
	if got, err := rm.MongoExposureResult(id); err != nil || got == nil || got.Accepted {
		t.Fatalf("missing ownership phase chain accepted: %+v %v", got, err)
	}
	restore()
	var latePhases bytes.Buffer
	for i, line := range bytes.Split(bytes.TrimSuffix(baselinePhases, []byte{'\n'}), []byte{'\n'}) {
		var phase mongoPhaseEvidence
		if err := json.Unmarshal(line, &phase); err != nil {
			t.Fatal(err)
		}
		if i >= 6 {
			phase.At = started.Add(2*time.Millisecond + time.Duration(i-5)*100*time.Microsecond).Format(time.RFC3339Nano)
		}
		encoded, _ := json.Marshal(phase)
		latePhases.Write(encoded)
		latePhases.WriteByte('\n')
	}
	mongoTestWrite(t, phasePath, latePhases.Bytes())
	if got, err := rm.MongoExposureResult(id); err != nil || got == nil || got.Accepted {
		t.Fatalf("client creation after audit observation accepted: %+v %v", got, err)
	}
	restore()
}

func TestMongoExposureDecisionWindowAndRawReplyControls(t *testing.T) {
	now := time.Now().UTC()
	source := mongoSourceEvidence{PodName: "mongo-pod", PodUID: "pod-uid", PolicyUID: "policy-uid", PolicyGeneration: 2}
	rec := mongoTestDecision(now, source)
	row, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	joined := append(row, '\n')
	if rows, state, err := projectMongoAuditBytes(joined, source, now.Add(-time.Second), now.Add(time.Second)); err != nil || state != "JOINED" || len(rows) != 1 {
		t.Fatalf("valid decision refused: %s %v", state, err)
	}
	missing := rec
	missing.DecisionTrace = nil
	bad, _ := json.Marshal(missing)
	if _, state, err := projectMongoAuditBytes(append(append([]byte{}, joined...), append(bad, '\n')...), source, now.Add(-time.Second), now.Add(time.Second)); err == nil || state != "GAP" {
		t.Fatal("same-name missing trace omitted")
	}
	changed := rec
	copyTrace := *rec.DecisionTrace
	copyTrace.AssetUID = "replaced-uid"
	changed.DecisionTrace = &copyTrace
	bad, _ = json.Marshal(changed)
	if _, state, err := projectMongoAuditBytes(append(bad, '\n'), source, now.Add(-time.Second), now.Add(time.Second)); err == nil || state != "GAP" {
		t.Fatal("same-name replacement omitted")
	}
	if _, state, err := projectMongoAuditBytes(joined, source, now.Add(time.Second), now.Add(2*time.Second)); err == nil || state != "GAP" {
		t.Fatal("pre-run decision joined")
	}
	later := mongoTestDecision(now.Add(2*time.Second), source)
	lateRaw, _ := json.Marshal(later)
	if rows, state, err := projectMongoAuditBytes(append(append([]byte{}, joined...), append(lateRaw, '\n')...), source, now.Add(-time.Second), now.Add(time.Second)); err != nil || state != "JOINED" || len(rows) != 1 {
		t.Fatalf("post-observation manager tick affected sealed result: %s %v", state, err)
	}
	if status, _, err := mongoReply([]byte("CAT_MONGO_JSON={\"ok\":false,\"code\":13,\"codeName\":\"Unauthorized\",\"rows\":[]}\n"), strings.Repeat("e", 32)); err != nil || status != "MONGO_AUTH_DENIED" {
		t.Fatal("actual thrown code-13 shape misread")
	}
	if _, _, err := mongoReply([]byte("CAT_MONGO_JSON={\"ok\":true,\"ok\":true,\"code\":0,\"codeName\":\"\",\"rows\":[]}\n"), strings.Repeat("e", 32)); err == nil {
		t.Fatal("duplicate reply key accepted")
	}
	selected := rec
	selected.Action = string(model.ActionRotate)
	selected.DispatchOutcome = model.DispatchEmitted
	selected.DecisionTrace = caseTraceValidTrace(now, true, false)
	selected.DecisionTrace.PolicyNamespace, selected.DecisionTrace.PolicyUID = mongoExposureNamespace, source.PolicyUID
	selected.DecisionTrace.AssetNamespace, selected.DecisionTrace.AssetName, selected.DecisionTrace.AssetUID = mongoExposureNamespace, source.PodName, source.PodUID
	selected.DecisionTrace.TenantName = "mongo"
	selected.DecisionTrace.DispatchOutcome = model.DispatchEmitted
	for _, action := range model.MutatingActions {
		row := model.DecisionActionStatusV3{Action: string(action), Status: model.ActionStatusNotEnabled, ExclusionKind: model.ExclusionNotEnabled}
		if action == model.ActionRotate {
			row.Status, row.ExclusionKind, row.Scored = model.ActionStatusSelected, model.ExclusionNone, true
		}
		selected.DecisionTrace.ActionStatus = append(selected.DecisionTrace.ActionStatus, row)
	}
	if err := selected.DecisionTrace.Validate(); err != nil {
		t.Fatalf("selected fixture invalid: %v", err)
	}
	reason, err := projectMongoDecision(selected, source, now.Add(-time.Second), now.Add(time.Second))
	if err != nil || reason.ReasonCode != "OTHER_RECORDED_REASON" {
		t.Fatalf("selected action reason projection: %+v %v", reason, err)
	}
}

func TestMongoExposureNamedAdmissionAndGrantRecheck(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: filepath.Join(dir, "state"), HarnessDir: filepath.Join(dir, "harness"), MongoExposureEnabled: true,
		AuditSource: &audittransport.Client{}, AuditSourceIdentity: "mTLS-source"}
	rm := &RunManager{cfg: cfg}
	configPath := filepath.Join(cfg.HarnessDir, allowedConfigs[mongoExposureConfig].File)
	writeConfig := func(target string) {
		body := fmt.Sprintf("context: %s\nnamespace: document-store\nownedAck: true\ntrialsPerArm: 1\nscenarioFilter: [c2-mongo-uncredentialed-service-exposure]\ndefenderFilter: []\nmongoExposureFixture:\n  transport: in-cluster\n  clusterUID: 11111111-1111-4111-8111-111111111111\n  mongoDeployment: mongo\n  mongoService: mongo\n  mongoImageID: registry.test/mongo@sha256:%s\n  policyName: mongo-defense\n  managerNamespace: phorvex-system\n  managerDeployment: phorvex-phorvex\n  managerImageID: registry.test/manager@sha256:%s\n  allowedNodeNames: [cpu-node]\n  maxRunSeconds: 600\n", target, strings.Repeat("a", 64), strings.Repeat("b", 64))
		mongoTestWrite(t, configPath, []byte(body))
		cfg.MongoExposureProfileSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
		rm.cfg.MongoExposureProfileSHA256 = cfg.MongoExposureProfileSHA256
	}
	writeConfig("old-target")
	old, err := rm.SuiteDestination(mongoExposureConfig)
	if err != nil || old.ScopeTarget != "old-target" || len(old.Targets) != 2 || old.Targets[0] != hostTargetID {
		t.Fatalf("named destination invalid: %+v %v", old, err)
	}
	if item := cfg.mongoExposureCatalogueItem(); !item.Available || item.Profile != mongoExposureConfig || item.LaunchKind != "named-suite" {
		t.Fatalf("configured catalogue unavailable: %+v", item)
	}
	rm.cfg.MongoExposureProfileSHA256 = strings.Repeat("f", 64)
	if _, err := rm.SuiteDestination(mongoExposureConfig); err == nil {
		t.Fatal("changed Mongo profile hash accepted")
	}
	rm.cfg.MongoExposureProfileSHA256 = cfg.MongoExposureProfileSHA256
	placeholder := []byte("context: __SET_LOGICAL_CLUSTER_TARGET__\n")
	mongoTestWrite(t, configPath, placeholder)
	rm.cfg.MongoExposureProfileSHA256 = fmt.Sprintf("%x", sha256.Sum256(placeholder))
	if _, err := rm.SuiteDestination(mongoExposureConfig); err == nil {
		t.Fatal("Mongo placeholder admitted with matching owner hash")
	}
	writeConfig("old-target")
	incomplete := []byte("context: old-target\nnamespace: document-store\nmongoExposureFixture:\n  transport: in-cluster\n")
	mongoTestWrite(t, configPath, incomplete)
	cfg.MongoExposureProfileSHA256 = fmt.Sprintf("%x", sha256.Sum256(incomplete))
	if item := cfg.mongoExposureCatalogueItem(); item.Available {
		t.Fatal("incomplete source pins advertised as available")
	}
	writeConfig("old-target")
	if _, err := rm.StartScenario([]string{"c2-mongo-uncredentialed-service-exposure"}, false, false, "", "", "", ""); err == nil {
		t.Fatal("generic scenario admitted")
	}
	writeConfig("new-target")
	if _, err := rm.prepareSuite("run-1", allowedConfigs[mongoExposureConfig], old.SuiteSHA256); err == nil || !strings.Contains(err.Error(), "authorized suite bytes changed before launch") {
		t.Fatalf("changed Mongo config did not reach authorized-byte barrier: %v", err)
	}
	p := &Principal{Targets: []string{hostTargetID, "old-target"}, Tenants: []string{mongoExposureNamespace}}
	server := &Server{runs: rm}
	request := withTestPrincipal(httptest.NewRequest(http.MethodPost, "/api/runs/start", strings.NewReader(`{"config":"mongo-exposure-baseline"}`)), p)
	w := httptest.NewRecorder()
	server.startRun(w, request)
	if w.Code != http.StatusForbidden {
		t.Fatalf("changed target escaped second grant check: %d %s", w.Code, w.Body.String())
	}
	own := runOwnership{Target: "old-target", Tenant: mongoExposureNamespace, Config: mongoExposureConfig}
	if !runVisibleTo(p, own) {
		t.Fatal("complete Mongo run grant refused")
	}
	p.Targets = []string{"old-target"}
	if runVisibleTo(p, own) {
		t.Fatal("host grant revocation left Mongo run visible")
	}
	p.Targets, p.Tenants = []string{hostTargetID, "old-target"}, nil
	if runVisibleTo(p, own) {
		t.Fatal("tenant grant revocation left Mongo run visible")
	}
	cfg.MongoExposureEnabled = false
	if item := cfg.mongoExposureCatalogueItem(); item.Available {
		t.Fatal("disabled Mongo suite advertised as available")
	}
}

func TestMongoExposureActualAmbiguousProducerRemainsPartial(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: dir, AuditSourceIdentity: "mTLS-source"}
	rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{}, runOut: map[string]string{}}
	id, outName := "run-1", "out-partial"
	out := cfg.runOutputPath(outName)
	runtime := mongoRuntimeConfig{Context: "reviewed-dev-cluster", Namespace: mongoExposureNamespace, OutDir: out}
	runtime.MongoExposureFixture.RunID, runtime.MongoExposureFixture.Nonce, runtime.MongoExposureFixture.ClusterUID = id, strings.Repeat("e", 32), "11111111-1111-4111-8111-111111111111"
	runtime.MongoExposureFixture.MongoImageID, runtime.MongoExposureFixture.ManagerImageID = "mongo-image", "manager-image"
	configRaw := mongoTestJSON(t, filepath.Join(cfg.runsDir(), "configs", id+".yaml"), runtime)
	start := mongoAuditStart{Schema: "mongo-exposure-audit-start-v1", RunID: id, SourceIdentity: cfg.AuditSourceIdentity, ConfigSHA256: mongoHash(configRaw), Segment: audittransport.Segment{ID: "live", Generation: "old", Anchor: strings.Repeat("a", 32), Size: 100}, Offset: 100, ObservedAt: time.Now().Add(-time.Second).Format(time.RFC3339Nano)}
	startRaw := mongoTestJSON(t, filepath.Join(out, "mongo-exposure-audit-start.json"), start)
	base := filepath.Join("testdata", "mongo_producer_partial")
	artifactRaw, err := os.ReadFile(filepath.Join(base, "mongo-exposure.json"))
	if err != nil {
		t.Fatal(err)
	}
	var artifact mongoArtifactEvidence
	if err := json.Unmarshal(artifactRaw, &artifact); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	artifact.StartedAt, artifact.FinishedAt = started.Format(time.RFC3339Nano), started.Add(time.Millisecond).Format(time.RFC3339Nano)
	artifactRaw = mongoTestJSON(t, filepath.Join(out, "mongo-exposure.json"), artifact)
	terminalRaw, err := os.ReadFile(filepath.Join(base, "mongo-exposure-terminal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var terminal mongoTerminalEvidence
	if err := json.Unmarshal(terminalRaw, &terminal); err != nil {
		t.Fatal(err)
	}
	terminal.ArtifactSHA256 = mongoHash(artifactRaw)
	mongoTestJSON(t, filepath.Join(out, "mongo-exposure-terminal.json"), terminal)
	mongoTestJSON(t, filepath.Join(out, "mongo-exposure-audit-terminal.json"), mongoAuditTerminal{Schema: "mongo-exposure-audit-terminal-v1", RunID: id, StartSHA256: mongoHash(startRaw), ArtifactSHA256: mongoHash(artifactRaw), SourceIdentity: cfg.AuditSourceIdentity, BrainTrace: "GAP", IssueCode: "AUDIT_GAP"})
	rm.runs[id], rm.runOut[id] = &RunStatus{ID: id, Config: mongoExposureConfig, State: "partial"}, outName
	got, err := rm.MongoExposureResult(id)
	if err != nil || got == nil || got.Accepted || got.Finding != "UNKNOWN" || got.Cleanup != "UNCONFIRMED" || got.BrainTrace != "GAP" || got.ClientRead != "UNKNOWN" {
		t.Fatalf("ambiguous Pod CREATE producer promoted or hidden: %+v %v", got, err)
	}
}
