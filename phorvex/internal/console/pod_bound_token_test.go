package console

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/audittransport"
	"github.com/phorvex/phorvex/internal/model"
	"sigs.k8s.io/yaml"
)

func testPodBoundTokenProfile() podBoundTokenProfile {
	var p podBoundTokenProfile
	p.Context = "reviewed-cluster"
	p.Namespace = podBoundTokenNamespace
	p.OwnedAck = true
	p.TrialsPerArm = 1
	p.ScenarioFilter = []string{"c2-pod-bound-api-auth-response"}
	p.Fixture.Transport = "in-cluster"
	p.Fixture.ClusterUID = "11111111-1111-4111-8111-111111111111"
	p.Fixture.ManagerNamespace = "phorvex-system"
	p.Fixture.ManagerDeployment = "phorvex-phorvex"
	p.Fixture.ManagerImageID = "registry.example/phorvex@sha256:" + strings.Repeat("a", 64)
	p.Fixture.FixtureImageID = "registry.example/voice@sha256:" + strings.Repeat("b", 64)
	p.Fixture.SourceManifestSHA256 = strings.Repeat("c", 64)
	p.Fixture.SourceManifestPath = "/reviewed/source-manifest.json"
	p.Fixture.ProtectedLedgerName = "phorvex-quarantine-capacity-" + strings.Repeat("d", 40)
	p.Fixture.EventCreator = "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector"
	p.Fixture.PrometheusURL = "http://prometheus.monitoring.svc:9090"
	p.Fixture.ScrapeKind = "podmonitor"
	p.Fixture.ScrapeNamespace = podBoundTokenNamespace
	p.Fixture.AllowedNodeName = "worker-1"
	p.Fixture.MaxRunSeconds = 600
	return p
}

func TestPodBoundTokenProfileRequiresProtectedLedgerPin(t *testing.T) {
	p := testPodBoundTokenProfile()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePodBoundTokenProfile(raw); err != nil {
		t.Fatalf("reviewed-shape profile refused: %v", err)
	}
	p.Fixture.ProtectedLedgerName = ""
	raw, _ = json.Marshal(p)
	if _, err := parsePodBoundTokenProfile(raw); err == nil {
		t.Fatal("missing protected ledger pin advertised as available")
	}
}

func TestPodBoundTokenNamedDestinationBindsReviewedProfileBytes(t *testing.T) {
	dir := t.TempDir()
	p := testPodBoundTokenProfile()
	manifest, err := json.Marshal(testPodBoundSourceManifest(p))
	if err != nil {
		t.Fatal(err)
	}
	pinPodBoundSource(t, &p, filepath.Join(dir, "manifest.json"), manifest)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "config.pod-bound-api-auth-response.yaml")
	if err := os.WriteFile(profilePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	rm := &RunManager{cfg: Config{HarnessDir: dir, PodBoundTokenEnabled: true, PodBoundTokenProfileSHA256: podBoundHash(raw), AuditSource: &audittransport.Client{}, AuditSourceIdentity: "audit-source.test"}}
	dest, err := rm.SuiteDestination(podBoundTokenConfig)
	if err != nil || dest.ScopeTenant != "voice" || dest.ScopeTarget != p.Context || dest.SuiteSHA256 != podBoundHash(raw) {
		t.Fatalf("reviewed named destination unavailable: %+v %v", dest, err)
	}
	rm.cfg.PodBoundTokenProfileSHA256 = strings.Repeat("f", 64)
	if _, err := rm.SuiteDestination(podBoundTokenConfig); err == nil {
		t.Fatal("changed reviewed profile hash admitted")
	}
	rm.cfg.PodBoundTokenProfileSHA256 = podBoundHash(raw)
	if err := os.WriteFile(profilePath, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := rm.SuiteDestination(podBoundTokenConfig); err == nil {
		t.Fatal("changed server-owned profile bytes admitted")
	}
}

func TestPodBoundCPUNamedDestinationAndCurrentGrant(t *testing.T) {
	dir := t.TempDir()
	p := testPodBoundTokenProfile()
	p.Namespace = podBoundTokenCPUNamespace
	p.ScenarioFilter = []string{podBoundTokenCPUCaseID}
	p.Fixture.ScrapeNamespace = p.Namespace
	p.Fixture.EventCreator = podBoundCreator(podBoundTokenCPUConfig)
	manifest, err := json.Marshal(testPodBoundSourceManifest(p))
	if err != nil {
		t.Fatal(err)
	}
	pinPodBoundSource(t, &p, filepath.Join(dir, "manifest.json"), manifest)
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.pod-bound-api-auth-response-cpu.yaml"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{HarnessDir: dir, PodBoundTokenCPUEnabled: true, PodBoundTokenCPUProfileSHA256: podBoundHash(raw), AuditSource: &audittransport.Client{}, AuditSourceIdentity: "audit-source.test"}
	rm := NewRunManager(cfg)
	dest, err := rm.SuiteDestination(podBoundTokenCPUConfig)
	if err != nil || dest.ScopeTenant != podBoundTokenCPUNamespace {
		t.Fatalf("CPU reviewed destination refused: %+v %v", dest, err)
	}
	principal := Principal{Issuer: "https://issuer.example", Subject: "operator", Roles: []Role{RoleOperator}, Tenants: []string{podBoundTokenCPUNamespace}, Targets: []string{hostTargetID, p.Context}}
	grants, err := ParseGrantPolicy([]byte(`{"version":1,"subjects":[{"issuer":"https://issuer.example","subject":"operator","roles":["operator"],"tenants":["phorvex-catalogue-cpu"],"targets":["default","reviewed-cluster"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rm.runs["run-1"] = &RunStatus{ID: "run-1", Config: podBoundTokenCPUConfig, State: "running", Owner: principalKey(&principal), ScopeTenant: podBoundTokenCPUNamespace, ScopeTarget: p.Context}
	rm.podBoundTokenPrincipals["run-1"] = principal
	s := &Server{runs: rm, auth: &Authenticator{grants: grants}}
	if err := s.currentPodBoundTokenGrant("run-1"); err != nil {
		t.Fatalf("CPU grant refused: %v", err)
	}
	rm.runs["run-1"].ScopeTenant = "voice"
	if err := s.currentPodBoundTokenGrant("run-1"); err == nil {
		t.Fatal("Voice tenant grant substituted for CPU")
	}
	p.Namespace = "voice"
	raw, _ = json.Marshal(p)
	if _, err := parsePodBoundTokenProfileFor(raw, podBoundTokenCPUConfig); err == nil {
		t.Fatal("CPU profile accepted Voice namespace")
	}
}

func TestPodBoundTokenPreparedRuntimeKeepsTemplateAndCurrentGrant(t *testing.T) {
	dir := t.TempDir()
	p := testPodBoundTokenProfile()
	template, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	name := "config.pod-bound-api-auth-response.yaml"
	mongoTestWrite(t, filepath.Join(dir, name), template)
	cfg := Config{HarnessDir: dir, StateDir: filepath.Join(dir, "state"), PodBoundTokenProfileSHA256: podBoundHash(template)}
	rm := NewRunManager(cfg)
	prepared, err := rm.prepareSuite("run-1", allowedConfigs[podBoundTokenConfig], cfg.PodBoundTokenProfileSHA256)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRaw, err := os.ReadFile(prepared.File)
	if err != nil {
		t.Fatal(err)
	}
	var runtime podBoundTokenProfile
	if err := yaml.Unmarshal(runtimeRaw, &runtime); err != nil {
		t.Fatal(err)
	}
	request := podBoundTokenRequest{ProfileSHA256: podBoundHash(runtimeRaw), Nonce: runtime.Fixture.Nonce}
	if request.ProfileSHA256 == cfg.PodBoundTokenProfileSHA256 {
		t.Fatal("stamped run profile unexpectedly equals reviewed template")
	}
	if !podBoundTokenRuntimeMatchesTemplate(template, runtimeRaw, "run-1", request.Nonce, cfg.runOutputPath("run-1")) {
		t.Fatal("prepared suite lost reviewed template authority")
	}
	changed := append([]byte(nil), runtimeRaw...)
	changed = []byte(strings.Replace(string(changed), "reviewed-cluster", "other-cluster", 1))
	if podBoundTokenRuntimeMatchesTemplate(template, changed, "run-1", request.Nonce, cfg.runOutputPath("run-1")) {
		t.Fatal("changed runtime bytes accepted")
	}
	changed = append([]byte(nil), template...)
	changed = []byte(strings.Replace(string(changed), "reviewed-cluster", "other-cluster", 1))
	if podBoundTokenRuntimeMatchesTemplate(changed, runtimeRaw, "run-1", request.Nonce, cfg.runOutputPath("run-1")) {
		t.Fatal("changed template accepted")
	}
	principal := Principal{Issuer: "https://issuer.example", Subject: "operator", Roles: []Role{RoleOperator}, Tenants: []string{"voice"}, Targets: []string{hostTargetID, p.Context}}
	grants, err := ParseGrantPolicy([]byte(`{"version":1,"subjects":[{"issuer":"https://issuer.example","subject":"operator","roles":["operator"],"tenants":["voice"],"targets":["default","reviewed-cluster"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rm.runs["run-1"] = &RunStatus{ID: "run-1", Config: podBoundTokenConfig, State: "running", Owner: principalKey(&principal), ScopeTenant: "voice", ScopeTarget: p.Context}
	rm.podBoundTokenPrincipals["run-1"] = principal
	s := &Server{runs: rm, auth: &Authenticator{grants: grants}}
	if err := s.currentPodBoundTokenGrant("run-1"); err != nil {
		t.Fatalf("current exact launch grant refused: %v", err)
	}
	rm.runs["run-1"].ScopeTarget = "other-cluster"
	if err := s.currentPodBoundTokenGrant("run-1"); err == nil {
		t.Fatal("target change kept grant")
	}
}

func TestPodBoundTokenJSONRejectsTrailingMalformedBytes(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, podBoundRequestFile), []byte(`{"schema":"pod-bound-token-request-v1"}x`), 0600); err != nil {
		t.Fatal(err)
	}
	var req podBoundTokenRequest
	if _, err := readPodBoundJSON(out, podBoundRequestFile, &req); err == nil {
		t.Fatal("malformed bytes after first JSON object accepted")
	}
}

func testPodBoundCompleteResult(now time.Time) PodBoundTokenResult {
	names := []string{"ADMISSION", "OWNED_FIXTURE", "CREDENTIAL_AND_ROUTE_BASELINE", "AUDIT_START", "SOLE_TYPED_SIGNAL", "BRAIN_DECISION", "NATIVE_OPERATION", "INDEPENDENT_OUTCOME", "CLEANUP"}
	r := PodBoundTokenResult{Schema: podBoundTokenSchema, RunID: "run-1", Nonce: strings.Repeat("e", 24), TerminalStatus: "COMPLETE", MechanismObserved: true, SecurityEfficacy: "NOT_EVALUATED", SignalMode: "explicit-injected-typed-event"}
	for i, name := range names {
		r.Stages = append(r.Stages, PodBoundTokenStage{Name: name, Status: "CONFIRMED", ObservedAt: now.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)})
	}
	r.Admission = PodBoundTokenAdmission{Namespace: podBoundTokenNamespace, SourcePodUID: "source-uid", PeerPodUID: "peer-uid", ServiceUID: "service-uid", DeploymentUID: "dep-uid", ReplicaSetUID: "rs-uid", PolicyUID: "policy-uid", PolicyGeneration: 1, PolicySpecSHA256: strings.Repeat("a", 64), ManagerPodUID: "manager-uid", ProfileSHA256: strings.Repeat("b", 64)}
	r.Event = PodBoundTokenEvent{UID: "event-uid", Kind: "phorvex.attack.pod-bound-api-auth", Creator: "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector", SourcePodUID: "source-uid", TrustVerified: true}
	r.Decision = PodBoundTokenDecision{ID: "decision-1", SelectedAction: "rotate", DispatchOutcome: "emitted", AuditCoverage: "COMPLETE", RequestRateStatus: "MEASURED_FRESH"}
	r.Operation = PodBoundTokenOperation{TerminationStatus: "REQUEST_CONFIRMED", OriginalPodAbsent: true}
	r.Replay = PodBoundTokenReplay{SourceBeforeHTTP: 200, SourceAfterHTTP: 401, SourceExpiry: now.Add(60 * time.Second).Format(time.RFC3339Nano), SourceAfterAt: now.Add(6500 * time.Millisecond).Format(time.RFC3339Nano), PeerBeforeHTTP: 200, PeerAfterHTTP: 200, ServiceBeforeHTTP: 200, ServiceAfterHTTP: 200, SameSourceHandle: true, SamePeerHandle: true, ServiceMemberPodUID: "peer-uid", ServiceAfterAt: now.Add(7 * time.Second).Format(time.RFC3339Nano), ServiceAfterServiceUID: "service-uid", ServiceAfterEndpointSliceUID: "slice-uid", ServiceMemberReady: true, ServiceMemberOwnerDeploymentUID: "dep-uid"}
	r.Telemetry.ProducerStatus = "MEASURED_FRESH"
	r.Cleanup = PodBoundTokenCleanup{Status: "CONFIRMED_ABSENT", Absent: true}
	return r
}

func TestPodBoundTokenMechanismRequiresIndependentControls(t *testing.T) {
	now := time.Date(2026, 9, 24, 16, 0, 0, 0, time.UTC)
	base := testPodBoundCompleteResult(now)
	if err := validatePodBoundTokenResult(base); err != nil {
		t.Fatalf("complete mechanism fixture refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*PodBoundTokenResult)
	}{
		{"no operation receipt", func(r *PodBoundTokenResult) { r.Operation.TerminationStatus = "UNKNOWN" }},
		{"same bearer still authorized", func(r *PodBoundTokenResult) { r.Replay.SourceAfterHTTP = 200 }},
		{"source replay expired", func(r *PodBoundTokenResult) {
			r.Replay.SourceExpiry = now.Add(6 * time.Second).Format(time.RFC3339Nano)
		}},
		{"peer revoked", func(r *PodBoundTokenResult) { r.Replay.PeerAfterHTTP = 401 }},
		{"service moved", func(r *PodBoundTokenResult) { r.Replay.ServiceAfterServiceUID = "other-service" }},
		{"unready route member", func(r *PodBoundTokenResult) { r.Replay.ServiceMemberReady = false }},
		{"missing request rate", func(r *PodBoundTokenResult) { r.Decision.RequestRateStatus = "MISSING_REQUEST_RATE" }},
		{"unknown cleanup", func(r *PodBoundTokenResult) { r.Cleanup.Status = "UNCONFIRMED" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			tc.change(&r)
			if err := validatePodBoundTokenResult(r); err == nil {
				t.Fatal("unsupported mechanism claim accepted")
			}
		})
	}
	base.MechanismObserved = false
	base.Decision.SelectedAction = "noop"
	base.Decision.DispatchOutcome = "not-attempted"
	base.Operation.TerminationStatus = "NOT_DISPATCHED"
	base.Replay.SourceAfterHTTP = 200
	if err := validatePodBoundTokenResult(base); err != nil {
		t.Fatalf("complete negative observation refused: %v", err)
	}
}

func TestPodBoundCPUOriginalHandlesNeedBothResponsesBeforeExpiryMargin(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	r := testPodBoundCompleteResult(now)
	r.CaseID = podBoundTokenCPUCaseID
	r.Admission.Namespace = podBoundTokenCPUNamespace
	r.Admission.PDBUID = "pdb-uid"
	r.Event.Creator = podBoundCreator(podBoundTokenCPUConfig)
	r.Replay.SourceExpiry = now.Add(60 * time.Second).Format(time.RFC3339Nano)
	r.Replay.PeerExpiry = now.Add(60 * time.Second).Format(time.RFC3339Nano)
	r.Replay.SourceBeforeRequestAt = now.Add(time.Second).Format(time.RFC3339Nano)
	r.Replay.SourceBeforeAt = now.Add(1200 * time.Millisecond).Format(time.RFC3339Nano)
	r.Replay.PeerBeforeRequestAt = now.Add(1500 * time.Millisecond).Format(time.RFC3339Nano)
	r.Replay.PeerBeforeAt = now.Add(1700 * time.Millisecond).Format(time.RFC3339Nano)
	r.Replay.SourceAfterRequestAt = now.Add(6 * time.Second).Format(time.RFC3339Nano)
	r.Replay.PeerAfterRequestAt = now.Add(6600 * time.Millisecond).Format(time.RFC3339Nano)
	r.Replay.PeerAfterAt = now.Add(6800 * time.Millisecond).Format(time.RFC3339Nano)
	if err := validatePodBoundTokenResult(r); err != nil {
		t.Fatalf("in-margin complete CPU response refused: %v", err)
	}
	late := r
	late.Replay.SourceExpiry = now.Add(36 * time.Second).Format(time.RFC3339Nano)
	if err := validatePodBoundTokenResult(late); err == nil {
		t.Fatal("source 401 finished after expiry margin gained response credit")
	}
	late = r
	late.Replay.PeerExpiry = now.Add(36 * time.Second).Format(time.RFC3339Nano)
	if err := validatePodBoundTokenResult(late); err == nil {
		t.Fatal("peer 200 finished after expiry margin gained response credit")
	}
}

func TestPodBoundTokenRequestRateNeedsFreshFixtureAndManagerSource(t *testing.T) {
	now := time.Date(2026, 9, 24, 16, 0, 0, 0, time.UTC)
	r := podBoundTokenRequest{SourcePodName: "source", MetricSourcePodName: "source", MetricStatus: "MEASURED_FRESH", PodMonitorUID: "monitor-uid", MetricQuerySHA256: strings.Repeat("a", 64), MetricFirstValue: 1, MetricSecondValue: 2,
		MetricFirstAt: now.Format(time.RFC3339Nano), MetricSecondAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), RequestedAt: now.Add(31 * time.Second).Format(time.RFC3339Nano)}
	rec := audit.Record{DecisionTrace: &model.DecisionTraceV2{Timestamp: now.Add(45 * time.Second).Format(time.RFC3339Nano)}}
	rec.DecisionTrace.Inputs.RequestRate = model.OptionalFloat{Present: true, Value: 0.25}
	rec.DecisionTrace.Inputs.TelemetryStates = []model.DecisionSignalStateV3{{Signal: "reqRate", State: "present", Src: "prometheus-http"}}
	if !podBoundFreshRequestRate(r, rec) {
		t.Fatal("two fresh exact-Pod samples and actual manager source rejected")
	}
	r.MetricSecondAt = now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
	if podBoundFreshRequestRate(r, rec) {
		t.Fatal("stale producer samples accepted from trace presence")
	}
	r.MetricSecondAt = now.Add(30 * time.Second).Format(time.RFC3339Nano)
	rec.DecisionTrace.Inputs.TelemetryStates[0].Src = "fixture-assertion"
	if podBoundFreshRequestRate(r, rec) {
		t.Fatal("non-Prometheus manager signal accepted")
	}
	rec.DecisionTrace.Inputs.TelemetryStates[0].Src = "prometheus-http"
	r.MetricSourcePodName = "peer"
	if podBoundFreshRequestRate(r, rec) {
		t.Fatal("peer metric borrowed for source Pod")
	}
}

func TestPodBoundTokenReplayJournalBindsActualStatusAndHandle(t *testing.T) {
	now := time.Date(2026, 9, 24, 16, 0, 0, 0, time.UTC)
	baseline := testPodBoundCompleteResult(now)
	req := podBoundTokenRequest{RunID: baseline.RunID, Nonce: baseline.Nonce, SourceBeforeHTTP: 200, PeerBeforeHTTP: 200,
		SourceCaptureID: strings.Repeat("a", 32), PeerCaptureID: strings.Repeat("b", 32), RequestedAt: now.Add(3 * time.Second).Format(time.RFC3339Nano), SourceExpiry: now.Add(60 * time.Second).Format(time.RFC3339Nano)}
	baseline.Replay.SourceAfterAt = now.Add(7 * time.Second).Format(time.RFC3339Nano)
	rows := []podBoundReplayRow{
		{Schema: "pod-bound-token-replay-v1", RunID: req.RunID, Nonce: req.Nonce, Phase: "source-before", HTTP: 200, At: now.Add(time.Second).Format(time.RFC3339Nano), CaptureID: req.SourceCaptureID},
		{Schema: "pod-bound-token-replay-v1", RunID: req.RunID, Nonce: req.Nonce, Phase: "peer-before", HTTP: 200, At: now.Add(2 * time.Second).Format(time.RFC3339Nano), CaptureID: req.PeerCaptureID},
		{Schema: "pod-bound-token-replay-v1", RunID: req.RunID, Nonce: req.Nonce, Phase: "source-after", HTTP: 401, At: baseline.Replay.SourceAfterAt, CaptureID: req.SourceCaptureID},
		{Schema: "pod-bound-token-replay-v1", RunID: req.RunID, Nonce: req.Nonce, Phase: "peer-after", HTTP: 200, At: now.Add(8 * time.Second).Format(time.RFC3339Nano), CaptureID: req.PeerCaptureID},
	}
	out := t.TempDir()
	write := func() {
		var raw []byte
		for _, row := range rows {
			b, e := json.Marshal(row)
			if e != nil {
				t.Fatal(e)
			}
			raw = append(raw, b...)
			raw = append(raw, '\n')
		}
		if e := os.WriteFile(filepath.Join(out, podBoundReplayFile), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write()
	observationEnd := now.Add(9 * time.Second).Format(time.RFC3339Nano)
	if err := verifyPodBoundReplayJournal(out, req, baseline, observationEnd); err != nil {
		t.Fatalf("producer-shaped replay refused: %v", err)
	}
	rows[2].HTTP = 200
	write()
	if err := verifyPodBoundReplayJournal(out, req, baseline, observationEnd); err == nil {
		t.Fatal("artifact 401 accepted while original source replay was 200")
	}
	rows[2].HTTP = 401
	rows[2].CaptureID = strings.Repeat("c", 32)
	write()
	if err := verifyPodBoundReplayJournal(out, req, baseline, observationEnd); err == nil {
		t.Fatal("recaptured source handle accepted")
	}
}

func TestPodBoundTokenTypedDecisionNoopAndAttributionControls(t *testing.T) {
	now := time.Date(2026, 9, 24, 16, 0, 0, 0, time.UTC)
	r := podBoundTokenRequest{Nonce: strings.Repeat("e", 24), Namespace: "voice", SourcePodName: "pod-token-source", SourcePodUID: "source-uid", PolicyName: "pod-token-policy", PolicyUID: "policy-uid", PolicyGeneration: 1}
	trace := caseTraceValidTrace(now, false, false)
	trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID = "voice", r.PolicyName, r.PolicyUID
	trace.AssetNamespace, trace.AssetName, trace.AssetUID = "voice", r.SourcePodName, r.SourcePodUID
	trace.DispatchOutcome = model.DispatchNotAttempted
	trace.Facts[0].FactType = "podBoundKubeAPIAuthPotential"
	trace.Facts[0].CoveringActions = []string{"rotate"}
	trace.Facts[0].SteeredBy = &model.VectorSteeringAttribution{RuleType: model.AttackVectorPodBoundAPIAuth, AppliedMultiplier: 3, Events: []model.VectorSteeringEvent{{EventName: "phorvex-e2e-" + r.Nonce, EventUID: "event-uid", RuleType: model.AttackVectorPodBoundAPIAuth, DeclaredSource: "PhorvexE2EDetector", TrustVerdict: "trusted", CreatorIdentity: "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector", TargetPodUID: r.SourcePodUID}}}
	for _, action := range model.MutatingActions {
		trace.ActionStatus = append(trace.ActionStatus, model.DecisionActionStatusV3{Action: string(action), Status: model.ActionStatusNotEnabled, ExclusionKind: model.ExclusionNotEnabled})
	}
	if err := trace.Validate(); err != nil {
		t.Fatalf("typed no-op trace fixture invalid: %v", err)
	}
	event := model.EventEvidence{Name: "phorvex-e2e-" + r.Nonce, EventUID: "event-uid", Type: model.AttackVectorPodBoundAPIAuth, Source: "PhorvexE2EDetector", TrustVerdict: "trusted", CreatorIdentity: "system:serviceaccount:phorvex-system:phorvex-phorvex-e2e-detector", TargetPodUID: r.SourcePodUID, TargetsPod: true, TimestampPresent: true}
	rec := audit.Record{Kind: "phorvex.decision", Time: now, Namespace: r.Namespace, Pod: r.SourcePodName, Action: "noop", DecisionTrace: trace, Events: []model.EventEvidence{event}}
	encode := func(rec audit.Record) []byte {
		b, e := json.Marshal(rec)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	d, op, err := podBoundTypedDecision(encode(rec), r, event.EventUID)
	if err != nil || d.SelectedAction != "noop" || d.DispatchOutcome != model.DispatchNotAttempted || op.TerminationStatus != "NOT_DISPATCHED" {
		t.Fatalf("valid typed no-op lost: %+v %+v %v", d, op, err)
	}
	wrong := rec
	wrong.Events = []model.EventEvidence{event, event}
	if _, _, err := podBoundTypedDecision(encode(wrong), r, event.EventUID); err == nil {
		t.Fatal("duplicate trusted event accepted")
	}
	wrong = rec
	badEvent := event
	badEvent.TargetPodUID = "replacement-uid"
	wrong.Events = []model.EventEvidence{badEvent}
	if _, _, err := podBoundTypedDecision(encode(wrong), r, event.EventUID); err == nil {
		t.Fatal("different Pod incarnation accepted")
	}
	wrong = rec
	wrong.Events = []model.EventEvidence{event}
	wrong.Events[0].TrustVerdict = "untrusted-identity"
	if _, _, err := podBoundTypedDecision(encode(wrong), r, event.EventUID); err == nil {
		t.Fatal("untrusted event accepted")
	}
}

func TestPodBoundTokenPhaseJournalBindsCreatedUIDsAndOriginalAbsence(t *testing.T) {
	now := time.Date(2026, 9, 24, 16, 0, 0, 0, time.UTC)
	req := podBoundTokenRequest{RunID: "run-1", Nonce: strings.Repeat("e", 24), PolicyName: "pod-token-" + strings.Repeat("e", 24), SourcePodName: "source", SourcePodUID: "source-uid", PeerPodName: "peer", PeerPodUID: "peer-uid", DeploymentUID: "dep-uid", ServiceUID: "svc-uid", PolicyUID: "policy-uid", PodMonitorUID: "monitor-uid", RequestedAt: now.Add(20 * time.Second).Format(time.RFC3339Nano)}
	barrier := podBoundTokenBarrier{ObservedAt: now.Add(25 * time.Second).Format(time.RFC3339Nano)}
	a := podBoundTokenArtifact{ObservationEndedAt: now.Add(40 * time.Second).Format(time.RFC3339Nano)}
	a.Result.Operation.OriginalPodAbsent = true
	a.Result.Replay.SourceAfterAt = now.Add(35 * time.Second).Format(time.RFC3339Nano)
	resources := []string{"serviceaccounts", "deployments", "services", "poddisruptionbudgets", "roles", "rolebindings", "phorvexpolicies", "podmonitors"}
	uids := map[string]string{"deployments": req.DeploymentUID, "services": req.ServiceUID, "phorvexpolicies": req.PolicyUID, "podmonitors": req.PodMonitorUID}
	rows := []podBoundPhaseRow{}
	appendRow := func(op, resource, name, uid string, at time.Time) {
		rows = append(rows, podBoundPhaseRow{Schema: "pod-bound-token-phase-v1", RunID: req.RunID, Nonce: req.Nonce, Operation: op, Resource: resource, Name: name, UID: uid, At: at.Format(time.RFC3339Nano)})
	}
	for i, resource := range resources {
		uid := uids[resource]
		if uid == "" {
			uid = resource + "-uid"
		}
		appendRow("CREATE_INTENT", resource, req.PolicyName, "", now.Add(time.Duration(2*i)*time.Second))
		appendRow("CREATE_ACK", resource, req.PolicyName, uid, now.Add(time.Duration(2*i+1)*time.Second))
	}
	appendRow("ORIGINAL_POD_ABSENT", "pods", req.SourcePodName, req.SourcePodUID, now.Add(30*time.Second))
	for i, resource := range resources {
		uid := uids[resource]
		if uid == "" {
			uid = resource + "-uid"
		}
		appendRow("DELETE_INTENT", resource, req.PolicyName, uid, now.Add(time.Duration(41+2*i)*time.Second))
		appendRow("DELETE_ACK", resource, req.PolicyName, uid, now.Add(time.Duration(42+2*i)*time.Second))
	}
	out := t.TempDir()
	write := func() {
		var raw []byte
		for _, row := range rows {
			b, e := json.Marshal(row)
			if e != nil {
				t.Fatal(e)
			}
			raw = append(raw, b...)
			raw = append(raw, '\n')
		}
		if e := os.WriteFile(filepath.Join(out, podBoundPhaseFile), raw, 0600); e != nil {
			t.Fatal(e)
		}
		a.PhaseJournalSHA256 = podBoundHash(raw)
	}
	write()
	if err := verifyPodBoundPhaseJournal(out, req, barrier, a); err != nil {
		t.Fatalf("producer-shaped phase journal refused: %v", err)
	}
	rows[3].UID = "replacement-deployment"
	write()
	if err := verifyPodBoundPhaseJournal(out, req, barrier, a); err == nil {
		t.Fatal("CREATE_ACK UID differing from request accepted")
	}
	rows[3].UID = req.DeploymentUID
	rows[16].UID = "replacement-source"
	write()
	if err := verifyPodBoundPhaseJournal(out, req, barrier, a); err == nil {
		t.Fatal("absence of different Pod UID accepted")
	}
}

func TestPodBoundTokenEarlyUnsafeReceiptVisibleWithoutTerminal(t *testing.T) {
	out := t.TempDir()
	journal := []byte("{\"schema\":\"pod-bound-token-phase-v1\"}\n")
	if err := os.WriteFile(filepath.Join(out, podBoundPhaseFile), journal, 0600); err != nil {
		t.Fatal(err)
	}
	r := PodBoundTokenUnsafeReceipt{Schema: "pod-bound-token-unsafe-v1", RunID: "run-1", Nonce: strings.Repeat("e", 24), NamespaceUID: "voice-ns-uid", CreatedUIDs: []string{"deployments/pod-token-owned/dep-uid"}, PhaseJournalSHA256: podBoundHash(journal), CleanupStatus: "UNCONFIRMED", ErrorSHA256: strings.Repeat("a", 64), RecordedAt: time.Date(2026, 9, 24, 16, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "pod-bound-token-unsafe.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readPodBoundTokenUnsafe(out, "run-1")
	if err != nil || got == nil || len(got.CreatedUIDs) != 1 {
		t.Fatalf("early unsafe receipt invisible: %+v %v", got, err)
	}
	if _, err := readPodBoundTokenResult(out, "run-1"); err == nil {
		t.Fatal("unsafe receipt promoted without terminal")
	}
	if status := podBoundUnsafeStatus(out, "run-1"); !strings.Contains(status, "1 created UIDs") {
		t.Fatalf("unsafe run history lost debt: %s", status)
	}
}

func TestPodBoundTokenProducerNoopWithAuthenticatedAuditSelector(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	producer := filepath.Join("..", "..", "..", "build", "test-harness", "testdata", "pod_bound_token_producer")
	for _, name := range []string{podBoundRequestFile, podBoundBarrierFile, podBoundObservationEndFile, podBoundObservationCommittedFile, podBoundEventCleanupFile, podBoundReplayFile, podBoundPhaseFile, podBoundArtifactFile, podBoundTerminalFile} {
		raw, err := os.ReadFile(filepath.Join(producer, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var req podBoundTokenRequest
	if _, err := readPodBoundJSON(out, podBoundRequestFile, &req); err != nil {
		t.Fatal(err)
	}
	var barrier podBoundTokenBarrier
	if _, err := readPodBoundJSON(out, podBoundBarrierFile, &barrier); err != nil {
		t.Fatal(err)
	}
	var artifact podBoundTokenArtifact
	if _, err := readPodBoundJSON(out, podBoundArtifactFile, &artifact); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 24, 16, 0, 35, 0, time.UTC)
	trace := caseTraceValidTrace(at, false, false)
	trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID = req.Namespace, req.PolicyName, req.PolicyUID
	trace.AssetNamespace, trace.AssetName, trace.AssetUID = req.Namespace, req.SourcePodName, req.SourcePodUID
	trace.DispatchOutcome = model.DispatchNotAttempted
	trace.Facts[0].FactType = "podBoundKubeAPIAuthPotential"
	trace.Facts[0].CoveringActions = []string{"rotate"}
	trace.Facts[0].SteeredBy = &model.VectorSteeringAttribution{RuleType: model.AttackVectorPodBoundAPIAuth, AppliedMultiplier: 3, Events: []model.VectorSteeringEvent{{EventName: "phorvex-e2e-" + req.Nonce, EventUID: barrier.Event.UID, RuleType: model.AttackVectorPodBoundAPIAuth, DeclaredSource: "PhorvexE2EDetector", TrustVerdict: "trusted", CreatorIdentity: barrier.Event.Creator, TargetPodUID: req.SourcePodUID}}}
	for _, action := range model.MutatingActions {
		trace.ActionStatus = append(trace.ActionStatus, model.DecisionActionStatusV3{Action: string(action), Status: model.ActionStatusNotEnabled, ExclusionKind: model.ExclusionNotEnabled})
	}
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	rec := audit.Record{Kind: "phorvex.decision", Time: at, Namespace: req.Namespace, Pod: req.SourcePodName, Action: "noop", DecisionTrace: trace, Events: []model.EventEvidence{{Name: "phorvex-e2e-" + req.Nonce, EventUID: barrier.Event.UID, Type: model.AttackVectorPodBoundAPIAuth, Source: "PhorvexE2EDetector", TrustVerdict: "trusted", CreatorIdentity: barrier.Event.Creator, TargetPodUID: req.SourcePodUID, TargetsPod: true, TimestampPresent: true}}}
	row, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	decision, operation, err := podBoundTypedDecision(row, req, barrier.Event.UID)
	if err != nil {
		t.Fatal(err)
	}
	barrier.Decision, barrier.Operation, barrier.DecisionRowSHA = decision, operation, podBoundHash(row)
	barrierRaw := mongoTestJSON(t, filepath.Join(out, podBoundBarrierFile), barrier)
	var end podBoundTokenObservationEnd
	if _, err := readPodBoundJSON(out, podBoundObservationEndFile, &end); err != nil {
		t.Fatal(err)
	}
	end.BarrierSHA256 = podBoundHash(barrierRaw)
	endRaw := mongoTestJSON(t, filepath.Join(out, podBoundObservationEndFile), end)
	artifact.BarrierSHA256 = podBoundHash(barrierRaw)
	artifact.Result.Decision, artifact.Result.Operation = decision, operation
	artifactRaw := mongoTestJSON(t, filepath.Join(out, podBoundArtifactFile), artifact)
	var terminal podBoundTokenTerminal
	if _, err := readPodBoundJSON(out, podBoundTerminalFile, &terminal); err != nil {
		t.Fatal(err)
	}
	terminal.ArtifactSHA256 = podBoundHash(artifactRaw)
	mongoTestJSON(t, filepath.Join(out, podBoundTerminalFile), terminal)
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	auditPath := filepath.Join(dir, "audit.jsonl")
	mongoTestWrite(t, auditPath, append(append([]byte(nil), row...), '\n'))
	source := audittransport.ServerConfig{AuditPath: auditPath, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test"}
	ts := httptest.NewUnstartedServer(source.Handler())
	ts.TLS = source.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := client.Manifest(context.Background())
	if err != nil || len(manifest.Segments) != 1 {
		t.Fatalf("audit manifest: %v", err)
	}
	seg := manifest.Segments[0]
	start := podBoundTokenAuditStart{Schema: "pod-bound-token-audit-start-v1", RunID: req.RunID, Nonce: req.Nonce, SourceIdentity: "fixture-audit-source", Segment: seg, Offset: 0, RequestSHA256: podBoundHash(mustReadPodBoundFile(t, out, podBoundRequestFile))}
	mongoTestJSON(t, filepath.Join(out, "pod-bound-token-audit-start.json"), start)
	var committed podBoundTokenObservationCommitted
	if _, err := readPodBoundJSON(out, podBoundObservationCommittedFile, &committed); err != nil {
		t.Fatal(err)
	}
	committed.RequestSHA256 = start.RequestSHA256
	committed.BarrierSHA256 = podBoundHash(barrierRaw)
	committed.ObservationEndSHA256 = podBoundHash(endRaw)
	committed.Commitment = audittransport.ExactWindowCommitment{Segment: seg, StartOffset: 0, EndOffset: seg.Size, WindowSHA256: podBoundHash(append(append([]byte(nil), row...), '\n')), CapturedAtUnixNano: at.Add(47 * time.Second).UnixNano()}
	mongoTestJSON(t, filepath.Join(out, podBoundObservationCommittedFile), committed)
	rm := &RunManager{cfg: Config{AuditSource: client, AuditSourceIdentity: "fixture-audit-source"}}
	if err := rm.sealPodBoundTokenAudit(req.RunID, out); err != nil {
		t.Fatalf("authenticated selector refused producer fixture: %v", err)
	}
	result, err := readPodBoundTokenResult(out, req.RunID)
	if err != nil || result.TerminalStatus != "COMPLETE" || result.MechanismObserved || result.Decision.SelectedAction != "noop" {
		t.Fatalf("producer negative observation lost: %+v %v", result, err)
	}
	originalReplay := mustReadPodBoundFile(t, out, podBoundReplayFile)
	changedReplay := strings.Replace(string(originalReplay), `"http":200,"nonce":"0123456789abcdef01234567","phase":"source-after"`, `"http":401,"nonce":"0123456789abcdef01234567","phase":"source-after"`, 1)
	if changedReplay == string(originalReplay) {
		t.Fatal("producer source replay fixture missing")
	}
	mongoTestWrite(t, filepath.Join(out, podBoundReplayFile), []byte(changedReplay))
	if _, err := readPodBoundTokenResult(out, req.RunID); err == nil {
		t.Fatal("changed original source replay accepted")
	}
	mongoTestWrite(t, filepath.Join(out, podBoundReplayFile), originalReplay)
	originalPhases := mustReadPodBoundFile(t, out, podBoundPhaseFile)
	mongoTestWrite(t, filepath.Join(out, podBoundPhaseFile), append(originalPhases, []byte("{}\n")...))
	if _, err := readPodBoundTokenResult(out, req.RunID); err == nil {
		t.Fatal("changed original phase journal accepted")
	}
	mongoTestWrite(t, filepath.Join(out, podBoundPhaseFile), originalPhases)
	// An earlier same-source rotate without this injected event still confounds
	// the later attributed no-op. Both the producer seal and retained reader
	// must reject it even though the selected no-op row remains intact.
	earlyTrace := caseTraceValidTrace(at.Add(-time.Second), true, false)
	earlyTrace.PolicyNamespace, earlyTrace.PolicyName, earlyTrace.PolicyUID = req.Namespace, req.PolicyName, req.PolicyUID
	earlyTrace.AssetNamespace, earlyTrace.AssetName, earlyTrace.AssetUID = req.Namespace, req.SourcePodName, req.SourcePodUID
	earlyTrace.DispatchOutcome = model.DispatchEmitted
	if err := earlyTrace.Validate(); err != nil {
		t.Fatal(err)
	}
	early := audit.Record{Kind: "phorvex.decision", Time: at.Add(-time.Second), Namespace: req.Namespace, Pod: req.SourcePodName, Action: "rotate", Selected: true, Actuated: true, DispatchOutcome: model.DispatchEmitted, DecisionTrace: earlyTrace}
	earlyRaw, err := json.Marshal(early)
	if err != nil {
		t.Fatal(err)
	}
	earlyBytes := append(append(append([]byte(nil), earlyRaw...), '\n'), append(row, '\n')...)
	confoundOut := filepath.Join(dir, "confounded")
	if err := os.MkdirAll(confoundOut, 0700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == podBoundSealFile {
			continue
		}
		mongoTestWrite(t, filepath.Join(confoundOut, entry.Name()), mustReadPodBoundFile(t, out, entry.Name()))
	}
	confoundPath := filepath.Join(dir, "confounded-audit.jsonl")
	mongoTestWrite(t, confoundPath, earlyBytes)
	confoundSource := audittransport.ServerConfig{AuditPath: confoundPath, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test"}
	confoundServer := httptest.NewUnstartedServer(confoundSource.Handler())
	confoundServer.TLS = confoundSource.TLSConfig()
	confoundServer.StartTLS()
	defer confoundServer.Close()
	confoundClient, err := audittransport.NewClient(audittransport.ClientConfig{URL: confoundServer.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	confoundManifest, err := confoundClient.Manifest(context.Background())
	if err != nil || len(confoundManifest.Segments) != 1 {
		t.Fatalf("confounded audit manifest: %v", err)
	}
	confoundSegment := confoundManifest.Segments[0]
	start.Segment = confoundSegment
	mongoTestJSON(t, filepath.Join(confoundOut, "pod-bound-token-audit-start.json"), start)
	committed.Commitment = audittransport.ExactWindowCommitment{Segment: confoundSegment, StartOffset: 0, EndOffset: confoundSegment.Size, WindowSHA256: podBoundHash(earlyBytes), CapturedAtUnixNano: at.Add(47 * time.Second).UnixNano()}
	commitRaw := mongoTestJSON(t, filepath.Join(confoundOut, podBoundObservationCommittedFile), committed)
	confoundRM := &RunManager{cfg: Config{AuditSource: confoundClient, AuditSourceIdentity: "fixture-audit-source"}}
	if err := confoundRM.sealPodBoundTokenAudit(req.RunID, confoundOut); err == nil {
		t.Fatal("earlier unattributed emitted rotate was sealed as harmless")
	}
	exact, err := confoundClient.SelectExact(context.Background(), audittransport.ExactWindowRequest{Segment: confoundSegment, StartOffset: 0, EndOffset: confoundSegment.Size, Namespace: req.Namespace, PodName: req.SourcePodName, PodUID: req.SourcePodUID, PolicyUID: req.PolicyUID, Commitment: &committed.Commitment})
	if err != nil {
		t.Fatal(err)
	}
	var originalSeal podBoundTokenAuditSeal
	if _, err := readPodBoundJSON(out, podBoundSealFile, &originalSeal); err != nil {
		t.Fatal(err)
	}
	originalSeal.Exact, originalSeal.ObservationCommitSHA256 = exact, podBoundHash(commitRaw)
	mongoTestJSON(t, filepath.Join(confoundOut, podBoundSealFile), originalSeal)
	if _, err := readPodBoundTokenResult(confoundOut, req.RunID); err == nil {
		t.Fatal("earlier unattributed emitted rotate accepted by retained reader")
	}
}

func TestPodBoundTokenProducerRotateWithAuthenticatedAuditSelector(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	producer := filepath.Join("..", "..", "..", "build", "test-harness", "testdata", "pod_bound_token_producer")
	for _, name := range []string{podBoundRequestFile, podBoundBarrierFile, podBoundObservationEndFile, podBoundObservationCommittedFile, podBoundEventCleanupFile, podBoundReplayFile, podBoundPhaseFile, podBoundArtifactFile, podBoundTerminalFile} {
		mongoTestWrite(t, filepath.Join(out, name), mustReadPodBoundFile(t, producer, name))
	}
	var req podBoundTokenRequest
	if _, err := readPodBoundJSON(out, podBoundRequestFile, &req); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 24, 16, 0, 0, 0, time.UTC)
	req.MetricStatus = "MEASURED_FRESH"
	req.MetricFirstAt, req.MetricSecondAt = base.Add(2*time.Second).Format(time.RFC3339Nano), base.Add(22*time.Second).Format(time.RFC3339Nano)
	req.MetricFirstValue, req.MetricSecondValue = 1, 4
	reqRaw := mongoTestJSON(t, filepath.Join(out, podBoundRequestFile), req)
	var barrier podBoundTokenBarrier
	if _, err := readPodBoundJSON(out, podBoundBarrierFile, &barrier); err != nil {
		t.Fatal(err)
	}
	trace := caseTraceValidTrace(base.Add(35*time.Second), true, false)
	trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID = req.Namespace, req.PolicyName, req.PolicyUID
	trace.AssetNamespace, trace.AssetName, trace.AssetUID = req.Namespace, req.SourcePodName, req.SourcePodUID
	trace.DispatchOutcome = model.DispatchEmitted
	trace.Inputs.RequestRate = model.OptionalFloat{Present: true, Value: 0.25}
	trace.Inputs.TelemetryStates = []model.DecisionSignalStateV3{{Signal: "reqRate", State: "present", Src: "prometheus-http"}}
	trace.Facts[0].FactType = "podBoundKubeAPIAuthPotential"
	trace.Facts[0].CoveringActions = []string{"rotate"}
	trace.Facts[0].SteeredBy = &model.VectorSteeringAttribution{RuleType: model.AttackVectorPodBoundAPIAuth, AppliedMultiplier: 3, Events: []model.VectorSteeringEvent{{EventName: "phorvex-e2e-" + req.Nonce, EventUID: barrier.Event.UID, RuleType: model.AttackVectorPodBoundAPIAuth, DeclaredSource: "PhorvexE2EDetector", TrustVerdict: "trusted", CreatorIdentity: barrier.Event.Creator, TargetPodUID: req.SourcePodUID}}}
	if err := trace.Validate(); err != nil {
		t.Fatalf("selected trace: %v", err)
	}
	receipt := &model.GracefulTerminationReceipt{PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, PolicyGeneration: req.PolicyGeneration, PolicyGraceCapSeconds: 30, WorkloadGraceSeconds: 30, WorkloadGraceExplicit: true, EffectiveGracePeriodSeconds: 30, PodUID: req.SourcePodUID, PodResourceVersion: "123", TerminationStatus: "unconfirmed"}
	rec := audit.Record{Kind: "phorvex.decision", Time: base.Add(35 * time.Second), Namespace: req.Namespace, Pod: req.SourcePodName, Action: "rotate", Selected: true, Actuated: true, DispatchOutcome: model.DispatchEmitted, GracefulTermination: receipt, DecisionTrace: trace, Events: []model.EventEvidence{{Name: "phorvex-e2e-" + req.Nonce, EventUID: barrier.Event.UID, Type: model.AttackVectorPodBoundAPIAuth, Source: "PhorvexE2EDetector", TrustVerdict: "trusted", CreatorIdentity: barrier.Event.Creator, TargetPodUID: req.SourcePodUID, TargetsPod: true, TimestampPresent: true}}}
	row, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	decision, operation, err := podBoundTypedDecision(row, req, barrier.Event.UID)
	if err != nil || operation.TerminationStatus != "REQUEST_CONFIRMED" {
		t.Fatalf("real actuator receipt refused: %+v %v", operation, err)
	}
	if os.Getenv("UPDATE_CPU_TOKEN_AUDIT_PROJECTION") == "1" {
		cpuBase := time.Date(2026, 9, 24, 18, 0, 0, 0, time.UTC)
		cpuReq := req
		cpuReq.Namespace = podBoundTokenCPUNamespace
		cpuReq.CaseID = podBoundTokenCPUCaseID
		cpuReq.MetricFirstAt = cpuBase.Add(30 * time.Second).Format(time.RFC3339Nano)
		cpuReq.MetricSecondAt = cpuBase.Add(50 * time.Second).Format(time.RFC3339Nano)
		cpuReq.RequestedAt = cpuBase.Add(60 * time.Second).Format(time.RFC3339Nano)
		cpuBarrier := barrier
		cpuBarrier.Event.Creator = podBoundCreator(podBoundTokenCPUConfig)
		cpuTrace := trace
		cpuTrace.Timestamp = cpuBase.Add(65 * time.Second).Format(time.RFC3339Nano)
		cpuTrace.PolicyNamespace, cpuTrace.AssetNamespace = cpuReq.Namespace, cpuReq.Namespace
		cpuTrace.Facts = append([]model.DecisionFactV2(nil), trace.Facts...)
		steering := *trace.Facts[0].SteeredBy
		steering.Events = append([]model.VectorSteeringEvent(nil), steering.Events...)
		steering.Events[0].CreatorIdentity = cpuBarrier.Event.Creator
		cpuTrace.Facts[0].SteeredBy = &steering
		cpuReceipt := *receipt
		cpuReceipt.PolicyNamespace = cpuReq.Namespace
		cpuRec := rec
		cpuRec.Time = cpuBase.Add(65 * time.Second)
		cpuRec.Namespace = cpuReq.Namespace
		cpuRec.DecisionTrace = cpuTrace
		cpuRec.GracefulTermination = &cpuReceipt
		cpuRec.Events = append([]model.EventEvidence(nil), rec.Events...)
		cpuRec.Events[0].CreatorIdentity = cpuBarrier.Event.Creator
		cpuRaw, marshalErr := json.Marshal(cpuRec)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		cpuDecision, cpuOperation, projectErr := podBoundTypedDecision(cpuRaw, cpuReq, cpuBarrier.Event.UID)
		if projectErr != nil {
			t.Fatal(projectErr)
		}
		projection, marshalErr := json.Marshal(struct {
			Raw       json.RawMessage        `json:"raw"`
			Decision  PodBoundTokenDecision  `json:"decision"`
			Operation PodBoundTokenOperation `json:"operation"`
			RowSHA256 string                 `json:"rowSHA256"`
		}{cpuRaw, cpuDecision, cpuOperation, podBoundHash(cpuRaw)})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		path := filepath.Join("..", "..", "..", "build", "test-harness", "testdata", "pod_bound_token_cpu_positive", "audit-projection.json")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, projection, 0600); err != nil {
			t.Fatal(err)
		}
	}
	barrier.RequestSHA256 = podBoundHash(reqRaw)
	barrier.Decision, barrier.Operation, barrier.DecisionRowSHA = decision, operation, podBoundHash(row)
	barrierRaw := mongoTestJSON(t, filepath.Join(out, podBoundBarrierFile), barrier)
	var end podBoundTokenObservationEnd
	if _, err := readPodBoundJSON(out, podBoundObservationEndFile, &end); err != nil {
		t.Fatal(err)
	}
	end.RequestSHA256, end.BarrierSHA256 = podBoundHash(reqRaw), podBoundHash(barrierRaw)
	endRaw := mongoTestJSON(t, filepath.Join(out, podBoundObservationEndFile), end)
	var artifact podBoundTokenArtifact
	if _, err := readPodBoundJSON(out, podBoundArtifactFile, &artifact); err != nil {
		t.Fatal(err)
	}
	artifact.RequestSHA256, artifact.BarrierSHA256 = podBoundHash(reqRaw), podBoundHash(barrierRaw)
	artifact.Result.Decision, artifact.Result.Operation = decision, operation
	artifact.Result.Operation.OriginalPodAbsent = true
	artifact.Result.MechanismObserved = true
	artifact.Result.Replay.SourceAfterHTTP = 401
	artifact.Result.Telemetry = PodBoundTokenTelemetry{ProducerStatus: req.MetricStatus, FirstAt: req.MetricFirstAt, SecondAt: req.MetricSecondAt, FirstValue: req.MetricFirstValue, SecondValue: req.MetricSecondValue, SourcePodName: req.MetricSourcePodName, PodMonitorUID: req.PodMonitorUID, QuerySHA256: req.MetricQuerySHA256}
	replayRaw := mustReadPodBoundFile(t, out, podBoundReplayFile)
	replayChanged := strings.Replace(string(replayRaw), `"http":200,"nonce":"`+req.Nonce+`","phase":"source-after"`, `"http":401,"nonce":"`+req.Nonce+`","phase":"source-after"`, 1)
	if replayChanged == string(replayRaw) {
		t.Fatal("producer source replay row missing")
	}
	mongoTestWrite(t, filepath.Join(out, podBoundReplayFile), []byte(replayChanged))
	phases := mustReadPodBoundFile(t, out, podBoundPhaseFile)
	absence, err := json.Marshal(podBoundPhaseRow{Schema: "pod-bound-token-phase-v1", RunID: req.RunID, Nonce: req.Nonce, Operation: "ORIGINAL_POD_ABSENT", Resource: "pods", Name: req.SourcePodName, UID: req.SourcePodUID, At: base.Add(45 * time.Second).Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	cut := []byte(`{"at":"2026-09-24T16:01:25Z"`)
	idx := strings.Index(string(phases), string(cut))
	if idx < 0 {
		t.Fatal("producer cleanup phase missing")
	}
	changedPhases := append(append(append([]byte(nil), phases[:idx]...), absence...), '\n')
	changedPhases = append(changedPhases, phases[idx:]...)
	mongoTestWrite(t, filepath.Join(out, podBoundPhaseFile), changedPhases)
	artifact.PhaseJournalSHA256 = podBoundHash(changedPhases)
	artifactRaw := mongoTestJSON(t, filepath.Join(out, podBoundArtifactFile), artifact)
	var terminal podBoundTokenTerminal
	if _, err := readPodBoundJSON(out, podBoundTerminalFile, &terminal); err != nil {
		t.Fatal(err)
	}
	terminal.ArtifactSHA256 = podBoundHash(artifactRaw)
	mongoTestJSON(t, filepath.Join(out, podBoundTerminalFile), terminal)
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	auditPath := filepath.Join(dir, "audit.jsonl")
	mongoTestWrite(t, auditPath, append(append([]byte(nil), row...), '\n'))
	source := audittransport.ServerConfig{AuditPath: auditPath, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test"}
	ts := httptest.NewUnstartedServer(source.Handler())
	ts.TLS = source.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := client.Manifest(context.Background())
	if err != nil || len(manifest.Segments) != 1 {
		t.Fatalf("audit manifest: %v", err)
	}
	seg := manifest.Segments[0]
	start := podBoundTokenAuditStart{Schema: "pod-bound-token-audit-start-v1", RunID: req.RunID, Nonce: req.Nonce, SourceIdentity: "fixture-audit-source", Segment: seg, Offset: 0, RequestSHA256: podBoundHash(reqRaw)}
	mongoTestJSON(t, filepath.Join(out, "pod-bound-token-audit-start.json"), start)
	var committed podBoundTokenObservationCommitted
	if _, err := readPodBoundJSON(out, podBoundObservationCommittedFile, &committed); err != nil {
		t.Fatal(err)
	}
	committed.RequestSHA256, committed.BarrierSHA256, committed.ObservationEndSHA256 = podBoundHash(reqRaw), podBoundHash(barrierRaw), podBoundHash(endRaw)
	committed.Commitment = audittransport.ExactWindowCommitment{Segment: seg, StartOffset: 0, EndOffset: seg.Size, WindowSHA256: podBoundHash(append(append([]byte(nil), row...), '\n')), CapturedAtUnixNano: base.Add(82 * time.Second).UnixNano()}
	mongoTestJSON(t, filepath.Join(out, podBoundObservationCommittedFile), committed)
	rm := &RunManager{cfg: Config{AuditSource: client, AuditSourceIdentity: "fixture-audit-source"}}
	if err := rm.sealPodBoundTokenAudit(req.RunID, out); err != nil {
		t.Fatalf("authenticated selected audit refused: %v", err)
	}
	result, err := readPodBoundTokenResult(out, req.RunID)
	if err != nil || !result.MechanismObserved || result.Replay.SourceAfterHTTP != 401 || result.Replay.PeerAfterHTTP != 200 || result.Replay.ServiceAfterHTTP != 200 || !result.Operation.OriginalPodAbsent {
		t.Fatalf("producer rotate observation lost: %+v %v", result, err)
	}
	// Each counterexample keeps the ordinary JSON link hashes internally
	// consistent. The reader must reject the underlying causal contradiction.
	for _, tc := range []struct {
		name   string
		change func(string, *podBoundTokenRequest, *podBoundTokenBarrier, *podBoundTokenArtifact)
	}{
		{"wrong native receipt", func(_ string, _ *podBoundTokenRequest, b *podBoundTokenBarrier, a *podBoundTokenArtifact) {
			b.Operation.ReceiptSHA256 = strings.Repeat("f", 64)
			a.Result.Operation.ReceiptSHA256 = b.Operation.ReceiptSHA256
		}},
		{"retained source still 200", func(path string, _ *podBoundTokenRequest, _ *podBoundTokenBarrier, _ *podBoundTokenArtifact) {
			raw := mustReadPodBoundFile(t, path, podBoundReplayFile)
			changed := strings.Replace(string(raw), `"http":401,"nonce":"`+req.Nonce+`","phase":"source-after"`, `"http":200,"nonce":"`+req.Nonce+`","phase":"source-after"`, 1)
			if changed == string(raw) {
				t.Fatal("positive source-after row missing")
			}
			mongoTestWrite(t, filepath.Join(path, podBoundReplayFile), []byte(changed))
		}},
		{"service owner changed", func(_ string, _ *podBoundTokenRequest, _ *podBoundTokenBarrier, a *podBoundTokenArtifact) {
			a.Result.Replay.ServiceMemberOwnerDeploymentUID = "other-deployment"
		}},
		{"source replay after expiry", func(_ string, r *podBoundTokenRequest, _ *podBoundTokenBarrier, a *podBoundTokenArtifact) {
			r.SourceExpiry = base.Add(49 * time.Second).Format(time.RFC3339Nano)
			a.Result.Replay.SourceExpiry = r.SourceExpiry
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changedOut := t.TempDir()
			entries, e := os.ReadDir(out)
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				mongoTestWrite(t, filepath.Join(changedOut, entry.Name()), mustReadPodBoundFile(t, out, entry.Name()))
			}
			var r podBoundTokenRequest
			var b podBoundTokenBarrier
			var a podBoundTokenArtifact
			var endRecord podBoundTokenObservationEnd
			var c podBoundTokenObservationCommitted
			var s podBoundTokenAuditSeal
			var start podBoundTokenAuditStart
			var term podBoundTokenTerminal
			for _, item := range []struct {
				name  string
				value any
			}{{podBoundRequestFile, &r}, {podBoundBarrierFile, &b}, {podBoundArtifactFile, &a}, {podBoundObservationEndFile, &endRecord}, {podBoundObservationCommittedFile, &c}, {podBoundSealFile, &s}, {"pod-bound-token-audit-start.json", &start}, {podBoundTerminalFile, &term}} {
				if _, err := readPodBoundJSON(changedOut, item.name, item.value); err != nil {
					t.Fatal(err)
				}
			}
			tc.change(changedOut, &r, &b, &a)
			rawReq := mongoTestJSON(t, filepath.Join(changedOut, podBoundRequestFile), r)
			b.RequestSHA256 = podBoundHash(rawReq)
			rawBarrier := mongoTestJSON(t, filepath.Join(changedOut, podBoundBarrierFile), b)
			endRecord.RequestSHA256, endRecord.BarrierSHA256 = podBoundHash(rawReq), podBoundHash(rawBarrier)
			rawEnd := mongoTestJSON(t, filepath.Join(changedOut, podBoundObservationEndFile), endRecord)
			a.RequestSHA256, a.BarrierSHA256 = podBoundHash(rawReq), podBoundHash(rawBarrier)
			rawArtifact := mongoTestJSON(t, filepath.Join(changedOut, podBoundArtifactFile), a)
			term.ArtifactSHA256 = podBoundHash(rawArtifact)
			mongoTestJSON(t, filepath.Join(changedOut, podBoundTerminalFile), term)
			c.RequestSHA256, c.BarrierSHA256, c.ObservationEndSHA256 = podBoundHash(rawReq), podBoundHash(rawBarrier), podBoundHash(rawEnd)
			rawCommit := mongoTestJSON(t, filepath.Join(changedOut, podBoundObservationCommittedFile), c)
			start.RequestSHA256 = podBoundHash(rawReq)
			mongoTestJSON(t, filepath.Join(changedOut, "pod-bound-token-audit-start.json"), start)
			s.RequestSHA256, s.BarrierSHA256, s.ArtifactSHA256, s.ObservationCommitSHA256 = podBoundHash(rawReq), podBoundHash(rawBarrier), podBoundHash(rawArtifact), podBoundHash(rawCommit)
			mongoTestJSON(t, filepath.Join(changedOut, podBoundSealFile), s)
			if got, err := readPodBoundTokenResult(changedOut, r.RunID); err == nil {
				t.Fatalf("self-consistent adverse producer bytes credited: %+v", got)
			}
		})
	}
}

func TestPodBoundCPUOriginalPositiveReceiptWithAuthenticatedAudit(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	producer := filepath.Join("..", "..", "..", "build", "test-harness", "testdata", "pod_bound_token_cpu_positive")
	for _, name := range []string{podBoundRequestFile, podBoundBarrierFile, podBoundObservationEndFile, podBoundObservationCommittedFile, podBoundEventCleanupFile, podBoundReplayFile, podBoundPhaseFile, podBoundArtifactFile, podBoundTerminalFile} {
		mongoTestWrite(t, filepath.Join(out, name), mustReadPodBoundFile(t, producer, name))
	}
	var projection struct {
		Raw       json.RawMessage        `json:"raw"`
		Decision  PodBoundTokenDecision  `json:"decision"`
		Operation PodBoundTokenOperation `json:"operation"`
		RowSHA256 string                 `json:"rowSHA256"`
	}
	if err := json.Unmarshal(mustReadPodBoundFile(t, producer, "audit-projection.json"), &projection); err != nil {
		t.Fatal(err)
	}
	var req podBoundTokenRequest
	reqRaw, err := readPodBoundJSON(out, podBoundRequestFile, &req)
	if err != nil {
		t.Fatal(err)
	}
	var barrier podBoundTokenBarrier
	barrierRaw, err := readPodBoundJSON(out, podBoundBarrierFile, &barrier)
	if err != nil {
		t.Fatal(err)
	}
	if req.CaseID != podBoundTokenCPUCaseID || req.Namespace != podBoundTokenCPUNamespace || barrier.DecisionRowSHA != podBoundHash(projection.Raw) || barrier.Decision != projection.Decision || barrier.Operation != projection.Operation {
		t.Fatal("original CPU producer projection changed")
	}
	decision, operation, err := podBoundTypedDecision(projection.Raw, req, barrier.Event.UID)
	if err != nil || decision != projection.Decision || operation != projection.Operation {
		t.Fatalf("original CPU typed audit row differs: %v decision=%+v projected=%+v operation=%+v projected=%+v", err, decision, projection.Decision, operation, projection.Operation)
	}
	sc, sk, cc, ck, ca := m004Certificates(t, dir)
	auditPath := filepath.Join(dir, "audit.jsonl")
	mongoTestWrite(t, auditPath, append(append([]byte(nil), projection.Raw...), '\n'))
	source := audittransport.ServerConfig{AuditPath: auditPath, CertFile: sc, KeyFile: sk, CAFile: ca, ClientDNSName: "audit-console.test"}
	ts := httptest.NewUnstartedServer(source.Handler())
	ts.TLS = source.TLSConfig()
	ts.StartTLS()
	defer ts.Close()
	client, err := audittransport.NewClient(audittransport.ClientConfig{URL: ts.URL, ServerDNSName: "audit-source.test", CertFile: cc, KeyFile: ck, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := client.Manifest(context.Background())
	if err != nil || len(manifest.Segments) != 1 {
		t.Fatalf("local audit manifest: %v", err)
	}
	seg := manifest.Segments[0]
	start := podBoundTokenAuditStart{Schema: "pod-bound-token-audit-start-v1", RunID: req.RunID, Nonce: req.Nonce, SourceIdentity: "fixture-audit-source", Segment: seg, Offset: 0, RequestSHA256: podBoundHash(reqRaw)}
	mongoTestJSON(t, filepath.Join(out, "pod-bound-token-audit-start.json"), start)
	var end podBoundTokenObservationEnd
	endRaw, err := readPodBoundJSON(out, podBoundObservationEndFile, &end)
	if err != nil {
		t.Fatal(err)
	}
	var committed podBoundTokenObservationCommitted
	if _, err := readPodBoundJSON(out, podBoundObservationCommittedFile, &committed); err != nil {
		t.Fatal(err)
	}
	committed.RequestSHA256, committed.BarrierSHA256, committed.ObservationEndSHA256 = podBoundHash(reqRaw), podBoundHash(barrierRaw), podBoundHash(endRaw)
	committed.Commitment = audittransport.ExactWindowCommitment{Segment: seg, StartOffset: 0, EndOffset: seg.Size, WindowSHA256: podBoundHash(append(append([]byte(nil), projection.Raw...), '\n')), CapturedAtUnixNano: time.Date(2026, 9, 24, 18, 1, 42, 0, time.UTC).UnixNano()}
	// The commitment is a console-owned authenticated ACK, never a producer
	// artifact. All producer-authored request, replay, phase, barrier, end,
	// artifact and terminal bytes remain unchanged from testdata.
	mongoTestJSON(t, filepath.Join(out, podBoundObservationCommittedFile), committed)
	rm := &RunManager{cfg: Config{AuditSource: client, AuditSourceIdentity: "fixture-audit-source"}}
	if err := rm.sealPodBoundTokenAudit(req.RunID, out); err != nil {
		t.Fatalf("authenticated CPU audit seal refused: %v", err)
	}
	result, err := readPodBoundTokenResult(out, req.RunID)
	if err != nil || !result.MechanismObserved || result.CaseID != podBoundTokenCPUCaseID || result.Replay.SourceAfterHTTP != 401 || result.Replay.PeerAfterHTTP != 200 {
		t.Fatalf("unchanged CPU original positive receipt refused: %+v %v", result, err)
	}
	var original podBoundTokenArtifact
	if _, err := readPodBoundJSON(out, podBoundArtifactFile, &original); err != nil {
		t.Fatal(err)
	}
	beforeMonitor := req
	beforeMonitor.MetricFirstAt = time.Date(2026, 9, 24, 18, 0, 20, 0, time.UTC).Format(time.RFC3339Nano)
	if err := verifyPodBoundPhaseJournal(out, beforeMonitor, barrier, original); err == nil {
		t.Fatal("metric sample before owned PodMonitor ACK accepted")
	}
	for _, tc := range []struct{ name, old, new string }{{"late source response", `"at":"2026-09-24T18:01:20Z","captureID"`, `"at":"2026-09-24T18:20:00Z","captureID"`}, {"recaptured source handle", `"captureID":"` + req.SourceCaptureID + `"`, `"captureID":"` + strings.Repeat("f", 32) + `"`}} {
		t.Run(tc.name, func(t *testing.T) {
			changed := t.TempDir()
			entries, e := os.ReadDir(out)
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				mongoTestWrite(t, filepath.Join(changed, entry.Name()), mustReadPodBoundFile(t, out, entry.Name()))
			}
			raw := string(mustReadPodBoundFile(t, changed, podBoundReplayFile))
			modified := strings.Replace(raw, tc.old, tc.new, 1)
			if modified == raw {
				t.Fatal("adverse original replay marker absent")
			}
			mongoTestWrite(t, filepath.Join(changed, podBoundReplayFile), []byte(modified))
			if _, e := readPodBoundTokenResult(changed, req.RunID); e == nil {
				t.Fatal("altered original CPU replay accepted")
			}
		})
	}
}

func mustReadPodBoundFile(t *testing.T, out, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(out, name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
