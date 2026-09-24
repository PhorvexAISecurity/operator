package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
)

type catalogueSignalExec struct {
	mu         sync.Mutex
	created    []string
	manifests  []string
	createErr  error
	deleteCall bool
}

func (f *catalogueSignalExec) run(_ time.Duration, bin string, args ...string) (string, error) {
	if bin != "kubectl" {
		return "", errors.New("unexpected executable: " + bin)
	}
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "get phorvexpolicy -o name"):
		return "phorvexpolicy.amtd.r6security.com/demo", nil
	case strings.Contains(joined, "get pod -l r6th.io/rotation-target=true"):
		return "demo-0|ReplicaSet|Running\n", nil
	case strings.Contains(joined, "get pod demo-0 -o jsonpath={.spec.volumes"):
		return "", nil
	case strings.Contains(joined, "get pod demo-0 -o jsonpath={.metadata.uid}"):
		return "pod-uid", nil
	case strings.Contains(joined, "get deploy -o name"):
		return "deployment.apps/demo", nil
	case strings.Contains(joined, "get deploy demo --ignore-not-found"):
		return "1|1", nil
	case strings.Contains(joined, "get statefulset"):
		return "", nil
	case strings.Contains(joined, "get networkpolicy") || strings.Contains(joined, "get securityevent"):
		return "", nil
	case strings.Contains(joined, "delete securityevent"):
		f.mu.Lock()
		f.deleteCall = true
		f.mu.Unlock()
		return "", nil
	case strings.Contains(joined, "create -f"):
		path := ""
		for i := range args {
			if args[i] == "-f" && i+1 < len(args) {
				path = args[i+1]
			}
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		name := manifestValue(string(raw), "name:")
		correlation := manifestValue(string(raw), "phorvex.ai/attack-correlation:")
		targetUID := manifestValue(string(raw), "phorvex.ai/console-target-pod-uid:")
		rule := manifestValue(string(raw), "type:")
		f.mu.Lock()
		f.created = append(f.created, name)
		f.manifests = append(f.manifests, string(raw))
		createErr := f.createErr
		f.mu.Unlock()
		if createErr != nil {
			return "lost create acknowledgement", createErr
		}
		return `{"metadata":{"name":"` + name + `","uid":"event-uid-` + correlation + `","creationTimestamp":"2026-09-23T19:00:00Z","labels":{"phorvex.ai/attack-correlation":"` + correlation + `","phorvex.ai/console-catalogue":"true"},"annotations":{"phorvex.ai/console-target-pod-uid":"` + targetUID + `"}},"spec":{"targets":["demo/demo-0"],"rule":{"type":"` + rule + `","source":"ExternalDetector"}}}`, nil
	default:
		return "", nil
	}
}

func manifestValue(raw, key string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key) {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, key)), `"`)
		}
	}
	return ""
}

func catalogueHarness(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "harness")
	line := `  - ai1-inference-manipulation [AI] R6=AI1 realism=real benign=false declared=[T0001] exercised=[] caps=[]`
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' '"+line+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, bin
}

func resetSignalAttackLedger(t *testing.T) {
	t.Helper()
	attackMu.Lock()
	savedList, savedLoaded := attackList, attackLoaded
	attackList, attackLoaded = nil, false
	attackMu.Unlock()
	t.Cleanup(func() {
		attackMu.Lock()
		attackList, attackLoaded = savedList, savedLoaded
		attackMu.Unlock()
	})
}

func newCatalogueSignalServer(t *testing.T, fx *catalogueSignalExec, cluster *fakeExperimentCluster) *Server {
	t.Helper()
	harnessDir, harnessBin := catalogueHarness(t)
	stateDir := t.TempDir()
	cfg := Config{
		StateDir: stateDir, HarnessDir: harnessDir, HarnessBin: harnessBin, Exec: fx.run,
		AttackWatchDuration: 40 * time.Millisecond, AttackWatchInterval: 5 * time.Millisecond,
	}
	return &Server{cfg: cfg, experimentAPI: cluster}
}

func launchCatalogueSignal(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/workload/fire-scenario", strings.NewReader(body))
	req = withTestPrincipal(req, testOperatorPrincipal("demo"))
	w := httptest.NewRecorder()
	s.fireScenarioLive(w, req)
	return w
}

func waitCatalogueSignal(t *testing.T, id string) *attackRecord {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rec := attackSnapshotByID(id); rec != nil && rec.Status != "running" {
			return rec
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("catalogue signal watcher did not finish")
	return nil
}

func TestCatalogueSignalRouteIsUnscoredAndObservationOptIn(t *testing.T) {
	resetSignalAttackLedger(t)
	fx := &catalogueSignalExec{}
	cluster := &fakeExperimentCluster{podUID: "pod-uid", podFound: true}
	reads := 0
	cluster.podReadHook = func() {
		reads++
		if reads == 3 {
			cluster.podUID = "replacement-uid"
		}
	}
	s := newCatalogueSignalServer(t, fx, cluster)
	w := launchCatalogueSignal(t, s, `{"namespace":"demo","scenario":"ai1-inference-manipulation","expected":"guardrail-rotate","action":"fire"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("launch code=%d body=%s", w.Code, w.Body.String())
	}
	var launch struct {
		AttackID string `json:"attackId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &launch); err != nil || launch.AttackID == "" {
		t.Fatalf("launch=%s err=%v", w.Body.String(), err)
	}
	rec := waitCatalogueSignal(t, launch.AttackID)
	if rec.Outcome != "" || rec.Actuated || rec.Containment != "" || rec.DwellSec != 0 || rec.EvidenceKind != "catalogue-signal" {
		t.Fatalf("signal received security outcome: %+v", rec)
	}
	if !rec.ResponseObserved || rec.ResponseAction != "rotate" || rec.OutcomeClass != "response-only" {
		t.Fatalf("missing response-only observation: %+v", rec)
	}
	if rec.StimulusEvidence == nil || rec.StimulusEvidence.BehavioralExecuted || !rec.StimulusEvidence.Observed || rec.StimulusEvidence.EventUID == "" {
		t.Fatalf("stimulus evidence=%+v", rec.StimulusEvidence)
	}
	if rec.ProducerRoute != "/api/workload/fire-scenario" || rec.ResultSchema != "catalogue-signal-v1" {
		t.Fatalf("provenance=%+v", rec)
	}

	for _, tc := range []struct {
		query string
		want  int
	}{
		{"?limit=10&id=" + launch.AttackID, 0},
		{"?limit=10&id=" + launch.AttackID + "&includeObservations=true", 1},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/attack-results"+tc.query, nil)
		req = withTestPrincipal(req, testOperatorPrincipal("demo"))
		out := httptest.NewRecorder()
		s.attackResults(out, req)
		var body struct {
			Attacks []attackRecord `json:"attacks"`
		}
		if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil || len(body.Attacks) != tc.want {
			t.Fatalf("query=%s body=%s err=%v", tc.query, out.Body.String(), err)
		}
	}
	foreignReq := httptest.NewRequest(http.MethodGet, "/api/attack-results?limit=10&id="+launch.AttackID+"&includeObservations=true", nil)
	foreignReq = withTestPrincipal(foreignReq, testOperatorPrincipal("other-tenant"))
	foreignOut := httptest.NewRecorder()
	s.attackResults(foreignOut, foreignReq)
	var foreign struct {
		Attacks []attackRecord `json:"attacks"`
	}
	if err := json.Unmarshal(foreignOut.Body.Bytes(), &foreign); err != nil || len(foreign.Attacks) != 0 {
		t.Fatalf("foreign tenant observed signal: body=%s err=%v", foreignOut.Body.String(), err)
	}

	fx.mu.Lock()
	created := append([]string(nil), fx.created...)
	manifests := append([]string(nil), fx.manifests...)
	fx.mu.Unlock()
	if len(created) != 1 || created[0] == "redteam-scn-ai1-inference-manipulation" || !strings.HasPrefix(created[0], "redteam-scn-ai1-inference-manipulation-") {
		t.Fatalf("event name is not unique: %v", created)
	}
	if len(manifests) != 1 || !strings.Contains(manifests[0], `phorvex.ai/console-target-pod-uid: "pod-uid"`) {
		t.Fatalf("legacy-selected catalogue event lacks exact Pod UID binding: %v", manifests)
	}
}

func TestCatalogueSignalCannotPublishTransientDefendedForNamedEffect(t *testing.T) {
	resetSignalAttackLedger(t)
	cluster := &fakeExperimentCluster{podUID: "pod-uid", podFound: true}
	now := time.Now()
	rec := &attackRecord{
		ID: "atk-signal", Namespace: "demo", Pod: "demo-0", TargetUID: "pod-uid", AttackID: "kvcache",
		EvidenceKind: "catalogue-signal", OutcomeClass: "behavioral-oracle-unsupported", Status: "running",
		accepted: now, started: now, baseKVEpoch: "old",
	}
	s := &Server{cfg: Config{
		StateDir: t.TempDir(), AttackWatchInterval: 5 * time.Millisecond,
		Now: time.Now, Exec: func(_ time.Duration, _ string, args ...string) (string, error) {
			if strings.Contains(strings.Join(args, " "), "kv-reset-epoch") {
				return "new", nil
			}
			return "", nil
		},
	}, experimentAPI: cluster}
	publishAttack(rec)
	done := make(chan struct{})
	go func() {
		s.watchAttackUntil("", rec, time.Now().Add(45*time.Millisecond), 5*time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(35 * time.Millisecond)
	for time.Now().Before(deadline) {
		mid := attackSnapshotByID(rec.ID)
		if mid != nil && (mid.Outcome != "" || mid.Actuated) {
			t.Fatalf("signal was transiently scored during observation: %+v", mid)
		}
		time.Sleep(time.Millisecond)
	}
	<-done
}

func TestCatalogueSignalFailurePersistsExactCandidateAndClearRefuses(t *testing.T) {
	for _, tc := range []struct {
		name       string
		createErr  error
		clusterUID string
	}{
		{name: "lost create acknowledgement", createErr: errors.New("timeout"), clusterUID: "pod-uid"},
		{name: "target changed after accepted create", clusterUID: "changed-uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetSignalAttackLedger(t)
			fx := &catalogueSignalExec{createErr: tc.createErr}
			cluster := &fakeExperimentCluster{podUID: "pod-uid", podFound: true}
			if tc.createErr == nil {
				reads := 0
				cluster.podReadHook = func() {
					reads++
					if reads == 2 {
						cluster.podUID = tc.clusterUID
					}
				}
			}
			s := newCatalogueSignalServer(t, fx, cluster)
			w := launchCatalogueSignal(t, s, `{"namespace":"demo","scenario":"ai1-inference-manipulation","expected":"guardrail-rotate","action":"fire"}`)
			if w.Code != http.StatusBadGateway {
				t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
			}
			var response struct {
				EventName, EventUID, Correlation, Restoration string
				Mutated                                       bool
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || !response.Mutated || response.EventName == "" || response.Correlation == "" || response.Restoration != "reconciliation-required" {
				t.Fatalf("response=%s err=%v", w.Body.String(), err)
			}
			if tc.createErr == nil && response.EventUID == "" {
				t.Fatalf("accepted event UID missing: %s", w.Body.String())
			}
			ledger, err := readStateLedgerHistory(s.cfg.statePath("effect-intents.jsonl"))
			if err != nil || !strings.Contains(string(ledger), response.EventName) || !strings.Contains(string(ledger), response.Correlation) || !strings.Contains(string(ledger), `"restoration":"reconciliation-required"`) {
				t.Fatalf("ledger=%s err=%v", ledger, err)
			}
			if attackSnapshotByID(response.EventName) != nil {
				t.Fatal("failure registered an attack result")
			}
		})
	}

	fx := &catalogueSignalExec{}
	s := newCatalogueSignalServer(t, fx, &fakeExperimentCluster{podUID: "pod-uid", podFound: true})
	w := launchCatalogueSignal(t, s, `{"namespace":"demo","scenario":"ai1-inference-manipulation","action":"clear"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "exact record-owned") {
		t.Fatalf("clear code=%d body=%s", w.Code, w.Body.String())
	}
	fx.mu.Lock()
	deleted := fx.deleteCall
	fx.mu.Unlock()
	if deleted {
		t.Fatal("clear dispatched an unowned cluster-scoped delete")
	}
}

func TestCatalogueSignalMetadataMismatchRefusesBeforeCreate(t *testing.T) {
	fx := &catalogueSignalExec{}
	s := newCatalogueSignalServer(t, fx, &fakeExperimentCluster{podUID: "pod-uid", podFound: true})
	w := launchCatalogueSignal(t, s, `{"namespace":"demo","scenario":"ai1-inference-manipulation","expected":"kv-reset","action":"fire"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "metadata-mismatch") {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	fx.mu.Lock()
	created := len(fx.created)
	fx.mu.Unlock()
	if created != 0 {
		t.Fatalf("metadata mismatch created %d event(s)", created)
	}
}

func TestGenericObservationFailureDoesNotDefaultLanded(t *testing.T) {
	for _, tc := range []struct {
		name        string
		podErr      error
		wantOutcome string
	}{
		{name: "unavailable remains unscored", podErr: errors.New("read unavailable")},
		{name: "fully observed unchanged behavioral target remains landed", wantOutcome: "LANDED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetSignalAttackLedger(t)
			now := time.Now()
			rec := &attackRecord{ID: "atk-generic", Namespace: "demo", Pod: "demo-0", TargetUID: "pod-uid", AttackID: "foothold", Status: "running", accepted: now, started: now}
			s := &Server{cfg: Config{StateDir: t.TempDir(), Now: time.Now}, experimentAPI: &fakeExperimentCluster{podUID: "pod-uid", podFound: true, podErr: tc.podErr}}
			s.watchAttackUntil("", rec, time.Now().Add(20*time.Millisecond), 5*time.Millisecond)
			if tc.podErr != nil {
				if rec.Outcome != "" || rec.Action != "" || rec.Actuated || rec.OutcomeClass != "observation-unavailable" || rec.ObservationError == "" {
					t.Fatalf("generic error was scored: %+v", rec)
				}
				return
			}
			if rec.Outcome != tc.wantOutcome || rec.Action != "noop" || rec.Actuated || rec.ObservationError != "" {
				t.Fatalf("fully observed behavioral control changed: %+v", rec)
			}
		})
	}
}

func TestCatalogueSignalRetainsTemporalNoopDecisionWithoutCausalClaim(t *testing.T) {
	fired := time.Date(2026, 9, 23, 19, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	rows := []audit.Record{
		{Kind: "phorvex.decision", Time: fired.Add(time.Second), Namespace: "demo", Pod: "demo-0", Action: "noop", Reason: "resource-capacity: no feasible action", Selected: false, Actuated: false},
	}
	data, err := json.Marshal(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{AuditPath: path, Now: func() time.Time { return fired.Add(2 * time.Second) }})
	rec := &attackRecord{FiredAt: fired.Format(time.RFC3339Nano), Namespace: "demo", Pod: "demo-0", EvidenceKind: "catalogue-signal"}
	s.fillReasoning("", rec)
	if rec.DecisionEvidence == nil || rec.DecisionEvidence.Correlation != "temporal-workload-noop" || rec.DecisionEvidence.Action != "noop" || rec.DecisionEvidence.Selected || rec.DecisionEvidence.Actuated || !strings.Contains(rec.DecisionEvidence.Reason, "no feasible") {
		t.Fatalf("temporal NOOP diagnostic missing or overstated: %+v", rec.DecisionEvidence)
	}
}
