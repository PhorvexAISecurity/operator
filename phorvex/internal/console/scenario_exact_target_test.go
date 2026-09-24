package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// This is the actual fire-scenario producer seam. The baseline decoder ignores
// targetPod/targetUid and its preferred-label lookup selects voice-bot-0. The
// repaired handler must emit one UID-bound event for the owned Pod instead.
type exactScenarioExec struct {
	mu             sync.Mutex
	podReads       int
	changeAt       int
	ownerChangeAt  int
	policyChangeAt int
	absent         bool
	wrongNamespace bool
	wrongUID       bool
	notReady       bool
	deleting       bool
	noOwner        bool
	badPolicy      bool
	disabledHint   bool
	overlap        bool
	manifests      []string
}

func (f *exactScenarioExec) run(_ time.Duration, bin string, args ...string) (string, error) {
	if bin != "kubectl" {
		return "", fmt.Errorf("unexpected executable %s", bin)
	}
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "get pod -l r6th.io/rotation-target=true"):
		return "voice-bot-0|ReplicaSet|Running\n", nil
	case strings.Contains(joined, "get phorvexpolicy -o name"):
		return "phorvexpolicy.phorvex.ai/voice-defense", nil
	case strings.Contains(joined, "get pod owned-0 -o jsonpath={.metadata.uid}"):
		return "owned-uid", nil
	case strings.Contains(joined, "get pod owned-0 -o jsonpath="):
		return "", nil
	case strings.Contains(joined, "get pod owned-0 -o json"):
		f.mu.Lock()
		f.podReads++
		read := f.podReads
		f.mu.Unlock()
		if f.absent {
			return "", fmt.Errorf("NotFound")
		}
		uid := "owned-uid"
		if f.wrongUID || (f.changeAt > 0 && read >= f.changeAt) {
			uid = "replacement-uid"
		}
		phase, ready := "Running", "True"
		if f.notReady {
			phase, ready = "Pending", "False"
		}
		owner := `,"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"owned-rs","uid":"rs-uid","controller":true}]`
		if f.noOwner {
			owner = ""
		}
		deletion := ""
		if f.deleting {
			deletion = `,"deletionTimestamp":"2026-09-24T00:00:00Z"`
		}
		ns := "voice"
		if f.wrongNamespace {
			ns = "other"
		}
		return fmt.Sprintf(`{"metadata":{"namespace":%q,"name":"owned-0","uid":%q,"resourceVersion":"17","labels":{"app":"owned","campaign.phorvex.ai/fixture":"nonce-1"}%s%s},"spec":{"volumes":[]},"status":{"phase":%q,"conditions":[{"type":"Ready","status":%q}]}}`, ns, uid, owner, deletion, phase, ready), nil
	case strings.Contains(joined, "get replicaset owned-rs -o json"):
		return `{"metadata":{"namespace":"voice","name":"owned-rs","uid":"rs-uid","resourceVersion":"20","ownerReferences":[{"apiVersion":"apps/v1","kind":"Deployment","name":"owned","uid":"owner-uid","controller":true}]}}`, nil
	case strings.Contains(joined, "get deployment owned -o jsonpath={.metadata.uid}"):
		return "owner-uid", nil
	case strings.Contains(joined, "get deployment owned -o json"):
		uid := "owner-uid"
		if f.ownerChangeAt > 0 && f.podReads >= f.ownerChangeAt {
			uid = "replacement-owner-uid"
		}
		return fmt.Sprintf(`{"metadata":{"namespace":"voice","name":"owned","uid":%q,"resourceVersion":"25"},"spec":{"replicas":2},"status":{"readyReplicas":2}}`, uid), nil
	case strings.Contains(joined, "get phorvexpolicy -o json"):
		mode := "active"
		if f.badPolicy {
			mode = "dryRun"
		}
		generation := 2
		if f.policyChangeAt > 0 && f.podReads >= f.policyChangeAt {
			generation = 3
		}
		action := "rotate"
		if f.disabledHint {
			action = "quarantine"
		}
		items := fmt.Sprintf(`{"metadata":{"namespace":"voice","name":"owned-policy","uid":"policy-uid","resourceVersion":"30","generation":%d},"spec":{"tenant":"voice","selector":{"matchLabels":{"campaign.phorvex.ai/fixture":"nonce-1"}},"mode":%q,"actions":{"enabled":[%q]}}}`, generation, mode, action)
		if f.overlap {
			items += `,{"metadata":{"namespace":"voice","name":"overlap","uid":"other-policy","resourceVersion":"31","generation":1},"spec":{"tenant":"voice","selector":{"matchLabels":{"app":"owned"}},"mode":"active","actions":{"enabled":["rotate"]}}}`
		}
		items += `,{"metadata":{"namespace":"voice","name":"voice-defense","uid":"business-policy","resourceVersion":"5","generation":2},"spec":{"tenant":"voice","selector":{"matchLabels":{"r6th.io/rotation-target":"true"}},"mode":"active","actions":{"enabled":["rotate"]}}}`
		return `{"items":[` + items + `]}`, nil
	case strings.Contains(joined, "get deploy owned --ignore-not-found"):
		return "2|2", nil
	case strings.Contains(joined, "get deploy -o name"):
		return "deployment.apps/voice-bot\ndeployment.apps/owned", nil
	case strings.Contains(joined, "get deploy voice-bot --ignore-not-found"):
		return "3|3", nil
	case strings.Contains(joined, "get pod voice-bot-0 -o jsonpath={.metadata.uid}"):
		return "business-uid", nil
	case strings.Contains(joined, "get pod") && strings.Contains(joined, "persistentVolumeClaim"):
		return "", nil
	case strings.Contains(joined, "get networkpolicy") || strings.Contains(joined, "get securityevent"):
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
		f.mu.Lock()
		f.manifests = append(f.manifests, string(raw))
		f.mu.Unlock()
		name := manifestValue(string(raw), "name:")
		corr := manifestValue(string(raw), "phorvex.ai/attack-correlation:")
		uid := manifestValue(string(raw), "phorvex.ai/console-target-pod-uid:")
		target := strings.Trim(manifestValue(string(raw), "targets:"), `[]"`)
		rule := manifestValue(string(raw), "type:")
		return fmt.Sprintf(`{"metadata":{"name":%q,"uid":"event-uid","creationTimestamp":"2026-09-24T00:00:00Z","labels":{"phorvex.ai/attack-correlation":%q,"phorvex.ai/console-catalogue":"true"},"annotations":{"phorvex.ai/console-target-pod-uid":%q}},"spec":{"targets":[%q],"rule":{"type":%q,"source":"ExternalDetector"}}}`, name, corr, uid, target, rule), nil
	default:
		return "", nil
	}
}

func exactSignalServer(t *testing.T, fx *exactScenarioExec) *Server {
	t.Helper()
	dir, bin := catalogueHarness(t)
	line := `  - c2-persistence-evict [K8s] R6=C2 realism=real benign=false declared=[T0001] exercised=[] caps=[]`
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' '"+line+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: t.TempDir(), HarnessDir: dir, HarnessBin: bin, Exec: fx.run, AttackWatchDuration: 8 * time.Millisecond, AttackWatchInterval: 2 * time.Millisecond}
	return &Server{cfg: cfg, experimentAPI: &fakeExperimentCluster{podUID: "owned-uid", podFound: true}}
}

func exactSignalRequest(s *Server, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/workload/fire-scenario", strings.NewReader(body))
	r = withTestPrincipal(r, testOperatorPrincipal("voice"))
	w := httptest.NewRecorder()
	s.fireScenarioLive(w, r)
	return w
}

func TestExactCatalogueTargetUsesOwnedPodAndDeployment(t *testing.T) {
	resetSignalAttackLedger(t)
	fx := &exactScenarioExec{}
	s := exactSignalServer(t, fx)
	w := exactSignalRequest(s, `{"namespace":"voice","scenario":"c2-persistence-evict","expected":"rotate","action":"fire","targetPod":"owned-0","targetUid":"owned-uid"}`)
	if w.Code != http.StatusOK {
		fx.mu.Lock()
		manifests := append([]string(nil), fx.manifests...)
		fx.mu.Unlock()
		t.Fatalf("status=%d body=%s createdManifests=%v", w.Code, w.Body.String(), manifests)
	}
	var response struct{ AttackID, Pod string }
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.AttackID == "" || response.Pod != "owned-0" {
		t.Fatalf("response=%s err=%v", w.Body.String(), err)
	}
	fX := fx
	fX.mu.Lock()
	manifests := append([]string(nil), fX.manifests...)
	fX.mu.Unlock()
	if len(manifests) != 1 || !strings.Contains(manifests[0], `targets: ["voice/owned-0"]`) || !strings.Contains(manifests[0], `phorvex.ai/console-target-pod-uid: "owned-uid"`) || strings.Contains(manifests[0], "voice-bot-0") {
		t.Fatalf("wrong serialized SecurityEvent: %v", manifests)
	}
	rec := waitCatalogueSignal(t, response.AttackID)
	if rec == nil || rec.Pod != "owned-0" || rec.TargetUID != "owned-uid" || rec.Deploy != "owned" || rec.UptimeBefore != 100 || rec.StimulusEvidence == nil || rec.StimulusEvidence.BehavioralExecuted || rec.Outcome != "" {
		t.Fatalf("wrong owned case baseline: %+v", rec)
	}
	serialized, err := json.Marshal(rec)
	if err != nil || !strings.Contains(string(serialized), `"ownerUid":"owner-uid"`) {
		t.Fatalf("case owner identity missing: %s err=%v", serialized, err)
	}
	intent, err := os.ReadFile(s.cfg.statePath("effect-intents.jsonl"))
	if err != nil || !strings.Contains(string(intent), "owned-uid") || strings.Contains(string(intent), "business-uid") {
		t.Fatalf("intent=%s err=%v", intent, err)
	}
}

func TestExactCatalogueTargetRejectsBeforeIntent(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		modify     func(*exactScenarioExec)
	}{
		{"missing UID", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0"}`, nil},
		{"duplicate Pod", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetPod":"voice-bot-0","targetUid":"owned-uid"}`, nil},
		{"case alias UID", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","TargetUid":"owned-uid"}`, nil},
		{"case alias duplicate", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","TargetPod":"voice-bot-0","targetUid":"owned-uid"}`, nil},
		{"malformed UID", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned/uid"}`, nil},
		{"wrong UID", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"wrong-uid"}`, nil},
		{"absent target", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.absent = true }},
		{"namespace mismatch", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.wrongNamespace = true }},
		{"not Ready", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.notReady = true }},
		{"deleting", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.deleting = true }},
		{"missing owner", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.noOwner = true }},
		{"inactive policy", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.badPolicy = true }},
		{"overlap policy", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.overlap = true }},
		{"replaced on recheck", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.changeAt = 2 }},
		{"owner changed on recheck", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.ownerChangeAt = 2 }},
		{"policy changed on recheck", `{"namespace":"voice","scenario":"c2-persistence-evict","targetPod":"owned-0","targetUid":"owned-uid"}`, func(f *exactScenarioExec) { f.policyChangeAt = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetSignalAttackLedger(t)
			fx := &exactScenarioExec{}
			if tc.modify != nil {
				tc.modify(fx)
			}
			s := exactSignalServer(t, fx)
			w := exactSignalRequest(s, tc.body)
			if w.Code == http.StatusOK {
				t.Fatalf("unsafe request accepted: %s", w.Body.String())
			}
			fx.mu.Lock()
			created := len(fx.manifests)
			fx.mu.Unlock()
			if created != 0 {
				t.Fatalf("rejected request created %d events", created)
			}
			if b, err := os.ReadFile(s.cfg.statePath("effect-intents.jsonl")); err == nil && len(b) > 0 {
				t.Fatalf("rejected request persisted intent: %s", b)
			}
		})
	}
}

func TestExactCatalogueTargetAllowsPolicyDisabledHintAsDiagnosticSignal(t *testing.T) {
	resetSignalAttackLedger(t)
	fx := &exactScenarioExec{disabledHint: true}
	s := exactSignalServer(t, fx)
	w := exactSignalRequest(s, `{"namespace":"voice","scenario":"c2-persistence-evict","expected":"rotate","targetPod":"owned-0","targetUid":"owned-uid"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("a name-based actuator hint became an authorization requirement: %d %s", w.Code, w.Body.String())
	}
}

func TestExactBoundUptimeRejectsReplacedDeploymentInSingleRead(t *testing.T) {
	fx := &exactScenarioExec{ownerChangeAt: 1, podReads: 1}
	s := exactSignalServer(t, fx)
	if got := s.workloadUptimeBound("voice", "owned", "owner-uid"); got != -1 {
		t.Fatalf("replacement owner's 2/2 uptime credited to original owner: %g", got)
	}
}
