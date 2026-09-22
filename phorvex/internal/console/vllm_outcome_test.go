package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func actualGuardrailExec(t *testing.T, serverURL string) func(string) (string, error) {
	t.Helper()
	return func(command string) (string, error) {
		command = strings.ReplaceAll(command, vllmGuardrailURL, serverURL)
		out, err := exec.Command("sh", "-c", command).CombinedOutput()
		return string(out), err
	}
}

func TestVLLMGuardrailHTTPProducerValidatesAcknowledgementAndReadback(t *testing.T) {
	var mu sync.Mutex
	active := "pgv2"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/guardrail/state":
			_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "active": active})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/guardrail/reload":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			active = body["variant"]
			_ = json.NewEncoder(w).Encode(map[string]any{"active": active, "applied": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	execIn := actualGuardrailExec(t, server.URL)
	state, err := readGuardrailState(execIn)
	if err != nil || state.Active != "pgv2" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	state, err = reloadGuardrail(execIn, "pgv1")
	if err != nil || state.Active != "pgv1" {
		t.Fatalf("reload state=%+v err=%v", state, err)
	}
}

func TestVLLMGuardrailHTTPProducerRejectsFailedAndMalformedReplies(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.Handler
	}{
		{"http failure", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
		})},
		{"malformed", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"ready":true}`)) })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()
			if _, err := readGuardrailState(actualGuardrailExec(t, server.URL)); err == nil {
				t.Fatal("invalid producer reply accepted")
			}
		})
	}
}

func testStimulus() *attackStimulusEvidence {
	return &attackStimulusEvidence{Kind: "synthetic-security-event", Observed: true, TargetUID: "pod-uid", EventName: "event-1", EventUID: "event-uid", EventCreatedAt: "2026-09-22T14:00:00Z", EventRule: "phorvex.attack.guardrail", Correlation: "corr", BehavioralExecuted: false, Limitation: "no behavioral attack"}
}

func vllmEffectExec(t *testing.T, serverURL string, activePodUID string) func(time.Duration, string, ...string) (string, error) {
	t.Helper()
	return func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" {
			return "", errors.New("unexpected binary")
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, " exec "):
			command := args[len(args)-1]
			return actualGuardrailExec(t, serverURL)(command)
		case strings.Contains(joined, "get pod vllm-0 -o json"):
			return `{"metadata":{"name":"vllm-0","uid":"` + activePodUID + `","labels":{"phorvex.ai/route-key":"ep-new"},"annotations":{"phorvex.ai/route-service":"vllm-infer"}}}`, nil
		case strings.Contains(joined, "get securityevent event-1 -o json"):
			return `{"metadata":{"name":"event-1","namespace":"vllm","uid":"event-uid","creationTimestamp":"2026-09-22T14:00:00Z","labels":{"phorvex.ai/attack-correlation":"corr"}},"spec":{"targets":["vllm/vllm-0"],"rule":{"type":"phorvex.attack.guardrail","source":"redteam"}}}`, nil
		case strings.Contains(joined, "get deploy") || strings.Contains(joined, "get statefulset"):
			return "1|1", nil
		default:
			return "", errors.New("unexpected kubectl command: " + joined)
		}
	}
}

func TestGuardrailRuntimeEffectIsNotBehavioralDefense(t *testing.T) {
	var mu sync.Mutex
	active := "pgv1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/v1/guardrail/state" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "active": active})
	}))
	defer server.Close()

	now := time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC)
	cfg := Config{StateDir: t.TempDir(), AttackWatchInterval: time.Millisecond}
	cfg.Now = func() time.Time { return now }
	cfg.Sleep = func(d time.Duration) {
		now = now.Add(d + 20*time.Millisecond)
		mu.Lock()
		active = "pgv2"
		mu.Unlock()
	}
	cfg.Exec = vllmEffectExec(t, server.URL, "pod-uid")
	s := &Server{cfg: cfg}
	r := &attackRecord{ID: "atk-1", FiredAt: now.Format(time.RFC3339Nano), Service: "vllm", Namespace: "vllm", Pod: "vllm-0", Deploy: "vllm", Attack: "Guardrail runtime-effect observation", AttackID: "guardrail-rotate", Expected: "guardrail-rotate", EvidenceKind: "vllm-in-place-effect", TargetUID: "pod-uid", Status: "running", UptimeBefore: 100, started: now, accepted: now, StimulusEvidence: testStimulus(), OutcomeClass: "behavioral-oracle-unsupported", vllmEffect: &vllmEffectBaseline{kind: "guardrail-runtime-state", before: "pgv1"}}
	s.watchAttackUntil("", r, now.Add(100*time.Millisecond), time.Millisecond)
	if r.Status != "done" || r.Outcome != "" || r.Actuated || r.Action != "guardrail-rotate" || r.EffectEvidence == nil || !r.EffectEvidence.Observed || r.OutcomeClass != "effect-only" || r.EffectEvidence.Seconds <= 0 {
		t.Fatalf("effect-only record=%+v effect=%+v", r, r.EffectEvidence)
	}
	if r.DwellSec != 0 || r.DwellOngoing || r.Containment != "" || r.StimulusEvidence.BehavioralExecuted {
		t.Fatalf("effect-only record manufactured behavioral evidence: %+v", r)
	}
	persisted := persistedAttackByID(cfg, r.ID)
	if persisted == nil || persisted.Outcome != "" || persisted.EffectEvidence == nil || !persisted.EffectEvidence.Observed {
		t.Fatalf("persisted effect-only evidence=%+v", persisted)
	}
}

func TestGuardrailUnchangedRuntimeIsPartialNotLanded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "active": "pgv1"})
	}))
	defer server.Close()
	now := time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC)
	cfg := Config{StateDir: t.TempDir()}
	cfg.Now = func() time.Time { return now }
	cfg.Sleep = func(d time.Duration) { now = now.Add(d) }
	cfg.Exec = vllmEffectExec(t, server.URL, "pod-uid")
	s := &Server{cfg: cfg}
	r := &attackRecord{ID: "atk-2", FiredAt: now.Format(time.RFC3339Nano), Service: "vllm", Namespace: "vllm", Pod: "vllm-0", Deploy: "vllm", AttackID: "guardrail-rotate", Expected: "guardrail-rotate", EvidenceKind: "vllm-in-place-effect", TargetUID: "pod-uid", Status: "running", UptimeBefore: 100, started: now, accepted: now, StimulusEvidence: testStimulus(), OutcomeClass: "behavioral-oracle-unsupported", vllmEffect: &vllmEffectBaseline{kind: "guardrail-runtime-state", before: "pgv1"}}
	s.watchAttackUntil("", r, now.Add(3*time.Millisecond), time.Millisecond)
	if r.Status != "partial" || r.Outcome != "" || r.Actuated || r.EffectEvidence != nil || r.OutcomeClass != "effect-unverified" || r.ObservationError == "" {
		t.Fatalf("unverified record=%+v", r)
	}
}

func TestGuardrailEffectCompletingAfterDeadlineIsNotCredited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "active": "pgv2"})
	}))
	defer server.Close()
	now := time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC)
	deadline := now.Add(10 * time.Millisecond)
	baseExec := vllmEffectExec(t, server.URL, "pod-uid")
	cfg := Config{StateDir: t.TempDir()}
	cfg.Now = func() time.Time { return now }
	cfg.Sleep = func(d time.Duration) { now = now.Add(d) }
	cfg.Exec = func(timeout time.Duration, bin string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), " exec ") {
			now = deadline.Add(time.Millisecond)
		}
		return baseExec(timeout, bin, args...)
	}
	s := &Server{cfg: cfg}
	r := &attackRecord{ID: "atk-late", FiredAt: now.Format(time.RFC3339Nano), Service: "vllm", Namespace: "vllm", Pod: "vllm-0", Deploy: "vllm", AttackID: "guardrail-rotate", Expected: "guardrail-rotate", EvidenceKind: "vllm-in-place-effect", TargetUID: "pod-uid", Status: "running", UptimeBefore: 100, started: now, accepted: now, StimulusEvidence: testStimulus(), OutcomeClass: "behavioral-oracle-unsupported", vllmEffect: &vllmEffectBaseline{kind: "guardrail-runtime-state", before: "pgv1"}}
	s.watchAttackUntil("", r, deadline, time.Millisecond)
	if r.Status != "partial" || r.Outcome != "" || r.EffectEvidence != nil || r.Actuated || !strings.Contains(r.ObservationError, "outside the registered window") {
		t.Fatalf("late effect was credited: %+v", r)
	}
}

func TestCreateCorrelatedVLLMEventRequiresExactAPIAcknowledgement(t *testing.T) {
	now := time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC)
	s := &Server{cfg: Config{Now: func() time.Time { return now }, Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || !strings.Contains(strings.Join(args, " "), " create ") {
			return "", errors.New("unexpected command")
		}
		manifest, err := os.ReadFile(args[4])
		if err != nil {
			return "", err
		}
		name, correlation := "", ""
		for _, line := range strings.Split(string(manifest), "\n") {
			if strings.HasPrefix(line, "  name: ") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "  name: "))
			}
			if strings.Contains(line, "phorvex.ai/attack-correlation:") {
				correlation = strings.Trim(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), `"`)
			}
		}
		return `{"metadata":{"name":"` + name + `","namespace":"vllm","uid":"event-uid","creationTimestamp":"2026-09-22T14:00:00Z","labels":{"phorvex.ai/attack-correlation":"` + correlation + `"}},"spec":{"targets":["vllm/vllm-0"],"rule":{"type":"phorvex.attack.guardrail","source":"redteam"}}}`, nil
	}}}
	evidence, err := s.createCorrelatedVLLMEvent("vllm-0", "pod-uid", "GuardrailBypass", "signal", "0.95")
	if err != nil || !evidence.Observed || evidence.EventUID != "event-uid" || evidence.BehavioralExecuted {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	s.cfg.Exec = func(_ time.Duration, _ string, args ...string) (string, error) {
		return `{"metadata":{"name":"foreign","namespace":"vllm","uid":"foreign-uid","creationTimestamp":"2026-09-22T14:00:00Z","labels":{"phorvex.ai/attack-correlation":"wrong"}},"spec":{"targets":["vllm/foreign"],"rule":{"type":"phorvex.attack.guardrail","source":"redteam"}}}`, nil
	}
	if _, err := s.createCorrelatedVLLMEvent("vllm-0", "pod-uid", "GuardrailBypass", "signal", "0.95"); err == nil || !strings.Contains(err.Error(), "requires reconciliation") {
		t.Fatalf("foreign API acknowledgement accepted: %v", err)
	}
}

func TestEndpointRouteEffectRetainsUnsupportedBehavioralVerdict(t *testing.T) {
	execFn := func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" {
			return "", errors.New("unexpected binary")
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "get pod vllm-0 -o json"):
			return `{"metadata":{"name":"vllm-0","uid":"pod-uid","labels":{"phorvex.ai/route-key":"ep-new"},"annotations":{"phorvex.ai/route-service":"vllm-infer"}}}`, nil
		case strings.Contains(joined, "get securityevent event-1 -o json"):
			return `{"metadata":{"name":"event-1","namespace":"vllm","uid":"event-uid","creationTimestamp":"2026-09-22T14:00:00Z","labels":{"phorvex.ai/attack-correlation":"corr"}},"spec":{"targets":["vllm/vllm-0"],"rule":{"type":"EndpointPinning","source":"redteam"}}}`, nil
		case strings.Contains(joined, "get service vllm-infer -o json"):
			return `{"metadata":{"name":"vllm-infer","uid":"service-uid"},"spec":{"selector":{"app":"vllm","phorvex.ai/route-key":"ep-new"}}}`, nil
		case strings.Contains(joined, "get endpointslice"):
			return `{"items":[{"metadata":{"labels":{"kubernetes.io/service-name":"vllm-infer"},"ownerReferences":[{"kind":"Service","name":"vllm-infer","uid":"service-uid"}]},"endpoints":[{"targetRef":{"uid":"pod-uid"},"conditions":{"ready":true,"terminating":false}}]}]}`, nil
		default:
			return "", errors.New("unexpected kubectl command: " + joined)
		}
	}
	s := &Server{cfg: Config{Exec: execFn, Now: func() time.Time { return time.Date(2026, 9, 22, 14, 0, 1, 0, time.UTC) }}}
	stimulus := testStimulus()
	stimulus.EventRule = "EndpointPinning"
	r := &attackRecord{Namespace: "vllm", Pod: "vllm-0", TargetUID: "pod-uid", StimulusEvidence: stimulus, vllmEffect: &vllmEffectBaseline{kind: "endpoint-route-state", before: "ep-old", serviceUID: "service-uid"}}
	effect, err := s.observeVLLMInPlaceEffect(r)
	if err != nil || effect == nil || !effect.Observed || effect.After != "ep-new" || effect.ServiceUID != "service-uid" {
		t.Fatalf("effect=%+v err=%v", effect, err)
	}
	if r.Outcome != "" || r.StimulusEvidence.BehavioralExecuted {
		t.Fatalf("route effect manufactured behavioral verdict: %+v", r)
	}
	r.TargetUID = "stale-pod-uid"
	if effect, err := s.observeVLLMInPlaceEffect(r); err == nil || effect != nil || !strings.Contains(err.Error(), "UID changed") {
		t.Fatalf("stale target accepted effect=%+v err=%v", effect, err)
	}
}

func TestEndpointSetupRestorationUsesExactCapturedAuthority(t *testing.T) {
	var writes []string
	s := &Server{cfg: Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" {
			return "", errors.New("unexpected binary")
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "get pod vllm-0 -o json"):
			return `{"metadata":{"name":"vllm-0","uid":"pod-uid","labels":{"phorvex.ai/route-key":"ep-old"},"annotations":{"phorvex.ai/route-service":"vllm-infer"}}}`, nil
		case strings.Contains(joined, "get service vllm-infer -o json"):
			return `{"metadata":{"name":"vllm-infer","uid":"service-uid"},"spec":{"selector":{"app":"vllm","phorvex.ai/route-key":"ep-old"}}}`, nil
		default:
			writes = append(writes, joined)
			return "restored", nil
		}
	}}}
	authority := &endpointSetupAuthority{pod: "vllm-0", targetUID: "pod-uid", serviceUID: "service-uid", oldSelector: map[string]string{"app": "vllm", "phorvex.ai/role": "leader"}}
	if err := s.restoreEndpointSetup(authority); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(writes, "\n")
	for _, required := range []string{"phorvex.ai/route-key-", "phorvex.ai/route-service-", `"phorvex.ai/role":"leader"`, `"phorvex.ai/route-key":null`} {
		if !strings.Contains(joined, required) {
			t.Fatalf("restoration omitted %q:\n%s", required, joined)
		}
	}
}
