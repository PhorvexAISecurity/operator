package console

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestVLLMSetupFailurePersistsRestorationDispositionAndRefusesUnsafeRetry(t *testing.T) {
	dir := t.TempDir()
	s := &Server{cfg: Config{StateDir: dir, Now: func() time.Time { return time.Date(2026, 9, 22, 15, 0, 0, 0, time.UTC) }}}
	cause := errors.New("metadata synchronization failed")
	candidate := &attackStimulusEvidence{EventName: "redteam-vllm-endpointpinning-candidate", Correlation: "candidate-correlation"}
	if err := s.persistVLLMSetupFailure("operator", "endpoint-rotate", "setup", "pod-uid", "service-uid", candidate, true, "restored", cause); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(s.cfg.statePath("effect-intents.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatalf("missing durable setup failure: %v", scanner.Err())
	}
	var record vllmSetupFailureRecord
	if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.TargetUID != "pod-uid" || record.ServiceUID != "service-uid" || record.EventName != candidate.EventName || record.Correlation != candidate.Correlation || !record.Mutated || record.Restoration != "restored" || record.Error != cause.Error() {
		t.Fatalf("durable setup failure mismatch: %+v", record)
	}

	unsafe := &Server{cfg: Config{Now: s.cfg.Now}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/vllm/attack", nil)
	unsafe.writeVLLMSetupFailure(w, r, "guardrail-rotate", "setup", "pod-uid", "", nil, true, "required", cause)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "unsafe-to-retry") {
		t.Fatalf("persistence failure did not surface unsafe retry: code=%d body=%s", w.Code, w.Body.String())
	}
}

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
			return `{"metadata":{"name":"vllm-0","uid":"` + activePodUID + `","resourceVersion":"11","labels":{"phorvex.ai/route-key":"ep-new"},"annotations":{"phorvex.ai/route-service":"vllm-infer"}}}`, nil
		case strings.Contains(joined, "get securityevent event-1 -o json"):
			return `{"metadata":{"name":"event-1","uid":"event-uid","creationTimestamp":"2026-09-22T14:00:00Z","labels":{"phorvex.ai/attack-correlation":"corr","phorvex.ai/console-vllm":"true"}},"spec":{"targets":["vllm/vllm-0"],"rule":{"type":"phorvex.attack.guardrail","source":"redteam"}}}`, nil
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

func TestGuardrailEffectRefusesPodReplacementAcrossHTTPReadback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "active": "pgv2"})
	}))
	defer server.Close()
	podReads := 0
	s := &Server{cfg: Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case bin == "kubectl" && strings.Contains(joined, " exec "):
			return actualGuardrailExec(t, server.URL)(args[len(args)-1])
		case bin == "kubectl" && strings.Contains(joined, "get pod vllm-0 -o json"):
			podReads++
			uid := "pod-uid"
			if podReads > 1 {
				uid = "replacement-uid"
			}
			return `{"metadata":{"name":"vllm-0","uid":"` + uid + `","resourceVersion":"1"}}`, nil
		case bin == "kubectl" && strings.Contains(joined, "get securityevent event-1 -o json"):
			return `{"metadata":{"name":"event-1","uid":"event-uid","creationTimestamp":"2026-09-22T14:00:00Z","labels":{"phorvex.ai/attack-correlation":"corr","phorvex.ai/console-vllm":"true"}},"spec":{"targets":["vllm/vllm-0"],"rule":{"type":"phorvex.attack.guardrail","source":"redteam"}}}`, nil
		default:
			return "", errors.New("unexpected command: " + joined)
		}
	}}}
	r := &attackRecord{Namespace: "vllm", Pod: "vllm-0", TargetUID: "pod-uid", StimulusEvidence: testStimulus(), vllmEffect: &vllmEffectBaseline{kind: "guardrail-runtime-state", before: "pgv1"}}
	effect, err := s.observeVLLMInPlaceEffect(r)
	if err == nil || effect != nil || !strings.Contains(err.Error(), "across guardrail observation") {
		t.Fatalf("replacement effect=%+v err=%v", effect, err)
	}
}

func TestCreateCorrelatedVLLMEventRequiresExactAPIAcknowledgement(t *testing.T) {
	now := time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC)
	s := &Server{cfg: Config{Now: func() time.Time { return now }, Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || !strings.Contains(strings.Join(args, " "), "create -f") {
			return "", errors.New("unexpected command")
		}
		manifest, err := os.ReadFile(args[2])
		if err != nil {
			return "", err
		}
		if strings.Contains(string(manifest), "\n  namespace:") {
			return "", errors.New("cluster-scoped SecurityEvent contained metadata.namespace")
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
		return `{"metadata":{"name":"` + name + `","uid":"event-uid","creationTimestamp":"2026-09-22T14:00:00Z","labels":{"phorvex.ai/attack-correlation":"` + correlation + `","phorvex.ai/console-vllm":"true"}},"spec":{"targets":["vllm/vllm-0"],"rule":{"type":"phorvex.attack.guardrail","source":"redteam"}}}`, nil
	}}}
	evidence, err := s.createCorrelatedVLLMEvent("vllm-0", "pod-uid", "GuardrailBypass", "signal", "0.95")
	if err != nil || !evidence.Observed || evidence.EventUID != "event-uid" || evidence.BehavioralExecuted {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	if !strings.Contains(string(evidence.createManifest), "phorvex.ai/attack-correlation: "+`"`+evidence.Correlation+`"`) ||
		!strings.Contains(string(evidence.createReply), `"uid":"event-uid"`) {
		t.Fatal("original fixed event create request/reply not retained for independent effect projection")
	}
	s.cfg.Exec = func(_ time.Duration, _ string, args ...string) (string, error) {
		return "request timed out after server may have accepted it", errors.New("timeout")
	}
	candidate, err := s.createCorrelatedVLLMEvent("vllm-0", "pod-uid", "GuardrailBypass", "signal", "0.95")
	if err == nil || candidate == nil || candidate.Observed || candidate.EventName == "" || candidate.Correlation == "" || !strings.Contains(err.Error(), candidate.EventName) || !strings.Contains(err.Error(), "outcome unknown") {
		t.Fatalf("unknown create outcome lost reconciliation identity: candidate=%+v err=%v", candidate, err)
	}
	s.cfg.Exec = func(_ time.Duration, _ string, args ...string) (string, error) {
		return `{"metadata":{"name":"foreign","uid":"foreign-uid","creationTimestamp":"2026-09-22T14:00:00Z","labels":{"phorvex.ai/attack-correlation":"wrong","phorvex.ai/console-vllm":"true"}},"spec":{"targets":["vllm/foreign"],"rule":{"type":"phorvex.attack.guardrail","source":"redteam"}}}`, nil
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
			return `{"metadata":{"name":"event-1","uid":"event-uid","creationTimestamp":"2026-09-22T14:00:00Z","labels":{"phorvex.ai/attack-correlation":"corr","phorvex.ai/console-vllm":"true"}},"spec":{"targets":["vllm/vllm-0"],"rule":{"type":"EndpointPinning","source":"redteam"}}}`, nil
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

func TestEndpointSetupRestorationRefusesConcurrentMetadataChange(t *testing.T) {
	writes := 0
	s := &Server{cfg: Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" {
			return "", errors.New("unexpected binary")
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "get pod vllm-0 -o json"):
			return `{"metadata":{"name":"vllm-0","uid":"pod-uid","resourceVersion":"12","labels":{"app":"vllm","foreign":"changed"},"annotations":{"phorvex.ai/route-service":"vllm-infer"}}}`, nil
		case strings.Contains(joined, "get service vllm-infer -o json"):
			return `{"metadata":{"name":"vllm-infer","uid":"service-uid","resourceVersion":"22"},"spec":{"selector":{"app":"vllm","phorvex.ai/route-key":"ep-old"}}}`, nil
		default:
			writes++
			return "", nil
		}
	}}}
	originalLabels := map[string]string{"app": "vllm"}
	stagedLabels := map[string]string{"app": "vllm", "phorvex.ai/route-key": "ep-old"}
	annotations := map[string]string{"phorvex.ai/route-service": "vllm-infer"}
	selector := map[string]string{"app": "vllm", "phorvex.ai/route-key": "ep-old"}
	authority := &endpointSetupAuthority{pod: "vllm-0", targetUID: "pod-uid", serviceUID: "service-uid", originalLabels: &originalLabels, stagedLabels: &stagedLabels, originalAnnotations: &annotations, stagedAnnotations: &annotations, originalSelector: &selector, stagedSelector: &selector, podStaged: true, serviceStaged: true}
	if err := s.restoreEndpointSetup(authority); err == nil || !strings.Contains(err.Error(), "metadata changed") {
		t.Fatalf("concurrent metadata change accepted: %v", err)
	}
	if writes != 0 {
		t.Fatalf("restoration wrote after authority conflict: %d", writes)
	}
}

func TestExactJSONPatchBindsUIDResourceVersionAndAbsentMap(t *testing.T) {
	var command string
	s := &Server{cfg: Config{Exec: func(_ time.Duration, _ string, args ...string) (string, error) {
		command = strings.Join(args, " ")
		return "patched", nil
	}}}
	after := map[string]string{"phorvex.ai/guardrail-variant": "pgv1"}
	if err := s.exactJSONPatch("pod", "vllm-0", "pod-uid", "17", replaceOptionalMapPatch("/metadata/annotations", nil, &after)...); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"path":"/metadata/uid","value":"pod-uid"`, `"path":"/metadata/resourceVersion","value":"17"`, `"op":"add","path":"/metadata/annotations"`} {
		if !strings.Contains(command, required) {
			t.Fatalf("exact patch omitted %q: %s", required, command)
		}
	}
}

func TestGuardrailSetupObservesCoherentCurrentVariantWithoutWrites(t *testing.T) {
	for _, active := range []string{"pgv2", "pgv1"} {
		t.Run(active, func(t *testing.T) {
			posts, kubectlWrites := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					posts++
					http.Error(w, "writes refused", http.StatusMethodNotAllowed)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "active": active})
			}))
			defer server.Close()
			podJSON := fmt.Sprintf(`{"metadata":{"name":"vllm-0","uid":"pod-uid","resourceVersion":"19","annotations":{"phorvex.ai/guardrail-variant":%q,"phorvex.ai/guardrail-variants":"pgv2,pgv1"}}}`, active)
			s := &Server{cfg: Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				if bin == "kubectl" && strings.Contains(joined, "get pod vllm-0 -o json") {
					return podJSON, nil
				}
				if bin == "kubectl" {
					kubectlWrites++
				}
				return "", errors.New("unexpected command: " + joined)
			}}}
			authority, err := s.prepareGuardrailEffect("vllm-0", "pod-uid", actualGuardrailExec(t, server.URL))
			if err != nil || authority == nil || authority.originalRuntime.Active != active || authority.restoration != "not-needed" || posts != 0 || kubectlWrites != 0 {
				t.Fatalf("read-only coherent setup authority=%+v posts=%d kubectlWrites=%d err=%v", authority, posts, kubectlWrites, err)
			}
		})
	}
}

func TestGuardrailSetupRejectsIncoherentOrChangingStateWithoutWrites(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second string
		active        string
	}{
		{name: "runtime-metadata-mismatch", first: "pgv2", second: "pgv2", active: "pgv1"},
		{name: "metadata-changed", first: "pgv2", second: "pgv1", active: "pgv2"},
		{name: "invalid-roster", first: "pgv2", second: "pgv2", active: "pgv2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			posts, reads := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					posts++
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "active": tc.active})
			}))
			defer server.Close()
			s := &Server{cfg: Config{Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
				if bin != "kubectl" || !strings.Contains(strings.Join(args, " "), "get pod vllm-0 -o json") {
					return "", errors.New("unexpected write")
				}
				current := tc.first
				if reads > 0 {
					current = tc.second
				}
				reads++
				roster := "pgv2,pgv1"
				if tc.name == "invalid-roster" {
					roster = "pgv2"
				}
				return fmt.Sprintf(`{"metadata":{"name":"vllm-0","uid":"pod-uid","resourceVersion":"%d","annotations":{"phorvex.ai/guardrail-variant":%q,"phorvex.ai/guardrail-variants":%q}}}`, 19+reads, current, roster), nil
			}}}
			if authority, err := s.prepareGuardrailEffect("vllm-0", "pod-uid", actualGuardrailExec(t, server.URL)); err == nil || authority != nil || posts != 0 {
				t.Fatalf("incoherent setup authority=%+v posts=%d err=%v", authority, posts, err)
			}
		})
	}
}
