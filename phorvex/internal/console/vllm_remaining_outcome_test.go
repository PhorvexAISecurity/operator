package console

import (
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

func actualVLLMExec(t *testing.T, serverURL string) func(string) (string, error) {
	t.Helper()
	return func(command string) (string, error) {
		command = strings.ReplaceAll(command, vllmGuardrailURL, serverURL)
		out, err := exec.Command("sh", "-c", command).CombinedOutput()
		return string(out), err
	}
}

func TestVLLMWorkloadHTTPProducerChecksStatusSchemaAndInventory(t *testing.T) {
	var mu sync.Mutex
	loaded := false
	status := http.StatusServiceUnavailable
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if status != http.StatusOK {
			http.Error(w, "unavailable", status)
			return
		}
		switch r.URL.Path {
		case "/v1/load_lora_adapter":
			loaded = true
			_ = json.NewEncoder(w).Encode(map[string]any{"loaded": true})
		case "/v1/models":
			data := []map[string]string{{"id": "Qwen/Qwen2.5-7B-Instruct-AWQ"}}
			if loaded {
				data = append(data, map[string]string{"id": "evil"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		case "/v1/completions", "/v1/chat/completions":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "choices": []map[string]any{{"index": 0, "finish_reason": "stop"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	execIn := actualVLLMExec(t, server.URL)
	if err := loadVLLMAdapter(execIn, "evil", "/tmp/evil-lora"); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("HTTP 503 adapter load accepted: %v", err)
	}
	if err := runVLLMCompletion(execIn, false, map[string]any{"model": "m", "prompt": "p", "max_tokens": 1}); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("HTTP 503 completion accepted: %v", err)
	}
	mu.Lock()
	status = http.StatusOK
	mu.Unlock()
	if err := loadVLLMAdapter(execIn, "evil", "/tmp/evil-lora"); err != nil {
		t.Fatalf("valid adapter producer failed: %v", err)
	}
	if err := runVLLMCompletion(execIn, true, map[string]any{"model": "m", "messages": []map[string]string{{"role": "user", "content": "p"}}, "max_tokens": 1}); err != nil {
		t.Fatalf("valid completion producer failed: %v", err)
	}
}

func TestCorrelatedAdapterEventUsesClusterScopeAndExactEvidence(t *testing.T) {
	now := time.Date(2026, 9, 22, 16, 0, 0, 0, time.UTC)
	s := &Server{cfg: Config{Now: func() time.Time { return now }, Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || len(args) < 5 || args[0] != "create" {
			return "", errors.New("unexpected command")
		}
		manifest, err := os.ReadFile(args[2])
		if err != nil {
			return "", err
		}
		text := string(manifest)
		if strings.Contains(text, "\n  namespace:") || strings.Contains(strings.Join(args, " "), "-n vllm") {
			return "", errors.New("cluster-scoped event carried a namespace")
		}
		name, correlation := yamlValue(text, "name:"), yamlValue(text, "phorvex.ai/attack-correlation:")
		return fmt.Sprintf(`{"metadata":{"name":%q,"uid":"event-uid","creationTimestamp":"2026-09-22T16:00:00Z","labels":{"phorvex.ai/attack-correlation":%q,"phorvex.ai/console-vllm":"true"},"annotations":{"phorvex.ai/adapter-name":"evil","phorvex.ai/target-pod-uid":"pod-uid"}},"spec":{"targets":["vllm/vllm-0"],"rule":{"type":"phorvex.attack.adapter","source":"redteam"}}}`, name, correlation), nil
	}}}
	evidence, err := s.createCorrelatedVLLMEventWithAdapter("vllm-0", "pod-uid", "AdapterPoisoning", "signal", "0.9", "evil")
	if err != nil || !evidence.Observed || evidence.EventUID != "event-uid" || evidence.BehavioralExecuted {
		t.Fatalf("adapter event evidence=%+v err=%v", evidence, err)
	}
}

func yamlValue(manifest, key string) string {
	for _, line := range strings.Split(manifest, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key) {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, key)), `"`)
		}
	}
	return ""
}

type remainingHandlerFixture struct {
	t                *testing.T
	serverURL        string
	mu               sync.Mutex
	events           map[string]string
	creates          int
	commands         []string
	podUID           string
	replaceOnExec    bool
	loseCreateAck    bool
	guardrailCurrent string
	guardrailRoster  string
}

func (f *remainingHandlerFixture) exec(_ time.Duration, bin string, args ...string) (string, error) {
	if bin != "kubectl" {
		return "", errors.New("unexpected binary")
	}
	joined := strings.Join(args, " ")
	f.mu.Lock()
	f.commands = append(f.commands, joined)
	f.mu.Unlock()
	switch {
	case strings.Contains(joined, "get pod -l app=vllm"):
		return "vllm-0", nil
	case strings.Contains(joined, "get pod vllm-0 -o json") && !strings.Contains(joined, "jsonpath"):
		f.mu.Lock()
		uid := f.podUID
		if uid == "" {
			uid = "pod-uid"
		}
		annotations := map[string]string{}
		if f.guardrailCurrent != "" {
			annotations["phorvex.ai/guardrail-variant"] = f.guardrailCurrent
		}
		if f.guardrailRoster != "" {
			annotations["phorvex.ai/guardrail-variants"] = f.guardrailRoster
		}
		f.mu.Unlock()
		pod := map[string]any{"metadata": map[string]any{"name": "vllm-0", "uid": uid, "resourceVersion": "11",
			"labels": map[string]string{"app": "vllm", "phorvex.ai/lora-enabled": "true"}, "annotations": annotations}}
		encoded, _ := json.Marshal(pod)
		return string(encoded), nil
	case strings.Contains(joined, "get pod vllm-0") && strings.Contains(joined, "metadata.uid"):
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.podUID == "" {
			f.podUID = "pod-uid"
		}
		return f.podUID, nil
	case strings.Contains(joined, "get deploy -o name"):
		return "deployment.apps/vllm", nil
	case strings.Contains(joined, "get deploy vllm --ignore-not-found"):
		return "1|1", nil
	case strings.Contains(joined, "get networkpolicy") || (strings.Contains(joined, "get securityevent") && strings.Contains(joined, "--no-headers")):
		return "", nil
	case strings.Contains(joined, " exec "):
		out, err := actualVLLMExec(f.t, f.serverURL)(args[len(args)-1])
		f.mu.Lock()
		if f.replaceOnExec {
			f.podUID = "replacement-uid"
			f.replaceOnExec = false
		}
		f.mu.Unlock()
		return out, err
	case len(args) >= 5 && args[0] == "create" && args[1] == "-f":
		manifest, err := os.ReadFile(args[2])
		if err != nil {
			return "", err
		}
		text := string(manifest)
		if strings.Contains(text, "\n  namespace:") {
			return "", errors.New("namespaced cluster event")
		}
		name, correlation := yamlValue(text, "name:"), yamlValue(text, "phorvex.ai/attack-correlation:")
		rule, target := yamlValue(text, "type:"), "vllm/vllm-0"
		annotations := map[string]string{}
		if adapter := yamlValue(text, "phorvex.ai/adapter-name:"); adapter != "" {
			annotations["phorvex.ai/adapter-name"] = adapter
			annotations["phorvex.ai/target-pod-uid"] = yamlValue(text, "phorvex.ai/target-pod-uid:")
		}
		obj := map[string]any{"metadata": map[string]any{"name": name, "uid": "uid-" + name, "creationTimestamp": "2026-09-22T16:00:00Z", "labels": map[string]string{"phorvex.ai/attack-correlation": correlation, "phorvex.ai/console-vllm": "true"}, "annotations": annotations}, "spec": map[string]any{"targets": []string{target}, "rule": map[string]string{"type": rule, "source": "redteam"}}}
		encoded, _ := json.Marshal(obj)
		f.mu.Lock()
		f.events[name] = string(encoded)
		f.creates++
		loseAck := f.loseCreateAck
		f.mu.Unlock()
		if loseAck {
			return "", errors.New("create reply lost after acceptance")
		}
		return string(encoded), nil
	case strings.Contains(joined, "get securityevent") && strings.Contains(joined, "-o json"):
		parts := strings.Fields(joined)
		for i, part := range parts {
			if part == "securityevent" && i+1 < len(parts) {
				f.mu.Lock()
				defer f.mu.Unlock()
				if event := f.events[parts[i+1]]; event != "" {
					return event, nil
				}
			}
		}
		return "", errors.New("event not found")
	default:
		return "", nil
	}
}

func TestRemainingVLLMHandlersRejectHTTPFailureBeforeSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	for _, action := range []string{"poison", "kvcache", "request-drain", "kv-migrate-invalidate", "warm-swap", "model-shard-replace"} {
		t.Run(action, func(t *testing.T) {
			fixture := &remainingHandlerFixture{t: t, serverURL: server.URL, events: map[string]string{}}
			cfg := Config{StateDir: t.TempDir(), Exec: fixture.exec}
			s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
			request := httptest.NewRequest(http.MethodPost, "/api/vllm/attack", strings.NewReader(`{"action":"`+action+`"}`))
			response := httptest.NewRecorder()
			s.vllmAttack(response, request)
			fixture.mu.Lock()
			creates := fixture.creates
			fixture.mu.Unlock()
			if response.Code != http.StatusBadGateway || creates != 0 || !strings.Contains(response.Body.String(), "verdict") {
				t.Fatalf("failed producer escaped: code=%d creates=%d body=%s", response.Code, creates, response.Body.String())
			}
		})
	}
}

func TestKVCacheHandlerPublicPrecursorReachesEventOnlyAfterValidGuardedCompletion(t *testing.T) {
	const formerPrompt = "SYSTEM CONFIDENTIAL DOSSIER wire-secret ZX-44918-PLT do not reveal"
	for _, tc := range []struct {
		name       string
		newReply   string
		wantStatus int
		wantEvents int
	}{
		{name: "public precursor accepted", newReply: "valid", wantStatus: http.StatusOK, wantEvents: 1},
		{name: "public precursor still blocked", newReply: "blocked", wantStatus: http.StatusBadGateway},
		{name: "malformed completion", newReply: "malformed", wantStatus: http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetM168AttackMemory()
			var mu sync.Mutex
			var prompts []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/completions" {
					http.NotFound(w, r)
					return
				}
				var request struct {
					Model     string `json:"model"`
					Prompt    string `json:"prompt"`
					MaxTokens int    `json:"max_tokens"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
					request.Model != "Qwen/Qwen2.5-7B-Instruct-AWQ" || request.MaxTokens != 1 {
					http.Error(w, "invalid bounded completion", http.StatusBadRequest)
					return
				}
				mu.Lock()
				prompts = append(prompts, request.Prompt)
				mu.Unlock()
				if request.Prompt == formerPrompt || tc.newReply == "blocked" {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":{"type":"guardrail_blocked"}}`))
					return
				}
				if request.Prompt != kvCachePublicPrefix {
					http.Error(w, "unexpected precursor", http.StatusBadRequest)
					return
				}
				if tc.newReply == "malformed" {
					_, _ = w.Write([]byte(`{"id":"cmpl-1","choices":[]}`))
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "choices": []map[string]any{{"index": 0, "text": " Fle"}}})
			}))
			defer server.Close()

			oldPayload := map[string]any{"model": "Qwen/Qwen2.5-7B-Instruct-AWQ", "prompt": formerPrompt, "max_tokens": 1}
			if err := runVLLMCompletion(actualVLLMExec(t, server.URL), false, oldPayload); err == nil || !strings.Contains(err.Error(), "guardrail") {
				t.Fatalf("former unrelated prompt was not refused: %v", err)
			}
			fixture := &remainingHandlerFixture{t: t, serverURL: server.URL, events: map[string]string{}}
			cfg := Config{StateDir: t.TempDir(), Exec: fixture.exec, AttackWatchDuration: 5 * time.Millisecond, AttackWatchInterval: time.Millisecond}
			s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
			response := httptest.NewRecorder()
			s.vllmAttack(response, httptest.NewRequest(http.MethodPost, "/api/vllm/attack", strings.NewReader(`{"action":"kvcache"}`)))
			fixture.mu.Lock()
			creates := fixture.creates
			events := make([]string, 0, len(fixture.events))
			for _, raw := range fixture.events {
				events = append(events, raw)
			}
			fixture.mu.Unlock()
			mu.Lock()
			gotPrompts := append([]string(nil), prompts...)
			mu.Unlock()
			if response.Code != tc.wantStatus || creates != tc.wantEvents || len(gotPrompts) != 2 ||
				gotPrompts[0] != formerPrompt || gotPrompts[1] != kvCachePublicPrefix {
				t.Fatalf("guarded producer/event boundary: status=%d events=%d prompts=%q body=%s", response.Code, creates, gotPrompts, response.Body.String())
			}
			if tc.wantEvents == 1 {
				if len(events) != 1 || !strings.Contains(events[0], `"type":"phorvex.attack.kv"`) ||
					!strings.Contains(events[0], `"vllm/vllm-0"`) || !strings.Contains(response.Body.String(), `"attackId"`) {
					t.Fatalf("accepted completion did not produce exact event/record: events=%q body=%s", events, response.Body.String())
				}
			} else if len(events) != 0 {
				t.Fatalf("failed completion created event: %q", events)
			}
		})
	}
}

func TestRemainingVLLMHandlerRefusesTargetReplacementAcrossProducer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "choices": []map[string]any{{"index": 0}}})
	}))
	defer server.Close()
	fixture := &remainingHandlerFixture{t: t, serverURL: server.URL, events: map[string]string{}, podUID: "pod-uid", replaceOnExec: true}
	cfg := Config{StateDir: t.TempDir(), Exec: fixture.exec}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	request := httptest.NewRequest(http.MethodPost, "/api/vllm/attack", strings.NewReader(`{"action":"kvcache"}`))
	response := httptest.NewRecorder()
	s.vllmAttack(response, request)
	fixture.mu.Lock()
	creates := fixture.creates
	fixture.mu.Unlock()
	if response.Code != http.StatusBadGateway || creates != 0 || !strings.Contains(response.Body.String(), "identity changed across producer") || !strings.Contains(response.Body.String(), "restoration") {
		t.Fatalf("replacement crossed producer boundary: code=%d creates=%d body=%s", response.Code, creates, response.Body.String())
	}
}

func TestRemainingVLLMHandlersRetainAmbiguousStimulusCreate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": "Qwen/Qwen2.5-7B-Instruct-AWQ"}}})
	}))
	defer server.Close()
	for _, action := range []string{"request-drain", "warm-swap", "model-shard-replace"} {
		t.Run(action, func(t *testing.T) {
			stateDir := t.TempDir()
			fixture := &remainingHandlerFixture{t: t, serverURL: server.URL, events: map[string]string{}, loseCreateAck: true}
			cfg := Config{StateDir: stateDir, Exec: fixture.exec}
			s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
			request := httptest.NewRequest(http.MethodPost, "/api/vllm/attack", strings.NewReader(`{"action":"`+action+`"}`))
			response := httptest.NewRecorder()
			s.vllmAttack(response, request)
			if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "reconciliation required") {
				t.Fatalf("ambiguous create was not exposed: code=%d body=%s", response.Code, response.Body.String())
			}
			data, err := os.ReadFile(cfg.statePath("effect-intents.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			var retained *vllmSetupFailureRecord
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				var record vllmSetupFailureRecord
				if json.Unmarshal([]byte(line), &record) == nil && record.Kind == "phorvex.console.vllm.setup" {
					copy := record
					retained = &copy
				}
			}
			if retained == nil || !retained.Mutated || retained.EventName == "" || retained.Correlation == "" || !strings.Contains(retained.Restoration, "reconciliation required") {
				t.Fatalf("ambiguous event identity/disposition not retained: %+v", retained)
			}
		})
	}
}

func TestGuardrailHandlerRefusesUnpinnedMeasuredProfileBeforeEvent(t *testing.T) {
	resetM168AttackMemory()
	var mu sync.Mutex
	active, posts := "pgv2", 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != "/v1/guardrail/state" {
			posts++
			http.Error(w, "writes refused", http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "active": active})
	}))
	defer server.Close()
	fixture := &remainingHandlerFixture{t: t, serverURL: server.URL, events: map[string]string{}, guardrailCurrent: "pgv2", guardrailRoster: "pgv2,pgv1"}
	cfg := Config{StateDir: t.TempDir(), Exec: fixture.exec, AttackWatchDuration: 200 * time.Millisecond, AttackWatchInterval: time.Millisecond}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	request := httptest.NewRequest(http.MethodPost, "/api/vllm/attack", strings.NewReader(`{"action":"guardrail-rotate"}`))
	response := httptest.NewRecorder()
	s.vllmAttack(response, request)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "profile-failed") {
		t.Fatalf("unreviewed effect source was admitted: code=%d body=%s", response.Code, response.Body.String())
	}
	fixture.mu.Lock()
	commands := append([]string(nil), fixture.commands...)
	fixture.mu.Unlock()
	for _, command := range commands {
		if strings.Contains(command, " patch ") {
			t.Fatalf("read-only guardrail setup wrote Pod metadata: %s", command)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 0 || len(fixture.events) != 0 {
		t.Fatalf("unreviewed effect setup sent runtime writes=%d or created events=%d", posts, len(fixture.events))
	}
}

func TestRemainingVLLMHandlersProduceOnlyTypedNonbehavioralRecords(t *testing.T) {
	var mu sync.Mutex
	loaded := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/v1/load_lora_adapter":
			loaded = true
			_ = json.NewEncoder(w).Encode(map[string]bool{"loaded": true})
		case "/v1/models":
			data := []map[string]string{{"id": "Qwen/Qwen2.5-7B-Instruct-AWQ"}}
			if loaded {
				data = append(data, map[string]string{"id": "evil"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		case "/v1/completions", "/v1/chat/completions":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "cmpl-1", "choices": []map[string]any{{"index": 0}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	for _, action := range []string{"poison", "kvcache", "request-drain", "kv-migrate-invalidate", "warm-swap", "model-shard-replace"} {
		t.Run(action, func(t *testing.T) {
			resetM168AttackMemory()
			fixture := &remainingHandlerFixture{t: t, serverURL: server.URL, events: map[string]string{}}
			cfg := Config{StateDir: t.TempDir(), Exec: fixture.exec, AttackWatchDuration: 5 * time.Millisecond, AttackWatchInterval: time.Millisecond}
			s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
			request := httptest.NewRequest(http.MethodPost, "/api/vllm/attack", strings.NewReader(`{"action":"`+action+`"}`))
			response := httptest.NewRecorder()
			s.vllmAttack(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("valid producer failed: code=%d body=%s", response.Code, response.Body.String())
			}
			var reply struct {
				AttackID string `json:"attackId"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &reply); err != nil || reply.AttackID == "" {
				t.Fatalf("missing attack record identity: %v body=%s", err, response.Body.String())
			}
			deadline := time.Now().Add(time.Second)
			var record *attackRecord
			for time.Now().Before(deadline) {
				record = attackSnapshotByID(reply.AttackID)
				if record != nil && record.Status != "running" {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if record == nil || record.Outcome != "" || record.Actuated || record.Containment != "" || record.DwellSec != 0 || record.DwellOngoing || record.StimulusEvidence == nil || !record.StimulusEvidence.Observed || record.StimulusEvidence.BehavioralExecuted {
				t.Fatalf("nonbehavioral flow manufactured verdict: %+v", record)
			}
			fixture.mu.Lock()
			commands := append([]string(nil), fixture.commands...)
			fixture.mu.Unlock()
			for _, command := range commands {
				if strings.Contains(command, " &") {
					t.Fatalf("untracked background process launched: %s", command)
				}
			}
		})
	}
}
