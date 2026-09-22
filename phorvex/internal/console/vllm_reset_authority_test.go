package console

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type resetAuthorityFixture struct {
	mu       sync.Mutex
	commands []string
	podJSON  string
	podErr   error
}

func (f *resetAuthorityFixture) exec(_ time.Duration, bin string, args ...string) (string, error) {
	if bin != "kubectl" {
		return "", errors.New("unexpected binary")
	}
	command := strings.Join(args, " ")
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.mu.Unlock()
	switch {
	case strings.Contains(command, "get pod -l app=vllm"):
		return "vllm-0", nil
	case strings.Contains(command, "get pod vllm-0 -o json"):
		if f.podErr != nil {
			return "", f.podErr
		}
		if f.podJSON != "" {
			return f.podJSON, nil
		}
		return `{"metadata":{"name":"vllm-0","uid":"pod-uid","resourceVersion":"11","labels":{"app":"vllm"},"annotations":{}}}`, nil
	default:
		return "", errors.New("unexpected reset command: " + command)
	}
}

func (f *resetAuthorityFixture) mutationCommands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, command := range f.commands {
		for _, verb := range []string{" exec ", " annotate ", " label ", " patch ", " delete ", " create ", " apply "} {
			if strings.Contains(" "+command+" ", verb) {
				out = append(out, command)
				break
			}
		}
	}
	return out
}

func runResetRequest(s *Server) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/vllm/attack", strings.NewReader(`{"action":"reset"}`))
	s.vllmAttack(response, request)
	return response
}

func TestVLLMResetRefusesWithoutDurableAuthorityAndMakesNoWrites(t *testing.T) {
	fixture := &resetAuthorityFixture{}
	cfg := Config{StateDir: t.TempDir(), Exec: fixture.exec}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	response := runResetRequest(s)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"verdict":"unsupported-restoration-authority"`) ||
		!strings.Contains(response.Body.String(), `"targetUid":"pod-uid"`) || !strings.Contains(response.Body.String(), "reconciliation required") {
		t.Fatalf("reset refusal mismatch: HTTP%d %s", response.Code, response.Body.String())
	}
	if commands := fixture.mutationCommands(); len(commands) != 0 {
		t.Fatalf("reset dispatched mutation commands: %v", commands)
	}
	data, err := os.ReadFile(cfg.statePath("effect-intents.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var refusal *vllmSetupFailureRecord
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var record vllmSetupFailureRecord
		if json.Unmarshal([]byte(line), &record) == nil && record.Kind == "phorvex.console.vllm.setup" {
			copy := record
			refusal = &copy
		}
	}
	if refusal == nil || refusal.Action != "reset" || refusal.TargetUID != "pod-uid" || refusal.Mutated || !strings.Contains(refusal.Restoration, "not-attempted") || !strings.Contains(refusal.Restoration, "reconciliation required") {
		t.Fatalf("durable reset refusal mismatch: %+v", refusal)
	}
}

func TestVLLMResetEvidenceFailureIsUnsafeAndMakesNoWrites(t *testing.T) {
	fixture := &resetAuthorityFixture{}
	cfg := Config{Exec: fixture.exec}
	s := &Server{cfg: cfg, runs: NewRunManager(cfg)}
	response := runResetRequest(s)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"verdict":"unsafe-to-retry"`) {
		t.Fatalf("reset evidence failure mismatch: HTTP%d %s", response.Code, response.Body.String())
	}
	if commands := fixture.mutationCommands(); len(commands) != 0 {
		t.Fatalf("reset dispatched mutation commands after evidence failure: %v", commands)
	}
}

func TestVLLMResetRequiresExactTargetIdentityBeforeRefusal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		podJSON string
		podErr  error
	}{
		{name: "missing uid", podJSON: `{"metadata":{"name":"vllm-0","resourceVersion":"11"}}`},
		{name: "wrong name", podJSON: `{"metadata":{"name":"replacement","uid":"pod-uid","resourceVersion":"11"}}`},
		{name: "read failure", podErr: errors.New("API unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := &resetAuthorityFixture{podJSON: tc.podJSON, podErr: tc.podErr}
			cfg := Config{StateDir: t.TempDir(), Exec: fixture.exec}
			response := runResetRequest(&Server{cfg: cfg, runs: NewRunManager(cfg)})
			if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "target identity is unavailable") {
				t.Fatalf("invalid target accepted: HTTP%d %s", response.Code, response.Body.String())
			}
			if commands := fixture.mutationCommands(); len(commands) != 0 {
				t.Fatalf("invalid target triggered writes: %v", commands)
			}
		})
	}
}
