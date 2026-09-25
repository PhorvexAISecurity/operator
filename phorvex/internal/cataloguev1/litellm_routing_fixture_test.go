package cataloguev1

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const routingKnownAlias = "gpt-4o-mini"

const routingSyntheticConfig = `general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY
litellm_settings: {}
model_list:
  - model_name: gpt-3.5-turbo
    litellm_params:
      model: openai/gpt-3.5-turbo
      api_base: https://provider.invalid/v1
      api_key: os.environ/OPENAI_API_KEY
  - model_name: gpt-4o-mini
    litellm_params:
      model: openai/gpt-4o-mini
      api_base: https://provider.invalid/v1
      api_key: os.environ/OPENAI_API_KEY
`

func installRoutingFixtureAuthority(t *testing.T, runtime Runtime, base *liteFixtureTransport, syntheticKey string) string {
	t.Helper()
	cm, err := runtime.Kube.CoreV1().ConfigMaps("litellm").Get(context.Background(), "litellm-config", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cm.Data["config.yaml"] = routingSyntheticConfig
	if _, err := runtime.Kube.CoreV1().ConfigMaps("litellm").Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	pods, err := runtime.Kube.CoreV1().Pods("litellm").List(context.Background(), metav1.ListOptions{LabelSelector: "app=litellm"})
	if err != nil || len(pods.Items) != 2 {
		t.Fatalf("fixture serving Pod count: %d, %v", len(pods.Items), err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		pod.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "LITELLM_MASTER_KEY", Value: syntheticKey},
			{Name: "OPENAI_API_KEY", Value: "synthetic-provider-never-used"}}
		if _, err := runtime.Kube.CoreV1().Pods("litellm").Update(context.Background(), pod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(routingSyntheticConfig)))
	base.fixtureConfigSHA = sum
	return sum
}

// routingHTTPFixture is a real local HTTP boundary for the fixed inference
// request. It records only model aliases, never the synthetic test bearer.
type routingHTTPFixture struct {
	server *httptest.Server
	port   string
	mu     sync.Mutex
	models []string
}

type routingFixtureReply struct {
	status      int
	contentType string
	body        string
	location    string
	delay       time.Duration
	trickle     time.Duration
}

func routingValidCompletion(t *testing.T, model string) routingFixtureReply {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"id": "chatcmpl-local-control", "object": "chat.completion", "model": model,
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": "Ready."}, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
	})
	if err != nil {
		t.Fatal(err)
	}
	return routingFixtureReply{status: http.StatusOK, contentType: "application/json", body: string(body)}
}

func routingTypedError(t *testing.T, status int, errorType, code, message string) routingFixtureReply {
	t.Helper()
	body, err := json.Marshal(map[string]any{"error": map[string]any{
		"type": errorType, "code": code, "message": message,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return routingFixtureReply{status: status, contentType: "application/json", body: string(body)}
}

func newRoutingHTTPFixture(t *testing.T, syntheticKey string, respond func(model string) routingFixtureReply) *routingHTTPFixture {
	t.Helper()
	fixture := &routingHTTPFixture{}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected inference route: %s %s", r.Method, r.URL.Path)
			http.Error(w, "wrong route", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+syntheticKey {
			t.Error("inference request did not use the synthetic master-key path")
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8193))
		if err != nil || len(body) == 0 || len(body) > 8192 || strings.Contains(string(body), syntheticKey) {
			t.Error("inference request body absent, over bound, or contains bearer")
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var request struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			MaxTokens   int             `json:"max_tokens"`
			Temperature float64         `json:"temperature"`
			Stream      bool            `json:"stream"`
			Tools       json.RawMessage `json:"tools"`
			Audio       json.RawMessage `json:"audio"`
		}
		if err := json.Unmarshal(body, &request); err != nil || request.Model == "" || len(request.Messages) != 1 ||
			request.Messages[0].Role != "user" || len(request.Messages[0].Content) == 0 || len(request.Messages[0].Content) > 256 ||
			request.MaxTokens != 16 || request.Temperature != 0 || request.Stream || len(request.Tools) != 0 || len(request.Audio) != 0 {
			t.Error("inference request is not the bounded, harmless, nonstreaming contract")
			http.Error(w, "bad request shape", http.StatusBadRequest)
			return
		}
		fixture.mu.Lock()
		fixture.models = append(fixture.models, request.Model)
		fixture.mu.Unlock()
		reply := respond(request.Model)
		if reply.delay > 0 {
			time.Sleep(reply.delay)
		}
		if reply.contentType != "" {
			w.Header().Set("Content-Type", reply.contentType)
		}
		if reply.location != "" {
			w.Header().Set("Location", reply.location)
		}
		w.WriteHeader(reply.status)
		if reply.trickle > 0 {
			for _, ch := range reply.body {
				_, _ = io.WriteString(w, string(ch))
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				time.Sleep(reply.trickle)
			}
			return
		}
		_, _ = io.WriteString(w, reply.body)
	}))
	parsed, err := url.Parse(fixture.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strconv.Atoi(parsed.Port()); err != nil {
		t.Fatal(err)
	}
	fixture.port = parsed.Port()
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *routingHTTPFixture) requestedModels() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.models...)
}
