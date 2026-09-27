package console

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAvailabilityRuntimeReadAuthenticatesOnlyRawLoopbackModels(t *testing.T) {
	const key = "synthetic-test-key-only"
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("public guardrail request received upstream key")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/guardrail/state" {
			_, _ = w.Write([]byte(`{"ready":true}`))
		} else {
			_, _ = w.Write([]byte(`{"data":[]}`))
		}
	}))
	defer public.Close()
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer raw.Close()
	port := func(rawURL string) string {
		u, err := url.Parse(rawURL)
		if err != nil || u.Port() == "" || u.Hostname() != "127.0.0.1" {
			t.Fatalf("local test server address invalid: %v", err)
		}
		return u.Port()
	}
	source := filepath.Join(t.TempDir(), "guardrail_proxy.py")
	if err := os.WriteFile(source, []byte("fixed synthetic source"), 0600); err != nil {
		t.Fatal(err)
	}
	program := strings.NewReplacer("/src/guardrail_proxy.py", source,
		"8000", port(public.URL), "8001", port(raw.URL)).Replace(availabilityRuntimeCode)
	for _, tc := range []struct {
		name string
		key  string
		want float64
	}{{"missing key refuses", "", 401}, {"exact key accepted", key, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "python3", "-B", "-c", program)
			cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, "VLLM_API_KEY="+tc.key)
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("fixed Python probe failed: %v", err)
			}
			if bytes.Contains(output, []byte(key)) {
				t.Fatal("probe reflected the synthetic key into stdout")
			}
			var reply map[string]any
			if err := json.Unmarshal(output, &reply); err != nil {
				t.Fatal(err)
			}
			rawStatus, _ := reply[port(raw.URL)+"/v1/models"].(map[string]any)
			publicStatus, _ := reply[port(public.URL)+"/v1/models"].(map[string]any)
			if got := rawStatus["status"]; got != tc.want {
				t.Fatalf("raw model status = %v; want %v", got, tc.want)
			}
			if got := publicStatus["status"]; got != float64(200) {
				t.Fatalf("public model status = %v", got)
			}
		})
	}
}

func TestGuardrailEffectDualListenerSourceJoinsConfigMapAndMount(t *testing.T) {
	const sourceText = "fixed dual-listener source"
	pin := availabilityHash([]byte(sourceText))
	source := map[string]any{"data": map[string]any{"dual_server.py": sourceText}}
	runtime := map[string]any{"_mountedBoundarySHA256": pin}
	if got, err := availabilityBoundarySource(source, runtime, pin); err != nil || got != pin {
		t.Fatalf("exact dual-listener source refused: %s %v", got, err)
	}
	for _, tc := range []struct {
		name    string
		source  map[string]any
		runtime map[string]any
		pin     string
	}{
		{"missing source", map[string]any{"data": map[string]any{}}, runtime, pin},
		{"changed ConfigMap", map[string]any{"data": map[string]any{"dual_server.py": "changed"}}, runtime, pin},
		{"changed mounted file", source, map[string]any{"_mountedBoundarySHA256": strings.Repeat("c", 64)}, pin},
		{"invalid profile pin", source, runtime, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := availabilityBoundarySource(tc.source, tc.runtime, tc.pin); err == nil {
				t.Fatal("dual-listener source drift admitted")
			}
		})
	}
}
