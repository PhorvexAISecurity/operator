package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExactPairDenyAndTwoSidedControls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "denied.json")
	if err := os.WriteFile(path, []byte(`{"denied_agent_actions":["caller-a::destroy-data"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(path)
	for name, target := range map[string]struct {
		target   string
		status   int
		decision string
	}{
		"abused":   {"/act?caller=caller-a&action=destroy-data", http.StatusForbidden, `"decision":"deny"`},
		"benign":   {"/act?caller=caller-z&action=read-report", http.StatusOK, `"decision":"allow"`},
		"surgical": {"/act?caller=caller-a&action=read-report", http.StatusOK, `"decision":"allow"`},
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target.target, nil))
			if response.Code != target.status || !strings.Contains(response.Body.String(), target.decision) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestEmptyGuardReadbackIsAnArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "denied.json")
	if err := os.WriteFile(path, []byte(`{"denied_agent_actions":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	newHandler(path).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/phorvex-guard/state", nil))
	if response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != `{"denied_agent_actions":[]}` {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMalformedOrAbsentGuardFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "denied.json")
	handler := newHandler(path)
	for _, target := range []string{"/healthz", "/phorvex-guard/state", "/act?caller=caller-a&action=destroy-data"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
	if err := os.WriteFile(path, []byte(`{"denied_agent_actions":[],"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/act?caller=caller-a&action=destroy-data", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("malformed guard failed open: status=%d body=%s", response.Code, response.Body.String())
	}
}
