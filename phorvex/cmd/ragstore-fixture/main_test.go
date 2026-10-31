package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/phorvex/phorvex/internal/datastore"
)

// store is the canonical two-record fixture content the chart seeds into the
// datastore-content ConfigMap.
const store = `{"records":[{"id":"benign-control","content":"reviewed benign catalogue fixture"},{"id":"second","content":"two"}]}`

func newTestServer(t *testing.T, read func(context.Context) ([]byte, error)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(newStoreMux(read))
	t.Cleanup(server.Close)
	return server
}

func get(t *testing.T, base, path string, query url.Values) (*http.Response, map[string]any) {
	t.Helper()
	target := base + path
	if query != nil {
		target += "?" + query.Encode()
	}
	resp, err := http.Get(target) //nolint:gosec // httptest URL
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	var body map[string]any
	if resp.Header.Get("Content-Type") == "application/json" {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return resp, body
}

func TestHealthzIsReadyForTheChartProbe(t *testing.T) {
	// The chart's rag-store readinessProbe hits /healthz; it must return 200 even when
	// the store is empty so the pod can become Ready before any content is seeded.
	server := newTestServer(t, func(context.Context) ([]byte, error) { return nil, nil })
	resp, body := get(t, server.URL, "/healthz", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz status = %d, want 200", resp.StatusCode)
	}
	if body["status"] != "ok" {
		t.Fatalf("/healthz body = %v, want status ok", body)
	}
}

func TestReadbackMatchesTheCanonicalActuatorHash(t *testing.T) {
	want, err := datastore.CanonicalSHA([]byte(store))
	if err != nil {
		t.Fatalf("canonical sha: %v", err)
	}
	server := newTestServer(t, func(context.Context) ([]byte, error) { return []byte(store), nil })
	resp, body := get(t, server.URL, datastore.ReadbackPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readback status = %d, want 200", resp.StatusCode)
	}
	if body["sha256"] != want {
		t.Fatalf("readback sha256 = %v, want %s (the actuator's canonical algorithm)", body["sha256"], want)
	}
}

func TestGetServesPresentRecordAndReports404ForRestoredAway(t *testing.T) {
	server := newTestServer(t, func(context.Context) ([]byte, error) { return []byte(store), nil })
	resp, body := get(t, server.URL, datastore.GetPath, url.Values{"id": {"benign-control"}})
	if resp.StatusCode != http.StatusOK || body["content"] != "reviewed benign catalogue fixture" {
		t.Fatalf("get present record = %d %v", resp.StatusCode, body)
	}
	resp, _ = get(t, server.URL, datastore.GetPath, url.Values{"id": {"poisoned"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get missing record status = %d, want 404", resp.StatusCode)
	}
}

func TestDumpListsServedIDsAndHash(t *testing.T) {
	server := newTestServer(t, func(context.Context) ([]byte, error) { return []byte(store), nil })
	resp, body := get(t, server.URL, datastore.DumpPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dump status = %d, want 200", resp.StatusCode)
	}
	if body["count"].(float64) != 2 {
		t.Fatalf("dump count = %v, want 2", body["count"])
	}
	ids, ok := body["ids"].([]any)
	if !ok || len(ids) != 2 || ids[0] != "benign-control" {
		t.Fatalf("dump ids = %v, want the two seeded records", body["ids"])
	}
}

// TestRateTargetBackendStaysReadyWithoutDatastoreClient proves the serving-rate
// rate-target use of this image: with no in-cluster identity the store reader fails
// closed, yet /healthz still returns 200 so the pod is a live HTTP backend (deployable)
// instead of crash-looping.
func TestRateTargetBackendStaysReadyWithoutDatastoreClient(t *testing.T) {
	degraded := func(context.Context) ([]byte, error) {
		return nil, errors.New("datastore API client unavailable")
	}
	server := newTestServer(t, degraded)
	resp, body := get(t, server.URL, "/healthz", nil)
	if resp.StatusCode != http.StatusOK || body["status"] != "ok" {
		t.Fatalf("/healthz without a datastore client = %d %v, want 200 ok", resp.StatusCode, body)
	}
	resp, _ = get(t, server.URL, datastore.ReadbackPath, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readback without a datastore client = %d, want 503", resp.StatusCode)
	}
}

func TestStoreUnavailableFailsClosed(t *testing.T) {
	server := newTestServer(t, func(context.Context) ([]byte, error) {
		return nil, errors.New("configmap unavailable")
	})
	for _, path := range []string{datastore.ReadbackPath, datastore.GetPath, datastore.DumpPath} {
		resp, _ := get(t, server.URL, path, nil)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s with no store = %d, want 503", path, resp.StatusCode)
		}
	}
}
