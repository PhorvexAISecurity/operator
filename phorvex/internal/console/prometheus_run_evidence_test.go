package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPrometheusRunEvidencePersistsBaselineFinalDeltasAndRange(t *testing.T) {
	var mu sync.Mutex
	instantCalls := map[string]int{}
	prometheus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if query == "" {
			t.Error("query missing")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/query_range" {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{
				"resultType": "matrix", "result": []any{map[string]any{
					"metric": map[string]string{}, "values": [][]any{{1700000000.0, "10"}, {1700000015.0, "11"}},
				}},
			}})
			return
		}
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		instantCalls[query]++
		call := instantCalls[query]
		mu.Unlock()
		value := "10"
		if strings.Contains(query, "< bool 90") {
			value = "1"
		} else if call > 1 {
			value = "11"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{
			"resultType": "vector", "result": []any{map[string]any{
				"metric": map[string]string{}, "value": []any{1700000000.0, value},
			}},
		}})
	}))
	defer prometheus.Close()

	cfg := Config{StateDir: t.TempDir(), RunPrometheusEvidence: PrometheusRunEvidenceConfig{
		Enabled: true, URL: prometheus.URL, Environment: "staging", SettleDelay: time.Millisecond,
		RequestTimeout: time.Second, RangeStep: 15 * time.Second,
	}}
	server := &Server{cfg: cfg}
	started := time.Now().UTC().Add(-time.Minute)
	evidence, err := server.beginPrometheusRunEvidence(context.Background(), "cat-7", "AML.T0012", "console-identity-test", "identity-rotate", started)
	if err != nil {
		t.Fatalf("baseline capture: %v", err)
	}
	if err = server.completePrometheusRunEvidence(context.Background(), evidence, time.Now().UTC()); err != nil {
		t.Fatalf("terminal capture: %v", err)
	}
	if evidence.Status != "COMPLETE" || len(evidence.Metrics) != 8 || len(evidence.Errors) != 0 {
		t.Fatalf("terminal evidence=%+v", evidence)
	}
	for _, metric := range evidence.Metrics {
		wantDelta := float64(1)
		if metric.Key == "telemetry-source-fresh" {
			wantDelta = 0
		}
		if len(metric.Baseline) != 1 || len(metric.Final) != 1 || len(metric.Range) != 1 || len(metric.Range[0].Samples) != 2 ||
			len(metric.Deltas) != 1 || metric.Deltas[0].Delta != wantDelta || !metric.Deltas[0].BaselinePresent || !metric.Deltas[0].FinalPresent {
			t.Fatalf("metric %s was not preserved completely: %+v", metric.Key, metric)
		}
		if !strings.Contains(metric.Query, `environment="staging"`) {
			t.Fatalf("metric %s escaped the environment boundary: %s", metric.Key, metric.Query)
		}
	}

	rm := &RunManager{cfg: cfg, runs: map[string]*RunStatus{"cat-7": {
		ID: "cat-7", Config: "AML.T0012", ExecutionKind: attackCatalogExecutionKind,
	}}, runOut: map[string]string{"cat-7": "cat-7"}}
	retained, err := rm.PrometheusRunEvidence("cat-7")
	if err != nil || retained == nil || retained.Status != "COMPLETE" {
		t.Fatalf("retained evidence unavailable: evidence=%+v err=%v", retained, err)
	}
	if _, err = os.Stat(filepath.Join(cfg.runOutputPath("cat-7"), prometheusRunEvidenceFile)); err != nil {
		t.Fatalf("durable evidence file missing: %v", err)
	}
}

func TestPrometheusRunEvidenceBaselineFailurePersistsPartialAndStopsPreflight(t *testing.T) {
	prometheus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer prometheus.Close()
	cfg := Config{StateDir: t.TempDir(), RunPrometheusEvidence: PrometheusRunEvidenceConfig{
		Enabled: true, URL: prometheus.URL, Environment: "staging", RequestTimeout: time.Second,
	}}
	server := &Server{cfg: cfg}
	evidence, err := server.beginPrometheusRunEvidence(context.Background(), "cat-8", "AML.T0012", "console-identity-test", "identity-rotate", time.Now().UTC())
	if err == nil || evidence == nil || evidence.Status != "PARTIAL" || len(evidence.Errors) != 8 {
		t.Fatalf("failed baseline was not retained honestly: evidence=%+v err=%v", evidence, err)
	}
	raw, readErr := os.ReadFile(filepath.Join(cfg.runOutputPath("cat-8"), prometheusRunEvidenceFile))
	if readErr != nil || !strings.Contains(string(raw), `"status": "PARTIAL"`) {
		t.Fatalf("partial baseline artifact missing: err=%v body=%s", readErr, raw)
	}
}

func TestPrometheusRunEvidenceRequiresFreshDecisionTelemetry(t *testing.T) {
	prometheus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := "0"
		if !strings.Contains(r.URL.Query().Get("query"), "< bool 90") {
			value = "1"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{
				"resultType": "vector",
				"result": []any{map[string]any{
					"metric": map[string]string{},
					"value":  []any{1700000000.0, value},
				}},
			},
		})
	}))
	defer prometheus.Close()
	cfg := Config{StateDir: t.TempDir(), RunPrometheusEvidence: PrometheusRunEvidenceConfig{
		Enabled: true, URL: prometheus.URL, Environment: "staging", RequestTimeout: time.Second,
	}}
	evidence, err := (&Server{cfg: cfg}).beginPrometheusRunEvidence(context.Background(), "cat-9", "AML.T0012", "console-identity-test", "identity-rotate", time.Now().UTC())
	if err == nil || evidence == nil || evidence.Status != "PARTIAL" ||
		!strings.Contains(strings.Join(evidence.Errors, " "), "older than 90s") {
		t.Fatalf("stale telemetry did not stop preflight: evidence=%+v err=%v", evidence, err)
	}
}

func TestPrometheusDeltasTreatBornAndResetCountersHonestly(t *testing.T) {
	born := prometheusDeltas(nil, []PrometheusSeries{{Labels: map[string]string{"mode": "reactive"}, Samples: []PrometheusSample{{Value: 1}}}})
	if len(born) != 1 || born[0].BaselinePresent || !born[0].FinalPresent || born[0].Delta != 1 || born[0].CounterReset {
		t.Fatalf("born counter delta=%+v", born)
	}
	reset := prometheusDeltas(
		[]PrometheusSeries{{Labels: map[string]string{}, Samples: []PrometheusSample{{Value: 9}}}},
		[]PrometheusSeries{{Labels: map[string]string{}, Samples: []PrometheusSample{{Value: 2}}}},
	)
	if len(reset) != 1 || !reset[0].CounterReset || reset[0].Delta != 2 {
		t.Fatalf("reset counter delta=%+v", reset)
	}
}
