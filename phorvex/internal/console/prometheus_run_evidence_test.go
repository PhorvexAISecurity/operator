package console

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPrometheusTimePreservesSubMillisecondCaptureBoundary(t *testing.T) {
	captured := time.Unix(1761766259, 435498645).UTC()
	formatted, err := strconv.ParseFloat(formatPrometheusTime(captured), 64)
	if err != nil {
		t.Fatal(err)
	}
	want := float64(captured.UnixNano()) / float64(time.Second)
	if formatted != want {
		t.Fatalf("formatted query time %.9f moved capture boundary %.9f", formatted, want)
	}
}

func TestPrometheusRangeCoverageAllowsOnlyMillisecondSerializationLoss(t *testing.T) {
	baseline := time.Unix(1761766259, 435498645).UTC()
	final := baseline.Add(3*time.Minute + 17*time.Millisecond)
	first := float64(baseline.Truncate(time.Millisecond).UnixNano()) / float64(time.Second)
	last := float64(final.Truncate(time.Millisecond).UnixNano()) / float64(time.Second)
	if !prometheusRangeCoversCaptures(first, last, baseline, final, true) {
		t.Fatal("millisecond Prometheus timestamps did not cover nanosecond capture boundaries")
	}
	if prometheusRangeCoversCaptures(first, last-2*float64(time.Millisecond)/float64(time.Second), baseline, final, true) {
		t.Fatal("range ending more than one millisecond before final capture was accepted")
	}
	if prometheusRangeCoversCaptures(first+2*float64(time.Millisecond)/float64(time.Second), last, baseline, final, true) {
		t.Fatal("range starting more than one millisecond after baseline capture was accepted")
	}
}

func TestPrometheusRangeCoverageAllowsSeriesBornAfterEmptyBaseline(t *testing.T) {
	baseline := time.Unix(1793422103, 687061238).UTC()
	final := time.Unix(1793422276, 880911235).UTC()
	first := 1793422141.881
	last := 1793422276.881
	if !prometheusRangeCoversCaptures(first, last, baseline, final, false) {
		t.Fatal("series born after an empty baseline was rejected")
	}
	if prometheusRangeCoversCaptures(first, last, baseline, final, true) {
		t.Fatal("late first sample was accepted for a series present at baseline")
	}
}

func TestPrometheusAnchoredRangeGridIncludesCaptureBoundaries(t *testing.T) {
	// These are the real boundaries that exposed Prometheus truncating the old
	// 14.2096114987s step to 14.209s and ending the range before final.
	baseline := time.Unix(1793499604, 36584556).UTC()
	final := time.Unix(1793499746, 130795597).UTC()
	start, end, step := prometheusAnchoredRange(baseline, final, 15*time.Second)
	if !start.Equal(baseline.Truncate(time.Millisecond)) || !start.Before(baseline) || end.Before(final) {
		t.Fatalf("range boundaries moved: start=%s end=%s", start, end)
	}
	if step <= 0 || step > 15 {
		t.Fatalf("range step=%f", step)
	}
	parsedStep, err := time.ParseDuration(strconv.FormatFloat(step, 'f', -1, 64) + "s")
	if err != nil {
		t.Fatal(err)
	}
	if parsedStep%time.Millisecond != 0 {
		t.Fatalf("range step %s is not integral milliseconds", parsedStep)
	}
	intervals := math.Round(float64(end.Sub(start)) / float64(parsedStep))
	first := float64(start.UnixNano()) / float64(time.Second)
	lastAt := start.Add(time.Duration(intervals) * parsedStep)
	if !lastAt.Equal(end) {
		t.Fatalf("serialized grid ends at %s, want %s", lastAt, end)
	}
	last := float64(lastAt.UnixNano()) / float64(time.Second)
	if !prometheusRangeCoversCaptures(first, last, baseline, final, true) {
		t.Fatalf("anchored grid did not cover baseline=%s final=%s: first=%f last=%f", baseline, final, first, last)
	}
}

func TestPrometheusRangeQueryMustCoverEmptyBaselineAndFinal(t *testing.T) {
	baselineAt := time.Unix(1793422103, 687061238).UTC()
	finalAt := time.Unix(1793422276, 880911235).UTC()
	query := `sum(phorvex_decisions_total{selected="true"})`
	baseline := &PrometheusResponseCapture{CapturedAt: baselineAt, Path: "/api/v1/query", Parameters: map[string]string{
		"query": query, "time": formatPrometheusTime(baselineAt),
	}}
	final := &PrometheusResponseCapture{CapturedAt: finalAt, Path: "/api/v1/query", Parameters: map[string]string{
		"query": query, "time": formatPrometheusTime(finalAt),
	}}
	raw := &PrometheusResponseCapture{CapturedAt: finalAt.Add(time.Millisecond), Path: "/api/v1/query_range", Parameters: map[string]string{
		"query": query, "start": "1793422096.880911350", "end": "1793422276.882098436", "step": "15",
	}}
	if !prometheusRangeQueryCoversCaptures(raw, baseline, final) {
		t.Fatal("real empty-baseline query window was rejected")
	}
	raw.Parameters["start"] = "1793422141.881"
	if prometheusRangeQueryCoversCaptures(raw, baseline, final) {
		t.Fatal("query window starting after the baseline was accepted")
	}
}

func TestPrometheusEmptyCandidateExclusionsProveAbsence(t *testing.T) {
	empty := PrometheusMetricEvidence{Key: "candidate-exclusions"}
	if !prometheusEmptyCandidateExclusionsProveAbsence(empty) {
		t.Fatal("validated empty candidate exclusions were rejected")
	}

	cases := map[string]PrometheusMetricEvidence{
		"positive metric": {Key: "selected-action"},
		"baseline present": {
			Key: "candidate-exclusions", Baseline: []PrometheusSeries{{}},
		},
		"final present": {
			Key: "candidate-exclusions", Final: []PrometheusSeries{{}},
		},
		"range present": {
			Key: "candidate-exclusions", Range: []PrometheusSeries{{}},
		},
		"delta present": {
			Key: "candidate-exclusions", Deltas: []PrometheusDelta{{}},
		},
	}
	for name, metric := range cases {
		t.Run(name, func(t *testing.T) {
			if prometheusEmptyCandidateExclusionsProveAbsence(metric) {
				t.Fatal("inconsistent empty range was accepted")
			}
		})
	}
}

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
		labels := map[string]string{}
		if strings.Contains(query, "< bool 90") {
			value = "1"
		} else if call > 1 {
			value = "11"
		}
		if strings.Contains(query, `selected="true"`) {
			labels["mode"] = "reactive"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{
			"resultType": "vector", "result": []any{map[string]any{
				"metric": labels, "value": []any{1700000000.0, value},
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
	evidence, err := server.beginPrometheusRunEvidence(context.Background(), "cat-7", "AML.T0012", "identity-sa-rotate", "console-identity-test", "identity-rotate", AttackCatalogExecutionActive, AttackCatalogTriggerReactive, started)
	if err != nil {
		t.Fatalf("baseline capture: %v", err)
	}
	if err = server.completePrometheusRunEvidence(context.Background(), evidence, time.Now().UTC()); err != nil {
		t.Fatalf("terminal capture: %v", err)
	}
	if evidence.Status != "COMPLETE" || evidence.ExecutionMode != AttackCatalogExecutionActive ||
		evidence.TriggerMode != AttackCatalogTriggerReactive || len(evidence.Metrics) != 8 || len(evidence.Errors) != 0 {
		t.Fatalf("terminal evidence=%+v", evidence)
	}
	if len(evidence.ObservedDecisionModes) != 1 || evidence.ObservedDecisionModes[0] != "reactive" {
		t.Fatalf("actual decision mode was not retained: %+v", evidence.ObservedDecisionModes)
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

func TestPrometheusRunMetricActionPreservesOtherFamilies(t *testing.T) {
	for _, tc := range []struct{ family, action string }{
		{"agent-action", "agent-action-deny"},
		{"credential", "credential-revoke"},
		{"datastore", "datastore-restore"},
		{"identity-sa-rotate", "identity-rotate"},
		{"image", "registry-rollback"},
		{"network-edge", "network-isolate"},
		{"node-recycle", "node-cordon-drain-replace"},
		{"pod-rotate", "rotate"},
		{"quarantine", "quarantine"},
		{"sensitive-output", "sensitive-output-policy-activate"},
		{"serving-kv", "kv-reset"},
		{"serving-rate", "throttle"},
		// The real controller retirement primitive outside the reviewed family
		// and a mismatched family/action pair must never be remapped.
		{"unrelated-family", "controller-stop"},
		{"controller-stop", "quarantine"},
	} {
		t.Run(tc.family+"/"+tc.action, func(t *testing.T) {
			if got := prometheusRunMetricAction(tc.family, tc.action); got != tc.action {
				t.Fatalf("metric action = %q, want unchanged %q", got, tc.action)
			}
		})
	}
}

func TestPrometheusControllerStopCapturesNativeRotateEvidence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		present bool
		advance bool
	}{
		{name: "positive-native-delta", present: true, advance: true},
		{name: "missing-native-counter"},
		{name: "zero-native-delta", present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			instantCalls := map[string]int{}
			prometheus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query().Get("query")
				isNative := strings.Contains(query, `action="rotate"`)
				missing := strings.Contains(query, `action="controller-stop"`) || (isNative && !tc.present)
				labels := map[string]string{}
				if strings.Contains(query, `selected="true"`) {
					labels["mode"] = "active"
				}
				baseline, final := "10", "11"
				if strings.Contains(query, "< bool 90") {
					baseline, final = "1", "1"
				} else if isNative && !tc.advance {
					final = baseline
				}
				resultType := "vector"
				series := map[string]any{"metric": labels}
				if r.URL.Path == "/api/v1/query_range" {
					resultType = "matrix"
					start, _ := strconv.ParseFloat(r.URL.Query().Get("start"), 64)
					end, _ := strconv.ParseFloat(r.URL.Query().Get("end"), 64)
					series["values"] = [][]any{{start, baseline}, {end, final}}
				} else {
					mu.Lock()
					instantCalls[query]++
					call := instantCalls[query]
					mu.Unlock()
					value := baseline
					if call > 1 {
						value = final
					}
					at, _ := strconv.ParseFloat(r.URL.Query().Get("time"), 64)
					series["value"] = []any{at, value}
				}
				result := []any{series}
				if missing {
					result = []any{}
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{
					"resultType": resultType, "result": result,
				}})
			}))
			defer prometheus.Close()
			cfg := Config{StateDir: t.TempDir(), RunPrometheusEvidence: PrometheusRunEvidenceConfig{
				Enabled: true, URL: prometheus.URL, Environment: "staging", SettleDelay: time.Millisecond,
				RequestTimeout: time.Second, RangeStep: 15 * time.Second,
			}}
			server := &Server{cfg: cfg}
			started := time.Now().UTC().Add(-time.Minute)
			evidence, err := server.beginPrometheusRunEvidence(context.Background(), "controller-test", "AML.T0074", "controller-stop", "p4-demo", "controller-stop", AttackCatalogExecutionActive, AttackCatalogTriggerReactive, started)
			if err != nil {
				t.Fatalf("baseline capture: %v", err)
			}
			if err = server.completePrometheusRunEvidence(context.Background(), evidence, time.Now().UTC()); err != nil {
				t.Fatalf("terminal capture: %v", err)
			}
			if evidence.ExpectedAction != "controller-stop" || evidence.Family != "controller-stop" || evidence.Status != "COMPLETE" {
				t.Fatalf("logical evidence identity changed: %+v", evidence)
			}
			for _, metric := range evidence.Metrics {
				for _, capture := range []*PrometheusResponseCapture{metric.BaselineCapture, metric.FinalCapture, metric.RawCapture} {
					if err = validatePrometheusResponseCapture(capture, started, time.Now().UTC()); err != nil || capture.Parameters["query"] != metric.Query {
						t.Fatalf("%s lost its bound raw capture: %v", metric.Key, err)
					}
				}
				if metric.Key == "noop" || metric.Key == "trusted-events" || metric.Key == "telemetry-source-fresh" {
					continue
				}
				if !strings.Contains(metric.Query, `tenant="p4-demo",environment="staging",action="rotate"`) {
					t.Fatalf("%s did not query the native action: %s", metric.Key, metric.Query)
				}
				if !tc.present {
					if len(metric.Baseline) != 0 || len(metric.Final) != 0 || len(metric.Range) != 0 || len(metric.Deltas) != 0 {
						t.Fatalf("%s fabricated absent native counters: %+v", metric.Key, metric)
					}
				} else {
					wantDelta := float64(0)
					if tc.advance {
						wantDelta = 1
					}
					if len(metric.Baseline) != 1 || len(metric.Final) != 1 || len(metric.Range) != 1 || len(metric.Deltas) != 1 || metric.Deltas[0].Delta != wantDelta {
						t.Fatalf("%s lost native samples or delta: %+v", metric.Key, metric)
					}
				}
			}
			if tc.present && tc.advance {
				if len(evidence.ObservedDecisionModes) != 1 || evidence.ObservedDecisionModes[0] != "active" {
					t.Fatalf("positive native selection was not observed: %v", evidence.ObservedDecisionModes)
				}
			} else if len(evidence.ObservedDecisionModes) != 0 {
				t.Fatalf("missing/zero native delta fabricated a selected mode: %v", evidence.ObservedDecisionModes)
			}
			result := AttackCatalogResult{CatalogueID: evidence.CatalogueID, RunID: evidence.RunID, Family: evidence.Family,
				ExpectedAction: "controller-stop", ExecutionMode: AttackCatalogExecutionActive, TriggerMode: AttackCatalogTriggerReactive,
				StartedAt: started, FinishedAt: time.Now().UTC()}
			if err = validatePrometheusReleaseEvidence(evidence, result); (err == nil) != tc.present {
				t.Fatalf("native capture validation with present=%v: %v", tc.present, err)
			}
		})
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
	evidence, err := server.beginPrometheusRunEvidence(context.Background(), "cat-8", "AML.T0012", "identity-sa-rotate", "console-identity-test", "identity-rotate", AttackCatalogExecutionActive, AttackCatalogTriggerReactive, time.Now().UTC())
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
	evidence, err := (&Server{cfg: cfg}).beginPrometheusRunEvidence(context.Background(), "cat-9", "AML.T0012", "identity-sa-rotate", "console-identity-test", "identity-rotate", AttackCatalogExecutionActive, AttackCatalogTriggerReactive, time.Now().UTC())
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

func TestObservedPrometheusDecisionModesUsesOnlyPositiveSelectedDeltas(t *testing.T) {
	metrics := []PrometheusMetricEvidence{
		{Key: "selected-action", Deltas: []PrometheusDelta{
			{Labels: map[string]string{"mode": "reactive"}, FinalPresent: true, Delta: 1},
			{Labels: map[string]string{"mode": "proactive"}, FinalPresent: true, Delta: 2},
			{Labels: map[string]string{"mode": "ignored-zero"}, FinalPresent: true, Delta: 0},
		}},
		{Key: "noop", Deltas: []PrometheusDelta{{Labels: map[string]string{"mode": "ignored-noop"}, FinalPresent: true, Delta: 9}}},
	}
	modes := observedPrometheusDecisionModes(metrics)
	if len(modes) != 2 || modes[0] != "proactive" || modes[1] != "reactive" {
		t.Fatalf("observed modes=%v", modes)
	}
}
