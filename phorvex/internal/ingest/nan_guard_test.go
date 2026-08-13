package ingest

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// nan_guard_test.go — the INGEST half of the NaN-poisoning defence (PHORVEXSEC-46).
//
// `strconv.ParseFloat("NaN")` returns NaN with `err == nil`, and Prometheus really does serve the
// literal `NaN` (a 0/0 expression, a stale/absent series). If such a sample is admitted it reaches
// C_flow -> ECost, and because every comparison against NaN is false the optimizer's `gain > best`
// is always false: the engine does not error, it silently stops selecting.
//
// The cost-layer clamps are covered by cost/costaudit_test.go and decision/nan_property_test.go.
// This file covers the FIRST line of defence — dropping the sample at ingest — which had guards in
// code but no test: removing them was verified to leave the entire suite green.

func promServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
}

// vectorBody builds a Prometheus instant-query vector response carrying the given raw sample
// strings verbatim, so the test exercises the real parse path rather than a pre-parsed float.
func vectorBody(pod, raw string) string {
	return `{"status":"success","data":{"resultType":"vector","result":[` +
		`{"metric":{"pod":"` + pod + `"},"value":[1712345678,"` + raw + `"]}` +
		`]}}`
}

// TestInstantQueryDropsNonFiniteSamples is the regression: Prometheus serves NaN/+Inf/-Inf as
// literals that ParseFloat accepts WITHOUT error. Each must be dropped (honest-absent), never
// ingested — an absent metric is recoverable, a NaN one silently disables selection.
func TestInstantQueryDropsNonFiniteSamples(t *testing.T) {
	for _, raw := range []string{"NaN", "nan", "+Inf", "-Inf", "Inf"} {
		t.Run(raw, func(t *testing.T) {
			srv := promServer(t, vectorBody("api-0", raw))
			defer srv.Close()

			p := NewPromHTTP(srv.URL, DefaultPromQueries())
			got, err := p.instantQuery(context.Background(), "whatever")
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if v, ok := got["api-0"]; ok {
				t.Fatalf("a %q sample must be DROPPED, not ingested (got %v — it would poison "+
					"C_flow/ECost and make the optimizer stop selecting)", raw, v)
			}
		})
	}
}

// TestInstantQueryKeepsFiniteSamples pins the other side: the guard must not throw away good data.
func TestInstantQueryKeepsFiniteSamples(t *testing.T) {
	srv := promServer(t, vectorBody("api-0", "0.37"))
	defer srv.Close()

	p := NewPromHTTP(srv.URL, DefaultPromQueries())
	got, err := p.instantQuery(context.Background(), "whatever")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	v, ok := got["api-0"]
	if !ok {
		t.Fatal("a finite sample must be ingested")
	}
	if math.IsNaN(v) || math.IsInf(v, 0) || v != 0.37 {
		t.Fatalf("want 0.37, got %v", v)
	}
}

// TestPodMetricsNeverYieldsNonFiniteTelemetry is the end-to-end property at the ingest boundary:
// whatever Prometheus serves, no Telemetry field handed to the decision path may be non-finite.
//
// The first version of this test ranged over the returned map and checked each field. That was
// VACUOUS: when every series is NaN the guard drops every sample, so no pod is ever added and the
// range body never ran — the test passed without asserting anything, which is precisely the failure
// mode this file was written to catch. It now asserts BOTH halves explicitly.
func TestPodMetricsNeverYieldsNonFiniteTelemetry(t *testing.T) {
	// (a) Fully stale exporter: every series NaN. The honest outcome is that the pod is ABSENT,
	//     not present-with-zeroes — an absent metric is recoverable, a zeroed one is a lie.
	t.Run("all NaN => the pod is dropped entirely", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, vectorBody("api-0", "NaN"))
		}))
		defer srv.Close()
		p := NewPromHTTP(srv.URL, DefaultPromQueries())
		tele, err := p.PodMetrics(context.Background(), "prod", []string{"api-0"})
		if err != nil {
			t.Fatalf("PodMetrics: %v", err)
		}
		if len(tele) != 0 {
			t.Fatalf("every series was NaN, so nothing should have been ingested; got %d pods: %v", len(tele), tele)
		}
	})

	// (b) The case that actually exercises the loop: SOME series are finite, so the pod IS present
	//     and every field it carries must be finite. Without this arm the assertion above is the
	//     only thing running, and the per-field check is dead code.
	t.Run("mixed => the pod is present and every field is finite", func(t *testing.T) {
		var nth int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			nth++
			raw := "NaN"
			if nth%2 == 1 {
				raw = "12.5" // alternate finite / non-finite across the signal queries
			}
			fmt.Fprint(w, vectorBody("api-0", raw))
		}))
		defer srv.Close()
		p := NewPromHTTP(srv.URL, DefaultPromQueries())
		tele, err := p.PodMetrics(context.Background(), "prod", []string{"api-0"})
		if err != nil {
			t.Fatalf("PodMetrics: %v", err)
		}
		if len(tele) == 0 {
			t.Fatal("some series were finite, so the pod must be present — otherwise the per-field " +
				"check below never runs and this test asserts nothing")
		}
		for pod, tl := range tele {
			if !tl.Present {
				t.Errorf("pod %s: ingested but Present=false", pod)
			}
			for name, v := range map[string]float64{
				"ReqRate": tl.ReqRate, "LatencyMs": tl.LatencyMs, "P99Ms": tl.P99Ms,
				"QueueDepth": tl.QueueDepth, "ConnCount": tl.ConnCount, "BytesIn": tl.BytesIn,
				"BytesOut": tl.BytesOut, "GPUUtil": tl.GPUUtil, "SyscallRate": tl.SyscallRate,
				"TokensPerSec": tl.TokensPerSec,
			} {
				if math.IsNaN(v) || math.IsInf(v, 0) {
					t.Errorf("pod %s: Telemetry.%s is non-finite (%v) — it would poison ECost and "+
						"silently stop the optimizer selecting", pod, name, v)
				}
			}
		}
	})
}

// TestParseFloatAcceptsNaN documents WHY the guards are required — this is not hypothetical:
// Go's ParseFloat accepts these literals with a NIL error, so "err == nil" is NOT a validity check.
func TestParseFloatAcceptsNaN(t *testing.T) {
	for _, raw := range []string{"NaN", "nan", "+Inf", "-Inf"} {
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			continue // if Go ever rejects these, the ingest guard becomes redundant, not wrong
		}
		if !math.IsNaN(f) && !math.IsInf(f, 0) {
			t.Fatalf("%q parsed to a finite %v — unexpected", raw, f)
		}
		t.Logf("ParseFloat(%q) = %v with err == nil — this is why the ingest guard exists", raw, f)
	}
}
