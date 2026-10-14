/*
 * Phorvex — live DCGM/Prometheus ingest verification (PHORVEXSEC-55/85).
 */

package ingest

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestPopulateGPUWitnessParsesLiveT4DCGMShape(t *testing.T) {
	const key = "vllm/vllm-584bdd646f-t54kd"
	var mu sync.Mutex
	seen := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		mu.Lock()
		seen = append(seen, q)
		mu.Unlock()

		value, present := 0.0, true
		switch {
		case strings.Contains(q, "DCGM_FI_DEV_FB_USED"):
			value = 9996 // real EKS/T4 sample shape, MiB
		case strings.Contains(q, "DCGM_FI_DEV_FB_FREE"):
			value = 5098
		case strings.Contains(q, "DCGM_FI_PROF_SM_ACTIVE"):
			present = false // not exported by the live T4 stack
		case strings.Contains(q, "PCIE_LINK_GEN") || strings.Contains(q, "PCIE_LINK_WIDTH"):
			present = false // M-114 discovery step 1: the live T4 exporter publishes no link fields
		case strings.Contains(q, "modelName"):
			// M-114 discovery step 2: the byte series carry the exporter's device model label.
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"vllm","pod":"vllm-584bdd646f-t54kd","modelName":"Tesla T4"},"value":[0,"1"]}]}}`)
			return
		case strings.Contains(q, "DCGM_FI_PROF_PCIE_RX_BYTES"):
			value = mustCap(PCIeLink{Gen: 3, Width: 16}) /* M-114: T4 class capacity, discovered */ / 10
		default:
			t.Fatalf("unexpected PromQL: %s", q)
		}

		w.Header().Set("Content-Type", "application/json")
		if !present {
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
			return
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"vllm","pod":"vllm-584bdd646f-t54kd"},"value":[1,%q]}]}}`, fmt.Sprintf("%.9g", value))
	}))
	defer server.Close()

	snap := &Snapshot{}
	PopulateGPUWitness(context.Background(), snap, server.URL, nil)
	w, ok := snap.GPUWitness[key]
	if !ok || !w.GPUPresent {
		t.Fatalf("live DCGM pod missing from PhysicsWitness: %+v", snap.GPUWitness)
	}
	wantVRAM := 9996.0 / (9996.0 + 5098.0)
	if math.Abs(w.VRAMFraction-wantVRAM) > 1e-9 {
		t.Errorf("VRAMFraction = %.12f, want %.12f", w.VRAMFraction, wantVRAM)
	}
	if w.SMOccupancy != 0 || w.SMSource != "" {
		t.Errorf("T4 SM occupancy must be honest-absent without PROF_SM_ACTIVE: occupancy=%v source=%q", w.SMOccupancy, w.SMSource)
	}
	if math.Abs(w.LinkBandwidth-0.1) > 1e-9 || !strings.Contains(w.LinkSource, "PCIE_RX") {
		t.Errorf("PCIe witness not parsed: bandwidth=%v source=%q", w.LinkBandwidth, w.LinkSource)
	}

	mu.Lock()
	queries := strings.Join(seen, "\n")
	mu.Unlock()
	if strings.Contains(queries, "NVLINK") || strings.Contains(queries, "DCGM_FI_DEV_GPU_UTIL") || !strings.Contains(queries, "rate(DCGM_FI_PROF_PCIE_RX_BYTES") || !strings.Contains(queries, "by (namespace, pod)") {
		t.Errorf("cluster-wide query did not use the live T4 PCIe shape:\n%s", queries)
	}
}

func TestPopulateGPUWitnessUsesProfiledSMActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q, "DCGM_FI_PROF_SM_ACTIVE") {
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"vllm","pod":"gpu-pod"},"value":[1,"0.61"]}]}}`)
			return
		}
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer server.Close()

	snap := &Snapshot{}
	if err := PopulateGPUWitness(context.Background(), snap, server.URL, nil); err != nil {
		t.Fatal(err)
	}
	w := snap.GPUWitness["vllm/gpu-pod"]
	if math.Abs(w.SMOccupancy-0.61) > 1e-12 || w.SMSource != "DCGM_FI_PROF_SM_ACTIVE" {
		t.Fatalf("profiled SM occupancy not preserved: occupancy=%v source=%q", w.SMOccupancy, w.SMSource)
	}
}

func TestPodMetricsParsesDCGMGPUUtilIntoTelemetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"vllm","pod":"gpu-pod"},"value":[1,"0.42"]}]}}`)
	}))
	defer server.Close()

	p := NewPromHTTP(server.URL, map[string]string{SigGPUUtil: `avg by (pod) (DCGM_FI_DEV_GPU_UTIL{namespace="{namespace}"}) / 100`})
	got, err := p.PodMetrics(context.Background(), "vllm", []string{"gpu-pod"})
	if err != nil {
		t.Fatal(err)
	}
	tel := got["gpu-pod"]
	if !tel.GPUUtil.Usable() || math.Abs(tel.GPUUtil.Value-0.42) > 1e-12 {
		t.Fatalf("real DCGM GPU utilization was not parsed into Telemetry: %+v", tel)
	}
}

func TestPrometheusInstantQueryRetriesTransientFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"vllm","pod":"gpu-pod"},"value":[1,"9996"]}]}}`)
	}))
	defer server.Close()

	p := NewPromHTTP(server.URL, nil)
	got, err := p.instantQueryNsPod(context.Background(), "DCGM_FI_DEV_FB_USED")
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || got["vllm/gpu-pod"] != 9996 {
		t.Fatalf("transient query was not retried into a real value: attempts=%d values=%v", attempts, got)
	}
}

// The admission and native completion boundaries already use distinct namespace
// labels. Exercise the actual ReqRate parser without summing native and bridge
// counters or pretending an admission Pod is a serving Pod.
func TestGatewayAndVLLMReqRateKeepSeparateNamespaces(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		want := strings.ReplaceAll(DefaultPromQueries()[SigReqRate], "{namespace}", "litellm")
		pod, value := "litellm-gateway-a", "2"
		if q != want {
			if q != strings.ReplaceAll(DefaultPromQueries()[SigReqRate], "{namespace}", "vllm") {
				t.Errorf("unexpected ReqRate query: %s", q)
				http.Error(w, "bad query", 400)
				return
			}
			pod, value = "vllm-serving-a", "1"
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pod":%q},"value":[1,%q]}]}}`, pod, value)
	}))
	defer server.Close()
	p := NewPromHTTP(server.URL, map[string]string{SigReqRate: DefaultPromQueries()[SigReqRate]})
	for _, tc := range []struct {
		namespace, pod, other string
		want                  float64
	}{{"litellm", "litellm-gateway-a", "vllm-serving-a", 2}, {"vllm", "vllm-serving-a", "litellm-gateway-a", 1}} {
		got, err := p.PodMetrics(context.Background(), tc.namespace, []string{tc.pod})
		if err != nil || !got[tc.pod].ReqRate.Usable() || got[tc.pod].ReqRate.Value != tc.want {
			t.Fatalf("separate namespace rate: %+v %v", got, err)
		}
		if _, exists := got[tc.other]; exists {
			t.Fatal("another boundary entered per-Pod telemetry")
		}
	}
}
