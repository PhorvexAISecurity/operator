package ingest

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/model"
)

func m142PromTelemetry(t *testing.T, values map[string]string) model.Telemetry {
	t.Helper()
	defaults := DefaultPromQueries()
	queries := map[string]string{
		SigReqRate:      defaults[SigReqRate],
		SigQueueDepth:   defaults[SigQueueDepth],
		SigGPUUtil:      defaults[SigGPUUtil],
		SigTokensPerSec: defaults[SigTokensPerSec],
	}
	expected := make(map[string]string, len(queries))
	for signal, query := range queries {
		expected[strings.ReplaceAll(query, "{namespace}", "prod")] = signal
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signal, ok := expected[r.URL.Query().Get("query")]
		if !ok {
			http.Error(w, "unexpected query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		value, present := values[signal]
		if !present {
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
			return
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"prod","pod":"api-0"},"value":[1700000000,%q]}]}}`, value)
	}))
	t.Cleanup(server.Close)

	got, err := NewPromHTTP(server.URL, queries).PodMetrics(context.Background(), "prod", []string{"api-0"})
	if err != nil {
		t.Fatal(err)
	}
	telemetry, ok := got["api-0"]
	if !ok {
		t.Fatalf("Prometheus result omitted api-0: %+v", got)
	}
	return telemetry
}

func TestM142PrometheusActivityReachesPhaseAndRespawnCost(t *testing.T) {
	cases := []struct {
		name       string
		values     map[string]string
		wantPhase  model.WorkloadPhase
		wantReason string
		wantCost   float64
	}{
		{
			name:       "queued work vetoes idle",
			values:     map[string]string{SigReqRate: "0", SigQueueDepth: "10"},
			wantPhase:  model.PhaseWarm,
			wantReason: PhaseReasonBusyMeasured,
			wantCost:   0.70,
		},
		{
			name:       "token throughput vetoes idle",
			values:     map[string]string{SigReqRate: "0", SigTokensPerSec: "5"},
			wantPhase:  model.PhaseWarm,
			wantReason: PhaseReasonBusyMeasured,
			wantCost:   0.70,
		},
		{
			name:       "fresh measured idle remains idle",
			values:     map[string]string{SigReqRate: "0"},
			wantPhase:  model.PhaseIdle,
			wantReason: PhaseReasonIdleMeasured,
			wantCost:   0.15,
		},
		{
			name:       "negative request rate is uncertain",
			values:     map[string]string{SigReqRate: "-1"},
			wantPhase:  model.PhaseWarm,
			wantReason: PhaseReasonWarmUncertain,
			wantCost:   0.70,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			telemetry := m142PromTelemetry(t, tc.values)
			if !telemetry.ReqRate.Usable() || telemetry.ReqRate.Src != "prometheus-http" || telemetry.ReqRate.Age != 0 {
				t.Fatalf("request-rate provenance/freshness was not preserved: %+v", telemetry.ReqRate)
			}
			pod := t1cReadyPod()
			phase, reason := PhaseOf(pod, telemetry), PhaseReasonOf(pod, telemetry)
			if phase != tc.wantPhase || reason != tc.wantReason {
				t.Fatalf("phase/reason = %s/%s, want %s/%s; telemetry=%+v", phase, reason, tc.wantPhase, tc.wantReason, telemetry)
			}
			view := &model.WorkloadView{Pod: pod, Telemetry: telemetry, Phase: phase, PhaseReason: reason}
			gotCost := cost.NewP1Cost().ECost(view, model.Move{Action: model.ActionRotate}, model.Policy{FlowDisruption: 1})
			if math.Abs(gotCost-tc.wantCost) > 1e-12 {
				t.Fatalf("respawn cost = %.12f, want existing phase prior %.12f", gotCost, tc.wantCost)
			}
		})
	}
}

func TestM142PhaseRequiresFreshConsistentAppInactivity(t *testing.T) {
	present := func(value float64) model.Signal { return model.PresentSignal(value, "fixture") }
	stale := model.Signal{Value: 0, State: model.Stale, Age: time.Minute, Src: "fixture", Reason: model.ReasonStale}
	errored := model.Signal{State: model.Error, Src: "fixture", Reason: model.ReasonQueryFailed}

	cases := []struct {
		name       string
		telemetry  model.Telemetry
		wantPhase  model.WorkloadPhase
		wantReason string
	}{
		{"request threshold is idle", model.Telemetry{ReqRate: present(0.001)}, model.PhaseIdle, PhaseReasonIdleMeasured},
		{"request above threshold is busy", model.Telemetry{ReqRate: present(math.Nextafter(0.001, math.Inf(1)))}, model.PhaseWarm, PhaseReasonBusyMeasured},
		{"absent optional gpu permits idle", model.Telemetry{ReqRate: present(0)}, model.PhaseIdle, PhaseReasonIdleMeasured},
		{"explicit zero gpu permits idle", model.Telemetry{ReqRate: present(0), GPUUtil: present(0)}, model.PhaseIdle, PhaseReasonIdleMeasured},
		{"gpu threshold permits idle", model.Telemetry{ReqRate: present(0), GPUUtil: present(0.01)}, model.PhaseIdle, PhaseReasonIdleMeasured},
		{"gpu above threshold is busy", model.Telemetry{ReqRate: present(0), GPUUtil: present(math.Nextafter(0.01, math.Inf(1)))}, model.PhaseWarm, PhaseReasonBusyMeasured},
		{"zero queue permits idle", model.Telemetry{ReqRate: present(0), QueueDepth: present(0)}, model.PhaseIdle, PhaseReasonIdleMeasured},
		{"positive queue is busy", model.Telemetry{ReqRate: present(0), QueueDepth: present(1)}, model.PhaseWarm, PhaseReasonBusyMeasured},
		{"zero tokens permit idle", model.Telemetry{ReqRate: present(0), TokensPerSec: present(0)}, model.PhaseIdle, PhaseReasonIdleMeasured},
		{"positive tokens are busy", model.Telemetry{ReqRate: present(0), TokensPerSec: present(1)}, model.PhaseWarm, PhaseReasonBusyMeasured},
		{"missing request with optional zero is uncertain", model.Telemetry{QueueDepth: present(0)}, model.PhaseWarm, PhaseReasonWarmUncertain},
		{"stale request is uncertain", model.Telemetry{ReqRate: stale}, model.PhaseWarm, PhaseReasonWarmUncertain},
		{"errored request is uncertain", model.Telemetry{ReqRate: errored}, model.PhaseWarm, PhaseReasonWarmUncertain},
		{"stale optional gpu is uncertain", model.Telemetry{ReqRate: present(0), GPUUtil: stale}, model.PhaseWarm, PhaseReasonWarmUncertain},
		{"errored optional queue is uncertain", model.Telemetry{ReqRate: present(0), QueueDepth: errored}, model.PhaseWarm, PhaseReasonWarmUncertain},
		{"negative request is uncertain", model.Telemetry{ReqRate: present(-1)}, model.PhaseWarm, PhaseReasonWarmUncertain},
		{"negative queue is uncertain", model.Telemetry{ReqRate: present(0), QueueDepth: present(-1)}, model.PhaseWarm, PhaseReasonWarmUncertain},
		{"nan request is uncertain", model.Telemetry{ReqRate: present(math.NaN())}, model.PhaseWarm, PhaseReasonWarmUncertain},
		{"infinite tokens are uncertain", model.Telemetry{ReqRate: present(0), TokensPerSec: present(math.Inf(1))}, model.PhaseWarm, PhaseReasonWarmUncertain},
		{"cadvisor only preserves no-app warm", model.Telemetry{ConnCount: present(42)}, model.PhaseWarm, PhaseReasonWarmNoApp},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := t1cReadyPod()
			if gotPhase, gotReason := PhaseOf(pod, tc.telemetry), PhaseReasonOf(pod, tc.telemetry); gotPhase != tc.wantPhase || gotReason != tc.wantReason {
				t.Fatalf("phase/reason = %s/%s, want %s/%s", gotPhase, gotReason, tc.wantPhase, tc.wantReason)
			}
		})
	}
}

func TestM142PrometheusUncertainRequestCannotSupportIdle(t *testing.T) {
	query := DefaultPromQueries()[SigReqRate]
	response := "0"
	status := http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if status != http.StatusOK {
			http.Error(w, "query failed", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch response {
		case "":
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		default:
			fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"prod","pod":"api-0"},"value":[1700000000,%q]}]}}`, response)
		}
	}))
	defer server.Close()

	prom := NewPromHTTP(server.URL, map[string]string{SigReqRate: query})
	first, err := prom.PodMetrics(context.Background(), "prod", []string{"api-0"})
	if err != nil || !first["api-0"].ReqRate.Usable() {
		t.Fatalf("first measured-idle sample failed: telemetry=%+v err=%v", first, err)
	}

	t.Run("stale", func(t *testing.T) {
		response = ""
		time.Sleep(time.Millisecond)
		got, err := prom.PodMetrics(context.Background(), "prod", []string{"api-0"})
		if err != nil {
			t.Fatal(err)
		}
		signal := got["api-0"].ReqRate
		if signal.State != model.Stale || signal.Value != 0 || signal.Age <= 0 || signal.Src != "prometheus-http" || signal.Reason != model.ReasonStale {
			t.Fatalf("stale value/provenance not preserved: %+v", signal)
		}
		if phase, reason := PhaseOf(t1cReadyPod(), got["api-0"]), PhaseReasonOf(t1cReadyPod(), got["api-0"]); phase != model.PhaseWarm || reason != PhaseReasonWarmUncertain {
			t.Fatalf("stale request phase/reason = %s/%s, want Warm/%s", phase, reason, PhaseReasonWarmUncertain)
		}
	})

	t.Run("query error", func(t *testing.T) {
		status = http.StatusInternalServerError
		got, err := prom.PodMetrics(context.Background(), "prod", []string{"api-0"})
		if err == nil {
			t.Fatal("failed request-rate query returned nil error")
		}
		signal := got["api-0"].ReqRate
		if signal.State != model.Error || signal.Reason != model.ReasonQueryFailed || signal.Usable() {
			t.Fatalf("query error was not typed explicitly: %+v", signal)
		}
		telemetry := got["api-0"]
		phase, reason := PhaseOf(t1cReadyPod(), telemetry), PhaseReasonOf(t1cReadyPod(), telemetry)
		if phase != model.PhaseWarm || reason != PhaseReasonWarmUncertain {
			t.Fatalf("errored request phase/reason = %s/%s, want Warm/%s", phase, reason, PhaseReasonWarmUncertain)
		}
		view := &model.WorkloadView{Pod: t1cReadyPod(), Telemetry: telemetry, Phase: phase, PhaseReason: reason}
		eval := cost.NewP1Cost().Evaluation(view, model.Move{Action: model.ActionRotate}, model.Policy{FlowDisruption: 1})
		if eval.UnactionableCategory != cost.UnactionableNaNCategory || eval.NaNFeature != "telemetry.reqRate" {
			t.Fatalf("errored request did not fail cost evaluation conservatively: %+v", eval)
		}
	})
}

func TestM142PrometheusNonFiniteRequestIsUncertainAndUnactionable(t *testing.T) {
	telemetry := m142PromTelemetry(t, map[string]string{SigReqRate: "NaN"})
	if telemetry.ReqRate.State != model.Error || telemetry.ReqRate.Reason != model.ReasonNonFinite || telemetry.ReqRate.Usable() {
		t.Fatalf("non-finite request was not typed Error/non-finite: %+v", telemetry.ReqRate)
	}
	phase, reason := PhaseOf(t1cReadyPod(), telemetry), PhaseReasonOf(t1cReadyPod(), telemetry)
	if phase != model.PhaseWarm || reason != PhaseReasonWarmUncertain {
		t.Fatalf("non-finite request phase/reason = %s/%s, want Warm/%s", phase, reason, PhaseReasonWarmUncertain)
	}
	view := &model.WorkloadView{Pod: t1cReadyPod(), Telemetry: telemetry, Phase: phase, PhaseReason: reason}
	eval := cost.NewP1Cost().Evaluation(view, model.Move{Action: model.ActionRotate}, model.Policy{FlowDisruption: 1})
	if eval.UnactionableCategory != cost.UnactionableNaNCategory || eval.NaNFeature != "telemetry.reqRate" {
		t.Fatalf("non-finite request did not fail cost evaluation conservatively: %+v", eval)
	}
}

func TestM142LifecyclePrecedesTelemetryClassification(t *testing.T) {
	bad := model.Telemetry{ReqRate: model.PresentSignal(math.NaN(), "fixture")}
	cases := []struct {
		name       string
		pod        model.Pod
		wantPhase  model.WorkloadPhase
		wantReason string
	}{
		{"terminal", model.Pod{Phase: "Succeeded", Ready: true}, model.PhaseDraining, PhaseReasonDraining},
		{"young not ready", model.Pod{Age: time.Minute}, model.PhaseColdStarting, PhaseReasonColdStart},
		{"old not ready", model.Pod{Age: 3 * time.Minute}, model.PhaseUnknown, PhaseReasonUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if gotPhase, gotReason := PhaseOf(tc.pod, bad), PhaseReasonOf(tc.pod, bad); gotPhase != tc.wantPhase || gotReason != tc.wantReason {
				t.Fatalf("phase/reason = %s/%s, want %s/%s", gotPhase, gotReason, tc.wantPhase, tc.wantReason)
			}
		})
	}
}
