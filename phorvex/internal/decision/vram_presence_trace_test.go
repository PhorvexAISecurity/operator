/*
 * Phorvex — M-152: the decision record must show the VRAM residency the fleet actually measured.
 *
 * End-to-end over the real chain: a dcgm-exporter-shaped Prometheus answering the brain's own
 * witness queries over HTTP -> ingest.PopulateGPUWitness -> the selected GPU adapter ->
 * WorkloadView.Physics -> the real trace builder and its JSON serialization. The presence bit is
 * never injected; it is whatever the producer derived from the served samples. A measured VRAM
 * fraction is a residency observation only — it is not evidence of model theft or of a defense.
 */

package decision

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
)

// The decision fixture's namespace with the live M-152 subject's shape: a vLLM server on a
// Tesla T4 (15360 MiB) whose FB_USED answered 14488 while every record showed vramFraction dark.
const (
	vramTraceNamespace = "ns"
	vramTracePod       = "vllm-77997646c9-nhzv4"
	vramTraceKey       = vramTraceNamespace + "/" + vramTracePod
)

// vramTraceScrape is one dcgm-exporter answer set as the raw sample strings Prometheus returns;
// "" means the series carried no sample for this pod, and failQuery is a metric-name fragment
// whose query returns 503 (a real query failure, not an empty vector).
type vramTraceScrape struct {
	used, free string
	smActive   string
	failQuery  string
}

// vramTraceFeed serves the brain's DCGM witness queries over real HTTP and returns its base URL.
func vramTraceFeed(t *testing.T, scrape vramTraceScrape) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		if scrape.failQuery != "" && strings.Contains(query, scrape.failQuery) {
			http.Error(w, "prometheus unavailable", http.StatusServiceUnavailable)
			return
		}
		value := ""
		switch {
		case strings.Contains(query, "modelName"):
		case strings.Contains(query, "DCGM_FI_DEV_FB_USED"):
			value = scrape.used
		case strings.Contains(query, "DCGM_FI_DEV_FB_FREE"):
			value = scrape.free
		case strings.Contains(query, "DCGM_FI_PROF_SM_ACTIVE"):
			value = scrape.smActive
		}
		result := []any{}
		if value != "" {
			result = append(result, map[string]any{
				"metric": map[string]string{"namespace": vramTraceNamespace, "pod": vramTracePod},
				"value":  []any{1789056000, value},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "success",
			"data":   map[string]any{"resultType": "vector", "result": result},
		})
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// vramTraceWitness runs a full production tick of the physics chain — live scrape, then the
// label-selected GPU adapter — and returns the witness the runner would stamp on the view.
func vramTraceWitness(t *testing.T, scrape vramTraceScrape, wantScrapeErr bool) model.PhysicsWitness {
	t.Helper()
	snap := &ingest.Snapshot{
		Nodes: []ingest.NodeInfo{{
			Name: "gpu-node-1", AllocatableCPUMilli: 8000, AllocatableMemBytes: 32 << 30,
			AllocatableGPU: 1, MIGResources: map[string]int64{},
			Labels:      map[string]string{"eks.amazonaws.com/nodegroup": "gpu-ng"},
			Schedulable: true,
		}},
		Pods: []model.Pod{{
			Namespace: vramTraceNamespace, Name: vramTracePod, Node: "gpu-node-1", HasGPU: true,
			ImageID: "vllm/vllm-openai@sha256:aa11", ModelID: "meta-llama/Llama-3-8B", Phase: "Running",
		}},
	}
	err := ingest.PopulateGPUWitness(context.Background(), snap, vramTraceFeed(t, scrape), nil)
	if wantScrapeErr != (err != nil) {
		t.Fatalf("fixture: PopulateGPUWitness error = %v, want error %v", err, wantScrapeErr)
	}
	selected, physics := platform.Derive(snap)
	if selected != "eks-gpu" {
		t.Fatalf("fixture: adapter selected = %q, want eks-gpu", selected)
	}
	return physics[vramTraceKey]
}

// vramTraceInputs is the serialized record an auditor actually reads.
type vramTraceInputs struct {
	Inputs struct {
		VRAMFraction model.OptionalFloat `json:"vramFraction"`
		SMOccupancy  model.OptionalFloat `json:"smOccupancy"`
		Leakage      model.OptionalFloat `json:"leakage"`
	} `json:"inputs"`
}

func vramTraceOf(t *testing.T, witness model.PhysicsWitness) (*model.DecisionTraceV2, vramTraceInputs) {
	t.Helper()
	view := covView(vramTracePod, true, 2*time.Hour, false)
	view.Physics = witness
	decisions := fixedTraceEngine().Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))
	if len(decisions) == 0 || decisions[0].Trace == nil {
		t.Fatalf("no traced decision: %+v", decisions)
	}
	trace := decisions[0].Trace
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	var wire vramTraceInputs
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	return trace, wire
}

// TestDecisionTraceCarriesMeasuredVRAMFromTheLiveDCGMChain — M-152. The record must report VRAM
// exactly as measured: a live fraction and an observed zero are present, while a missing series,
// an unusable denominator, a non-finite sample and a failed query stay absent. The trace could
// not previously distinguish "VRAM absent" from "VRAM live but the flag was dropped at the
// platform seam", which is the field a gate audit needs.
func TestDecisionTraceCarriesMeasuredVRAMFromTheLiveDCGMChain(t *testing.T) {
	cases := []struct {
		name        string
		scrape      vramTraceScrape
		wantErr     bool
		wantPresent bool
		wantValue   float64
	}{
		{"measured-nonzero", vramTraceScrape{used: "14488", free: "872", smActive: "0.42"}, false, true, 14488.0 / (14488.0 + 872.0)},
		{"measured-zero", vramTraceScrape{used: "0", free: "15360", smActive: "0.42"}, false, true, 0},
		{"missing-free-series", vramTraceScrape{used: "14488", smActive: "0.42"}, false, false, 0},
		{"no-vram-samples", vramTraceScrape{smActive: "0.42"}, false, false, 0},
		{"zero-denominator", vramTraceScrape{used: "0", free: "0", smActive: "0.42"}, false, false, 0},
		{"nonfinite-used", vramTraceScrape{used: "NaN", free: "872", smActive: "0.42"}, false, false, 0},
		{"vram-query-failure", vramTraceScrape{used: "14488", free: "872", smActive: "0.42", failQuery: "DCGM_FI_DEV_FB_USED"}, true, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			witness := vramTraceWitness(t, tc.scrape, tc.wantErr)
			// Producer precondition: the served samples must really drive the chain to the
			// state under test, so a green trace assertion cannot come from an inert fixture.
			if witness.VRAMPresent != tc.wantPresent {
				t.Fatalf("fixture: derived witness presence = %v, want %v (%+v)", witness.VRAMPresent, tc.wantPresent, witness)
			}
			if math.Abs(witness.VRAMFraction-tc.wantValue) > 1e-9 {
				t.Fatalf("fixture: derived VRAMFraction = %v, want %v", witness.VRAMFraction, tc.wantValue)
			}

			trace, wire := vramTraceOf(t, witness)
			if trace.Inputs.VRAMFraction.Present != tc.wantPresent {
				t.Fatalf("trace vramFraction presence = %+v, want present %v with a measured %v",
					trace.Inputs.VRAMFraction, tc.wantPresent, witness.VRAMFraction)
			}
			if wire.Inputs.VRAMFraction != trace.Inputs.VRAMFraction {
				t.Fatalf("serialized vramFraction = %+v, in-memory %+v", wire.Inputs.VRAMFraction, trace.Inputs.VRAMFraction)
			}
			if tc.wantPresent && wire.Inputs.VRAMFraction.Value != witness.VRAMFraction {
				t.Fatalf("serialized vramFraction value = %v, measured %v", wire.Inputs.VRAMFraction.Value, witness.VRAMFraction)
			}
			if !tc.wantPresent && wire.Inputs.VRAMFraction.Value != 0 {
				t.Fatalf("absent vramFraction carried a value: %+v", wire.Inputs.VRAMFraction)
			}
			// Canonical() is the redacted form the record is archived in; it must keep the field.
			if canonical := trace.Canonical(); canonical.Inputs.VRAMFraction != trace.Inputs.VRAMFraction {
				t.Fatalf("Canonical() altered vramFraction: %+v", canonical.Inputs.VRAMFraction)
			}
			// SM occupancy keys on SMSource and is untouched by this fix; the model-theft gate
			// input (Leakage) reads SM activity only, never VRAM residency.
			if wire.Inputs.SMOccupancy.Present != (witness.SMSource != "") || wire.Inputs.SMOccupancy.Value != witness.SMOccupancy {
				t.Fatalf("SM occupancy presence changed: %+v (witness source %q, value %v)",
					wire.Inputs.SMOccupancy, witness.SMSource, witness.SMOccupancy)
			}
			if wire.Inputs.Leakage.Present != (witness.SMSource != "") {
				t.Fatalf("leakage gate input presence changed: %+v", wire.Inputs.Leakage)
			}
		})
	}
}

// TestMeasuredVRAMPresenceChangesOnlyTheRecordedField — the repair restores an audit field, it
// does not touch physics interpretation, scoring or action selection. With the SAME measured
// fraction, flipping presence must change the vramFraction record and NOTHING else: identical
// decisions and a trace that is otherwise equal field for field.
func TestMeasuredVRAMPresenceChangesOnlyTheRecordedField(t *testing.T) {
	measured := vramTraceWitness(t, vramTraceScrape{used: "14488", free: "872", smActive: "0.42"}, false)
	if !measured.VRAMPresent || measured.VRAMFraction == 0 {
		t.Fatalf("fixture: the live chain did not produce a measured VRAM witness: %+v", measured)
	}
	dark := measured
	dark.VRAMPresent = false // the pre-repair shape: the same float, no presence

	decide := func(witness model.PhysicsWitness) []model.Decision {
		view := covView(vramTracePod, true, 2*time.Hour, false)
		view.Physics = witness
		return fixedTraceEngine().Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))
	}
	present, absent := decide(measured), decide(dark)
	if !reflect.DeepEqual(decisionsWithoutTrace(present), decisionsWithoutTrace(absent)) {
		t.Fatalf("VRAM presence altered the decisions themselves:\n present=%+v\n absent=%+v",
			decisionsWithoutTrace(present), decisionsWithoutTrace(absent))
	}
	if !present[0].Trace.Inputs.VRAMFraction.Present || absent[0].Trace.Inputs.VRAMFraction.Present {
		t.Fatalf("presence did not reach the record: present=%+v absent=%+v",
			present[0].Trace.Inputs.VRAMFraction, absent[0].Trace.Inputs.VRAMFraction)
	}
	withoutVRAM := func(trace *model.DecisionTraceV2) model.DecisionTraceV2 {
		out := *trace
		out.Inputs.VRAMFraction = model.OptionalFloat{}
		return out
	}
	if !reflect.DeepEqual(withoutVRAM(present[0].Trace), withoutVRAM(absent[0].Trace)) {
		t.Fatal("VRAM presence changed a trace field other than vramFraction")
	}
}
