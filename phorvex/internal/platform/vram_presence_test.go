/*
 * Phorvex — M-152: the measured-VRAM presence bit must survive the platform adapter seam.
 *
 * These tests drive the REAL producer chain: a dcgm-exporter-shaped Prometheus answering the
 * brain's own witness queries over HTTP -> ingest.PopulateGPUWitness -> the selected GPU adapter.
 * Nothing mocks the presence flag; every case asserts the adapter's observable output against
 * what the producer actually derived from the served samples. Measuring VRAM says nothing about
 * whether a model is being stolen or defended — these assertions are about signal fidelity only.
 */

package platform

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// The live subject from the M-152 investigation: a vLLM server on a Tesla T4 (15360 MiB), whose
// FB_USED answered 14488 from the very Prometheus the brain reads while every decision record
// still showed vramFraction absent.
const (
	vramNamespace = "vllm"
	vramPodName   = "vllm-77997646c9-nhzv4"
	vramKey       = vramNamespace + "/" + vramPodName
	vramSampleTS  = 1789056000
)

// dcgmScrape is one exporter answer set, as the raw sample strings Prometheus returns. An empty
// string means the series carried NO sample for this pod (honest-absent), and failQueries lists
// metric-name fragments whose query returns 503 (a real query failure, not an empty vector).
type dcgmScrape struct {
	used, free  string
	smActive    string
	pcieBytes   string
	linkGen     string
	linkWidth   string
	modelName   string
	failQueries []string
}

// liveScrape is the healthy fleet shape: VRAM, SM occupancy, PCIe byte-rate and the negotiated
// link all answering for the same pod.
func liveScrape() dcgmScrape {
	return dcgmScrape{
		used: "14488", free: "872", smActive: "0.42", pcieBytes: "1073741824",
		linkGen: "3", linkWidth: "16", modelName: "Tesla T4",
	}
}

// dcgmFeed serves the brain's DCGM witness queries over real HTTP. The served scrape can be
// swapped between ticks so a test can model consecutive live observations of the same pod.
type dcgmFeed struct {
	mu     sync.Mutex
	scrape dcgmScrape
	URL    string
}

func newDCGMFeed(t *testing.T, scrape dcgmScrape) *dcgmFeed {
	t.Helper()
	f := &dcgmFeed{scrape: scrape}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	f.URL = server.URL
	return f
}

func (f *dcgmFeed) set(scrape dcgmScrape) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scrape = scrape
}

func (f *dcgmFeed) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	scrape := f.scrape
	f.mu.Unlock()
	query := r.URL.Query().Get("query")
	for _, failing := range scrape.failQueries {
		if strings.Contains(query, failing) {
			http.Error(w, "prometheus unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	labels := map[string]string{"namespace": vramNamespace, "pod": vramPodName}
	value := ""
	switch {
	case strings.Contains(query, "modelName"): // the device-model discovery query
		labels["modelName"], value = scrape.modelName, scrape.modelName
		if scrape.modelName != "" {
			value = "1"
		}
	case strings.Contains(query, "DCGM_FI_DEV_FB_USED"):
		value = scrape.used
	case strings.Contains(query, "DCGM_FI_DEV_FB_FREE"):
		value = scrape.free
	case strings.Contains(query, "DCGM_FI_PROF_SM_ACTIVE"):
		value = scrape.smActive
	case strings.Contains(query, "DCGM_FI_DEV_PCIE_LINK_GEN"):
		value = scrape.linkGen
	case strings.Contains(query, "DCGM_FI_DEV_PCIE_LINK_WIDTH"):
		value = scrape.linkWidth
	case strings.Contains(query, "DCGM_FI_PROF_PCIE_RX_BYTES"):
		value = scrape.pcieBytes
	}
	result := []any{}
	if value != "" {
		result = append(result, map[string]any{"metric": labels, "value": []any{vramSampleTS, value}})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"data":   map[string]any{"resultType": "vector", "result": result},
	})
}

// gpuFleetSnapshot is a live-shaped scan: one GPU node carrying the platform's own labels, the
// GPU pod under test and a second tenant's pod on the same node, so the K8s half (image/model
// rarity, co-residency, slack) is non-trivial and any perturbation of it would show.
func gpuFleetSnapshot(nodeLabels map[string]string) *ingest.Snapshot {
	return &ingest.Snapshot{
		Nodes: []ingest.NodeInfo{{
			Name: "gpu-node-1", AllocatableCPUMilli: 8000, AllocatableMemBytes: 32 << 30,
			AllocatableGPU: 1, MIGResources: map[string]int64{}, Labels: nodeLabels, Schedulable: true,
		}},
		Pods: []model.Pod{
			{
				Namespace: vramNamespace, Name: vramPodName, Node: "gpu-node-1", HasGPU: true,
				ImageID: "vllm/vllm-openai@sha256:aa11", ModelID: "meta-llama/Llama-3-8B",
				Phase: "Running", CPURequestMilli: 2000, MemRequestBytes: 8 << 30,
			},
			{
				Namespace: "batch", Name: "trainer-0", Node: "gpu-node-1",
				ImageID: "batch/trainer@sha256:bb22", Phase: "Running",
				CPURequestMilli: 1000, MemRequestBytes: 4 << 30,
			},
		},
	}
}

// gpuAdapters are the three DCGM-stamping adapters, each selected by its own real node labels.
var gpuAdapters = []struct {
	name   string
	labels map[string]string
}{
	{"eks-gpu", map[string]string{"eks.amazonaws.com/nodegroup": "gpu-ng", "node.kubernetes.io/instance-type": "g4dn.xlarge"}},
	{"coreweave", map[string]string{"node.coreweave.cloud/class": "gpu", "nvidia.com/gpu.product": "Tesla-T4"}},
	{"gpu-marketplace", map[string]string{"node.kubernetes.io/instance-type": "bare-metal"}},
}

// stampedGPUHalf projects exactly the fields stampGPU carries across the seam, so one comparison
// covers VRAM presence/value together with the SM and PCIe-link halves.
func stampedGPUHalf(w model.PhysicsWitness) model.PhysicsWitness {
	return model.PhysicsWitness{
		GPUPresent: w.GPUPresent, VRAMPresent: w.VRAMPresent, VRAMFraction: w.VRAMFraction,
		SMOccupancy: w.SMOccupancy, SMSource: w.SMSource,
		LinkBandwidth: w.LinkBandwidth, LinkSource: w.LinkSource,
		LinkPresent: w.LinkPresent, LinkCapacityBytesPerSec: w.LinkCapacityBytesPerSec,
		LinkCapacitySource: w.LinkCapacitySource, LinkGen: w.LinkGen, LinkWidth: w.LinkWidth,
		LinkReason: w.LinkReason,
	}
}

// withoutGPUHalf blanks every field a GPU adapter may stamp, leaving the platform-INVARIANT K8s
// half. A GPU adapter's witness must equal genericK8s's under this projection: if stampGPU ever
// writes outside the DCGM half, the remaining fields diverge and this catches it.
func withoutGPUHalf(w model.PhysicsWitness) model.PhysicsWitness {
	blank := stampedGPUHalf(model.PhysicsWitness{})
	w.GPUPresent, w.VRAMPresent, w.VRAMFraction = blank.GPUPresent, blank.VRAMPresent, blank.VRAMFraction
	w.SMOccupancy, w.SMSource = blank.SMOccupancy, blank.SMSource
	w.LinkBandwidth, w.LinkSource = blank.LinkBandwidth, blank.LinkSource
	w.LinkPresent, w.LinkCapacityBytesPerSec = blank.LinkPresent, blank.LinkCapacityBytesPerSec
	w.LinkCapacitySource, w.LinkGen, w.LinkWidth, w.LinkReason = blank.LinkCapacitySource, blank.LinkGen, blank.LinkWidth, blank.LinkReason
	return w
}

// TestGPUAdapterPreservesMeasuredVRAMPresence — M-152. Every GPU adapter must hand the decision
// layer the SAME VRAM presence the producer derived from the served samples: an observed zero
// stays present, and a missing series, an unusable denominator, a non-finite sample or a failed
// query stays absent. Presence is never inferred from a non-zero float or from GPU hardware.
func TestGPUAdapterPreservesMeasuredVRAMPresence(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*dcgmScrape)
		wantPresent bool
		wantValue   float64
		wantErr     bool
	}{
		// Positive controls: a real measurement, including the observed zero the honest-absent
		// contract exists for, and a saturated device.
		{"measured-nonzero", nil, true, 14488.0 / (14488.0 + 872.0), false},
		{"measured-zero", func(s *dcgmScrape) { s.used, s.free = "0", "15360" }, true, 0, false},
		{"measured-saturated", func(s *dcgmScrape) { s.used, s.free = "15360", "0" }, true, 1, false},
		// Absence controls: each arm of the producer's "both series answered with a usable
		// denominator" predicate, plus the query-failure and total-outage paths.
		{"missing-free-series", func(s *dcgmScrape) { s.free = "" }, false, 0, false},
		{"missing-used-series", func(s *dcgmScrape) { s.used = "" }, false, 0, false},
		{"no-vram-samples", func(s *dcgmScrape) { s.used, s.free = "", "" }, false, 0, false},
		{"zero-denominator", func(s *dcgmScrape) { s.used, s.free = "0", "0" }, false, 0, false},
		{"nonfinite-used", func(s *dcgmScrape) { s.used = "NaN" }, false, 0, false},
		{"nonfinite-free", func(s *dcgmScrape) { s.free = "+Inf" }, false, 0, false},
		{"vram-query-failure", func(s *dcgmScrape) { s.failQueries = []string{"DCGM_FI_DEV_FB_USED"} }, false, 0, true},
		{"prometheus-outage", func(s *dcgmScrape) { s.failQueries = []string{"DCGM_FI"} }, false, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scrape := liveScrape()
			if tc.mutate != nil {
				tc.mutate(&scrape)
			}
			feed := newDCGMFeed(t, scrape)

			// Producer precondition: the fixture must really drive the producer to the state
			// under test, so a green adapter assertion cannot come from an inert fixture.
			probe := gpuFleetSnapshot(gpuAdapters[0].labels)
			err := ingest.PopulateGPUWitness(context.Background(), probe, feed.URL, nil)
			if tc.wantErr != (err != nil) {
				t.Fatalf("fixture: PopulateGPUWitness error = %v, want error %v", err, tc.wantErr)
			}
			upstream := probe.GPUWitness[vramKey]
			if upstream.VRAMPresent != tc.wantPresent {
				t.Fatalf("fixture: producer presence = %v, want %v (witness %+v)", upstream.VRAMPresent, tc.wantPresent, upstream)
			}
			if math.Abs(upstream.VRAMFraction-tc.wantValue) > 1e-9 {
				t.Fatalf("fixture: producer VRAMFraction = %v, want %v", upstream.VRAMFraction, tc.wantValue)
			}

			for _, adapter := range gpuAdapters {
				t.Run(adapter.name, func(t *testing.T) {
					// A fresh snapshot per adapter, populated by the same live feed: this is a
					// full production tick, not a re-read of the previous witness map.
					snap := gpuFleetSnapshot(adapter.labels)
					if err := ingest.PopulateGPUWitness(context.Background(), snap, feed.URL, nil); tc.wantErr != (err != nil) {
						t.Fatalf("PopulateGPUWitness error = %v, want error %v", err, tc.wantErr)
					}
					selected, witnesses := Derive(snap)
					if selected != adapter.name {
						t.Fatalf("adapter selected = %q, want %q", selected, adapter.name)
					}
					got := witnesses[vramKey]

					if got.VRAMPresent != upstream.VRAMPresent {
						t.Fatalf("VRAM presence lost at the adapter seam: producer=%v adapter=%v value=%v",
							upstream.VRAMPresent, got.VRAMPresent, got.VRAMFraction)
					}
					if got.VRAMFraction != upstream.VRAMFraction {
						t.Fatalf("VRAMFraction changed at the seam: producer=%v adapter=%v", upstream.VRAMFraction, got.VRAMFraction)
					}
					// SM and PCIe-link presence/values are unchanged by this fix; compare the
					// whole stamped half so a regression in either shows here.
					if !reflect.DeepEqual(stampedGPUHalf(got), stampedGPUHalf(upstream)) {
						t.Fatalf("stamped GPU half diverged from the producer:\n producer=%+v\n adapter=%+v",
							stampedGPUHalf(upstream), stampedGPUHalf(got))
					}
					// The platform-invariant K8s half is still genericK8s's, byte for byte.
					generic := genericK8s{}.Derive(snap)[vramKey]
					if !reflect.DeepEqual(withoutGPUHalf(got), withoutGPUHalf(generic)) {
						t.Fatalf("K8s half diverged from generic-k8s:\n generic=%+v\n adapter=%+v", generic, got)
					}
				})
			}
		})
	}
}

// TestGPUAdapterDropsVRAMPresenceWhenALaterScrapeIsAbsent — presence is a property of the CURRENT
// observation. When the exporter stops publishing FB_USED/FB_FREE for a pod, the next tick's
// witness must report VRAM absent rather than inheriting the previous tick's measurement.
func TestGPUAdapterDropsVRAMPresenceWhenALaterScrapeIsAbsent(t *testing.T) {
	feed := newDCGMFeed(t, liveScrape())
	tick := func() model.PhysicsWitness {
		t.Helper()
		snap := gpuFleetSnapshot(gpuAdapters[0].labels)
		if err := ingest.PopulateGPUWitness(context.Background(), snap, feed.URL, nil); err != nil {
			t.Fatalf("PopulateGPUWitness: %v", err)
		}
		selected, witnesses := Derive(snap)
		if selected != "eks-gpu" {
			t.Fatalf("adapter selected = %q, want eks-gpu", selected)
		}
		return witnesses[vramKey]
	}

	measured := tick()
	if !measured.VRAMPresent || measured.VRAMFraction == 0 {
		t.Fatalf("first tick did not observe live VRAM: %+v", measured)
	}

	// The DCGM VRAM series go away (exporter restart / device unbound); SM keeps answering, so
	// the pod still has a GPU witness — only the VRAM measurement is gone.
	gone := liveScrape()
	gone.used, gone.free = "", ""
	feed.set(gone)

	absent := tick()
	if absent.VRAMPresent {
		t.Fatalf("stale VRAM presence carried into a later absent observation: %+v", absent)
	}
	if absent.VRAMFraction != 0 {
		t.Fatalf("stale VRAMFraction carried into a later absent observation: %v", absent.VRAMFraction)
	}
	if !absent.GPUPresent || absent.SMSource != measured.SMSource {
		t.Fatalf("the rest of the GPU half was disturbed: %+v", absent)
	}
}

// TestGenericK8sKeepsVRAMAbsentWithoutGPUNodes — the no-GPU path. genericK8s has no DCGM half at
// all: on a CPU-only cluster the witness stays honest-absent, and it stays absent even when the
// shared snapshot carries a GPU witness produced for a different fleet — presence is never
// inferred from hardware availability or from a value lying in the snapshot.
func TestGenericK8sKeepsVRAMAbsentWithoutGPUNodes(t *testing.T) {
	feed := newDCGMFeed(t, liveScrape())

	// A real measured witness, produced by the live feed on a GPU fleet.
	gpuSnap := gpuFleetSnapshot(gpuAdapters[0].labels)
	if err := ingest.PopulateGPUWitness(context.Background(), gpuSnap, feed.URL, nil); err != nil {
		t.Fatalf("PopulateGPUWitness: %v", err)
	}
	if !gpuSnap.GPUWitness[vramKey].VRAMPresent {
		t.Fatalf("fixture: the feed did not produce a measured witness: %+v", gpuSnap.GPUWitness[vramKey])
	}

	cpuOnly := gpuFleetSnapshot(map[string]string{"kubernetes.io/hostname": "kind-worker"})
	cpuOnly.Nodes[0].AllocatableGPU = 0
	cpuOnly.Pods[0].HasGPU = false
	for _, carriesWitness := range []bool{false, true} {
		cpuOnly.GPUWitness = nil
		if carriesWitness {
			cpuOnly.GPUWitness = gpuSnap.GPUWitness
		}
		selected, witnesses := Derive(cpuOnly)
		if selected != "generic-k8s" {
			t.Fatalf("adapter selected = %q, want generic-k8s", selected)
		}
		got := witnesses[vramKey]
		if got.GPUPresent || got.VRAMPresent || got.VRAMFraction != 0 {
			t.Fatalf("generic-k8s claimed a GPU measurement (snapshot carries witness = %v): %+v", carriesWitness, got)
		}
		if !got.Scanned || !got.ImageRarityPresent || !got.CoResidencyPresent {
			t.Fatalf("the K8s-derived half regressed: %+v", got)
		}
	}
}
