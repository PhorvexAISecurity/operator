package ingest

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// pcie_test.go — PHORVEXSEC-197 / M-114: the LinkBandwidth denominator is discovered.

const oldT4Ceiling = 2 * 15.754e9 // the constant the old code applied to every device

// The spec table reproduces the T4 figure: an all-T4 fleet reads byte-identically (predicted
// delta zero).
func TestPCIeSpecTableReproducesT4Ceiling(t *testing.T) {
	c, ok := PCIeCapacityBytesPerSec(PCIeLink{Gen: 3, Width: 16})
	if !ok || math.Abs(c-oldT4Ceiling)/oldT4Ceiling > 1e-4 {
		t.Fatalf("Gen3 x16 aggregate = %.6e, old T4 constant %.6e", c, oldT4Ceiling)
	}
	if _, ok := PCIeCapacityBytesPerSec(PCIeLink{Gen: 9, Width: 16}); ok {
		t.Fatal("unknown generation must not yield a capacity")
	}
	if _, ok := PCIeCapacityBytesPerSec(PCIeLink{Gen: 3, Width: 0}); ok {
		t.Fatal("zero width must not yield a capacity")
	}
}

// Gen4 x16 reads HALF the old value for equal bytes (fails on old code: 0.635 vs 0.317).
func TestPCIeGen4ReadsHalfOfT4ForEqualBytes(t *testing.T) {
	cap4, link, src, reason := PCIeCapacity(PCIeLink{Gen: 4, Width: 16}, "", DefaultPCIeClassTable())
	if src != PCIeSourceLink || reason != "" || link.Gen != 4 {
		t.Fatalf("negotiated Gen4 x16 → %v %q %q", link, src, reason)
	}
	b := 20e9
	gen3 := b / mustCap(PCIeLink{Gen: 3, Width: 16}) // the spec-table Gen3 x16 reading (= old T4 constant to 1e-4)
	if got := b / cap4; math.Abs(got-gen3/2) > 1e-9 {
		t.Fatalf("Gen4 x16 utilisation = %.6f, want exactly half the Gen3 x16 reading %.6f (old code gave %.4f for every device)", got, gen3, clampUnit(b/oldT4Ceiling))
	}
}

// Discovery order: negotiated link beats the class table; class table when no link telemetry;
// absent with a reason when neither exists.
func TestPCIeCapacityDiscoveryOrder(t *testing.T) {
	classes := PCIeClassTable{"Tesla T4": {Gen: 3, Width: 16}, "NVIDIA A100": {Gen: 4, Width: 16}}
	// a Gen4 card negotiated at Gen3 (Gen3 slot): the negotiated link wins over the class entry.
	if c, l, src, _ := PCIeCapacity(PCIeLink{Gen: 3, Width: 16}, "NVIDIA A100", classes); src != PCIeSourceLink || l.Gen != 3 || c != mustCap(PCIeLink{3, 16}) {
		t.Fatalf("negotiated link must win: %v %q", l, src)
	}
	if c, l, src, _ := PCIeCapacity(PCIeLink{}, "Tesla T4", classes); src != PCIeSourceClass || l.Gen != 3 || c != mustCap(PCIeLink{3, 16}) {
		t.Fatalf("class fallback: %v %q", l, src)
	}
	if c, _, src, reason := PCIeCapacity(PCIeLink{}, "Unknown GPU", classes); c != 0 || src != PCIeSourceAbsent || !strings.Contains(reason, "no class entry for Unknown GPU") {
		t.Fatalf("unknown model must be absent with a reason: %v %q %q", c, src, reason)
	}
	if c, _, src, reason := PCIeCapacity(PCIeLink{}, "", classes); c != 0 || src != PCIeSourceAbsent || !strings.Contains(reason, "no device model label") {
		t.Fatalf("no label must be absent with a reason: %v %q %q", c, src, reason)
	}
}

func mustCap(l PCIeLink) float64 { c, _ := PCIeCapacityBytesPerSec(l); return c }

// The chart table parses, merges over the default, and rejects an unsupported link.
func TestPCIeClassTableParse(t *testing.T) {
	tbl, err := ParsePCIeClassTable(`{"NVIDIA A100":{"gen":4,"width":16}}`)
	if err != nil || tbl["Tesla T4"].Gen != 3 || tbl["NVIDIA A100"].Gen != 4 {
		t.Fatalf("parse/merge: %v %+v", err, tbl)
	}
	if _, err := ParsePCIeClassTable(`{"X":{"gen":7,"width":16}}`); err == nil {
		t.Fatal("unsupported generation must be rejected")
	}
	if tbl, err := ParsePCIeClassTable("  "); err != nil || len(tbl) != 1 {
		t.Fatalf("empty must yield the shipped default: %v %+v", err, tbl)
	}
}

// End to end through PopulateGPUWitness with a fake exporter: the modelName label selects the
// class capacity; an unknown model yields an absent link signal with the reason recorded.
func TestPopulateGPUWitnessDiscoversPCIeCapacity(t *testing.T) {
	halfT4 := strconv.FormatFloat(mustCap(PCIeLink{Gen: 3, Width: 16})/2, 'f', 0, 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "PCIE_LINK_GEN") || strings.Contains(q, "PCIE_LINK_WIDTH"):
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`)) // exporter has no link fields
		case strings.Contains(q, "modelName"):
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` +
				`{"metric":{"namespace":"vllm","pod":"t4-pod","modelName":"Tesla T4"},"value":[0,"1"]},` +
				`{"metric":{"namespace":"vllm","pod":"odd-pod","modelName":"Mystery GPU"},"value":[0,"1"]}]}}`))
		case strings.Contains(q, "PCIE_RX_BYTES"):
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` +
				`{"metric":{"namespace":"vllm","pod":"t4-pod"},"value":[0,"` + halfT4 + `"]},` +
				`{"metric":{"namespace":"vllm","pod":"odd-pod"},"value":[0,"` + halfT4 + `"]}]}}`))
		default:
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
		}
	}))
	defer srv.Close()
	snap := &Snapshot{}
	if err := PopulateGPUWitness(context.Background(), snap, srv.URL, nil); err != nil {
		t.Logf("non-fatal query errors: %v", err)
	}
	t4 := snap.GPUWitness["vllm/t4-pod"]
	if !t4.LinkPresent || t4.LinkCapacitySource != PCIeSourceClass || t4.LinkGen != 3 || t4.LinkWidth != 16 || math.Abs(t4.LinkBandwidth-0.5) > 1e-6 {
		t.Fatalf("T4 witness = %+v, want class-config Gen3 x16 at 0.5", t4)
	}
	odd := snap.GPUWitness["vllm/odd-pod"]
	if odd.LinkPresent || odd.LinkBandwidth != 0 || odd.LinkCapacitySource != PCIeSourceAbsent || odd.LinkReason == "" {
		t.Fatalf("unknown device must be absent, never the T4 number: %+v", odd)
	}
}
