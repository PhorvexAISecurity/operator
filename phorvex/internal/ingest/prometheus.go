/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"math"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// PromHTTP is a real Prometheus instant-query MetricsSource (FR1). It runs one
// PromQL per signal with a {namespace} placeholder, expecting a result vector keyed
// by a "pod" label, and folds the vectors into per-pod Telemetry. It is configured
// (URL + optional query overrides) by the operator; when no URL is set the default
// nilSource is used instead, so an unconfigured cluster yields honest Present=false.
type PromHTTP struct {
	BaseURL string
	Client  *http.Client
	Queries map[string]string // signal -> PromQL with a {namespace} placeholder
}

// Signal keys for the query map.
const (
	SigReqRate      = "reqRate"
	SigP99Ms        = "p99Ms"
	SigQueueDepth   = "queueDepth"
	SigConnCount    = "connCount"
	SigBytesIn      = "bytesIn"
	SigBytesOut     = "bytesOut"
	SigGPUUtil      = "gpuUtil"
	SigSyscallRate  = "syscallRate"
	SigTokensPerSec = "tokensPerSec"
)

// DefaultPromQueries are conventional PromQL templates. They are intentionally
// generic; a site overrides any that don't match its metric names. A query that
// returns nothing simply leaves that signal at zero (honest absence).
func DefaultPromQueries() map[string]string {
	return map[string]string{
		SigReqRate:      `sum by (pod) (rate(http_requests_total{namespace="{namespace}"}[1m]))`,
		SigP99Ms:        `1000 * histogram_quantile(0.99, sum by (pod, le) (rate(http_request_duration_seconds_bucket{namespace="{namespace}"}[5m])))`,
		SigConnCount:    `sum by (pod) (container_network_tcp_usage_total{namespace="{namespace}"})`,
		SigBytesIn:      `sum by (pod) (rate(container_network_receive_bytes_total{namespace="{namespace}"}[1m]))`,
		SigBytesOut:     `sum by (pod) (rate(container_network_transmit_bytes_total{namespace="{namespace}"}[1m]))`,
		SigGPUUtil:      `avg by (pod) (DCGM_FI_DEV_GPU_UTIL{namespace="{namespace}"}) / 100`,
		SigTokensPerSec: `sum by (pod) (rate(nim_tokens_total{namespace="{namespace}"}[1m]))`,
	}
}

// Signal keys for the GPU PhysicsWitness half (DCGM-via-Prometheus). A GPU platform adapter
// (eksGPU/coreWeave) wires these in a Derive() override to STAMP the witness GPU floats.
const (
	SigVRAMUsedMiB = "vramUsedMiB"
	SigVRAMFreeMiB = "vramFreeMiB"
	SigSMActive    = "smActive"    // PROF_SM_ACTIVE — TRUE occupancy (needs DCP profiling)
	SigSMUtilFb    = "smUtilFb"    // GPU_UTIL fallback — DUTY-CYCLE, must be source-labeled, NOT occupancy
	SigNVLinkBytes = "nvlinkBytes"
)

// DCGMWitnessQueries are the DESIGNED DCGM-via-Prometheus templates for the GPU witness half.
// VALUES are [SP-0-PENDING-P4] — these are query STRINGS only; NO DCGM value is hardcoded into
// any witness float, and no adapter wires them until a real GPU run at P4. Scraped through
// Prometheus (read-only HTTP), so the GPU half adds ZERO additional Kubernetes RBAC verb.
//
// HONESTY (red-team, load-bearing): SMOccupancy must prefer PROF_SM_ACTIVE (true occupancy);
// the GPU_UTIL duty-cycle is only a labeled FALLBACK — conflating them would overstate the AI
// kill-chain model-theft leakage gate. A wiring adapter MUST record which source fed SMOccupancy.
func DCGMWitnessQueries() map[string]string {
	return map[string]string{
		// VRAMFraction = used / (used + free).
		SigVRAMUsedMiB: `sum by (pod) (DCGM_FI_DEV_FB_USED{namespace="{namespace}"})`,
		SigVRAMFreeMiB: `sum by (pod) (DCGM_FI_DEV_FB_FREE{namespace="{namespace}"})`,
		// SMOccupancy: prefer the profiling signal; fall back to duty-cycle ONLY if absent.
		SigSMActive: `avg by (pod) (DCGM_FI_PROF_SM_ACTIVE{namespace="{namespace}"})`,
		SigSMUtilFb: `avg by (pod) (DCGM_FI_DEV_GPU_UTIL{namespace="{namespace}"}) / 100`,
		// LinkBandwidth = NVLink TX+RX byte-rate (interconnect saturation).
		SigNVLinkBytes: `sum by (pod) (rate(DCGM_FI_PROF_NVLINK_TX_BYTES{namespace="{namespace}"}[1m]) + rate(DCGM_FI_PROF_NVLINK_RX_BYTES{namespace="{namespace}"}[1m]))`,
	}
}

// NewPromHTTP builds a PromHTTP with sensible defaults.
func NewPromHTTP(baseURL string, queries map[string]string) *PromHTTP {
	if queries == nil {
		queries = DefaultPromQueries()
	}
	return &PromHTTP{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client:  &http.Client{Timeout: 5 * time.Second},
		Queries: queries,
	}
}

// Name implements MetricsSource.
func (*PromHTTP) Name() string { return "prometheus-http" }

// PodMetrics implements MetricsSource.
func (p *PromHTTP) PodMetrics(ctx context.Context, namespace string, _ []string) (map[string]model.Telemetry, error) {
	out := map[string]model.Telemetry{}
	for sig, tmpl := range p.Queries {
		q := strings.ReplaceAll(tmpl, "{namespace}", namespace)
		vec, err := p.instantQuery(ctx, q)
		if err != nil {
			// Best-effort: skip this signal, keep going (do not fail the whole tick).
			continue
		}
		for pod, val := range vec {
			t := out[pod]
			t.Present = true
			assignSignal(&t, sig, val)
			out[pod] = t
		}
	}
	return out, nil
}

func assignSignal(t *model.Telemetry, sig string, v float64) {
	switch sig {
	case SigReqRate:
		t.ReqRate = v
	case SigP99Ms:
		t.P99Ms = v
		t.LatencyMs = v
	case SigQueueDepth:
		t.QueueDepth = v
	case SigConnCount:
		t.ConnCount = v
	case SigBytesIn:
		t.BytesIn = v
	case SigBytesOut:
		t.BytesOut = v
	case SigGPUUtil:
		t.GPUUtil = v
	case SigSyscallRate:
		t.SyscallRate = v
	case SigTokensPerSec:
		t.TokensPerSec = v
	}
}

// promResponse models the Prometheus query API instant-vector response.
type promResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]interface{}    `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

func (p *PromHTTP) instantQuery(ctx context.Context, query string) (map[string]float64, error) {
	u := fmt.Sprintf("%s/api/v1/query?query=%s", p.BaseURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus query status %d", resp.StatusCode)
	}
	var pr promResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}
	if pr.Status != "success" {
		return nil, fmt.Errorf("prometheus query status %q", pr.Status)
	}
	out := map[string]float64{}
	for _, r := range pr.Data.Result {
		pod := r.Metric["pod"]
		if pod == "" {
			continue
		}
		s, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		f, err := strconv.ParseFloat(s, 64)
		// Prometheus legitimately serves "NaN" (e.g. 0/0, a stale/absent series) and Go's
		// ParseFloat accepts it WITHOUT error. Admitting it would make every downstream cost NaN,
		// so an unusable sample is DROPPED (honest-absent) rather than ingested.
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			continue
		}
		out[pod] = f
	}
	return out, nil
}

// instantQueryNsPod runs query and keys results by "namespace/pod" (DCGM series carry both
// labels). Series missing either label are skipped.
func (p *PromHTTP) instantQueryNsPod(ctx context.Context, query string) (map[string]float64, error) {
	u := fmt.Sprintf("%s/api/v1/query?query=%s", p.BaseURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus query status %d", resp.StatusCode)
	}
	var pr promResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}
	if pr.Status != "success" {
		return nil, fmt.Errorf("prometheus query status %q", pr.Status)
	}
	out := map[string]float64{}
	for _, r := range pr.Data.Result {
		ns, pod := r.Metric["namespace"], r.Metric["pod"]
		if ns == "" || pod == "" {
			continue
		}
		s, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			out[ns+"/"+pod] = f
		}
	}
	return out, nil
}

// clusterWide strips the per-namespace selector so a DCGM witness query matches every GPU pod
// cluster-wide (the physics scan is not tenant-scoped), and widens the aggregation to keep the
// namespace label (the default `by (pod)` would drop it, so the ns/pod key could not be built).
func clusterWide(q string) string {
	q = strings.ReplaceAll(q, `{namespace="{namespace}"}`, "")
	q = strings.ReplaceAll(q, "{namespace}", "")
	q = strings.ReplaceAll(q, "by (pod)", "by (namespace, pod)")
	return q
}

const nvlinkCeilingBytesPerSec = 25e9 // ~25 GB/s order-of-magnitude per-link ceiling for [0,1] normalization

func clampUnit(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// PopulateGPUWitness fills snap.GPUWitness from a live dcgm-exporter feed via Prometheus
// (read-only HTTP; zero extra K8s RBAC). For each pod DCGM reports a GPU for, it stamps
// GPUPresent + VRAMFraction (FB_USED/(USED+FREE)) + SMOccupancy (PROF_SM_ACTIVE true occupancy,
// falling back to the GPU_UTIL duty-cycle) + LinkBandwidth (NVLink rate, normalized). An empty
// promURL or no DCGM data leaves GPUWitness empty => the GPU half stays honest-absent
// ([SP-0-PENDING]); no GPU float is ever fabricated.
func PopulateGPUWitness(ctx context.Context, snap *Snapshot, promURL string) {
	if snap == nil || promURL == "" {
		return
	}
	p := NewPromHTTP(promURL, nil)
	q := DCGMWitnessQueries()
	used, _ := p.instantQueryNsPod(ctx, clusterWide(q[SigVRAMUsedMiB]))
	free, _ := p.instantQueryNsPod(ctx, clusterWide(q[SigVRAMFreeMiB]))
	smActive, _ := p.instantQueryNsPod(ctx, clusterWide(q[SigSMActive]))
	smUtil, _ := p.instantQueryNsPod(ctx, clusterWide(q[SigSMUtilFb]))
	nvlink, _ := p.instantQueryNsPod(ctx, clusterWide(q[SigNVLinkBytes]))

	keys := map[string]struct{}{}
	for _, m := range []map[string]float64{used, free, smActive, smUtil} {
		for k := range m {
			keys[k] = struct{}{}
		}
	}
	if len(keys) == 0 {
		return
	}
	wit := make(map[string]model.PhysicsWitness, len(keys))
	for k := range keys {
		w := model.PhysicsWitness{GPUPresent: true, ModelRarity: 1}
		if u, f := used[k], free[k]; u+f > 0 {
			w.VRAMFraction = clampUnit(u / (u + f))
		}
		if v, ok := smActive[k]; ok {
			w.SMOccupancy = clampUnit(v) // PROF_SM_ACTIVE is a [0,1] occupancy fraction
		} else {
			w.SMOccupancy = clampUnit(smUtil[k]) // duty-cycle fallback (query already /100)
		}
		if b, ok := nvlink[k]; ok && b > 0 {
			w.LinkBandwidth = clampUnit(b / nvlinkCeilingBytesPerSec)
		}
		wit[k] = w
	}
	snap.GPUWitness = wit
}
