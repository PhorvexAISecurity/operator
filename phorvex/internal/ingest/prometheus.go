/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// PromHTTP is a real Prometheus instant-query MetricsSource (FR1). It runs one
// PromQL per signal with a {namespace} placeholder, expecting a result vector keyed
// by a "pod" label, and folds the vectors into per-pod Telemetry. It is configured
// (URL + optional query overrides) by the operator; when no URL is set the default
// absentSource is used instead, so an unconfigured cluster yields honest Present=false.
type PromHTTP struct {
	BaseURL string
	Client  *http.Client
	Queries map[string]string // signal -> PromQL with a {namespace} placeholder
	// ScrapeInterval sizes the staleness bound maxAge = 3x interval (0 => 30s default).
	ScrapeInterval time.Duration

	mu       sync.Mutex
	lastGood map[string]map[string]lastSample // "ns\x00pod" -> signal -> last usable sample
	lastAgg  map[string]aggSample             // "ns\x00pod" -> last cAdvisor aggregate (for deltas)
}

// lastSample is a per-signal last-good reading, reused as Stale within maxAge.
type lastSample struct {
	value float64
	at    time.Time
}

// aggSample is the previous cAdvisor aggregate, used to derive the raw rate deltas
// (T1-M142 input; logged into the record only, no consumer reads them in T1-C).
type aggSample struct {
	conn  float64
	bytes float64
	at    time.Time
}

func (p *PromHTTP) maxAge() time.Duration {
	iv := p.ScrapeInterval
	if iv <= 0 {
		iv = 30 * time.Second
	}
	return 3 * iv
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
	// M-115 flow inputs — one 5m window, one boundary (the vLLM engine), one population
	// (completed requests). Only the vLLM exporter publishes all three today; every other
	// class reads Absent, which the flow residual reports as mean-sojourn-unavailable.
	SigInFlightMean   = "inFlightMean"
	SigCompletionRate = "completionRate"
	SigMeanSojournSec = "meanSojournSec"
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
		// M-115: time-average number in system, completion rate and mean sojourn over the SAME
		// 5m window and boundary. L is avg_over_time of an instantaneous gauge (a time mean,
		// sampled at the scrape interval); λ is the completion rate of the population whose
		// mean latency W is; W = Σ latency / count of completed requests (arithmetic mean, s).
		SigInFlightMean:   `avg by (pod) (avg_over_time(vllm:num_requests_running{namespace="{namespace}"}[5m]))`,
		SigCompletionRate: `sum by (pod) (rate(vllm:e2e_request_latency_seconds_count{namespace="{namespace}"}[5m]))`,
		SigMeanSojournSec: `sum by (pod) (increase(vllm:e2e_request_latency_seconds_sum{namespace="{namespace}"}[5m])) / sum by (pod) (increase(vllm:e2e_request_latency_seconds_count{namespace="{namespace}"}[5m]))`,

		// QueueDepth feeds the queue term of the physics residual (littleslaw.go:51 —
		// "queue depth large relative to arrival rate means items pile up"). It had NO
		// entry here at all, so t.QueueDepth was always 0 and that entire term of
		// Residual() was dead code in every deployment.
		//
		// The `or` chain keeps a vendor-neutral name FIRST so a site exporting its own
		// gauge wins outright, then falls back to the serving stacks. PromQL `or` yields
		// the left side wherever it has samples and the right side only for series the
		// left does not cover, so a fallback can never overwrite a real generic reading.
		//
		// SigSyscallRate is deliberately absent: nothing in the codebase reads
		// Telemetry.SyscallRate, so giving it a query would cost a scrape per tick per
		// namespace and change no decision.
		SigQueueDepth: `sum by (pod) (workload_queue_depth{namespace="{namespace}"})` +
			` or sum by (pod) (vllm:num_requests_waiting{namespace="{namespace}"})` +
			` or sum by (pod) (nv_inference_pending_request_count{namespace="{namespace}"})`,
	}
}

// Signal keys for the GPU PhysicsWitness half (DCGM-via-Prometheus). A GPU platform adapter
// (eksGPU/coreWeave) wires these in a Derive() override to STAMP the witness GPU floats.
const (
	SigVRAMUsedMiB = "vramUsedMiB"
	SigVRAMFreeMiB = "vramFreeMiB"
	SigSMActive    = "smActive" // PROF_SM_ACTIVE — TRUE occupancy (needs DCP profiling)
	SigPCIeBytes   = "pcieBytes"
)

// DCGMWitnessQueries are the live DCGM-via-Prometheus templates for the GPU witness half.
// They were validated against dcgm-exporter on an EKS Tesla T4 node. Scraping stays read-only
// HTTP, so the GPU half adds zero Kubernetes RBAC verbs. Missing series remain honest-absent.
//
// HONESTY (red-team, load-bearing): only PROF_SM_ACTIVE may feed SMOccupancy. GPU_UTIL is
// device duty-cycle, not occupancy; substituting it would overstate the AI kill-chain
// model-theft leakage gate. On T4 stacks without DCP profiling, SMOccupancy stays
// honest-absent (zero with an empty source) while Telemetry.GPUUtil remains independently live.
func DCGMWitnessQueries() map[string]string {
	return map[string]string{
		// VRAMFraction = used / (used + free).
		SigVRAMUsedMiB: `sum by (pod) (DCGM_FI_DEV_FB_USED{namespace="{namespace}"})`,
		SigVRAMFreeMiB: `sum by (pod) (DCGM_FI_DEV_FB_FREE{namespace="{namespace}"})`,
		// SMOccupancy: only the profiling signal has the required physical meaning.
		SigSMActive: `avg by (pod) (DCGM_FI_PROF_SM_ACTIVE{namespace="{namespace}"})`,
		// LinkBandwidth = PCIe RX+TX byte-rate. Tesla T4 is PCIe-attached and its live
		// exporter does not expose the NVLink counters assumed by the old template.
		SigPCIeBytes: `sum by (pod) (rate(DCGM_FI_PROF_PCIE_RX_BYTES{namespace="{namespace}"}[1m]) + rate(DCGM_FI_PROF_PCIE_TX_BYTES{namespace="{namespace}"}[1m]))`,
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

// PodMetrics implements MetricsSource. Each signal query yields a typed Signal per pod:
// a fresh finite reading is Present; a non-finite sample is Error; a signal whose whole
// query failed reuses its last-good within maxAge as Stale (else Absent). Absence is never
// a measured zero (P-SENSING). It returns best-effort telemetry AND a joined error naming
// every failed signal query, so the caller can raise TelemetryDegraded (M-113/M-130) rather
// than dropping the tick.
func (p *PromHTTP) PodMetrics(ctx context.Context, namespace string, _ []string) (map[string]model.Telemetry, error) {
	now := time.Now()
	finite := map[string]map[string]float64{}     // signal -> pod -> value
	nonfinite := map[string]map[string]struct{}{} // signal -> pod set (saw pod, bad value)
	failed := map[string]bool{}                   // signal -> query errored
	var queryErrs []error
	for sig, tmpl := range p.Queries {
		q := strings.ReplaceAll(tmpl, "{namespace}", namespace)
		vec, bad, err := p.instantQuery(ctx, q)
		if err != nil {
			failed[sig] = true
			queryErrs = append(queryErrs, fmt.Errorf("%s: %w", sig, err))
			continue
		}
		finite[sig] = vec
		nonfinite[sig] = bad
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastGood == nil {
		p.lastGood = map[string]map[string]lastSample{}
	}
	maxAge := p.maxAge()

	// Pod universe = every pod any successful query returned (finite or non-finite) PLUS every
	// pod we still hold recent last-good for in this namespace. The last set matters when a
	// pod's only signal query FAILED this tick: it must still appear with State=Error, not
	// vanish (M-113: Error is distinguishable from scraped-empty). B.4.
	prefix := namespace + "\x00"
	pods := map[string]struct{}{}
	for _, vec := range finite {
		for pod := range vec {
			pods[pod] = struct{}{}
		}
	}
	for _, bad := range nonfinite {
		for pod := range bad {
			pods[pod] = struct{}{}
		}
	}
	for key := range p.lastGood {
		if strings.HasPrefix(key, prefix) {
			pods[strings.TrimPrefix(key, prefix)] = struct{}{}
		}
	}

	out := make(map[string]model.Telemetry, len(pods))
	for pod := range pods {
		key := namespace + "\x00" + pod
		var t model.Telemetry
		for sig := range p.Queries {
			var s model.Signal
			switch {
			case hasVal(finite[sig], pod):
				v := finite[sig][pod]
				s = model.Signal{Value: v, State: model.Present, Src: p.Name()}
				if p.lastGood[key] == nil {
					p.lastGood[key] = map[string]lastSample{}
				}
				p.lastGood[key][sig] = lastSample{value: v, at: now}
			case hasKey(nonfinite[sig], pod):
				s = model.Signal{State: model.Error, Src: p.Name()} // saw the pod, non-finite value
			case failed[sig]:
				// The job for this signal errored: State=Error (source is broken, M-113/M-130),
				// distinguishable from a scraped-empty absent. Not Stale — Stale is for a healthy
				// source whose series merely flickered (below).
				s = model.Signal{State: model.Error, Src: p.Name()}
			default:
				// Query succeeded but this pod had no series this tick. Reuse a fresh-enough
				// last-good as Stale (value retained for the record, not usable); else Absent.
				if lg, ok := p.lastGood[key][sig]; ok && now.Sub(lg.at) <= maxAge {
					s = model.Signal{Value: lg.value, State: model.Stale, Age: now.Sub(lg.at), Src: p.Name()}
				}
			}
			assignSignal(&t, sig, s)
		}
		p.computeDeltas(&t, key, now)
		out[pod] = t
	}
	p.pruneCache(now, maxAge)
	return out, errors.Join(queryErrs...)
}

// pruneCache evicts last-good/aggregate entries older than maxAge across all namespaces, so a
// pod that churns out stops consuming memory once its history ages past the staleness bound.
func (p *PromHTTP) pruneCache(now time.Time, maxAge time.Duration) {
	for key, sigs := range p.lastGood {
		newest := time.Time{}
		for sig, lg := range sigs {
			if now.Sub(lg.at) > maxAge {
				delete(sigs, sig)
				continue
			}
			if lg.at.After(newest) {
				newest = lg.at
			}
		}
		if len(sigs) == 0 {
			delete(p.lastGood, key)
		}
	}
	for key, agg := range p.lastAgg {
		if now.Sub(agg.at) > maxAge {
			delete(p.lastAgg, key)
		}
	}
}

func hasVal(m map[string]float64, pod string) bool  { _, ok := m[pod]; return ok }
func hasKey(m map[string]struct{}, pod string) bool { _, ok := m[pod]; return ok }

// computeDeltas derives the raw cAdvisor rate deltas from the previous tick's aggregate.
// Logged into the record only (T1-M142 owns whether/how they enter the phase boundary).
// CAVEAT for T1-M142 (K3 P3 F2): when a signal is unusable this tick its aggregate contributes
// 0, so the first delta after a gap can read inflated. T1-M142 must gate on signal usability
// (or skip deltas across a non-Present span) before trusting them as a load estimate.
func (p *PromHTTP) computeDeltas(t *model.Telemetry, key string, now time.Time) {
	conn, connOK := 0.0, t.ConnCount.Usable()
	if connOK {
		conn = t.ConnCount.Value
	}
	bytes, bytesOK := 0.0, false
	if t.BytesIn.Usable() {
		bytes += t.BytesIn.Value
		bytesOK = true
	}
	if t.BytesOut.Usable() {
		bytes += t.BytesOut.Value
		bytesOK = true
	}
	if p.lastAgg == nil {
		p.lastAgg = map[string]aggSample{}
	}
	if prev, ok := p.lastAgg[key]; ok {
		if dt := now.Sub(prev.at).Seconds(); dt > 0 {
			if connOK {
				t.ConnDeltaPerSec = (conn - prev.conn) / dt
			}
			if bytesOK {
				t.BytesDeltaPerSec = (bytes - prev.bytes) / dt
			}
		}
	}
	p.lastAgg[key] = aggSample{conn: conn, bytes: bytes, at: now}
}

// assignSignal stores a typed Signal onto the matching Telemetry field.
func assignSignal(t *model.Telemetry, sig string, s model.Signal) {
	switch sig {
	case SigReqRate:
		t.ReqRate = s
	case SigP99Ms:
		t.P99Ms = s
		t.LatencyMs = s
	case SigQueueDepth:
		t.QueueDepth = s
	case SigConnCount:
		t.ConnCount = s
	case SigBytesIn:
		t.BytesIn = s
	case SigBytesOut:
		t.BytesOut = s
	case SigGPUUtil:
		t.GPUUtil = s
	case SigSyscallRate:
		t.SyscallRate = s
	case SigTokensPerSec:
		t.TokensPerSec = s
	case SigInFlightMean:
		t.InFlightMean = s
	case SigCompletionRate:
		t.CompletionRate = s
	case SigMeanSojournSec:
		t.MeanSojournSec = s
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

func (p *PromHTTP) instantQuery(ctx context.Context, query string) (map[string]float64, map[string]struct{}, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		out, bad, err := p.instantQueryOnce(ctx, query)
		if err == nil {
			return out, bad, nil
		}
		lastErr = err
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return nil, nil, lastErr
}

func (p *PromHTTP) instantQueryOnce(ctx context.Context, query string) (map[string]float64, map[string]struct{}, error) {
	u := fmt.Sprintf("%s/api/v1/query?query=%s", p.BaseURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("prometheus query status %d", resp.StatusCode)
	}
	var pr promResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, nil, err
	}
	if pr.Status != "success" {
		return nil, nil, fmt.Errorf("prometheus query status %q", pr.Status)
	}
	out := map[string]float64{}
	bad := map[string]struct{}{}
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
		// Prometheus legitimately serves "NaN" (0/0, a stale/absent series); Go parses it
		// without error. A non-finite sample is now typed State==Error (the pod is recorded
		// as seen-with-bad-value) instead of silently dropped — never a measured zero (M-111).
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			bad[pod] = struct{}{}
			continue
		}
		out[pod] = f
	}
	return out, bad, nil
}

// instantQueryNsPod runs query and keys results by "namespace/pod" (DCGM series carry both
// labels). Series missing either label are skipped.
func (p *PromHTTP) instantQueryNsPod(ctx context.Context, query string) (map[string]float64, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		out, err := p.instantQueryNsPodOnce(ctx, query)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return nil, lastErr
}

func (p *PromHTTP) instantQueryNsPodOnce(ctx context.Context, query string) (map[string]float64, error) {
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

// A Tesla T4 is PCIe Gen3 x16: 15.754 GB/s per direction. The query sums RX and TX,
// hence the 31.508 GB/s aggregate ceiling used to normalize the measured byte-rate.
const pcieT4AggregateCeilingBytesPerSec = 2 * 15.754e9

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
// GPUPresent + VRAMFraction (FB_USED/(USED+FREE)) + SMOccupancy (PROF_SM_ACTIVE true occupancy)
// + LinkBandwidth (PCIe RX+TX rate, normalized to the measured T4 hardware class). On T4
// exporters without PROF_SM_ACTIVE, SM occupancy stays honest-absent rather than borrowing
// GPU_UTIL duty-cycle. An empty promURL or no DCGM data leaves GPUWitness empty; no GPU float
// is ever fabricated.
func PopulateGPUWitness(ctx context.Context, snap *Snapshot, promURL string) error {
	if snap == nil || promURL == "" {
		return nil
	}
	p := NewPromHTTP(promURL, nil)
	q := DCGMWitnessQueries()
	used, usedErr := p.instantQueryNsPod(ctx, clusterWide(q[SigVRAMUsedMiB]))
	free, freeErr := p.instantQueryNsPod(ctx, clusterWide(q[SigVRAMFreeMiB]))
	smActive, smActiveErr := p.instantQueryNsPod(ctx, clusterWide(q[SigSMActive]))
	pcie, pcieErr := p.instantQueryNsPod(ctx, clusterWide(q[SigPCIeBytes]))
	var queryErrs []error
	for _, item := range []struct {
		signal string
		err    error
	}{
		{SigVRAMUsedMiB, usedErr}, {SigVRAMFreeMiB, freeErr}, {SigSMActive, smActiveErr},
		{SigPCIeBytes, pcieErr},
	} {
		if item.err != nil {
			queryErrs = append(queryErrs, fmt.Errorf("%s: %w", item.signal, item.err))
		}
	}

	keys := map[string]struct{}{}
	for _, m := range []map[string]float64{used, free, smActive, pcie} {
		for k := range m {
			keys[k] = struct{}{}
		}
	}
	if len(keys) == 0 {
		return errors.Join(queryErrs...)
	}
	wit := make(map[string]model.PhysicsWitness, len(keys))
	for k := range keys {
		w := model.PhysicsWitness{GPUPresent: true, ModelRarity: 1}
		u, usedOK := used[k]
		f, freeOK := free[k]
		if usedOK && freeOK && u+f > 0 {
			w.VRAMPresent = true
			w.VRAMFraction = clampUnit(u / (u + f))
		}
		if v, ok := smActive[k]; ok {
			w.SMOccupancy = clampUnit(v) // PROF_SM_ACTIVE is a [0,1] occupancy fraction
			w.SMSource = "DCGM_FI_PROF_SM_ACTIVE"
		}
		if b, ok := pcie[k]; ok {
			w.LinkBandwidth = clampUnit(b / pcieT4AggregateCeilingBytesPerSec)
			w.LinkSource = "DCGM_FI_PROF_PCIE_RX_BYTES+DCGM_FI_PROF_PCIE_TX_BYTES"
		}
		wit[k] = w
	}
	snap.GPUWitness = wit
	return errors.Join(queryErrs...)
}
