/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
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
		if err != nil {
			continue
		}
		out[pod] = f
	}
	return out, nil
}
