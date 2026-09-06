package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// scrape_reasons_test.go — PHORVEXSEC-200 / M-113: two non-measurements, two reasons; a
// whole-source outage is a separate verdict; a good query in the same tick is unaffected.

const vec1 = `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pod":"api-0"},"value":[0,"3"]}]}}`
const vecEmpty = `{"status":"success","data":{"resultType":"vector","result":[]}}`

// reasonProm: reqRate query FAILS (500); gpuUtil query SUCCEEDS with no series; connCount succeeds.
func reasonProm(t *testing.T, failAll bool) *PromHTTP {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if failAll || strings.Contains(q, "http_requests_total") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q, "tcp") {
			w.Write([]byte(vec1))
			return
		}
		w.Write([]byte(vecEmpty))
	}))
	t.Cleanup(srv.Close)
	return NewPromHTTP(srv.URL, map[string]string{
		SigReqRate:   `sum by (pod) (rate(http_requests_total{namespace="{namespace}"}[1m]))`,
		SigGPUUtil:   `avg by (pod) (DCGM_FI_DEV_GPU_UTIL{namespace="{namespace}"}) / 100`,
		SigConnCount: `sum by (pod) (container_network_tcp_usage_total{namespace="{namespace}"})`,
	})
}

// (a) failed query → Error/query-failed, never a value; (b) ok-but-empty → Absent/no-series;
// (e) the good query in the same tick is Present with no reason (positive control).
func TestScrapeReasonsDistinguishFailedFromNoSeries(t *testing.T) {
	p := reasonProm(t, false)
	tele, err := p.PodMetrics(context.Background(), "prod", []string{"api-0"})
	if err == nil {
		t.Fatal("a failed signal query must surface in the joined error")
	}
	tl := tele["api-0"]
	if tl.ReqRate.State != model.Error || tl.ReqRate.Reason != model.ReasonQueryFailed || tl.ReqRate.Usable() {
		t.Fatalf("failed query → %+v, want Error/query-failed (old code: Error with no reason)", tl.ReqRate)
	}
	if tl.GPUUtil.State != model.Absent || tl.GPUUtil.Reason != model.ReasonNoSeries || tl.GPUUtil.Usable() {
		t.Fatalf("query ok, no series → %+v, want Absent/no-series", tl.GPUUtil)
	}
	if !tl.ConnCount.Usable() || tl.ConnCount.Value != 3 || tl.ConnCount.Reason != "" {
		t.Fatalf("good query in the same tick must be Present without a reason: %+v", tl.ConnCount)
	}
	h := p.LastHealth()
	if h.Unreachable() || h.Total != 3 || h.Failed != 1 || h.Reason != "" {
		t.Fatalf("partial failure is not a source outage: %+v", h)
	}
}

// (c) every query fails → source verdict unreachable, each signal Error/query-failed.
func TestScrapeAllQueriesFailedIsSourceUnreachable(t *testing.T) {
	p := reasonProm(t, true)
	_, err := p.PodMetrics(context.Background(), "prod", []string{"api-0"})
	if err == nil {
		t.Fatal("expected a joined error")
	}
	h := p.LastHealth()
	if !h.Unreachable() || h.Reason != model.ReasonSourceUnreachable || h.Failed != 3 || h.Total != 3 {
		t.Fatalf("all-failed health = %+v, want unreachable 3/3", h)
	}
}

// Stale reuse carries its reason; a measured zero carries none.
func TestScrapeStaleAndMeasuredZeroReasons(t *testing.T) {
	var body = vec1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	p := NewPromHTTP(srv.URL, map[string]string{SigConnCount: `x{namespace="{namespace}"}`})
	body = strings.Replace(vec1, `"3"`, `"0"`, 1)
	tele, _ := p.PodMetrics(context.Background(), "prod", nil)
	if s := tele["api-0"].ConnCount; s.State != model.Present || s.Value != 0 || s.Reason != "" {
		t.Fatalf("measured zero must be Present with no reason: %+v", s)
	}
	body = vecEmpty
	tele, _ = p.PodMetrics(context.Background(), "prod", nil)
	if s := tele["api-0"].ConnCount; s.State != model.Stale || s.Reason != model.ReasonStale {
		t.Fatalf("series flicker must be Stale/stale within maxAge: %+v", s)
	}
}
