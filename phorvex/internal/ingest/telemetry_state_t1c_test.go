/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// routingProm serves connCount for every pod but 500s the reqRate query, to exercise a
// partial source failure.
func routingProm(t *testing.T, failReqRate bool, connBody string) *PromHTTP {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if strings.Contains(q, "http_requests_total") {
			if failReqRate {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(q, "tcp") { // connCount query
			w.Write([]byte(connBody))
			return
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	t.Cleanup(srv.Close)
	return NewPromHTTP(srv.URL, map[string]string{
		SigReqRate:   `sum by (pod) (rate(http_requests_total{namespace="{namespace}"}[1m]))`,
		SigConnCount: `sum by (pod) (container_network_tcp_usage_total{namespace="{namespace}"})`,
	})
}

// (e) A failed per-signal query must make that signal State=Error for the pod (distinguishable
// from absent, M-113), the pod must still APPEAR (B.4), and PodMetrics must return an error so
// the caller can surface the degraded source (M-130).
func TestPodMetrics_FailedQueryIsErrorNotVanished(t *testing.T) {
	p := routingProm(t, true, vectorBody("api-0", "12"))
	tele, err := p.PodMetrics(context.Background(), "prod", []string{"api-0"})
	if err == nil {
		t.Fatal("a failed scrape query must return a non-nil error (M-130 surfacing)")
	}
	tl, ok := tele["api-0"]
	if !ok {
		t.Fatal("pod whose reqRate query failed must still appear (B.4), not vanish")
	}
	if tl.ReqRate.State != model.Error {
		t.Errorf("failed reqRate query: State = %v, want Error (M-113: not a measured zero)", tl.ReqRate.State)
	}
	if tl.ReqRate.Usable() {
		t.Error("an errored signal must not be Usable")
	}
	if !tl.ConnCount.Usable() || tl.ConnCount.Value != 12 {
		t.Errorf("the healthy connCount signal must stay Present=12, got %+v", tl.ConnCount)
	}
}

// (d) A signal that returns fresh, then stops returning a series, is Stale within maxAge (value
// retained in the record, but NOT usable) and Absent beyond maxAge.
func TestPodMetrics_StaleWithinMaxAgeThenAbsent(t *testing.T) {
	t.Run("within maxAge => Stale, value retained, not usable", func(t *testing.T) {
		p := routingProm(t, false, vectorBody("api-0", "55"))
		p.ScrapeInterval = 30 * time.Second // maxAge = 90s; the second call is immediate
		if _, err := p.PodMetrics(context.Background(), "prod", []string{"api-0"}); err != nil {
			t.Fatal(err)
		}
		// Now the connCount series disappears: repoint the query to one the server returns
		// empty for (no "tcp" => routing handler yields an empty result vector). Same cache.
		p.Queries[SigConnCount] = `sum by (pod) (definitely_absent_series{namespace="{namespace}"})`
		tele, err := p.PodMetrics(context.Background(), "prod", []string{"api-0"})
		if err != nil {
			t.Fatal(err)
		}
		tl := tele["api-0"]
		if tl.ConnCount.State != model.Stale {
			t.Fatalf("flickered series within maxAge: State = %v, want Stale", tl.ConnCount.State)
		}
		if tl.ConnCount.Value != 55 {
			t.Errorf("Stale must retain the last-good value in the record, got %v", tl.ConnCount.Value)
		}
		if tl.ConnCount.Usable() {
			t.Error("a Stale signal must not be Usable")
		}
	})

	t.Run("beyond maxAge => Absent", func(t *testing.T) {
		p := routingProm(t, false, vectorBody("api-0", "55"))
		p.ScrapeInterval = time.Nanosecond // maxAge = 3ns
		if _, err := p.PodMetrics(context.Background(), "prod", []string{"api-0"}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1 * time.Millisecond) // well beyond 3ns
		p.Queries[SigConnCount] = `sum by (pod) (definitely_absent_series{namespace="{namespace}"})`
		tele, _ := p.PodMetrics(context.Background(), "prod", []string{"api-0"})
		tl := tele["api-0"]
		if tl.ConnCount.State != model.Absent {
			t.Fatalf("beyond maxAge: State = %v, want Absent", tl.ConnCount.State)
		}
	})
}
