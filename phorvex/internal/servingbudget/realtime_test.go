package servingbudget

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"
)

// Real wall-clock HTTP acceptance: socket-bound caller identities, the actual
// reverse proxy and backend, simultaneous abusive workers and legitimate growth.
// No fake time, identity header, readiness probe or below-reserve legit load.
func TestServingRateRealtimeAboveReserveAcceptance(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	p, err := NewProxy(backend.URL, "real-http-proxy")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := testContract()
	c.Calibrating = false
	c.Enabled = true
	c.Baseline = 2
	c.Reserved = 2
	c.Burst = 2
	c.Revision = 1
	c.OperationID = "real-http"
	c.CalibrationStart = now.Add(-2 * time.Minute)
	c.CalibrationEnd = now.Add(-time.Minute)
	c.ActivatedAt = now
	c.ExpiresAt = now.Add(MaxLease)
	ids := map[string]string{"127.0.0.2": "legit", "127.0.0.3": "abuser", "127.0.0.4": "abuser", "127.0.0.5": "abuser"}
	if err = p.Apply(c, "real-config", ids, now); err != nil {
		t.Fatal(err)
	}
	public := httptest.NewServer(p)
	defer public.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var refresh sync.WaitGroup
	refresh.Add(1)
	go func() {
		defer refresh.Done()
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case at := <-tick.C:
				if e := p.Apply(c, "real-config", ids, at); e != nil {
					t.Errorf("refresh: %v", e)
					return
				}
			}
		}
	}()
	var mu sync.Mutex
	legitOK, legitFailed, abuseOK, abuse429 := 0, 0, 0, 0
	var latencies []time.Duration
	hit := func(hc *http.Client, legit bool) {
		start := time.Now()
		resp, e := hc.Get(public.URL)
		code := 0
		body := ""
		if e == nil {
			data, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			code = resp.StatusCode
			body = string(data)
		}
		mu.Lock()
		defer mu.Unlock()
		if legit {
			latencies = append(latencies, time.Since(start))
			if code == 200 && body == "ok" {
				legitOK++
			} else {
				legitFailed++
			}
		} else {
			if code == 200 && body == "ok" {
				abuseOK++
			} else if code == 429 {
				abuse429++
			} else {
				t.Errorf("abusive path unexpected code=%d error=%v", code, e)
			}
		}
	}
	clientFor := func(ip string) *http.Client {
		d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}, Timeout: 2 * time.Second}
		tr := &http.Transport{DialContext: d.DialContext, Proxy: nil}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 2 * time.Second}
	}
	var workers sync.WaitGroup
	started := time.Now()
	workers.Add(5)
	for _, ip := range []string{"127.0.0.3", "127.0.0.4", "127.0.0.5"} {
		go func(ip string) {
			defer workers.Done()
			hc := clientFor(ip)
			tick := time.NewTicker(100 * time.Millisecond)
			defer tick.Stop()
			for i := 0; i < 100; i++ {
				<-tick.C
				hit(hc, false)
			}
		}(ip)
	}
	go func() {
		defer workers.Done()
		hc := clientFor("127.0.0.2")
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for i := 0; i < 50; i++ {
			<-tick.C
			hit(hc, true)
		}
	}()
	go func() {
		defer workers.Done()
		hc := clientFor("127.0.0.2")
		tick := time.NewTicker(3 * time.Second)
		defer tick.Stop()
		for i := 0; i < 3; i++ {
			<-tick.C
			for j := 0; j < 10; j++ {
				hit(hc, true)
			}
		}
	}()
	workers.Wait()
	elapsed := time.Since(started)
	cancel()
	refresh.Wait()
	s := p.Snapshot(time.Now())
	limit := c.Baseline*elapsed.Seconds() + c.Burst + 1
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p99 := latencies[(len(latencies)-1)*99/100]
	if legitOK != 80 || legitFailed != 0 || s.Legitimate.Rejected != 0 || abuseOK+abuse429 != 300 || abuse429 == 0 || float64(abuseOK) > limit || p99 > 500*time.Millisecond {
		t.Fatalf("legit=%d failed=%d abuse200=%d abuse429=%d limit=%g p99=%s status=%+v", legitOK, legitFailed, abuseOK, abuse429, limit, p99, s)
	}
	t.Logf("REAL HTTP elapsed=%s reserve=2qps; legitimate 5qps + bursts of10: %d/80 HTTP200 body=ok, failed=%d rejected=%d p99=%s; 3 abusive workers=300 attempts HTTP200=%d HTTP429=%d cap bound=%.3f", elapsed, legitOK, legitFailed, s.Legitimate.Rejected, p99, abuseOK, abuse429, limit)
}
