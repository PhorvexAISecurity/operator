package servingbudget

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testContract() Contract {
	return Contract{Version: 1, SourceSHA256: strings.Repeat("a", 64), ProxyImage: "test@sha256:" + strings.Repeat("b", 64), AbusiveAccount: "abuser", LegitimateAccount: "legit", Path: "/", Calibrating: true}
}
func request(p *Proxy, ip string) int {
	r := httptest.NewRequest("GET", "http://public/", nil)
	r.RemoteAddr = ip + ":1234"
	r.Header.Set("X-Forwarded-For", "10.0.0.2")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w.Code
}
func TestServingRateProxyBothDirections(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer backend.Close()
	p, e := NewProxy(backend.URL, "proxy")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	p.now = func() time.Time { return now }
	c := testContract()
	ids := map[string]string{"10.0.0.1": "abuser", "10.0.0.3": "abuser", "10.0.0.4": "abuser", "10.0.0.2": "legit"}
	if e = p.Apply(c, "config", ids, now); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 60; i++ {
		now = now.Add(time.Second)
		_ = p.Apply(c, "config", ids, now)
		for j := 0; j < 42; j++ {
			if request(p, "10.0.0.1") != 200 || request(p, "10.0.0.2") != 200 {
				t.Fatal("quiet calibration traffic failed")
			}
		}
	}
	// Finish calibration after all 60 seconds' requests, avoiding a boundary sample.
	s := p.Snapshot(now)
	if !Positive(s.Baseline) || !Positive(s.Reserved) {
		t.Fatal(s)
	}
	c.Calibrating = false
	c.Enabled = true
	c.ActivatedAt = now
	c.ExpiresAt = now.Add(MaxLease)
	c.Revision = 1
	c.OperationID = "operation"
	c.Baseline = s.Baseline
	c.Reserved = s.Reserved
	c.Burst = s.Baseline
	c.CalibrationStart = s.CalibrationStart
	c.CalibrationEnd = s.CalibrationEnd
	if e = p.Apply(c, "config", ids, now); e != nil {
		t.Fatal(e)
	}
	start := p.Snapshot(now)
	for second := 0; second < 10; second++ {
		now = now.Add(time.Second)
		_ = p.Apply(c, "config", ids, now)
		for j := 0; j < 500; j++ {
			code := request(p, []string{"10.0.0.1", "10.0.0.3", "10.0.0.4"}[j%3])
			if code != 200 && code != 429 {
				t.Fatal(code)
			}
		}
		for j := 0; j < 100; j++ {
			if request(p, "10.0.0.2") != 200 {
				t.Fatal("legitimate request lost")
			}
		}
	}
	end := p.Snapshot(now)
	admitted := end.Abusive.Admitted - start.Abusive.Admitted
	limit := c.Baseline*10 + c.Burst
	if float64(admitted) > limit || end.Abusive.Rejected-start.Abusive.Rejected == 0 || end.Legitimate.OK-start.Legitimate.OK != 1000 {
		t.Fatalf("both-direction failure: admitted=%d limit=%g end=%+v", admitted, limit, end)
	}
	t.Logf("5000 attack attempts: admitted=%d <= baseline*10+burst=%g rejected=%d; legitimate (100qps burst, reserve=%g) HTTP200=%d/1000", admitted, limit, end.Abusive.Rejected-start.Abusive.Rejected, c.Reserved, end.Legitimate.OK-start.Legitimate.OK)
	restarted, err := NewProxy(backend.URL, "new-proxy")
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = p.now
	if err = restarted.Apply(c, "config", ids, now); err != nil {
		t.Fatal("restart lost durable cap", err)
	}
	if request(restarted, "10.0.0.2") != 200 {
		t.Fatal("restart lost legitimate reservation")
	}
	if request(p, "10.0.0.9") != 403 {
		t.Fatal("spoofed header authorized unknown peer")
	}
	c.Enabled = false
	c.Revision++
	if e = p.Apply(c, "config", ids, now); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 500; i++ {
		if request(p, "10.0.0.1") != 200 {
			t.Fatal("rollback failed")
		}
	}
	now = now.Add(6 * time.Second)
	if request(p, "10.0.0.2") != 503 {
		t.Fatal("stale identity inventory admitted request")
	}
}
func TestServingRateDetectorSustainedAndReset(t *testing.T) {
	now := time.Now()
	s := Status{PodUID: "p", BootID: "b", ConfigUID: "c", Contract: testContract(), Baseline: 42, Reserved: 42, CalibrationEnd: now.Add(-time.Minute)}
	s.Contract.Calibrating = false
	d := &Detector{}
	for i := 0; i <= 13; i++ {
		s.UpdatedAt = now.Add(time.Duration(i) * 5 * time.Second)
		s.Abusive.Attempted = uint64(i) * 9105
		rate, fired := d.Observe(s, s.UpdatedAt)
		if fired != (i >= 12) {
			t.Fatalf("i=%d rate=%g fired=%t", i, rate, fired)
		}
	}
	s.UpdatedAt = s.UpdatedAt.Add(5 * time.Second)
	s.Abusive.Attempted += 100
	if _, f := d.Observe(s, s.UpdatedAt); f {
		t.Fatal("calm window did not reset")
	}
	s.UpdatedAt = s.UpdatedAt.Add(5 * time.Second)
	s.Abusive.Attempted += 9105
	if _, f := d.Observe(s, s.UpdatedAt.Add(time.Minute)); f {
		t.Fatal("stale sample fired")
	}
	s.BootID = "restarted"
	if _, f := d.Observe(s, s.UpdatedAt); f {
		t.Fatal("restart inherited baseline window")
	}
}

func TestServingRateProxyAutomaticallyReleasesQuietAndExpiredCaps(t *testing.T) {
	for _, reason := range []string{"quiet-window", "lease-expired"} {
		t.Run(reason, func(t *testing.T) {
			now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
			p, err := NewProxy("http://backend.invalid", "proxy")
			if err != nil {
				t.Fatal(err)
			}
			p.forward = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
			p.now = func() time.Time { return now }
			c := testContract()
			c.Calibrating = false
			c.Enabled = true
			c.Baseline = 2
			c.Reserved = 2
			c.Burst = 2
			c.OperationID = "release"
			c.Revision = 1
			c.CalibrationStart = now.Add(-2 * time.Minute)
			c.CalibrationEnd = now.Add(-time.Minute)
			c.ActivatedAt = now
			c.ExpiresAt = now.Add(MaxLease)
			ids := map[string]string{"10.0.0.1": "abuser", "10.0.0.2": "legit"}
			if err = p.Apply(c, "config", ids, now); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 10; i++ {
				request(p, "10.0.0.1")
			}
			if !p.Snapshot(now).CapActive || request(p, "10.0.0.1") != 429 {
				t.Fatal("abuse was not capped")
			}
			if reason == "quiet-window" {
				// A sample gap cannot masquerade as a quiet minute.
				now = now.Add(61 * time.Second)
				_ = p.Apply(c, "config", ids, now)
				if !p.Snapshot(now).CapActive {
					t.Fatal("missing samples released cap")
				}
				for i := 0; i < 60; i++ {
					now = now.Add(time.Second)
					_ = p.Apply(c, "config", ids, now)
				}
			} else {
				// Durable absolute expiry survives a fresh proxy boot, without a brain or detector.
				now = c.ExpiresAt
				p, err = NewProxy("http://backend.invalid", "restarted")
				if err != nil {
					t.Fatal(err)
				}
				p.forward = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
				p.now = func() time.Time { return now }
				if err = p.Apply(c, "config", ids, now); err != nil {
					t.Fatal(err)
				}
			}
			s := p.Snapshot(now)
			if s.CapActive || s.ReleaseReason != reason {
				t.Fatalf("cap not automatically released: %+v", s)
			}
			// Re-reading the old enabled contract must not silently reinstall this cap.
			_ = p.Apply(c, "config", ids, now)
			for i := 0; i < 100; i++ {
				if request(p, "10.0.0.1") != 200 || request(p, "10.0.0.2") != 200 {
					t.Fatal("released public path lost 200")
				}
			}
			t.Logf("%s: capActive=%t, 100/100 abusive and legitimate public requests return 200 after automatic release", reason, s.CapActive)
		})
	}
}
