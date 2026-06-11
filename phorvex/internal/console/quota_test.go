/*
 * Phorvex — P-VCLUSTER Pass 2: per-tenant DoS quota tests. One tenant's flood is rate-limited and does
 * NOT degrade another tenant's quota (the R5 isolation property).
 */

package console

import (
	"testing"
	"time"
)

func fixedClockQuota() (*func() time.Time, func(d time.Duration)) {
	now := time.Unix(1_700_000_000, 0)
	f := func() time.Time { return now }
	return &f, func(d time.Duration) { now = now.Add(d) }
}

func TestQuota_NoisyTenantIsolatedFromQuiet(t *testing.T) {
	q := NewTenantQuota(QuotaConfig{RatePerSec: 1, Burst: 5, MaxConc: 100, MaxTenants: 1024})
	fp, _ := fixedClockQuota()
	q.now = *fp

	// the NOISY tenant floods: 5 burst tokens allowed, then rate-limited.
	allowed := 0
	for i := 0; i < 50; i++ {
		if q.Allow("noisy") {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("noisy tenant must be capped at its burst (5), got %d allowed of 50", allowed)
	}

	// the QUIET tenant is UNAFFECTED — its own bucket is full.
	quiet := 0
	for i := 0; i < 5; i++ {
		if q.Allow("quiet") {
			quiet++
		}
	}
	if quiet != 5 {
		t.Errorf("R5 LEAK: a noisy tenant's flood degraded the quiet tenant's quota: quiet allowed %d/5", quiet)
	}
}

func TestQuota_RefillsOverTime(t *testing.T) {
	q := NewTenantQuota(QuotaConfig{RatePerSec: 2, Burst: 2, MaxConc: 100, MaxTenants: 16})
	fp, advance := fixedClockQuota()
	q.now = *fp
	if !q.Allow("t") || !q.Allow("t") || q.Allow("t") {
		t.Fatal("burst=2 must allow exactly 2 then deny")
	}
	advance(1 * time.Second) // +2 tokens at rate 2/s
	if !q.Allow("t") || !q.Allow("t") {
		t.Fatal("must refill 2 tokens after 1s at rate 2/s")
	}
}

func TestQuota_ConcurrencyCapPerTenant(t *testing.T) {
	q := NewTenantQuota(QuotaConfig{RatePerSec: 100, Burst: 100, MaxConc: 2, MaxTenants: 16})
	fp, _ := fixedClockQuota()
	q.now = *fp
	r1, err := q.Acquire("a")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := q.Acquire("a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Acquire("a"); err == nil {
		t.Error("tenant a must hit its concurrency cap (2) on the 3rd in-flight")
	}
	// another tenant is unaffected.
	if _, err := q.Acquire("b"); err != nil {
		t.Errorf("tenant b must not be blocked by tenant a's concurrency: %v", err)
	}
	r1()
	if _, err := q.Acquire("a"); err != nil {
		t.Errorf("releasing one slot must let tenant a acquire again: %v", err)
	}
	r2()
}

func TestQuota_TrackedMapBounded(t *testing.T) {
	q := NewTenantQuota(QuotaConfig{RatePerSec: 1, Burst: 1, MaxConc: 1, MaxTenants: 8})
	fp, advance := fixedClockQuota()
	q.now = *fp
	for i := 0; i < 100; i++ {
		advance(time.Millisecond)
		q.Allow(time.Now().Add(time.Duration(i)).String()) // spray many distinct tenant ids
	}
	if len(q.buckets) > 8 {
		t.Errorf("the limiter map must stay bounded (<=8) to resist a memory-DoS, got %d", len(q.buckets))
	}
}
