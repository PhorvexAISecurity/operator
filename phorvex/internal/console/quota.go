/*
 * Phorvex — P-VCLUSTER Pass 2: per-tenant DoS quota (the R5 keyed limiter). Replaces the single shared
 * RunManager.guard for tenant-facing surfaces so ONE tenant's flood exhausts only its OWN quota and can
 * never starve another tenant's capacity or budget.
 *
 * A per-tenant token bucket (rate + burst) plus a per-tenant concurrency cap; the tracked-tenant map is
 * BOUNDED (anti-unbounded-growth — the limiter cannot itself be DoS'd by spraying tenant ids).
 */

package console

import (
	"fmt"
	"sync"
	"time"
)

// QuotaConfig parameterizes the limiter (no hardcoded magics — set from Config).
type QuotaConfig struct {
	RatePerSec  float64 // tokens refilled per second, per tenant
	Burst       float64 // bucket capacity (max burst), per tenant
	MaxConc     int     // concurrent in-flight ops, per tenant
	MaxTenants  int     // bound on tracked tenants (the limiter's own memory cap)
}

// DefaultQuota is a conservative tenant quota; production overrides via Config.
func DefaultQuota() QuotaConfig {
	return QuotaConfig{RatePerSec: 1.0, Burst: 5, MaxConc: 2, MaxTenants: 4096}
}

type tokenBucket struct {
	tokens float64
	last   time.Time
	active int
}

// TenantQuota is a per-tenant token-bucket + concurrency limiter.
type TenantQuota struct {
	mu      sync.Mutex
	cfg     QuotaConfig
	buckets map[string]*tokenBucket
	now     func() time.Time
}

func NewTenantQuota(cfg QuotaConfig) *TenantQuota {
	if cfg.Burst <= 0 {
		cfg.Burst = 1
	}
	if cfg.MaxTenants <= 0 {
		cfg.MaxTenants = 4096
	}
	return &TenantQuota{cfg: cfg, buckets: map[string]*tokenBucket{}}
}

func (q *TenantQuota) clock() time.Time {
	if q.now != nil {
		return q.now()
	}
	return time.Now()
}

// bucketFor returns the tenant's bucket, creating it (bounded) and refilling it to `now`.
func (q *TenantQuota) bucketFor(tenant string, now time.Time) *tokenBucket {
	b := q.buckets[tenant]
	if b == nil {
		if len(q.buckets) >= q.cfg.MaxTenants {
			q.evictOldestLocked() // anti-unbounded-growth: the limiter cannot be memory-DoS'd
		}
		b = &tokenBucket{tokens: q.cfg.Burst, last: now}
		q.buckets[tenant] = b
		return b
	}
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = minf(q.cfg.Burst, b.tokens+d*q.cfg.RatePerSec)
		b.last = now
	}
	return b
}

// Allow consumes one token for the tenant; false => rate-limited (the tenant's OWN bucket is empty).
func (q *TenantQuota) Allow(tenant string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	b := q.bucketFor(tenant, q.clock())
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Acquire takes a rate token AND a concurrency slot; returns a release func, or an error if either is
// exhausted FOR THIS TENANT. Used by the write-path / run endpoints.
func (q *TenantQuota) Acquire(tenant string) (func(), error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	b := q.bucketFor(tenant, q.clock())
	if q.cfg.MaxConc > 0 && b.active >= q.cfg.MaxConc {
		return nil, fmt.Errorf("tenant %q over concurrency quota (%d in-flight)", tenant, b.active)
	}
	if b.tokens < 1 {
		return nil, fmt.Errorf("tenant %q rate-limited (quota exhausted)", tenant)
	}
	b.tokens--
	b.active++
	released := false
	return func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		if !released {
			released = true
			if bb := q.buckets[tenant]; bb != nil && bb.active > 0 {
				bb.active--
			}
		}
	}, nil
}

func (q *TenantQuota) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, b := range q.buckets {
		if first || b.last.Before(oldest) {
			oldest, oldestKey, first = b.last, k, false
		}
	}
	if oldestKey != "" {
		delete(q.buckets, oldestKey)
	}
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
