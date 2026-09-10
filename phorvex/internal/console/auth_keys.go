/*
 * Phorvex Console — bounded signing-key retrieval (M-136).
 *
 * Both credential paths need public keys they did not ship with: the ALB's per-kid EC keys and
 * the bearer IdP's JWKS. That fetch is an attacker-reachable side effect of an UNVERIFIED token
 * header, so it is bounded on every axis:
 *
 *   - the URL is built by the console from CONFIGURED values (region / configured JWKS URL) and
 *     a charset-validated kid. A URL, host or path from the token is never fetched, and
 *     redirects are refused so a compromised endpoint cannot re-point the fetch.
 *   - request deadline, response size and TLS are fixed; the transport is injectable for tests.
 *   - results are cached with a TTL and shared under one mutex; concurrent misses for the same
 *     kid collapse into a single in-flight fetch.
 *   - misses are rate-limited by a token bucket, so a flood of forged arbitrary-kid tokens
 *     cannot turn the console into a fetch amplifier against the key endpoint.
 *   - a fetch failure NEVER downgrades authentication: the request fails closed.
 */

package console

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

const (
	keyFetchTimeout = 5 * time.Second
	keyMaxBody      = 1 << 20 // 1 MiB is far beyond any JWKS or PEM key
)

// kidRe is the charset a key id may use before it is ever interpolated into a URL path.
var kidRe = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,128}$`)

func validKID(kid string) bool { return kidRe.MatchString(kid) }

// boundedFetcher performs the only outbound HTTP the auth path is allowed to make.
type boundedFetcher struct {
	client  *http.Client
	maxBody int64
}

func newBoundedFetcher(rt http.RoundTripper, timeout time.Duration, maxBody int64) *boundedFetcher {
	if timeout <= 0 {
		timeout = keyFetchTimeout
	}
	if maxBody <= 0 {
		maxBody = keyMaxBody
	}
	return &boundedFetcher{
		client: &http.Client{
			Transport: rt, // nil => http.DefaultTransport
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("redirect refused")
			},
		},
		maxBody: maxBody,
	}
}

func (f *boundedFetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > f.maxBody {
		return nil, fmt.Errorf("response exceeds %d bytes", f.maxBody)
	}
	return body, nil
}

// missBudget is a token bucket over cache MISSES. A verified-key cache hit costs nothing; only
// a kid the console has never seen consumes budget, which is exactly the forged-token path.
type missBudget struct {
	mu     sync.Mutex
	tokens float64
	rate   float64 // refill per second
	burst  float64
	last   time.Time
	now    func() time.Time
}

func newMissBudget(ratePerSec, burst float64, now func() time.Time) *missBudget {
	if now == nil {
		now = time.Now
	}
	return &missBudget{tokens: burst, rate: ratePerSec, burst: burst, last: now(), now: now}
}

func (b *missBudget) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	if !b.last.IsZero() {
		if elapsed := t.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens = minFloat(b.burst, b.tokens+elapsed*b.rate)
		}
	}
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// singleFlight collapses concurrent fetches of the same key id into one.
type singleFlight struct {
	mu    sync.Mutex
	calls map[string]chan struct{}
}

func newSingleFlight() *singleFlight { return &singleFlight{calls: map[string]chan struct{}{}} }

// enter returns (true, done) when the caller owns the fetch — it must call done() when finished.
// It returns (false, wait) when another goroutine already owns it; the caller waits on wait and
// then re-reads the cache.
func (s *singleFlight) enter(key string) (bool, chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, busy := s.calls[key]; busy {
		return false, ch
	}
	ch := make(chan struct{})
	s.calls[key] = ch
	return true, ch
}

func (s *singleFlight) leave(key string, ch chan struct{}) {
	s.mu.Lock()
	delete(s.calls, key)
	s.mu.Unlock()
	close(ch)
}

// minFloat is spelled out rather than using the builtin `min`, because a package-level `min`
// would shadow the builtin the history reader relies on for int64 offsets.
func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
