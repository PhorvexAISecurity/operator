/*
 * M-163: the observation-only authorization read.
 *
 * Observed must answer the SAME question as Allowed from authorization already reviewed, and
 * must be inert: no SelfSubjectAccessReview, no cache entry written, no entry's timestamp
 * refreshed. The current / absent / expired cache states are covered here, where the cache
 * clock is injectable and the boundary is exact rather than slept for.
 */

package authz

import (
	"context"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type countingSAR struct {
	allowed bool
	err     error
	calls   int
}

func (s *countingSAR) Create(_ context.Context, sar *authorizationv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	sar.Status.Allowed = s.allowed
	return sar, nil
}

var m163Verbs = []Verb{{Group: "", Resource: "pods", Verb: "delete"}}

// clockAt returns a settable clock and the knob that advances it.
func clockAt(start time.Time) (func() time.Time, func(time.Duration)) {
	now := start
	return func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }
}

// cacheSnapshot copies the cache so a test can prove it did not change.
func cacheSnapshot(c *Checker) map[string]entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]entry, len(c.cache))
	for k, v := range c.cache {
		out[k] = v
	}
	return out
}

func sameCache(a, b map[string]entry) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		w, ok := b[k]
		if !ok || w != v {
			return false
		}
	}
	return true
}

// ABSENT: never reviewed. Honest unknown (the caller's existing fail-open), never an
// invented allow, and no review is issued to resolve it.
func TestM163_ObservedWithNoEvidenceIsUnknownAndIssuesNoReview(t *testing.T) {
	now, _ := clockAt(time.Unix(1000, 0))
	sar := &countingSAR{allowed: true}
	c := NewCheckerWithClock(sar, time.Hour, now)

	allowed, unknown, why := c.Observed("ns", m163Verbs)
	if allowed || !unknown {
		t.Fatalf("absent evidence read as allowed=%v unknown=%v, want (false,true)", allowed, unknown)
	}
	if sar.calls != 0 {
		t.Fatalf("the observation-only path issued %d SelfSubjectAccessReviews", sar.calls)
	}
	if len(cacheSnapshot(c)) != 0 {
		t.Fatal("the observation-only path wrote a cache entry")
	}
	if want := "authorization-unobserved (never-reviewed)"; len(why) < len(want) || why[:len(want)] != want {
		t.Fatalf("why = %q, want it to name the evidence as never reviewed", why)
	}
}

// CURRENT: an allow and a deny already reviewed are reported exactly as the reviewing path
// reports them, without a second review and without refreshing the entry.
func TestM163_ObservedWithCurrentEvidenceMatchesAllowedAndIsInert(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allowed bool
	}{{"current-allow", true}, {"current-deny", false}} {
		t.Run(tc.name, func(t *testing.T) {
			now, advance := clockAt(time.Unix(1000, 0))
			sar := &countingSAR{allowed: tc.allowed}
			c := NewCheckerWithClock(sar, time.Hour, now)

			wantAllowed, wantUnknown, wantWhy := c.Allowed(context.Background(), "ns", m163Verbs)
			if sar.calls != 1 {
				t.Fatalf("precondition: the real path issued %d reviews, want 1", sar.calls)
			}
			before := cacheSnapshot(c)

			advance(30 * time.Minute) // still inside the TTL
			allowed, unknown, why := c.Observed("ns", m163Verbs)
			if allowed != wantAllowed || unknown != wantUnknown || why != wantWhy {
				t.Fatalf("observed (%v,%v,%q) != reviewed (%v,%v,%q)",
					allowed, unknown, why, wantAllowed, wantUnknown, wantWhy)
			}
			if sar.calls != 1 {
				t.Fatalf("the observation-only path issued a review: %d total", sar.calls)
			}
			if !sameCache(before, cacheSnapshot(c)) {
				t.Fatalf("the observation-only path rewrote the cache: before=%v after=%v",
					before, cacheSnapshot(c))
			}

			// It must not have extended the entry's life either: at the ORIGINAL expiry the
			// entry is gone for both paths.
			advance(30 * time.Minute)
			if _, unk, _ := c.Observed("ns", m163Verbs); !unk {
				t.Fatal("the observation-only path refreshed the entry's timestamp")
			}
		})
	}
}

// EXPIRED: evidence that has aged out is unknown, is named as expired, and is NOT quietly
// refreshed by a review the shadow issues on production's behalf.
func TestM163_ObservedWithExpiredEvidenceIsUnknownAndDoesNotRefresh(t *testing.T) {
	now, advance := clockAt(time.Unix(1000, 0))
	sar := &countingSAR{allowed: true}
	c := NewCheckerWithClock(sar, time.Minute, now)

	if allowed, _, _ := c.Allowed(context.Background(), "ns", m163Verbs); !allowed {
		t.Fatal("precondition: the first review should allow")
	}
	expired := cacheSnapshot(c)

	advance(time.Minute) // exactly at the TTL boundary: no longer current
	allowed, unknown, why := c.Observed("ns", m163Verbs)
	if allowed || !unknown {
		t.Fatalf("expired evidence read as allowed=%v unknown=%v, want (false,true)", allowed, unknown)
	}
	if want := "authorization-unobserved (expired)"; len(why) < len(want) || why[:len(want)] != want {
		t.Fatalf("why = %q, want it to name the evidence as expired", why)
	}
	if sar.calls != 1 {
		t.Fatalf("the observation-only path re-reviewed expired evidence: %d calls", sar.calls)
	}
	if !sameCache(expired, cacheSnapshot(c)) {
		t.Fatal("the observation-only path rewrote the expired entry")
	}

	// Production still re-reviews it itself, and now sees the CURRENT external answer.
	sar.allowed = false
	if allowed, _, _ := c.Allowed(context.Background(), "ns", m163Verbs); allowed {
		t.Fatal("production did not re-review expired evidence")
	}
	if sar.calls != 2 {
		t.Fatalf("production issued %d reviews, want 2", sar.calls)
	}
}

// A multi-verb set reports the FIRST verb without current evidence, matching Allowed's
// short-circuit, so the two paths attribute a verdict to the same verb.
func TestM163_ObservedShortCircuitsOnTheFirstUnobservedVerb(t *testing.T) {
	now, _ := clockAt(time.Unix(1000, 0))
	sar := &countingSAR{allowed: true}
	c := NewCheckerWithClock(sar, time.Hour, now)

	verbs := []Verb{
		{Resource: "pods", Verb: "delete"},
		{Resource: "networkpolicies", Group: "networking.k8s.io", Verb: "create"},
	}
	// Review only the FIRST verb.
	if allowed, _, _ := c.Allowed(context.Background(), "ns", verbs[:1]); !allowed {
		t.Fatal("precondition: first verb should be allowed")
	}
	_, unknown, why := c.Observed("ns", verbs)
	if !unknown {
		t.Fatal("a partially observed verb set must be unknown, not allowed")
	}
	if want := "networkpolicies"; !contains(why, want) {
		t.Fatalf("why = %q, want it to name the unobserved verb %q", why, want)
	}
	if sar.calls != 1 {
		t.Fatalf("the observation-only path issued a review for the missing verb: %d calls", sar.calls)
	}
}

// A nil checker is unknown, never an allow (the gate guards on w.az != nil, but the read
// must be safe on its own).
func TestM163_ObservedOnNilCheckerIsUnknown(t *testing.T) {
	var c *Checker
	allowed, unknown, _ := c.Observed("ns", m163Verbs)
	if allowed || !unknown {
		t.Fatalf("nil checker read as allowed=%v unknown=%v, want (false,true)", allowed, unknown)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
