/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

// Package authz confirms, before an action is offered to the optimizer, that the
// operator's own ServiceAccount may actually perform it in the target namespace — via
// SelfSubjectAccessReview ("can I?"). It is the RBAC leg of the T1-E capability gate.
//
// Two disciplines are load-bearing:
//   - BOUNDED (P-BOUNDED-AUTHZ): SSAR is an apiserver write; results are cached per
//     (namespace, verb) with a TTL so a busy fleet cannot amplify into apiserver load.
//     The gate calls this LAST (after the free local checks), so an ineligible-by-a-
//     cheaper-check candidate never reaches an SSAR at all.
//   - FAIL-OPEN ON ERROR (P-NO-FREEZE): an SSAR that ERRORS (apiserver blip) is not a
//     measured "no" — it returns unknown=true and the caller must NOT exclude on it
//     (else a transient apiserver failure silently disables all actuation). Only an
//     explicit DENY excludes. Real actuation still needs real RBAC, so a fail-open here
//     at worst surfaces a visible downstream dispatch error, never a silent freeze.
package authz

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DefaultTTL is the cache lifetime for one (namespace, verb) SSAR result.
const DefaultTTL = 5 * time.Minute

// Verb is one RBAC access tuple the gate must confirm before an action is eligible.
// It is the SINGLE source of truth for the SSAR verb-set — handlers declare their verbs
// via RequiredVerbs(), and this gate reviews exactly those.
type Verb struct {
	Group    string // API group ("" for core)
	Resource string // e.g. "pods", "networkpolicies"
	Verb     string // e.g. "delete", "create", "patch"
}

func (v Verb) String() string { return v.Group + "/" + v.Resource + ":" + v.Verb }

// SSARClient is the minimal SelfSubjectAccessReview surface the Checker needs. The real
// implementation is a kubernetes.Interface (see NewChecker); tests inject a fake.
type SSARClient interface {
	Create(ctx context.Context, sar *authorizationv1.SelfSubjectAccessReview, opts metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error)
}

type entry struct {
	allowed bool
	at      time.Time
}

// Checker answers "may I do these verbs in this namespace?" over a TTL cache.
type Checker struct {
	cli SSARClient
	ttl time.Duration
	now func() time.Time

	mu    sync.Mutex
	cache map[string]entry // key = ns + "|" + verb.String()
}

// NewChecker builds a Checker over the cluster's SelfSubjectAccessReviews client.
func NewChecker(cs kubernetes.Interface, ttl time.Duration) *Checker {
	return NewCheckerWithClient(cs.AuthorizationV1().SelfSubjectAccessReviews(), ttl)
}

// NewCheckerWithClient is the injectable constructor (tests pass a fake SSARClient).
func NewCheckerWithClient(cli SSARClient, ttl time.Duration) *Checker {
	return NewCheckerWithClock(cli, ttl, time.Now)
}

// NewCheckerWithClock additionally injects the cache clock. The TTL boundary decides whether
// authorization counts as CURRENTLY OBSERVED, and M-163 made that boundary load-bearing for
// the read-only Observed path, so it has to be reachable from a test without sleeping. A nil
// clock is time.Now, so this is the same Checker every runtime caller builds.
func NewCheckerWithClock(cli SSARClient, ttl time.Duration, now func() time.Time) *Checker {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if now == nil {
		now = time.Now
	}
	return &Checker{cli: cli, ttl: ttl, now: now, cache: map[string]entry{}}
}

// Allowed reports whether the operator SA may perform ALL of verbs in ns.
//   - allowed=true  iff every verb is allowed (and none errored).
//   - unknown=true  iff at least one SSAR errored — the caller MUST NOT exclude (fail-open).
//   - why           names the first denied or errored verb (empty when allowed).
//
// On a cache hit no apiserver call is made. Errors are never cached (so a transient blip
// self-heals on the next tick); allows and denies are cached for ttl.
func (c *Checker) Allowed(ctx context.Context, ns string, verbs []Verb) (allowed, unknown bool, why string) {
	for _, v := range verbs {
		ok, unk, w := c.allowedOne(ctx, ns, v)
		if unk {
			return false, true, w
		}
		if !ok {
			return false, false, w
		}
	}
	return true, false, ""
}

// Observed answers the same question from AUTHORIZATION ALREADY REVIEWED (M-163). It issues
// no SelfSubjectAccessReview, writes no cache entry and refreshes no entry's timestamp, so a
// counterfactual evaluation cannot change what the next real gate observes — neither by
// caching an answer production would otherwise have re-reviewed, nor by extending the life
// of one already held.
//
//   - allowed=true  iff every verb holds a CURRENT cached allow.
//   - unknown=true  iff any verb has no current evidence (never reviewed, or expired). This
//     is the SAME unknown the errored-SSAR path returns, so the caller applies the existing
//     fail-open policy (flagged, not excluded). Absent evidence is reported as absent; it is
//     never resolved into an invented allow.
//   - a cached DENY is a measured deny and reports exactly as it does on the reviewing path.
//
// Verb order and short-circuiting match Allowed, so the two paths agree on WHICH verb a
// verdict is attributed to.
func (c *Checker) Observed(ns string, verbs []Verb) (allowed, unknown bool, why string) {
	if c == nil {
		return false, true, "authorization-unobserved: no checker"
	}
	for _, v := range verbs {
		ok, unk, w := c.observedOne(ns, v)
		if unk {
			return false, true, w
		}
		if !ok {
			return false, false, w
		}
	}
	return true, false, ""
}

func (c *Checker) observedOne(ns string, v Verb) (allowed, unknown bool, why string) {
	e, held, fresh := c.lookup(ns, v)
	if !fresh {
		state := "never-reviewed"
		if held {
			state = "expired"
		}
		return false, true, "authorization-unobserved (" + state + ") " + v.String() + " in " + ns
	}
	if !e.allowed {
		return false, false, "denied " + v.String() + " in " + ns
	}
	return true, false, ""
}

// lookup is the single cache read shared by the reviewing and the observation-only path, so
// the two can never disagree about what counts as current evidence. It takes the lock to read
// consistently and writes nothing.
func (c *Checker) lookup(ns string, v Verb) (e entry, held, fresh bool) {
	key := ns + "|" + v.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, held = c.cache[key]
	return e, held, held && c.now().Sub(e.at) < c.ttl
}

func (c *Checker) allowedOne(ctx context.Context, ns string, v Verb) (allowed, unknown bool, why string) {
	key := ns + "|" + v.String()
	if e, _, fresh := c.lookup(ns, v); fresh {
		if !e.allowed {
			return false, false, "denied " + v.String() + " in " + ns
		}
		return true, false, ""
	}

	sar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: ns, Group: v.Group, Resource: v.Resource, Verb: v.Verb,
			},
		},
	}
	res, err := c.cli.Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		// Fail-open: an errored review is NOT a measured deny. Do not cache.
		return false, true, "ssar-error " + v.String() + " in " + ns + ": " + err.Error()
	}
	c.mu.Lock()
	c.cache[key] = entry{allowed: res.Status.Allowed, at: c.now()}
	c.mu.Unlock()
	if !res.Status.Allowed {
		return false, false, "denied " + v.String() + " in " + ns
	}
	return true, false, ""
}

// SortVerbs returns verbs in a stable order (for deterministic verb-set keys / logs).
func SortVerbs(verbs []Verb) []Verb {
	out := append([]Verb(nil), verbs...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// VerbSetKey is a stable key for a verb-set (used where a set, not per-verb, is logged).
func VerbSetKey(verbs []Verb) string {
	sorted := SortVerbs(verbs)
	parts := make([]string, len(sorted))
	for i, v := range sorted {
		parts[i] = v.String()
	}
	return strings.Join(parts, ",")
}
