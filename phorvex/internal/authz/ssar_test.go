package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeSSAR counts Create calls and answers per (namespace) from a table; nil error =
// definitive allow/deny, non-nil = an errored review (fail-open path).
type fakeSSAR struct {
	calls    int
	allowNS  map[string]bool
	errNS    map[string]bool
	nilNS    map[string]bool
	statusNS map[string]authorizationv1.SubjectAccessReviewStatus
	last     *authorizationv1.ResourceAttributes
}

func (f *fakeSSAR) Create(_ context.Context, sar *authorizationv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error) {
	f.calls++
	f.last = sar.Spec.ResourceAttributes.DeepCopy()
	ns := f.last.Namespace
	if f.errNS[ns] {
		return nil, errors.New("apiserver blip")
	}
	if f.nilNS[ns] {
		return nil, nil
	}
	if status, ok := f.statusNS[ns]; ok {
		sar.Status = status
		return sar, nil
	}
	sar.Status.Allowed = f.allowNS[ns]
	return sar, nil
}

func TestAllowed_ClusterScopedVerbUsesEmptyNamespace(t *testing.T) {
	f := &fakeSSAR{allowNS: map[string]bool{"": true}}
	c := NewCheckerWithClient(f, time.Minute)
	verb := Verb{Group: "amtd.r6security.com", Resource: "securityevents", Verb: "create", ClusterScoped: true}
	if allowed, unknown, why := c.Allowed(context.Background(), "tenant-a", []Verb{verb}); !allowed || unknown || why != "" {
		t.Fatalf("cluster scoped allow: allowed=%v unknown=%v why=%q", allowed, unknown, why)
	}
	if f.last.Namespace != "" {
		t.Fatalf("cluster-scoped review carried namespace %q", f.last.Namespace)
	}
}

func TestAllowed_MalformedAndUnavailableResponsesAreUnknown(t *testing.T) {
	f := &fakeSSAR{statusNS: map[string]authorizationv1.SubjectAccessReviewStatus{
		"contradictory": {Allowed: true, Denied: true},
		"evaluation":    {EvaluationError: "authorizer incomplete"},
	}}
	c := NewCheckerWithClient(f, time.Minute)
	for _, ns := range []string{"contradictory", "evaluation"} {
		if allowed, unknown, why := c.Allowed(context.Background(), ns, testVerbs); allowed || !unknown || why == "" {
			t.Fatalf("%s: allowed=%v unknown=%v why=%q", ns, allowed, unknown, why)
		}
	}
	if allowed, unknown, _ := NewCheckerWithClient(nil, time.Minute).Allowed(context.Background(), "ns", testVerbs); allowed || !unknown {
		t.Fatalf("nil client: allowed=%v unknown=%v", allowed, unknown)
	}
	var nilChecker *Checker
	if allowed, unknown, _ := nilChecker.Allowed(context.Background(), "ns", testVerbs); allowed || !unknown {
		t.Fatalf("nil checker: allowed=%v unknown=%v", allowed, unknown)
	}
}

func TestAllowed_EncodesSubresourceSeparatelyAndTreatsEmptyResponseAsUnknown(t *testing.T) {
	f := &fakeSSAR{allowNS: map[string]bool{"allowed": true}, nilNS: map[string]bool{"empty": true}}
	c := NewCheckerWithClient(f, time.Minute)
	verb := Verb{Resource: "pods", Subresource: "ephemeralcontainers", Verb: "update"}
	if allowed, unknown, why := c.Allowed(context.Background(), "allowed", []Verb{verb}); !allowed || unknown || why != "" {
		t.Fatalf("subresource allow: allowed=%v unknown=%v why=%q", allowed, unknown, why)
	}
	if f.last.Resource != "pods" || f.last.Subresource != "ephemeralcontainers" {
		t.Fatalf("wire attributes resource=%q subresource=%q", f.last.Resource, f.last.Subresource)
	}
	if allowed, unknown, why := c.Allowed(context.Background(), "empty", []Verb{verb}); allowed || !unknown || why == "" {
		t.Fatalf("empty response: allowed=%v unknown=%v why=%q", allowed, unknown, why)
	}
}

var testVerbs = []Verb{{Resource: "pods", Verb: "delete"}}

func TestAllowed_DenyExcludes_ErrorFailsOpen_PerNamespace(t *testing.T) {
	f := &fakeSSAR{allowNS: map[string]bool{"nsB": true}, errNS: map[string]bool{"nsC": true}}
	c := NewCheckerWithClient(f, time.Minute)

	// ns A: deny — allowed=false, unknown=false (definitive → excludes).
	if allowed, unknown, _ := c.Allowed(context.Background(), "nsA", testVerbs); allowed || unknown {
		t.Fatalf("nsA deny: want allowed=false unknown=false, got allowed=%v unknown=%v", allowed, unknown)
	}
	// ns B: allow.
	if allowed, unknown, _ := c.Allowed(context.Background(), "nsB", testVerbs); !allowed || unknown {
		t.Fatalf("nsB allow: want allowed=true unknown=false, got allowed=%v unknown=%v", allowed, unknown)
	}
	// ns C: error — unknown=true (fail-open: caller must NOT exclude).
	if allowed, unknown, _ := c.Allowed(context.Background(), "nsC", testVerbs); allowed || !unknown {
		t.Fatalf("nsC error: want allowed=false unknown=true, got allowed=%v unknown=%v", allowed, unknown)
	}
}

// (e) the cache bound: 100 ticks, one ns, one verb-set ⇒ ≤ 1 SSAR per verb per TTL.
func TestAllowed_CacheBoundsSSARCalls(t *testing.T) {
	f := &fakeSSAR{allowNS: map[string]bool{"ns": true}}
	c := NewCheckerWithClient(f, time.Minute)
	for i := 0; i < 100; i++ {
		c.Allowed(context.Background(), "ns", testVerbs)
	}
	if f.calls != 1 {
		t.Fatalf("cache bound: want 1 SSAR for 100 identical checks, got %d", f.calls)
	}
}

// An errored review is NOT cached (so a transient blip self-heals next tick).
func TestAllowed_ErrorNotCached(t *testing.T) {
	f := &fakeSSAR{errNS: map[string]bool{"ns": true}}
	c := NewCheckerWithClient(f, time.Minute)
	c.Allowed(context.Background(), "ns", testVerbs)
	c.Allowed(context.Background(), "ns", testVerbs)
	if f.calls != 2 {
		t.Fatalf("errored reviews must not cache: want 2 calls, got %d", f.calls)
	}
}

func TestOperatorScopedVerbRequiresResolvedNamespaceAndIsolatesCache(t *testing.T) {
	f := &fakeSSAR{allowNS: map[string]bool{"operator-a": true}}
	c := NewCheckerWithClient(f, time.Minute)
	verb := Verb{Resource: "configmaps", Name: "phorvex-endpoint-lease-journal", Verb: "update", OperatorScoped: true}
	if allowed, unknown, _ := c.Allowed(context.Background(), "vllm", []Verb{verb}); allowed || !unknown || f.calls != 0 {
		t.Fatalf("missing operator scope allowed=%t unknown=%t calls=%d", allowed, unknown, f.calls)
	}
	if allowed, unknown, _ := c.Observed("vllm", []Verb{verb}); allowed || !unknown || f.calls != 0 {
		t.Fatalf("missing observed scope allowed=%t unknown=%t calls=%d", allowed, unknown, f.calls)
	}
	a := verb
	a.Namespace = "operator-a"
	b := verb
	b.Namespace = "operator-b"
	if VerbSetKey([]Verb{a}) == VerbSetKey([]Verb{b}) {
		t.Fatal("operator namespaces collapsed in verb set key")
	}
	if allowed, unknown, _ := c.Allowed(context.Background(), "vllm", []Verb{a}); !allowed || unknown {
		t.Fatal("operator-a grant was not observed")
	}
	if allowed, unknown, _ := c.Allowed(context.Background(), "vllm", []Verb{b}); allowed || unknown {
		t.Fatal("operator-b inherited operator-a cached grant")
	}
	if f.calls != 2 || f.last.Namespace != "operator-b" {
		t.Fatalf("cache scopes calls=%d last=%+v", f.calls, f.last)
	}
}
