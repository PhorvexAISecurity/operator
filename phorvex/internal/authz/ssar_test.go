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
	calls   int
	allowNS map[string]bool
	errNS   map[string]bool
}

func (f *fakeSSAR) Create(_ context.Context, sar *authorizationv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error) {
	f.calls++
	ns := sar.Spec.ResourceAttributes.Namespace
	if f.errNS[ns] {
		return nil, errors.New("apiserver blip")
	}
	sar.Status.Allowed = f.allowNS[ns]
	return sar, nil
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
