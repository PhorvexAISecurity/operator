/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (M-6)
 *
 * L0-L2 verifier tests through the PRODUCTION reader (NewK8sReader over a fake transport):
 * fail-closed boot, full-content drift rejection (the reviewer's seven enforcement-drift
 * bypasses + more, isolated with a positive control), C3 scope, TTL, epoch interleaving, and
 * the LIVE pre-submit scope check (a managed label removed since the tick is caught by a fresh
 * namespace GET). These exercise the real projection + trusted-contract comparison, not fakes.
 */

package codeexec

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func managedLabels() map[string]string { return map[string]string{ManagedLabelKey: ManagedLabelVal} }

// fakeClient builds a clientset holding the given policy+binding (+extra objects) with SSAR
// allowed. reactorErr, when set, makes the SSAR error (unknown). ssarDeny denies it.
func fakeClient(p *admissionv1.ValidatingAdmissionPolicy, b *admissionv1.ValidatingAdmissionPolicyBinding, extra ...runtime.Object) *fake.Clientset {
	objs := append([]runtime.Object{}, extra...)
	if p != nil {
		objs = append(objs, p)
	}
	if b != nil {
		objs = append(objs, b)
	}
	cs := fake.NewSimpleClientset(objs...)
	cs.PrependReactor("create", "selfsubjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})
	return cs
}

func verifierOver(cs *fake.Clientset, cfg Config) *Verifier { return New(NewK8sReader(cs), cfg) }

// --- boot: fail-closed before the first verification -------------------------------------

func TestUnavailableBeforeFirstVerify(t *testing.T) {
	p, b := ExpectedContract()
	v := verifierOver(fakeClient(p, b), Config{})
	if ok, _ := v.Available(managedLabels()); ok {
		t.Fatal("code-exec must be UNAVAILABLE before the first successful verification")
	}
}

// --- allow path + C3 out-of-scope --------------------------------------------------------

func TestVerifyThenAvailableInScopeOnly(t *testing.T) {
	p, b := ExpectedContract()
	v := verifierOver(fakeClient(p, b), Config{})
	if err := v.Verify(context.Background()); err != nil {
		t.Fatalf("valid contract must verify: %v", err)
	}
	if ok, why := v.Available(managedLabels()); !ok {
		t.Fatalf("in-scope namespace must be available: %s", why)
	}
	if ok, why := v.Available(map[string]string{"team": "x"}); ok {
		t.Fatalf("out-of-scope namespace must be unavailable (C3), got available (%s)", why)
	}
	if ok, _ := v.Available(nil); ok {
		t.Fatal("nil-label namespace must be out of scope (C3)")
	}
}

// --- full enforcement-content drift: each isolated mutation of the trusted manifest must be
// REJECTED through the production reader; the unmutated positive control verifies. -------------

func TestEnforcementContentDriftRejected(t *testing.T) {
	ignore := admissionv1.Ignore
	cases := []struct {
		name   string
		mutate func(*admissionv1.ValidatingAdmissionPolicy, *admissionv1.ValidatingAdmissionPolicyBinding)
	}{
		// The seven reviewer bypasses:
		{"cel-replaced-by-true", func(p *admissionv1.ValidatingAdmissionPolicy, _ *admissionv1.ValidatingAdmissionPolicyBinding) {
			p.Spec.Validations = []admissionv1.Validation{{Expression: "true"}}
		}},
		{"all-new-containers-hidden", func(p *admissionv1.ValidatingAdmissionPolicy, _ *admissionv1.ValidatingAdmissionPolicyBinding) {
			p.Spec.Variables[2].Expression = "[]"
		}},
		{"policy-match-condition-false", func(p *admissionv1.ValidatingAdmissionPolicy, _ *admissionv1.ValidatingAdmissionPolicyBinding) {
			p.Spec.MatchConditions = []admissionv1.MatchCondition{{Name: "skip", Expression: "false"}}
		}},
		{"wrong-resource-api-group", func(p *admissionv1.ValidatingAdmissionPolicy, _ *admissionv1.ValidatingAdmissionPolicyBinding) {
			p.Spec.MatchConstraints.ResourceRules[0].APIGroups = []string{"example.invalid"}
		}},
		{"binding-excludes-subresource", func(p *admissionv1.ValidatingAdmissionPolicy, b *admissionv1.ValidatingAdmissionPolicyBinding) {
			b.Spec.MatchResources.ExcludeResourceRules = p.Spec.MatchConstraints.ResourceRules
		}},
		{"binding-namespace-expression-excludes-target", func(_ *admissionv1.ValidatingAdmissionPolicy, b *admissionv1.ValidatingAdmissionPolicyBinding) {
			b.Spec.MatchResources.NamespaceSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "team", Operator: metav1.LabelSelectorOpIn, Values: []string{"restricted"}}}
		}},
		{"binding-object-selector-excludes-target", func(_ *admissionv1.ValidatingAdmissionPolicy, b *admissionv1.ValidatingAdmissionPolicyBinding) {
			b.Spec.MatchResources.ObjectSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"only": "other-pods"}}
		}},
		// More:
		{"failure-policy-ignore", func(p *admissionv1.ValidatingAdmissionPolicy, _ *admissionv1.ValidatingAdmissionPolicyBinding) {
			p.Spec.FailurePolicy = &ignore
		}},
		{"version-annotation-wrong", func(p *admissionv1.ValidatingAdmissionPolicy, _ *admissionv1.ValidatingAdmissionPolicyBinding) {
			p.Annotations = map[string]string{versionAnnotation: "bogus"}
		}},
		{"binding-no-deny", func(_ *admissionv1.ValidatingAdmissionPolicy, b *admissionv1.ValidatingAdmissionPolicyBinding) {
			b.Spec.ValidationActions = []admissionv1.ValidationAction{admissionv1.Warn}
		}},
		{"binding-wrong-policyname", func(_ *admissionv1.ValidatingAdmissionPolicy, b *admissionv1.ValidatingAdmissionPolicyBinding) {
			b.Spec.PolicyName = "other"
		}},
		{"binding-selector-wrong-label", func(_ *admissionv1.ValidatingAdmissionPolicy, b *admissionv1.ValidatingAdmissionPolicyBinding) {
			b.Spec.MatchResources.NamespaceSelector.MatchLabels = map[string]string{"x": "y"}
		}},
		{"validation-dropped", func(p *admissionv1.ValidatingAdmissionPolicy, _ *admissionv1.ValidatingAdmissionPolicyBinding) {
			p.Spec.Validations = p.Spec.Validations[:len(p.Spec.Validations)-1] // drop the command rule
		}},
		{"variable-added", func(p *admissionv1.ValidatingAdmissionPolicy, _ *admissionv1.ValidatingAdmissionPolicyBinding) {
			p.Spec.Variables = append(p.Spec.Variables, admissionv1.Variable{Name: "sneak", Expression: "true"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, b := ExpectedContract()
			tc.mutate(p, b)
			v := verifierOver(fakeClient(p, b), Config{})
			err := v.Verify(context.Background())
			ok, why := v.Available(managedLabels())
			if err == nil || ok {
				t.Fatalf("unsafe enforcement accepted: Verify=%v Available=%v reason=%q", err, ok, why)
			}
		})
	}
	// Positive control: the unmutated trusted contract verifies and is available.
	p, b := ExpectedContract()
	v := verifierOver(fakeClient(p, b), Config{})
	if err := v.Verify(context.Background()); err != nil {
		t.Fatalf("positive control must verify: %v", err)
	}
	if ok, why := v.Available(managedLabels()); !ok {
		t.Fatalf("positive control must be available: %s", why)
	}
}

// --- absent objects + SSAR failures ------------------------------------------------------

func TestAbsentAndSSARFailures(t *testing.T) {
	t.Run("policy-absent", func(t *testing.T) {
		_, b := ExpectedContract()
		v := verifierOver(fakeClient(nil, b), Config{})
		if err := v.Verify(context.Background()); err == nil {
			t.Fatal("absent policy must fail")
		}
	})
	t.Run("binding-absent", func(t *testing.T) {
		p, _ := ExpectedContract()
		v := verifierOver(fakeClient(p, nil), Config{})
		if err := v.Verify(context.Background()); err == nil {
			t.Fatal("absent binding must fail")
		}
	})
	t.Run("ssar-deny", func(t *testing.T) {
		p, b := ExpectedContract()
		cs := fakeClient(p, b)
		cs.PrependReactor("create", "selfsubjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, &authorizationv1.SelfSubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: false}}, nil
		})
		v := verifierOver(cs, Config{})
		if err := v.Verify(context.Background()); err == nil {
			t.Fatal("SSAR deny must fail (read grant absent)")
		}
	})
	t.Run("ssar-error-unknown", func(t *testing.T) {
		p, b := ExpectedContract()
		cs := fakeClient(p, b)
		cs.PrependReactor("create", "selfsubjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("apiserver blip")
		})
		v := verifierOver(cs, Config{})
		if err := v.Verify(context.Background()); err == nil {
			t.Fatal("SSAR error (unknown) must fail-closed")
		}
	})
}

// --- TTL expiry --------------------------------------------------------------------------

func TestTTLExpiry(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1000, 0)}
	p, b := ExpectedContract()
	v := verifierOver(fakeClient(p, b), Config{TTL: 30 * time.Second, Now: clock.now})
	if err := v.Verify(context.Background()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	clock.advance(29 * time.Second)
	if ok, _ := v.Available(managedLabels()); !ok {
		t.Fatal("must still be available just before TTL")
	}
	clock.advance(2 * time.Second)
	if ok, why := v.Available(managedLabels()); ok {
		t.Fatalf("must be unavailable after TTL (%s)", why)
	}
}

// --- epoch interleaving ------------------------------------------------------------------

func TestInvalidationMidVerifyDiscardsInFlightSuccess(t *testing.T) {
	p, b := ExpectedContract()
	cs := fakeClient(p, b)
	v := verifierOver(cs, Config{})
	// A concurrent invalidation fires while this verify reads the binding. The read returns
	// valid content, but the publish MUST be discarded because the epoch advanced.
	cs.PrependReactor("get", "validatingadmissionpolicybindings", func(ktesting.Action) (bool, runtime.Object, error) {
		v.Invalidate("external enforcement weakened mid-verify")
		return false, nil, nil // fall through to the tracker (returns the stored binding)
	})
	if err := v.Verify(context.Background()); err == nil {
		t.Fatal("verify racing a mid-flight invalidation must not report a published success")
	}
	if ok, _ := v.Available(managedLabels()); ok {
		t.Fatal("a stale in-flight success must not clear a later invalidation")
	}
}

func TestInvalidateThenFreshVerifyRecovers(t *testing.T) {
	p, b := ExpectedContract()
	v := verifierOver(fakeClient(p, b), Config{})
	if err := v.Verify(context.Background()); err != nil {
		t.Fatalf("initial verify: %v", err)
	}
	v.Invalidate("simulated read timeout")
	if ok, _ := v.Available(managedLabels()); ok {
		t.Fatal("must be unavailable immediately after an invalidation")
	}
	if err := v.Verify(context.Background()); err != nil {
		t.Fatalf("fresh verify after timeout must recover: %v", err)
	}
	if ok, why := v.Available(managedLabels()); !ok {
		t.Fatalf("must recover after a fresh successful verify (%s)", why)
	}
}

// --- FinalCheck reads LIVE namespace scope (stale-label bypass closed) --------------------

func managedNS(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{ManagedLabelKey: ManagedLabelVal}}}
}

func TestFinalCheckRejectsNamespaceLabelRemovedSinceSnapshot(t *testing.T) {
	ctx := context.Background()
	p, b := ExpectedContract()
	ns := managedNS("managed-fixture")
	cs := fakeClient(p, b, ns)
	v := verifierOver(cs, Config{})

	if ok, why := v.FinalCheck(ctx, "managed-fixture"); !ok {
		t.Fatalf("initial legitimate control must pass: %s", why)
	}
	// Remove the managed label live, then FinalCheck must reject AND must have read the
	// namespace fresh (a stale snapshot label cannot authorize the submit).
	ns.Labels = map[string]string{}
	if _, err := cs.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	cs.ClearActions()
	ok, why := v.FinalCheck(ctx, "managed-fixture")
	reads := 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "get" && a.GetResource().Resource == "namespaces" {
			reads++
		}
	}
	if ok {
		t.Fatalf("stale scope authorized submit after label removed: reason=%q", why)
	}
	if reads == 0 {
		t.Fatal("FinalCheck must read the namespace LIVE (zero fresh namespace GETs)")
	}
}

func TestFinalCheckNamespaceAbsentFailsClosed(t *testing.T) {
	p, b := ExpectedContract()
	v := verifierOver(fakeClient(p, b), Config{}) // no namespace object
	if ok, why := v.FinalCheck(context.Background(), "ghost"); ok {
		t.Fatalf("absent namespace must be out of scope (fail-closed), got ok (%s)", why)
	}
}

// apiDefaulted mirrors what the real API server ADDS to the committed manifest on write:
// matchPolicy=Equivalent, empty namespace/object selectors, rule scope "*". (Confirmed by a
// server-side dry-run: evidence/p3/rev2/api-defaulted-objects.json.)
func apiDefaulted() (*admissionv1.ValidatingAdmissionPolicy, *admissionv1.ValidatingAdmissionPolicyBinding) {
	p, b := ExpectedContract()
	eq := admissionv1.Equivalent
	all := admissionv1.AllScopes
	p.Spec.MatchConstraints.MatchPolicy = &eq
	p.Spec.MatchConstraints.NamespaceSelector = &metav1.LabelSelector{}
	p.Spec.MatchConstraints.ObjectSelector = &metav1.LabelSelector{}
	p.Spec.MatchConstraints.ResourceRules[0].Scope = &all
	b.Spec.MatchResources.MatchPolicy = &eq
	b.Spec.MatchResources.ObjectSelector = &metav1.LabelSelector{}
	return p, b
}

// The actual server-defaulted object must be ACCEPTED (defaults canonicalized on both sides),
// or the verifier would refuse a legitimately-installed policy and never enable code-exec.
func TestServerDefaultedContractAccepted(t *testing.T) {
	p, b := apiDefaulted()
	if why := validatePolicyContent(p); why != "" {
		t.Fatalf("server-defaulted policy rejected: %s", why)
	}
	if why := validateBindingContent(b); why != "" {
		t.Fatalf("server-defaulted binding rejected: %s", why)
	}
	v := verifierOver(fakeClient(p, b), Config{})
	if err := v.Verify(context.Background()); err != nil {
		t.Fatalf("server-defaulted install must verify: %v", err)
	}
}

// A Cluster-scoped rule cannot protect namespaced pods; filling defaults must NOT erase an
// explicit incompatible scope, so it is rejected (scope "*"/Namespaced default is fine).
func TestClusterScopeRejected(t *testing.T) {
	p, b := ExpectedContract()
	cluster := admissionv1.ClusterScope
	p.Spec.MatchConstraints.ResourceRules[0].Scope = &cluster
	v := verifierOver(fakeClient(p, b), Config{})
	if err := v.Verify(context.Background()); err == nil {
		t.Fatal("a Cluster-scoped rule must be rejected (cannot cover namespaced pods)")
	}
}

// An invalidation observed DURING the final namespace read (a concurrent poll seeing the policy
// weakened) must void the submit even though the labels read back valid.
func TestFinalCheckInvalidationDuringScopeReadStopsSubmit(t *testing.T) {
	p, b := ExpectedContract()
	cs := fakeClient(p, b, managedNS("managed-fixture"))
	v := verifierOver(cs, Config{})
	cs.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		v.Invalidate("concurrent poll observed policy removed during final namespace read")
		return false, nil, nil // fall through: labels read back valid
	})
	if ok, why := v.FinalCheck(context.Background(), "managed-fixture"); ok {
		t.Fatalf("FinalCheck must not authorize after an invalidation observed during the read: %s", why)
	}
	if avail, _ := v.Status(); avail {
		t.Fatal("global status must be unavailable after the observed invalidation")
	}
}

// A namespace read failure (incl. a deadline) is a partial read: it must invalidate global
// state (bump the epoch), not merely refuse this one call.
func TestFinalCheckNamespaceReadFailureInvalidates(t *testing.T) {
	p, b := ExpectedContract()
	cs := fakeClient(p, b)
	v := verifierOver(cs, Config{})
	cs.PrependReactor("get", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, context.DeadlineExceeded
	})
	before := v.epoch.Load()
	ok, _ := v.FinalCheck(context.Background(), "managed-fixture")
	avail, _ := v.Status()
	if ok || avail || v.epoch.Load() == before {
		t.Fatalf("a partial read failure must invalidate: FinalCheck=%v Available=%v epochBefore=%d epochAfter=%d", ok, avail, before, v.epoch.Load())
	}
}

// --- fakeClock ---------------------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}
