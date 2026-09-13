/*
 * M-163: the runtime tick's capability wiring.
 *
 * The tick composes TWO collaborators from one per-tick witness: the reviewing gate for the
 * production evaluation and the observation-only gate for the counterfactual. These tests
 * exercise the exact closures the runtime uses, so the shadow arm cannot regress into issuing
 * SelfSubjectAccessReviews or into losing a local gate leg.
 */

package runner

import (
	"context"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

type m163CountingSAR struct {
	allowed bool
	calls   int
}

func (s *m163CountingSAR) Create(_ context.Context, sar *authorizationv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error) {
	s.calls++
	sar.Status.Allowed = s.allowed
	return sar, nil
}

// m163SupportedBackend is an EXPLICIT support double: a backend that implements every
// action for every target.
//
// The capability gate is cheapest-first and the RBAC leg is LAST, so an earlier leg that
// excludes the action makes these tests assert nothing about authorization. M-21 makes an
// ABSENT backend fail closed for every action — a nil actuator has no hands, so it cannot
// establish support — which would exclude rotate one leg too early. Wiring a real support
// double keeps the whole witness/cache chain intact and leaves the deciding leg where these
// tests need it. No gate is weakened: the backend answers only "could this backend enact this
// action", and the RBAC leg still runs afterwards and still decides.
//
// It is deliberately NOT named after the M-21 double in this package: both must be able to
// exist side by side in the composed tree. The actuator.Actuator interface is identical
// before and after M-21, so this compiles and behaves the same on either source.
type m163SupportedBackend struct{}

func (m163SupportedBackend) Name() string { return "m163-supported-backend" }

func (m163SupportedBackend) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }

func (m163SupportedBackend) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return actuator.Result{}, nil
}

func (m163SupportedBackend) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}

func m163AuthzWitness(sar authz.SSARClient) capability.Witness {
	az := authz.NewCheckerWithClient(sar, time.Hour)
	return capability.BuildWitness(context.Background(), capability.BuildIndex(nil, nil, nil),
		nil, az, m163SupportedBackend{})
}

func m163RotateView() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "victim"}}
}

func noQualified(*model.WorkloadView) bool { return false }

// m163RequireRotateReachesRBAC fails loudly if any leg BEFORE authorization decides rotate on
// this witness, so a gate change cannot quietly turn the tests below into assertions about
// some other leg. The witness under test carries a live SSAR checker, so the probe uses an
// equivalent witness with NO checker: a verdict there means an earlier leg is deciding.
func m163RequireRotateReachesRBAC(t *testing.T) {
	t.Helper()
	if verbs := actuator.RequiredVerbs(model.ActionRotate); len(verbs) == 0 {
		t.Fatal("fixture stale: rotate declares no required verbs, so the RBAC leg cannot fire")
	}
	w := capability.BuildWitness(context.Background(), capability.BuildIndex(nil, nil, nil),
		nil, nil, m163SupportedBackend{})
	v := m163RotateView()
	if ok, why := w.Capable(v, model.ActionRotate); !ok {
		t.Fatalf("fixture stale: the capability leg excludes rotate (%q), so the RBAC leg is unreachable", why)
	}
	if r := w.Eligible(v, model.ActionRotate, []string{"cover-key"}); r != nil {
		t.Fatalf("fixture stale: rotate is excluded before the RBAC leg (kind=%q detail=%q); "+
			"these tests would assert nothing about authorization", r.Kind, r.Detail)
	}
}

// The observation-only closure must never reach the apiserver, and must not resolve absent
// evidence into an allow: it reports the existing RBAC-unknown fail-open instead.
func TestM163_ObservedEligibilityIssuesNoReview(t *testing.T) {
	m163RequireRotateReachesRBAC(t)
	sar := &m163CountingSAR{allowed: true}
	wit := m163AuthzWitness(sar)

	got := codeExecAwareEligibilityObserved(wit, false, noQualified, m163RotateView(), model.ActionRotate, []string{"cover-key"})
	if sar.calls != 0 {
		t.Fatalf("the observation-only closure issued %d SelfSubjectAccessReviews", sar.calls)
	}
	if got == nil {
		t.Fatal("unobserved authorization was reported as plainly eligible; it must be flagged RBAC-unknown")
	}
	if got.Excluded {
		t.Fatalf("unobserved authorization EXCLUDED the action; the existing policy is fail-open: %+v", got)
	}
	if !got.RBACUnknown {
		t.Fatalf("unobserved authorization was not flagged RBAC-unknown: %+v", got)
	}

	// The reviewing closure, on the same witness, still does the real review.
	if got := codeExecAwareEligibility(wit, false, noQualified, m163RotateView(), model.ActionRotate, []string{"cover-key"}); got != nil {
		t.Fatalf("an allowed rotate must be eligible on the reviewing path, got %+v", got)
	}
	if sar.calls != 1 {
		t.Fatalf("the reviewing closure issued %d reviews, want 1", sar.calls)
	}

	// And now that production HAS reviewed, the observation-only closure reads that answer.
	if got := codeExecAwareEligibilityObserved(wit, false, noQualified, m163RotateView(), model.ActionRotate, []string{"cover-key"}); got != nil {
		t.Fatalf("a current cached allow must read as eligible, got %+v", got)
	}
	if sar.calls != 1 {
		t.Fatalf("the observation-only closure re-reviewed current evidence: %d calls", sar.calls)
	}
}

// A cached DENY is measured evidence and still excludes on the observation-only path, with
// the same attribution class the record carries on the real path.
func TestM163_ObservedEligibilityStillHonoursACachedDeny(t *testing.T) {
	m163RequireRotateReachesRBAC(t)
	sar := &m163CountingSAR{allowed: false}
	wit := m163AuthzWitness(sar)

	if got := codeExecAwareEligibility(wit, false, noQualified, m163RotateView(), model.ActionRotate, []string{"cover-key"}); got == nil || !got.Excluded {
		t.Fatalf("precondition: a denied rotate must be excluded on the reviewing path, got %+v", got)
	}
	got := codeExecAwareEligibilityObserved(wit, false, noQualified, m163RotateView(), model.ActionRotate, []string{"cover-key"})
	if got == nil || !got.Excluded || got.Kind != capability.ReasonNoRBAC {
		t.Fatalf("a cached deny must still exclude with the no-rbac class, got %+v", got)
	}
	if sar.calls != 1 {
		t.Fatalf("the observation-only closure issued a review: %d calls", sar.calls)
	}
}

// The local legs are NOT skipped on the shadow path, and the M99 precedence is preserved:
// a code-exec move with unverified admission is excluded by the code-exec leg in BOTH modes
// and can never be re-admitted by the qualified-outcome fallback.
func TestM163_ObservedEligibilityKeepsTheLocalLegsAndM99Precedence(t *testing.T) {
	wit := unverifiedCodeExecWitness()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "victim"}}
	qualified := func(*model.WorkloadView) bool { return true }

	for _, action := range []model.Action{model.ActionDebugger, model.ActionCustomInject} {
		got := codeExecAwareEligibilityObserved(wit, true, qualified, v, action, []string{"cover-key"})
		if got == nil || !got.Excluded || got.Kind != capability.ReasonCodeExec {
			t.Fatalf("%s must stay excluded by the code-exec leg on the shadow path, got %+v", action, got)
		}
	}
	// The no-cover leg is local too.
	if got := codeExecAwareEligibilityObserved(wit, false, noQualified, v, model.ActionRotate, nil); got == nil ||
		!got.Excluded || got.Kind != capability.ReasonNoCover {
		t.Fatalf("the no-cover leg was skipped on the shadow path, got %+v", got)
	}
	// The M99 no-rbac marker still applies when the full gate returns eligible.
	if got := codeExecAwareEligibilityObserved(wit, true, qualified, v, model.ActionRotate, []string{"cover-key"}); got == nil ||
		!got.Excluded || got.Kind != capability.ReasonNoRBAC {
		t.Fatalf("the M99 fallback did not apply on the shadow path, got %+v", got)
	}
}

// The tick must install BOTH collaborators. Wiring only the reviewing one would silently
// disable the shadow arm; wiring only the observing one would disable production's real RBAC
// check. This exercises the exact function the tick calls.
func TestM163_TickWiresBothCapabilityGates(t *testing.T) {
	m163RequireRotateReachesRBAC(t)
	sar := &m163CountingSAR{allowed: true}
	wit := m163AuthzWitness(sar)
	ce := decision.NewCoverageEngine()

	wireCapabilityGates(ce, wit, false, noQualified)
	if ce.Capability == nil {
		t.Fatal("the tick did not wire the production capability gate")
	}
	if ce.ShadowCapability == nil {
		t.Fatal("the tick did not wire the read-only shadow capability gate")
	}

	v := m163RotateView()
	if got := ce.ShadowCapability(v, model.ActionRotate, []string{"cover-key"}); got == nil || !got.RBACUnknown {
		t.Fatalf("the wired shadow gate is not the observation-only one: %+v", got)
	}
	if sar.calls != 0 {
		t.Fatalf("the wired shadow gate issued %d SelfSubjectAccessReviews", sar.calls)
	}
	if got := ce.Capability(v, model.ActionRotate, []string{"cover-key"}); got != nil {
		t.Fatalf("the wired production gate did not perform the real review: %+v", got)
	}
	if sar.calls != 1 {
		t.Fatalf("the wired production gate issued %d reviews, want 1", sar.calls)
	}
}

// Both modes must agree wherever authorization is not the deciding leg, so the shadow's
// comparison stays meaningful rather than silently diverging on local state.
func TestM163_ObservedAndReviewingAgreeOnTheLocalLegs(t *testing.T) {
	m163RequireRotateReachesRBAC(t)
	sar := &m163CountingSAR{allowed: true}
	wit := m163AuthzWitness(sar)
	v := m163RotateView()

	// Prime the cache so authorization is current for both.
	codeExecAwareEligibility(wit, false, noQualified, v, model.ActionRotate, []string{"cover-key"})

	for _, action := range []model.Action{
		model.ActionRotate, model.ActionQuarantine, model.ActionWarmSwap, model.ActionMIGRebind,
		model.ActionKVReset, model.ActionEndpointRotate, model.ActionAdapterRotate,
	} {
		want := codeExecAwareEligibility(wit, false, noQualified, v, action, []string{"cover-key"})
		got := codeExecAwareEligibilityObserved(wit, false, noQualified, v, action, []string{"cover-key"})
		switch {
		case want == nil && got == nil:
		case want == nil || got == nil:
			t.Fatalf("%s: reviewing=%+v observed=%+v", action, want, got)
		case *want != *got:
			t.Fatalf("%s: reviewing=%+v observed=%+v", action, *want, *got)
		}
	}
}
