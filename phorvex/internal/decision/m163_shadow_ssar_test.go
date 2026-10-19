/*
 * M-163 head regressions at the RUNTIME AUTHORIZATION BOUNDARY.
 *
 * The producers are the real ones the runtime composes: CoverageEngine ->
 * capability.Witness -> authz.Checker -> SelfSubjectAccessReview, with only the apiserver
 * client faked (an SSAR is an apiserver write; there is no offline way to issue a real one).
 * The verb set comes from actuator.RequiredVerbs, so a routing/permission change to that set
 * moves the reviewing and the observation-only path together.
 *
 * The defect: a counterfactual evaluation reached Witness.Eligible -> Checker.Allowed ->
 * SSAR Create and CACHED the answer. A later production evaluation then read the shadow's
 * cached allow instead of reviewing the authorization that had since been denied, and
 * selected an action the operator was no longer permitted to take. Isolation here is
 * therefore not only about counters: it decides a production gate.
 */

package decision

import (
	"context"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/capability"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// m163SSAR is the fake apiserver: it records every review and answers with whatever the
// external authorization state currently is.
type m163SSAR struct {
	allowed bool
	calls   int
}

func (s *m163SSAR) Create(_ context.Context, sar *authorizationv1.SelfSubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error) {
	s.calls++
	sar.Status.Allowed = s.allowed
	return sar, nil
}

// m163AuthzPolicy isolates the authorization decision from the unrelated conformal-SLO veto
// and the proactive-cadence cap, so a change in the selected action is attributable to the
// gate under test.
func m163AuthzPolicy() model.Policy {
	pol := m163Policy()
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
	pol.Lambda = 0
	pol.ProactiveFloor = time.Minute
	pol.CostCeiling = 10
	return pol
}

// m163SupportedBackend is an EXPLICIT support double: a backend that implements every
// action for every target.
//
// It is not decoration. The capability gate is cheapest-first and the RBAC leg is LAST, so
// every earlier leg must be satisfied or the candidate never reaches the authorization
// predicate these tests exist to exercise. M-21 makes an ABSENT backend fail closed for every
// action (a nil actuator can enact nothing, so it cannot establish support), which would
// exclude rotate one leg too early and leave these tests asserting nothing about
// authorization at all. Wiring a real support double keeps the whole witness/cache/engine
// chain intact and moves the deciding leg back to where it belongs. It does not weaken any
// gate: the backend answers only "could this backend enact this action", and the RBAC leg
// still runs afterwards and still decides.
//
// The actuator.Actuator interface is identical before and after M-21, so this double
// compiles and behaves the same on the individual and the composed source.
type m163SupportedBackend struct{}

func (m163SupportedBackend) Name() string { return "m163-supported-backend" }

func (m163SupportedBackend) EnsurePolicy(context.Context, actuator.TenantTarget) error { return nil }

func (m163SupportedBackend) Actuate(context.Context, actuator.Request) (actuator.Result, error) {
	return actuator.Result{}, nil
}

func (m163SupportedBackend) SupportsAction(context.Context, model.Action, actuator.Target) (bool, string) {
	return true, ""
}

// m163Witness builds the per-tick witness these tests share: real index, real SSAR checker,
// and the explicit support double above.
func m163Witness(az *authz.Checker) capability.Witness {
	return capability.BuildWitness(context.Background(), capability.BuildIndex(nil, nil, nil),
		nil, az, localActuator(m163SupportedBackend{}))
}

// m163WireGate composes the engine's two gate collaborators from ONE real per-tick witness,
// exactly as the runtime tick does: the reviewing gate for production, the observation-only
// gate for the counterfactual.
func m163WireGate(e *CoverageEngine, az *authz.Checker) {
	w := m163Witness(az)
	adapt := func(r *capability.Reason) *actionset.Eligibility {
		if r == nil {
			return nil
		}
		return &actionset.Eligibility{Excluded: r.Excluded, Kind: r.Kind, Detail: r.Detail, RBACUnknown: r.RBACUnknown}
	}
	e.Capability = func(v *model.WorkloadView, a model.Action, keys []string) *actionset.Eligibility {
		return adapt(w.Eligible(v, a, keys))
	}
	e.ShadowCapability = func(v *model.WorkloadView, a model.Action, keys []string) *actionset.Eligibility {
		return adapt(w.EligibleObserved(v, a, keys))
	}
}

// m163RequireRotateReachesRBAC fails loudly if rotate is stopped by any leg BEFORE the RBAC
// one, so a gate change can never quietly turn the authorization tests below into vacuous
// no-candidate assertions. It is the fixture-relevance guard for this whole file.
func m163RequireRotateReachesRBAC(t *testing.T, snap *ingest.Snapshot) {
	t.Helper()
	if verbs := actuator.RequiredVerbs(model.ActionRotate); len(verbs) == 0 {
		t.Fatal("fixture stale: rotate declares no required verbs, so the RBAC leg cannot fire")
	}
	view := m163Views(t, snap)[0]
	// No SSAR checker: every leg EXCEPT authorization runs. A verdict here means an earlier
	// leg is deciding, and the authorization predicate is unreachable.
	w := m163Witness(nil)
	if ok, why := w.Capable(view, model.ActionRotate); !ok {
		t.Fatalf("fixture stale: the capability leg excludes rotate (%q), so the RBAC leg is unreachable", why)
	}
	if r := w.Eligible(view, model.ActionRotate, []string{"cover-key"}); r != nil {
		t.Fatalf("fixture stale: rotate is excluded before the RBAC leg (kind=%q detail=%q); "+
			"these tests would assert nothing about authorization", r.Kind, r.Detail)
	}
}

// m163RotateStatus returns the decision trace's row for rotate. The row carries the
// STRUCTURAL exclusion kind, which is how a test attributes an outcome to a specific gate
// leg rather than to a reason string.
func m163RotateStatus(t *testing.T, d model.Decision) (model.DecisionActionStatusV3, bool) {
	t.Helper()
	if d.Trace == nil {
		t.Fatal("fixture: trace disabled, so no gate can be attributed")
	}
	for _, status := range d.Trace.ActionStatus {
		if status.Action == string(model.ActionRotate) {
			return status, true
		}
	}
	return model.DecisionActionStatusV3{}, false
}

// The fixture only means something if rotate actually reaches the authorization leg.
func TestM163_RotateReachesTheAuthorizationLeg(t *testing.T) {
	m163RequireRotateReachesRBAC(t, m163Snapshot(t))
}

// The incident, at the runtime boundary. A shadow must issue no review and cache nothing, so
// the production gate that follows still sees the CURRENT external authorization.
func TestM163_ShadowDoesNotCacheAuthorizationForTheProductionGate(t *testing.T) {
	for _, tc := range []struct {
		name            string
		shadowFirst     bool
		productionAllow bool
	}{
		{"denied-no-shadow-control", false, false},
		{"allowed-production-positive-control", false, true},
		{"shadow-must-not-decide-the-production-gate", true, false},
		{"shadow-must-not-suppress-an-allowed-production", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := m163Snapshot(t)
			pol := m163AuthzPolicy()
			pol.TraceEnabled = true
			m163RequireRotateReachesRBAC(t, snap)

			// External authorization ALLOWS while the shadow runs...
			sar := &m163SSAR{allowed: true}
			az := authz.NewCheckerWithClient(sar, time.Hour)
			e := m163Engine(t)
			m163WireGate(e, az)

			if tc.shadowFirst {
				if _, err := e.DecideShadowChecked(m163Views(t, snap), pol); err != nil {
					t.Fatalf("shadow decide: %v", err)
				}
				if sar.calls != 0 {
					t.Fatalf("the shadow issued %d SelfSubjectAccessReviews and populated the operational cache", sar.calls)
				}
			}

			// ...and is the test's real answer by the time production evaluates.
			sar.allowed = tc.productionAllow
			decisions := m163Decide(t, e, snap, pol)
			if len(decisions) != 1 {
				t.Fatalf("got %d decisions, want 1", len(decisions))
			}
			d := decisions[0]
			if d.Selected != tc.productionAllow {
				t.Fatalf("production selected=%v want=%v (action=%s reason=%q) after shadow=%v",
					d.Selected, tc.productionAllow, d.Action, d.Reason, tc.shadowFirst)
			}
			if sar.calls != 1 {
				t.Fatalf("production issued %d reviews, want exactly the 1 it needs", sar.calls)
			}
			// Attribution: the outcome must be the AUTHORIZATION leg's, not an earlier gate's.
			// Without this, a change that excludes rotate for some other reason would satisfy
			// the deny cases above while proving nothing about the cache.
			status, ok := m163RotateStatus(t, d)
			if !ok {
				t.Fatalf("rotate is absent from the decision trace, so no gate can be attributed: %+v", d.Trace.ActionStatus)
			}
			if tc.productionAllow {
				if status.ExclusionKind == capability.ReasonNoRBAC {
					t.Fatalf("an allowed rotate was excluded by the RBAC leg: %+v", status)
				}
			} else if status.ExclusionKind != capability.ReasonNoRBAC {
				t.Fatalf("the denied rotate was excluded by %q, not by the RBAC leg; the fixture "+
					"is no longer exercising the authorization predicate: %+v", status.ExclusionKind, status)
			}
		})
	}
}

// Production's decision must be identical whether or not shadows ran — the same invariant as
// the stage clock, now across the authorization path.
func TestM163_ShadowsDoNotChangeTheAuthorizedProductionDecision(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163AuthzPolicy()
	pol.TraceEnabled = true
	m163RequireRotateReachesRBAC(t, snap)

	run := func(shadows int) []model.Decision {
		sar := &m163SSAR{allowed: true}
		az := authz.NewCheckerWithClient(sar, time.Hour)
		e := m163Engine(t)
		m163WireGate(e, az)
		for i := 0; i < shadows; i++ {
			if _, err := e.DecideShadowChecked(m163Views(t, snap), pol); err != nil {
				t.Fatalf("shadow decide: %v", err)
			}
		}
		sar.allowed = false // the operator's grant is revoked before the real tick
		return m163Decide(t, e, snap, pol)
	}

	control := run(0)
	// The control must be a REVOKED-authorization outcome attributed to the RBAC leg, or the
	// comparison below would hold trivially for any number of shadows.
	if status, ok := m163RotateStatus(t, control[0]); !ok || status.ExclusionKind != capability.ReasonNoRBAC {
		t.Fatalf("the no-shadow control was not decided by the RBAC leg (found=%v %+v); "+
			"the comparison would prove nothing about authorization", ok, status)
	}
	for _, n := range []int{1, 3, 7} {
		if got := run(n); got[0].Selected != control[0].Selected || got[0].Action != control[0].Action ||
			got[0].InfeasibleWhy != control[0].InfeasibleWhy {
			t.Fatalf("%d shadows changed the authorized production decision:\n control: %+v\n subject: %+v",
				n, control[0], got[0])
		}
	}
}

// The shadow's own verdict across the three cache states. Absent and expired evidence are
// reported as RBAC-UNKNOWN — the existing fail-open, flagged and not excluded — never as an
// invented allow; current evidence is read exactly as production reads it.
func TestM163_ShadowVerdictAcrossCacheStates(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163AuthzPolicy()
	pol.TraceEnabled = true
	m163RequireRotateReachesRBAC(t, snap)

	rbacUnknownInTrace := func(t *testing.T, d model.Decision) bool {
		t.Helper()
		status, ok := m163RotateStatus(t, d)
		if !ok {
			t.Fatalf("rotate is absent from the decision trace: %+v", d.Trace.ActionStatus)
		}
		// An exclusion by any EARLIER leg means the authorization predicate never ran, so the
		// RBAC-unknown flag below would be meaningless rather than merely false.
		if status.ExclusionKind != "" && status.ExclusionKind != capability.ReasonNoRBAC &&
			status.ExclusionKind != model.ExclusionNone && status.ExclusionKind != model.ExclusionSelection {
			t.Fatalf("rotate was decided by %q before the RBAC leg: %+v", status.ExclusionKind, status)
		}
		return status.RBACUnknown
	}

	t.Run("absent-evidence-is-unknown-not-an-invented-allow", func(t *testing.T) {
		sar := &m163SSAR{allowed: true}
		e := m163Engine(t)
		m163WireGate(e, authz.NewCheckerWithClient(sar, time.Hour))

		shadow, err := e.DecideShadowChecked(m163Views(t, snap), pol)
		if err != nil {
			t.Fatal(err)
		}
		if sar.calls != 0 {
			t.Fatalf("the shadow issued %d reviews", sar.calls)
		}
		if !rbacUnknownInTrace(t, shadow[0]) {
			t.Fatalf("unobserved authorization was not reported as RBAC-unknown: %+v", shadow[0].Trace.ActionStatus)
		}
		if !shadow[0].Feasible {
			t.Fatalf("unobserved authorization EXCLUDED the candidate; the existing policy is fail-open: %q",
				shadow[0].InfeasibleWhy)
		}
	})

	t.Run("current-allow-is-read-as-allowed", func(t *testing.T) {
		sar := &m163SSAR{allowed: true}
		e := m163Engine(t)
		m163WireGate(e, authz.NewCheckerWithClient(sar, time.Hour))

		m163Decide(t, e, snap, pol) // production reviews and caches the allow
		calls := sar.calls
		shadow, err := e.DecideShadowChecked(m163Views(t, snap), pol)
		if err != nil {
			t.Fatal(err)
		}
		if sar.calls != calls {
			t.Fatalf("the shadow re-reviewed current evidence: %d -> %d", calls, sar.calls)
		}
		if rbacUnknownInTrace(t, shadow[0]) {
			t.Fatal("a current cached allow was reported as RBAC-unknown")
		}
		if !shadow[0].Selected {
			t.Fatalf("a current cached allow did not admit the candidate: %+v", shadow[0])
		}
	})

	t.Run("current-deny-still-excludes", func(t *testing.T) {
		sar := &m163SSAR{allowed: false}
		e := m163Engine(t)
		m163WireGate(e, authz.NewCheckerWithClient(sar, time.Hour))

		m163Decide(t, e, snap, pol) // production reviews and caches the deny
		calls := sar.calls
		shadow, err := e.DecideShadowChecked(m163Views(t, snap), pol)
		if err != nil {
			t.Fatal(err)
		}
		if sar.calls != calls {
			t.Fatalf("the shadow re-reviewed a cached deny: %d -> %d", calls, sar.calls)
		}
		if shadow[0].Selected {
			t.Fatal("a cached deny did not exclude the shadow candidate")
		}
	})

	t.Run("expired-evidence-is-unknown-and-production-re-reviews", func(t *testing.T) {
		at := m163Now(t)
		clock := func() time.Time { return at }
		sar := &m163SSAR{allowed: true}
		az := authz.NewCheckerWithClock(sar, time.Minute, func() time.Time { return clock() })
		e := m163Engine(t)
		m163WireGate(e, az)

		m163Decide(t, e, snap, pol) // caches the allow at t0
		if sar.calls != 1 {
			t.Fatalf("precondition: production issued %d reviews, want 1", sar.calls)
		}
		at = at.Add(time.Minute) // the cached allow is no longer current

		shadow, err := e.DecideShadowChecked(m163Views(t, snap), pol)
		if err != nil {
			t.Fatal(err)
		}
		if sar.calls != 1 {
			t.Fatalf("the shadow re-reviewed expired evidence: %d calls", sar.calls)
		}
		if !rbacUnknownInTrace(t, shadow[0]) {
			t.Fatal("expired authorization was not reported as RBAC-unknown")
		}

		// The grant is revoked while the evidence is stale: production must re-review and
		// exclude, unaffected by the shadow that just read the same entry.
		sar.allowed = false
		prod := m163Decide(t, e, snap, pol)
		if sar.calls != 2 {
			t.Fatalf("production issued %d reviews, want 2 (it must re-review expired evidence)", sar.calls)
		}
		if prod[0].Selected {
			t.Fatalf("production selected a revoked action: %+v", prod[0])
		}
	})
}

// The supported-collaborator contract: a reviewing gate without its observation-only twin
// cannot be proven side-effect free, so the COMPARISON is reported unavailable. The engine
// neither runs the impure gate nor drops the gate and compares against a substrate
// production never had — and production is untouched either way.
func TestM163_ShadowWithoutAReadOnlyGateIsUnavailableNotUngated(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163AuthzPolicy()
	pol.TraceEnabled = true
	m163RequireRotateReachesRBAC(t, snap)

	sar := &m163SSAR{allowed: true}
	az := authz.NewCheckerWithClient(sar, time.Hour)
	e := m163Engine(t)
	m163WireGate(e, az)
	e.ShadowCapability = nil // a caller that wired only the reviewing gate

	if _, err := e.DecideShadowChecked(m163Views(t, snap), pol); err != ErrShadowCapabilityUnavailable {
		t.Fatalf("shadow returned %v, want ErrShadowCapabilityUnavailable", err)
	}
	if sar.calls != 0 {
		t.Fatalf("reporting the shadow unavailable still cost %d reviews", sar.calls)
	}

	// Production is unaffected and still reviews for itself.
	sar.allowed = false
	d := m163Decide(t, e, snap, pol)
	if d[0].Selected {
		t.Fatalf("production was affected by the unavailable shadow: %+v", d[0])
	}
	if status, ok := m163RotateStatus(t, d[0]); !ok || status.ExclusionKind != capability.ReasonNoRBAC {
		t.Fatalf("production's exclusion was not the RBAC leg's (found=%v %+v); the fixture is "+
			"no longer reaching the authorization predicate", ok, status)
	}
	if sar.calls != 1 {
		t.Fatalf("production issued %d reviews, want 1", sar.calls)
	}

	// With NO gate wired at all (legacy/offline producers) the substrate is the same in both
	// modes, so the shadow stays available.
	bare := m163Engine(t)
	if _, err := bare.DecideShadowChecked(m163Views(t, snap), pol); err != nil {
		t.Fatalf("an ungated engine must still support a shadow comparison: %v", err)
	}
}
