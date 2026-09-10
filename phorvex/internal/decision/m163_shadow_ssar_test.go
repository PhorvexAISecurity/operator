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

// m163WireGate composes the engine's two gate collaborators from ONE real per-tick witness,
// exactly as the runtime tick does: the reviewing gate for production, the observation-only
// gate for the counterfactual.
func m163WireGate(e *CoverageEngine, az *authz.Checker) {
	w := capability.BuildWitness(context.Background(), capability.BuildIndex(nil, nil, nil), nil, az, nil)
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

// The fixture only means something if rotate actually requires RBAC verbs.
func TestM163_RotateReachesTheAuthorizationLeg(t *testing.T) {
	if verbs := actuator.RequiredVerbs(model.ActionRotate); len(verbs) == 0 {
		t.Fatal("fixture stale: rotate declares no required verbs, so the RBAC leg cannot fire")
	}
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
		})
	}
}

// Production's decision must be identical whether or not shadows ran — the same invariant as
// the stage clock, now across the authorization path.
func TestM163_ShadowsDoNotChangeTheAuthorizedProductionDecision(t *testing.T) {
	snap := m163Snapshot(t)
	pol := m163AuthzPolicy()

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

	rbacUnknownInTrace := func(t *testing.T, d model.Decision) bool {
		t.Helper()
		if d.Trace == nil {
			t.Fatal("fixture: trace disabled")
		}
		for _, status := range d.Trace.ActionStatus {
			if status.Action == string(model.ActionRotate) {
				return status.RBACUnknown
			}
		}
		return false
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
	if d := m163Decide(t, e, snap, pol); d[0].Selected {
		t.Fatalf("production was affected by the unavailable shadow: %+v", d[0])
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
