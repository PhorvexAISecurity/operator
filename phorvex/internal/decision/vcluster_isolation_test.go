/*
 * Phorvex — P-VCLUSTER O2/O4 co-resident adversarial isolation tests. The cross-tenant attacker is the
 * decoy-flood / λ-pump pattern the production RL red-team discovered. These run on the POST-refactor
 * engine with tenants A and B CO-RESIDENT in ONE engine, and prove tenant B's decision stream is
 * EXACTLY byte-identical with vs without tenant A's adversarial activity (delta == 0, not "bounded").
 */

package decision

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func vtClock() func() time.Time { return func() time.Time { return time.Unix(1_700_000_000, 0).UTC() } }

func vtPol(tenant string) model.Policy { p := covPolicy(2); p.Tenant = tenant; return p }

func vtBFleet() []*model.WorkloadView {
	return []*model.WorkloadView{
		covView("b-crown", true, 3*time.Hour, false),
		lowValueView("b-cheap1"),
		lowValueView("b-cheap2"),
	}
}

// vtDecoyFleet is tenant A's adversarial decoy flood (manufactured high-coverage fresh pods — the
// dispersion-steer / λ-pump attack), in A's own namespace.
func vtDecoyFleet(ns string, n int) []*model.WorkloadView {
	out := make([]*model.WorkloadView, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &model.WorkloadView{
			Pod: model.Pod{
				Namespace: ns, Name: fmt.Sprintf("decoy%d", i), UID: fmt.Sprintf("u-%s-%d", ns, i),
				DesiredReplicas: 3, ReadyReplicas: 3, Ready: true,
			},
			Phase:              model.PhaseWarm,
			BlastRadius:        0.9,
			ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 5 * time.Hour},
		})
	}
	return out
}

func vtFingerprint(b *strings.Builder, decs []model.Decision) {
	for _, d := range decs {
		fmt.Fprintf(b, "%s/%s act=%s sel=%v pd=%.9f lam=%.9f cw=%.9f net=%.9f\n",
			d.Namespace, d.Pod, d.Action, d.Selected, d.PerDollar, d.Lambda, d.CoveredWeight, d.Net)
	}
}

// O2 — λ NON-INFLUENCE. Tenant A floods decoys to pump ITS OWN λ; tenant B's decision stream must be
// byte-identical to a run where A is absent. Co-resident, exact-zero.
func TestO2_LambdaNonInfluenceExactZero(t *testing.T) {
	bStream := func(floodA bool) string {
		e := NewCoverageEngine()
		e.Now = vtClock()
		aViews := vtDecoyFleet("ns-a", 12)
		var b strings.Builder
		for tick := 0; tick < 8; tick++ {
			if floodA {
				e.Decide(aViews, vtPol("A")) // A pumps its OWN bucket's λ
			}
			vtFingerprint(&b, e.Decide(vtBFleet(), vtPol("B")))
		}
		return b.String()
	}
	control := bStream(false) // B alone
	treat := bStream(true)    // B co-resident with A's decoy flood
	if control != treat {
		t.Errorf("O2 LEAK: tenant A's decoy flood changed tenant B's decisions — cross-tenant λ delta is NOT exactly zero.\n--- B alone ---\n%s\n--- B + A flood ---\n%s", control, treat)
	}
}

// O4 — RLS/CONFORMAL NON-INFLUENCE (pre-emptive). Tenant A's measured rotations (ObserveRotation, the
// latent shared-learning channel) fire heavily on the co-resident engine; tenant B's cost-based
// decisions must be byte-identical. Proves the live-wired calibrators remain per-tenant.
func TestO4_RLSConformalNonInfluenceExactZero(t *testing.T) {
	bAlone := func() string {
		e := NewCoverageEngine()
		e.Now = vtClock()
		var b strings.Builder
		for tick := 0; tick < 8; tick++ {
			vtFingerprint(&b, e.Decide(vtBFleet(), vtPol("B")))
		}
		return b.String()
	}
	control := bAlone()

	e := NewCoverageEngine()
	e.Now = vtClock()
	aView := covView("a-expensive", true, 3*time.Hour, true) // a GPU/expensive A workload
	for i := 0; i < 50; i++ {
		e.costFor("A").ObserveRotation(aView, 9.0) // A's RLS/Conformal bucket absorbs costly rotations
	}
	var b strings.Builder
	for tick := 0; tick < 8; tick++ {
		vtFingerprint(&b, e.Decide(vtBFleet(), vtPol("B")))
	}
	if control != b.String() {
		t.Errorf("O4 LEAK: tenant A's measured rotations (RLS/Conformal) changed tenant B's cost-based decisions.\n--- B alone ---\n%s\n--- B after A's rotations ---\n%s", control, b.String())
	}
}

func TestObserveRotationUpdatesOnlyItsTenantBucket(t *testing.T) {
	e := NewCoverageEngine()
	v := covView("observed", false, 3*time.Hour, false)
	v.Phase = model.PhaseWarm
	pol := vtPol("A")
	move := model.Move{Action: model.ActionRotate}

	a := e.costFor("A")
	before := a.ECost(v, move, pol)
	e.ObserveRotation("A", v, 0.05)
	after := a.ECost(v, move, pol)
	if !a.RLS.Primed() || after == before {
		t.Fatalf("tenant A rotation feedback did not reach its RLS: primed=%v before=%v after=%v", a.RLS.Primed(), before, after)
	}
	if e.costFor("B").RLS.Primed() {
		t.Fatal("tenant A rotation feedback primed tenant B's isolated RLS bucket")
	}
}

func TestObservedTenantCostFeedsGeneratedCandidates(t *testing.T) {
	e := NewCoverageEngine()
	_ = e.costFor("A") // make the legacy scalar belong to another tenant
	v := covView("b-observed", false, 3*time.Hour, false)
	pol := vtPol("B")

	rotateCost := func() float64 {
		set, _ := e.AssembleSet([]*model.WorkloadView{v}, pol)
		for _, candidate := range set.Candidates {
			if candidate.Action == model.ActionRotate {
				return candidate.ECost
			}
		}
		t.Fatal("rotate candidate missing from feasible action set")
		return 0
	}
	before := rotateCost()
	e.ObserveRotation("B", v, 0.05)
	after := rotateCost()
	if after == before {
		t.Fatalf("tenant B learned cost did not reach generated candidates: before=%v after=%v", before, after)
	}
}
