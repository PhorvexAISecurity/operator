/*
 * Phorvex — P-VCLUSTER O8/O9: fleet-relative physics disclosure bound.
 *  O8 — co-residency reveals at most the COUNT of co-resident tenants, never their IDENTITIES.
 *  O9 — image/model-rarity (and slack) are IDENTITY-FREE bounded magnitudes; the magnitude DOES shift
 *       with fleet composition — a bounded, coarse, DISCLOSED membership-inference residual (same class
 *       as the co-residency count, R2), NOT identity disclosure. Physics is fleet-relative by nature, so
 *       this is bound+disclose, not "non-influence."
 */

package platform

import (
	"testing"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

func snapWith(pods ...model.Pod) *ingest.Snapshot { return &ingest.Snapshot{Pods: pods} }

// O8 — CoResidency is a function of the COUNT only; co-tenant IDENTITIES never affect it.
func TestO8_CoResidencyCountOnlyIdentityFree(t *testing.T) {
	g := genericK8s{}
	// Same COUNT (2 co-tenants), different IDENTITIES.
	a := g.Derive(snapWith(
		model.Pod{Namespace: "X", Name: "x", Node: "n1"},
		model.Pod{Namespace: "alpha", Name: "a", Node: "n1"},
		model.Pod{Namespace: "beta", Name: "b", Node: "n1"},
	))
	b := g.Derive(snapWith(
		model.Pod{Namespace: "X", Name: "x", Node: "n1"},
		model.Pod{Namespace: "gamma", Name: "g", Node: "n1"},
		model.Pod{Namespace: "delta", Name: "d", Node: "n1"},
	))
	if a["X/x"].CoResidency != b["X/x"].CoResidency {
		t.Errorf("O8 LEAK: CoResidency depends on co-tenant IDENTITY — same count gave different values: %.6f vs %.6f", a["X/x"].CoResidency, b["X/x"].CoResidency)
	}
	// The count IS disclosed (bounded, coarse [1,2]): more co-tenants raises it monotonically.
	alone := g.Derive(snapWith(model.Pod{Namespace: "X", Name: "x", Node: "n1"}))
	if !(alone["X/x"].CoResidency <= a["X/x"].CoResidency && a["X/x"].CoResidency <= 2.0) {
		t.Errorf("O8: co-residency must be a bounded [1,2] coarse count disclosure: alone=%.4f shared=%.4f", alone["X/x"].CoResidency, a["X/x"].CoResidency)
	}
}

// O9 — fleet-relative rarity is identity-free + bounded; the magnitude shift is a DISCLOSED residual.
func TestO9_FleetRelativePhysicsIdentityFreeBoundedDisclosure(t *testing.T) {
	g := genericK8s{}
	base := []model.Pod{
		{Namespace: "X", Name: "x", Node: "n1", ImageID: "rare-img"},
		{Namespace: "X", Name: "x2", Node: "n1", ImageID: "common"},
		{Namespace: "X", Name: "x3", Node: "n1", ImageID: "common"},
	}
	xAlone := g.Derive(snapWith(base...))
	// another tenant deploys X's rare image (and a different identity entirely).
	withY := append(append([]model.Pod{}, base...), model.Pod{Namespace: "Y-secret-name", Name: "y", Node: "n1", ImageID: "rare-img"})
	xWithY := g.Derive(snapWith(withY...))

	wAlone, wWithY := xAlone["X/x"], xWithY["X/x"]

	// (a) IDENTITY-FREE + BOUNDED: the witness is bounded float magnitudes; it carries no co-tenant
	//     identity (PhysicsWitness has no string identity fields — structural).
	if wWithY.ImageRarity < 1.0 || wWithY.ImageRarity > 2.0 {
		t.Errorf("O9: ImageRarity must be a bounded [1,2] magnitude, got %.4f", wWithY.ImageRarity)
	}
	// (b) DISCLOSED RESIDUAL: Y deploying X's image LOWERS X's image-rarity — a bounded, coarse,
	//     identity-free membership-inference channel. Measured + disclosed (a property of fleet-relative
	//     physics, NOT a closeable leak). The defense is coarseness (clamped [1,2]) + identity-freedom.
	if wWithY.ImageRarity >= wAlone.ImageRarity {
		t.Errorf("O9 expected the fleet-relative rarity to move (disclosed residual): alone=%.4f withY=%.4f", wAlone.ImageRarity, wWithY.ImageRarity)
	}
	t.Logf("O9 DISCLOSED RESIDUAL (bounded, identity-free): X image-rarity %.4f -> %.4f when another tenant deploys the same image — a coarse [1,2] membership-inference channel, same class as the co-residency count (R2). NOT closeable in software; physics is fleet-relative.", wAlone.ImageRarity, wWithY.ImageRarity)
}
