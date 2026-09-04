package platform

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// epss_ranking_test.go — PHORVEXSEC-59 acceptance criterion:
// "EPSS values flow into PhysicsWitness; test proves non-neutral EPSS changes ranking."
//
// The existing UCW ablation test sets ph.EPSS = 2.0 by hand, which exercises the consumer but not
// the SOURCE. This drives the real path end to end: SeedEPSS -> epssMultiplier -> PhysicsWitness,
// keyed on a real image digest, and then compares the resulting order.

// The two images live in DIFFERENT repositories. Since M-141 (PHORVEXSEC-203) a digest with no
// cache entry falls back to the latest scan of its own repository, so two digests of one repo
// are no longer "exploitable" and "benign" — they are the same software at two builds. The
// honest-absent pod of this test is therefore an image whose repository was never scanned.
const (
	exploitableImg = "registry.example/app@sha256:" +
		"1111111111111111111111111111111111111111111111111111111111111111"
	benignImg = "registry.example/other@sha256:" +
		"2222222222222222222222222222222222222222222222222222222222222222"
)

func twoPodSnapshot() *ingest.Snapshot {
	return &ingest.Snapshot{Pods: []model.Pod{
		{Namespace: "ns", Name: "exploitable", Node: "node-a", ImageID: exploitableImg},
		{Namespace: "ns", Name: "benign", Node: "node-a", ImageID: benignImg},
	}}
}

func witnessByPod(t *testing.T, snap *ingest.Snapshot) map[string]model.PhysicsWitness {
	t.Helper()
	out := map[string]model.PhysicsWitness{}
	for k, w := range (genericK8s{}).Derive(snap) {
		out[k] = w
	}
	return out
}

// TestSeededEPSSReachesPhysicsWitness is criterion (a): a seeded score must arrive as a non-neutral
// multiplier on the pod whose image carries it, and must leave the other pod at honest-absent 1.0.
func TestSeededEPSSReachesPhysicsWitness(t *testing.T) {
	SeedEPSS(map[string]struct{ EPSS, CVSS float64 }{
		exploitableImg: {EPSS: 0.97, CVSS: 9.8},
	})
	defer SeedEPSS(nil)

	w := witnessByPod(t, twoPodSnapshot())
	got, absent := w["ns/exploitable"].EPSSMultiplier, w["ns/benign"].EPSSMultiplier

	// M-104 form: 1 + 0.97*(9.8/10) = 1.9506
	if math.Abs(got-1.9506) > 1e-9 {
		t.Fatalf("seeded EPSS did not reach PhysicsWitness: got %v, want 1.975 — the cache is not "+
			"feeding epssMultiplier, which is exactly what this ticket alleges", got)
	}
	if absent != 1.0 {
		t.Fatalf("an image with no cache entry must stay honest-absent at 1.0; got %v", absent)
	}
}

// TestNonNeutralEPSSChangesRanking is criterion (b), the one the ticket actually turns on. Two pods
// identical in every other respect: only the EPSS entry differs, so any change in the scarcity
// ordering is attributable to EPSS alone.
func TestNonNeutralEPSSChangesRanking(t *testing.T) {
	snap := twoPodSnapshot()

	// Baseline: nothing seeded. Both pods are honest-absent, so the two are indistinguishable.
	SeedEPSS(nil)
	flat := witnessByPod(t, snap)
	if flat["ns/exploitable"].EPSSMultiplier != flat["ns/benign"].EPSSMultiplier {
		t.Fatalf("with an empty cache both pods must tie; got %v vs %v",
			flat["ns/exploitable"].EPSSMultiplier, flat["ns/benign"].EPSSMultiplier)
	}
	baseRatio := scarcity(flat["ns/exploitable"]) / scarcity(flat["ns/benign"])
	if math.Abs(baseRatio-1.0) > 1e-9 {
		t.Fatalf("unseeded, the two pods must be exactly tied on scarcity; ratio %v", baseRatio)
	}

	// Seed only the exploitable image.
	SeedEPSS(map[string]struct{ EPSS, CVSS float64 }{
		exploitableImg: {EPSS: 0.97, CVSS: 9.8},
	})
	defer SeedEPSS(nil)
	seeded := witnessByPod(t, snap)
	ratio := scarcity(seeded["ns/exploitable"]) / scarcity(seeded["ns/benign"])

	if ratio <= 1.0 {
		t.Fatalf("a known-exploitable pod must outrank an otherwise identical benign one; "+
			"scarcity ratio %v (exploitable %v, benign %v)",
			ratio, scarcity(seeded["ns/exploitable"]), scarcity(seeded["ns/benign"]))
	}
	t.Logf("EPSS moved the pair from a %.4f tie to a %.4f ratio", baseRatio, ratio)

	// LIVE-FLEET CAVEAT, recorded deliberately rather than left to be rediscovered.
	//
	// This proves the MECHANISM. It does not prove EPSS changes ranking on the current cluster.
	// Measured there (PHORVEXSEC-104): the uncapped product already spans 1.875-7.500 against
	// MaxDispersionMult = 4.0, so 26% of assets are pinned at the cap and an EPSS lift on them is
	// discarded before it reaches a decision. Widening EPSS coverage without re-fitting that cap
	// moves 86% of assets onto it and REDUCES resolution. The pods below are deliberately given no
	// other dispersion so the cap is not reached and EPSS is observable in isolation.
	if s := scarcity(seeded["ns/exploitable"]); s > 4.0 {
		t.Fatalf("fixture reached the live MaxDispersionMult of 4.0 (%v); the assertion above would "+
			"then be measuring the clamp rather than EPSS", s)
	}
}

// scarcity is the product ucw.go forms before boundMult: ImageRarity * EPSS * CoResidency.
// ModelRarity is excluded — these fixtures are not model-serving pods.
func scarcity(w model.PhysicsWitness) float64 {
	return w.ImageRarity * w.EPSSMultiplier * w.CoResidency
}
