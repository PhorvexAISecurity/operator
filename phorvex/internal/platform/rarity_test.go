/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package platform

import (
	"math"
	"testing"
)

// TestRarityIsPopulationRelative pins what rarity() actually measures, because the one result that
// looks like a bug is the one that is most obviously correct (PHVX-24 item 4).
//
// rarity() answers "how much of ITS OWN population does this thing occupy", not "how many distinct
// kinds exist". ImageRarity and ModelRarity call this same function; only the population differs.
// A digest that is 1 of 76 pods is rare, so 2.0. A model that runs on every model-serving pod in the
// fleet is, within that population, universal — so 1.0, no matter that it is the only model in the
// cluster.
//
// 1.0 for a sole, ubiquitous model is CORRECT: it runs on 100% of model-serving pods. Do NOT "fix"
// this to 2.0. Doing so would assert scarcity at frequency 1.0 — mathematically false — and would
// inflate every GPU pod on single-model fleets, which is the most common deployment shape.
func TestRarityIsPopulationRelative(t *testing.T) {
	for _, tc := range []struct {
		name     string
		count, n int
		want     float64
		why      string
	}{
		{"singleton in a large fleet", 1, 76, 2.0,
			"1 of 76 is maximally surprising within this population -> the top of the range"},
		{"uncommon in a large fleet", 5, 76, 1.6283683,
			"1 + log2(76/5)/log2(76); the interior of the range is reachable, not just the endpoints"},
		{"sole model, ubiquitous in its own population", 2, 2, 1.0,
			"runs on 100% of model-serving pods -> neutral. This is the case that looks wrong and is not"},
		{"half its population", 2, 4, 1.5,
			"1 + log2(2)/log2(4) = 1.5 -> the midpoint is exactly half occupancy"},
		{"population of one", 1, 1, 1.0,
			"the n<2 guard: with nothing to compare against, honest-neutral rather than maximally rare"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := rarity(tc.count, tc.n)
			if math.Abs(got-tc.want) > 1e-6 {
				t.Fatalf("rarity(%d, %d) = %.7f, want %.7f — %s", tc.count, tc.n, got, tc.want, tc.why)
			}
		})
	}
}

// TestRarityIsTheSameFunctionForImagesAndModels is the point item 4 rests on: the asymmetry between
// a 2.0 image and a 1.0 model is entirely in the population handed to rarity(), never in the formula.
// Give the model the image's population and it returns the image's answer.
func TestRarityIsTheSameFunctionForImagesAndModels(t *testing.T) {
	const fleet = 76
	if img, mdl := rarity(1, fleet), rarity(1, fleet); img != mdl {
		t.Fatalf("same call returned %v and %v", img, mdl)
	}
	// A model that is 1 of 76 model-serving pods scores exactly what a singleton digest scores.
	if got := rarity(1, fleet); math.Abs(got-2.0) > 1e-9 {
		t.Fatalf("a model at 1-of-%d scored %.6f, want 2.0 — the formula does return 2.0 for a model "+
			"when the population makes it rare, so a live 1.0 is a statement about the fleet, not the formula", fleet, got)
	}
}

// TestRarityIsMonotonicInOccupancy guards the direction of the relationship: the more of its
// population a thing occupies, the LESS rare it is. An inverted sign here would silently reverse
// every dispersion ranking while keeping the output inside [1,2] and looking plausible.
func TestRarityIsMonotonicInOccupancy(t *testing.T) {
	const n = 64
	prev := math.Inf(1)
	for count := 1; count <= n; count *= 2 {
		got := rarity(count, n)
		if got < 1.0 || got > 2.0 {
			t.Fatalf("rarity(%d, %d) = %v, outside the documented [1,2] range", count, n, got)
		}
		if got > prev {
			t.Fatalf("rarity(%d, %d) = %v rose above the less-occupied case %v — the sign is inverted",
				count, n, got, prev)
		}
		prev = got
	}
}
