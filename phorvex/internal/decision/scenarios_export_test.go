/*
 * Phorvex — scenario export (benchmark-only, no decision-path change). Generates the scale-sweep grid
 * (disjoint vs non-disjoint × N × B × seeds), computes the REAL Phorvex greedy / greedy+swaps / brute-force
 * objectives over the shared substrate, and writes one JSONL line per instance (facts + candidates + Go
 * results) so an external MILP/PuLP solver can compute the EXACT optimum at any scale (brute-force is capped
 * at 18 assets). Run: SCEN_OUT=bin/scenarios-instances.jsonl go test ./internal/decision -run TestScenariosExport -v
 */

package decision

import (
	"encoding/json"
	"os"
	"testing"
)

func TestScenariosExport(t *testing.T) {
	path := os.Getenv("SCEN_OUT")
	if path == "" {
		path = "bin/scenarios-instances.jsonl"
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)

	prov1 := func(string) float64 { return 1 } // isolate the submodular (coverage-overlap) gap from prov
	const lambda, alpha, corr = 0.3, 1.1, 0.0
	regimes := []struct {
		name    string
		overlap float64
	}{{"disjoint", 0.0}, {"non-disjoint", 0.6}}
	sizes := []int{6, 10, 14, 18, 24, 30, 40, 50, 60}
	budgets := []int{1, 3, 7}
	const seeds = 12

	type candJ struct {
		Key   string   `json:"key"`
		Cover []string `json:"cover"`
		ECost float64  `json:"ecost"`
	}
	type instJ struct {
		Regime    string             `json:"regime"`
		N         int                `json:"n"`
		B         int                `json:"b"`
		Seed      int                `json:"seed"`
		Lambda    float64            `json:"lambda"`
		Disjoint  bool               `json:"disjoint"`
		Weights   map[string]float64 `json:"weights"`
		Cands     []candJ            `json:"cands"`
		GreedyObj float64            `json:"greedyObj"`
		SwapsObj  float64            `json:"swapsObj"`
		BruteObj  float64            `json:"bruteObj"`
		BruteOK   bool               `json:"bruteOK"`
	}

	n := 0
	for _, rg := range regimes {
		for _, N := range sizes {
			for _, B := range budgets {
				for s := 0; s < seeds; s++ {
					set := synthFleet(N, rg.overlap, alpha, corr, int64(s+1))
					// De-duplicate each candidate's cover keys. synthFleet can append the SAME pool fact
					// twice to one candidate (rng.Intn can repeat), and covering a fact twice == once. All
					// arms must see distinct keys so the measured gap is the GENUINE cross-asset submodular
					// overlap, not a within-candidate double-count (which the greedy marginal inflates while
					// setObjective/MILP de-dup — an unfair, non-genuine gap). The shipped recon profile never
					// emits duplicate cover keys, so this only sanitizes the synthetic fixture.
					for i := range set.Candidates {
						seen := map[string]bool{}
						uniq := set.Candidates[i].CoverKeys[:0:0]
						for _, k := range set.Candidates[i].CoverKeys {
							if !seen[k] {
								seen[k] = true
								uniq = append(uniq, k)
							}
						}
						set.Candidates[i].CoverKeys = uniq
					}
					gObj := setObjective(greedyPicksOnSet(set, B, prov1, lambda), set.FactWeights, prov1, lambda)
					swObj := setObjective(greedyThenSwaps(set, B, prov1, lambda), set.FactWeights, prov1, lambda)
					bObj, skipped := exactObjective(set, B, prov1, lambda)
					dj, _ := coversDisjoint(set)
					cands := make([]candJ, 0, len(set.Candidates))
					for _, c := range set.Candidates {
						cands = append(cands, candJ{Key: c.Key, Cover: c.CoverKeys, ECost: c.ECost})
					}
					if err := enc.Encode(instJ{
						Regime: rg.name, N: N, B: B, Seed: s + 1, Lambda: lambda, Disjoint: dj,
						Weights: set.FactWeights, Cands: cands,
						GreedyObj: gObj, SwapsObj: swObj, BruteObj: bObj, BruteOK: !skipped,
					}); err != nil {
						t.Fatal(err)
					}
					n++
				}
			}
		}
	}
	t.Logf("exported %d instances (regimes=%d sizes=%d budgets=%d seeds=%d) to %s", n, len(regimes), len(sizes), len(budgets), seeds, path)
}
