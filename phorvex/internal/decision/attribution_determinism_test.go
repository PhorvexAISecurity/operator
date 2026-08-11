package decision

import (
	"encoding/json"
	"testing"

	"github.com/phorvex/phorvex/internal/actionset"
)

// attribution_determinism_test.go — the audit record must be BYTE-STABLE across runs.
//
// attributionOf builds its terms by ranging a map, so they enter in random order. Sorting on
// Contribution alone did not fix that: sort.Slice is unstable and ties are the common case (every
// cover term is 0.0 on a low-risk pod), so the random map order survived into the record. Replaying
// identical views then produced a different attribution ordering every run — measured on live
// phorvex-dev-eks views (69 pods): 5 replays, 5 distinct record hashes. That breaks the ticket's
// "replay -> bit-identical decisions" requirement and makes two audit logs undiffable.

// TestAttributionOrderIsStableAcrossRuns pins the byte-stability. The all-equal-contribution case is
// the one that regressed, so it is exercised directly.
func TestAttributionOrderIsStableAcrossRuns(t *testing.T) {
	// Cover keys spanning several fact kinds whose weights are ALL EQUAL — the tie case.
	c := actionset.Candidate{
		CoverKeys: []string{
			"ns/pod|podIdentity|a",
			"ns/pod|inMemory|b",
			"ns/pod|session|c",
			"ns/pod|networkIdentity|d",
		},
		ECost: 0.5,
	}
	weights := map[string]float64{
		"ns/pod|podIdentity|a":     0,
		"ns/pod|inMemory|b":        0,
		"ns/pod|session|c":         0,
		"ns/pod|networkIdentity|d": 0,
	}

	first, err := json.Marshal(attributionOf(c, weights, 0))
	if err != nil {
		t.Fatal(err)
	}
	// Many rounds: Go randomises map iteration per range, so a single repeat can pass by luck.
	for i := 0; i < 200; i++ {
		got, err := json.Marshal(attributionOf(c, weights, 0))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(first) {
			t.Fatalf("attribution order is NOT stable (audit records cannot be hashed or diffed)\n"+
				"  round %d: %s\n  first   : %s", i, got, first)
		}
	}
}

// TestAttributionOrdersByContributionThenSource keeps the intended primary ordering (largest
// contributor first) while making the tiebreak explicit.
func TestAttributionOrdersByContributionThenSource(t *testing.T) {
	c := actionset.Candidate{
		CoverKeys: []string{
			"ns/pod|podIdentity|a", // 0.10
			"ns/pod|inMemory|b",    // 0.50  <- largest, must come first
			"ns/pod|session|c",     // 0.10  <- ties with podIdentity, "session" sorts after
		},
		ECost: 0,
	}
	weights := map[string]float64{
		"ns/pod|podIdentity|a": 0.10,
		"ns/pod|inMemory|b":    0.50,
		"ns/pod|session|c":     0.10,
	}
	terms := attributionOf(c, weights, 0)
	if len(terms) != 4 { // 3 cover kinds + the cost term
		t.Fatalf("want 4 terms, got %d: %+v", len(terms), terms)
	}
	if terms[0].Source != "cover:inMemory" {
		t.Errorf("largest contribution must come first, got %q", terms[0].Source)
	}
	// The two 0.10 terms must be ordered by Source, deterministically.
	if terms[1].Source != "cover:podIdentity" || terms[2].Source != "cover:session" {
		t.Errorf("ties must order by Source, got %q then %q", terms[1].Source, terms[2].Source)
	}
	for i := 1; i < len(terms); i++ {
		if terms[i-1].Contribution < terms[i].Contribution {
			t.Errorf("contributions must be descending: %+v", terms)
			break
		}
	}
}
