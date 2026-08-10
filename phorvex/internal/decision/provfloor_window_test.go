package decision

import (
	"math"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/killchain"
)

// provfloor_window_test.go — PHVX-72 / PHORVEXSEC-128, §6 of the threshold analysis.
//
// The provenance discount is only REACHABLE inside
//
//	AntiOverRotationWindow <= t < ProactiveFloor   and   U(t) <= threshold
//
// below the window the candidate is infeasible (feasibility/defaults.go:87) so it has no coverage to
// discount; at or above the floor prov() returns 1 because the asset is genuinely due. This test
// pins that geometry against the LIVE tenant policies, because two of them close the window
// entirely — a fact that is invisible from the code alone and would otherwise be rediscovered the
// hard way.

// evidenceLessUrgency is U(t) for an asset with no kill-chain evidence: stage=Recon, next=Exploit,
// Weibull sojourn 1800s with shape 2 (killchain.NewModel defaults).
func evidenceLessUrgency(sec float64) float64 {
	h := 1 - math.Exp(-math.Pow(sec/1800.0, 2))
	return 0.5*0.1 + 0.5*h*0.35
}

func TestDiscountWindowGeometryPerLiveTenant(t *testing.T) {
	// t at which an evidence-less asset reaches the threshold and escapes the discount.
	hAt := (killchain.ProvenanceEvidenceThreshold - 0.05) / 0.175
	escape := 1800 * math.Sqrt(-math.Log(1-hAt))

	for _, tc := range []struct {
		name      string
		antiOver  time.Duration
		floor     time.Duration
		wantEmpty bool
	}{
		{"litellm", 90 * time.Second, 15 * time.Minute, false},
		{"nats", 60 * time.Second, 15 * time.Minute, false},
		{"phorvex-live-demo", 90 * time.Second, 15 * time.Minute, false},
		{"voice", 90 * time.Second, 15 * time.Minute, false},
		// window >= floor: every FEASIBLE candidate is already overdue, so prov() short-circuits to 1.
		{"vllm", 15 * time.Minute, 15 * time.Minute, true},
		// floor < window: same, even more starkly.
		{"mock-rag-chatbot", 90 * time.Second, 15 * time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lo := tc.antiOver.Seconds()
			hi := math.Min(tc.floor.Seconds(), escape)
			empty := hi <= lo
			if empty != tc.wantEmpty {
				t.Fatalf("window [%.0fs,%.0fs) empty=%v, want empty=%v", lo, hi, empty, tc.wantEmpty)
			}
			if !empty {
				u := evidenceLessUrgency(lo)
				if u > killchain.ProvenanceEvidenceThreshold {
					t.Fatalf("at the feasibility onset (%.0fs) urgency is already %.4f > threshold %.4f: "+
						"the discount can never act for this tenant", lo, u, killchain.ProvenanceEvidenceThreshold)
				}
				t.Logf("window [%.0fs, %.0fs) = %.0fs wide; urgency at onset %.4f", lo, hi, hi-lo, u)
			} else {
				t.Logf("EMPTY window [%.0fs, %.0fs): this defence cannot act for this tenant at ANY threshold", lo, hi)
			}
		})
	}
}
