package platform

import (
	"fmt"
	"testing"
)

// Cross-check: does the SHIPPED Go rarity/co-residency match the Python I used for the PHVX-130
// percentile numbers? If these diverge, the numbers sent to the math owner are wrong.
func TestDiagCrossCheckFormulas(t *testing.T) {
	fmt.Println("  rarity(count,N) — Go:")
	for _, c := range []struct{ cnt, n int }{{1, 100}, {2, 100}, {4, 100}, {8, 100}, {21, 100}, {100, 100}} {
		fmt.Printf("    rarity(%3d,%d) = %.10f\n", c.cnt, c.n, rarity(c.cnt, c.n))
	}
	fmt.Println("  co-residency 1+clamp01((tenants-1)/CoResidencyCap) — Go:")
	for _, tn := range []int{1, 2, 5, 7, 8, 9} {
		fmt.Printf("    tenants=%d -> %.10f\n", tn, 1+clamp01(float64(tn-1)/CoResidencyCap))
	}
	fmt.Printf("  CoResidencyCap = %v\n", CoResidencyCap)
	fmt.Printf("  LIVE: rarity(1,1) = %.10f   rarity(2,2) = %.10f\n", rarity(1,1), rarity(2,2))
}
