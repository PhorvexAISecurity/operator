package decision

import (
	"fmt"
	"math"
	"testing"
)

func TestDiagWorkEstimateEdges(t *testing.T) {
	cases := []struct{ n, b, k int }{
		{0, 2, 3}, {5, 0, 3}, {5, 2, 0}, {-1, 2, 3}, {5, -1, 3},
		{3, 10, 2},                            // B > n
		{1000000, 5, 17}, {2000000000, 8, 17}, // overflow probes
		{76, 1, 6}, {76, 2, 6}, {76, 3, 6}, {600, 1, 6},
	}
	for _, c := range cases {
		v := exactWorkEstimate(c.n, c.b, c.k)
		skip := v > exactWorkBudget
		flag := ""
		if math.IsNaN(v) {
			flag = "  <-- NaN!"
		} else if v < 0 {
			flag = "  <-- NEGATIVE!"
		}
		fmt.Printf("  n=%-11d B=%-3d k=%-3d work=%-14.4g skip=%-6v%s\n", c.n, c.b, c.k, v, skip, flag)
	}
}

// Does the guard actually stop an intractable enumeration, or only estimate it?
func TestDiagGuardActuallyBlocks(t *testing.T) {
	set := overCapWorkSet() // 40 assets x 6 actions
	for _, b := range []int{1, 2, 3, 4} {
		_, skipped := exactObjective(set, b, func(string) float64 { return 1 }, 0.3)
		fmt.Printf("  40 assets k=6 B=%d -> skipped=%v (work=%.4g)\n", b, skipped, exactWorkEstimate(40, b, 6))
	}
}
