package decision

import (
	"testing"
	"time"
)

// provfloor_window_test.go — PHVX-72 / PHORVEXSEC-128, §6 of the threshold analysis.
//
// The provenance discount is only REACHABLE inside
//
//	AntiOverRotationWindow <= t < ProactiveFloor   and   U(t) <= threshold
//
// below the window the candidate is infeasible (feasibility/defaults.go:87) so it has no coverage to
// discount; at or above the floor prov() returns 1 because the asset is genuinely due. This test
// pins that geometry against the LIVE tenant policies. Keep this table synchronized with the
// deployed policy values: an older fixture incorrectly retained vllm's former 15m anti-rotation
// window after production moved it to 90s, and therefore kept reporting a closed defence window.

func TestDiscountWindowGeometryPerLiveTenant(t *testing.T) {
	// With the explicit evidence gate, an evidence-less asset stays discounted right up to the
	// proactive floor; there is no urgency-based escape. The window is therefore purely
	// [AntiOverRotationWindow, ProactiveFloor).

	for _, tc := range []struct {
		name      string
		antiOver  time.Duration
		floor     time.Duration
		wantEmpty bool
	}{
		{"litellm", 90 * time.Second, 15 * time.Minute, false},
		{"nats", 60 * time.Second, 15 * time.Minute, false},
		// Verified on phorvex-dev-eks on 2026-08-16: vllm now has the same 90s/15m
		// geometry as the other application tenants, so its discount window is active.
		{"vllm", 90 * time.Second, 15 * time.Minute, false},
		{"voice", 90 * time.Second, 15 * time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lo := tc.antiOver.Seconds()
			hi := tc.floor.Seconds()
			empty := hi <= lo
			if empty != tc.wantEmpty {
				t.Fatalf("window [%.0fs,%.0fs) empty=%v, want empty=%v", lo, hi, empty, tc.wantEmpty)
			}
			if !empty {
				t.Logf("window [%.0fs, %.0fs) = %.0fs wide", lo, hi, hi-lo)
			} else {
				t.Logf("EMPTY window [%.0fs, %.0fs): this defence cannot act for this tenant at ANY threshold", lo, hi)
			}
		})
	}
}
