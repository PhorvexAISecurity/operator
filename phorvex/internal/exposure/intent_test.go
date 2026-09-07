package exposure

import (
	"testing"
	"time"
)

func TestIntentsMarkAndSince(t *testing.T) {
	now := time.Now()
	i := NewIntents()
	i.Mark("t", "ns", "p", "guardrailEpoch", now.Add(-20*time.Second))

	since := i.Since("t", "ns", "p", now)
	if got, ok := since["guardrailEpoch"]; !ok || got < 19*time.Second || got > 21*time.Second {
		t.Fatalf("intent since = %v (ok=%v), want ~20s", got, ok)
	}
	// Untouched slot / variable is absent (so Check fail-opens on it).
	if len(i.Since("t", "ns", "other", now)) != 0 {
		t.Error("a slot with no intent must return no durations")
	}
	if _, ok := i.Since("t", "ns", "p", now)["drainEpoch"]; ok {
		t.Error("an unmarked variable must be absent")
	}
}

func TestIntentsMarkOverwritesAndClampsSkew(t *testing.T) {
	now := time.Now()
	i := NewIntents()
	i.Mark("t", "ns", "p", "v", now.Add(-5*time.Minute))
	i.Mark("t", "ns", "p", "v", now.Add(-10*time.Second)) // most recent emission wins
	if got := i.Since("t", "ns", "p", now)["v"]; got > 11*time.Second {
		t.Fatalf("Mark must overwrite with the most recent emission; since=%v", got)
	}
	// A future mark (clock skew) clamps to 0, never negative.
	i.Mark("t", "ns", "p", "v", now.Add(time.Minute))
	if got := i.Since("t", "ns", "p", now)["v"]; got < 0 {
		t.Fatalf("negative since not clamped: %v", got)
	}
	// Empty pod / variable is a no-op.
	i.Mark("t", "ns", "", "v", now)
	i.Mark("t", "ns", "p", "", now)
}

func TestIntentsRetainTenant(t *testing.T) {
	now := time.Now()
	i := NewIntents()
	i.Mark("t", "ns", "keep", "v", now)
	i.Mark("t", "ns", "drop", "v", now)
	i.Mark("other", "ns", "p", "v", now) // different tenant, must be untouched

	keep := map[string]struct{}{SlotKey("t", "ns", "keep"): {}}
	if dropped := i.RetainTenant("t", keep); dropped != 1 {
		t.Fatalf("RetainTenant dropped %d, want 1 (the 'drop' pod)", dropped)
	}
	if len(i.Since("t", "ns", "drop", now)) != 0 {
		t.Error("dropped pod's intent should be gone")
	}
	if len(i.Since("t", "ns", "keep", now)) == 0 {
		t.Error("kept pod's intent should survive")
	}
	if len(i.Since("other", "ns", "p", now)) == 0 {
		t.Error("another tenant's intent must not be touched by RetainTenant('t')")
	}
}
