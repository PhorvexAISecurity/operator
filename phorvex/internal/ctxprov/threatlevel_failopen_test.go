package ctxprov

import (
	"fmt"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// threatlevel_failopen_test.go — PHVX-14d.
//
// `v1beta1.ThreatLevelRank` returns -1 for any level outside the canonical vocabulary. That -1 used
// to be clamped to 0, which is not "no opinion" — 0 is exactly `info`, the LOWEST severity. So a
// detector emitting a level we have not mapped ("severe", "warning", a new Falco/CrowdStrike level,
// a localised string) had its event scored as the most harmless thing the system can represent, and
// the threat effectively disappeared from the posture signal. Unknown must not read as benign.

func eventAt(level string, targetsPod bool) model.SecurityEventInfo {
	return model.SecurityEventInfo{ThreatLevel: level, TargetsPod: targetsPod, Age: 0}
}

func postureFor(t *testing.T, level string) float64 {
	t.Helper()
	sig := sensed{}.Context(
		&model.WorkloadView{
			Pod:    model.Pod{Namespace: "ns", Name: "p"},
			Events: []model.SecurityEventInfo{eventAt(level, true)},
		},
		model.Policy{ProactiveFloor: 15 * time.Minute},
	)
	return sig.ThreatPosture
}

// TestUnknownThreatLevelDoesNotReadAsInfo is the regression. An unmapped level must NOT produce the
// same posture as the explicitly-lowest level; if it does, the event has been silently discarded.
func TestUnknownThreatLevelDoesNotReadAsInfo(t *testing.T) {
	info := postureFor(t, "info")
	if info != 0 {
		t.Fatalf("precondition: canonical %q should score 0, got %v", "info", info)
	}

	for _, unknown := range []string{"severe", "warning", "SEV-1", "critique", ""} {
		t.Run(unknown, func(t *testing.T) {
			got := postureFor(t, unknown)
			if got <= info {
				t.Errorf("unknown threat level %q scored %v, no higher than %q (%v) — an unmapped "+
					"severity is being treated as the most harmless case, so a real detector event "+
					"disappears from the posture signal", unknown, got, "info", info)
			}
		})
	}
}

// TestUnknownThreatLevelIsMidNotMax pins the other side: unknown means uncertain, so it must not
// outrank an explicitly-critical event either. Otherwise one mislabelled event could dominate the
// posture of a whole tenant, and a vocabulary gap becomes an amplifier.
func TestUnknownThreatLevelIsMidNotMax(t *testing.T) {
	critical := postureFor(t, "critical")
	unknown := postureFor(t, "not-a-real-level")
	if unknown >= critical {
		t.Errorf("unknown (%v) must rank BELOW critical (%v) — uncertainty is not maximum severity",
			unknown, critical)
	}
	medium := postureFor(t, "medium")
	if unknown != medium {
		t.Errorf("unknown (%v) should map to the medium rank (%v)", unknown, medium)
	}
}

// TestUnknownThreatLevelIsReported makes the vocabulary gap findable. Silently degrading a signal is
// the failure mode this ticket is about, so the levels we could not map must be retrievable.
func TestUnknownThreatLevelIsReported(t *testing.T) {
	_ = postureFor(t, "phvx-14d-probe-level")
	seen := UnknownThreatLevelsSeen()
	found := false
	for _, s := range seen {
		if s == "phvx-14d-probe-level" {
			found = true
		}
	}
	if !found {
		t.Errorf("an unmapped threat level must be recorded for the operator, got %v", seen)
	}
}

// TestCanonicalLevelsAreOrdered guards the mapping itself, so a future edit cannot flatten it.
func TestCanonicalLevelsAreOrdered(t *testing.T) {
	var prev float64 = -1
	for _, lvl := range []string{"info", "low", "medium", "high", "critical"} {
		got := postureFor(t, lvl)
		if got < prev {
			t.Errorf("posture must be non-decreasing across the canonical vocabulary: %q gave %v after %v",
				lvl, got, prev)
		}
		prev = got
	}
}

// TestUnknownThreatLevelsAreBounded is the growth guard. The map is keyed on a string that arrives
// from outside the operator, and this code path exists precisely BECAUSE that string is not from a
// fixed vocabulary — so an unbounded map here is a leak waiting for a misconfigured detector. The
// operator never resets it, so it would only grow. Against the unbounded version this test fails
// with a count of 5000.
func TestUnknownThreatLevelsAreBounded(t *testing.T) {
	resetUnknownThreatLevels()
	for i := 0; i < 5000; i++ {
		unknownThreatLevel(fmt.Sprintf("garbage-level-%d", i))
	}
	got := UnknownThreatLevelsSeen()
	if len(got) > unknownThreatLevelBudget {
		t.Fatalf("retained %d distinct levels against a budget of %d — the map is unbounded and is "+
			"keyed on unvalidated external input", len(got), unknownThreatLevelBudget)
	}
	if !UnknownThreatLevelsTruncated() {
		t.Error("overflowing the budget must be visible; dropping silently hides the stronger signal " +
			"that the detector is emitting unbounded variety")
	}
}

// TestUnknownThreatLevelsStillReportUnderTheBudget pins that the cap did not break the feature it
// guards: a handful of genuinely unmapped levels must still be reported in full.
func TestUnknownThreatLevelsStillReportUnderTheBudget(t *testing.T) {
	resetUnknownThreatLevels()
	for _, l := range []string{"sev-9", "URGENT", "p0"} {
		unknownThreatLevel(l)
		unknownThreatLevel(l) // repeated every tick: must not double-count
	}
	got := UnknownThreatLevelsSeen()
	if len(got) != 3 {
		t.Fatalf("expected the 3 distinct levels, got %v", got)
	}
	if UnknownThreatLevelsTruncated() {
		t.Error("three levels is well inside the budget; truncation must not be reported")
	}
}

// resetUnknownThreatLevels clears the package-level state so the two tests above do not interfere
// with each other or with anything that ran earlier in the package.
func resetUnknownThreatLevels() {
	unknownThreatLevels.Range(func(k, _ any) bool { unknownThreatLevels.Delete(k); return true })
	unknownThreatLevelCount.Store(0)
	unknownThreatLevelTruncated.Store(false)
}
