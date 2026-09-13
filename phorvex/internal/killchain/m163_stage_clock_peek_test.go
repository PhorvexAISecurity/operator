/*
 * M-163 head regressions (kill-chain side): the read-only stage-clock assessment.
 *
 * These are UNIT tests on the shared dwell arithmetic. They supplement — they do not
 * replace — the real producer-chain regression in
 * internal/decision/m163_shadow_isolation_test.go, which drives platform.Derive and
 * calib.Runtime.ShadowViews through DecideShadowChecked/DecideChecked.
 *
 * The property under test: Peek returns exactly what Observe would return for the same
 * (slot, uid, stage, exposure) against the same existing entry, and leaves that entry
 * where it was. Every arm Observe distinguishes is covered on both sides.
 */

package killchain

import "testing"

const (
	peekOwner = "name\x00t"
	peekNS    = "ns"
	peekPod   = "gpu-pod"
	peekUID   = "uid-1"
)

// peekAndObserveAgree runs both calls against a clock in the given state and reports the
// two dwell values. Peek runs FIRST so a leaked write would be visible in Observe's answer.
func peekAndObserveAgree(t *testing.T, build func() *StageClock, uid string, stage Stage, exposure float64) (float64, float64) {
	t.Helper()
	peeked := build().Peek(peekOwner, peekNS, peekPod, uid, stage, exposure)
	observed := build().Observe(peekOwner, peekNS, peekPod, uid, stage, exposure)
	if peeked != observed {
		t.Fatalf("Peek and Observe disagree on dwell: peek=%v observe=%v", peeked, observed)
	}
	return peeked, observed
}

func seededClock(t *testing.T, stage Stage, exposure float64) *StageClock {
	t.Helper()
	c := NewStageClock()
	c.Observe(peekOwner, peekNS, peekPod, peekUID, stage, exposure)
	return c
}

func entryOf(t *testing.T, c *StageClock) (stageEntry, bool) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.state[peekOwner+"\x00"+peekNS+"\x00"+peekPod]
	return e, ok
}

// A never-seen slot reads the pod-age fallback in both modes, but only Observe seeds it.
func TestM163_PeekOnFreshSlotMatchesObserveAndSeedsNothing(t *testing.T) {
	dwell, _ := peekAndObserveAgree(t, NewStageClock, peekUID, StageRecon, 1200)
	if dwell != 1200 {
		t.Fatalf("fresh slot dwell = %v, want the exposure fallback 1200", dwell)
	}
	c := NewStageClock()
	c.Peek(peekOwner, peekNS, peekPod, peekUID, StageRecon, 1200)
	if _, ok := entryOf(t, c); ok {
		t.Fatal("Peek created a stage entry for a slot production has never observed")
	}
}

// The incident arm: a hypothetical stage CHANGE reads 0 like a real one, but the production
// entry keeps its stage and its entry reading, so the next real Observe still reports the
// accrued dwell rather than the shadow's zero.
func TestM163_PeekOnStageChangeDoesNotTakeTheTransition(t *testing.T) {
	dwell, _ := peekAndObserveAgree(t, func() *StageClock { return seededClock(t, StageRecon, 0) },
		peekUID, StageGPUSideChannel, 1200)
	if dwell != 0 {
		t.Fatalf("hypothetical transition dwell = %v, want 0", dwell)
	}

	c := seededClock(t, StageRecon, 0)
	before, _ := entryOf(t, c)
	if got := c.Peek(peekOwner, peekNS, peekPod, peekUID, StageGPUSideChannel, 1200); got != 0 {
		t.Fatalf("peeked transition dwell = %v, want 0", got)
	}
	after, ok := entryOf(t, c)
	if !ok || after != before {
		t.Fatalf("Peek replaced the production entry: before=%+v after=%+v", before, after)
	}
	if got := c.Observe(peekOwner, peekNS, peekPod, peekUID, StageRecon, 1200); got != 1200 {
		t.Fatalf("production dwell after a peeked transition = %v, want the accrued 1200", got)
	}
}

// An unchanged stage reads the elapsed dwell in both modes, and repeated peeks are stable.
func TestM163_PeekOnSameStageReadsElapsedDwellRepeatably(t *testing.T) {
	c := seededClock(t, StageRecon, 200) // entry = 0 on the first observation
	for i := 0; i < 5; i++ {
		if got := c.Peek(peekOwner, peekNS, peekPod, peekUID, StageRecon, 1400); got != 1400 {
			t.Fatalf("peek %d read dwell %v, want 1400", i, got)
		}
	}
	if got := c.Observe(peekOwner, peekNS, peekPod, peekUID, StageRecon, 1400); got != 1400 {
		t.Fatalf("production dwell after repeated peeks = %v, want 1400", got)
	}
}

// A replaced UID is a fresh slot in both modes; the peek must not adopt the new identity.
func TestM163_PeekOnReplacedUIDMatchesObserveAndKeepsTheOldIdentity(t *testing.T) {
	dwell, _ := peekAndObserveAgree(t, func() *StageClock { return seededClock(t, StageRecon, 0) },
		"uid-2", StageRecon, 30)
	if dwell != 30 {
		t.Fatalf("replaced-UID dwell = %v, want the exposure fallback 30", dwell)
	}
	c := seededClock(t, StageRecon, 0)
	c.Peek(peekOwner, peekNS, peekPod, "uid-2", StageRecon, 30)
	entry, ok := entryOf(t, c)
	if !ok || entry.uid != peekUID {
		t.Fatalf("Peek adopted the replacement UID: %+v", entry)
	}
}

// A negative exposure reading clamps at 0 identically in both modes.
func TestM163_PeekClampsNegativeExposureLikeObserve(t *testing.T) {
	dwell, _ := peekAndObserveAgree(t, NewStageClock, peekUID, StageRecon, -5)
	if dwell != 0 {
		t.Fatalf("negative exposure dwell = %v, want the 0 clamp", dwell)
	}
	// Same-stage arm: entry above the reading must not produce a negative dwell.
	c := seededClock(t, StageRecon, 900)
	c.Observe(peekOwner, peekNS, peekPod, peekUID, StageGPUSideChannel, 900) // entry = 900
	if got := c.Peek(peekOwner, peekNS, peekPod, peekUID, StageGPUSideChannel, 100); got != 0 {
		t.Fatalf("backwards exposure dwell = %v, want the 0 clamp", got)
	}
}

// A nil tracker degrades to the identity clock in both modes (no panic, no divergence).
func TestM163_PeekOnNilTrackerMatchesObserve(t *testing.T) {
	var c *StageClock
	if got := c.Peek(peekOwner, peekNS, peekPod, peekUID, StageRecon, 77); got != 77 {
		t.Fatalf("nil-tracker peek = %v, want the exposure fallback 77", got)
	}
	if got := c.Observe(peekOwner, peekNS, peekPod, peekUID, StageRecon, 77); got != 77 {
		t.Fatalf("nil-tracker observe = %v, want the exposure fallback 77", got)
	}
}

// Peeking a slot must not resurrect it past the runner's per-tick GC.
func TestM163_PeekDoesNotResurrectAPrunedSlot(t *testing.T) {
	c := seededClock(t, StageRecon, 0)
	if pruned := c.RetainOwner(peekOwner, nil); pruned != 1 {
		t.Fatalf("pruned %d slots, want 1", pruned)
	}
	c.Peek(peekOwner, peekNS, peekPod, peekUID, StageGPUSideChannel, 1200)
	if _, ok := entryOf(t, c); ok {
		t.Fatal("Peek re-created a pruned slot")
	}
}

// The conjugate prior has the same split: a shadow read reports the number production would
// report without being the event that brings the owner's belief into existence.
func TestM163_PriorPeekMatchesPriorWithoutSeeding(t *testing.T) {
	m := NewConjugateMemory()
	wantA, wantB := 1.0, 4.0

	gotA, gotB := m.PriorPeek(peekOwner)
	if gotA != wantA || gotB != wantB {
		t.Fatalf("peeked cold prior = (%v,%v), want the shipped default (%v,%v)", gotA, gotB, wantA, wantB)
	}
	if m.Tracked(peekOwner) {
		t.Fatal("PriorPeek seeded an owner the memory has never learned about")
	}
	if got, want := m.PHoldUCBWithEvidenceMode(peekOwner, 2, 0, EvalShadow),
		m.PHoldUCBWithEvidenceMode(peekOwner, 2, 0, EvalProduction); got != want {
		t.Fatalf("shadow posterior %v != production posterior %v on a cold owner", got, want)
	}

	// On a LEARNED owner the shadow read must return the learned values, never a fresh model.
	m2 := NewConjugateMemory()
	for i := 0; i < 10; i++ {
		m2.Observe(peekOwner, 0.25)
	}
	learnedA, learnedB := m2.Prior(peekOwner)
	peekA, peekB := m2.PriorPeek(peekOwner)
	if peekA != learnedA || peekB != learnedB {
		t.Fatalf("peeked learned prior = (%v,%v), want the learned (%v,%v)", peekA, peekB, learnedA, learnedB)
	}
	if learnedA == wantA {
		t.Fatalf("precondition: training did not move alpha off the default %v", wantA)
	}
}
