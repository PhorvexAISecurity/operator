/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package killchain

import "sync"

// StageClock tracks time-IN-current-stage per pod slot (T1-B, CLOCK->BELIEF).
//
// The Weibull stage-exit hazard must read accrued dwell in the CURRENT stage, not the pod's
// lifecycle/identity age. There is no stage-entry timestamp anywhere else in the pipeline, so
// this is the origin. It is keyed on the monotonic identity-exposure clock (`exposureSec` —
// seconds since the pod UID last changed), NOT wall-clock time: that keeps Assess deterministic
// and signature-stable, and makes the restart fallback conservative by construction.
//
//   - First observation of a slot: entry = 0, so InStage = exposureSec = pod age. This
//     reproduces today's behaviour exactly (we do not know when the pod entered its stage).
//   - Stage value changes: entry = exposureSec, so InStage restarts at 0 and regrows on the
//     new stage's own scale.
//   - Pod UID changes (recreated pod): treated as a fresh slot (entry reset with the new UID).
//   - Brain restart (map empty): the slot re-seeds entry = 0 ⇒ InStage = exposureSec =
//     pod-age-UPPER-BOUND — conservative (never under-states imminence), matching T1-B U-2.
//
// Reset happens ONLY on a stage-value change or a UID change; repeated Assess calls in one tick
// with an unchanged stage return the same dwell (idempotent — the ablation arm relies on this).
type StageClock struct {
	mu    sync.Mutex
	state map[string]stageEntry
}

type stageEntry struct {
	uid         string
	stage       Stage
	entryExpSec float64
}

// NewStageClock returns an empty tracker.
func NewStageClock() *StageClock {
	return &StageClock{state: map[string]stageEntry{}}
}

// Observe folds this tick's (slot, uid, stage, exposureSec) and returns time-in-stage seconds.
// exposureSec is the identity clock (monotonic within a UID epoch, resets to ~0 on a new UID).
// The slot key is owner\x00namespace\x00name — identical shape to exposure.Clock, so the runner
// prunes both with the same keep set.
//
// Only an ACTUAL production observation may fold: this is the origin of stage-entry time, so a
// write here is the pod's real history.
func (c *StageClock) Observe(owner, namespace, name, uid string, stage Stage, exposureSec float64) float64 {
	return c.evaluate(owner, namespace, name, uid, stage, exposureSec, true)
}

// Peek returns the dwell a counterfactual stage WOULD read, without folding it (M-163).
// It runs the identical arithmetic as Observe against the identical existing entry — new
// slot / replaced UID falls back to exposureSec, a hypothetical stage change reads 0, an
// unchanged stage reads the elapsed dwell, a negative exposure clamps at 0 and a nil tracker
// returns exposureSec — so the shadow arm sees exactly the number production would compute
// while the production entry (its uid, stage and entry reading) stays where it was.
//
// Peek is deliberately NOT idempotent-with-Observe in the other direction: peeking a
// transition never establishes the new stage, so the next real Observe still sees the
// transition it has to record.
func (c *StageClock) Peek(owner, namespace, name, uid string, stage Stage, exposureSec float64) float64 {
	return c.evaluate(owner, namespace, name, uid, stage, exposureSec, false)
}

// evaluate is the single dwell calculation shared by Observe and Peek. commit=false makes
// every store below unreachable, so the read-only path cannot drift from the writing one.
func (c *StageClock) evaluate(owner, namespace, name, uid string, stage Stage, exposureSec float64, commit bool) float64 {
	if c == nil {
		return exposureSec // no tracker => today's behaviour (dwell == identity age)
	}
	if exposureSec < 0 {
		exposureSec = 0
	}
	key := owner + "\x00" + namespace + "\x00" + name
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, ok := c.state[key]
	switch {
	case !ok || prev.uid != uid:
		// new slot or recreated pod: entry = 0 so InStage = exposureSec (pod-age fallback).
		if commit {
			c.state[key] = stageEntry{uid: uid, stage: stage, entryExpSec: 0}
		}
		return exposureSec
	case prev.stage != stage:
		// stage transition: restart the dwell at this tick's exposure reading.
		if commit {
			c.state[key] = stageEntry{uid: uid, stage: stage, entryExpSec: exposureSec}
		}
		return 0
	default:
		d := exposureSec - prev.entryExpSec
		if d < 0 {
			d = 0
		}
		return d
	}
}

// RetainOwner prunes only THIS owner's slots not in keep — same signature and semantics as
// exposure.Clock.RetainOwner, so the runner passes the identical (owner, keep) it already builds.
func (c *StageClock) RetainOwner(owner string, keep map[string]struct{}) int {
	if c == nil {
		return 0
	}
	prefix := owner + "\x00"
	c.mu.Lock()
	defer c.mu.Unlock()
	pruned := 0
	for k := range c.state {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			if _, ok := keep[k]; !ok {
				delete(c.state, k)
				pruned++
			}
		}
	}
	return pruned
}
