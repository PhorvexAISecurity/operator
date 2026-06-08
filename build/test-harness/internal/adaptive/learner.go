// Package adaptive implements the ADAPTIVE attacker arm: an attacker that observes
// the inter-rotation gaps a defender produces across trials, estimates the
// rotation rhythm, and schedules its kill-chain into the predicted lull (the
// window between rotations where a foothold is most likely to survive).
//
// Against a periodic timer (d-r6blindtimer) the learner converges quickly and
// the attacker's dwell improves. Against a memoryless random-rate arm
// (d-randomequal) the gaps carry no exploitable structure, so the learner's
// prediction is no better than chance — which is exactly the value the
// equal-rate comparison is designed to expose.
package adaptive

import (
	"math"
	"sort"
	"sync"
)

// Learner accumulates observed rotation timestamps across trials of one
// (scenario, defender) arm and predicts the next safe lull. It is safe for
// concurrent use (the runner drives trials sequentially today, but adaptive
// state is shared across them).
type Learner struct {
	mu sync.Mutex
	// gaps are the observed inter-rotation gaps (seconds) seen so far.
	gaps []float64
	// lastRotation is the most recent observed rotation time (unix seconds).
	lastRotation float64
	// observations is the count of rotation events fed in.
	observations int
}

// NewLearner returns an empty learner.
func NewLearner() *Learner { return &Learner{} }

// ObserveRotations feeds the sorted rotation timestamps (unix seconds) seen in a
// trial. Consecutive differences become inter-rotation gaps. Called once per
// trial after the defender's DefensiveActions are read.
func (l *Learner) ObserveRotations(atUnix []float64) {
	if len(atUnix) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := append([]float64(nil), atUnix...)
	sort.Float64s(s)
	for i := 1; i < len(s); i++ {
		g := s[i] - s[i-1]
		if g > 0 {
			l.gaps = append(l.gaps, g)
		}
	}
	l.lastRotation = s[len(s)-1]
	l.observations += len(s)
}

// EstimatedInterval returns the learner's current best estimate of the rotation
// period (the median observed gap, robust to outliers). Zero until at least one
// gap is observed.
func (l *Learner) EstimatedInterval() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return median(l.gaps)
}

// GapRegularity returns a 0..1 score of how PREDICTABLE the rotation rhythm is:
// 1 = perfectly periodic (zero variance), →0 = highly irregular (random). It is
// 1 - clamp(coefficient_of_variation). The adaptive attacker uses this to decide
// whether timing is worth exploiting at all.
func (l *Learner) GapRegularity() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.gaps) < 2 {
		return 0
	}
	m := mean(l.gaps)
	if m == 0 {
		return 0
	}
	var ss float64
	for _, g := range l.gaps {
		d := g - m
		ss += d * d
	}
	std := math.Sqrt(ss / float64(len(l.gaps)-1))
	cv := std / m // coefficient of variation
	reg := 1 - cv
	if reg < 0 {
		reg = 0
	}
	if reg > 1 {
		reg = 1
	}
	return reg
}

// PlanDelaySeconds returns how long the attacker should WAIT after the trial's
// most recent observed rotation before striking, to land its kill-chain in the
// safest part of the lull. The strategy: strike just after a predicted rotation
// (maximizing time until the next one). With no learned rhythm it returns 0
// (strike immediately). The result is clamped to [0, estInterval].
//
// sinceLastRotation is how long ago (seconds) the last rotation was observed in
// THIS trial; it lets the attacker align to the live cadence.
func (l *Learner) PlanDelaySeconds(sinceLastRotation float64) float64 {
	est := l.EstimatedInterval()
	if est <= 0 {
		return 0
	}
	reg := l.GapRegularity()
	// If the rhythm is irregular, timing buys little: shrink the planned offset.
	// If it is regular, wait until just after the next predicted rotation.
	phase := math.Mod(sinceLastRotation, est)
	// Time until the next predicted rotation:
	untilNext := est - phase
	// Strike just AFTER the next rotation to maximize the following lull. Scale by
	// regularity so a random arm collapses the plan toward "strike now".
	delay := untilNext * reg
	if delay < 0 {
		delay = 0
	}
	if delay > est {
		delay = est
	}
	return delay
}

// Observations returns how many rotation events have been fed in (telemetry).
func (l *Learner) Observations() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.observations
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}
