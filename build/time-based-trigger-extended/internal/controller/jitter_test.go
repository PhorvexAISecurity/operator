/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

// Package controller jitter tests — the deterministic cheap-suite MIRROR for the
// time-based-trigger SOLE cadence owner (arch §6 Phase 2). Pure unit tests over
// Apply / parseJitterParams / seedForPod (no envtest); they assert the same
// properties as the phoenix internal/scheduler suite plus the two load-bearing
// gates the plan calls out:
//
//	e. JitterMin==JitterMax==0 reproduces the deterministic sched.Next BIT-FOR-BIT
//	f. restart-safety: re-derive the seed from the stable UID => identical fire
//
// plus: gap mean ~ period (symmetric band), spread/no-spike, max-lifetime bound,
// reconcile-stability (same slot is NOT re-randomized), PerPodPhaseOffset de-sync,
// and annotation parsing/defaulting.
package controller

import (
	"math"
	"strconv"
	"testing"
	"time"
)

const (
	jtPeriod = 60 * time.Minute
	jtN      = 5000
)

// schedNextBase models today's deterministic schedule: lastRun + period.
func schedNextBase(lastRun time.Time, period time.Duration) time.Time {
	return lastRun.Add(period)
}

// --- e. zero jitter reproduces the deterministic schedule BIT-FOR-BIT ---------
func TestTBTJitter_E_ZeroJitterBitForBit(t *testing.T) {
	// 0/0 band AND stagger None => Apply must return the base fire UNCHANGED, so a
	// walk of the schedule has every gap == period exactly (== today's sched.Next).
	p := JitterParams{MinPercent: 0, MaxPercent: 0, Distribution: distributionUniform, Stagger: staggerNone}
	seed := seedForPod("pod-uid-zero")
	last := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	cur := last
	for i := 0; i < 1000; i++ {
		base := schedNextBase(cur, jtPeriod)
		got := Apply(cur, base, "pod-uid-zero", seed, p)
		if got != base {
			t.Fatalf("e) zero-jitter Apply = %s, want EXACTLY the base fire %s (bit-for-bit)", got, base)
		}
		if gap := got.Sub(cur); gap != jtPeriod {
			t.Fatalf("e) zero-jitter gap = %s, want EXACTLY %s", gap, jtPeriod)
		}
		cur = got
	}
}

// --- f. restart-safety: re-derive seed from UID => identical jittered fire ----
func TestTBTJitter_F_RestartSafetyDeterministic(t *testing.T) {
	uid := "pod-uid-restart-7f3a"
	p := DefaultJitterParams() // 10-30%, Uniform, Crypto, PerPodPhaseOffset
	last := time.Date(2026, 5, 30, 1, 0, 0, 0, time.UTC)
	base := schedNextBase(last, jtPeriod)

	// "Process instance 1" computes the fire; "instance 2" (a restart) re-derives
	// the seed from the SAME durable UID + the SAME durable lastRun and must land on
	// the SAME jittered fire (=> <= 1 extra rotation, never a re-randomized storm).
	seed1 := seedForPod(uid)
	seed2 := seedForPod(uid)
	fire1 := Apply(last, base, uid, seed1, p)
	fire2 := Apply(last, base, uid, seed2, p)
	if !fire1.Equal(fire2) {
		t.Fatalf("f) restart must reproduce the jittered fire: %s vs %s", fire1, fire2)
	}

	// And across many slots the whole schedule reproduces.
	cur1, cur2 := last, last
	for i := 0; i < 500; i++ {
		n1 := Apply(cur1, schedNextBase(cur1, jtPeriod), uid, seed1, p)
		n2 := Apply(cur2, schedNextBase(cur2, jtPeriod), uid, seed2, p)
		if !n1.Equal(n2) {
			t.Fatalf("f) schedule diverged at slot %d: %s vs %s", i, n1, n2)
		}
		cur1, cur2 = n1, n2
	}
}

// --- reconcile-stability: the SAME slot is not re-randomized across ticks -----
func TestTBTJitter_ReconcileStability(t *testing.T) {
	uid := "pod-uid-stable"
	p := DefaultJitterParams()
	seed := seedForPod(uid)
	last := time.Date(2026, 5, 30, 2, 0, 0, 0, time.UTC)
	base := schedNextBase(last, jtPeriod)

	// Apply for the SAME (lastRun, baseFire) must be identical no matter how many
	// times Reconcile recomputes it — otherwise nextRun would jump between ticks.
	first := Apply(last, base, uid, seed, p)
	for i := 0; i < 1000; i++ {
		if got := Apply(last, base, uid, seed, p); !got.Equal(first) {
			t.Fatalf("reconcile-stability: Apply re-randomized on tick %d (%s != %s)", i, got, first)
		}
	}
}

// jtGaps draws n jittered gaps over consecutive slots (Independent stagger so the
// per-key phase does not perturb the per-slot gap measurement).
func jtGaps(p JitterParams, uid string, n int) []time.Duration {
	pp := p
	pp.Stagger = staggerIndependent
	seed := seedForPod(uid)
	out := make([]time.Duration, n)
	cur := time.Date(2026, 5, 30, 3, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		nxt := Apply(cur, schedNextBase(cur, jtPeriod), uid, seed, pp)
		out[i] = nxt.Sub(cur)
		cur = nxt
	}
	return out
}

func jtMeanStd(ds []time.Duration) (mean, std float64) {
	var sum float64
	for _, d := range ds {
		sum += float64(d)
	}
	mean = sum / float64(len(ds))
	var v float64
	for _, d := range ds {
		diff := float64(d) - mean
		v += diff * diff
	}
	return mean, math.Sqrt(v / float64(len(ds)))
}

// --- gap mean ~ period, spread present, no degenerate spike ------------------
func TestTBTJitter_DistributionMeanSpreadNoSpike(t *testing.T) {
	p := DefaultJitterParams()
	ds := jtGaps(p, "pod-uid-dist", jtN)
	mean, std := jtMeanStd(ds)
	period := float64(jtPeriod)

	if math.Abs(mean-period) > 0.02*period {
		t.Errorf("gap mean = %s, want ~%s (symmetric band)", time.Duration(mean), jtPeriod)
	}
	if std <= 0 {
		t.Fatal("jittered cadence must have variance > 0 (no degenerate spike)")
	}

	// No single histogram bucket dominates.
	lo, hi := period*0.70, period*1.30
	const buckets = 20
	width := (hi - lo) / float64(buckets)
	counts := make([]int, buckets)
	for _, d := range ds {
		idx := int((float64(d) - lo) / width)
		if idx < 0 {
			idx = 0
		}
		if idx >= buckets {
			idx = buckets - 1
		}
		counts[idx]++
	}
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	if float64(maxCount) > 0.5*float64(len(ds)) {
		t.Errorf("degenerate spike: one bucket holds %d/%d draws", maxCount, len(ds))
	}
}

// --- max-lifetime bound: every gap <= period*(1+JitterMax/100) ---------------
func TestTBTJitter_MaxLifetimeBounded(t *testing.T) {
	p := DefaultJitterParams()
	ds := jtGaps(p, "pod-uid-bound", jtN)
	bound := float64(jtPeriod) * (1 + 0.30)
	eps := float64(jtPeriod) * 1e-6
	for _, d := range ds {
		if float64(d) > bound+eps {
			t.Errorf("gap %s exceeds the max-lifetime bound %s", d, time.Duration(bound))
		}
	}
}

// --- prediction-error >= jitter magnitude ------------------------------------
func TestTBTJitter_PredictionErrorAtLeastJitter(t *testing.T) {
	p := DefaultJitterParams()
	ds := jtGaps(p, "pod-uid-pred", jtN)
	period := float64(jtPeriod)
	minMag := period * 0.10
	eps := period * 1e-6
	worst := math.MaxFloat64
	for _, d := range ds {
		if e := math.Abs(float64(d) - period); e < worst {
			worst = e
		}
	}
	if worst < minMag-eps {
		t.Errorf("min prediction-error %.0f < jitter floor %.0f", worst, minMag)
	}
}

// --- PerPodPhaseOffset de-sync: distinct UIDs => distinct deterministic fires -
func TestTBTJitter_PerPodPhaseOffsetDeSync(t *testing.T) {
	// Use a 0/0 band so ONLY the phase offset differentiates the fires (isolates
	// the de-sync). Same lastRun + base; distinct UID keys must spread the fire.
	p := JitterParams{MinPercent: 0, MaxPercent: 0, Distribution: distributionUniform, Stagger: staggerPerPodPhaseOffset}
	last := time.Date(2026, 5, 30, 4, 0, 0, 0, time.UTC)
	base := schedNextBase(last, jtPeriod)

	const fleet = 200
	seen := map[time.Time]int{}
	for i := 0; i < fleet; i++ {
		uid := "pod-" + strconv.Itoa(i)
		fire := Apply(last, base, uid, seedForPod(uid), p)
		// Offset stays within one period of the base fire.
		if fire.Before(base) || fire.Sub(base) >= jtPeriod {
			t.Fatalf("phase offset out of [0,period) for %s: fire=%s base=%s", uid, fire, base)
		}
		seen[fire]++
	}
	if len(seen) < fleet/2 {
		t.Errorf("PerPodPhaseOffset poorly de-syncs: only %d distinct fires across %d UIDs", len(seen), fleet)
	}

	// Same UID is stable (deterministic).
	if Apply(last, base, "pod-1", seedForPod("pod-1"), p) != Apply(last, base, "pod-1", seedForPod("pod-1"), p) {
		t.Error("same UID must yield a stable fire")
	}
}

// --- annotation parsing + defaulting (malformed falls back, never hard-fails) -
func TestTBTJitter_ParseParamsDefaults(t *testing.T) {
	// nil annotations => full defaults.
	d := parseJitterParams(nil, nil)
	if d != DefaultJitterParams() {
		t.Errorf("nil annotations must yield defaults, got %+v", d)
	}

	// Valid overrides.
	ann := map[string]string{
		TimeBasedTriggerJitterMinPercentAnnotation:   "5",
		TimeBasedTriggerJitterMaxPercentAnnotation:   "40",
		TimeBasedTriggerJitterDistributionAnnotation: distributionTruncatedNormal,
		TimeBasedTriggerEntropySourceAnnotation:      entropyPseudoRandom,
		TimeBasedTriggerStaggerModeAnnotation:        staggerNone,
	}
	got := parseJitterParams(ann, nil)
	if got.MinPercent != 5 || got.MaxPercent != 40 || got.Distribution != distributionTruncatedNormal ||
		got.EntropySource != entropyPseudoRandom || got.Stagger != staggerNone {
		t.Errorf("valid overrides not parsed: %+v", got)
	}

	// Malformed values fall back to defaults and trigger the warn callback.
	warns := 0
	bad := map[string]string{
		TimeBasedTriggerJitterMinPercentAnnotation:   "not-a-number",
		TimeBasedTriggerJitterMaxPercentAnnotation:   "150", // out of [0,100]
		TimeBasedTriggerJitterDistributionAnnotation: "Bogus",
		TimeBasedTriggerEntropySourceAnnotation:      "Nope",
		TimeBasedTriggerStaggerModeAnnotation:        "Whatever",
	}
	bgot := parseJitterParams(bad, func(string) { warns++ })
	if bgot != DefaultJitterParams() {
		t.Errorf("malformed annotations must fall back to defaults, got %+v", bgot)
	}
	if warns != 5 {
		t.Errorf("expected 5 malformed warnings, got %d", warns)
	}
}

// --- TruncatedNormal stays in-band -------------------------------------------
func TestTBTJitter_TruncatedNormalInBand(t *testing.T) {
	p := DefaultJitterParams()
	p.Distribution = distributionTruncatedNormal
	ds := jtGaps(p, "pod-uid-tn", jtN)
	period := float64(jtPeriod)
	lo, hi := period*0.70, period*1.30
	eps := period * 1e-6
	for _, d := range ds {
		if float64(d) < lo-eps || float64(d) > hi+eps {
			t.Fatalf("TruncatedNormal gap %s escaped band [%s,%s]", d, time.Duration(lo), time.Duration(hi))
		}
	}
}
