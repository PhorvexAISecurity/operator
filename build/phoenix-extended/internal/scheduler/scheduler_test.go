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

// Package scheduler tests — the deterministic "strongest cheap suite" for the
// jittered-cadence primitive (arch §6 Phase 2). Everything here uses a manual
// Clock + a SEEDED RandSource so the math is exercised with NO real clock and NO
// crypto/rand non-determinism:
//
//	a. gap mean == BaseInterval                          (symmetric band, zero mean)
//	b. spread covers base*(1 +/- JitterMax/100), NO spike (variance>0, many buckets)
//	c. prediction-error >= jitter magnitude              (predict base; err >= min band)
//	d. max instance lifetime <= base*(1 + JitterMax/100) (exposure-window bound)
//	e. JitterMin==JitterMax==0 (and nil) reproduces deterministic cadence BIT-FOR-BIT
//	f. restart-safety: re-seed => identical offset => <= 1 extra rotation
//	g. PerPodPhaseOffset: distinct keys => distinct deterministic offsets; same key stable
package scheduler

import (
	"math"
	"testing"
	"time"
)

const (
	testBase = 60 * time.Minute
	nDraws   = 5000 // >= 1000 as the plan requires; large enough for stable stats.
)

// uniformPolicy is the paper-band Uniform policy (10-30%, PerPodPhaseOffset).
func uniformPolicy() Policy {
	return Policy{
		BaseInterval:     testBase,
		JitterMinPercent: 10,
		JitterMaxPercent: 30,
		Distribution:     Uniform,
		Stagger:          PerPodPhaseOffset,
	}
}

// gaps draws n jittered intervals from a freshly-seeded source.
func gaps(p Policy, seed int64, n int) []time.Duration {
	r := NewSeededRand(seed)
	out := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		out[i] = JitteredInterval(p, r)
	}
	return out
}

func meanStd(ds []time.Duration) (mean, std float64) {
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
	std = math.Sqrt(v / float64(len(ds)))
	return
}

// --- a. gap mean == BaseInterval (within tolerance) -------------------------
func TestCheapSuite_A_GapMeanEqualsBaseInterval(t *testing.T) {
	p := uniformPolicy()
	ds := gaps(p, 1, nDraws)
	mean, _ := meanStd(ds)
	base := float64(testBase)

	// Symmetric +/- band => the magnitude is symmetric in sign, so the mean gap
	// should sit at BaseInterval. Allow 2% sampling tolerance on the mean.
	tol := 0.02 * base
	if math.Abs(mean-base) > tol {
		t.Errorf("a) gap mean = %s, want ~%s (|diff|=%.0f > tol %.0f)",
			time.Duration(mean), testBase, math.Abs(mean-base), tol)
	}
}

// --- b. spread over the band, NO degenerate spike ---------------------------
func TestCheapSuite_B_SpreadNoDegenerateSpike(t *testing.T) {
	p := uniformPolicy()
	ds := gaps(p, 2, nDraws)
	_, std := meanStd(ds)
	if std <= 0 {
		t.Fatalf("b) jittered cadence must have variance > 0 (got std=%.0f) — a degenerate spike", std)
	}

	// Histogram the gaps into buckets across [base*(1-max), base*(1+max)]; assert
	// no single bucket dominates (no degenerate spike) and many buckets are hit.
	base := float64(testBase)
	maxFrac := 0.30
	lo := base * (1 - maxFrac)
	hi := base * (1 + maxFrac)
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
	nonEmpty := 0
	maxCount := 0
	for _, c := range counts {
		if c > 0 {
			nonEmpty++
		}
		if c > maxCount {
			maxCount = c
		}
	}
	// Symmetric band with a forbidden gap around the center (|m|>=10%): we expect
	// many populated buckets and no single bucket holding the bulk of the mass.
	if nonEmpty < 6 {
		t.Errorf("b) expected the spread to populate many buckets, got %d/%d", nonEmpty, buckets)
	}
	if float64(maxCount) > 0.5*float64(len(ds)) {
		t.Errorf("b) degenerate spike: one bucket holds %d/%d draws (> 50%%)", maxCount, len(ds))
	}
}

// --- c. prediction-error >= jitter magnitude --------------------------------
func TestCheapSuite_C_PredictionErrorAtLeastJitter(t *testing.T) {
	p := uniformPolicy()
	ds := gaps(p, 3, nDraws)
	base := float64(testBase)
	// An attacker predicting the next fire at exactly BaseInterval incurs an error
	// of |gap - base| = base*|m|, which is >= base*JitterMin/100 on EVERY draw
	// (the band excludes [0, min)). Assert the minimum observed error meets the
	// band's lower magnitude (minus a tiny epsilon for float rounding).
	minMagnitude := base * 0.10
	eps := base * 1e-6
	worst := math.MaxFloat64
	for _, d := range ds {
		err := math.Abs(float64(d) - base)
		if err < worst {
			worst = err
		}
	}
	if worst < minMagnitude-eps {
		t.Errorf("c) min prediction-error %.0f < jitter magnitude floor %.0f (base*10%%)", worst, minMagnitude)
	}
}

// --- d. max instance lifetime <= base*(1 + JitterMax/100) -------------------
func TestCheapSuite_D_MaxLifetimeBounded(t *testing.T) {
	p := uniformPolicy()
	ds := gaps(p, 4, nDraws)
	bound := float64(testBase) * (1 + 0.30)
	eps := float64(testBase) * 1e-6
	for _, d := range ds {
		if float64(d) > bound+eps {
			t.Errorf("d) gap %s exceeds the max-lifetime bound %s (base*(1+30%%))", d, time.Duration(bound))
		}
	}
}

// --- e. JitterMin==JitterMax==0 reproduces deterministic cadence BIT-FOR-BIT -
func TestCheapSuite_E_ZeroJitterDeterministicBitForBit(t *testing.T) {
	// (i) explicit 0/0 band.
	zero := Policy{BaseInterval: testBase, JitterMinPercent: 0, JitterMaxPercent: 0}
	// (ii) the "nil-equivalent" projection the executor produces when no jitter is
	// configured is also 0/0 (effectiveJitter* default to 10/30, but the
	// backward-compat contract is specifically the 0/0 degenerate case; a policy
	// with equal endpoints is deterministic regardless of the value).
	for _, p := range []Policy{zero, {BaseInterval: testBase, JitterMinPercent: 0, JitterMaxPercent: 0, Distribution: Uniform, Stagger: PerPodPhaseOffset}} {
		r := NewSeededRand(99)
		now := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
		// Today's deterministic cadence is exactly prev + BaseInterval. Walk the
		// schedule and assert every gap equals BaseInterval EXACTLY.
		cur := now
		for i := 0; i < 1000; i++ {
			nxt := Next(cur, "any-key", p, []byte("seed"), r)
			if gap := nxt.Sub(cur); gap != testBase {
				t.Fatalf("e) zero-jitter gap = %s, want EXACTLY %s (bit-for-bit deterministic cadence)", gap, testBase)
			}
			cur = nxt
		}
	}
}

// --- e'. Equal NON-ZERO endpoints fix the MAGNITUDE (not the sign): the gap is
// always exactly one of {base*(1-m), base*(1+m)} (the symmetric +/- sign still
// flips per draw), and the two-point distribution is zero-mean about base. This
// documents that the bit-for-bit determinism guarantee is specifically the 0/0
// degenerate band (test e), where m==0 makes the sign irrelevant.
func TestCheapSuite_E_EqualEndpointsFixedMagnitude(t *testing.T) {
	p := Policy{BaseInterval: testBase, JitterMinPercent: 20, JitterMaxPercent: 20}
	r := NewSeededRand(7)
	// Compute the two expected points EXACTLY as JitteredInterval does, so the
	// equality is not fragile to float rounding of 0.20.
	m := float64(20) / 100.0
	base := float64(testBase)
	down := time.Duration(base * (1 + (-1.0)*m)) // base*(1-0.20)
	up := time.Duration(base * (1 + (1.0)*m))    // base*(1+0.20)
	sawDown, sawUp := false, false
	for i := 0; i < 1000; i++ {
		got := JitteredInterval(p, r)
		switch got {
		case down:
			sawDown = true
		case up:
			sawUp = true
		default:
			t.Fatalf("e') equal endpoints must fix the magnitude: draw %d = %s, want %s or %s", i, got, down, up)
		}
	}
	if !sawDown || !sawUp {
		t.Errorf("e') symmetric sign must produce BOTH sides: sawDown=%v sawUp=%v", sawDown, sawUp)
	}
}

// --- f. restart-safety: re-seed => identical offset => <= 1 extra rotation ---
func TestCheapSuite_F_RestartSafetyReseedReproducesOffset(t *testing.T) {
	p := uniformPolicy()
	seed := []byte("persisted-secret-seed-bytes-xxxx")
	key := "pod-uid-abc"

	// Two independent "process instances" re-seed from the SAME persisted seed.
	off1 := PhaseOffset(key, p, seed)
	off2 := PhaseOffset(key, p, seed)
	if off1 != off2 {
		t.Fatalf("f) PhaseOffset must be reproducible across restarts: %s vs %s", off1, off2)
	}

	// The jittered gap sequence is also reproducible across two re-seeded sources
	// (so a restart that re-seeds from the Secret recomputes the same schedule;
	// the only possible divergence is the single in-flight cycle == <= 1 extra
	// rotation). Drive the SAME deterministic source seed both times.
	srcSeed := SeedToInt63(seed)
	a := NewSeededRand(srcSeed)
	b := NewSeededRand(srcSeed)
	for i := 0; i < 1000; i++ {
		if JitteredInterval(p, a) != JitteredInterval(p, b) {
			t.Fatalf("f) re-seeded gap sequences diverged at draw %d", i)
		}
	}
}

// --- g. PerPodPhaseOffset: distinct keys => distinct deterministic offsets ---
func TestCheapSuite_G_PerPodPhaseOffsetDeSync(t *testing.T) {
	p := uniformPolicy()
	seed := []byte("seed-for-stagger")

	// Same key is stable (deterministic).
	if PhaseOffset("k1", p, seed) != PhaseOffset("k1", p, seed) {
		t.Error("g) same key must yield a stable offset")
	}

	// Distinct keys de-sync: across a fleet of keys we expect a healthy number of
	// DISTINCT offsets (not all colliding to one phase).
	const fleet = 200
	seen := map[time.Duration]int{}
	for i := 0; i < fleet; i++ {
		k := "pod-" + itoa(i)
		off := PhaseOffset(k, p, seed)
		if off < 0 || off >= testBase {
			t.Fatalf("g) offset %s out of [0,BaseInterval=%s) for key %s", off, testBase, k)
		}
		seen[off]++
	}
	if len(seen) < fleet/2 {
		t.Errorf("g) PerPodPhaseOffset poorly de-syncs: only %d distinct offsets across %d keys", len(seen), fleet)
	}

	// Folding the SEED in makes the phase private: a different seed yields a
	// different offset for the same key (so BaseInterval+key alone don't predict it).
	if PhaseOffset("k1", p, seed) == PhaseOffset("k1", p, []byte("a-different-seed")) {
		t.Error("g) PhaseOffset must depend on the seed (private cadence): equal offsets across different seeds")
	}

	// Independent / None disable the fixed offset.
	pi := p
	pi.Stagger = Independent
	if PhaseOffset("k1", pi, seed) != 0 {
		t.Error("g) Independent stagger must yield a 0 fixed offset")
	}
	pn := p
	pn.Stagger = None
	if PhaseOffset("k1", pn, seed) != 0 {
		t.Error("g) None stagger must yield a 0 fixed offset")
	}
}

// --- TruncatedNormal stays in-band (lower-entropy opt-in) --------------------
func TestCheapSuite_TruncatedNormalInBand(t *testing.T) {
	p := uniformPolicy()
	p.Distribution = TruncatedNormal
	ds := gaps(p, 11, nDraws)
	base := float64(testBase)
	lo := base * (1 - 0.30)
	hi := base * (1 + 0.30)
	eps := base * 1e-6
	for _, d := range ds {
		if float64(d) < lo-eps || float64(d) > hi+eps {
			t.Fatalf("TruncatedNormal gap %s escaped the band [%s,%s]", d, time.Duration(lo), time.Duration(hi))
		}
	}
	// And it still has spread (not a spike).
	if _, std := meanStd(ds); std <= 0 {
		t.Error("TruncatedNormal must still have variance > 0")
	}
}

// --- CryptoRand smoke: production source produces in-band, varied gaps -------
func TestCryptoRand_InBandAndVaried(t *testing.T) {
	p := uniformPolicy()
	r := NewCryptoRand()
	base := float64(testBase)
	lo := base * (1 - 0.30)
	hi := base * (1 + 0.30)
	eps := base * 1e-6
	seen := map[time.Duration]int{}
	for i := 0; i < 1000; i++ {
		d := JitteredInterval(p, r)
		if float64(d) < lo-eps || float64(d) > hi+eps {
			t.Fatalf("crypto gap %s escaped the band [%s,%s]", d, time.Duration(lo), time.Duration(hi))
		}
		seen[d]++
	}
	if len(seen) < 100 {
		t.Errorf("crypto source should produce varied gaps, only %d distinct in 1000 draws", len(seen))
	}
}

// itoa is a tiny non-fmt int->string for test keys.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
