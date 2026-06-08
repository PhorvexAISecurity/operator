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

// Package scheduler is the single jittered-cadence PRIMITIVE for Phoenix
// (capability #4, arch §6 Phase 2; decisions D5/D9/D10/D12g/D13/D14).
//
// It is a SELF-CONTAINED, side-effect-free library: it depends only on the Go
// stdlib (crypto/rand, math, time) plus the tiny seedable test RNG, and it does
// NOT import the api/v1beta1 types — the caller projects RotationPolicy into the
// plain Policy struct (filling the code defaults). This keeps the math unit-
// testable with a manual Clock + a seeded RandSource and keeps the package free
// of Kubernetes machinery. (time-based-trigger mirrors this algorithm natively in
// its own package; it does NOT import this one — there is no cross-module import.)
//
// THE MODEL (D9/D10/D12g/D13/D14):
//
//	Next(now, key, p, seed, r) = now + jitteredInterval(p, r)
//	jitteredInterval           = BaseInterval * (1 + s*m)
//	  m  in [JitterMinPercent, JitterMaxPercent]/100  via Distribution (D12g)
//	  s  in {-1, +1}                                   one entropy bit (symmetric, D10)
//	  entropy from RandSource r (crypto/rand in prod, seeded for tests) (D13)
//
//	PhaseOffset(key, p, seed) = hash(seed || key) mod BaseInterval         (D14)
//	  the deterministic, restart-safe PER-KEY de-sync phase. The caller applies it
//	  ONCE to stagger the FIRST emission (so two keys never align), while Next's
//	  per-cycle gap stays a pure jittered interval. Folding the seed in makes the
//	  phase private (an attacker who knows BaseInterval+key still cannot predict it)
//	  AND restart-reproducible (re-seeding from the persisted Secret yields the same
//	  phase => <= 1 extra rotation after a restart).
//
// BACKWARD-COMPAT (the cheap-suite gate): JitterMinPercent == JitterMaxPercent ==
// 0 (the degenerate band) makes m == 0, so jitteredInterval == BaseInterval
// EXACTLY and Next(prev) - prev == BaseInterval bit-for-bit — identical to today's
// deterministic `sched.Next(lastRun) = lastRun + BaseInterval`. PhaseOffset stays
// deterministic but is a separate, opt-in stagger the caller may or may not apply.
//
// SCHEDULE SECRECY (D5): this package returns a next-fire to its caller for
// requeue/emission; the caller MUST NOT publish that value in any world-readable
// Status/CR field. The package itself persists nothing and exposes no schedule.
package scheduler

import (
	"crypto/rand"
	"hash/fnv"
	"math"
	"math/big"
	mrand "math/rand"
	"time"
)

// Clock abstracts the wall clock so cadence math is deterministic in tests.
type Clock interface {
	Now() time.Time
}

// RealClock is the production Clock.
type RealClock struct{}

// Now returns the current time.
func (RealClock) Now() time.Time { return time.Now() }

// ManualClock is a test Clock whose time is set explicitly.
type ManualClock struct{ T time.Time }

// Now returns the manual time.
func (c *ManualClock) Now() time.Time { return c.T }

// Advance moves the manual clock forward by d.
func (c *ManualClock) Advance(d time.Duration) { c.T = c.T.Add(d) }

// RandSource is the entropy seam (D13). Production uses CryptoRand (crypto/rand);
// tests inject SeededRand (math/rand) for determinism. Float64 returns a value in
// [0,1); Int63n returns a value in [0,n); Read fills p with random bytes.
type RandSource interface {
	Float64() float64
	Int63n(n int64) int64
	Read(p []byte) (int, error)
}

// ----------------------------------------------------------------------------
// CryptoRand — the production RandSource (crypto/rand). (D13 default.)
// ----------------------------------------------------------------------------

// CryptoRand is the crypto/rand-backed production RandSource: an unforgeable
// cadence whose future draws cannot be predicted from past ones.
type CryptoRand struct{}

// NewCryptoRand returns the production crypto/rand RandSource.
func NewCryptoRand() RandSource { return CryptoRand{} }

// float64Denominator is 2^53, the number of representable fractions in a float64
// mantissa; drawing a 53-bit integer and dividing yields a uniform [0,1).
const float64Denominator = 1 << 53

// Float64 returns a uniform value in [0,1) using a 53-bit crypto/rand draw. On
// the (astronomically unlikely) error path it falls back to 0 (the band lower
// endpoint), which is safe — it never panics and never escapes the band.
func (CryptoRand) Float64() float64 {
	n, err := rand.Int(rand.Reader, big.NewInt(float64Denominator))
	if err != nil {
		return 0
	}
	return float64(n.Int64()) / float64(float64Denominator)
}

// Int63n returns a uniform value in [0,n) via crypto/rand. For n<=0 it returns 0.
func (CryptoRand) Int63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

// Read fills p with crypto/rand bytes.
func (CryptoRand) Read(p []byte) (int, error) { return rand.Read(p) }

// ----------------------------------------------------------------------------
// SeededRand — the TEST RandSource (math/rand), == EntropySource "PseudoRandom".
// ----------------------------------------------------------------------------

// SeededRand is a seeded math/rand RandSource used ONLY for test determinism (the
// EntropySource "PseudoRandom" enum value). Selecting PseudoRandom on a live AMTD
// records an EntropyWarning condition because a leaked seed makes every future
// rotation forecastable (D13).
type SeededRand struct{ r *mrand.Rand }

// NewSeededRand returns a deterministic RandSource seeded with the given seed.
func NewSeededRand(seed int64) *SeededRand {
	return &SeededRand{r: mrand.New(mrand.NewSource(seed))}
}

// Float64 returns a deterministic value in [0,1).
func (s *SeededRand) Float64() float64 { return s.r.Float64() }

// Int63n returns a deterministic value in [0,n). For n<=0 it returns 0.
func (s *SeededRand) Int63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return s.r.Int63n(n)
}

// Read fills p with deterministic bytes.
func (s *SeededRand) Read(p []byte) (int, error) { return s.r.Read(p) }

// ----------------------------------------------------------------------------
// Policy — the plain projection of RotationPolicy used by the math.
// ----------------------------------------------------------------------------

// Distribution names the jitter-magnitude shape (mirrors api JitterDistribution).
type Distribution string

const (
	// Uniform draws the magnitude uniformly over the band (max entropy; default).
	Uniform Distribution = "Uniform"
	// TruncatedNormal draws from a band-truncated normal (lower-entropy opt-in).
	TruncatedNormal Distribution = "TruncatedNormal"
)

// Stagger names the per-key de-sync mode (mirrors api StaggerMode).
type Stagger string

const (
	// PerPodPhaseOffset gives a deterministic per-key initial phase (default).
	PerPodPhaseOffset Stagger = "PerPodPhaseOffset"
	// Independent applies jitter only (no fixed phase).
	Independent Stagger = "Independent"
	// None applies no phase.
	None Stagger = "None"
)

// Policy is the plain, api-free projection the executor fills from RotationPolicy
// (applying the code defaults: BaseInterval 60m/floor 5m, band 10/30, Uniform,
// PerPodPhaseOffset). Keeping it api-free is what lets the math be unit-tested in
// isolation and keeps this package importable without Kubernetes types.
type Policy struct {
	// BaseInterval is the cadence PERIOD R (already defaulted + floored by the
	// caller's effective-policy code).
	BaseInterval time.Duration
	// JitterMinPercent / JitterMaxPercent are the symmetric band endpoints (0..100,
	// already validated by the caller). Equal endpoints (incl. 0/0) => deterministic.
	JitterMinPercent int
	JitterMaxPercent int
	// Distribution shapes the magnitude draw; empty => Uniform.
	Distribution Distribution
	// Stagger selects the per-key de-sync phase; empty => PerPodPhaseOffset.
	Stagger Stagger
}

// normalized returns the policy with empty enum fields resolved to their code
// defaults and the band clamped into [0,100] with min<=max (a final in-package
// safety net; the apiserver CEL rule already enforces the bounds).
func (p Policy) normalized() Policy {
	if p.Distribution == "" {
		p.Distribution = Uniform
	}
	if p.Stagger == "" {
		p.Stagger = PerPodPhaseOffset
	}
	if p.JitterMinPercent < 0 {
		p.JitterMinPercent = 0
	}
	if p.JitterMaxPercent > 100 {
		p.JitterMaxPercent = 100
	}
	if p.JitterMaxPercent < p.JitterMinPercent {
		p.JitterMaxPercent = p.JitterMinPercent
	}
	return p
}

// ----------------------------------------------------------------------------
// The primitive: Next + JitteredInterval + PhaseOffset.
// ----------------------------------------------------------------------------

// Next returns the next jittered fire time after now for the given key. It is a
// PURE function of (now, key, policy, seed, r-draw): with the SAME seed and the
// SAME RandSource state it returns the SAME result, which is what makes the
// cadence restart-reproducible from the persisted seed (D5). key and seed are
// accepted for symmetry with PhaseOffset and so a future per-key entropy mix can
// be added without changing the signature; today the gap is keyed purely by the
// RandSource draw (the caller supplies a per-key/seeded source where per-key
// decorrelation of the GAP is wanted, while the deterministic per-key PHASE is
// provided by PhaseOffset).
func Next(now time.Time, key string, p Policy, seed []byte, r RandSource) time.Time {
	return now.Add(JitteredInterval(p, r))
}

// JitteredInterval returns one jittered cadence interval BaseInterval*(1 +/- m).
// With JitterMinPercent == JitterMaxPercent (in particular 0/0) the magnitude m
// is 0, so the result is EXACTLY BaseInterval (the deterministic-cadence
// bit-for-bit backward-compat guarantee). The result is always clamped to be
// strictly positive (a magnitude of 100% downward would otherwise yield 0).
func JitteredInterval(p Policy, r RandSource) time.Duration {
	p = p.normalized()
	base := float64(p.BaseInterval)

	m := drawMagnitude(p, r) // in [min,max]/100, >= 0
	if m == 0 {
		// Degenerate band => deterministic cadence, bit-for-bit == BaseInterval.
		return p.BaseInterval
	}

	// Symmetric sign from one entropy bit (D10): {-1,+1}.
	sign := 1.0
	if r.Int63n(2) == 0 {
		sign = -1.0
	}

	eff := base * (1 + sign*m)
	if eff < 1 {
		eff = 1 // never produce a non-positive interval.
	}
	return time.Duration(eff)
}

// drawMagnitude draws the jitter magnitude m in [JitterMinPercent,
// JitterMaxPercent]/100 using the selected distribution (D12g). Equal endpoints
// short-circuit to the (deterministic) endpoint value.
func drawMagnitude(p Policy, r RandSource) float64 {
	minP := float64(p.JitterMinPercent) / 100.0
	maxP := float64(p.JitterMaxPercent) / 100.0
	if maxP <= minP {
		return minP
	}
	switch p.Distribution {
	case TruncatedNormal:
		mean := (minP + maxP) / 2.0
		stddev := (maxP - minP) / 4.0
		// Resample until in-band (bounded attempts; fall back to the uniform draw
		// so we never loop unboundedly on a pathological RNG).
		for i := 0; i < 64; i++ {
			v := mean + stddev*normFromUniform(r)
			if v >= minP && v <= maxP {
				return v
			}
		}
		return minP + r.Float64()*(maxP-minP)
	default: // Uniform
		return minP + r.Float64()*(maxP-minP)
	}
}

// normFromUniform returns a standard-normal sample via the Box-Muller transform
// from two uniform draws (keeps the package's only RNG dependency RandSource).
func normFromUniform(r RandSource) float64 {
	u1 := r.Float64()
	if u1 < 1e-12 {
		u1 = 1e-12 // avoid log(0).
	}
	u2 := r.Float64()
	return math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2.0*math.Pi*u2)
}

// PhaseOffset returns the deterministic per-key initial phase offset (D14
// PerPodPhaseOffset): hash(seed || key) mod BaseInterval. It is RESTART-SAFE
// (pure in seed+key+BaseInterval, no persisted next-fire) and PRIVATE (folding the
// seed in means an attacker who knows BaseInterval+key still cannot compute it).
// The caller applies it ONCE to stagger the FIRST emission so two keys de-sync;
// the per-cycle gap from Next is unaffected (preserving the deterministic-cadence
// bit-for-bit property). Stagger==Independent or None returns 0.
func PhaseOffset(key string, p Policy, seed []byte) time.Duration {
	p = p.normalized()
	if p.Stagger != PerPodPhaseOffset || p.BaseInterval <= 0 {
		return 0
	}
	h := fnv.New64a()
	// Mix the seed first, then the key, so distinct (seed,key) pairs decorrelate.
	_, _ = h.Write(seed)
	_, _ = h.Write([]byte{0x1f}) // domain separator between seed and key.
	_, _ = h.Write([]byte(key))
	sum := h.Sum64()
	return time.Duration(sum % uint64(p.BaseInterval))
}

// SeedToInt63 folds a seed byte slice into an int63 suitable for NewSeededRand,
// so a persisted Secret seed can deterministically drive the PseudoRandom test
// source if ever selected. (Production uses CryptoRand and ignores this.)
func SeedToInt63(seed []byte) int64 {
	h := fnv.New64a()
	_, _ = h.Write(seed)
	v := h.Sum64()
	// Mask to a non-negative int64.
	return int64(v & 0x7fffffffffffffff)
}

// RandBytes returns n cryptographically-random bytes (used by the caller to mint a
// fresh persisted seed). On error it returns a zero-filled slice of length n; the
// caller is expected to surface the error and not persist a weak seed silently.
func RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// Uint64FromSeed is a small helper exposing the seed-mixing used internally, so a
// caller can derive a stable sub-key from the persisted seed if needed.
func Uint64FromSeed(seed []byte, salt string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(seed)
	_, _ = h.Write([]byte(salt))
	return h.Sum64()
}
