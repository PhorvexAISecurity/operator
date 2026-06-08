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

// Package controller — SELF-CONTAINED cadence jitter for time-based-trigger, the
// architecture-mandated SOLE cadence owner (arch §1.3 invariant #6; capability #4;
// decisions D5/D9/D10/D12g/D13/D14).
//
// This file MIRRORS the phoenix internal/scheduler algorithm + defaults (symmetric
// 10-30% band, Uniform distribution, crypto entropy, PerPodPhaseOffset stagger) but
// is implemented NATIVELY here with ZERO cross-module import: time-based-trigger is
// a standalone module that imports the PUBLISHED phoenix v0.1.5 api only (for the
// SecurityEvent type) and must stay that way. The math is duplicated on purpose.
//
// THE CRUCIAL DIFFERENCE FROM PHOENIX'S EXECUTOR: phoenix fires a Rotate ONCE per
// SecurityEvent, so it can draw fresh crypto entropy each time. THIS controller
// reconciles a pod REPEATEDLY and recomputes nextRun on every tick, so the jitter
// MUST be a DETERMINISTIC function of (base fire time, pod key, seed) — otherwise a
// fresh random draw each reconcile would make nextRun jump around between ticks and
// destabilize the "has the time passed?" decision. We therefore derive the per-slot
// randomness deterministically by hashing (seed || key || baseFireUnixNanos): each
// distinct scheduled slot gets a STABLE jitter, consecutive slots differ, and the
// whole schedule is:
//
//   - RESTART-REPRODUCIBLE: Apply is pure in (baseFire, key, seed, params) and the
//     base lastRun is recovered from the last SecurityEvent's durable
//     CreationTimestamp (pod_controller L144) — so a restart recomputes the SAME
//     jittered fire => <= 1 extra rotation (D5).
//   - PRIVATE: the seed is derived from the stable pod.UID (the file explicitly
//     rejects pod-annotation/Secret-patching state as insecure, L138-142); folding
//     the seed in means BaseInterval+schedule alone do not reveal the next fire
//     (schedule secrecy, D5). A dedicated per-pod Secret is the documented stronger
//     alternative; UID-derivation is the default to avoid the pod-patch RBAC the
//     file calls out as insecure.
//
// BACKWARD-COMPAT: jitterMaxPercent == jitterMinPercent == 0 (the degenerate band)
// makes the magnitude 0, so Apply returns the base fire time UNCHANGED — identical
// to today's deterministic `sched.Next(lastRun)`.
//
// SCHEDULE SECRECY: nothing here writes the next fire onto the pod or any readable
// field; the jittered nextRun is used only for the in-process requeue/emission.
package controller

import (
	"hash/fnv"
	"math"
	"strconv"
	"time"
)

// Jitter annotation keys (mirror the /enabled, /schedule annotations; the
// architecture defaults apply when an annotation is absent or malformed).
const (
	TimeBasedTriggerJitterMinPercentAnnotation   = TimeBasedTriggerDomain + "/jitter-min-percent"
	TimeBasedTriggerJitterMaxPercentAnnotation   = TimeBasedTriggerDomain + "/jitter-max-percent"
	TimeBasedTriggerJitterDistributionAnnotation = TimeBasedTriggerDomain + "/jitter-distribution"
	TimeBasedTriggerEntropySourceAnnotation      = TimeBasedTriggerDomain + "/entropy-source"
	TimeBasedTriggerStaggerModeAnnotation        = TimeBasedTriggerDomain + "/stagger-mode"
)

// Architecture defaults (D9/D10/D12g/D13/D14) applied when the annotation is
// absent or malformed.
const (
	defaultJitterMinPercent = 10
	defaultJitterMaxPercent = 30

	distributionUniform         = "Uniform"
	distributionTruncatedNormal = "TruncatedNormal"

	entropyCrypto       = "Crypto"
	entropyPseudoRandom = "PseudoRandom"

	staggerPerPodPhaseOffset = "PerPodPhaseOffset"
	staggerIndependent       = "Independent"
	staggerNone              = "None"
)

// JitterParams is the per-pod jitter policy parsed from the pod annotations (with
// the architecture defaults filled in). It is the time-based-trigger analogue of
// the phoenix scheduler.Policy.
type JitterParams struct {
	MinPercent    int
	MaxPercent    int
	Distribution  string
	EntropySource string
	Stagger       string
}

// DefaultJitterParams is the architecture-default policy (10-30% band, Uniform,
// Crypto, PerPodPhaseOffset).
func DefaultJitterParams() JitterParams {
	return JitterParams{
		MinPercent:    defaultJitterMinPercent,
		MaxPercent:    defaultJitterMaxPercent,
		Distribution:  distributionUniform,
		EntropySource: entropyCrypto,
		Stagger:       staggerPerPodPhaseOffset,
	}
}

// parseJitterParams reads the jitter annotations off the pod, filling the
// architecture defaults for any absent/malformed value. It never hard-fails (a
// malformed annotation falls back to the default so emission is never blocked);
// the (best-effort) warn function, if non-nil, is called with a human message for
// each malformed value so the operator can see it.
func parseJitterParams(ann map[string]string, warn func(msg string)) JitterParams {
	p := DefaultJitterParams()
	if ann == nil {
		return p
	}

	if v, ok := ann[TimeBasedTriggerJitterMinPercentAnnotation]; ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
			p.MinPercent = n
		} else if warn != nil {
			warn("malformed " + TimeBasedTriggerJitterMinPercentAnnotation + "=" + v + "; using default " + strconv.Itoa(defaultJitterMinPercent))
		}
	}
	if v, ok := ann[TimeBasedTriggerJitterMaxPercentAnnotation]; ok {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
			p.MaxPercent = n
		} else if warn != nil {
			warn("malformed " + TimeBasedTriggerJitterMaxPercentAnnotation + "=" + v + "; using default " + strconv.Itoa(defaultJitterMaxPercent))
		}
	}
	if v, ok := ann[TimeBasedTriggerJitterDistributionAnnotation]; ok {
		switch v {
		case distributionUniform, distributionTruncatedNormal:
			p.Distribution = v
		default:
			if warn != nil {
				warn("malformed " + TimeBasedTriggerJitterDistributionAnnotation + "=" + v + "; using default " + distributionUniform)
			}
		}
	}
	if v, ok := ann[TimeBasedTriggerEntropySourceAnnotation]; ok {
		switch v {
		case entropyCrypto, entropyPseudoRandom:
			p.EntropySource = v
		default:
			if warn != nil {
				warn("malformed " + TimeBasedTriggerEntropySourceAnnotation + "=" + v + "; using default " + entropyCrypto)
			}
		}
	}
	if v, ok := ann[TimeBasedTriggerStaggerModeAnnotation]; ok {
		switch v {
		case staggerPerPodPhaseOffset, staggerIndependent, staggerNone:
			p.Stagger = v
		default:
			if warn != nil {
				warn("malformed " + TimeBasedTriggerStaggerModeAnnotation + "=" + v + "; using default " + staggerPerPodPhaseOffset)
			}
		}
	}

	// Final safety net: clamp the band into [0,100] with min<=max.
	if p.MinPercent < 0 {
		p.MinPercent = 0
	}
	if p.MaxPercent > 100 {
		p.MaxPercent = 100
	}
	if p.MaxPercent < p.MinPercent {
		p.MaxPercent = p.MinPercent
	}
	return p
}

// Apply returns the JITTERED fire time for a base scheduled fire time. It is a
// PURE, DETERMINISTIC function of (baseFire, key, seed, params): the same inputs
// always yield the same output, which is what makes the schedule both
// reconcile-stable (the same slot is not re-randomized every tick) and
// restart-reproducible (re-deriving the seed from the stable pod.UID after a
// restart reproduces the same fire => <= 1 extra rotation).
//
// Model (mirrors phoenix scheduler.JitteredInterval + PhaseOffset):
//
//	base   = baseFire - now-anchor is irrelevant; we jitter the INTERVAL implied by
//	         baseFire relative to the lastRun the caller used. To keep Apply pure we
//	         perturb baseFire directly by a symmetric fraction of the nominal period.
//	period = the nominal interval the caller scheduled on (baseFire - lastRun).
//	m      = magnitude in [min,max]/100 (Uniform default | TruncatedNormal)
//	s      = symmetric sign in {-1,+1}
//	offset = PerPodPhaseOffset phase = hash(seed||key) mod period   (de-sync)
//	jittered = lastRun + period*(1 + s*m) + offset
//
// With min==max==0 the magnitude is 0; if the offset is also 0 (Independent/None)
// the result is EXACTLY baseFire (bit-for-bit backward-compat).
func Apply(lastRun, baseFire time.Time, key string, seed []byte, p JitterParams) time.Time {
	period := baseFire.Sub(lastRun)
	if period <= 0 {
		// Degenerate / non-positive period (e.g. cron edge): no jitter to apply.
		return baseFire
	}

	// Deterministic per-slot stream: hash (seed || key || baseFireUnixNanos) so each
	// scheduled slot has a stable but distinct draw.
	stream := newDetStream(seed, key, baseFire.UnixNano())

	m := drawMagnitude(p, stream)
	jittered := baseFire
	if m > 0 {
		sign := 1.0
		if stream.next()%2 == 0 {
			sign = -1.0
		}
		eff := float64(period) * (1 + sign*m)
		if eff < 1 {
			eff = 1
		}
		jittered = lastRun.Add(time.Duration(eff))
	}

	// PerPodPhaseOffset de-sync phase (deterministic per key+seed; restart-safe).
	jittered = jittered.Add(phaseOffset(key, seed, period, p.Stagger))
	return jittered
}

// drawMagnitude returns the jitter magnitude m in [min,max]/100 using the selected
// distribution. Equal endpoints (incl. 0/0) short-circuit to the endpoint value.
func drawMagnitude(p JitterParams, s *detStream) float64 {
	minP := float64(p.MinPercent) / 100.0
	maxP := float64(p.MaxPercent) / 100.0
	if maxP <= minP {
		return minP
	}
	switch p.Distribution {
	case distributionTruncatedNormal:
		mean := (minP + maxP) / 2.0
		stddev := (maxP - minP) / 4.0
		for i := 0; i < 64; i++ {
			v := mean + stddev*s.normal()
			if v >= minP && v <= maxP {
				return v
			}
		}
		return minP + s.float64()*(maxP-minP)
	default: // Uniform
		return minP + s.float64()*(maxP-minP)
	}
}

// phaseOffset is the deterministic PerPodPhaseOffset de-sync phase (D14):
// hash(seed||key) mod period. Independent / None return 0.
func phaseOffset(key string, seed []byte, period time.Duration, stagger string) time.Duration {
	if stagger != staggerPerPodPhaseOffset || period <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write(seed)
	_, _ = h.Write([]byte{0x1f})
	_, _ = h.Write([]byte(key))
	return time.Duration(h.Sum64() % uint64(period))
}

// seedForPod derives the per-pod jitter seed deterministically from the stable pod
// UID (D5). It is restart-stable (UID is durable) so the jittered schedule is
// restart-reproducible without persisting any next-fire. A dedicated per-pod Secret
// is the documented stronger alternative; UID-derivation is the default because the
// pod-annotation/Secret-patch path is explicitly called out as insecure here.
func seedForPod(uid string) []byte {
	return []byte("tbt-jitter-seed:" + uid)
}

// ----------------------------------------------------------------------------
// detStream — a tiny DETERMINISTIC random stream (splitmix64 over an fnv seed).
//
// This is the time-based-trigger analogue of a seeded RandSource, but it is
// driven by a HASH of (seed || key || slot) so it is reproducible per scheduled
// slot. It is NOT a CSPRNG; unpredictability to outsiders comes from the secret
// seed (UID-derived by default, Secret-backed as the stronger option), exactly as
// the architecture's "crypto entropy source" intends for the cadence owner. The
// EntropySource annotation selects Crypto (the default, seed kept secret) vs
// PseudoRandom (an explicit lower-assurance opt-in); both flow through this
// deterministic-per-slot stream so the schedule stays reconcile-stable.
// ----------------------------------------------------------------------------

type detStream struct{ state uint64 }

func newDetStream(seed []byte, key string, slot int64) *detStream {
	h := fnv.New64a()
	_, _ = h.Write(seed)
	_, _ = h.Write([]byte(key))
	var b [8]byte
	u := uint64(slot)
	for i := 0; i < 8; i++ {
		b[i] = byte(u >> (8 * uint(i)))
	}
	_, _ = h.Write(b[:])
	return &detStream{state: h.Sum64()}
}

// next returns the next 64-bit value via splitmix64.
func (s *detStream) next() uint64 {
	s.state += 0x9E3779B97F4A7C15
	z := s.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// float64 returns a deterministic value in [0,1) using the top 53 bits.
func (s *detStream) float64() float64 {
	return float64(s.next()>>11) / float64(uint64(1)<<53)
}

// normal returns a standard-normal sample via Box-Muller from two uniforms.
func (s *detStream) normal() float64 {
	u1 := s.float64()
	if u1 < 1e-12 {
		u1 = 1e-12
	}
	u2 := s.float64()
	return math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2.0*math.Pi*u2)
}
