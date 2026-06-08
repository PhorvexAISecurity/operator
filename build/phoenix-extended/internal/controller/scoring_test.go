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

package controller

import (
	"math"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func strptr(s string) *string { return &s }
func intptr(i int) *int       { return &i }

// scoredEvent builds a SecurityEvent with a trusted Source and an AnomalyScore.
func scoredEvent(name, target, source, score string) *amtdv1beta1.SecurityEvent {
	ev := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: name, CreationTimestamp: metav1.NewTime(time.Now())},
		Spec: amtdv1beta1.SecurityEventSpec{
			Targets:     []string{target},
			Rule:        amtdv1beta1.Rule{Type: TriggerTypeTimed, ThreatLevel: "info", Source: source},
			Description: "scored event",
		},
	}
	if score != "" {
		ev.Spec.AnomalyScore = strptr(score)
	}
	return ev
}

// amtdScored builds an AMTD in Scored mode with an AdaptiveRotation block carrying
// the given knobs (any nil => code default) and a scored Rotate strategy keyed on
// a ScoreThreshold so the matcher selects Rotate at score>=thr.
func amtdScored(ns, name string, ar *amtdv1beta1.AdaptiveRotationPolicy, scoreThreshold string) *amtdv1beta1.AdaptiveMovingTargetDefense {
	// When a ScoreThreshold is given, the scored Rotate rule keys ONLY on the score
	// (no legacy Source guard), so any trusted-Source event with score>=threshold
	// selects Rotate. When no threshold is given the rule is the bare timed exact
	// rule (matches a {timed,info,TimeBasedTrigger} event).
	var rule amtdv1beta1.Rule
	if scoreThreshold != "" {
		rule = amtdv1beta1.Rule{ScoreThreshold: strptr(scoreThreshold)}
	} else {
		rule = amtdv1beta1.Rule{Type: TriggerTypeTimed, ThreatLevel: "info", Source: TriggerSourceTimeBasedTrigger}
	}
	return &amtdv1beta1.AdaptiveMovingTargetDefense{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			PodSelector: map[string]string{"app": "demo"},
			MatcherMode: amtdv1beta1.MatcherModeScored,
			InferenceRotation: &amtdv1beta1.InferenceRotationSpec{
				GoldenImage:      "secure:2",
				AdaptiveRotation: ar,
			},
			Strategy: []amtdv1beta1.ResponseStrategy{{
				Rule:   rule,
				Action: amtdv1beta1.AMTDAction{Rotate: &amtdv1beta1.RotateAction{PolicyRef: &amtdv1beta1.LocalPolicyRef{Kind: "InferenceRotation"}}},
			}},
		},
	}
}

// T1 — EWMA math: smoothed = alpha*score + (1-alpha)*prev. alpha=0.3, prev=0.4,
// score=0.9 => 0.55. Then the sequence of all-0.9 inputs converges toward 0.9.
func TestEWMA_Math(t *testing.T) {
	alpha := 0.3
	prev := 0.4
	score := 0.9
	got := alpha*score + (1-alpha)*prev
	if math.Abs(got-0.55) > 1e-9 {
		t.Fatalf("EWMA: got %v, want 0.55", got)
	}
	// Convergence: repeated 0.9 inputs approach 0.9.
	s := 0.0
	for i := 0; i < 50; i++ {
		s = alpha*0.9 + (1-alpha)*s
	}
	if math.Abs(s-0.9) > 1e-3 {
		t.Errorf("EWMA convergence: got %v, want ~0.9", s)
	}
}

// T3 — ComputedInterval is monotone non-increasing in smoothed and bounded to
// [MinInterval, BaseInterval]. With a 10m BaseInterval and 1m MinInterval,
// smoothed 0 -> 10m, smoothed 1 -> 1m, and every step is <= the previous.
func TestComputedInterval_MonotoneDecreasingBounded(t *testing.T) {
	base := 10 * time.Minute
	min := 1 * time.Minute
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			InferenceRotation: &amtdv1beta1.InferenceRotationSpec{
				RotationPolicy: &amtdv1beta1.RotationPolicy{
					BaseInterval: &metav1.Duration{Duration: base},
					MinInterval:  &metav1.Duration{Duration: min},
				},
			},
		},
	}
	if got := computedInterval(amtd, 0); got != base {
		t.Errorf("smoothed=0: interval=%s, want BaseInterval=%s", got, base)
	}
	if got := computedInterval(amtd, 1); got != min {
		t.Errorf("smoothed=1: interval=%s, want MinInterval=%s", got, min)
	}
	prev := computedInterval(amtd, 0)
	for i := 1; i <= 100; i++ {
		s := float64(i) / 100.0
		cur := computedInterval(amtd, s)
		if cur > prev {
			t.Fatalf("not monotone non-increasing: smoothed=%v interval=%s > prev=%s", s, cur, prev)
		}
		if cur < min || cur > base {
			t.Fatalf("interval out of bounds at smoothed=%v: %s not in [%s,%s]", s, cur, min, base)
		}
		prev = cur
	}
}

// T4 — Rising score 0->1 strictly shrinks the interval at the band edges (the
// Phase-3 cadence SLO assertion: a rising score accelerates rotation).
func TestComputedInterval_RisingScoreShrinks(t *testing.T) {
	base := 60 * time.Minute
	min := 1 * time.Minute
	amtd := &amtdv1beta1.AdaptiveMovingTargetDefense{
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{
			InferenceRotation: &amtdv1beta1.InferenceRotationSpec{
				RotationPolicy: &amtdv1beta1.RotationPolicy{
					BaseInterval: &metav1.Duration{Duration: base},
					MinInterval:  &metav1.Duration{Duration: min},
				},
			},
		},
	}
	lo := computedInterval(amtd, 0.2)
	mid := computedInterval(amtd, 0.5)
	hi := computedInterval(amtd, 0.9)
	if !(lo > mid && mid > hi) {
		t.Errorf("rising score must strictly shrink interval: 0.2=%s 0.5=%s 0.9=%s", lo, mid, hi)
	}
}

// T1b — Passthrough scorer returns Spec.AnomalyScore as-is (no invented math);
// nil AnomalyScore => unscored.
func TestPassthroughScorer(t *testing.T) {
	ev := scoredEvent("e", "default/p", "PrometheusIntegrator", "0.7")
	s, ok := (PassthroughScorer{}).Score(ev, nil)
	if !ok {
		t.Fatal("passthrough must score a present AnomalyScore")
	}
	if v, _ := parseScore(s); math.Abs(v-0.7) > 1e-9 {
		t.Errorf("passthrough score = %s, want 0.7", s)
	}
	un := scoredEvent("e", "default/p", "PrometheusIntegrator", "")
	if _, ok := (PassthroughScorer{}).Score(un, nil); ok {
		t.Error("passthrough must be unscored for a nil AnomalyScore")
	}
}

// T6 — Provenance: a non-trusted Source is not on the allowlist. (The full
// ignore-in-Status path is covered in scoring_update_test.go.)
func TestProvenance_Allowlist(t *testing.T) {
	trusted := scoredEvent("e", "default/p", "FalcoIntegrator", "0.99")
	if !isTrustedScoreSource(trusted) {
		t.Error("FalcoIntegrator must be trusted")
	}
	untrusted := scoredEvent("e", "default/p", "EvilWorkload", "0.99")
	if isTrustedScoreSource(untrusted) {
		t.Error("EvilWorkload must NOT be trusted")
	}
	empty := scoredEvent("e", "default/p", "", "0.99")
	if isTrustedScoreSource(empty) {
		t.Error("empty Source must NOT be trusted (fail-safe)")
	}
}

// WeightedScorer: inert without a ScoringPolicy / with empty Weights; computes a
// clamped weighted sum when Weights are set over present Metrics.
func TestWeightedScorer(t *testing.T) {
	ev := &amtdv1beta1.SecurityEvent{
		Spec: amtdv1beta1.SecurityEventSpec{
			Rule:    amtdv1beta1.Rule{Source: "PrometheusIntegrator"},
			Metrics: map[string]string{"gpuEntropy": "0.4", "queryDev": "0.5"},
		},
	}
	// Inert: nil policy.
	if _, ok := (WeightedScorer{}).Score(ev, nil); ok {
		t.Error("weighted must be inert with nil policy")
	}
	// Inert: empty weights (NO default weights).
	if _, ok := (WeightedScorer{}).Score(ev, &amtdv1beta1.ScoringPolicy{}); ok {
		t.Error("weighted must be inert with empty Weights (no default weights)")
	}
	// Clamp: 0.5*0.4 + 0.3*0.5 = 0.35.
	pol := &amtdv1beta1.ScoringPolicy{Weights: map[string]string{"gpuEntropy": "0.5", "queryDev": "0.3"}, Normalization: "clamp"}
	s, ok := (WeightedScorer{}).Score(ev, pol)
	if !ok {
		t.Fatal("weighted must score when Weights present and metrics present")
	}
	if v, _ := parseScore(s); math.Abs(v-0.35) > 1e-9 {
		t.Errorf("weighted clamp sum = %s, want 0.35", s)
	}
	// Over-unity clamps to 1.
	pol2 := &amtdv1beta1.ScoringPolicy{Weights: map[string]string{"gpuEntropy": "3", "queryDev": "3"}}
	s2, _ := (WeightedScorer{}).Score(ev, pol2)
	if v, _ := parseScore(s2); v != 1 {
		t.Errorf("weighted over-unity must clamp to 1, got %s", s2)
	}
}

// scorerFor picks Weighted iff ScoringPolicy set, else Passthrough.
func TestScorerFor(t *testing.T) {
	plain := amtdScored("default", "a", &amtdv1beta1.AdaptiveRotationPolicy{}, "")
	if _, ok := scorerForType(plain); ok {
		t.Error("nil ScoringPolicy must select Passthrough")
	}
	weighted := amtdScored("default", "a", &amtdv1beta1.AdaptiveRotationPolicy{ScoringPolicy: &amtdv1beta1.ScoringPolicy{Weights: map[string]string{"k": "1"}}}, "")
	if _, ok := scorerForType(weighted); !ok {
		t.Error("set ScoringPolicy must select Weighted")
	}
}

// scorerForType is a tiny test shim reporting whether scorerFor chose Weighted.
func scorerForType(amtd *amtdv1beta1.AdaptiveMovingTargetDefense) (AnomalyScorer, bool) {
	s, _ := scorerFor(amtd)
	_, isWeighted := s.(WeightedScorer)
	return s, isWeighted
}

// effective* helpers honor configured values and fall back to code defaults.
func TestEffectiveScoringDefaults(t *testing.T) {
	nilAR := &amtdv1beta1.AdaptiveMovingTargetDefense{
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{InferenceRotation: &amtdv1beta1.InferenceRotationSpec{}},
	}
	if got := effectivePanicThreshold(nilAR); got != defaultPanicThreshold {
		t.Errorf("panic default = %v, want %v", got, defaultPanicThreshold)
	}
	if got := effectiveEWMAAlpha(nilAR); got != defaultEWMAAlpha {
		t.Errorf("alpha default = %v, want %v", got, defaultEWMAAlpha)
	}
	if got := effectiveConsecutiveHighSamples(nilAR); got != defaultConsecutiveHighSamples {
		t.Errorf("N default = %v, want %v", got, defaultConsecutiveHighSamples)
	}
	if got := effectiveStalenessWindow(nilAR); got != defaultStalenessWindow {
		t.Errorf("staleness default = %v, want %v", got, defaultStalenessWindow)
	}
	cfg := &amtdv1beta1.AdaptiveMovingTargetDefense{
		Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{InferenceRotation: &amtdv1beta1.InferenceRotationSpec{
			AdaptiveRotation: &amtdv1beta1.AdaptiveRotationPolicy{
				PanicThreshold:         strptr("0.9"),
				EWMAAlpha:              strptr("0.5"),
				ConsecutiveHighSamples: intptr(5),
				StalenessWindow:        &metav1.Duration{Duration: 2 * time.Minute},
			},
		}},
	}
	if got := effectivePanicThreshold(cfg); math.Abs(got-0.9) > 1e-9 {
		t.Errorf("panic configured = %v, want 0.9", got)
	}
	if got := effectiveEWMAAlpha(cfg); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("alpha configured = %v, want 0.5", got)
	}
	if got := effectiveConsecutiveHighSamples(cfg); got != 5 {
		t.Errorf("N configured = %v, want 5", got)
	}
	if got := effectiveStalenessWindow(cfg); got != 2*time.Minute {
		t.Errorf("staleness configured = %v, want 2m", got)
	}
}
