package metricvalidity

// validity_test.go — PERMANENT regressions for the SHARED contract (V3-M161,
// lead review R2 finding 1 and the negative-control/cost note).
//
// This package is the single implementation every producer and reader uses, so
// the table below IS the contract. Each case states a decoded claim and the
// verdict every consumer must reach; a positive control keeps a genuine row
// certifiable.

import "math"
import "testing"

// sound is a genuine, fully corroborated version-1 claim.
func sound() *Validity {
	return &Validity{
		Version: Version, Kind: TrialOrdinary, Status: StatusValid, Phase: PhaseComplete,
		AttackExecuted: true, OracleObserved: true, ObserverPresent: true, CostObserved: true,
		Scored: true,
		Baseline: BaselineRef{Required: true, Defender: "d-nomtd", Kind: TrialOrdinary,
			Observed: true, Valid: true, OracleAchieved: true, Usable: true},
		Cleanup: CleanupRecord{Complete: true, Verified: true},
	}
}

func soundObs() Observations {
	return Observations{Trial: 0, Disruption: 1, DefensiveActions: 2, FalseDefensiveActions: -1,
		TimeToActionSeconds: 1, AttackerDwellSeconds: 3}
}

// POSITIVE CONTROL: a genuine claim is certified in every respect.
func TestEvaluateCertifiesAGenuineClaim(t *testing.T) {
	v := Evaluate(sound(), soundObs())
	if !v.Supported || v.Unverified || !v.Scorable || !v.CostUsable || !v.OracleUsable {
		t.Fatalf("a genuine claim was refused: %+v", v)
	}
	if len(v.Rejections) != 0 {
		t.Fatalf("unexpected rejections: %v", v.Rejections)
	}
	if v.Kind() != TrialOrdinary || v.Status() != StatusValid {
		t.Fatalf("kind/status wrong: %s/%s", v.Kind(), v.Status())
	}
}

// A pre-contract row is LEGACY: readable, never certified, never "unverified".
func TestEvaluateClassifiesLegacy(t *testing.T) {
	v := Evaluate(nil, soundObs())
	if !v.Legacy || v.Unverified {
		t.Fatalf("legacy classification wrong: %+v", v)
	}
	if v.Scorable || v.CostUsable || v.OracleUsable || v.NegControlUsable {
		t.Fatalf("a legacy row was treated as a measurement: %+v", v)
	}
	if v.Status() != StatusLegacy {
		t.Fatalf("legacy status = %q", v.Status())
	}
}

// Every unsupported marker and every self-contradiction is refused, stays
// visible as UNVERIFIED, and carries a reason.
func TestEvaluateRefusesUnsupportedOrContradictoryClaims(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Validity, *Observations)
	}{
		{"future-version", func(v *Validity, _ *Observations) { v.Version = Version + 1 }},
		{"past-version", func(v *Validity, _ *Observations) { v.Version = 0 }},
		{"unknown-kind", func(v *Validity, _ *Observations) { v.Kind = "sideways" }},
		{"unknown-status", func(v *Validity, _ *Observations) { v.Status = "unrecognized" }},
		{"status-not-valid", func(v *Validity, _ *Observations) { v.Status = StatusInvalid }},
		{"oracle-not-observed", func(v *Validity, _ *Observations) { v.OracleObserved = false }},
		{"cleanup-incomplete", func(v *Validity, _ *Observations) { v.Cleanup.Complete = false }},
		{"cleanup-unresolved", func(v *Validity, _ *Observations) {
			v.Cleanup.Complete, v.Cleanup.Unresolved = false, true
		}},
		{"cleanup-retained-failure", func(v *Validity, _ *Observations) {
			v.Cleanup.Attempted = append(v.Cleanup.Attempted, CleanupStep{Step: "env.Close", Error: "forbidden"})
		}},
		{"cleanup-blocked-step", func(v *Validity, _ *Observations) {
			v.Cleanup.Attempted = append(v.Cleanup.Attempted, CleanupStep{Step: "env.Close", Blocked: true})
		}},
		{"baseline-not-usable", func(v *Validity, _ *Observations) { v.Baseline.Usable = false }},
		{"baseline-usable-but-unobserved", func(v *Validity, _ *Observations) { v.Baseline.Observed = false }},
		{"baseline-usable-but-invalid", func(v *Validity, _ *Observations) { v.Baseline.Valid = false }},
		{"baseline-usable-but-attack-failed", func(v *Validity, _ *Observations) { v.Baseline.OracleAchieved = false }},
		{"baseline-without-identity", func(v *Validity, _ *Observations) { v.Baseline.Defender = "" }},
		{"scored-negative-control", func(v *Validity, _ *Observations) { v.Kind = TrialNegativeControl }},
		{"disruption-out-of-range", func(_ *Validity, o *Observations) { o.Disruption = 2 }},
		{"disruption-not-finite", func(_ *Validity, o *Observations) { o.Disruption = math.Inf(1) }},
		{"cost-observed-but-sentinel", func(_ *Validity, o *Observations) { o.DefensiveActions = -1 }},
		{"cost-observed-but-nan-timing", func(_ *Validity, o *Observations) { o.TimeToActionSeconds = math.NaN() }},
		{"dwell-not-finite", func(_ *Validity, o *Observations) { o.AttackerDwellSeconds = math.NaN() }},
		// Cross-field invariants: the anchor must be the control observed at the
		// SAME index and kind, and the lifecycle must hang together.
		{"baseline-kind-mismatch", func(v *Validity, _ *Observations) { v.Baseline.Kind = TrialAdaptive }},
		{"baseline-trial-mismatch", func(v *Validity, o *Observations) { v.Baseline.Trial = o.Trial + 10 }},
		{"oracle-without-attack", func(v *Validity, _ *Observations) { v.AttackExecuted = false }},
		{"cost-without-observer", func(v *Validity, _ *Observations) { v.ObserverPresent = false }},
		{"valid-at-non-terminal-phase", func(v *Validity, _ *Observations) { v.Phase = PhaseScenarioSetup }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claim, obs := sound(), soundObs()
			tc.mutate(claim, &obs)
			if !claim.Scored {
				t.Fatalf("fixture relevance: the row must still CLAIM scored")
			}
			v := Evaluate(claim, obs)
			if v.Scorable {
				t.Errorf("a contradictory/unsupported claim was certified: %+v", v)
			}
			if !v.Unverified {
				t.Errorf("refused claim not marked UNVERIFIED, so it would vanish from the counts: %+v", v)
			}
			if len(v.Rejections) == 0 {
				t.Errorf("refusal recorded no reason")
			}
			if v.UnscoredReason() == "" {
				t.Errorf("refused claim gives no unscored reason")
			}
		})
	}
}

// Cleanup integrity is checked for EVERY row, not only scored ones: a negative
// control is never "scored", and that must not let a dirty trial certify a
// clean arm.
func TestEvaluateChecksCleanupOnUnscoredRowsToo(t *testing.T) {
	negControl := func() *Validity {
		v := sound()
		v.Kind, v.Scored = TrialNegativeControl, false
		v.Baseline = BaselineRef{}
		return v
	}
	obs := Observations{DefensiveActions: 0, FalseDefensiveActions: 0, TimeToActionSeconds: 0, AttackerDwellSeconds: 0}

	// POSITIVE CONTROL: a clean, observed negative control establishes its zero.
	clean := Evaluate(negControl(), obs)
	if !clean.NegControlUsable || !clean.CostUsable {
		t.Fatalf("a clean negative control was refused: %+v", clean)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*Validity)
	}{
		{"retained-cleanup-error", func(v *Validity) {
			v.Cleanup.Attempted = []CleanupStep{{Step: "env.Close", Error: "forbidden"}}
		}},
		{"cleanup-incomplete", func(v *Validity) { v.Cleanup.Complete = false }},
		{"cleanup-unresolved", func(v *Validity) { v.Cleanup.Complete, v.Cleanup.Unresolved = false, true }},
		{"cleanup-blocked", func(v *Validity) {
			v.Cleanup.Attempted = []CleanupStep{{Step: "env.Close", Blocked: true}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := negControl()
			tc.mutate(v)
			got := Evaluate(v, obs)
			if got.NegControlUsable {
				t.Errorf("a dirty negative control certified a clean arm: %+v", got)
			}
			if got.CostUsable || got.OracleUsable {
				t.Errorf("a dirty trial's observations were still usable: %+v", got)
			}
		})
	}
}

// A negative control whose false-move count is the UNOBSERVED sentinel does not
// establish anything, even when everything else is sound.
func TestEvaluateNegativeControlSentinelIsNotAMeasuredZero(t *testing.T) {
	v := sound()
	v.Kind, v.Scored = TrialNegativeControl, false
	v.Baseline = BaselineRef{}
	got := Evaluate(v, Observations{DefensiveActions: 0, FalseDefensiveActions: -1})
	if got.NegControlUsable {
		t.Fatalf("an unobserved false-move count established a clean arm: %+v", got)
	}
	if len(got.Rejections) == 0 {
		t.Fatalf("the sentinel contradiction was not recorded")
	}
}

// A row that claims nothing cannot contradict itself: an honestly unscored,
// valid row keeps its independent observations.
func TestEvaluateKeepsObservationsOnAnHonestlyUnscoredRow(t *testing.T) {
	v := sound()
	v.Scored = false
	v.UnscoredReason = "no VALID control was observed at trial index 0"
	// The producer records WHICH control it needed even when none was usable, so
	// the identity fields stay populated; only the observation is missing.
	v.Baseline = BaselineRef{Required: true, Defender: "d-nomtd", Kind: TrialOrdinary,
		Trial: 0, Reason: v.UnscoredReason}
	got := Evaluate(v, soundObs())
	if got.Scorable {
		t.Fatalf("an unscored row was scored")
	}
	if got.Unverified {
		t.Fatalf("an honestly unscored row was marked unverified: %v", got.Rejections)
	}
	if !got.CostUsable || !got.OracleUsable {
		t.Fatalf("independent observations were discarded: %+v", got)
	}
	if got.UnscoredReason() != v.UnscoredReason {
		t.Fatalf("unscored reason = %q, want the producer's own", got.UnscoredReason())
	}
}

// Cleanup soundness is the single predicate the whole contract leans on.
func TestCleanupRecordSound(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  CleanupRecord
		want bool
	}{
		{"clean", CleanupRecord{Complete: true, Attempted: []CleanupStep{{Step: "a"}}}, true},
		{"empty-complete", CleanupRecord{Complete: true}, true},
		{"not-complete", CleanupRecord{}, false},
		{"failed-step", CleanupRecord{Complete: true, Attempted: []CleanupStep{{Step: "a", Error: "x"}}}, false},
		{"unresolved-step", CleanupRecord{Complete: true, Attempted: []CleanupStep{{Step: "a", Unresolved: true}}}, false},
		{"blocked-step", CleanupRecord{Complete: true, Attempted: []CleanupStep{{Step: "a", Blocked: true}}}, false},
		{"unresolved-flag", CleanupRecord{Complete: true, Unresolved: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.Sound(); got != tc.want {
				t.Fatalf("Sound() = %v, want %v", got, tc.want)
			}
		})
	}
}
