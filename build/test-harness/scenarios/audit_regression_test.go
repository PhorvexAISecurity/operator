package scenarios

import (
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

// audit_regression_test.go (P-AUDIT) — pins the measurement-bug fixes so the assumption-bug class
// cannot silently recur.

// TestNeutralizedDerivedFromOutcomeNotArm: `neutralized` (NEUTRALIZES mtdEffect) MUST be derived from
// the measured outcome — persistence disrupted AND the in-request leg failed — and be arm-neutral.
// The prior `armIsFullPhoenix(env) && X` form over-credited the reactive arm and under-credited
// emergent-rate PX. The arm-gated field on the oracle must be IGNORED by result().
func TestNeutralizedDerivedFromOutcomeNotArm(t *testing.T) {
	cases := []struct {
		persistenceDisrupted, inRequestAchieved, wantNeutralized bool
	}{
		{true, false, true},   // both legs defeated => NEUTRALIZES
		{true, true, false},   // persistence disrupted but in-request fired => BOUNDS-ONLY, NOT neutralized
		{false, false, false}, // nothing disrupted => not neutralized
		{false, true, false},
	}
	for _, c := range cases {
		o := aiOracle{
			persistenceDisrupted: c.persistenceDisrupted,
			inRequestAchieved:    c.inRequestAchieved,
			neutralized:          true, // arm-gated junk that result() MUST ignore
		}
		got := o.result().Evidence[core.EvNeutralized] == "true"
		if got != c.wantNeutralized {
			t.Errorf("neutralized(pd=%v,inReq=%v)=%v want %v (must be pd && !inReq, arm-neutral)",
				c.persistenceDisrupted, c.inRequestAchieved, got, c.wantNeutralized)
		}
	}
}

// TestArmRotatesCreditsEmergentRate: armRotates must credit ANY non-baseline arm (incl. emergent-rate
// PX whose MeanRotationIntervalSeconds=0) and exclude only the no-MTD baseline. Pins the fixed-interval
// assumption out of existence.
func TestArmRotatesCreditsEmergentRate(t *testing.T) {
	mk := func(name string) *core.Env { return &core.Env{DefenderName: name} }
	if armRotates(mk("d-nomtd")) {
		t.Error("d-nomtd (no MTD) must NOT count as a rotating arm")
	}
	for _, name := range []string{"d-phorvex", "d-reactive-only", "d-fullphoenix", "d-r6blindtimer", "d-randomequal"} {
		if !armRotates(mk(name)) {
			t.Errorf("%s must count as a rotating arm (emergent-rate arms included)", name)
		}
	}
}

// TestAttackIDReAcceptsAtlas: the technique-id validator must accept ATT&CK (Txxxx[.yyy]) AND ATLAS
// (AML.Txxxx[.yyy]) — AI scenarios legitimately carry ATLAS techniques — and still reject junk.
func TestAttackIDReAcceptsAtlas(t *testing.T) {
	for _, id := range []string{"T1059", "T1059.013", "T1496.001", "AML.T0040", "AML.T0024.002", "AML.T0051.000"} {
		if !attackIDRe.MatchString(id) {
			t.Errorf("attackIDRe must accept well-formed id %q", id)
		}
	}
	for _, id := range []string{"T1induce-not-real-removed", "AML.T", "T123", "AMLT0040", "foo", "T10590"} {
		if attackIDRe.MatchString(id) {
			t.Errorf("attackIDRe must reject malformed id %q", id)
		}
	}
}
