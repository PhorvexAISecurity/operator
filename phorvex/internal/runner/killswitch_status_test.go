package runner

import (
	"encoding/json"
	"strings"
	"testing"

	v1 "github.com/phorvex/phorvex/api/v1alpha1"
)

// killswitch_status_test.go — PHVX-17 / PHORVEXSEC-109.
//
// The ticket's premise — that status.killSwitchEngaged is fed from a different source than the
// engine — is FALSE: manager.go computes killEngaged once per tick and the same variable gates
// actuation, sets the metric and writes the status. Verified before changing anything.
//
// The real defect is narrower and was confirmed on the live fleet: with `omitempty`, a `false`
// disappeared from the CR entirely, so "the defence is running" and "this status was never written"
// looked identical. All four live policies showed the field ABSENT while the sentinel said
// engaged=false.

// TestKillSwitchFalseIsSerialised is the regression. A safety-control readout must state the safe
// value explicitly; omitting it is not the same as reporting it.
func TestKillSwitchFalseIsSerialised(t *testing.T) {
	b, err := json.Marshal(v1.PhorvexPolicyStatus{KillSwitchEngaged: false})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"killSwitchEngaged":false`) {
		t.Fatalf("a disengaged kill-switch did not serialise. With omitempty the field vanishes and "+
			"an operator cannot distinguish a running defence from a status that was never "+
			"reconciled. Got: %s", b)
	}
}

func TestKillSwitchTrueStillSerialises(t *testing.T) {
	b, _ := json.Marshal(v1.PhorvexPolicyStatus{KillSwitchEngaged: true})
	if !strings.Contains(string(b), `"killSwitchEngaged":true`) {
		t.Fatalf("engaged kill-switch missing from the status: %s", b)
	}
}
