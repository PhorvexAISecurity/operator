package console

import (
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	"strings"
	"testing"
)

func TestM47RotationDoesNotClaimReplacementOrProtection(t *testing.T) {
	for _, emitted := range []bool{false, true} {
		got := ToOwnerEvent(audit.Record{Action: "rotate", Selected: true, Actuated: emitted})
		if got.AttackPrevented || strings.Contains(got.Why, "clean") || strings.Contains(got.Why, "Replaced") {
			t.Fatalf("unsupported outcome: %+v", got)
		}
		if emitted && !strings.Contains(got.Why, "not confirmed") {
			t.Fatalf("missing uncertainty: %+v", got)
		}
	}
}

func TestM47RefusalVisibleWithoutRawReasonLeak(t *testing.T) {
	rec := audit.Record{Action: "rotate", Selected: true, DecisionTrace: &model.DecisionTraceV2{DispatchReason: "Rotation not performed: ownerless"}}
	if got := ToOwnerEvent(rec); !strings.Contains(got.Why, "no verified replacement controller") {
		t.Fatal(got.Why)
	}
	rec.DecisionTrace.DispatchReason = "private-untrusted-detail"
	if strings.Contains(ToOwnerEvent(rec).Why, "private-untrusted-detail") {
		t.Fatal("raw reason leaked")
	}
}
