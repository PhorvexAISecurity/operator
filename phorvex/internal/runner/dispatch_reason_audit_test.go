package runner

import (
	"testing"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func TestClosedRunnerDispatchReasonsReachAuditRecord(t *testing.T) {
	// These literals are stamped by manager dispatch gates. Exercise the actual
	// producer and audit conversion so a new gate cannot silently lose its reason.
	for _, reason := range []string{
		"standing-policy-guard-unavailable",
		"context-cancelled",
		"shared-capacity-refused",
		"shared-capacity-operation-already-recorded",
		"shared-capacity-claim-unconfirmed",
		"quarantine-capacity-refused",
	} {
		t.Run(reason, func(t *testing.T) {
			d := model.Decision{Selected: true, Feasible: true, Action: model.ActionQuarantine}
			stampDispatchEvidence(&d, model.DispatchNotAttempted, reason)
			rec := audit.ToRecord(d)
			if rec.DispatchOutcome != model.DispatchNotAttempted || rec.DispatchReason != reason {
				t.Fatalf("audit dispatch = (%q, %q), want (%q, %q)", rec.DispatchOutcome, rec.DispatchReason, model.DispatchNotAttempted, reason)
			}
		})
	}
	for _, suffix := range []string{
		"shared-capacity-release-pending",
		"shared-capacity-unknown-retention-unconfirmed",
	} {
		t.Run(suffix, func(t *testing.T) {
			d := model.Decision{Selected: true, Feasible: true, Action: model.ActionQuarantine}
			stampDispatchEvidence(&d, model.DispatchError, "outcome-unknown")
			appendDispatchReason(&d, suffix)
			want := "outcome-unknown; " + suffix
			rec := audit.ToRecord(d)
			if rec.DispatchOutcome != model.DispatchError || rec.DispatchReason != want {
				t.Fatalf("audit dispatch = (%q, %q), want (%q, %q)", rec.DispatchOutcome, rec.DispatchReason, model.DispatchError, want)
			}
		})
	}
}

func TestUnknownRunnerDispatchReasonsStayOutOfAuditRecord(t *testing.T) {
	for _, reason := range []string{
		"",
		"future-unreviewed-reason",
		"context-cancelled; future-unreviewed-suffix",
		"context-cancelled; ",
		"outcome-unknown; shared-capacity-release-pending; shared-capacity-release-pending",
	} {
		t.Run(reason, func(t *testing.T) {
			d := model.Decision{Selected: true, Feasible: true, Action: model.ActionQuarantine}
			stampDispatchEvidence(&d, model.DispatchNotAttempted, reason)
			rec := audit.ToRecord(d)
			if rec.DispatchOutcome != model.DispatchNotAttempted || rec.DispatchReason != "" {
				t.Fatalf("unreviewed reason retained in audit: (%q, %q)", rec.DispatchOutcome, rec.DispatchReason)
			}
		})
	}
}
