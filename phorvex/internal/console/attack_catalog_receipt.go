package console

import (
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

const attackCatalogReceiptFutureSkew = 2 * time.Second

// validAttackCatalogReceiptTime accepts only a real audit observation within
// the current run lifetime. The small future bound matches the audit-reader
// clock-skew allowance; it is not a substitute timestamp.
func validAttackCatalogReceiptTime(receiptAt, signalCreatedAt time.Time) bool {
	return !receiptAt.IsZero() && !signalCreatedAt.IsZero() &&
		!receiptAt.Before(signalCreatedAt) &&
		!receiptAt.After(time.Now().UTC().Add(attackCatalogReceiptFutureSkew))
}

// acceptedAttackCatalogAuditReceipt is the common audit/trace invariant only.
// Callers retain their family-specific event, target, object and oracle rules.
func acceptedAttackCatalogAuditReceipt(rec audit.Record, signalCreatedAt time.Time, expectedAction, expectedHandler string) bool {
	trace := rec.DecisionTrace
	return trace != nil && validAttackCatalogReceiptTime(rec.Time, signalCreatedAt) &&
		!rec.DryRun && !trace.DryRun && trace.DryRun == rec.DryRun &&
		rec.Selected && rec.Feasible && rec.Actuated && rec.Action == expectedAction &&
		trace.SelectedAction == rec.Action && rec.DispatchOutcome == model.DispatchEmitted &&
		trace.DispatchOutcome == rec.DispatchOutcome && rec.Handler == expectedHandler
}
