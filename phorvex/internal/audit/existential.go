package audit

import (
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// RecordOutcomeInventory is additive to per-workload decisions. It retains raw
// assertions, not trust/activation verdicts, including when the policy selects no pods.
func (l *Logger) RecordOutcomeInventory(tenant string, now time.Time, inventory *model.ExistentialInventory) error {
	rec := struct {
		Kind      string                      `json:"kind"`
		Tenant    string                      `json:"tenant"`
		Time      time.Time                   `json:"time"`
		Inventory *model.ExistentialInventory `json:"inventory"`
	}{"phorvex.existential-inventory.v1", tenant, now, inventory}
	err := l.writeRecord(tenant, rec)
	if !inventory.ScopeComplete {
		l.log.Info("existential inventory scope unresolved", "tenant", tenant, "policyUID", inventory.PolicyUID, "recordCount", len(inventory.Records))
	}
	return err
}
