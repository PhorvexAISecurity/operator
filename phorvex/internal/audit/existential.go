package audit

import (
	"encoding/json"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// RecordOutcomeInventory is additive to per-workload decisions. It retains raw
// assertions, not trust/activation verdicts, including when the policy selects no pods.
func (l *Logger) RecordOutcomeInventory(tenant string, now time.Time, inventory *model.ExistentialInventory) {
	rec := struct {
		Kind      string                      `json:"kind"`
		Tenant    string                      `json:"tenant"`
		Time      time.Time                   `json:"time"`
		Inventory *model.ExistentialInventory `json:"inventory"`
	}{"phorvex.existential-inventory.v1", tenant, now, inventory}
	l.mu.Lock()
	out := l.jsonOut
	if l.sinkFor != nil {
		if w := l.sinkFor(tenant); w != nil {
			out = w
		}
	}
	if out != nil {
		if b, err := json.Marshal(rec); err == nil {
			_, _ = out.Write(append(b, '\n'))
		}
	}
	l.mu.Unlock()
	if !inventory.ScopeComplete {
		l.log.Info("existential inventory scope unresolved", "tenant", tenant, "policyUID", inventory.PolicyUID, "recordCount", len(inventory.Records))
	}
}
