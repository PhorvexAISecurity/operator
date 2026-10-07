package console

import (
	"encoding/json"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCostPreferencesMatchedAuditProjectionAndReplacement(t *testing.T) {
	fired := time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC)
	p := model.Policy{Lambda: 1, CostPreferencesConfigured: true, NormPreference: 0, FlowPreference: 2}
	e, err := p.Economics(1)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	result := &attackRecord{FiredAt: fired.Format(time.RFC3339Nano), Namespace: "tenant", Pod: "api", Action: "quarantine"}
	for _, independent := range []bool{true, false} {
		if !independent {
			p.CostPreferencesConfigured = false
			e, err = p.Economics(1)
			if err != nil {
				t.Fatal(err)
			}
		}
		rec := audit.Record{Kind: "phorvex.decision", Time: fired.Add(time.Second), Namespace: "tenant", Pod: "api", Action: "quarantine", Selected: true, Actuated: true, Lambda: 1, Economics: &e}
		raw, _ := json.Marshal(rec)
		if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		s := NewServer(Config{AuditPath: path, Now: func() time.Time { return fired.Add(2 * time.Second) }})
		s.fillReasoning("", result)
		if !result.EconomicsAvailable {
			t.Fatal("matched economics absent")
		}
		if independent {
			if result.NormPreference == nil || !result.NormPreference.Present || result.NormPreference.Value != 0 || result.FlowPreference == nil || result.FlowPreference.Value != 2 {
				t.Fatal("independent zero/value lost")
			}
			raw, _ := json.Marshal(result)
			var wire map[string]any
			json.Unmarshal(raw, &wire)
			if _, present := wire["effectiveCostCoefficient"]; present {
				t.Fatal("P2 projection fabricated scalar")
			}
		} else if result.NormPreference != nil || result.FlowPreference != nil {
			t.Fatal("reused record retained stale preferences")
		}
	}
}
