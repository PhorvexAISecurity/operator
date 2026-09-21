package console

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func TestPost25EconomicsConsoleRejectsRoundedLambdaContradiction(t *testing.T) {
	metadata := model.EconomicsMetadata{
		Version:                  model.EconomicsFixedDisruptionAversionV1,
		DisruptionAversion:       model.OptionalFloat{Present: true, Value: 0.00004},
		LambdaRuntimeLegacy:      model.OptionalFloat{Present: true, Value: 0.123456789},
		EffectiveCostCoefficient: 0.00004, CoefficientSource: model.CostCoefficientSourceBeta,
	}
	if decoded, ok := decodeAuditEconomics(metadata, 0.1235); !ok || decoded.LambdaRuntimeLegacy.Value != 0.123456789 {
		t.Fatalf("valid exact economics unavailable: ok=%t metadata=%+v", ok, decoded)
	}
	if _, ok := decodeAuditEconomics(metadata, 0.1234); ok {
		t.Fatal("console accepted economics metadata contradicting the rounded lambda alias")
	}
}

func TestPost25EconomicsFillReasoningUsesMatchedCanonicalAudit(t *testing.T) {
	fired := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	economics := &model.EconomicsMetadata{
		Version:                  model.EconomicsFixedDisruptionAversionV1,
		DisruptionAversion:       model.OptionalFloat{Present: true, Value: 0.00004},
		LambdaRuntimeLegacy:      model.OptionalFloat{Present: true, Value: 0.123456789},
		EffectiveCostCoefficient: 0.00004,
		CoefficientSource:        model.CostCoefficientSourceBeta,
	}
	record := audit.Record{
		Kind:      "phorvex.decision",
		Time:      fired.Add(time.Second),
		Namespace: "tenant-a",
		Pod:       "api-0",
		Action:    "quarantine",
		Selected:  true,
		Actuated:  true,
		Reason:    "canonical candidate reason",
		Lambda:    0.1235,
		Economics: economics,
	}
	valid, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		if err := os.WriteFile(path, append(valid, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		s := NewServer(Config{AuditPath: path, Now: func() time.Time { return fired.Add(2 * time.Second) }})
		result := &attackRecord{
			FiredAt: fired.Format(time.RFC3339Nano), Namespace: "tenant-a", Pod: "api-0",
			Action: "quarantine", Outcome: "DEFENDED", Why: "observed event reason",
		}
		s.fillReasoning("", result)

		if !result.EconomicsAvailable || result.EconomicsVersion != model.EconomicsFixedDisruptionAversionV1 ||
			!result.DisruptionAversionPresent || result.DisruptionAversion != 0.00004 ||
			result.EffectiveCostCoefficient != 0.00004 || !result.LambdaAvailable || result.Lambda != 0.1235 {
			t.Fatalf("validated economics did not survive projection: %+v", result)
		}
		if result.Action != "quarantine" || result.Outcome != "DEFENDED" || result.Why != "observed event reason" {
			t.Fatalf("audit projection overwrote observed facts: action=%q outcome=%q why=%q", result.Action, result.Outcome, result.Why)
		}
		if result.DecisionEvidence == nil || result.DecisionEvidence.Correlation != "temporal-workload" ||
			result.DecisionEvidence.Action != "quarantine" || result.DecisionEvidence.Reason != "canonical candidate reason" {
			t.Fatalf("candidate provenance was not retained: %+v", result.DecisionEvidence)
		}
	})

	t.Run("mismatched metadata", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		invalid := []byte(strings.Replace(string(valid), `"lambda":0.1235`, `"lambda":0.1234`, 1))
		if string(invalid) == string(valid) {
			t.Fatal("test fixture did not alter the rounded lambda alias")
		}
		if err := os.WriteFile(path, append(invalid, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		s := NewServer(Config{AuditPath: path, Now: func() time.Time { return fired.Add(2 * time.Second) }})
		result := &attackRecord{
			FiredAt: fired.Format(time.RFC3339Nano), Namespace: "tenant-a", Pod: "api-0",
			Action: "quarantine", Outcome: "DEFENDED", Why: "observed event reason",
		}
		s.fillReasoning("", result)

		if result.EconomicsAvailable || result.EconomicsVersion != "" || result.LambdaAvailable || result.DecisionEvidence != nil {
			t.Fatalf("invalid canonical record was exposed: %+v", result)
		}
		if result.Action != "quarantine" || result.Outcome != "DEFENDED" || result.Why != "observed event reason" {
			t.Fatalf("rejected audit record altered observed facts: action=%q outcome=%q why=%q", result.Action, result.Outcome, result.Why)
		}
	})
}
