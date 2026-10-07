package model

import (
	"encoding/json"
	"math"
	"testing"
)

func TestIndependentEconomicsValidationAndWire(t *testing.T) {
	p := Policy{Lambda: 1, CostPreferencesConfigured: true, NormPreference: 0, FlowPreference: 2}
	e, err := p.Economics(9)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateEconomicsMetadata(&e); err != nil {
		t.Fatal(err)
	}
	if got := e.CostPenalty(3, .5, 100); got != 1 {
		t.Fatal(got)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	json.Unmarshal(raw, &wire)
	if _, ok := wire["effectiveCostCoefficient"]; ok {
		t.Fatal("unavailable scalar exported")
	}
	wire["effectiveCostCoefficient"] = 0
	bad, _ := json.Marshal(wire)
	if json.Unmarshal(bad, &EconomicsMetadata{}) == nil {
		t.Fatal("accepted spoofed scalar zero")
	}
	for _, value := range []float64{-1, math.NaN(), math.Inf(1), 10.01} {
		p.NormPreference = value
		if _, err := p.Economics(0); err == nil {
			t.Fatal("invalid preference accepted")
		}
	}
	p.NormPreference = 1
	p.DisruptionAversionConfigured = true
	if _, err := p.Economics(0); err == nil {
		t.Fatal("conflicting objective accepted")
	}
}
