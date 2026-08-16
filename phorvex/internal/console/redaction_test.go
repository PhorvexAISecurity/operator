/*
 * Phorvex Console (P-DASHBOARD) — THE ELIGIBILITY GATE.
 *
 * This test fails `go test` (= fails CI) if the platform-owner payload contains ANY Phorvex
 * IP-internal field. It populates a fully-loaded audit.Record (every IP field set to a
 * recognizable value), projects it through ToOwnerEvent, marshals the result, and asserts
 * the JSON contains NONE of the redacted field names AND none of the sentinel IP VALUES.
 * Because ToOwnerEvent is a WHITELIST (explicit field-copy), a newly-added IP field can
 * never leak by default — and this test catches any regression that tries.
 */

package console

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

// fullyLoadedRecord sets EVERY IP-sensitive field to a unique sentinel so a leak is visible.
func fullyLoadedRecord() audit.Record {
	return audit.Record{
		Kind: "phorvex.decision", Tenant: "acme", Namespace: "prod", Pod: "api-7", Node: "node-1",
		Action: "quarantine", Selected: true, Feasible: true, Actuated: true, MutationKind: "reversible",
		Handler: "quarantine", ObjectsTouched: []string{"NetworkPolicy/prod/phorvex-quarantine-api-7", "Pod/prod/api-7"},
		// --- IP-SENSITIVE (must NEVER reach the owner payload) ---
		CoverageValue: 0.731, ThreatRisk: 0.888, Cost: 0.422, Net: 0.309, Residual: 0.555, ThreatPosture: 0.666, Exposure: 0.777,
		AssetValue: 0.999, BlastRadius: 0.444, SLOHeadroom: 0.222,
		PerDollar: 2.381, CoveredWeight: 1.234, CoveredFacts: 7, Lambda: 0.400, ProactiveRate: 0.123,
		Stage: "exploit", NextStage: "lateral", StageHazard: 0.654, PHold: 0.842,
		// the raw Reason inlines the EMR/per-$/lambda/hazard math verbatim — the worst leak vector:
		Reason:             "cov=1.23/$0.42=2.93 per-$ > lambda=0.40 scarcity=image-rarity*EPSS*co-residency hazard=0.65 pHold=0.84",
		R6Counterfactual:   "blind would Delete",
		CounterfactualNote: "EMR scarcity scalar 2.00; submodular greedy picked api-7",
		Attribution:        []model.AttributionTerm{{Source: "cover:pod-identity", Contribution: 0.51}},
	}
}

func TestOwnerViewLeaksZeroIP(t *testing.T) {
	rec := fullyLoadedRecord()
	body, err := json.Marshal(ToOwnerEvent(rec))
	if err != nil {
		t.Fatalf("marshal owner event: %v", err)
	}
	js := string(body)

	// (1) no redacted FIELD NAME appears.
	if leaked, ok := mustNoIP(js); !ok {
		t.Fatalf("IP LEAK: owner payload contains redacted token %q\npayload=%s", leaked, js)
	}

	// (2) no sentinel IP VALUE appears (catches a value leaking under a renamed key).
	sentinels := []string{
		"0.731", "0.422", "0.309", "0.555", "0.666", "0.777", "0.888", "0.999", "0.444",
		"2.381", "1.234", "0.400", "0.123", "0.654", "0.842", "0.91", "2763",
		"image-rarity", "EPSS", "co-residency", "scarcity", "submodular", "cov=", "per-$", "lambda",
		"cover:pod-identity", "0.51",
	}
	for _, s := range sentinels {
		if strings.Contains(js, s) {
			t.Fatalf("IP LEAK: owner payload contains the IP VALUE %q (a renamed-field leak)\npayload=%s", s, js)
		}
	}

	// (3) the owner STILL gets the outcome it needs (the view is not empty/useless).
	oe := ToOwnerEvent(rec)
	if oe.Pod != "api-7" || oe.Action != "quarantine" || oe.Why == "" || oe.BlindOutcome == "" {
		t.Fatalf("owner event missing owner-safe outcome fields: %+v", oe)
	}
	if oe.AttackStage == "exploit" {
		t.Fatalf("owner event exposed the RAW stage enum %q (must be a coarse label)", oe.AttackStage)
	}
}

// TestOwnerEndpointNeverMarshalsRecord guards the construction discipline: the only owner
// projection is ToOwnerEvent; a future handler must not json.Marshal a Record/Decision.
func TestOwnerWhyNeverEchoesRawReason(t *testing.T) {
	rec := fullyLoadedRecord()
	oe := ToOwnerEvent(rec)
	if strings.Contains(oe.Why, "cov=") || strings.Contains(oe.Why, "lambda") || strings.Contains(oe.Why, "scarcity") {
		t.Fatalf("owner Why echoed the raw Reason math: %q", oe.Why)
	}
	if strings.Contains(oe.BlindOutcome, "scarcity") || strings.Contains(oe.BlindOutcome, "greedy") {
		t.Fatalf("owner BlindOutcome echoed IP internals: %q", oe.BlindOutcome)
	}
}
