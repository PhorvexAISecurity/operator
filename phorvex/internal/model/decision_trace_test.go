package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func validDecisionTrace() DecisionTraceV2 {
	return DecisionTraceV2{
		SchemaVersion: DecisionTraceSchemaV2,
		DecisionID:    "decision-1", TickID: "tick-1", Timestamp: "2026-08-30T12:00:00Z",
		BrainImage: "registry/phorvex:sha-abc", GitSHA: "abcdef1234567890", DecisionEngine: "p1-coverage",
		PolicyNamespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", TenantName: "tenant",
		AssetNamespace: "ns", AssetName: "pod", AssetUID: "pod-uid",
		Budget: 1, CandidateDemand: 1, MovesSpent: 1,
		LambdaConfiguredSeed: 0.6, LambdaRuntime: 0.6,
		Facts: []DecisionFactV2{
			{FactKey: "z", FactType: "session", FinalWeight: 1},
			{FactKey: "a", FactType: "podIdentity", FinalWeight: 2},
		},
		Candidates: []DecisionCandidateV2{
			{Action: string(ActionQuarantine), CandidateKey: "z", CoverKeys: []string{"z", "a"}, Feasible: OptionalBool{Present: true, Value: true}},
			{
				Action: string(ActionRotate), CandidateKey: "a", CoverKeys: []string{"b", "a"},
				MarginalCoverage:   OptionalFloat{Present: true, Value: 2},
				Provenance:         OptionalFloat{Present: true, Value: 0.5},
				ExpectedCost:       OptionalFloat{Present: true, Value: 0.5},
				CostHigh:           OptionalFloat{Present: true, Value: 0.6},
				LambdaContribution: OptionalFloat{Present: true, Value: 0.3},
				NetGain:            OptionalFloat{Present: true, Value: 0.7},
				Feasible:           OptionalBool{Present: true, Value: true}, Selected: true,
			},
		},
		SelectedAction: string(ActionRotate), SelectedCandidateKey: "a",
		SelectionRound: OptionalInt{Present: true, Value: 1}, TieBreakReason: "strict-greater",
	}
}

func TestDecisionTraceV2RoundTripAndCanonicalOrdering(t *testing.T) {
	trace := validDecisionTrace()
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DecisionTraceV2
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if decoded.Facts[0].FactKey != "a" || decoded.Facts[1].FactKey != "z" {
		t.Fatalf("facts are not canonical: %+v", decoded.Facts)
	}
	if decoded.Candidates[0].CandidateKey != "a" || decoded.Candidates[1].CandidateKey != "z" {
		t.Fatalf("candidates are not canonical: %+v", decoded.Candidates)
	}
	if got := decoded.Candidates[0].CoverKeys; len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("cover keys are not canonical: %v", got)
	}
}

func TestDecisionTraceV2RequiresSchemaAndBuildIdentity(t *testing.T) {
	trace := validDecisionTrace()
	trace.SchemaVersion = ""
	if err := trace.Validate(); err == nil {
		t.Fatal("trace without schema version validated")
	}
	trace = validDecisionTrace()
	trace.GitSHA = ""
	if err := trace.Validate(); err == nil {
		t.Fatal("trace without Git SHA validated")
	}
	trace = validDecisionTrace()
	trace.BrainImage = ""
	if err := trace.Validate(); err == nil {
		t.Fatal("trace without brain image validated")
	}
}

func TestDecisionTraceV2SelectionIntegrityAndGainReconstruction(t *testing.T) {
	trace := validDecisionTrace()
	trace.Candidates[0].Selected = true
	if err := trace.Validate(); err == nil {
		t.Fatal("two selected candidates validated")
	}
	trace = validDecisionTrace()
	trace.Candidates[1].NetGain.Value = 0.8
	if err := trace.Validate(); err == nil {
		t.Fatal("non-reconstructable gain validated")
	}
}

func TestDecisionTraceV2NoopIntegrity(t *testing.T) {
	trace := validDecisionTrace()
	trace.SelectedAction = string(ActionNoop)
	trace.SelectedCandidateKey = ""
	trace.SelectionRound = OptionalInt{}
	trace.NoopReason = "priced-out"
	trace.Candidates[1].Selected = false
	if err := trace.Validate(); err != nil {
		t.Fatal(err)
	}
	trace.NoopReason = ""
	if err := trace.Validate(); err == nil {
		t.Fatal("noop without a reason validated")
	}
}

func TestDecisionTraceV2RedactsBearerTokensAndCredentialHeaders(t *testing.T) {
	trace := validDecisionTrace()
	trace.NoopReason = "Authorization: Basic dXNlcjpwYXNz"
	trace.Candidates[0].ExistingExclusionReason = "password=hunter2 token=abc123"
	trace.BrainImage = "https://user:registry-password@registry.example/phorvex:tag"
	raw, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, secret := range []string{"dXNlcjpwYXNz", "hunter2", "abc123", "registry-password"} {
		if strings.Contains(text, secret) {
			t.Fatalf("serialized trace leaked %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("serialized trace did not carry an explicit redaction: %s", text)
	}
}
