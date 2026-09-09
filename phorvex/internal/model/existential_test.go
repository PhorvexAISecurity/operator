package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestM99AuditMetadataRedactsWithoutMutatingInputs(t *testing.T) {
	r := ProtectedOutcome{ClassBasis: "Authorization: Bearer secret-fixture-value"}
	d := ExistentialDecision{Evidence: []OutcomeEvidence{{Outcome: r}}}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret-fixture-value") {
		t.Fatal("credential leaked in outcome metadata")
	}
	if d.Evidence[0].Outcome.ClassBasis != r.ClassBasis {
		t.Fatal("redaction mutated selection input")
	}
}
