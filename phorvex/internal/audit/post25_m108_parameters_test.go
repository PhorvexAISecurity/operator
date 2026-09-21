package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func post25M108ParameterReference() *model.ParameterSetReference {
	return &model.ParameterSetReference{
		SchemaVersion:       model.DecisionParameterSetV1,
		ManifestID:          "production-source",
		ManifestHash:        "sha256:" + strings.Repeat("1", 64),
		PolicyOverridesID:   "ns/policy/uid/7",
		PolicyOverridesHash: "sha256:" + strings.Repeat("2", 64),
	}
}

func TestPost25M108TraceOffAuditRetainsCompactParameterIdentity(t *testing.T) {
	ref := post25M108ParameterReference()
	record := ToRecord(model.Decision{Engine: "p1-coverage", ParameterSet: ref})
	ref.ManifestID = "mutated-after-conversion"
	if record.ParameterSet == nil || record.ParameterSet.ManifestID != "production-source" {
		t.Fatalf("audit record aliases mutable decision provenance: %+v", record.ParameterSet)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Record
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.DecisionTrace != nil || decoded.ParameterSet == nil || decoded.ParameterSet.ManifestID != "production-source" ||
		decoded.ParameterSet.PolicyOverridesID != "ns/policy/uid/7" {
		t.Fatalf("trace-off parameter identity was lost: %+v", decoded)
	}
}

func TestPost25M108AuditLegacyAbsenceAndMalformedReference(t *testing.T) {
	var legacy Record
	if err := json.Unmarshal([]byte(`{"schemaVersion":"phorvex.audit.v2","kind":"phorvex.decision"}`), &legacy); err != nil {
		t.Fatalf("legacy record without parameter identity must remain readable: %v", err)
	}
	if legacy.ParameterSet != nil {
		t.Fatalf("legacy absence was relabelled as known provenance: %+v", legacy.ParameterSet)
	}

	bad := post25M108ParameterReference()
	bad.ManifestHash = "sha256:not-a-digest"
	if _, err := json.Marshal(Record{ParameterSet: bad}); err == nil {
		t.Fatal("malformed parameter identity marshalled")
	}
	raw := `{"schemaVersion":"phorvex.audit.v2","parameterSet":{"schemaVersion":"phorvex.decision-parameter-set.v1","manifestId":"production-source","manifestHash":"sha256:not-a-digest","policyOverridesId":"ns/policy/uid/7","policyOverridesHash":"sha256:2222222222222222222222222222222222222222222222222222222222222222"}}`
	if err := json.Unmarshal([]byte(raw), &legacy); err == nil {
		t.Fatal("malformed parameter identity decoded")
	}
}
