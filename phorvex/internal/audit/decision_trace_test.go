package audit

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/phorvex/phorvex/internal/model"
)

func TestAuditRecordCarriesVersionedDecisionTrace(t *testing.T) {
	trace := &model.DecisionTraceV2{
		SchemaVersion: model.DecisionTraceSchemaV2,
		DecisionID:    "decision", TickID: "tick", Timestamp: time.Unix(1, 0).UTC().Format(time.RFC3339Nano),
		BrainImage: "registry/phorvex:sha-test", GitSHA: "abcdef", DecisionEngine: "p1-coverage",
		PolicyUID: "policy-uid", AssetUID: "pod-uid", SelectedAction: string(model.ActionNoop),
		TieBreakReason: "notApplicable", NoopReason: "priced-out",
	}
	record := ToRecord(model.Decision{Action: model.ActionNoop, Trace: trace})
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	nested, ok := fields["decisionTrace"]
	if !ok {
		t.Fatalf("audit record omitted decisionTrace: %s", raw)
	}
	var decoded model.DecisionTraceV2
	if err := json.Unmarshal(nested, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != model.DecisionTraceSchemaV2 || decoded.DecisionID != "decision" {
		t.Fatalf("nested trace changed on audit serialization: %+v", decoded)
	}
}

func TestAuditLoggerSerializesRedactedRecordWithoutMutatingProducer(t *testing.T) {
	trace := &model.DecisionTraceV2{
		SchemaVersion: model.DecisionTraceSchemaV2,
		DecisionID:    "decision-stable", TickID: "tick-stable", Timestamp: time.Unix(2, 0).UTC().Format(time.RFC3339Nano),
		BrainImage: "https://registry-user:registry-password@registry.example/phorvex:tag", GitSHA: "abcdef", DecisionEngine: "p1-coverage",
		PolicyUID: "policy-uid", AssetUID: "pod-uid", SelectedAction: string(model.ActionNoop),
		TieBreakReason: "notApplicable", NoopReason: "Authorization: Bearer decision-secret",
		Facts: []model.DecisionFactV2{
			{FactKey: "fact-stable", FactType: "access", SourceComponent: "password=fact-secret"},
		},
		Candidates: []model.DecisionCandidateV2{
			{Action: string(model.ActionNoop), CandidateKey: "candidate-stable", SelectionReason: "Bearer candidate-secret", CoverKeys: []string{"fact-stable"}},
		},
	}
	before := *trace
	before.Facts = append([]model.DecisionFactV2(nil), trace.Facts...)
	before.Candidates = append([]model.DecisionCandidateV2(nil), trace.Candidates...)
	before.Candidates[0].CoverKeys = append([]string(nil), trace.Candidates[0].CoverKeys...)

	var sink bytes.Buffer
	logger := New(logr.Discard(), &sink)
	decision := model.Decision{
		Tenant: "tenant-a", Namespace: "ns-a", Pod: "pod-a",
		Action: model.ActionNoop, DecidedAt: time.Unix(2, 0).UTC(), Trace: trace,
	}
	if err := logger.Record(decision); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*trace, before) {
		t.Fatalf("audit serialization mutated producer trace:\n got %+v\nwant %+v", *trace, before)
	}

	raw := strings.TrimSpace(sink.String())
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatal(err)
	}
	nested, ok := fields["decisionTrace"]
	if !ok {
		t.Fatalf("serialized record dropped the decision trace: %s", raw)
	}
	// ToRecord also projects BrainImage into the legacy top-level ClaimScope,
	// whose preexisting raw-string behavior is tracked separately by M181. This
	// bounded control proves the nested trace boundary without treating that
	// distinct predecessor behavior as a regression caused by the regex guards.
	for _, secret := range []string{"registry-password", "decision-secret", "fact-secret", "candidate-secret"} {
		if bytes.Contains(nested, []byte(secret)) {
			t.Fatalf("serialized nested trace leaked %q: %s", secret, nested)
		}
	}
	var record Record
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		t.Fatal(err)
	}
	if record.DecisionTrace == nil {
		t.Fatal("serialized record dropped the decision trace")
	}
	if got := record.DecisionTrace.DecisionID; got != "decision-stable" {
		t.Fatalf("safe trace identity changed: %q", got)
	}
	if got := record.DecisionTrace.BrainImage; got != "https://[REDACTED]@registry.example/phorvex:tag" {
		t.Fatalf("nested URI user-info redaction changed: %q", got)
	}
	if got := record.DecisionTrace.NoopReason; got != "Authorization:[REDACTED]" {
		t.Fatalf("authorization redaction changed: %q", got)
	}
	if got := record.DecisionTrace.Facts[0].SourceComponent; got != "password=[REDACTED]" {
		t.Fatalf("fact redaction changed: %q", got)
	}
	if got := record.DecisionTrace.Candidates[0].SelectionReason; got != "Bearer [REDACTED]" {
		t.Fatalf("candidate redaction changed: %q", got)
	}

	trace.NoopReason = "mutated-after-record"
	if strings.Contains(sink.String(), trace.NoopReason) {
		t.Fatal("retained serialized record changed after producer mutation")
	}
}
