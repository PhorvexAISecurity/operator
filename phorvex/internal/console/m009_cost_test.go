package console

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestM009ActuationCostCountsConfirmedPhoenixOnceAndSurfacesUnknown(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0).UTC()
	rows := []map[string]any{
		{"schemaVersion": "phorvex.audit.v2", "kind": "phorvex.decision", "time": t0.Format(time.RFC3339Nano), "tenant": "tenant", "action": "rotate", "actuated": true, "handler": "rotate"}, // typed native preserved
		{"schemaVersion": "phorvex.audit.v2", "kind": "phorvex.decision", "time": t0.Add(5 * time.Minute).Format(time.RFC3339Nano), "tenant": "tenant", "action": "rotate", "actuated": true}, // untyped legacy preserved, but labelled partial
		{"schemaVersion": "phorvex.audit.v2", "kind": "phorvex.decision", "time": t0.Add(10 * time.Minute).Format(time.RFC3339Nano), "tenant": "tenant", "namespace": "ns", "pod": "pod", "action": "rotate", "actuated": true, "decisionTrace": map[string]any{"decisionID": "decision-a", "assetUID": "pod-uid"}, "phoenix": map[string]any{"eventName": "event-a", "eventUID": "confirmed"}},
		{"schemaVersion": "phorvex.audit.v2", "kind": "phorvex.decision", "time": t0.Add(15 * time.Minute).Format(time.RFC3339Nano), "tenant": "tenant", "namespace": "ns", "pod": "pod", "action": "rotate", "actuated": true, "decisionTrace": map[string]any{"decisionID": "decision-missing", "assetUID": "pod-uid"}, "phoenix": map[string]any{"eventName": "event-missing"}},
		{"schemaVersion": "phorvex.audit.v2", "kind": "phorvex.decision", "time": t0.Add(20 * time.Minute).Format(time.RFC3339Nano), "tenant": "tenant", "namespace": "ns", "pod": "pod", "action": "rotate", "actuated": true, "decisionTrace": map[string]any{"decisionID": "decision-b", "assetUID": "pod-uid"}, "phoenix": map[string]any{"eventName": "event-b", "eventUID": "pending"}},
		{"schemaVersion": "phorvex.audit.v2", "kind": "phorvex.actuation-observation", "time": t0.Add(time.Hour).Format(time.RFC3339Nano), "tenant": "tenant", "namespace": "ns", "pod": "pod", "targetUID": "pod-uid", "backend": "phoenix", "action": "rotate", "decisionID": "decision-a", "eventName": "event-a", "eventUID": "confirmed", "outcome": "confirmed-execution-recovery-censored", "executionConfirmed": true},
		// Duplicate terminal rows must not double-price one event UID.
		{"schemaVersion": "phorvex.audit.v2", "kind": "phorvex.actuation-observation", "time": t0.Add(2 * time.Hour).Format(time.RFC3339Nano), "tenant": "tenant", "namespace": "ns", "pod": "pod", "targetUID": "pod-uid", "backend": "phoenix", "action": "rotate", "decisionID": "decision-a", "eventName": "event-a", "eventUID": "confirmed", "outcome": "confirmed-execution-recovery", "executionConfirmed": true},
	}
	var body []byte
	for _, row := range rows {
		b, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, append(b, '\n')...)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	cost, rate, coverage, err := (&Config{AuditPath: path}).actuationCostPerYear(context.Background(), 1, func(tenant string) bool { return tenant == "tenant" })
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(rate-9) > 1e-9 || math.Abs(cost-9*8760) > 1e-6 || !coverage.Partial() || coverage.TypedNative != 1 || coverage.UntypedLegacy != 1 || coverage.PendingPhoenix != 2 {
		t.Fatalf("cost=%v rate=%v coverage=%+v; want typed native, preserved untyped legacy, and confirmed Phoenix over decision-only 20m span", cost, rate, coverage)
	}
}

func TestM009ActuationCostRequiresFullObservationCorrelation(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0).UTC()
	rows := []map[string]any{
		{"kind": "phorvex.decision", "time": t0.Format(time.RFC3339Nano), "tenant": "tenant", "namespace": "ns", "pod": "pod", "action": "rotate", "actuated": true, "decisionTrace": map[string]any{"decisionID": "decision-a", "assetUID": "pod-uid"}, "phoenix": map[string]any{"eventName": "event-a", "eventUID": "event-uid"}},
		{"kind": "phorvex.decision", "time": t0.Add(time.Hour).Format(time.RFC3339Nano), "tenant": "tenant", "action": "noop", "actuated": false},
		// Event UID alone is insufficient: this row is bound to a different decision.
		{"kind": "phorvex.actuation-observation", "time": t0.Add(10 * time.Hour).Format(time.RFC3339Nano), "tenant": "tenant", "namespace": "ns", "pod": "pod", "targetUID": "pod-uid", "backend": "phoenix", "action": "rotate", "decisionID": "decision-other", "eventName": "event-a", "eventUID": "event-uid", "outcome": "confirmed-execution-recovery", "executionConfirmed": true},
		// Matching the decision and event still cannot price a different target identity.
		{"kind": "phorvex.actuation-observation", "time": t0.Add(11 * time.Hour).Format(time.RFC3339Nano), "tenant": "tenant", "namespace": "ns", "pod": "pod", "targetUID": "replacement-uid", "backend": "phoenix", "action": "rotate", "decisionID": "decision-a", "eventName": "event-a", "eventUID": "event-uid", "outcome": "confirmed-execution-recovery", "executionConfirmed": true},
	}
	var body []byte
	for _, row := range rows {
		b, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		body = append(body, append(b, '\n')...)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	cost, rate, coverage, err := (&Config{AuditPath: path}).actuationCostPerYear(context.Background(), 1, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if cost != 0 || rate != 0 || coverage.PendingPhoenix != 1 || !coverage.Partial() {
		t.Fatalf("mismatched observation priced submission: cost=%v rate=%v coverage=%+v", cost, rate, coverage)
	}
}
