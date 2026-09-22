package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

func TestNativeRouteReceiptRequiresCompleteTypedProductionEvidence(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"schema": nativeRouteReceiptSchema, "sourceRevision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "action": "route-rotate",
		"fixture":   map[string]any{"namespaceUID": "00000000-0000-4000-8000-000000000001", "extra": "retained"},
		"startedAt": "2026-09-22T00:00:00Z", "finishedAt": "2026-09-22T00:00:01Z", "status": "COMPLETE",
		"baseline": map[string]any{"phase": "baseline"}, "forward": map[string]any{"phase": "forward"}, "restored": map[string]any{"phase": "restored"},
		"forwardResult":     map[string]any{"Actuator": "native", "Handler": "route-rotate", "Emitted": true, "MutationKind": "reversible", "RollbackRef": "opaque", "Note": "retained"},
		"rollbackAttempted": true, "http": []any{map[string]any{"endpoint": "service", "error": "", "status": 200}},
		"writes":                  []any{map[string]any{"method": "PATCH", "kind": "*v1.Pod", "namespace": "fixture", "name": "target"}},
		"writeJournalSchema":      "phorvex.native-route-catalogue.write-journal.v1",
		"writeJournalSHA256":      strings.Repeat("d", 64),
		"writeJournalBytes":       100,
		"availabilityInterrupted": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	var receipt nativeRouteReceipt
	if err := strictNativeRouteReceipt(raw, &receipt); err != nil {
		t.Fatalf("real-shaped receipt rejected: %v", err)
	}
	authority := config.NativeRouteFixtureConfig{Action: receipt.Action, SourceRevision: receipt.SourceRevision, NamespaceUID: receipt.Fixture.NamespaceUID, JournalNamespaceUID: receipt.Fixture.JournalNamespaceUID, PolicyUID: receipt.Fixture.PolicyUID, PolicyGeneration: receipt.Fixture.PolicyGeneration, TargetUID: receipt.Fixture.TargetUID, PeerUID: receipt.Fixture.PeerUID, ServiceUID: receipt.Fixture.ServiceUID, OperationID: receipt.Fixture.OperationID}
	scenario := &c2NativeRouteCutover{action: "route-rotate", name: nativeRouteScenario, receipt: receipt, evidence: map[string]string{"oracleStatus": "COMPLETE"}, authority: authority}
	result, err := scenario.SuccessOracle(nil, nil)
	if err != nil || !result.Achieved {
		t.Fatalf("complete production receipt rejected: result=%+v err=%v", result, err)
	}
	receipt.Writes[0].Error = "write ambiguous"
	scenario.receipt = receipt
	result, err = scenario.SuccessOracle(nil, nil)
	if err != nil || result.Achieved {
		t.Fatalf("failed write was accepted: result=%+v err=%v", result, err)
	}
}

func TestNativeRouteAdapterConfigBindsFullFixtureBeforeExecution(t *testing.T) {
	authority := &config.NativeRouteFixtureConfig{Action: "route-rotate", SourceRevision: strings.Repeat("a", 40), NamespaceUID: "ns", JournalNamespaceUID: "journal", PolicyUID: "policy", PolicyGeneration: 2, TargetUID: "target", PeerUID: "peer", ServiceUID: "service", OperationID: strings.Repeat("b", 64)}
	wire := nativeRouteAdapterConfig{Schema: "phorvex.native-route-catalogue.command.v1", Kubeconfig: "/private/kubeconfig", Context: "owned", MaxDurationSeconds: 60, Run: nativeRouteAdapterRun{Schema: "phorvex.native-route-catalogue.config.v1", SourceRevision: authority.SourceRevision, Action: authority.Action, Fixture: nativeRouteAdapterFixture{Namespace: "tenant", NamespaceUID: authority.NamespaceUID, JournalNamespaceUID: authority.JournalNamespaceUID, PolicyUID: authority.PolicyUID, PolicyGeneration: authority.PolicyGeneration, TargetUID: authority.TargetUID, PeerUID: authority.PeerUID, ServiceUID: authority.ServiceUID, OperationID: authority.OperationID}}}
	path := filepath.Join(t.TempDir(), "config.json")
	write := func() {
		raw, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := validateNativeRouteAdapterConfig(path, "owned", "tenant", authority); err != nil {
		t.Fatalf("exact adapter config rejected: %v", err)
	}
	wire.Run.Fixture.OperationID = strings.Repeat("c", 64)
	write()
	if err := validateNativeRouteAdapterConfig(path, "owned", "tenant", authority); err == nil {
		t.Fatal("different operation authority accepted before execution")
	}
}

func TestNativeRouteReceiptRejectsUnknownTopLevelField(t *testing.T) {
	raw := []byte(`{"schema":"phorvex.native-route-catalogue.receipt.v1","unknown":true}`)
	if err := strictNativeRouteReceipt(raw, &nativeRouteReceipt{}); err == nil {
		t.Fatal("unknown top-level receipt field accepted")
	}
}

func TestNativeRouteReceiptRefusesDifferentSourceOrFixtureAuthority(t *testing.T) {
	authority := &config.NativeRouteFixtureConfig{Action: "route-rotate", SourceRevision: strings.Repeat("a", 40), NamespaceUID: "ns", JournalNamespaceUID: "journal", PolicyUID: "policy", PolicyGeneration: 2, TargetUID: "target", PeerUID: "peer", ServiceUID: "service", OperationID: strings.Repeat("b", 64)}
	receipt := nativeRouteReceipt{Action: authority.Action, SourceRevision: authority.SourceRevision, Fixture: nativeRouteReceiptFixture{NamespaceUID: authority.NamespaceUID, JournalNamespaceUID: authority.JournalNamespaceUID, PolicyUID: authority.PolicyUID, PolicyGeneration: authority.PolicyGeneration, TargetUID: authority.TargetUID, PeerUID: authority.PeerUID, ServiceUID: authority.ServiceUID, OperationID: authority.OperationID}}
	if err := validateNativeRouteReceiptAuthority(receipt, authority); err != nil {
		t.Fatalf("exact receipt authority rejected: %v", err)
	}
	receipt.SourceRevision = strings.Repeat("c", 40)
	if err := validateNativeRouteReceiptAuthority(receipt, authority); err == nil {
		t.Fatal("different source receipt accepted")
	}
	receipt.SourceRevision = authority.SourceRevision
	receipt.Fixture.ServiceUID = "different-service"
	if err := validateNativeRouteReceiptAuthority(receipt, authority); err == nil {
		t.Fatal("different fixture receipt accepted")
	}
}
