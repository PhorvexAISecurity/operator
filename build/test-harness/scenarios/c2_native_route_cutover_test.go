package scenarios

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	corev1 "k8s.io/api/core/v1"
)

func validNativeRouteReceipt(t *testing.T) (nativeRouteReceipt, nativeRouteAdapterRun, config.NativeRouteFixtureConfig) {
	t.Helper()
	fixture := nativeRouteReceiptFixture{
		Nonce: "receipt-test", Tenant: "tenant", Namespace: "fixture", NamespaceUID: "00000000-0000-4000-8000-000000000001",
		JournalNamespace: "fixture-journal", JournalNamespaceUID: "00000000-0000-4000-8000-000000000002", PolicyName: "policy", PolicyUID: "00000000-0000-4000-8000-000000000003", PolicyGeneration: 2,
		TargetName: "target", TargetUID: "00000000-0000-4000-8000-000000000004", PeerName: "peer", PeerUID: "00000000-0000-4000-8000-000000000005", ServiceName: "route", ServiceUID: "00000000-0000-4000-8000-000000000006", OperationID: strings.Repeat("b", 64),
	}
	pod := func(name, uid, ip, marker string) nativeRoutePod {
		return nativeRoutePod{Name: name, UID: uid, ResourceVersion: "1", PodIP: ip, PodIPs: []string{ip}, Labels: map[string]string{"fixture": "route", nativeRouteKey: "initial"}, Annotations: map[string]string{nativeRouteEpochKey: "r0", nativeEndpointEpochKey: "e0"}, ContainerIDs: map[string]string{"http": marker}, RestartCounts: map[string]int32{"http": 0}, Ready: true}
	}
	target := pod(fixture.TargetName, fixture.TargetUID, "10.0.0.1", "containerd://target")
	peer := pod(fixture.PeerName, fixture.PeerUID, "10.0.0.2", "containerd://peer")
	service := nativeRouteService{Name: fixture.ServiceName, UID: fixture.ServiceUID, ResourceVersion: "1", ClusterIP: "None", Selector: map[string]string{"fixture": "route", nativeRouteKey: "initial"}, Ports: []corev1.ServicePort{{Name: "http", Port: 8080}}}
	members := []string{fixture.TargetUID, fixture.PeerUID}
	sort.Strings(members)
	baseline := &nativeRouteState{Phase: "baseline", ObservedAt: "2026-09-22T00:00:00Z", NamespaceUID: fixture.NamespaceUID, JournalNamespaceUID: fixture.JournalNamespaceUID, PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGeneration, Target: target, Peer: peer, Service: service, ReadyMembers: members, Journal: []nativeRouteJournal{}}
	forward := *baseline
	forward.Phase, forward.ObservedAt = "forward", "2026-09-22T00:00:01Z"
	forward.Target.Labels = map[string]string{"fixture": "route", nativeRouteKey: "next"}
	forward.Target.Annotations = map[string]string{nativeRouteEpochKey: "r1", nativeEndpointEpochKey: "e0"}
	forward.Service.Selector = map[string]string{"fixture": "route", nativeRouteKey: "next"}
	forward.ReadyMembers = []string{fixture.TargetUID}
	serviceJournal, targetGuard := nativeRouteJournalNames(fixture)
	forward.Journal = []nativeRouteJournal{{Name: serviceJournal, UID: "00000000-0000-4000-8000-000000000007", ResourceVersion: "2", Labels: map[string]string{nativeOperationLabel: "v1"}, DataSHA256: strings.Repeat("c", 64), DataBytes: 100}}
	restored := *baseline
	restored.Phase, restored.ObservedAt = "restored", "2026-09-22T00:00:02Z"
	result := nativeRouteResult{Note: "retained", Actuator: "native", Handler: "route-rotate", Emitted: true, ObjectsTouched: []string{"Pod/fixture/target", "Service/fixture/route", "ConfigMap/fixture-journal/" + serviceJournal}, MutationKind: "reversible", RollbackRef: "fixture-journal/" + serviceJournal + "@" + forward.Journal[0].UID + "#" + strings.Repeat("d", 40)}
	request := nativeRouteReceipt{Schema: nativeRouteReceiptSchema, SourceRevision: strings.Repeat("a", 40), Action: "route-rotate", Fixture: fixture, StartedAt: "2026-09-22T00:00:00Z", FinishedAt: "2026-09-22T00:00:03Z", Status: "COMPLETE", Baseline: baseline, Forward: &forward, Restored: &restored, ForwardResult: result, RollbackAttempted: true, WriteJournalSchema: "phorvex.native-route-catalogue.write-journal.v1", WriteJournalSHA256: strings.Repeat("e", 64), WriteJournalBytes: 100}
	addHTTP := func(phase, endpoint string, identity nativeRouteHTTPIdentity) {
		raw, err := json.Marshal(identity)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		request.HTTP = append(request.HTTP, nativeRouteHTTP{Sequence: int64(len(request.HTTP) + 1), Phase: phase, Endpoint: endpoint, StartedAt: "2026-09-22T00:00:00Z", FinishedAt: "2026-09-22T00:00:00.001Z", Status: 200, Bytes: len(raw), SHA256: fmt.Sprintf("%x", sum), Body: string(raw), Identity: &identity})
	}
	targetIdentity := nativeRouteHTTPIdentity{Schema: nativeRouteIdentitySchema, Nonce: fixture.Nonce, Role: "target", PodUID: fixture.TargetUID, ProcessMarker: "target-process"}
	peerIdentity := nativeRouteHTTPIdentity{Schema: nativeRouteIdentitySchema, Nonce: fixture.Nonce, Role: "peer", PodUID: fixture.PeerUID, ProcessMarker: "peer-process"}
	for _, phase := range []string{"baseline", "forward-stable", "rollback-stable"} {
		addHTTP(phase, "target", targetIdentity)
		addHTTP(phase, "peer", peerIdentity)
		serviceIdentity := peerIdentity
		if phase == "forward-stable" {
			serviceIdentity = targetIdentity
		}
		addHTTP(phase, "service", serviceIdentity)
	}
	addWrite := func(method, kind, namespace, name, uid string) {
		request.Writes = append(request.Writes, nativeRouteWrite{Sequence: len(request.Writes) + 1, Method: method, Kind: kind, Namespace: namespace, Name: name, UID: uid, StartedAt: "2026-09-22T00:00:00Z", FinishedAt: "2026-09-22T00:00:00.001Z"})
	}
	addWrite("CREATE", "*v1.ConfigMap", fixture.JournalNamespace, targetGuard, "00000000-0000-4000-8000-000000000008")
	addWrite("CREATE", "*v1.ConfigMap", fixture.JournalNamespace, serviceJournal, forward.Journal[0].UID)
	addWrite("PATCH", "*v1.Pod", fixture.Namespace, fixture.TargetName, fixture.TargetUID)
	addWrite("UPDATE", "*v1.Service", fixture.Namespace, fixture.ServiceName, fixture.ServiceUID)
	addWrite("DELETE", "*v1.ConfigMap", fixture.JournalNamespace, targetGuard, "00000000-0000-4000-8000-000000000008")
	addWrite("UPDATE", "*v1.Service", fixture.Namespace, fixture.ServiceName, fixture.ServiceUID)
	addWrite("PATCH", "*v1.Pod", fixture.Namespace, fixture.TargetName, fixture.TargetUID)
	addWrite("DELETE", "*v1.ConfigMap", fixture.JournalNamespace, serviceJournal, forward.Journal[0].UID)
	run := nativeRouteAdapterRun{Schema: "phorvex.native-route-catalogue.config.v1", SourceRevision: request.SourceRevision, Action: request.Action, Fixture: nativeRouteAdapterFixture{Nonce: fixture.Nonce, Tenant: fixture.Tenant, Namespace: fixture.Namespace, NamespaceUID: fixture.NamespaceUID, JournalNamespace: fixture.JournalNamespace, JournalNamespaceUID: fixture.JournalNamespaceUID, PolicyName: fixture.PolicyName, PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGeneration, TargetName: fixture.TargetName, TargetUID: fixture.TargetUID, PeerName: fixture.PeerName, PeerUID: fixture.PeerUID, ServiceName: fixture.ServiceName, ServiceUID: fixture.ServiceUID, OperationID: fixture.OperationID}}
	authority := config.NativeRouteFixtureConfig{Action: request.Action, SourceRevision: request.SourceRevision, NamespaceUID: fixture.NamespaceUID, JournalNamespaceUID: fixture.JournalNamespaceUID, PolicyUID: fixture.PolicyUID, PolicyGeneration: fixture.PolicyGeneration, TargetUID: fixture.TargetUID, PeerUID: fixture.PeerUID, ServiceUID: fixture.ServiceUID, OperationID: fixture.OperationID}
	return request, run, authority
}

func replaceNativeRouteHTTPIdentity(t *testing.T, row *nativeRouteHTTP, identity nativeRouteHTTPIdentity) {
	t.Helper()
	raw, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	row.Body = string(raw)
	row.Bytes = len(raw)
	row.SHA256 = fmt.Sprintf("%x", sum)
	row.Identity = &identity
}

func TestNativeRouteReceiptRequiresCompleteTypedProductionEvidence(t *testing.T) {
	want, run, authority := validNativeRouteReceipt(t)
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var receipt nativeRouteReceipt
	if err := strictNativeRouteReceipt(raw, &receipt); err != nil {
		t.Fatalf("real-shaped receipt rejected: %v", err)
	}
	scenario := &c2NativeRouteCutover{action: "route-rotate", name: nativeRouteScenario, receipt: receipt, evidence: map[string]string{"oracleStatus": "COMPLETE"}, authority: authority, runAuthority: run}
	result, err := scenario.SuccessOracle(nil, nil)
	if err != nil || !result.Achieved {
		t.Fatalf("complete production receipt rejected: result=%+v err=%v", result, err)
	}
	for name, corrupt := range map[string]func(*nativeRouteReceipt){
		"forward-membership":       func(r *nativeRouteReceipt) { r.Forward.ReadyMembers = []string{r.Fixture.PeerUID} },
		"restoration":              func(r *nativeRouteReceipt) { r.Restored.Service.Selector[nativeRouteKey] = "wrong" },
		"forward-service-identity": func(r *nativeRouteReceipt) { replaceNativeRouteHTTPIdentity(t, &r.HTTP[5], *r.HTTP[1].Identity) },
		"process-marker": func(r *nativeRouteReceipt) {
			identity := *r.HTTP[3].Identity
			identity.ProcessMarker = "changed"
			replaceNativeRouteHTTPIdentity(t, &r.HTTP[3], identity)
		},
		"foreign-write": func(r *nativeRouteReceipt) { r.Writes[0].Name = "phorvex-route-target-" + strings.Repeat("f", 40) },
		"journal-link":  func(r *nativeRouteReceipt) { r.ForwardResult.RollbackRef = "opaque" },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(receipt)
			var candidate nativeRouteReceipt
			if err := json.Unmarshal(raw, &candidate); err != nil {
				t.Fatal(err)
			}
			corrupt(&candidate)
			scenario.receipt = candidate
			result, err := scenario.SuccessOracle(nil, nil)
			if err != nil || result.Achieved {
				t.Fatalf("corrupt typed evidence was accepted: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestNativeRouteReceiptRetainsTransportAndTerminalRowsTruthfully(t *testing.T) {
	base, _, _ := validNativeRouteReceipt(t)
	for name, mutate := range map[string]func(*nativeRouteReceipt){
		"terminal-cancellation-is-not-outage": func(r *nativeRouteReceipt) {
			r.HTTP = append(r.HTTP, nativeRouteHTTP{Sequence: int64(len(r.HTTP) + 1), Phase: "rollback-stable", Endpoint: "service", StartedAt: "2026-09-22T00:00:03Z", FinishedAt: "2026-09-22T00:00:03.001Z", Error: "Get service: context canceled", TerminalCancellation: true})
		},
		"observed-service-transport-error-is-outage": func(r *nativeRouteReceipt) {
			r.HTTP = append(r.HTTP, nativeRouteHTTP{Sequence: int64(len(r.HTTP) + 1), Phase: "forward-transition", Endpoint: "service", StartedAt: "2026-09-22T00:00:01Z", FinishedAt: "2026-09-22T00:00:01.001Z", Error: "dial tcp: connection refused"})
			r.AvailabilityInterrupted = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var receipt nativeRouteReceipt
			if err := json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			mutate(&receipt)
			if err := validateNativeRouteHTTPEvidence(receipt); err != nil {
				t.Fatalf("truthful retained error row rejected: %v", err)
			}
		})
	}

	base.HTTP = append(base.HTTP, nativeRouteHTTP{Sequence: int64(len(base.HTTP) + 1), Phase: "rollback-stable", Endpoint: "service", StartedAt: "2026-09-22T00:00:03Z", FinishedAt: "2026-09-22T00:00:03.001Z", Body: "unbound", Bytes: 7, Error: "Get service: context canceled", TerminalCancellation: true})
	if err := validateNativeRouteHTTPEvidence(base); err == nil {
		t.Fatal("terminal cancellation with unbound response body accepted")
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
