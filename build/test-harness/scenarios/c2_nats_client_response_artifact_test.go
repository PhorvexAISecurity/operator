package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNATSResponseArtifactRetainsPartialEvidenceAndBindsExclusiveTerminal(t *testing.T) {
	out := t.TempDir()
	a := natsResponseArtifact{Schema: natsResponseArtifactSchema, RunID: "run-7", Nonce: "0123456789abcdef01234567",
		Namespace: natsResponseFixtureNamespace, NamespaceUID: "namespace-uid", ClusterUID: "cluster-uid",
		Fixture:           natsResponseFixture{NamespaceUID: "namespace-uid"},
		InitialDisclosure: "EXPOSED", OngoingAccess: "CONTINUING_EXPOSURE", LegitimateService: "UNKNOWN",
		SecurityOutcome: "NOT_EVALUATED", Validity: "INCONCLUSIVE", Cleanup: "UNCONFIRMED",
		CapacityReservationStatus: "UNKNOWN", Repeatability: "UNKNOWN"}
	if err := writeNATSResponseArtifact(out, a, natsResponseCleanupChecks{}); err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(filepath.Join(out, "nats-response.json"))
	if err != nil {
		t.Fatal(err)
	}
	terminalRaw, err := os.ReadFile(filepath.Join(out, "nats-response-terminal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var terminal natsResponseTerminal
	if json.Unmarshal(terminalRaw, &terminal) != nil || terminal.ArtifactSHA256 != natsSHA(artifact) ||
		terminal.Cleanup != "UNCONFIRMED" || terminal.Schema != natsResponseTerminalSchema {
		t.Fatalf("partial terminal does not bind observed artifact: %+v", terminal)
	}
	if err := writeNATSResponseArtifact(out, a, natsResponseCleanupChecks{}); err == nil {
		t.Fatal("second artifact publication overwrote first observation")
	}
}

func TestNATSResponseArtifactRefusesUnsupportedDefenseClaims(t *testing.T) {
	base := natsResponseArtifact{Schema: natsResponseArtifactSchema, RunID: "run-7", Nonce: "0123456789abcdef01234567",
		Namespace: natsResponseFixtureNamespace, NamespaceUID: "namespace-uid", ClusterUID: "cluster-uid",
		Fixture:           natsResponseFixture{NamespaceUID: "namespace-uid"},
		InitialDisclosure: "EXPOSED", OngoingAccess: "UNKNOWN", LegitimateService: "UNKNOWN",
		SecurityOutcome: "NOT_EVALUATED", Validity: "INCONCLUSIVE", Cleanup: "UNCONFIRMED",
		CapacityReservationStatus: "UNKNOWN", Repeatability: "UNKNOWN"}
	for name, mutate := range map[string]func(*natsResponseArtifact){
		"silence-as-defense":    func(a *natsResponseArtifact) { a.SecurityOutcome = "CONTAINMENT_ACHIEVED" },
		"unknown-as-success":    func(a *natsResponseArtifact) { a.Validity = "MEASUREMENT_COMPLETE" },
		"cleanup-without-proof": func(a *natsResponseArtifact) { a.Cleanup = "CONFIRMED_ABSENT" },
		"changed-namespace":     func(a *natsResponseArtifact) { a.Fixture.NamespaceUID = "replacement" },
		"unknown-decision-as-no-debt": func(a *natsResponseArtifact) {
			a.CapacityReservationStatus = "NOT_APPLICABLE"
		},
		"negative-without-effect": func(a *natsResponseArtifact) {
			a.OngoingAccess = "CONTINUING_EXPOSURE"
			a.SecurityOutcome = "CONTAINMENT_NOT_ACHIEVED"
		},
		"unsupported-noop-negative": func(a *natsResponseArtifact) {
			a.OngoingAccess = "CONTINUING_EXPOSURE"
			a.SecurityOutcome = "CONTAINMENT_NOT_ACHIEVED"
			a.Decision = &natsResponseSignalDecision{SelectedAction: "noop", EffectStatus: "NOT_DISPATCHED"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := base
			mutate(&a)
			if err := writeNATSResponseArtifact(t.TempDir(), a, natsResponseCleanupChecks{}); err == nil {
				t.Fatal("unsupported defense/cleanup claim serialized")
			}
		})
	}
}
