package console

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

// The harness emits its actual request and M0 prefix first. This test inserts
// only the console-owned decision barrier through the production one-shot
// writers; the harness then emits its actual artifact and terminal receipt.
func TestNATSResponseProduceWireDecision(t *testing.T) {
	out := os.Getenv("NATS_RESPONSE_WIRE_OUT")
	if out == "" {
		t.Skip("cross-module wire fixture not requested")
	}
	if os.Getenv("NATS_RESPONSE_WIRE_PHASE") == "read" {
		got, err := readNATSResponseResult(out, "run-7", natsFixtureNamespace)
		if err != nil || !got.Accepted || got.SecurityEfficacy != "NOT_EVALUATED" || got.M1Status != "CONTINUING_EXPOSURE" {
			t.Fatalf("actual harness wire refused or overstated: result=%+v err=%v", got, err)
		}
		files := []string{"nats-response-signal-request.json", "nats-response-m0-prefix.jsonl", "nats-response-peer-m0-prefix.jsonl",
			"nats-response-decision-evidence.json", "nats-response-signal-decision.json", "nats-response.json", "nats-response-terminal.json"}
		clone := func() string {
			t.Helper()
			copyDir := t.TempDir()
			for _, name := range files {
				raw, readErr := os.ReadFile(filepath.Join(out, name))
				if readErr != nil || os.WriteFile(filepath.Join(copyDir, name), raw, 0600) != nil {
					t.Fatalf("copy producer wire %s: %v", name, readErr)
				}
			}
			return copyDir
		}
		t.Run("swapped original peer M1", func(t *testing.T) {
			copyDir := clone()
			artifactPath := filepath.Join(copyDir, "nats-response.json")
			raw, readErr := os.ReadFile(artifactPath)
			var a natsResponseArtifact
			if readErr != nil || json.Unmarshal(raw, &a) != nil {
				t.Fatal("producer artifact unavailable")
			}
			a.M1.PeerObserver[3].PodUID = "replacement-not-peer"
			raw, err = json.Marshal(a)
			if err != nil || os.WriteFile(artifactPath, raw, 0600) != nil {
				t.Fatal("swapped peer fixture write failed")
			}
			terminalPath := filepath.Join(copyDir, "nats-response-terminal.json")
			terminalRaw, _ := os.ReadFile(terminalPath)
			var terminal natsResponseTerminal
			if json.Unmarshal(terminalRaw, &terminal) != nil {
				t.Fatal("producer terminal unavailable")
			}
			terminal.ArtifactSHA256 = natsSHA(raw)
			terminalRaw, _ = json.Marshal(terminal)
			if err := os.WriteFile(terminalPath, terminalRaw, 0600); err != nil {
				t.Fatal(err)
			}
			if result, err := readNATSResponseResult(copyDir, "run-7", natsFixtureNamespace); err == nil && result.Accepted {
				t.Fatal("swapped peer received-payload identity admitted")
			}
		})
		t.Run("late original peer M0 prefix drift", func(t *testing.T) {
			copyDir := clone()
			path := filepath.Join(copyDir, "nats-response-peer-m0-prefix.jsonl")
			raw, err := os.ReadFile(path)
			if err != nil || os.WriteFile(path, append(raw, '\n'), 0600) != nil {
				t.Fatal("peer prefix drift fixture failed")
			}
			if result, err := readNATSResponseResult(copyDir, "run-7", natsFixtureNamespace); err == nil && result.Accepted {
				t.Fatal("late M0 prefix change admitted")
			}
		})
		return
	}
	r, err := readNATSResponseRequest(out, "run-7")
	if err != nil {
		t.Fatal(err)
	}
	trace := caseTraceValidTrace(time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), false, false)
	trace.PolicyNamespace, trace.PolicyName, trace.PolicyUID = r.Namespace, r.PolicyName, r.PolicyUID
	trace.TenantName = r.Namespace
	trace.AssetNamespace, trace.AssetName, trace.AssetUID = r.Namespace, r.ClientPod, r.ClientPodUID
	trace.DispatchOutcome = model.DispatchNotAttempted
	trace.ActionStatus = nil
	for _, action := range model.MutatingActions {
		trace.ActionStatus = append(trace.ActionStatus, model.DecisionActionStatusV3{Action: string(action), Status: model.ActionStatusNotEnabled, ExclusionKind: model.ExclusionNotEnabled})
	}
	if err := trace.Validate(); err != nil {
		t.Fatalf("synthetic manager trace fixture invalid: %v", err)
	}
	traceRaw, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	rec := &audit.Record{Action: "noop", DispatchOutcome: model.DispatchNotAttempted, DecisionTrace: trace}
	created := &attackStimulusEvidence{EventName: "synthetic-owned-event", EventUID: "synthetic-event-uid"}
	evidenceSHA, err := publishNATSDecisionEvidence(out, r, rec, natsSHA(traceRaw), created, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := natsResponseDecision{Schema: natsResponseSchema, RunID: r.RunID, Nonce: r.Nonce, NamespaceUID: r.NamespaceUID,
		ClientPodUID: r.ClientPodUID, PeerPodUID: r.PeerPodUID, PolicyUID: r.PolicyUID, PolicyGeneration: r.PolicyGeneration,
		ManagerPodUID: r.ManagerPodUID, ManagerContainerID: r.ManagerContainerID, M0ReceiptSHA256: r.M0ReceiptSHA256,
		PeerM0ReceiptSHA256: r.PeerM0ReceiptSHA256, EventName: created.EventName, EventUID: created.EventUID,
		AttackID: "synthetic-attack-id", DecisionID: trace.DecisionID, DecisionTraceSHA256: natsSHA(traceRaw),
		DecisionEvidenceSHA256: evidenceSHA, SelectedAction: "noop", DispatchOutcome: model.DispatchNotAttempted,
		EffectStatus: "NOT_DISPATCHED", EventCleanupStatus: "CONFIRMED_ABSENT"}
	if err := publishNATSResponseDecision(out, d); err != nil {
		t.Fatal(err)
	}
}
