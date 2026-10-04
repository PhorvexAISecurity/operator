package console

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/crmrefund"
	"github.com/phorvex/phorvex/internal/model"
)

// The event the producer stamps must serialize to exactly the keyset the actuator's
// crmrefund.ParseObservation accepts, or the brain can never bind the fact. This pins that
// contract in the console so a drift in either side fails here, not silently on-cluster.
func TestCRMLiveObservationParsesForActuator(t *testing.T) {
	observation := crmrefund.Observation{
		Version: 1, OrderID: crmLiveOrderID, OrderAccountID: crmLiveOrderAccountID, CallerAccountID: crmLiveCallerAccountID,
		GuardConfigMapUID: "11111111-1111-1111-1111-111111111111", ServiceUID: "22222222-2222-2222-2222-222222222222",
		TargetPodUID: "33333333-3333-3333-3333-333333333333", PeerPodUID: "44444444-4444-4444-4444-444444444444",
		Objective: "ai2-cross-record-refund", ObservedAt: time.Now().UTC().Truncate(time.Second),
		PolicyName: crmLivePolicyName, PolicyUID: "55555555-5555-5555-5555-555555555555", PolicyGeneration: 2,
	}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := crmrefund.ParseObservation(string(raw))
	if err != nil {
		t.Fatalf("the producer observation must satisfy the actuator contract: %v", err)
	}
	if got.OrderID != crmLiveOrderID || got.OrderAccountID == got.CallerAccountID || got.Objective != "ai2-cross-record-refund" {
		t.Fatalf("round-trip lost the abused pair: %+v", got)
	}
}

func crmLiveTestTrace(podUID string) *model.DecisionTraceV2 {
	return &model.DecisionTraceV2{
		SchemaVersion: model.DecisionTraceSchemaV2, DecisionID: "crm-decision-1", TickID: "crm-tick-1",
		PolicyNamespace: "crm", PolicyName: crmLivePolicyName, PolicyUID: "policy-uid",
		AssetNamespace: "crm", AssetName: "crm-abc", AssetUID: podUID,
		SelectedAction: string(model.ActionCRMRefundRevoke),
	}
}

func TestCRMLiveSelectedDecisionBindsOnlyExactEvent(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	record := &attackRecord{Pod: "crm-abc", TargetUID: "pod-uid", started: now.Add(-time.Minute)}
	snap := crmLiveSnapshot{PolicyUID: "policy-uid"}
	trusted := model.EventEvidence{EventUID: "event-uid", TargetPodUID: "pod-uid", TrustVerdict: "trusted", Weight: 1}

	good := audit.Record{Kind: "phorvex.decision", Namespace: "crm", Pod: "crm-abc", Time: now, Selected: true,
		Action: string(model.ActionCRMRefundRevoke), DecisionTrace: crmLiveTestTrace("pod-uid"),
		Events: []model.EventEvidence{trusted}}
	if d, ok := crmLiveSelectedDecision(good, record, snap, "event-uid"); !ok || d.Action != string(model.ActionCRMRefundRevoke) || d.DecisionID != "crm-decision-1" {
		t.Fatalf("exact crm decision did not bind: ok=%v d=%+v", ok, d)
	}

	// Wrong event id: an untrusted or unrelated event must not credit this run.
	if _, ok := crmLiveSelectedDecision(good, record, snap, "other-event"); ok {
		t.Fatal("decision bound to the wrong event uid")
	}
	// Two trusted events make the decision unattributable.
	twoEvents := good
	twoEvents.Events = []model.EventEvidence{trusted, {EventUID: "x", TargetPodUID: "pod-uid", TrustVerdict: "trusted", Weight: 1}}
	if _, ok := crmLiveSelectedDecision(twoEvents, record, snap, "event-uid"); ok {
		t.Fatal("decision bound despite two trusted events")
	}
	// Wrong namespace / policy / action are all rejected.
	wrongNS := good
	wrongNS.Namespace = "voice"
	if _, ok := crmLiveSelectedDecision(wrongNS, record, snap, "event-uid"); ok {
		t.Fatal("decision bound in the wrong namespace")
	}
}

// Arming is gated on BOTH the mounted deny-guard and the console producer being enabled.
func TestCRMLiveArmingGate(t *testing.T) {
	base := appStack{Namespace: "crm", Workload: true, Armed: true, CRMRefundGuard: true, CRMRefundLive: true}
	find := func(st appStack) compatEntry {
		for _, e := range compatibleLive(st) {
			if e.StackLabel == "crm-refund" {
				return e
			}
		}
		t.Fatal("crm-refund row missing from catalogue")
		return compatEntry{}
	}
	if e := find(base); !e.Armed {
		t.Fatalf("crm-refund should arm when guard+producer present: %+v", e)
	}
	noProducer := base
	noProducer.CRMRefundLive = false
	if e := find(noProducer); e.Armed {
		t.Fatalf("crm-refund must not arm without the Live producer: %+v", e)
	}
	noGuard := base
	noGuard.CRMRefundGuard, noGuard.CRMRefundLive = false, false
	if e := find(noGuard); e.Armed {
		t.Fatalf("crm-refund must not arm without the deny-guard: %+v", e)
	}
}
