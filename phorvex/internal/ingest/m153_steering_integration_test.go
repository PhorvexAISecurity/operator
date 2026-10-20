package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func m153SecurityEvent(name, uid, identity, vector string, targets ...string) *amtdv1beta1.SecurityEvent {
	e := seEvent(name, identity, "declared-"+name, targets...)
	e.UID = types.UID(uid)
	e.Spec.Rule.Type = vector
	return e
}

func TestM153ActualIngestionReconDecisionSerializedTrace(t *testing.T) {
	trustEvents(t, "ns/detector")
	trustedIdentity := "system:serviceaccount:ns:detector"
	objects := []*amtdv1beta1.SecurityEvent{
		m153SecurityEvent("trusted", "uid-trusted", trustedIdentity, model.AttackVectorKV, "ns/serve"),
		m153SecurityEvent("untrusted", "uid-untrusted", untrustedSA, model.AttackVectorKV, "ns/serve"),
		m153SecurityEvent("unstamped", "uid-unstamped", "", model.AttackVectorKV, "ns/serve"),
		m153SecurityEvent("wrong-target", "uid-target", trustedIdentity, model.AttackVectorKV, "ns/other"),
		m153SecurityEvent("wrong-type", "uid-type", trustedIdentity, "Persistence", "ns/serve"),
	}
	scheme := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	clientObjects := make([]client.Object, len(objects))
	for i := range objects {
		clientObjects[i] = objects[i]
	}
	all, byPod, err := collectEvents(context.Background(), fake.NewClientBuilder().WithScheme(scheme).WithObjects(clientObjects...).Build(), time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 || len(byPod["ns/serve"]) != 2 {
		t.Fatalf("ingestion all/byPod=%d/%d", len(all), len(byPod["ns/serve"]))
	}

	view := &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "serve", UID: "pod-uid", HasGPU: true, ModelID: "model", Ready: true, DesiredReplicas: 1, ReadyReplicas: 1},
		Phase: model.PhaseWarm, Physics: model.NeutralPhysics(), Events: byPod["ns/serve"], ExposureByVariable: map[string]time.Duration{model.VarSession: 2 * time.Hour}}
	engine := decision.NewCoverageEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon absent")
	}
	engine.Recon = profile
	policy := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", TickID: "tick", BrainImage: "image", GitSHA: "sha",
		DryRun: true, Lambda: cost.DefaultLambdaSeed, NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, MaxMovesPerTick: 1,
		ProactiveFloor: time.Hour, AntiOverRotationWindow: time.Minute, EnabledActions: map[model.Action]bool{model.ActionKVMigrateInvalidate: true}, TraceEnabled: true}
	decisions := engine.Decide([]*model.WorkloadView{view}, policy)
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("decision trace absent: %+v", decisions)
	}
	var steering *model.VectorSteeringAttribution
	for _, fact := range decisions[0].Trace.Facts {
		if fact.FactType == recon.FactSession {
			steering = fact.SteeredBy
		}
	}
	if steering == nil || steering.AppliedMultiplier != 3 || len(steering.Events) != 1 {
		t.Fatalf("steering=%+v", steering)
	}
	ref := steering.Events[0]
	if ref.EventName != "trusted" || ref.EventUID != "uid-trusted" || ref.DeclaredSource != "declared-trusted" || ref.TrustVerdict != eventtrust.TrustTrusted || ref.CreatorIdentity != trustedIdentity {
		t.Fatalf("actual event identity lost: %+v", ref)
	}
	raw, err := json.Marshal(decisions[0].Trace)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatalf("invalid serialized trace: %s", raw)
	}
}
