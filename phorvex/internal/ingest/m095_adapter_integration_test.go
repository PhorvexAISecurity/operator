package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func TestM095PodAnnotationAloneCannotMintIntegrity(t *testing.T) {
	trustEvents(t, "ns/detector")
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "serve", UID: "pod-1",
		Labels: map[string]string{"phorvex.ai/lora-enabled": "true"}, Annotations: map[string]string{"phorvex.ai/lora-adapter": "forged", "phorvex.ai/model-id": "model"}}}
	projected := projectPod(p, now)
	if projected.SuspectAdapter != "" || projected.AdapterObservation != nil {
		t.Fatalf("tenant annotation created evidence: %+v", projected)
	}
	view := &model.WorkloadView{Pod: projected}
	if hasAdapterFact(view) {
		t.Fatal("annotation-only Pod minted adapterIntegrity")
	}
}

func m95Event(name, uid, creator, typ, targetUID, adapter string, created time.Time, target string) *amtdv1beta1.SecurityEvent {
	e := seEvent(name, creator, "tenant-claimed-detector", target)
	e.UID = types.UID(uid)
	e.Spec.Rule.Type = typ
	e.CreationTimestamp = metav1.NewTime(created)
	e.Annotations = map[string]string{CreatorIdentityAnnotation: creator, AdapterTargetUIDAnnotation: targetUID, AdapterNameAnnotation: adapter}
	return e
}

func hasAdapterFact(v *model.WorkloadView) bool {
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		panic("ucw-recon missing")
	}
	af := profile.AssetFacts(v, recon.FactContext{AssetValue: 1, PHold: 1, StageUrgency: 1, HasGPU: true})
	for _, f := range af.Facts {
		if f.Kind == recon.FactAdapterIntegrity {
			return true
		}
	}
	return false
}

func TestM095TrustedEventBindsAdapterAndRefreshClearsIt(t *testing.T) {
	trustEvents(t, "ns/detector")
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	creator := "system:serviceaccount:ns:detector"
	good := m95Event("detected", "event-1", creator, model.AttackVectorAdapter, "pod-1", "detected-adapter", now.Add(-time.Minute), "ns/serve")
	scheme := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(good).Build()
	read := func(uid, modelID string) model.Pod {
		_, byPod, err := collectEvents(context.Background(), c, now)
		if err != nil {
			t.Fatal(err)
		}
		// Adapter authority is the trusted UID-bound event, independent of a generic
		// model/GPU/serving declaration.
		p := model.Pod{Namespace: "ns", Name: "serve", UID: uid, ModelID: modelID}
		bindAdapterObservation(&p, byPod["ns/serve"])
		return p
	}
	var p model.Pod
	for _, modelID := range []string{"model", ""} {
		p = read("pod-1", modelID)
		if p.SuspectAdapter != "detected-adapter" || p.AdapterObservation == nil || !hasAdapterFact(&model.WorkloadView{Pod: p}) {
			t.Fatalf("trusted control absent with model-id %q: %+v", modelID, p)
		}
	}
	if p.AdapterObservation.EventUID != "event-1" || p.AdapterObservation.TargetPodUID != "pod-1" {
		t.Fatalf("wrong provenance: %+v", p.AdapterObservation)
	}
	if recreated := read("pod-2", ""); recreated.SuspectAdapter != "" || hasAdapterFact(&model.WorkloadView{Pod: recreated}) {
		t.Fatal("same-name recreated Pod inherited evidence")
	}
	if err := c.Delete(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	if refreshed := read("pod-1", ""); refreshed.SuspectAdapter != "" || hasAdapterFact(&model.WorkloadView{Pod: refreshed}) {
		t.Fatal("removed event left stale evidence")
	}
}

func TestM095AdapterObservationRejectsControlsAndConflict(t *testing.T) {
	trustEvents(t, "ns/detector")
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	creator := "system:serviceaccount:ns:detector"
	good := model.SecurityEventInfo{Name: "good", UID: "e1", Trust: TrustTrusted, CreatorIdentity: creator, Type: model.AttackVectorAdapter,
		TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-1", CreatedAt: now.Add(-time.Minute), Age: time.Minute}
	controls := []model.SecurityEventInfo{
		{Name: "self", UID: "e0", Trust: TrustSelf, CreatorIdentity: creator, Type: model.AttackVectorAdapter, TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-1"},
		{Name: "unstamped", UID: "e00", Trust: TrustUnstamped, Type: model.AttackVectorAdapter, TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-1"},
		{Name: "untrusted", UID: "e2", Trust: TrustUntrusted, CreatorIdentity: "evil", Type: model.AttackVectorAdapter, TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-1"},
		{Name: "generic", UID: "e3", Trust: TrustTrusted, CreatorIdentity: creator, Type: "Persistence", TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-1"},
		{Name: "wrong namespace", UID: "e31", Trust: TrustTrusted, CreatorIdentity: creator, Type: model.AttackVectorAdapter, TargetsPod: false, AdapterName: "a", AdapterTargetUID: "pod-1"},
		{Name: "wrongUID", UID: "e4", Trust: TrustTrusted, CreatorIdentity: creator, Type: model.AttackVectorAdapter, TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-2"},
		{Name: "missingTime", UID: "e5", Trust: TrustTrusted, CreatorIdentity: creator, Type: model.AttackVectorAdapter, TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-1", TimestampMissing: true},
		{Name: "stale", UID: "e6", Trust: TrustTrusted, CreatorIdentity: creator, Type: model.AttackVectorAdapter, TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-1", Age: 15 * time.Minute},
		{Name: "invalid", UID: "e7", Trust: TrustTrusted, CreatorIdentity: creator, Type: model.AttackVectorAdapter, TargetsPod: true, AdapterName: "a/b", AdapterTargetUID: "pod-1"},
	}
	for _, e := range controls {
		p := model.Pod{Namespace: "ns", Name: "serve", UID: "pod-1"}
		bindAdapterObservation(&p, []model.SecurityEventInfo{e})
		if p.AdapterObservation != nil {
			t.Fatalf("control %q accepted", e.Name)
		}
	}
	p := model.Pod{Namespace: "ns", Name: "serve", UID: "pod-1"}
	bindAdapterObservation(&p, []model.SecurityEventInfo{good, {Name: "conflict", UID: "e8", Trust: TrustTrusted, CreatorIdentity: creator, Type: model.AttackVectorAdapter, TargetsPod: true, AdapterName: "b", AdapterTargetUID: "pod-1", Age: time.Minute}})
	if p.AdapterObservation != nil {
		t.Fatal("conflicting adapter identities accepted")
	}
}

func TestM071AdapterObservationSelectsFreshestSameAdapterEvent(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	creator := "system:serviceaccount:ns:detector"
	old := model.SecurityEventInfo{Name: "a-old", UID: "old", Trust: TrustTrusted, CreatorIdentity: creator, Type: model.AttackVectorAdapter,
		TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-1", CreatedAt: now.Add(-2 * time.Minute), Age: 2 * time.Minute}
	fresh := model.SecurityEventInfo{Name: "z-fresh", UID: "fresh", Trust: TrustTrusted, CreatorIdentity: creator, Type: model.AttackVectorAdapter,
		TargetsPod: true, AdapterName: "a", AdapterTargetUID: "pod-1", CreatedAt: now.Add(-time.Minute), Age: time.Minute}
	p := model.Pod{Namespace: "ns", Name: "serve", UID: "pod-1"}
	bindAdapterObservation(&p, []model.SecurityEventInfo{old, fresh})
	if p.AdapterObservation == nil || p.AdapterObservation.EventUID != fresh.UID {
		t.Fatalf("fresh poison assertion was shadowed by an older lexical event: %+v", p.AdapterObservation)
	}
	conflict := fresh
	conflict.UID, conflict.AdapterName, conflict.CreatedAt = "conflict", "b", now
	bindAdapterObservation(&p, []model.SecurityEventInfo{old, fresh, conflict})
	if p.AdapterObservation != nil {
		t.Fatalf("freshest selection weakened conflicting-adapter refusal: %+v", p.AdapterObservation)
	}
}

func TestM095ProductionSnapshotViewLifecycle(t *testing.T) {
	trustEvents(t, "ns/detector")
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	creator := "system:serviceaccount:ns:detector"
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "serve", UID: "pod-1",
		Labels: map[string]string{"phorvex.ai/lora-enabled": "true"}, Annotations: map[string]string{"phorvex.ai/lora-adapter": "tenant-forged", "phorvex.ai/model-id": "model"}}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}
	event := m95Event("detected", "event-1", creator, model.AttackVectorAdapter, "pod-1", "actual", now.Add(-time.Minute), "ns/serve")
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod, ns, event).Build()
	var productionEvents []model.SecurityEventInfo
	snapshot := func() model.Pod {
		snap, err := CollectSnapshot(context.Background(), c, now, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !snap.EventInventoryComplete {
			t.Fatal("event inventory unavailable")
		}
		productionEvents = append([]model.SecurityEventInfo(nil), snap.EventByPod["ns/serve"]...)
		return *snap.PodByKey["ns/serve"]
	}
	first := snapshot()
	if first.SuspectAdapter != "actual" || first.AdapterObservation == nil || !hasAdapterFact(&model.WorkloadView{Pod: first}) {
		t.Fatalf("trusted event absent from production snapshot: %+v", first)
	}
	view := &model.WorkloadView{Pod: first, Events: productionEvents, Phase: model.PhaseWarm, Physics: model.NeutralPhysics(), ExposureByVariable: map[string]time.Duration{model.VarAdapterEpoch: time.Hour}}
	pol := model.Policy{Tenant: "tenant", Namespace: "ns", DryRun: true, TraceEnabled: true, MaxMovesPerTick: 1,
		NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, Lambda: 0.1,
		AssetWeightFromLabels: func(map[string]string) float64 { return 1 },
		ProactiveFloor:        time.Hour, AntiOverRotationWindow: time.Minute, EnabledActions: map[model.Action]bool{model.ActionAdapterRotate: true}}
	engine := decision.NewCoverageEngine()
	profile, ok := recon.Registry.Get("ucw-recon")
	if !ok {
		t.Fatal("ucw-recon missing")
	}
	engine.Recon = profile
	ds := engine.Decide([]*model.WorkloadView{view}, pol)
	if len(ds) != 1 || ds[0].Trace == nil || ds[0].AdapterObservation == nil {
		t.Fatalf("observation absent from decision: %+v", ds)
	}
	var adapterTrace *model.VectorSteeringAttribution
	for _, f := range ds[0].Trace.Facts {
		if f.FactType == recon.FactAdapterIntegrity {
			adapterTrace = f.SteeredBy
		}
	}
	if adapterTrace == nil || len(adapterTrace.Events) != 1 || adapterTrace.Events[0].EventUID != "event-1" || adapterTrace.Events[0].TargetPodUID != "pod-1" || adapterTrace.Events[0].AdapterName != "actual" {
		t.Fatalf("serialized fact lost detector binding: %+v facts=%+v absent=%q phold=%v asset=%v view=%+v", adapterTrace, ds[0].Trace.Facts, ds[0].Trace.Inputs.FactsAbsentReason, ds[0].PHold, ds[0].AssetValue, view.Pod)
	}
	encoded, err := json.Marshal(ds[0])
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.Decision
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.AdapterObservation == nil || decoded.AdapterObservation.EventUID != "event-1" {
		t.Fatalf("decision wire lost observation: %s", encoded)
	}
	recordWire, err := json.Marshal(audit.ToRecord(ds[0]))
	if err != nil {
		t.Fatal(err)
	}
	var record audit.Record
	if err := json.Unmarshal(recordWire, &record); err != nil {
		t.Fatal(err)
	}
	if record.AdapterObservation == nil || record.AdapterObservation.EventUID != "event-1" {
		t.Fatalf("audit record lost observation: %s", recordWire)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	pod.UID = "pod-2"
	if err := c.Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	recreated := snapshot()
	if recreated.AdapterObservation != nil || hasAdapterFact(&model.WorkloadView{Pod: recreated}) {
		t.Fatal("recreated Pod inherited event identity")
	}
	if err := c.Delete(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	pod.UID = "pod-1"
	if err := c.Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	removed := snapshot()
	if removed.AdapterObservation != nil || hasAdapterFact(&model.WorkloadView{Pod: removed}) {
		t.Fatal("removed detector event left fact in refreshed snapshot")
	}
}
