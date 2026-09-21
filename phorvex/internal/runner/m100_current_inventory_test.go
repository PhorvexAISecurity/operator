package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/currentinventory"
	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/losshistory"
	"github.com/phorvex/phorvex/internal/model"
)

func m100CurrentRecord(now time.Time, scope model.ProtectedScope) model.AdmittedCurrentInventory {
	sum := sha256.Sum256([]byte("v2"))
	inv := model.CurrentInventoryV1{SchemaVersion: model.CurrentInventorySchemaV1, EvidenceID: "current-v2", PolicyEpoch: model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 2}, DecisionAsset: model.DecisionAssetIdentity{Namespace: "ns", Name: "new-pod", TargetUID: "new-uid"}, ImmediateController: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: "ns", Name: "rs", UID: "rs-uid"}, StableWorkloadOwner: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ns", Name: "app", UID: "dep-uid"}, ProtectedScope: scope, SourceBinding: model.CurrentInventorySourceBinding{ConfigMap: model.ObjectIdentity{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "data", UID: "cm-uid"}, ResourceVersion: "7", Key: "payload", VolumeName: "data", ContainerName: "server", MountPath: "/data", ProjectedPath: "payload", Bytes: 2, SHA256: hex.EncodeToString(sum[:])}, Classification: model.CurrentInventoryClassification{RuleVersion: model.CurrentInventoryRuleVersionV1, RuleDigest: strings.Repeat("b", 64), InventoryClass: model.CurrentInventoryClass, PossibleOutcome: "unauthorized-disclosure", ObserverIdentity: "observer"}, Observation: model.CurrentInventoryObservation{StartedAt: now, CompletedAt: now.Add(time.Second), ValidUntil: now.Add(time.Minute), StatusCode: 200, ManifestEOF: true}, Synthetic: true}
	_, digest, _ := currentinventory.Marshal(inv)
	return model.AdmittedCurrentInventory{SchemaVersion: model.AdmittedCurrentInventorySchemaV1, Inventory: inv, CanonicalPayloadSHA256: digest, SecurityEvent: model.SecurityEventIdentity{Name: "event", UID: "event-uid", CreationTimestamp: now.Add(2 * time.Second)}, AdmissionTime: now.Add(2500 * time.Millisecond), AuthenticatedCreator: "observer", TrustBoundary: model.DisclosureTrustBoundary{ConfigurationUID: "webhook-uid", ConfigurationResourceVersion: "7", ActivationTime: now.Add(-time.Minute), ContractVersion: currentinventory.BoundaryContract}, IngestedAt: now.Add(3 * time.Second)}
}

func m100ResealCurrentRecord(t *testing.T, record model.AdmittedCurrentInventory) model.AdmittedCurrentInventory {
	t.Helper()
	_, digest, err := currentinventory.Marshal(record.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	record.CanonicalPayloadSHA256 = digest
	return record
}

func TestM100CurrentInventoryHistoryGuardAndExactLossTransition(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	scope := model.ProtectedScope{Tenant: "tenant", Asset: "synthetic/customer-row", Version: "data-v2", Property: "confidentiality"}
	record := m100CurrentRecord(now, scope)
	lossPayload, lossEvent := m100PayloadAndEvent(t, now)
	_, lossDigest, err := disclosure.Marshal(lossPayload)
	if err != nil {
		t.Fatal(err)
	}
	loss := model.AdmittedLossV1{SchemaVersion: model.AdmittedLossSchemaV1, Disclosure: lossPayload, CanonicalPayloadSHA256: lossDigest, SecurityEvent: model.SecurityEventIdentity{Name: lossEvent.Name, UID: lossEvent.UID, CreationTimestamp: lossEvent.CreatedAt}, AdmissionTime: lossEvent.CreatedAt.Add(250 * time.Millisecond), AuthenticatedCreator: lossEvent.CreatorIdentity, TrustBoundary: model.DisclosureTrustBoundary{ConfigurationUID: "webhook-uid", ConfigurationResourceVersion: "7", ActivationTime: now.Add(-time.Minute), ContractVersion: disclosure.BoundaryContract}, IngestedAt: now}
	base := representationHistoryInput{owner: record.Inventory.StableWorkloadOwner, result: losshistory.Result{Status: "available", Records: []model.AdmittedLossV1{loss}}, current: currentinventory.Result{Status: "available", Records: []model.AdmittedCurrentInventory{record}}}
	p := model.Policy{Tenant: "tenant", TickID: "tick", PolicyUID: "policy-uid", PolicyGeneration: 2}
	d := model.Decision{Namespace: "ns", Pod: "new-pod"}
	report := representationSnapshotV1(d, p, "new-uid", model.ClaimScope{}, nil, base)
	built := report
	appendRepresentation(&d, built)
	if d.Representation == nil || d.Representation.CoverageShare.KnownAtRisk != 1 || d.Representation.KnownLossCount != 1 || d.Representation.FactStates[0].CurrentInventory == nil {
		t.Fatalf("available current fact = %#v", d.Representation)
	}
	tampered := built
	tampered.Facts[0].CurrentInventory.PolicyGeneration++
	d.Representation = nil
	appendRepresentation(&d, tampered)
	if d.Representation.CoverageShare.KnownAtRisk != 0 || d.Representation.CoverageShare.KnownUnknown != 1 || d.Representation.FactStates[0].Reason != "current-inventory-provenance-invalid" {
		t.Fatalf("mismatched current generation became at-risk: %#v", d.Representation)
	}
	empty := base
	empty.result.Records = nil
	d.Representation = nil
	appendRepresentation(&d, representationSnapshotV1(d, p, "new-uid", model.ClaimScope{}, nil, empty))
	if d.Representation.KnownLossCount != 0 || d.Representation.CoverageShare.KnownAtRisk != 1 {
		t.Fatalf("available empty bounded history = %#v", d.Representation)
	}
	blocked := base
	blocked.result.Status = "unavailable"
	blocked.result.Gaps = []string{"retained-loss-history-read-timeout"}
	d.Representation = nil
	appendRepresentation(&d, representationSnapshotV1(d, p, "new-uid", model.ClaimScope{}, nil, blocked))
	if d.Representation.CoverageShare.KnownAtRisk != 0 || d.Representation.CoverageShare.KnownUnknown != 1 || d.Representation.FactStates[0].Reason != "completed-loss-history-unavailable" {
		t.Fatalf("history outage = %#v", d.Representation)
	}
	completedV2 := loss
	completedV2.Disclosure.EvidenceID = "copy-v2"
	completedV2.Disclosure.ProtectedScope = scope
	completedV2.SecurityEvent.Name = "loss-v2"
	completedV2.SecurityEvent.UID = "loss-v2-uid"
	_, completedV2.CanonicalPayloadSHA256, err = disclosure.Marshal(completedV2.Disclosure)
	if err != nil {
		t.Fatal(err)
	}
	base.result.Records = append(base.result.Records, completedV2)
	d.Representation = nil
	appendRepresentation(&d, representationSnapshotV1(d, p, "new-uid", model.ClaimScope{}, nil, base))
	if d.Representation.KnownLossCount != 2 || d.Representation.CoverageShare.KnownAtRisk != 0 {
		t.Fatalf("completed v2 transition = %#v", d.Representation)
	}
}

func TestM100CurrentInventoryRevalidatesPodOwnerAndConfigMapSource(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	scope := model.ProtectedScope{Tenant: "tenant", Asset: "synthetic/customer-row", Version: "data-v2", Property: "confidentiality"}
	record := m100CurrentRecord(now, scope)
	yes := true
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: types.UID("dep-uid")}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs", UID: types.UID("rs-uid"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "app", UID: dep.UID, Controller: &yes}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "new-pod", UID: types.UID("new-uid"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: rs.UID, Controller: &yes}}}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "data"}}}}}, Containers: []corev1.Container{{Name: "server", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data", ReadOnly: true}}}}}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "data", UID: types.UID("cm-uid"), ResourceVersion: "7"}, Data: map[string]string{"payload": "v2"}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs, pod, cm).Build()
	current := currentinventory.NewStore()
	if err := current.Put(record); err != nil {
		t.Fatal(err)
	}
	history, err := losshistory.New(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	p := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 2}
	decisions := []model.Decision{{Namespace: "ns", Pod: "new-pod"}}
	versions := map[string]string{"ns/new-pod": "new-uid"}
	got := representationHistoryInputsWithStores(context.Background(), reader, history, current, decisions, versions, p, nil, now.Add(4*time.Second))["ns/new-pod"]
	if len(got.current.Records) != 1 {
		t.Fatalf("current source not joined: %#v", got)
	}
	var changed corev1.ConfigMap
	if err := reader.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "data"}, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Data["payload"] = "v3"
	if err := reader.Update(context.Background(), &changed); err != nil {
		t.Fatal(err)
	}
	got = representationHistoryInputsWithStores(context.Background(), reader, history, current, decisions, versions, p, nil, now.Add(5*time.Second))["ns/new-pod"]
	if len(got.current.Records) != 0 || len(got.currentUnknown) != 1 {
		t.Fatalf("source drift remained current: %#v", got)
	}
	p.PolicyGeneration = 3
	got = representationHistoryInputsWithStores(context.Background(), reader, history, current, decisions, versions, p, nil, now.Add(5*time.Second))["ns/new-pod"]
	if len(got.current.Records) != 0 {
		t.Fatalf("policy generation drift remained current: %#v", got)
	}
}

func TestM100CurrentInventoryIsolatesSiblingReplicasAndRetainsSameNameStaleness(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	scope := model.ProtectedScope{Tenant: "tenant", Asset: "synthetic/customer-row", Version: "data-v2", Property: "confidentiality"}
	first := m100CurrentRecord(now, scope)
	second := first
	second.Inventory.EvidenceID = "current-v2-sibling"
	second.Inventory.DecisionAsset.Name = "sibling-pod"
	second.Inventory.DecisionAsset.TargetUID = "sibling-uid"
	second.SecurityEvent.Name = "event-sibling"
	second.SecurityEvent.UID = "event-sibling-uid"
	second = m100ResealCurrentRecord(t, second)

	yes := true
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: types.UID("dep-uid")}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs", UID: types.UID("rs-uid"), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "app", UID: dep.UID, Controller: &yes}}}}
	newPod := func(name, uid string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, UID: types.UID(uid), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: rs.UID, Controller: &yes}}}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "data"}}}}}, Containers: []corev1.Container{{Name: "server", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data", ReadOnly: true}}}}}}
	}
	firstPod := newPod("new-pod", "new-uid")
	siblingPod := newPod("sibling-pod", "sibling-uid")
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "data", UID: types.UID("cm-uid"), ResourceVersion: "7"}, Data: map[string]string{"payload": "v2"}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(dep, rs, firstPod, siblingPod, cm).Build()
	current := currentinventory.NewStore()
	if err := current.Put(first); err != nil {
		t.Fatal(err)
	}
	if err := current.Put(second); err != nil {
		t.Fatal(err)
	}
	history, err := losshistory.New(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatal(err)
	}
	p := model.Policy{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 2}
	decisions := []model.Decision{{Namespace: "ns", Pod: "new-pod"}, {Namespace: "ns", Pod: "sibling-pod"}}
	versions := map[string]string{"ns/new-pod": "new-uid", "ns/sibling-pod": "sibling-uid"}
	got := representationHistoryInputsWithStores(context.Background(), reader, history, current, decisions, versions, p, nil, now.Add(4*time.Second))
	for key, wantEvidence := range map[string]string{"ns/new-pod": "current-v2", "ns/sibling-pod": "current-v2-sibling"} {
		entry := got[key]
		if len(entry.current.Records) != 1 || entry.current.Records[0].Inventory.EvidenceID != wantEvidence || len(entry.currentUnknown) != 0 || len(entry.gaps) != 0 {
			t.Fatalf("sibling isolation for %s = %#v", key, entry)
		}
	}
	additional := first
	additional.Inventory.EvidenceID = "current-v2-a"
	additional.Inventory.ProtectedScope.Asset = "synthetic/a"
	additional.SecurityEvent.Name = "event-a"
	additional.SecurityEvent.UID = "event-a-uid"
	additional = m100ResealCurrentRecord(t, additional)
	if err := current.Put(additional); err != nil {
		t.Fatal(err)
	}
	var frozen model.RepresentationSnapshot
	for i := 0; i < 32; i++ {
		currentResult := representationHistoryInputsWithStores(context.Background(), reader, history, current, decisions[:1], versions, p, nil, now.Add(4*time.Second))["ns/new-pod"]
		if len(currentResult.current.Records) != 2 || currentResult.current.Records[0].Inventory.EvidenceID != "current-v2-a" || currentResult.current.Records[1].Inventory.EvidenceID != "current-v2" {
			t.Fatalf("current record order is not canonical: %#v", currentResult.current.Records)
		}
		snapshot := representationSnapshotV1(decisions[0], p, versions["ns/new-pod"], model.ClaimScope{}, nil, currentResult)
		if i == 0 {
			frozen = snapshot
		} else if !reflect.DeepEqual(snapshot, frozen) {
			t.Fatalf("representation output changed across identical current inventory reads: first=%#v next=%#v", frozen, snapshot)
		}
	}

	if err := reader.Delete(context.Background(), firstPod); err != nil {
		t.Fatal(err)
	}
	replacement := newPod("new-pod", "replacement-uid")
	if err := reader.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	versions["ns/new-pod"] = "replacement-uid"
	got = representationHistoryInputsWithStores(context.Background(), reader, history, current, decisions[:1], versions, p, nil, now.Add(5*time.Second))
	stale := got["ns/new-pod"]
	if len(stale.current.Records) != 0 || len(stale.currentUnknown) != 2 || stale.currentUnknown[0].Reason != "current-inventory-current-binding-mismatch" || stale.currentUnknown[1].Reason != "current-inventory-current-binding-mismatch" {
		t.Fatalf("same-name replacement did not retain stale current evidence as unknown: %#v", stale)
	}
}
