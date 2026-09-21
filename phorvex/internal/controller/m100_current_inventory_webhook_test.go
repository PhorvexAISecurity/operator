package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/currentinventory"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func m100CurrentPayload(t *testing.T) string {
	t.Helper()
	now := time.Unix(100, 0).UTC()
	sum := sha256.Sum256([]byte("v2"))
	p := model.CurrentInventoryV1{SchemaVersion: model.CurrentInventorySchemaV1, EvidenceID: "current-v2", PolicyEpoch: model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1}, DecisionAsset: model.DecisionAssetIdentity{Namespace: "ns", Name: "pod", TargetUID: "pod-uid"}, ImmediateController: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: "ns", Name: "rs", UID: "rs-uid"}, StableWorkloadOwner: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ns", Name: "app", UID: "dep-uid"}, ProtectedScope: model.ProtectedScope{Tenant: "tenant", Asset: "synthetic", Version: "v2", Property: "confidentiality"}, SourceBinding: model.CurrentInventorySourceBinding{ConfigMap: model.ObjectIdentity{APIVersion: "v1", Kind: "ConfigMap", Namespace: "ns", Name: "data", UID: "cm-uid"}, ResourceVersion: "7", Key: "payload", VolumeName: "data", ContainerName: "server", MountPath: "/data", ProjectedPath: "payload", Bytes: 2, SHA256: hex.EncodeToString(sum[:])}, Classification: model.CurrentInventoryClassification{RuleVersion: model.CurrentInventoryRuleVersionV1, RuleDigest: strings.Repeat("b", 64), InventoryClass: model.CurrentInventoryClass, PossibleOutcome: "unauthorized-disclosure", ObserverIdentity: "system:serviceaccount:ns:current-observer"}, Observation: model.CurrentInventoryObservation{StartedAt: now, CompletedAt: now.Add(time.Second), ValidUntil: now.Add(time.Minute), StatusCode: 200, ManifestEOF: true}, Synthetic: true}
	raw, _, err := currentinventory.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func m100CurrentAdmission(t *testing.T, op admissionv1.Operation, user, payload, oldPayload string, mutate func(*amtdv1beta1.SecurityEvent)) admission.Response {
	t.Helper()
	event := &amtdv1beta1.SecurityEvent{TypeMeta: metav1.TypeMeta{APIVersion: "amtd.r6security.com/v1beta1", Kind: "SecurityEvent"}, ObjectMeta: metav1.ObjectMeta{Name: "event", Annotations: map[string]string{currentinventory.Annotation: payload}}, Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"ns/pod"}, Description: model.CurrentInventoryDescription, Rule: amtdv1beta1.Rule{Type: model.CurrentInventoryRuleType, ThreatLevel: "high", Source: model.CurrentInventorySource}}}
	var old runtime.RawExtension
	if oldPayload != "" {
		oldEvent := event.DeepCopy()
		oldEvent.Annotations[currentinventory.Annotation] = oldPayload
		oldEvent.Annotations[currentinventory.AdmissionTimeAnnotation] = time.Unix(102, 500_000_000).UTC().Format(time.RFC3339Nano)
		oldEvent.Annotations[currentinventory.AdmissionContractAnnotation] = currentinventory.BoundaryContract
		oldEvent.Annotations[ingest.CreatorIdentityAnnotation] = "system:serviceaccount:ns:current-observer"
		old.Raw, _ = json.Marshal(oldEvent)
	}
	if mutate != nil {
		mutate(event)
	}
	raw, _ := json.Marshal(event)
	yes := true
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: "tenant"}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: "dep-uid"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "app", UID: "dep-uid", Controller: &yes}}}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "data", UID: "cm-uid", ResourceVersion: "7"}, Data: map[string]string{"payload": "v2"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: types.UID("rs-uid"), Controller: &yes}}}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "data"}}}}}, Containers: []corev1.Container{{Name: "server", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data", ReadOnly: true}}}}}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(policy, dep, rs, cm, pod).Build()
	return (SecurityEventStamper{Reader: reader, Now: func() time.Time { return time.Unix(102, 500_000_000).UTC() }}).Handle(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: op, UserInfo: authenticationv1.UserInfo{Username: user}, Object: runtime.RawExtension{Raw: raw}, OldObject: old}})
}

func TestM100CurrentInventoryAdmissionIsIndependentCurrentAndImmutable(t *testing.T) {
	observer := "system:serviceaccount:ns:current-observer"
	ingest.ConfigureCurrentInventoryTrust(ingest.NewTrustedDetectors([]string{observer}))
	t.Cleanup(func() { ingest.ConfigureCurrentInventoryTrust(ingest.NewTrustedDetectors(nil)) })
	payload := m100CurrentPayload(t)
	if r := m100CurrentAdmission(t, admissionv1.Create, observer, payload, "", nil); !r.Allowed {
		t.Fatalf("valid current inventory denied: %+v", r.Result)
	}
	if r := m100CurrentAdmission(t, admissionv1.Create, "system:serviceaccount:ns:loss-observer", payload, "", nil); r.Allowed {
		t.Fatal("loss observer inherited current inventory authority")
	}
	if r := m100CurrentAdmission(t, admissionv1.Create, observer, strings.Replace(payload, `"resourceVersion":"7"`, `"resourceVersion":"8"`, 1), "", nil); r.Allowed {
		t.Fatal("stale ConfigMap resourceVersion admitted")
	}
	for name, replacement := range map[string][2]string{
		"stale pod UID":           {`"targetUID":"pod-uid"`, `"targetUID":"other-pod"`},
		"wrong immediate owner":   {`"uid":"rs-uid"`, `"uid":"other-rs"`},
		"wrong stable owner":      {`"uid":"dep-uid"`, `"uid":"other-dep"`},
		"wrong ConfigMap UID":     {`"uid":"cm-uid"`, `"uid":"other-cm"`},
		"stale policy generation": {`"generation":1`, `"generation":2`},
		"tenant mismatch":         {`"tenant":"tenant"`, `"tenant":"other"`},
	} {
		if r := m100CurrentAdmission(t, admissionv1.Create, observer, strings.Replace(payload, replacement[0], replacement[1], 1), "", nil); r.Allowed {
			t.Fatalf("%s admitted", name)
		}
	}
	if r := m100CurrentAdmission(t, admissionv1.Create, observer, payload, "", func(e *amtdv1beta1.SecurityEvent) { e.Spec.Rule.Source = "self-asserted" }); r.Allowed {
		t.Fatal("forged source admitted")
	}
	expired, _, _, err := currentinventory.Parse(payload)
	if err != nil {
		t.Fatal(err)
	}
	expired.Observation.ValidUntil = time.Unix(102, 0).UTC()
	expiredRaw, _, err := currentinventory.Marshal(expired)
	if err != nil {
		t.Fatal(err)
	}
	if r := m100CurrentAdmission(t, admissionv1.Create, observer, expiredRaw, "", nil); r.Allowed {
		t.Fatal("expired current observation admitted")
	}
	if r := m100CurrentAdmission(t, admissionv1.Update, observer, payload, payload, func(e *amtdv1beta1.SecurityEvent) { delete(e.Annotations, currentinventory.Annotation) }); r.Allowed {
		t.Fatal("current inventory removal admitted")
	}
}
