package controller

import (
	"context"
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

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/disclosure"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func m100Payload(t *testing.T) string {
	t.Helper()
	now := time.Unix(100, 0).UTC()
	digest := strings.Repeat("a", 64)
	p := model.CompletedDisclosureV1{SchemaVersion: model.CompletedDisclosureSchemaV1, EvidenceID: "evidence",
		PolicyEpoch:         model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1},
		DecisionAsset:       model.DecisionAssetIdentity{Namespace: "ns", Name: "pod", TargetUID: "pod-uid"},
		ImmediateController: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: "ns", Name: "rs", UID: "rs-uid"},
		StableWorkloadOwner: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ns", Name: "app", UID: "dep-uid"},
		ProtectedScope:      model.ProtectedScope{Tenant: "tenant", Asset: "synthetic", Version: "v1", Property: "confidentiality"},
		Classification: model.DisclosureClassification{RuleVersion: "rule-v1", RuleDigest: digest,
			ObserverClass: model.CompletedDisclosureClass, ObserverIdentity: "system:serviceaccount:ns:loss-observer"},
		Observation: model.DisclosureObservation{StartedAt: now, CompletedAt: now.Add(time.Second), StatusCode: 200, ExpectedBytes: 1, ObservedBytes: 1, ReachedEOF: true, ExpectedSHA256: digest, ObservedSHA256: digest}, Synthetic: true}
	raw, _, err := disclosure.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func m100Admission(t *testing.T, op admissionv1.Operation, user, payload string, mutate func(*amtdv1beta1.SecurityEvent), oldPayload string) admission.Response {
	t.Helper()
	event := &amtdv1beta1.SecurityEvent{TypeMeta: metav1.TypeMeta{APIVersion: "amtd.r6security.com/v1beta1", Kind: "SecurityEvent"},
		ObjectMeta: metav1.ObjectMeta{Name: "event", Annotations: map[string]string{disclosure.Annotation: payload}},
		Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"ns/pod"}, Description: model.CompletedDisclosureDescription,
			Rule: amtdv1beta1.Rule{Type: model.CompletedDisclosureRuleType, ThreatLevel: "high", Source: model.CompletedDisclosureSource}}}
	var old runtime.RawExtension
	if oldPayload != "" {
		oldEvent := event.DeepCopy()
		oldEvent.Annotations[disclosure.Annotation] = oldPayload
		oldEvent.Annotations[disclosure.AdmissionTimeAnnotation] = time.Unix(102, 500_000_000).UTC().Format(time.RFC3339Nano)
		oldEvent.Annotations[disclosure.AdmissionContractAnnotation] = disclosure.BoundaryContract
		oldEvent.Annotations[ingest.CreatorIdentityAnnotation] = "system:serviceaccount:ns:loss-observer"
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
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Tenant: "tenant"}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "app", UID: "dep-uid"}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs", UID: "rs-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "app", UID: "dep-uid", Controller: &yes}}}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod", UID: "pod-uid", OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: types.UID("rs-uid"), Controller: &yes}}}},
	).Build()
	stamper := SecurityEventStamper{Reader: reader, Now: func() time.Time { return time.Unix(102, 500_000_000).UTC() }}
	return stamper.Handle(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: op, UserInfo: authenticationv1.UserInfo{Username: user}, Object: runtime.RawExtension{Raw: raw}, OldObject: old,
	}})
}

func TestM100DisclosureAdmissionIsDedicatedFailClosedAndImmutable(t *testing.T) {
	observer := "system:serviceaccount:ns:loss-observer"
	ingest.ConfigureCompletedDisclosureTrust(ingest.NewTrustedDetectors([]string{observer}))
	t.Cleanup(func() { ingest.ConfigureCompletedDisclosureTrust(ingest.NewTrustedDetectors(nil)) })
	payload := m100Payload(t)
	if resp := m100Admission(t, admissionv1.Create, observer, payload, nil, ""); !resp.Allowed {
		t.Fatalf("valid observation denied: %+v", resp.Result)
	}
	if resp := m100Admission(t, admissionv1.Create, canaryUser, payload, nil, ""); resp.Allowed {
		t.Fatal("generally trusted detector acquired completed-loss authority")
	}
	otherObserver := "system:serviceaccount:ns:other-observer"
	ingest.ConfigureCompletedDisclosureTrust(ingest.NewTrustedDetectors([]string{observer, otherObserver}))
	if resp := m100Admission(t, admissionv1.Create, otherObserver, payload, nil, ""); resp.Allowed {
		t.Fatal("allowed creator substituted payload observer identity")
	}
	if resp := m100Admission(t, admissionv1.Create, observer, payload, func(e *amtdv1beta1.SecurityEvent) { e.Spec.Rule.Type = "Panic" }, ""); resp.Allowed {
		t.Fatal("wrong rule admitted")
	}
	if resp := m100Admission(t, admissionv1.Create, observer, payload, func(e *amtdv1beta1.SecurityEvent) { e.Spec.Targets[0] = "ns/other" }, ""); resp.Allowed {
		t.Fatal("wrong target admitted")
	}
	if resp := m100Admission(t, admissionv1.Create, observer, strings.Replace(payload, "dep-uid", "other-dep", 1), nil, ""); resp.Allowed {
		t.Fatal("stale stable owner admitted")
	}
	if resp := m100Admission(t, admissionv1.Create, observer, strings.Replace(payload, `"generation":1`, `"generation":2`, 1), nil, ""); resp.Allowed {
		t.Fatal("stale policy epoch admitted")
	}
	if resp := m100Admission(t, admissionv1.Update, observer, strings.Replace(payload, "evidence", "changed", 1), nil, payload); resp.Allowed {
		t.Fatal("changed evidence update admitted")
	}
	if resp := m100Admission(t, admissionv1.Update, canaryUser, payload, nil, payload); resp.Allowed {
		t.Fatal("unrelated full-resource updater retained the original observer authority")
	}
	if resp := m100Admission(t, admissionv1.Update, observer, payload, func(e *amtdv1beta1.SecurityEvent) {
		delete(e.Annotations, disclosure.Annotation)
	}, payload); resp.Allowed {
		t.Fatal("completed disclosure removal admitted")
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(payload), &doc)
	doc["body"] = "secret"
	unknown, _ := json.Marshal(doc)
	if resp := m100Admission(t, admissionv1.Create, observer, string(unknown), nil, ""); resp.Allowed {
		t.Fatal("unknown body field admitted")
	}
}
