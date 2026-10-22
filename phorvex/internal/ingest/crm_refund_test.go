package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/crmrefund"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
)

func crmIngestFixture(t *testing.T, namespace string) (client.Client, model.Pod, model.SecurityEventInfo) {
	t.Helper()
	labels := map[string]string{"app": "crm", crmrefund.StagingFixtureLabel: crmrefund.StagingFixtureValue}
	objects := []client.Object{
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: crmrefund.ServiceName, Namespace: namespace, UID: "svc-uid", Labels: labels},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "crm"}, Ports: []corev1.ServicePort{{Port: 8080, TargetPort: intstr.FromInt(8080)}}}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: crmrefund.GuardConfigMapName, Namespace: namespace, UID: "guard-uid", Labels: labels},
			Data: map[string]string{crmrefund.GuardKey: `{"denied_order_ids":[]}`}},
		&v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "crm-defense", Namespace: namespace, UID: "policy-uid", Generation: 1},
			Spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "crm"}}}},
	}
	ready := true
	var endpoints []discoveryv1.Endpoint
	for i, name := range []string{"crm-a", "crm-b"} {
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID(name + "-uid"), Labels: labels},
			Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "guard", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: crmrefund.GuardConfigMapName}}}}},
				Containers: []corev1.Container{{Name: "crm", VolumeMounts: []corev1.VolumeMount{{Name: "guard", MountPath: crmrefund.GuardMountPath, ReadOnly: true}}}}},
			Status: corev1.PodStatus{PodIP: []string{"10.0.0.1", "10.0.0.2"}[i], ContainerStatuses: []corev1.ContainerStatus{{Name: "crm", Ready: true}}}}
		objects = append(objects, pod)
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{pod.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: namespace, Name: name, UID: pod.UID}})
	}
	objects = append(objects, &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "crm-slice", Namespace: namespace, Labels: map[string]string{discoveryv1.LabelServiceName: crmrefund.ServiceName}}, Endpoints: endpoints})
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	now := time.Now().UTC().Truncate(time.Second)
	obs := crmrefund.Observation{Version: 1, OrderID: "OR-5002", OrderAccountID: "AC-1002", CallerAccountID: "AC-1001", GuardConfigMapUID: "guard-uid", ServiceUID: "svc-uid",
		TargetPodUID: "crm-a-uid", PeerPodUID: "crm-b-uid", Objective: "ai2-cross-record-refund", ObservedAt: now, PolicyName: "crm-defense", PolicyUID: "policy-uid", PolicyGeneration: 1}
	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	pod := model.Pod{Namespace: namespace, Name: "crm-a", UID: obs.TargetPodUID}
	event := model.SecurityEventInfo{CreatedAt: now, Trust: eventtrust.TrustTrusted, TargetsPod: true, Type: crmrefund.RuleType, Source: "redteam",
		CreatorIdentity: eventtrust.Injector(), Name: "crm-event", UID: "event-uid", ConsoleTargetPodUID: pod.UID, CRMRefundRaw: string(raw)}
	return c, pod, event
}

func TestCRMRefundIngestNamespaceAndTrustedObservation(t *testing.T) {
	for _, tc := range []struct {
		name, namespace, configured string
		mutate                      func(*model.SecurityEventInfo)
		want                        bool
	}{
		{name: "legacy-default", namespace: crmrefund.Namespace, want: true},
		{name: "staging-default-off", namespace: crmrefund.StagingNamespace},
		{name: "staging-explicit", namespace: crmrefund.StagingNamespace, configured: crmrefund.StagingNamespace, want: true},
		{name: "arbitrary-namespace", namespace: "other", configured: crmrefund.StagingNamespace},
		{name: "staging-untrusted", namespace: crmrefund.StagingNamespace, configured: crmrefund.StagingNamespace,
			mutate: func(e *model.SecurityEventInfo) { e.Trust = eventtrust.TrustUntrusted }},
		{name: "staging-stale", namespace: crmrefund.StagingNamespace, configured: crmrefund.StagingNamespace,
			mutate: func(e *model.SecurityEventInfo) { e.Age = time.Minute }},
		{name: "staging-wrong-target", namespace: crmrefund.StagingNamespace, configured: crmrefund.StagingNamespace,
			mutate: func(e *model.SecurityEventInfo) { e.ConsoleTargetPodUID = "different-pod" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(crmrefund.NamespaceEnv, tc.configured)
			c, pod, event := crmIngestFixture(t, tc.namespace)
			if tc.mutate != nil {
				tc.mutate(&event)
			}
			bindCRMRefundObservation(context.Background(), c, &pod, []model.SecurityEventInfo{event})
			if (pod.CRMRefundObservation != nil) != tc.want {
				t.Fatalf("bound=%v want=%v", pod.CRMRefundObservation != nil, tc.want)
			}
			if tc.want {
				bindCRMRefundObservation(context.Background(), c, &pod, []model.SecurityEventInfo{event, event})
				if pod.CRMRefundObservation != nil {
					t.Fatal("competing observations retained authority")
				}
			}
		})
	}
}
