package actuator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/crmrefund"
	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type crmRecordedClient struct {
	client.Client
	writes []client.ObjectKey
}

func (c *crmRecordedClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.writes = append(c.writes, client.ObjectKeyFromObject(obj))
	return c.Client.Update(ctx, obj, opts...)
}

type crmReadbackTransport func(*http.Request) (*http.Response, error)

func (f crmReadbackTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func crmRevokeFixture(t *testing.T, namespace string) (*crmRecordedClient, Request, EnactCtx) {
	t.Helper()
	labels := map[string]string{"app": "crm", crmrefund.StagingFixtureLabel: crmrefund.StagingFixtureValue}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: crmrefund.ServiceName, Namespace: namespace, UID: "svc-uid", Labels: labels},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "crm"}, Ports: []corev1.ServicePort{{Port: 8080, TargetPort: intstr.FromInt(8080)}}}}
	guard := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: crmrefund.GuardConfigMapName, Namespace: namespace, UID: "guard-uid", Labels: labels},
		Data: map[string]string{crmrefund.GuardKey: `{"denied_order_ids":[]}`}}
	objects := []client.Object{svc, guard}
	ready := true
	endpoints := []discoveryv1.Endpoint{}
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
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "crm-defense", Namespace: namespace, UID: "policy-uid", Generation: 1},
		Spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "crm"}},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionCRMRefundRevoke)}}}}
	now := time.Now().UTC().Truncate(time.Second)
	obs := crmrefund.Observation{Version: 1, OrderID: "OR-5002", OrderAccountID: "AC-1002", CallerAccountID: "AC-1001", GuardConfigMapUID: "guard-uid", ServiceUID: "svc-uid",
		TargetPodUID: "crm-a-uid", PeerPodUID: "crm-b-uid", Objective: "ai2-cross-record-refund", ObservedAt: now, PolicyName: "crm-defense", PolicyUID: "policy-uid", PolicyGeneration: 1}
	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: "crm-event", UID: "event-uid", CreationTimestamp: metav1.NewTime(now),
		Annotations: map[string]string{"phorvex.ai/creator-identity": eventtrust.Injector(), model.ConsoleTargetPodUIDAnnotation: obs.TargetPodUID, crmrefund.ObservationAnnotation: string(raw)}},
		Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{namespace + "/crm-a"}, Rule: amtdv1beta1.Rule{Type: crmrefund.RuleType, Source: "redteam"}}}
	objects = append(objects, policy, event)
	if namespace != crmrefund.Namespace {
		objects = append(objects, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: crmrefund.GuardConfigMapName, Namespace: crmrefund.Namespace, UID: "legacy-guard"},
			Data: map[string]string{crmrefund.GuardKey: `{"denied_order_ids":[]}`}})
	}
	c := &crmRecordedClient{Client: fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objects...).Build()}
	req := Request{Action: model.ActionCRMRefundRevoke, Namespace: namespace, Pod: "crm-a", TargetUID: obs.TargetPodUID, PolicyName: obs.PolicyName,
		PolicyUID: obs.PolicyUID, PolicyGeneration: obs.PolicyGeneration, OperationID: "refund-op-1", CRMRefundObservation: &model.CRMRefundObservation{
			EventName: event.Name, EventUID: string(event.UID), CreatorIdentity: eventtrust.Injector(), OrderID: obs.OrderID, OrderAccountID: obs.OrderAccountID,
			CallerAccountID: obs.CallerAccountID, GuardConfigMapUID: obs.GuardConfigMapUID, ServiceUID: obs.ServiceUID, TargetPodUID: obs.TargetPodUID,
			PeerPodUID: obs.PeerPodUID, PolicyName: obs.PolicyName, PolicyUID: obs.PolicyUID, PolicyGeneration: obs.PolicyGeneration, ObservedAt: now}}
	ec := EnactCtx{Client: c, Reader: c, CRMRefundTransport: crmReadbackTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/phorvex-guard/state" || (r.URL.Host != "10.0.0.1:8080" && r.URL.Host != "10.0.0.2:8080") {
			t.Fatalf("unexpected guard readback: %s", r.URL)
		}
		current := &corev1.ConfigMap{}
		if err := c.Get(r.Context(), client.ObjectKey{Namespace: namespace, Name: crmrefund.GuardConfigMapName}, current); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(current.Data[crmrefund.GuardKey]))}, nil
	})}
	return c, req, ec
}

func TestCRMRefundRevokeNamespaceCASAndLegacyBoundary(t *testing.T) {
	for _, namespace := range []string{crmrefund.Namespace, crmrefund.StagingNamespace} {
		t.Run(namespace, func(t *testing.T) {
			t.Setenv(crmrefund.NamespaceEnv, crmrefund.StagingNamespace)
			c, req, ec := crmRevokeFixture(t, namespace)
			ctx := context.Background()
			if ok, why := crmRefundCapability(ctx, c, Target{Namespace: namespace, Pod: req.Pod, UID: req.TargetUID}); !ok {
				t.Fatalf("valid fixture unavailable: %s", why)
			}
			got, err := (crmRefundRevokeHandler{}).Enact(ctx, ec, req)
			if err != nil || !got.Emitted || len(c.writes) != 1 || c.writes[0] != (client.ObjectKey{Namespace: namespace, Name: crmrefund.GuardConfigMapName}) {
				t.Fatalf("revoke: result=%+v err=%v writes=%v", got, err, c.writes)
			}
			if _, err := (crmRefundRevokeHandler{}).Enact(ctx, ec, req); err != nil || len(c.writes) != 1 {
				t.Fatalf("reconcile rewrote guard: err=%v writes=%v", err, c.writes)
			}
			req.OperationID = "unrelated-operation"
			if _, err := (crmRefundRevokeHandler{}).Enact(ctx, ec, req); err == nil || len(c.writes) != 1 {
				t.Fatal("different operation claimed or rewrote the existing revoke")
			}
			if namespace == crmrefund.StagingNamespace {
				legacy := &corev1.ConfigMap{}
				if err := c.Get(ctx, client.ObjectKey{Namespace: crmrefund.Namespace, Name: crmrefund.GuardConfigMapName}, legacy); err != nil {
					t.Fatal(err)
				}
				if legacy.Data[crmrefund.StateKey] != "" || legacy.Data[crmrefund.GuardKey] != `{"denied_order_ids":[]}` {
					t.Fatal("staging revoke changed legacy guard")
				}
			}
		})
	}
}

func TestCRMRefundStagingRequiresNamespaceAndExactEventAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, configured string
		mutate           func(*testing.T, *crmRecordedClient, *Request)
	}{
		{name: "disabled"},
		{name: "invalid-configuration", configured: "other"},
		{name: "arbitrary-namespace", configured: crmrefund.StagingNamespace, mutate: func(_ *testing.T, _ *crmRecordedClient, req *Request) { req.Namespace = "other" }},
		{name: "stale", configured: crmrefund.StagingNamespace, mutate: func(_ *testing.T, _ *crmRecordedClient, req *Request) {
			req.CRMRefundObservation.ObservedAt = time.Now().Add(-time.Minute)
		}},
		{name: "wrong-event-namespace", configured: crmrefund.StagingNamespace, mutate: func(t *testing.T, c *crmRecordedClient, _ *Request) {
			event := &amtdv1beta1.SecurityEvent{}
			if err := c.Get(context.Background(), client.ObjectKey{Name: "crm-event"}, event); err != nil {
				t.Fatal(err)
			}
			event.Spec.Targets = []string{"crm/crm-a"}
			if err := c.Update(context.Background(), event); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "policy-epoch", configured: crmrefund.StagingNamespace, mutate: func(_ *testing.T, _ *crmRecordedClient, req *Request) {
			req.PolicyGeneration++
			req.CRMRefundObservation.PolicyGeneration++
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(crmrefund.NamespaceEnv, tc.configured)
			c, req, ec := crmRevokeFixture(t, crmrefund.StagingNamespace)
			if tc.mutate != nil {
				tc.mutate(t, c, &req)
			}
			c.writes = nil
			if _, err := (crmRefundRevokeHandler{}).Enact(context.Background(), ec, req); err == nil || len(c.writes) != 0 {
				t.Fatalf("unbound revoke accepted or wrote: err=%v writes=%v", err, c.writes)
			}
		})
	}
}
