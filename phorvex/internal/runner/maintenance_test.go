package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

func TestIdleNativeTickRecoversWithoutDecisionSnapshot(t *testing.T) {
	ctx := context.Background()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme, networkingv1.AddToScheme, appsv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatal(err)
		}
	}
	var drainPosts atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"fixture"}]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/drain":
			drainPosts.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"aborted":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(backend.Close)
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	old := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "old", UID: "old-uid", ResourceVersion: "7", CreationTimestamp: metav1.NewTime(time.Unix(1, 0)), Labels: map[string]string{"phorvex.ai/swap-group": "g", "phorvex.ai/role": "leader"}}, Status: corev1.PodStatus{PodIP: host, PodIPs: []corev1.PodIP{{IP: host}}, Conditions: ready}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "serve", Image: "fixture"}}}}
	shadow := old.DeepCopy()
	shadow.Name, shadow.UID, shadow.Labels["phorvex.ai/role"], shadow.Labels["phorvex.ai/model-loaded"] = "new", "new-uid", "warm-shadow", "true"
	for _, p := range []*corev1.Pod{old, shadow} {
		p.Labels["app"] = "pool"
		p.Annotations = map[string]string{"phorvex.ai/route-service": "pool", "phorvex.ai/model-id": "fixture", "phorvex.ai/serving-port": portText}
	}
	controller := true
	owner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "pool", UID: "pool-uid", Controller: &controller}
	old.OwnerReferences, shadow.OwnerReferences = []metav1.OwnerReference{owner}, []metav1.OwnerReference{owner}
	replicas := int32(2)
	templateLabels := map[string]string{"app": "pool", "phorvex.ai/swap-group": "g", "phorvex.ai/role": "warm-shadow", "phorvex.ai/model-loaded": "false"}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pool", UID: "pool-uid", Generation: 1}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "pool", "phorvex.ai/swap-group": "g"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: templateLabels, Annotations: map[string]string{"phorvex.ai/route-service": "pool", "phorvex.ai/model-id": "fixture", "phorvex.ai/serving-port": portText}}, Spec: old.Spec}}, Status: appsv1.ReplicaSetStatus{ObservedGeneration: 1, Replicas: 2}}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pool", UID: "service-uid"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "pool", "phorvex.ai/swap-group": "g", "phorvex.ai/role": "leader"}, Ports: []corev1.ServicePort{{Port: int32(port)}}}}
	endpointReady := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pool-1", UID: "slice-uid", Labels: map[string]string{discoveryv1.LabelServiceName: service.Name}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(service, corev1.SchemeGroupVersion.WithKind("Service"))}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{host}, Conditions: discoveryv1.EndpointConditions{Ready: &endpointReady}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: old.Name, UID: old.UID}}}}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"phorvex.ai/swap-group": "g"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionWarmSwap)}}}}
	failPhase := true
	var deletedUID types.UID
	syncRoute := func(ctx context.Context, c client.Client) error {
		var pods corev1.PodList
		if err := c.List(ctx, &pods, client.InNamespace("ns"), client.MatchingLabels{"app": "pool", "phorvex.ai/swap-group": "g"}); err != nil {
			return err
		}
		current := &discoveryv1.EndpointSlice{}
		if err := c.Get(ctx, client.ObjectKeyFromObject(slice), current); err != nil {
			return err
		}
		current.Endpoints = nil
		for i := range pods.Items {
			pod := &pods.Items[i]
			if pod.Labels["phorvex.ai/role"] != "leader" || pod.DeletionTimestamp != nil {
				continue
			}
			current.Endpoints = append(current.Endpoints, discoveryv1.Endpoint{Addresses: []string{pod.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &endpointReady}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}})
		}
		return c.Update(ctx, current)
	}
	base := fake.NewClientBuilder().WithScheme(s).WithObjects(old, shadow, rs, service, slice, pol, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if obj.GetUID() == "" {
				obj.SetUID(types.UID("created-" + obj.GetName()))
			}
			return c.Create(ctx, obj, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if _, ok := obj.(*corev1.ConfigMap); ok && failPhase {
				failPhase = false
				return errors.New("post-promotion journal outage")
			}
			if err := c.Update(ctx, obj, opts...); err != nil {
				return err
			}
			if _, ok := obj.(*corev1.Pod); ok {
				return syncRoute(ctx, c)
			}
			return nil
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := c.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
			if _, ok := obj.(*corev1.Pod); ok {
				return syncRoute(ctx, c)
			}
			return nil
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if err := c.Delete(ctx, obj, opts...); err != nil {
				return err
			}
			p, ok := obj.(*corev1.Pod)
			if !ok || p.UID != old.UID {
				return nil
			}
			deletedUID = p.UID
			replacement := shadow.DeepCopy()
			replacement.Name, replacement.UID, replacement.ResourceVersion = "controller-new", "controller-new-uid", ""
			replacement.Labels["phorvex.ai/model-loaded"] = "true"
			if err := c.Create(ctx, replacement); err != nil {
				return err
			}
			return syncRoute(ctx, c)
		},
	}).Build()
	native := actuator.NewNativeActuator(base)
	native.Reader, native.JournalNamespace = base, "operator"
	legacy, _ := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "operator")
	native.SetServingSecurity(legacy)
	if _, err := native.Actuate(ctx, actuator.Request{Namespace: "ns", Pod: "old", TargetUID: "old-uid", Action: model.ActionWarmSwap, PolicyName: "policy", PolicyUID: "policy-uid"}); err == nil || failPhase {
		t.Fatal("producer did not interrupt after promotion")
	}
	var journals corev1.ConfigMapList
	if err := base.List(ctx, &journals, client.InNamespace("operator"), client.MatchingLabels{"phorvex.ai/operation-journal": "v1"}); err != nil || len(journals.Items) != 1 {
		t.Fatalf("producer interruption did not retain one receipt: count=%d err=%v", len(journals.Items), err)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(journals.Items[0].Data["receipt"]), &raw); err != nil || raw["version"] != float64(10) || raw["phase"] != "prepared" || raw["newEndpointConfigSHA256"] == "" {
		t.Fatalf("producer interruption retained wrong receipt: raw=%v err=%v", raw, err)
	}
	receiptBytes := journals.Items[0].Data["receipt"]
	if drainPosts.Load() != 0 {
		t.Fatalf("post-promotion producer interruption reached drain backend: posts=%d", drainPosts.Load())
	}
	phoenix, err := NewManagerWithBackend(base, logr.Discard(), actuator.BackendResolution{Backend: actuator.BackendPhoenix})
	if err != nil {
		t.Fatal(err)
	}
	phoenix.Calibration = nil
	phoenix.KillSwitch.Namespace = "operator"
	if result := phoenix.tick(ctx); result != tickNoSnapshot {
		t.Fatalf("Phoenix idle tick status: %v", result)
	}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "old"}, &corev1.Pod{}); err != nil {
		t.Fatalf("Phoenix backend ran native retirement: %v", err)
	}
	if err := base.List(ctx, &journals, client.InNamespace("operator"), client.MatchingLabels{"phorvex.ai/operation-journal": "v1"}); err != nil || len(journals.Items) != 1 || journals.Items[0].Data["receipt"] != receiptBytes {
		t.Fatalf("Phoenix idle tick changed protected receipt: count=%d err=%v", len(journals.Items), err)
	}
	promoted := &corev1.Pod{}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "new"}, promoted); err != nil || promoted.UID != shadow.UID || promoted.Labels["phorvex.ai/role"] != "leader" {
		t.Fatalf("Phoenix idle tick changed promoted survivor: %v %+v", err, promoted)
	}
	m, err := NewManagerWithBackend(base, logr.Discard(), actuator.BackendResolution{Backend: actuator.BackendNative})
	if err != nil {
		t.Fatal(err)
	}
	m.Actuator = native
	m.Calibration = nil
	m.KillSwitch.Namespace = "operator"
	m.Client = interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if _, ok := list.(*corev1.PodList); ok {
			return errors.New("decision Pod inventory read forbidden on idle tick")
		}
		return c.List(ctx, list, opts...)
	}})
	if result := m.tick(ctx); result != tickNoSnapshot {
		t.Fatalf("idle maintenance needed expensive decision snapshot: %v", result)
	}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "old"}, &corev1.Pod{}); err == nil {
		t.Fatal("idle tick did not retire recorded old Pod")
	}
	if deletedUID != old.UID || drainPosts.Load() != 1 {
		t.Fatalf("idle recovery effects: deletedUID=%s want=%s drainPosts=%d", deletedUID, old.UID, drainPosts.Load())
	}
	newPod := &corev1.Pod{}
	if err := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "new"}, newPod); err != nil || newPod.Labels["phorvex.ai/role"] != "leader" {
		t.Fatalf("recorded survivor lost: %v %+v", err, newPod.Labels)
	}
	replacement := &corev1.Pod{}
	replacementReady := false
	replacementErr := base.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "controller-new"}, replacement)
	if replacementErr == nil {
		for _, condition := range replacement.Status.Conditions {
			replacementReady = replacementReady || condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue
		}
	}
	if replacementErr != nil || replacement.UID != "controller-new-uid" || replacement.Labels["phorvex.ai/role"] != "warm-shadow" || replacement.Labels["phorvex.ai/model-loaded"] != "true" || !replacementReady {
		t.Fatalf("controller replenishment changed: %v uid=%s labels=%v ready=%t", replacementErr, replacement.UID, replacement.Labels, replacementReady)
	}
	if err := base.List(ctx, &journals, client.InNamespace("operator"), client.MatchingLabels{"phorvex.ai/operation-journal": "v1"}); err != nil || len(journals.Items) != 0 {
		t.Fatalf("completed idle recovery retained receipt: count=%d err=%v", len(journals.Items), err)
	}
}
