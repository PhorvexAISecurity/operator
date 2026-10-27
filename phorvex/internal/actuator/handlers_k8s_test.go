package actuator

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

func TestRouteRotateRestitchesServiceAndRollbackRestoresBoth(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	result, err := f.native.Actuate(f.ctx, f.request)
	if err != nil || !result.Emitted || result.RollbackRef == "" {
		t.Fatalf("route-rotate result=%+v err=%v", result, err)
	}
	if err := f.native.Rollback(f.ctx, f.request, result.RollbackRef); err != nil {
		t.Fatal(err)
	}
}

func TestRouteRotateWithoutServiceAnnotationEmitsNothing(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	pod := &corev1.Pod{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
		t.Fatal(err)
	}
	delete(pod.Annotations, annoRouteService)
	if err := f.client.Client.Update(f.ctx, pod); err != nil {
		t.Fatal(err)
	}
	result, err := f.native.Actuate(f.ctx, f.request)
	if !IsNoEffectRefusal(err) || result.Emitted || f.client.podPatches != 0 || f.client.serviceUpdates != 0 {
		t.Fatalf("missing declaration result=%+v err=%v", result, err)
	}
}

func TestM033RouteRotateRefusesMismatchedServiceSelector(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 1)
	svc := &corev1.Service{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), svc); err != nil {
		t.Fatal(err)
	}
	svc.Spec.Selector[labelRouteKey] = "different"
	if err := f.client.Client.Update(f.ctx, svc); err != nil {
		t.Fatal(err)
	}
	result, err := f.native.Actuate(f.ctx, f.request)
	if !IsNoEffectRefusal(err) || result.Emitted || f.client.podPatches != 0 {
		t.Fatalf("mismatched selector result=%+v err=%v", result, err)
	}
}

func TestRouteRotateRefusesFloorTwoBeforeMutation(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionRouteRotate, 2)
	result, err := f.native.Actuate(f.ctx, f.request)
	if !IsNoEffectRefusal(err) || result.Emitted || f.client.podPatches != 0 || f.client.serviceUpdates != 0 {
		t.Fatalf("floor refusal result=%+v err=%v", result, err)
	}
}

func TestIdentityRotateUnsupportedProfileRefusesWithoutWrites(t *testing.T) {
	// With no validated dedicated-SA external-theft observation on the request, the handler
	// refuses before any mutation (the unsupported reason), and touches neither the Pod nor
	// its ServiceAccount — only an admitted observation + exact policy epoch authorizes a rotation.
	pod := aiPod("ns", "target", map[string]string{"app": "web"})
	pod.Spec.ServiceAccountName = "workload-sa"
	c := fakeC(pod)
	result, err := (identityRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c}, Request{
		Namespace: "ns", Pod: "target", Action: model.ActionIdentityRotate,
	})
	if err == nil || result.Emitted || !strings.Contains(err.Error(), model.IdentityRotateUnsupportedReason) {
		t.Fatalf("identity handler result=%+v err=%v, want unsupported refusal", result, err)
	}
	var got corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "target"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Spec.ServiceAccountName != "workload-sa" {
		t.Fatalf("identity refusal changed pod: %+v", got)
	}
}
