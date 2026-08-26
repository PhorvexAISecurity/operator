package actuator

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

func routePod(ns, name string, ready bool) *corev1.Pod {
	pod := aiPod(ns, name, map[string]string{"app": "web", labelRouteKey: "route-old"})
	pod.Annotations[annoRouteService] = "web-route"
	if !ready {
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	}
	return pod
}

func routeService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-route"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web", labelRouteKey: "route-old"}},
	}
}

func TestRouteRotateRestitchesServiceAndRollbackRestoresBoth(t *testing.T) {
	target := routePod("ns", "target", true)
	sibling := routePod("ns", "sibling", true)
	svc := routeService()
	originalLabels := copyLabels(target.Labels)
	originalSelector := copyLabels(svc.Spec.Selector)
	c := fakeC(target, sibling, svc)
	ec := EnactCtx{Client: c}
	req := Request{Namespace: "ns", Pod: "target", Action: model.ActionRouteRotate}

	result, err := (routeRotateHandler{}).Enact(context.Background(), ec, req)
	if err != nil {
		t.Fatalf("route-rotate: %v", err)
	}
	if !result.Emitted || result.MutationKind != "reversible" {
		t.Fatalf("route-rotate result = %+v, want emitted reversible mutation", result)
	}

	var gotPod corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "target"}, &gotPod); err != nil {
		t.Fatal(err)
	}
	var gotService corev1.Service
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "web-route"}, &gotService); err != nil {
		t.Fatal(err)
	}
	newKey := gotPod.Labels[labelRouteKey]
	if newKey == "" || newKey == "route-old" {
		t.Fatalf("pod route-key = %q, want a fresh key", newKey)
	}
	if gotService.Spec.Selector[labelRouteKey] != newKey {
		t.Fatalf("Service route-key = %q, want pod key %q", gotService.Spec.Selector[labelRouteKey], newKey)
	}

	if err := (routeRotateHandler{}).Rollback(context.Background(), ec, req, result.RollbackRef); err != nil {
		t.Fatalf("route-rotate rollback: %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "target"}, &gotPod); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "web-route"}, &gotService); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotPod.Labels, originalLabels) {
		t.Errorf("rollback pod labels = %v, want %v", gotPod.Labels, originalLabels)
	}
	if !reflect.DeepEqual(gotService.Spec.Selector, originalSelector) {
		t.Errorf("rollback Service selector = %v, want %v", gotService.Spec.Selector, originalSelector)
	}
	if gotPod.Annotations[routeSnapAnno] != "" {
		t.Error("rollback left the route snapshot annotation behind")
	}
}

func TestRouteRotateWithoutServiceAnnotationEmitsNothing(t *testing.T) {
	pod := routePod("ns", "target", true)
	delete(pod.Annotations, annoRouteService)
	original := pod.DeepCopy()
	c := fakeC(pod)

	result, err := (routeRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c}, Request{
		Namespace: "ns", Pod: "target", Action: model.ActionRouteRotate,
	})
	if err != nil {
		t.Fatalf("route-rotate without annotation: %v", err)
	}
	if result.Emitted || result.MutationKind != "none" {
		t.Fatalf("result = %+v, want non-emitted none", result)
	}
	var got corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "target"}, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Labels, original.Labels) || got.Annotations[routeSnapAnno] != "" {
		t.Fatalf("annotation-free path mutated pod: labels=%v annotations=%v", got.Labels, got.Annotations)
	}
}

func TestRouteRotateRefusesSingleReadyBackend(t *testing.T) {
	target := routePod("ns", "target", true)
	unreadySibling := routePod("ns", "sibling", false)
	c := fakeC(target, unreadySibling, routeService())

	result, err := (routeRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c}, Request{
		Namespace: "ns", Pod: "target", Action: model.ActionRouteRotate,
	})
	if err == nil || !strings.Contains(err.Error(), "exactly one Ready backend") {
		t.Fatalf("single-backend result = %+v, err=%v; want refusal", result, err)
	}
	var got corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "target"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Labels[labelRouteKey] != "route-old" || got.Annotations[routeSnapAnno] != "" {
		t.Fatalf("refused route-rotate mutated pod: labels=%v annotations=%v", got.Labels, got.Annotations)
	}
}

type failServiceUpdateClient struct{ client.Client }

func (c failServiceUpdateClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if _, ok := obj.(*corev1.Service); ok {
		return errors.New("injected Service update failure")
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestRouteRotateCompensatesWhenServiceUpdateFails(t *testing.T) {
	target := routePod("ns", "target", true)
	sibling := routePod("ns", "sibling", true)
	base := fakeC(target, sibling, routeService())
	c := failServiceUpdateClient{Client: base}

	result, err := (routeRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c}, Request{
		Namespace: "ns", Pod: "target", Action: model.ActionRouteRotate,
	})
	if err == nil || result.Emitted {
		t.Fatalf("failed restitch result = %+v, err=%v; want failure without credit", result, err)
	}
	var got corev1.Pod
	if err := base.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "target"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Labels[labelRouteKey] != "route-old" || got.Annotations[routeSnapAnno] != "" {
		t.Fatalf("failed restitch left half-applied pod mutation: labels=%v annotations=%v", got.Labels, got.Annotations)
	}
}

func TestIdentityRotateMakesNoCredentialOrPodIdentityClaim(t *testing.T) {
	pod := aiPod("ns", "target", map[string]string{"app": "web"})
	pod.Spec.ServiceAccountName = "workload-sa"
	c := fakeC(pod)
	result, err := (identityRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c}, Request{
		Namespace: "ns", Pod: "target", Action: model.ActionIdentityRotate,
	})
	if err != nil {
		t.Fatal(err)
	}
	note := strings.ToLower(result.Note)
	if strings.Contains(note, "re-issue") || strings.Contains(note, "stale the attacker's identity") {
		t.Fatalf("identity-rotate still claims an effect it does not perform: %q", result.Note)
	}
	for _, unchanged := range []string{"token", "uid", "ip"} {
		if !strings.Contains(note, unchanged+" unchanged") && !strings.Contains(note, "token, pod uid and pod ip unchanged") {
			t.Errorf("identity-rotate note does not disclose unchanged %s: %q", unchanged, result.Note)
		}
	}
}
