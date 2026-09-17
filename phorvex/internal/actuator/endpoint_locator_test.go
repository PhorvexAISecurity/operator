package actuator

import (
	"context"
	"reflect"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Local API-object counterexample, not a live DNS/HTTP or EndpointSlice observation.
// The real handler can emit while the same Service identity still selects the same pod.
func TestEndpointRotateRetainsServiceLocator(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelRouteKey: "ep-old", "app": "infer"})
	pod.Annotations[annoRouteService] = "infer-svc"
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "infer-svc", UID: "uid-infer-svc", ResourceVersion: "9"}, Spec: corev1.ServiceSpec{ClusterIP: "10.0.0.10", Selector: map[string]string{"app": "infer", labelRouteKey: "ep-old"}, Ports: []corev1.ServicePort{{Port: 80}}}}
	before := svc.DeepCopy()
	if !labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(pod.Labels)) {
		t.Fatal("fixture Service does not select target")
	}
	c := fakeC(pod, svc)
	result, err := (endpointRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c}, Request{Namespace: "ns", Pod: "infer", TargetUID: string(pod.UID), Action: model.ActionEndpointRotate})
	if err != nil || !result.Emitted {
		t.Fatalf("handler=%+v err=%v", result, err)
	}
	var after corev1.Service
	var target corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(svc), &after); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), &target); err != nil {
		t.Fatal(err)
	}
	if target.Labels[labelRouteKey] == "ep-old" {
		t.Fatal("real handler did not re-key")
	}
	if after.Name != before.Name || after.Namespace != before.Namespace || after.Spec.ClusterIP != before.Spec.ClusterIP || !reflect.DeepEqual(after.Spec.Ports, before.Spec.Ports) {
		t.Fatal("Service locator fields changed")
	}
	if !labels.SelectorFromSet(after.Spec.Selector).Matches(labels.Set(target.Labels)) {
		t.Fatal("post-handler Service does not select same target")
	}
	t.Logf("emitted=%v locator=infer-svc.ns.svc:80 ClusterIP=%s selector=%v -> %v still selects target", result.Emitted, after.Spec.ClusterIP, before.Spec.Selector, after.Spec.Selector)
}
