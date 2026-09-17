package actuator

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

// Local API-object control for locator fields. The KCM test establishes real
// controller-owned EndpointSlice membership; this control isolates fields the
// route engine must never rewrite.
func TestEndpointRotateRetainsServiceLocator(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
	svc := &corev1.Service{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), svc); err != nil {
		t.Fatal(err)
	}
	svc.Spec.ClusterIP = "10.0.0.10"
	svc.Spec.Ports = []corev1.ServicePort{{Port: 80}}
	if err := f.client.Client.Update(f.ctx, svc); err != nil {
		t.Fatal(err)
	}
	before := svc.DeepCopy()
	result, err := f.native.Actuate(f.ctx, f.request)
	if err != nil || !result.Emitted {
		t.Fatalf("handler=%+v err=%v", result, err)
	}
	after, target := &corev1.Service{}, &corev1.Pod{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(svc), after); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), target); err != nil {
		t.Fatal(err)
	}
	if after.Name != before.Name || after.Namespace != before.Namespace || after.Spec.ClusterIP != before.Spec.ClusterIP || !reflect.DeepEqual(after.Spec.Ports, before.Spec.Ports) {
		t.Fatal("Service locator fields changed")
	}
	if !labels.SelectorFromSet(after.Spec.Selector).Matches(labels.Set(target.Labels)) {
		t.Fatal("post-handler Service does not select same target")
	}
}
