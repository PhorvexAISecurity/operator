package ingest

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/phorvex/phorvex/internal/model"
)

func m103Bool(value bool) *bool { return &value }

func m103ServiceSlice(ownerUID types.UID, endpoints ...discoveryv1.Endpoint) discoveryv1.EndpointSlice {
	controller := true
	return discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "serving-1", UID: "slice-uid", Labels: map[string]string{discoveryv1.LabelServiceName: "serving"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: "serving", UID: ownerUID, Controller: &controller}}}, AddressType: discoveryv1.AddressTypeIPv4, Endpoints: endpoints}
}

func m103Endpoint(name, uid string, ready bool) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: m103Bool(ready)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "ns", Name: name, UID: types.UID(uid)}}
}

func TestM103ServiceAvailabilityUsesExactReadyEndpointMembership(t *testing.T) {
	pods := []model.Pod{
		{Namespace: "ns", Name: "a", UID: "pod-a", Labels: map[string]string{"app": "x"}, Ready: true, ControllerUID: "controller-uid"},
		{Namespace: "ns", Name: "b", UID: "pod-b", Labels: map[string]string{"app": "x"}, Ready: true, ControllerUID: "controller-uid"},
		// Selector matches, but this Pod is not a Ready EndpointSlice member and
		// therefore does not consume this Service's current availability scope.
		{Namespace: "ns", Name: "not-routed", UID: "pod-c", Labels: map[string]string{"app": "x"}, Ready: true, ControllerUID: "controller-uid"},
	}
	services := []ServiceInfo{{Namespace: "ns", Name: "serving", UID: "service-uid", Selector: map[string]string{"app": "x"}}}
	slices := []discoveryv1.EndpointSlice{m103ServiceSlice("service-uid", m103Endpoint("a", "pod-a", true), m103Endpoint("b", "pod-b", true))}
	bindServiceAvailability(pods, services, slices, true)
	for i := 0; i < 2; i++ {
		if !pods[i].ServiceAvailabilityKnown || len(pods[i].ServiceAvailability) != 1 {
			t.Fatalf("ready member %s lacks exact Service observation: %+v", pods[i].Name, pods[i])
		}
		got := pods[i].ServiceAvailability[0]
		if !got.Complete || !got.TargetReady || got.ReadyMembers != 2 || got.Scope.ServiceUID != "service-uid" || got.Scope.ControllerUID != "controller-uid" {
			t.Fatalf("ready member observation = %+v", got)
		}
	}
	if len(pods[2].ServiceAvailability) != 0 {
		t.Fatalf("selector-only Pod was treated as a routed member: %+v", pods[2].ServiceAvailability)
	}
}

func TestM103ServiceAvailabilityFailsClosedOnOwnerOrControllerAmbiguity(t *testing.T) {
	base := []model.Pod{
		{Namespace: "ns", Name: "a", UID: "pod-a", Labels: map[string]string{"app": "x"}, Ready: true, ControllerUID: "controller-a"},
		{Namespace: "ns", Name: "b", UID: "pod-b", Labels: map[string]string{"app": "x"}, Ready: true, ControllerUID: "controller-b"},
	}
	services := []ServiceInfo{{Namespace: "ns", Name: "serving", UID: "service-uid", Selector: map[string]string{"app": "x"}}}
	slices := []discoveryv1.EndpointSlice{m103ServiceSlice("service-uid", m103Endpoint("a", "pod-a", true), m103Endpoint("b", "pod-b", true))}
	bindServiceAvailability(base, services, slices, true)
	for _, pod := range base {
		if len(pod.ServiceAvailability) != 1 || pod.ServiceAvailability[0].Complete || pod.ServiceAvailability[0].Reason != "service-ready-members-do-not-have-one-controller-uid" {
			t.Fatalf("multi-controller Service did not fail closed: %+v", pod.ServiceAvailability)
		}
	}

	badOwner := []model.Pod{{Namespace: "ns", Name: "a", UID: "pod-a", Labels: map[string]string{"app": "x"}, Ready: true, ControllerUID: "controller-a"}}
	wrong := []discoveryv1.EndpointSlice{m103ServiceSlice("replacement-service-uid", m103Endpoint("a", "pod-a", true))}
	bindServiceAvailability(badOwner, services, wrong, true)
	if len(badOwner[0].ServiceAvailability) != 1 || badOwner[0].ServiceAvailability[0].Complete || badOwner[0].ServiceAvailability[0].Reason != "endpointslice-service-identity-mismatch" {
		t.Fatalf("wrong Service owner UID did not fail closed: %+v", badOwner[0].ServiceAvailability)
	}

	unknown := []model.Pod{{Namespace: "ns", Name: "a", UID: "pod-a"}}
	bindServiceAvailability(unknown, nil, nil, false)
	if unknown[0].ServiceAvailabilityKnown || unknown[0].ServiceAvailabilityReason == "" {
		t.Fatalf("failed inventory was represented as known: %+v", unknown[0])
	}
}
