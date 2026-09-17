package actuator

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type m35RouteAuthorityReader struct {
	client.Reader
	err      error
	clearUID bool
	clearRV  bool
}

func (r m35RouteAuthorityReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Service); ok && r.err != nil {
		return r.err
	}
	if err := r.Reader.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if svc, ok := obj.(*corev1.Service); ok {
		if r.clearUID {
			svc.UID = ""
		}
		if r.clearRV {
			svc.ResourceVersion = ""
		}
	}
	return nil
}

type m35RouteReadbackReader struct {
	client.Reader
	writes *routeUnitClient
	fired  bool
}

func (r *m35RouteReadbackReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Pod); ok && r.writes.podPatches > 0 && !r.fired {
		r.fired = true
		return apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, key.Name, errors.New("readback denied"))
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func TestM035EndpointRotateRefusesInvalidAuthorityBeforeWrite(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*routeUnitFixture) error
	}{
		{name: "missing-target-uid", mutate: func(f *routeUnitFixture) error { f.request.TargetUID = ""; return nil }},
		{name: "mismatched-target-uid", mutate: func(f *routeUnitFixture) error { f.request.TargetUID = "replacement"; return nil }},
		{name: "missing-policy", mutate: func(f *routeUnitFixture) error { f.request.PolicyName = ""; return nil }},
		{name: "missing-operation", mutate: func(f *routeUnitFixture) error { f.request.OperationID = ""; return nil }},
		{name: "missing-journal", mutate: func(f *routeUnitFixture) error { f.native.JournalNamespace = ""; return nil }},
		{name: "missing-reader", mutate: func(f *routeUnitFixture) error { f.native.Reader = nil; return nil }},
		{name: "missing-writer", mutate: func(f *routeUnitFixture) error { f.native.Client = nil; return nil }},
		{name: "missing-service", mutate: func(f *routeUnitFixture) error { return f.client.Client.Delete(f.ctx, f.service) }},
		{name: "missing-route-key", mutate: func(f *routeUnitFixture) error {
			svc := &corev1.Service{}
			if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), svc); err != nil {
				return err
			}
			delete(svc.Spec.Selector, labelRouteKey)
			return f.client.Client.Update(f.ctx, svc)
		}},
		{name: "wrong-endpointslice-owner", mutate: func(f *routeUnitFixture) error {
			slice := &discoveryv1.EndpointSlice{}
			if err := f.client.Get(f.ctx, client.ObjectKey{Namespace: f.pod.Namespace, Name: f.service.Name + "-slice"}, slice); err != nil {
				return err
			}
			slice.OwnerReferences[0].UID = "replacement"
			return f.client.Client.Update(f.ctx, slice)
		}},
		{name: "multi-service-collision", mutate: func(f *routeUnitFixture) error {
			extra := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: f.service.Namespace, Name: "other"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "route"}}}
			return f.client.Client.Create(f.ctx, extra)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
			if err := tc.mutate(&f); err != nil {
				t.Fatal(err)
			}
			result, err := f.native.Actuate(f.ctx, f.request)
			if !IsNoEffectRefusal(err) || result.Emitted || f.client.podPatches != 0 || f.client.serviceUpdates != 0 {
				t.Fatalf("result=%+v err=%v patches=%d updates=%d", result, err, f.client.podPatches, f.client.serviceUpdates)
			}
		})
	}
}

func TestM035EndpointRotateRetainsOriginalAuthorityAndReadbackControls(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reader func(client.Reader) client.Reader
	}{
		{name: "unreadable-service", reader: func(r client.Reader) client.Reader {
			return m35RouteAuthorityReader{Reader: r, err: apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "route", errors.New("denied"))}
		}},
		{name: "missing-service-uid", reader: func(r client.Reader) client.Reader { return m35RouteAuthorityReader{Reader: r, clearUID: true} }},
		{name: "missing-service-resource-version", reader: func(r client.Reader) client.Reader { return m35RouteAuthorityReader{Reader: r, clearRV: true} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
			f.native.Reader = tc.reader(f.client)
			result, err := f.native.Actuate(f.ctx, f.request)
			if !IsNoEffectRefusal(err) || result.Emitted || f.client.podPatches != 0 || f.client.serviceUpdates != 0 {
				t.Fatalf("authority result=%+v err=%v patches=%d updates=%d", result, err, f.client.podPatches, f.client.serviceUpdates)
			}
		})
	}

	t.Run("accepted-Pod-write-readback-denied", func(t *testing.T) {
		f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
		reader := &m35RouteReadbackReader{Reader: f.client, writes: f.client}
		f.native.Reader = reader
		result, err := f.native.Actuate(f.ctx, f.request)
		if err == nil || IsNoEffectRefusal(err) || !result.Emitted || result.MutationKind != "partial" || !reader.fired {
			t.Fatalf("readback result=%+v err=%v fired=%t", result, err, reader.fired)
		}
	})

	t.Run("Service-conflict-after-Pod-write", func(t *testing.T) {
		f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
		f.client.failServiceAt = 1
		result, err := f.native.Actuate(f.ctx, f.request)
		if err == nil || IsNoEffectRefusal(err) || !result.Emitted || result.MutationKind != "partial" || f.client.podPatches == 0 {
			t.Fatalf("Service conflict result=%+v err=%v", result, err)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Pod)
	}{
		{name: "route-service-declaration-changed", mutate: func(p *corev1.Pod) { p.Annotations[annoRouteService] = "replacement" }},
		{name: "unrelated-selected-label-changed", mutate: func(p *corev1.Pod) { p.Labels["app"] = "replacement" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
			f.client.afterPodPatch = func(ctx context.Context, c *routeUnitClient, _ *corev1.Pod) {
				if c.podPatches != 1 {
					return
				}
				stored := &corev1.Pod{}
				if err := c.Client.Get(ctx, client.ObjectKeyFromObject(f.pod), stored); err != nil {
					t.Fatal(err)
				}
				tc.mutate(stored)
				if err := c.Client.Update(ctx, stored); err != nil {
					t.Fatal(err)
				}
			}
			result, err := f.native.Actuate(f.ctx, f.request)
			if err == nil || IsNoEffectRefusal(err) || !result.Emitted || result.MutationKind != "partial" {
				t.Fatalf("changed postcondition result=%+v err=%v", result, err)
			}
		})
	}

	t.Run("foreign-Service-selector-change-is-never-overwritten", func(t *testing.T) {
		f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
		f.client.afterServiceUpdate = func(ctx context.Context, c *routeUnitClient, _ *corev1.Service) {
			if c.serviceUpdates != 2 {
				return
			}
			stored := &corev1.Service{}
			if err := c.Client.Get(ctx, client.ObjectKeyFromObject(f.service), stored); err != nil {
				t.Fatal(err)
			}
			delete(stored.Spec.Selector, "foreign-selector")
			stored.Spec.Selector["replacement"] = ""
			if err := c.Client.Update(ctx, stored); err != nil {
				t.Fatal(err)
			}
		}
		result, err := f.native.Actuate(f.ctx, f.request)
		if err == nil || IsNoEffectRefusal(err) || !result.Emitted || result.MutationKind != "partial" {
			t.Fatalf("selector race result=%+v err=%v", result, err)
		}
		stored := &corev1.Service{}
		if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), stored); err != nil {
			t.Fatal(err)
		}
		if _, present := stored.Spec.Selector["foreign-selector"]; present || stored.Spec.Selector["replacement"] != "" || !strings.Contains(result.Note, "retained") {
			t.Fatalf("foreign selector mutation overwritten or unreported: selector=%v result=%+v", stored.Spec.Selector, result)
		}
	})
}

func TestM035EndpointRotateWriteFailureAfterIntentRemainsPartial(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
	f.client.failPodPatchAt = 1
	result, err := f.native.Actuate(f.ctx, f.request)
	if err == nil || IsNoEffectRefusal(err) || result.Emitted || result.MutationKind != "partial" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	var journals corev1.ConfigMapList
	if listErr := f.client.List(f.ctx, &journals, client.InNamespace("route-operator")); listErr != nil || len(journals.Items) != 2 {
		t.Fatalf("protected lock pair not retained: %d err=%v", len(journals.Items), listErr)
	}
}

func TestM035EndpointRotateEmptySelectorValuePresenceIsExact(t *testing.T) {
	f := newRouteUnitFixture(t, model.ActionEndpointRotate, 1)
	pod := &corev1.Pod{}
	svc := &corev1.Service{}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.pod), pod); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Get(f.ctx, client.ObjectKeyFromObject(f.service), svc); err != nil {
		t.Fatal(err)
	}
	pod.Labels[labelRouteKey] = ""
	svc.Spec.Selector[labelRouteKey] = ""
	if err := f.client.Client.Update(f.ctx, pod); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Client.Update(f.ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := f.client.reconcile(f.ctx, svc.Namespace, svc.Name); err != nil {
		t.Fatal(err)
	}
	result, err := f.native.Actuate(f.ctx, f.request)
	if err != nil || !result.Emitted {
		t.Fatalf("present-empty route key should remain supported: result=%+v err=%v", result, err)
	}
}
