package actuator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type m35CountingClient struct {
	client.Client
	updates int
}

func (c *m35CountingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updates++
	return c.Client.Update(ctx, obj, opts...)
}

type m35ServiceErrorReader struct {
	client.Reader
	err error
}

type m35NthGetErrorReader struct {
	client.Reader
	failAt int
	gets   int
	err    error
}

func (r *m35NthGetErrorReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	r.gets++
	if r.gets == r.failAt {
		return r.err
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

type m35NthGetMutationReader struct {
	client.Reader
	mutateAt int
	gets     int
	mutate   func(client.Object)
}

func (r *m35NthGetMutationReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	r.gets++
	if err := r.Reader.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if r.gets == r.mutateAt {
		r.mutate(obj)
	}
	return nil
}

type m35UpdateErrorClient struct {
	client.Client
	failKind string
	err      error
	updates  int
}

func (c *m35UpdateErrorClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updates++
	if obj.GetObjectKind().GroupVersionKind().Kind == c.failKind {
		return c.err
	}
	switch obj.(type) {
	case *corev1.Pod:
		if c.failKind == "Pod" {
			return c.err
		}
	case *corev1.Service:
		if c.failKind == "Service" {
			return c.err
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

func (r m35ServiceErrorReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Service); ok {
		return r.err
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func m35EndpointFixture(t *testing.T) (*corev1.Pod, *corev1.Service, client.Client) {
	t.Helper()
	pod := aiPod("ns", "infer", map[string]string{labelRouteKey: "ep-old", "app": "infer"})
	pod.Annotations[annoRouteService] = "infer-svc"
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: "infer-svc", UID: types.UID("uid-infer-svc"), ResourceVersion: "9"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "infer", labelRouteKey: "ep-old"}},
	}
	return pod, svc, fakeC(pod, svc)
}

func TestM035EndpointRotateRefusesMissingServiceBeforeWrite(t *testing.T) {
	pod := aiPod("ns", "infer", map[string]string{labelRouteKey: "ep-old"})
	pod.Annotations[annoRouteService] = "absent"
	base := fakeC(pod)
	c := &m35CountingClient{Client: base}
	result, err := endpointRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c}, Request{
		Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate,
	})
	if !IsNoEffectRefusal(err) || result.Emitted || c.updates != 0 {
		t.Fatalf("missing Service must be a zero-write refusal: result=%+v err=%v updates=%d", result, err, c.updates)
	}
	got := &corev1.Pod{}
	if getErr := base.Get(context.Background(), client.ObjectKeyFromObject(pod), got); getErr != nil {
		t.Fatal(getErr)
	}
	if got.Labels[labelRouteKey] != "ep-old" {
		t.Fatalf("refusal changed Pod route key to %q", got.Labels[labelRouteKey])
	}
}

func TestM035EndpointRotateRefusesUnreadableServiceBeforeWrite(t *testing.T) {
	pod, _, base := m35EndpointFixture(t)
	c := &m35CountingClient{Client: base}
	reader := m35ServiceErrorReader{Reader: base, err: apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "infer-svc", errors.New("denied"))}
	result, err := endpointRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: reader}, Request{
		Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate,
	})
	if !IsNoEffectRefusal(err) || result.Emitted || c.updates != 0 || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("unreadable Service must be a zero-write refusal: result=%+v err=%v updates=%d", result, err, c.updates)
	}
}

func TestM035EndpointRotateRefusesInvalidAuthorityBeforeWrite(t *testing.T) {
	tests := []struct {
		name          string
		mutateObjects func(*corev1.Pod, *corev1.Service)
		mutateRequest func(*Request)
		mutateContext func(*EnactCtx)
	}{
		{name: "missing-reader", mutateContext: func(ec *EnactCtx) { ec.Reader = nil }},
		{name: "missing-writer", mutateContext: func(ec *EnactCtx) { ec.Client = nil }},
		{name: "missing-target-uid", mutateRequest: func(req *Request) { req.TargetUID = "" }},
		{name: "mismatched-target-uid", mutateRequest: func(req *Request) { req.TargetUID = "replacement" }},
		{name: "empty-declaration", mutateObjects: func(pod *corev1.Pod, _ *corev1.Service) {
			delete(pod.Annotations, annoRouteService)
		}},
		{name: "service-uid-missing", mutateObjects: func(_ *corev1.Pod, svc *corev1.Service) { svc.UID = "" }},
		{name: "selector-does-not-select", mutateObjects: func(_ *corev1.Pod, svc *corev1.Service) { svc.Spec.Selector["app"] = "other" }},
		{name: "empty-selector-value-requires-label-presence", mutateObjects: func(_ *corev1.Pod, svc *corev1.Service) {
			svc.Spec.Selector = map[string]string{"missing": ""}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod, svc, _ := m35EndpointFixture(t)
			if tc.mutateObjects != nil {
				tc.mutateObjects(pod, svc)
			}
			req := Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate}
			if tc.mutateRequest != nil {
				tc.mutateRequest(&req)
			}
			base := fakeC(pod, svc)
			counting := &m35CountingClient{Client: base}
			ec := EnactCtx{Client: counting, Reader: counting}
			if tc.mutateContext != nil {
				tc.mutateContext(&ec)
			}
			result, err := endpointRotateHandler{}.Enact(context.Background(), ec, req)
			if !IsNoEffectRefusal(err) || result.Emitted || counting.updates != 0 {
				t.Fatalf("result=%+v err=%v updates=%d", result, err, counting.updates)
			}
		})
	}
}

func TestM035EndpointRotateRefusesMissingServiceResourceVersion(t *testing.T) {
	pod, _, base := m35EndpointFixture(t)
	c := &m35CountingClient{Client: base}
	reader := &m35NthGetMutationReader{Reader: base, mutateAt: 2, mutate: func(obj client.Object) {
		obj.(*corev1.Service).ResourceVersion = ""
	}}
	result, err := endpointRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: reader}, Request{
		Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate,
	})
	if !IsNoEffectRefusal(err) || result.Emitted || c.updates != 0 {
		t.Fatalf("missing Service RV must be a zero-write refusal: result=%+v err=%v updates=%d", result, err, c.updates)
	}
}

func TestM035EndpointRotateWriteAndReadbackFailuresRemainPartial(t *testing.T) {
	conflict := apierrors.NewConflict(schema.GroupResource{Resource: "services"}, "infer-svc", errors.New("replacement"))
	tests := []struct {
		name   string
		client func(client.Client) client.Client
		reader func(client.Client) client.Reader
	}{
		{
			name: "service-conflict-after-pod-write",
			client: func(base client.Client) client.Client {
				return &m35UpdateErrorClient{Client: base, failKind: "Service", err: conflict}
			},
			reader: func(base client.Client) client.Reader { return base },
		},
		{
			name:   "pod-readback-denied-after-accepted-write",
			client: func(base client.Client) client.Client { return base },
			reader: func(base client.Client) client.Reader {
				return &m35NthGetErrorReader{Reader: base, failAt: 3, err: apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "infer", errors.New("readback denied"))}
			},
		},
		{
			name:   "service-readback-lost-after-both-writes",
			client: func(base client.Client) client.Client { return base },
			reader: func(base client.Client) client.Reader {
				return &m35NthGetErrorReader{Reader: base, failAt: 6, err: errors.New("readback transport lost")}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod, _, base := m35EndpointFixture(t)
			writer := tc.client(base)
			result, err := endpointRotateHandler{}.Enact(context.Background(), EnactCtx{Client: writer, Reader: tc.reader(base)}, Request{
				Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate,
			})
			if err == nil || IsNoEffectRefusal(err) || !result.Emitted || result.MutationKind != "partial" || !strings.Contains(result.Note, "partial/unknown") {
				t.Fatalf("partial outcome lost: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestM035EndpointRotatePodConflictIsNoEffect(t *testing.T) {
	pod, _, base := m35EndpointFixture(t)
	conflict := apierrors.NewConflict(schema.GroupResource{Resource: "pods"}, pod.Name, errors.New("stale resource version"))
	c := &m35UpdateErrorClient{Client: base, failKind: "Pod", err: conflict}
	result, err := endpointRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: base}, Request{
		Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate,
	})
	if !IsNoEffectRefusal(err) || result.Emitted || c.updates != 1 {
		t.Fatalf("Pod conflict must remain a zero-effect refusal: result=%+v err=%v updates=%d", result, err, c.updates)
	}
	got := &corev1.Pod{}
	if getErr := base.Get(context.Background(), client.ObjectKeyFromObject(pod), got); getErr != nil {
		t.Fatal(getErr)
	}
	if got.Labels[labelRouteKey] != "ep-old" {
		t.Fatalf("conflicted write mutated target: %+v", got.Labels)
	}
}

func TestM035EndpointRotateFinalReadbackBindsDeclarationAndSelector(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(client.Object)
	}{
		{
			name: "route-service-declaration-changed",
			mutate: func(obj client.Object) {
				obj.(*corev1.Pod).Annotations[annoRouteService] = "replacement-service"
			},
		},
		{
			name: "unrelated-selected-label-changed",
			mutate: func(obj client.Object) {
				obj.(*corev1.Pod).Labels["app"] = "replacement"
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod, _, base := m35EndpointFixture(t)
			reader := &m35NthGetMutationReader{Reader: base, mutateAt: 5, mutate: tc.mutate}
			result, err := endpointRotateHandler{}.Enact(context.Background(), EnactCtx{Client: base, Reader: reader}, Request{
				Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionEndpointRotate,
			})
			if err == nil || IsNoEffectRefusal(err) || !result.Emitted || result.MutationKind != "partial" {
				t.Fatalf("changed postcondition was reported complete: result=%+v err=%v", result, err)
			}
		})
	}
}
