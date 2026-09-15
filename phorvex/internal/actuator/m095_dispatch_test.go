package actuator

import (
	"context"
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

type m95CaptureVLLM struct {
	mockVLLM
	unloadAdapter string
}

func (m *m95CaptureVLLM) UnloadAdapter(ctx context.Context, ep servingEndpoint, name string) error {
	m.unloadAdapter = name
	return m.mockVLLM.UnloadAdapter(ctx, ep, name)
}

func m95DispatchFixture(t *testing.T) (*corev1.Pod, *unstructured.Unstructured, model.AdapterObservation) {
	t.Helper()
	now := time.Now().Add(-time.Minute).UTC()
	pod := aiPod("ns", "infer", map[string]string{labelLoRAEnabled: "true"})
	pod.Annotations[annoLoRAAdapter] = "tenant-drift"
	creator := "system:serviceaccount:ns:detector"
	o := model.AdapterObservation{EventName: "detected", EventUID: "event-uid", CreatorIdentity: creator,
		TargetPodUID: string(pod.UID), AdapterName: "actual-poison", CreatedAt: now}
	e := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
		"metadata": map[string]interface{}{"name": o.EventName, "uid": o.EventUID,
			"creationTimestamp": now.Format(time.RFC3339), "annotations": map[string]interface{}{
				"phorvex.ai/creator-identity": creator, "phorvex.ai/target-pod-uid": o.TargetPodUID,
				"phorvex.ai/adapter-name": o.AdapterName}},
		"spec": map[string]interface{}{"rule": map[string]interface{}{"type": model.AttackVectorAdapter}, "targets": []interface{}{"ns/infer"}},
	}}
	return pod, e, o
}

func TestM095DispatchUsesDetectorAdapterDespitePodAnnotationDrift(t *testing.T) {
	pod, event, o := m95DispatchFixture(t)
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "SecurityEvent"}, &unstructured.Unstructured{})
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod, event).Build()
	ConfigureAdapterDetectorIdentities([]string{o.CreatorIdentity})
	t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
	mv := &m95CaptureVLLM{}
	req := Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionAdapterRotate, AdapterObservation: &o}
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: mv}, req)
	if err != nil || !hr.Emitted {
		t.Fatalf("trusted dispatch refused: result=%+v err=%v", hr, err)
	}
	if mv.unloadAdapter != "actual-poison" {
		t.Fatalf("unloaded %q, want event-owned adapter", mv.unloadAdapter)
	}
}

func TestM095DispatchRefusesSpoofedOrRecreatedObservation(t *testing.T) {
	pod, event, o := m95DispatchFixture(t)
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "SecurityEvent"}, &unstructured.Unstructured{})
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod, event).Build()
	ConfigureAdapterDetectorIdentities([]string{o.CreatorIdentity})
	t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
	for _, tc := range []struct {
		name   string
		mutate func(*Request)
	}{
		{"no observation", func(r *Request) { r.AdapterObservation = nil }},
		{"client asserted creator", func(r *Request) {
			copy := *r.AdapterObservation
			copy.CreatorIdentity = "evil"
			r.AdapterObservation = &copy
		}},
		{"wrong Pod UID", func(r *Request) { r.TargetUID = "recreated" }},
		{"wrong event UID", func(r *Request) {
			copy := *r.AdapterObservation
			copy.EventUID = "recreated"
			r.AdapterObservation = &copy
		}},
		{"wrong adapter", func(r *Request) {
			copy := *r.AdapterObservation
			copy.AdapterName = "tenant-drift"
			r.AdapterObservation = &copy
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mv := &m95CaptureVLLM{}
			r := Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionAdapterRotate, AdapterObservation: &o}
			tc.mutate(&r)
			hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: mv}, r)
			if err != nil || hr.Emitted || mv.unloadAdapter != "" {
				t.Fatalf("refusal crossed serving seam: %+v %v unload=%q", hr, err, mv.unloadAdapter)
			}
		})
	}
}

func TestM095UnchangedDetectorEventAndAbsentStackCreditsNoNewMitigation(t *testing.T) {
	pod, event, o := m95DispatchFixture(t)
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "SecurityEvent"}, &unstructured.Unstructured{})
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod, event).Build()
	ConfigureAdapterDetectorIdentities([]string{o.CreatorIdentity})
	t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
	r := Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionAdapterRotate, AdapterObservation: &o}
	for i := 0; i < 2; i++ {
		mv := &m95CaptureVLLM{mockVLLM: mockVLLM{unloadErr: fmt.Errorf("%w", errAdapterAbsent)}}
		hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: mv}, r)
		if err != nil || hr.Emitted || mv.unloadAdapter != "actual-poison" {
			t.Fatalf("repeat %d miscredited absent goal: result=%+v err=%v unload=%q", i, hr, err, mv.unloadAdapter)
		}
	}
	var after corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: pod.Namespace, Name: pod.Name}, &after); err != nil {
		t.Fatal(err)
	}
	if after.Annotations["phorvex.ai/adapter-epoch"] != "" {
		t.Fatal("absent response stamped a new mitigation epoch")
	}
}

func TestM095AuthoritativeEventRecheckRejectsInvalidLiveObjects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*unstructured.Unstructured)
	}{
		{"future timestamp", func(e *unstructured.Unstructured) {
			e.SetCreationTimestamp(metav1.NewTime(time.Now().Add(time.Minute)))
		}},
		{"deleting event", func(e *unstructured.Unstructured) {
			now := metav1.NewTime(time.Now())
			e.SetFinalizers([]string{"test/finalize"})
			e.SetDeletionTimestamp(&now)
		}},
		{"self source", func(e *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(e.Object, RuleSource, "spec", "rule", "source")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod, event, o := m95DispatchFixture(t)
			tc.mutate(event)
			s := runtime.NewScheme()
			if err := corev1.AddToScheme(s); err != nil {
				t.Fatal(err)
			}
			s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "SecurityEvent"}, &unstructured.Unstructured{})
			c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod, event).Build()
			ConfigureAdapterDetectorIdentities([]string{o.CreatorIdentity})
			t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
			mv := &m95CaptureVLLM{}
			r := Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionAdapterRotate, AdapterObservation: &o}
			hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: mv}, r)
			if err != nil || hr.Emitted || mv.unloadAdapter != "" {
				t.Fatalf("invalid live event crossed serving seam: %+v %v unload=%q", hr, err, mv.unloadAdapter)
			}
		})
	}
	pod, event, o := m95DispatchFixture(t)
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	s.AddKnownTypeWithName(schema.GroupVersionKind{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "SecurityEvent"}, &unstructured.Unstructured{})
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(pod, event).Build()
	ConfigureAdapterDetectorIdentities([]string{o.CreatorIdentity})
	t.Cleanup(func() { ConfigureAdapterDetectorIdentities(nil) })
	mv := &m95CaptureVLLM{}
	r := Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionAdapterRotate, AdapterObservation: &o}
	hr, err := adapterRotateHandler{}.Enact(context.Background(), EnactCtx{Client: c, VLLM: mv}, r)
	if err != nil || hr.Emitted || mv.unloadAdapter != "" {
		t.Fatalf("missing authoritative reader crossed serving seam: %+v %v unload=%q", hr, err, mv.unloadAdapter)
	}
}
