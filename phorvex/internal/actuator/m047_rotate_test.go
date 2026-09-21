package actuator

import (
	"context"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"strings"
	"testing"
)

func m47Pair() (*corev1.Pod, *appsv1.ReplicaSet) {
	yes := true
	n := int32(2)
	p := aiPod("ns", "p", map[string]string{"app": "web"})
	p.UID = "pod-uid"
	p.ResourceVersion = "7"
	p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-uid", Controller: &yes}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs", UID: "rs-uid"}, Spec: appsv1.ReplicaSetSpec{Replicas: &n, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}}
	return p, rs
}
func TestM47OwnershipMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		edit         func(*corev1.Pod, *appsv1.ReplicaSet)
	}{
		{"supported", "", func(*corev1.Pod, *appsv1.ReplicaSet) {}},
		{"bare", "ownerless", func(p *corev1.Pod, _ *appsv1.ReplicaSet) { p.OwnerReferences = nil }},
		{"not-controlling", "ownerless", func(p *corev1.Pod, _ *appsv1.ReplicaSet) { no := false; p.OwnerReferences[0].Controller = &no }},
		{"mirror", "mirror-pod", func(p *corev1.Pod, _ *appsv1.ReplicaSet) { p.Annotations[corev1.MirrorPodAnnotationKey] = "mirror" }},
		{"wrong-uid", "owner-uid-mismatch", func(p *corev1.Pod, _ *appsv1.ReplicaSet) { p.OwnerReferences[0].UID = "other" }},
		{"dangling", "owner-unresolved", func(p *corev1.Pod, _ *appsv1.ReplicaSet) { p.OwnerReferences[0].Name = "missing" }},
		{"job", "owner-kind-unsupported", func(p *corev1.Pod, _ *appsv1.ReplicaSet) {
			p.OwnerReferences[0].Kind = "Job"
			p.OwnerReferences[0].APIVersion = "batch/v1"
		}},
		{"scaled-zero", "owner-state-ineligible", func(_ *corev1.Pod, r *appsv1.ReplicaSet) { *r.Spec.Replicas = 0 }},
		{"scaled-down", "owner-state-ineligible", func(_ *corev1.Pod, r *appsv1.ReplicaSet) { r.Status.Replicas = 3 }},
		{"selector-mismatch", "owner-state-ineligible", func(p *corev1.Pod, _ *appsv1.ReplicaSet) { p.Labels["app"] = "other" }},
		{"terminating", "owner-terminating", func(_ *corev1.Pod, r *appsv1.ReplicaSet) {
			now := metav1.Now()
			r.DeletionTimestamp = &now
			r.Finalizers = []string{"test"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r := m47Pair()
			tc.edit(p, r)
			c := m47Client(p, r)
			got, err := dispatch(context.Background(), EnactCtx{Client: c, Reader: c}, m47Request(p))
			if err != nil {
				t.Fatal(err)
			}
			if tc.reason == "" {
				if !got.Emitted || !strings.Contains(got.Note, "replacement unconfirmed") || got.GracefulTermination == nil {
					t.Fatalf("%+v", got)
				}
			} else {
				if got.Emitted || !strings.Contains(got.Note, tc.reason) {
					t.Fatalf("%+v want refusal %s", got, tc.reason)
				}
				if err := c.Get(context.Background(), client.ObjectKeyFromObject(p), &corev1.Pod{}); err != nil {
					t.Fatalf("refused pod lost: %v", err)
				}
			}
		})
	}
}
func TestM47NameReuseAndMissingBoundary(t *testing.T) {
	p, r := m47Pair()
	c := m47Client(p, r)
	for _, tc := range []struct {
		reader client.Reader
		uid    types.UID
		reason string
	}{{c, "old-uid", "target-uid-mismatch"}, {nil, p.UID, "authoritative-reader-unavailable"}, {c, "", "target-uid-unavailable"}} {
		req := m47Request(p)
		req.TargetUID = string(tc.uid)
		got, err := (rotateHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: tc.reader}, req)
		if err != nil || got.Emitted || !strings.Contains(got.Note, tc.reason) {
			t.Fatalf("%+v %v", got, err)
		}
	}
}

func m47Client(objects ...client.Object) client.Client {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	objects = append(objects, m47Policy())
	return fake.NewClientBuilder().WithScheme(s).WithObjects(objects...).Build()
}

func m47Policy() *v1alpha1.PhorvexPolicy {
	return &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 3},
		Spec: v1alpha1.PhorvexPolicySpec{
			Mode:     v1alpha1.ModeActive,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Actions:  v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}},
		},
	}
}

func m47Request(p *corev1.Pod) Request {
	return Request{
		Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID), Action: model.ActionRotate,
		PolicyName: "policy", PolicyUID: "policy-uid", PolicyGeneration: 3, MaxGracePeriodSeconds: 30,
	}
}

func TestM47ParentAndReplicationController(t *testing.T) {
	p, rs := m47Pair()
	yes := true
	n := int32(2)
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "deploy", UID: "deployment-uid"}, Spec: appsv1.DeploymentSpec{Replicas: &n}}
	rs.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: &yes}}
	for _, paused := range []bool{true, false} {
		d.Spec.Paused = paused
		c := m47Client(p, rs, d)
		got, err := dispatch(context.Background(), EnactCtx{Client: c, Reader: c}, m47Request(p))
		if err != nil || got.Emitted == paused {
			t.Fatalf("paused=%v: %+v %v", paused, got, err)
		}
	}
	rc := &corev1.ReplicationController{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rc", UID: "rc-uid"}, Spec: corev1.ReplicationControllerSpec{Replicas: &n, Selector: map[string]string{"app": "web"}}}
	p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ReplicationController", Name: rc.Name, UID: rc.UID, Controller: &yes}}
	c := m47Client(p, rc)
	got, err := dispatch(context.Background(), EnactCtx{Client: c, Reader: c}, m47Request(p))
	if err != nil || !got.Emitted {
		t.Fatalf("RC positive: %+v %v", got, err)
	}
}
