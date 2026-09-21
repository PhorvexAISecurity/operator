package actuator

import (
	"context"
	"errors"

	"github.com/phorvex/phorvex/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"strings"
	"testing"
)

type m47PolicyReader struct {
	client.Reader
	policy *v1alpha1.PhorvexPolicy
}

func (r m47PolicyReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if policy, ok := obj.(*v1alpha1.PhorvexPolicy); ok && key.Namespace == r.policy.Namespace && key.Name == r.policy.Name {
		r.policy.DeepCopyInto(policy)
		return nil
	}
	return r.Reader.Get(ctx, key, obj, opts...)
}

func TestM47APIServerPreconditions(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API-server binaries")
	}
	e := &envtest.Environment{}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = policyv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	c, err := client.NewWithWatch(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m47-test"}}
	if err = c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	n := int32(2)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "rs"}, Spec: appsv1.ReplicaSetSpec{Replicas: &n, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "test:unused"}}}}}}
	if err = c.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	for _, race := range []bool{true, false} {
		name := "positive"
		if race {
			name = "race"
		}
		yes := true
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: name, Labels: map[string]string{"app": "web"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "test:unused"}}}}
		if err = c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		policy := m47Policy()
		policy.Namespace = ns.Name
		reader := m47PolicyReader{Reader: c, policy: policy}
		req := m47Request(p)
		req.PolicyGeneration = policy.Generation
		directDeletes, evictionCalls := 0, 0
		writer := interceptor.NewClient(c, interceptor.Funcs{
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				directDeletes++
				return errors.New("direct Pod DELETE fallback attempted")
			},
			SubResourceCreate: func(ctx context.Context, inner client.Client, subresource string, obj client.Object, sub client.Object, opts ...client.SubResourceCreateOption) error {
				evictionCalls++
				if race {
					current := &corev1.Pod{}
					if err := inner.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
						return err
					}
					current.OwnerReferences = nil
					if err := inner.Update(ctx, current); err != nil {
						return err
					}
				}
				return inner.SubResource(subresource).Create(ctx, obj, sub, opts...)
			},
		})
		got, err := dispatch(ctx, EnactCtx{Client: writer, Reader: reader}, req)
		if err != nil {
			t.Fatal(err)
		}
		if evictionCalls != 1 || directDeletes != 0 {
			t.Fatalf("evictions=%d directDeletes=%d", evictionCalls, directDeletes)
		}
		if race {
			if got.Emitted || !strings.Contains(got.Note, "target-changed-before-eviction") {
				t.Fatalf("stale owner mutation accepted: %+v", got)
			}
			if err = c.Get(ctx, client.ObjectKeyFromObject(p), p); err != nil || !p.DeletionTimestamp.IsZero() {
				t.Fatalf("raced pod deleted: %v %+v", err, p)
			}
		} else if !got.Emitted || !strings.Contains(got.Note, "replacement unconfirmed") {
			t.Fatalf("positive control failed: %+v", got)
		}
	}
}
