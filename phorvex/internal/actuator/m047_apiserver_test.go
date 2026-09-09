package actuator

import (
	"context"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"strings"
	"testing"
)

type m47RaceClient struct {
	client.Client
	race bool
}

func (c *m47RaceClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if c.race {
		p := &corev1.Pod{}
		if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), p); err != nil {
			return err
		}
		p.OwnerReferences = nil
		if err := c.Client.Update(ctx, p); err != nil {
			return err
		}
	}
	return c.Client.Delete(ctx, obj, opts...)
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
	c, err := client.New(cfg, client.Options{Scheme: s})
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
		got, err := dispatch(ctx, EnactCtx{Client: &m47RaceClient{Client: c, race: race}, Reader: c}, Request{Namespace: p.Namespace, Pod: p.Name, TargetUID: string(p.UID), Action: model.ActionRotate})
		if err != nil {
			t.Fatal(err)
		}
		if race {
			if got.Emitted || !strings.Contains(got.Note, "target-changed-before-delete") {
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
