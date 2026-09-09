package actuator

import (
	"context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"testing"
)

type qtnRaceClient struct {
	client.Client
	race bool
}

func (c *qtnRaceClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if c.race {
		if _, ok := obj.(*corev1.Pod); ok {
			fresh := &corev1.Pod{}
			if err := c.Client.Get(ctx, client.ObjectKeyFromObject(obj), fresh); err != nil {
				return err
			}
			fresh.Labels["concurrent"] = "keep"
			if err := c.Client.Update(ctx, fresh); err != nil {
				return err
			}
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}
func TestM038APIServerConditionalDetach(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires envtest assets")
	}
	e := &envtest.Environment{}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	c, err := client.New(cfg, client.Options{Scheme: qtnScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m038"}}
	if err = c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "front"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}, Ports: []corev1.ServicePort{{Port: 80}}}}
	if err = c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	for _, race := range []bool{false, true} {
		name := "healthy"
		if race {
			name = "conflict"
		}
		p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: name, Labels: map[string]string{"app": "web"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "fixture", Image: "unused:test"}}}}
		if err = c.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		n := NewNativeActuator(&qtnRaceClient{Client: c, race: race})
		n.SetBoundaryReader(c)
		req := Request{Namespace: ns.Name, Pod: name, TargetUID: string(p.UID), Action: "quarantine"}
		result, err := n.Actuate(ctx, req)
		got := &corev1.Pod{}
		if getErr := c.Get(ctx, client.ObjectKeyFromObject(p), got); getErr != nil {
			t.Fatal(getErr)
		}
		if race {
			if err == nil || !result.Emitted || got.Labels["concurrent"] != "keep" || got.Labels[quarantineLabel] != "" {
				t.Fatalf("conflict lost: %+v %v", result, err)
			}
		} else {
			if err != nil || got.Labels["app"] == "web" || got.Labels[quarantineLabel] != string(p.UID) {
				t.Fatalf("detach: %+v %v", result, err)
			}
			if err = n.Rollback(ctx, req, result.RollbackRef); err != nil {
				t.Fatal(err)
			}
			if err = c.Get(ctx, client.ObjectKeyFromObject(p), got); err != nil || got.Labels["app"] != "web" {
				t.Fatalf("rollback: %v", err)
			}
		}
	}
}
