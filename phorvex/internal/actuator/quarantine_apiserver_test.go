package actuator

import (
	"context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
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
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}}
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
	if err = c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}); err != nil {
		t.Fatal(err)
	}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: ns.Name}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionQuarantine)}}}}
	if err = c.Create(ctx, pol); err != nil {
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
		n.JournalNamespace = "operator"
		req := Request{Namespace: ns.Name, Pod: name, TargetUID: string(p.UID), Action: "quarantine", PolicyName: pol.Name, PolicyUID: string(pol.UID)}
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
