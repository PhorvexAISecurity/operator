package actuator

import (
	"context"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

// This test uses a real local kube-apiserver and etcd. It has no CNI or workload
// controllers, so it proves API identity/resourceVersion and recovery state only.
func TestAdministrativeRecoveryAPIServerLifecycle(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires envtest assets")
	}
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := e.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	}()
	c, err := client.New(cfg, client.Options{Scheme: qtnScheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{metav1.NamespaceSystem, "operator", "recovery-api"} {
		if err = c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatal(err)
		}
	}
	pol := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "recovery-api", Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "recovery"}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionQuarantine)}}}}
	if err = c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: pol.Namespace, Name: "recovery"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "recovery"}, Ports: []corev1.ServicePort{{Port: 80}}}}
	if err = c.Create(ctx, svc); err != nil {
		t.Fatal(err)
	}
	hold := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "operator", Name: RecoveryHoldName}, Data: map[string]string{"engaged": "true"}}
	if err = c.Create(ctx, hold); err != nil {
		t.Fatal(err)
	}
	n := NewNativeActuator(c)
	n.Reader, n.JournalNamespace = c, "operator"
	scope := RecoveryScope{OperatorNamespace: "operator", Namespace: pol.Namespace, PolicyName: pol.Name, MaxItems: 1}

	createAndQuarantine := func(name string) *corev1.Pod {
		t.Helper()
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: pol.Namespace, Name: name, Labels: map[string]string{"app": "recovery"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "fixture", Image: "unused:test"}}}}
		if err := c.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		result, enactErr := n.Actuate(ctx, Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionQuarantine, PolicyName: pol.Name, PolicyUID: string(pol.UID)})
		if enactErr != nil || !result.Emitted {
			t.Fatalf("quarantine %s: %+v %v", name, result, enactErr)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			t.Fatal(err)
		}
		return pod
	}

	t.Run("producer-plan-held-apply-readback", func(t *testing.T) {
		pod := createAndQuarantine("restore")
		plan, planErr := n.PlanRecovery(ctx, scope)
		if planErr != nil || len(plan.Items) != 1 {
			t.Fatalf("plan=%+v err=%v", plan, planErr)
		}
		item := plan.Items[0]
		result, applyErr := n.ApplyRecovery(ctx, plan)
		if applyErr != nil || !result.Complete || len(result.Items) != 1 || result.Items[0].Outcome != "restored" {
			t.Fatalf("apply=%+v err=%v", result, applyErr)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			t.Fatal(err)
		}
		if pod.Labels["app"] != "recovery" || pod.Labels[quarantineLabel] != "" || pod.Annotations[quarantineSnapAnno] != "" {
			t.Fatalf("Pod not restored: labels=%v annotations=%v", pod.Labels, pod.Annotations)
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: item.NetworkPolicy.Namespace, Name: item.NetworkPolicy.Name}, &networkingv1.NetworkPolicy{}); !apierrors.IsNotFound(err) {
			t.Fatalf("NetworkPolicy retained: %v", err)
		}
		if err := c.Get(ctx, client.ObjectKey{Namespace: item.Receipt.Namespace, Name: item.Receipt.Name}, &corev1.ConfigMap{}); !apierrors.IsNotFound(err) {
			t.Fatalf("receipt retained: %v", err)
		}
	})

	t.Run("stale-pod-resource-version-refuses-without-restore", func(t *testing.T) {
		pod := createAndQuarantine("stale")
		plan, planErr := n.PlanRecovery(ctx, scope)
		if planErr != nil || len(plan.Items) != 1 {
			t.Fatalf("plan=%+v err=%v", plan, planErr)
		}
		pod.Annotations["example.test/concurrent"] = "keep"
		if err := c.Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
		beforeRV := pod.ResourceVersion
		item := plan.Items[0]
		result, applyErr := n.ApplyRecovery(ctx, plan)
		if applyErr == nil || result.Complete || len(result.Items) != 1 || result.Items[0].Outcome != "refused" {
			t.Fatalf("stale apply=%+v err=%v", result, applyErr)
		}
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			t.Fatal(err)
		}
		if pod.ResourceVersion != beforeRV || pod.Labels[quarantineLabel] == "" || pod.Annotations["example.test/concurrent"] != "keep" {
			t.Fatalf("stale refusal changed Pod: rv=%s labels=%v annotations=%v", pod.ResourceVersion, pod.Labels, pod.Annotations)
		}
		np := &networkingv1.NetworkPolicy{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: item.NetworkPolicy.Namespace, Name: item.NetworkPolicy.Name}, np); err != nil || string(np.UID) != item.NetworkPolicy.UID || np.ResourceVersion != item.NetworkPolicy.ResourceVersion {
			t.Fatalf("stale refusal changed NetworkPolicy: %+v %v", np, err)
		}
		receipt := &corev1.ConfigMap{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: item.Receipt.Namespace, Name: item.Receipt.Name}, receipt); err != nil || string(receipt.UID) != item.Receipt.UID || receipt.ResourceVersion != item.Receipt.ResourceVersion {
			t.Fatalf("stale refusal changed receipt: %+v %v", receipt, err)
		}
	})
}
