package actuator

import (
	"context"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	phoenixcontrollers "github.com/r6security/phoenix/pkg/controllers"
)

// TestM052PhoenixProducerToShippedConsumer proves the production PhoenixActuator
// envelope is accepted by the shipped registered Phoenix consumer. It also proves
// the protected reservation makes the exact retry idempotent and keeps a same-name
// replacement from allocating a second delayed event at capacity.
func TestM052PhoenixProducerToShippedConsumer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	localOnly := false
	e := &envtest.Environment{
		CRDDirectoryPaths:  []string{"../../../build/phoenix-extended/config/crd/bases"},
		UseExistingCluster: &localOnly,
	}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: p4bScheme(), Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := phoenixcontrollers.RegisterCoreControllers(mgr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("stop Phoenix manager: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Phoenix manager did not stop")
		}
	})
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("Phoenix manager cache did not synchronize")
	}

	c := mgr.GetClient()
	reader := mgr.GetAPIReader()
	for _, name := range []string{"m052-phoenix-operator", "m052-phoenix-tenant"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	ns := &corev1.Namespace{}
	if err := reader.Get(ctx, client.ObjectKey{Name: "m052-phoenix-tenant"}, ns); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: ns.Name, Labels: map[string]string{"app": "model", "security": "managed"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}},
	}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}

	phoenix := NewPhoenixActuator(c)
	if err := phoenix.EnsurePolicy(ctx, TenantTarget{
		Tenant: "tenant", Namespace: ns.Name, PolicyName: "policy", PolicyUID: "policy-uid",
		MatchLabels:    map[string]string{"security": "managed"},
		EnabledActions: map[model.Action]bool{model.ActionQuarantine: true},
	}); err != nil {
		t.Fatal(err)
	}
	// The shipped AMTD reconciler must adopt the target before its SecurityEvent
	// consumer can resolve the matching strategy.
	m066Poll(t, 15*time.Second, func() (bool, error) {
		if err := reader.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			return false, err
		}
		return pod.Annotations["amtd.r6security.com/managed-by"] != "", nil
	})

	capacity, err := NewQuarantineCapacity(c, reader, "m052-phoenix-operator", 1)
	if err != nil {
		t.Fatal(err)
	}
	req := Request{
		Tenant: "tenant", PolicyName: "policy", PolicyUID: "policy-uid", Namespace: ns.Name,
		Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionQuarantine,
	}
	result, err := capacity.Actuate(ctx, phoenix, req)
	if err != nil || !result.Emitted || result.EventName == "" || result.EventUID == "" {
		t.Fatalf("Phoenix producer did not emit bound event below cap: result=%+v err=%v", result, err)
	}
	m066Poll(t, 15*time.Second, func() (bool, error) {
		if err := reader.Get(ctx, client.ObjectKeyFromObject(pod), pod); err != nil {
			return false, err
		}
		return pod.Labels[phoenixQuarantineMarker] != "", nil
	})
	policyName := pod.Labels[phoenixQuarantineMarker]
	policy := &networkingv1.NetworkPolicy{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: ns.Name, Name: policyName}, policy); err != nil {
		t.Fatalf("shipped Phoenix consumer did not create deny policy: %v", err)
	}
	if got := policy.Spec.PodSelector.MatchLabels[phoenixQuarantineMarker]; got != policyName {
		t.Fatalf("Phoenix consumer policy selector=%q want=%q", got, policyName)
	}
	inv, err := capacity.Inventory(ctx, ns.Name)
	if err != nil || inv.Used != 1 || inv.Observed != 1 || inv.Limit != 1 {
		t.Fatalf("connected Phoenix inventory=%+v err=%v", inv, err)
	}
	if _, err := capacity.Actuate(ctx, phoenix, req); err == nil {
		t.Fatal("same target retry emitted duplicate delayed Phoenix work")
	}
	var events amtdv1beta1.SecurityEventList
	if err := reader.List(ctx, &events); err != nil || len(events.Items) != 1 {
		t.Fatalf("controlled event count=%d err=%v", len(events.Items), err)
	}

	oldUID := pod.UID
	if err := c.Delete(ctx, pod, client.GracePeriodSeconds(0)); err != nil {
		t.Fatal(err)
	}
	m066Poll(t, 10*time.Second, func() (bool, error) {
		probe := &corev1.Pod{}
		err := reader.Get(ctx, client.ObjectKeyFromObject(pod), probe)
		return err != nil, client.IgnoreNotFound(err)
	})
	replacement := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: pod.Name, Namespace: ns.Name, Labels: map[string]string{"app": "model", "security": "managed"}},
		Spec:       pod.Spec,
	}
	if err := c.Create(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	if replacement.UID == "" || replacement.UID == oldUID {
		t.Fatalf("API did not create a distinct same-name replacement: old=%s new=%s", oldUID, replacement.UID)
	}
	replacementReq := req
	replacementReq.TargetUID = string(replacement.UID)
	if result, err := capacity.Actuate(ctx, phoenix, replacementReq); !IsNoEffectRefusal(err) || result.Emitted {
		t.Fatalf("same-name replacement escaped capacity: result=%+v err=%v", result, err)
	}
	if err := reader.List(ctx, &events); err != nil || len(events.Items) != 1 {
		t.Fatalf("replacement emitted duplicate controlled event: count=%d err=%v", len(events.Items), err)
	}
}
