package actuator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

// TestM052RealReplicaSetQuarantineStopsAtCapacity exercises the incident loop
// through a real API server and the real ReplicaSet controller: native quarantine
// retains and detaches the first Pod, KCM creates a replacement, and the protected
// namespace ledger refuses quarantine of that replacement at the configured bound.
func TestM052RealReplicaSetQuarantineStopsAtCapacity(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API binaries")
	}
	kcm := os.Getenv("KUBE_CONTROLLER_MANAGER")
	if kcm == "" {
		var lookupErr error
		kcm, lookupErr = exec.LookPath("kube-controller-manager")
		if lookupErr != nil {
			t.Skip("requires local Kubernetes v1.34.0 kube-controller-manager via KUBE_CONTROLLER_MANAGER or PATH")
		}
	}
	if _, err := os.Stat(kcm); err != nil {
		t.Skip("configured kube-controller-manager unavailable")
	}
	version, err := exec.Command(kcm, "--version").Output()
	if err != nil || !strings.Contains(string(version), "v1.34.0") {
		t.Fatalf("local kube-controller-manager must be v1.34.0: output=%q err=%v", string(version), err)
	}

	localOnly := false
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, UseExistingCluster: &localOnly}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	privateKubeconfig := m066Kubeconfig(t, cfg)
	cmd := exec.CommandContext(ctx, kcm, "--kubeconfig="+privateKubeconfig, "--controllers=replicaset", "--leader-elect=false", "--use-service-account-credentials=false", "--bind-address=127.0.0.1", "--secure-port=0")
	cmd.Env = []string{"KUBECONFIG=" + privateKubeconfig}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "KUBECONFIG=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	var kcmLog m066BoundedLog
	cmd.Stdout = &kcmLog
	cmd.Stderr = &kcmLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })

	c, err := client.NewWithWatch(cfg, client.Options{Scheme: p4bScheme()})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"m052-operator", "m052-tenant"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatalf("create namespace %s: %v", name, err)
		}
	}
	pol := &v1alpha1.PhorvexPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "m052-tenant", Name: "policy"},
		Spec: v1alpha1.PhorvexPolicySpec{
			Mode:     v1alpha1.ModeActive,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "m052"}},
			Budget: v1alpha1.BudgetSpec{
				TickInterval:           metav1.Duration{Duration: 20 * time.Second},
				AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute},
				ProactiveFloor:         metav1.Duration{Duration: time.Hour},
			},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionQuarantine)}},
		},
	}
	if err := c.Create(ctx, pol); err != nil {
		t.Fatal(err)
	}
	replicas := int32(1)
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "m052-tenant", Name: "pool"},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "m052"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "m052"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "model", Image: "registry.k8s.io/pause:3.10"}}},
			},
		},
	}
	if err := c.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	var pods corev1.PodList
	m066Poll(t, 20*time.Second, func() (bool, error) {
		if err := c.List(ctx, &pods, client.InNamespace("m052-tenant")); err != nil {
			return false, err
		}
		return len(pods.Items) == 1 && metav1.IsControlledBy(&pods.Items[0], rs), nil
	})
	original := pods.Items[0].DeepCopy()

	capacity, err := NewQuarantineCapacity(c, c, "m052-operator", 1)
	if err != nil {
		t.Fatal(err)
	}
	native := NewNativeActuator(c)
	native.Reader = c
	native.JournalNamespace = "m052-operator"
	request := Request{
		PolicyName: pol.Name, PolicyUID: string(pol.UID), Namespace: pol.Namespace,
		Pod: original.Name, TargetUID: string(original.UID), Action: model.ActionQuarantine,
	}
	result, err := capacity.Actuate(ctx, native, request)
	if err != nil || !result.Emitted {
		t.Fatalf("first quarantine below cap failed: result=%+v err=%v kcm=%s", result, err, kcmLog.String())
	}

	var replacement *corev1.Pod
	m066Poll(t, 20*time.Second, func() (bool, error) {
		if err := c.List(ctx, &pods, client.InNamespace("m052-tenant")); err != nil {
			return false, err
		}
		if len(pods.Items) != 2 {
			return false, nil
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			if pod.UID == original.UID {
				if pod.Labels[quarantineLabel] != string(original.UID) || metav1.GetControllerOf(pod) != nil {
					return false, fmt.Errorf("original Pod was not retained and detached: labels=%v owners=%v", pod.Labels, pod.OwnerReferences)
				}
				continue
			}
			if metav1.IsControlledBy(pod, rs) && pod.Labels["app"] == "m052" {
				replacement = pod.DeepCopy()
			}
		}
		return replacement != nil, nil
	})

	second := Request{
		PolicyName: pol.Name, PolicyUID: string(pol.UID), Namespace: pol.Namespace,
		Pod: replacement.Name, TargetUID: string(replacement.UID), Action: model.ActionQuarantine,
	}
	if result, err := capacity.Actuate(ctx, native, second); !IsNoEffectRefusal(err) || result.Emitted {
		t.Fatalf("replacement quarantine at cap must refuse without effect: result=%+v err=%v", result, err)
	}
	if err := c.List(ctx, &pods, client.InNamespace("m052-tenant")); err != nil {
		t.Fatal(err)
	}
	if len(pods.Items) != 2 {
		t.Fatalf("capacity refusal allowed another retained/replacement Pod: count=%d pods=%v", len(pods.Items), pods.Items)
	}
	currentReplacement := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(replacement), currentReplacement); err != nil {
		t.Fatal(err)
	}
	if currentReplacement.Labels[quarantineLabel] != "" || !metav1.IsControlledBy(currentReplacement, rs) {
		t.Fatalf("capacity refusal mutated replacement: labels=%v owners=%v", currentReplacement.Labels, currentReplacement.OwnerReferences)
	}
	inv, err := capacity.Inventory(ctx, "m052-tenant")
	if err != nil || inv.Used != 1 || inv.Observed != 1 || inv.Limit != 1 {
		t.Fatalf("bounded retained population inventory=%+v err=%v", inv, err)
	}
}
