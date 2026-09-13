package actuator

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

func TestMIGAgentPolicyRejectsMissingAndMalformedConfiguration(t *testing.T) {
	valid := testAgentPolicy()
	tests := map[string]func(*MIGAgentPolicy){
		"namespace":         func(p *MIGAgentPolicy) { p.Namespace = "" },
		"daemonset":         func(p *MIGAgentPolicy) { p.DaemonSet = "Bad_Name" },
		"container":         func(p *MIGAgentPolicy) { p.Container = "" },
		"service accounts":  func(p *MIGAgentPolicy) { p.ServiceAccounts = nil },
		"bad account":       func(p *MIGAgentPolicy) { p.ServiceAccounts = []string{"Bad_Name"} },
		"duplicate account": func(p *MIGAgentPolicy) { p.ServiceAccounts = []string{"mig-agent", "mig-agent"} },
		"zero timeout":      func(p *MIGAgentPolicy) { p.ExecTimeout = 0 },
		"excess timeout":    func(p *MIGAgentPolicy) { p.ExecTimeout = maxMIGExecTimeout + time.Nanosecond },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := valid
			p.ServiceAccounts = append([]string(nil), valid.ServiceAccounts...)
			mutate(&p)
			if err := p.validate(); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestWireRemoteNodeExecPublishesOnlyCompleteConfiguration(t *testing.T) {
	old := pkgNodeRunner
	pkgNodeRunner = nil
	t.Cleanup(func() { pkgNodeRunner = old })
	valid := RemoteExecConfig{Config: &rest.Config{Host: "https://unused.invalid"}, Clientset: fake.NewSimpleClientset(), Agent: testAgentPolicy()}
	bad := []RemoteExecConfig{{}, {Config: valid.Config, Clientset: valid.Clientset}, {Config: valid.Config, Agent: valid.Agent}, {Clientset: valid.Clientset, Agent: valid.Agent}}
	for i, cfg := range bad {
		if err := WireRemoteNodeExec(cfg); err == nil {
			t.Fatalf("partial config %d accepted", i)
		}
		if NodeExecWired() {
			t.Fatalf("partial config %d published a ready seam", i)
		}
	}
	if err := WireRemoteNodeExec(valid); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if !NodeExecWired() {
		t.Fatal("valid config was not published")
	}
}

func TestExecNodeRunnerRejectsUntrustedCandidates(t *testing.T) {
	mutations := map[string]func(*appsv1.DaemonSet, *corev1.Pod){
		"wrong service account": func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.Spec.ServiceAccountName = "rogue" },
		"wrong owner kind":      func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.OwnerReferences[0].Kind = "Deployment" },
		"wrong owner name":      func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.OwnerReferences[0].Name = "other" },
		"wrong owner uid":       func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.OwnerReferences[0].UID = "other" },
		"not controller":        func(_ *appsv1.DaemonSet, p *corev1.Pod) { f := false; p.OwnerReferences[0].Controller = &f },
		"uidless":               func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.UID = "" },
		"not ready":             func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.Status.Conditions = nil },
		"not running":           func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.Status.Phase = corev1.PodPending },
		"deleting": func(_ *appsv1.DaemonSet, p *corev1.Pod) {
			now := metav1.Now()
			p.DeletionTimestamp = &now
		},
		"wrong node":        func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.Spec.NodeName = "node-2" },
		"missing container": func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.Spec.Containers = []corev1.Container{{Name: "other"}} },
		"selector mismatch": func(_ *appsv1.DaemonSet, p *corev1.Pod) { p.Labels["app"] = "other" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			ds, pod := testAgentObjects("agent-a")
			mutate(ds, pod)
			r := execNodeRunner{client: fake.NewSimpleClientset(ds, pod), exec: noopExec, policy: testAgentPolicy()}
			if _, err := r.Prepare(context.Background(), "node-1"); err == nil || !strings.Contains(err.Error(), "got 0") {
				t.Fatalf("untrusted candidate accepted or wrong error: %v", err)
			}
		})
	}
}

func TestExecNodeRunnerNamespaceScopeAndAmbiguity(t *testing.T) {
	ds, trusted := testAgentObjects("trusted")
	_, rogue := testAgentObjects("aaa-rogue")
	rogue.Namespace = "attacker-ns"
	c := fake.NewSimpleClientset(ds, trusted, rogue)
	r := execNodeRunner{client: c, exec: noopExec, policy: testAgentPolicy()}
	if _, err := r.Prepare(context.Background(), "node-1"); err != nil {
		t.Fatalf("cross-namespace rogue affected selection: %v", err)
	}
	actions := c.Actions()
	found := false
	for _, action := range actions {
		if action.GetVerb() == "list" && action.GetResource().Resource == "pods" {
			found = true
			if action.GetNamespace() != "gpu-system" {
				t.Fatalf("pod List namespace=%q", action.GetNamespace())
			}
			list := action.(ktesting.ListAction)
			if !list.GetListRestrictions().Fields.Matches(fields.Set{"spec.nodeName": "node-1"}) {
				t.Fatalf("pod List is not field-scoped to node-1: %v", list.GetListRestrictions().Fields)
			}
		}
	}
	if !found {
		t.Fatal("no pod discovery List observed")
	}
	_, second := testAgentObjects("trusted-2")
	c = fake.NewSimpleClientset(ds, trusted, second)
	r.client = c
	if _, err := r.Prepare(context.Background(), "node-1"); err == nil || !strings.Contains(err.Error(), "got 2") {
		t.Fatalf("ambiguous candidates did not fail closed: %v", err)
	}
}

func TestPreparedMIGCarriesOneIdentityAcrossAllCommands(t *testing.T) {
	ds, pod := testAgentObjects("agent-a")
	c := fake.NewSimpleClientset(ds, pod)
	lists := 0
	c.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) { lists++; return false, nil, nil })
	var calls [][]string
	var targets []string
	exec := func(_ context.Context, ns, name, container string, argv []string) (string, error) {
		targets = append(targets, ns+"/"+name+"["+container+"]")
		calls = append(calls, append([]string(nil), argv...))
		return "", nil
	}
	mig := &nvidiaSMIMIG{run: execNodeRunner{client: c, exec: exec, policy: testAgentPolicy()}}
	prepared, err := mig.Prepare(context.Background(), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Repartition(context.Background(), "0", "1g.10gb"); err != nil {
		t.Fatal(err)
	}
	if lists != 1 || len(calls) != 3 || !reflect.DeepEqual(targets, []string{"gpu-system/agent-a[agent]", "gpu-system/agent-a[agent]", "gpu-system/agent-a[agent]"}) {
		t.Fatalf("lists=%d targets=%v calls=%v", lists, targets, calls)
	}
}

func TestPreparedMIGAbortsWhenBoundIdentityChangesBetweenSteps(t *testing.T) {
	tests := map[string]func(context.Context, *fake.Clientset, *appsv1.DaemonSet, *corev1.Pod) error{
		"pod replacement": func(ctx context.Context, c *fake.Clientset, _ *appsv1.DaemonSet, p *corev1.Pod) error {
			p.UID = "replacement"
			_, err := c.CoreV1().Pods(p.Namespace).Update(ctx, p, metav1.UpdateOptions{})
			return err
		},
		"pod deletion": func(ctx context.Context, c *fake.Clientset, _ *appsv1.DaemonSet, p *corev1.Pod) error {
			return c.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{})
		},
		"daemonset replacement": func(ctx context.Context, c *fake.Clientset, ds *appsv1.DaemonSet, _ *corev1.Pod) error {
			ds.UID = "replacement"
			_, err := c.AppsV1().DaemonSets(ds.Namespace).Update(ctx, ds, metav1.UpdateOptions{})
			return err
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			ds, pod := testAgentObjects("agent-a")
			c := fake.NewSimpleClientset(ds, pod)
			calls := 0
			exec := func(ctx context.Context, _, _, _ string, _ []string) (string, error) {
				calls++
				if calls == 1 {
					if err := mutate(ctx, c, ds.DeepCopy(), pod.DeepCopy()); err != nil {
						return "", err
					}
				}
				return "", nil
			}
			mig := &nvidiaSMIMIG{run: execNodeRunner{client: c, exec: exec, policy: testAgentPolicy()}}
			prepared, err := mig.Prepare(context.Background(), "node-1")
			if err != nil {
				t.Fatal(err)
			}
			if err := prepared.Repartition(context.Background(), "0", "1g.10gb"); err == nil {
				t.Fatal("identity drift did not abort")
			}
			if calls != 1 {
				t.Fatalf("exec calls=%d, want 1", calls)
			}
		})
	}
}

func TestPreparedMIGRevalidatesBeforeFirstAndEveryFollowingExec(t *testing.T) {
	tests := []struct {
		name       string
		afterCalls int
		mutate     func(context.Context, *fake.Clientset, *appsv1.DaemonSet, *corev1.Pod) error
		wantCalls  int
	}{
		{"pod read failure before first", 0, func(_ context.Context, c *fake.Clientset, _ *appsv1.DaemonSet, _ *corev1.Pod) error {
			c.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, fmt.Errorf("read unavailable") })
			return nil
		}, 0},
		{"owner drift after first", 1, func(ctx context.Context, c *fake.Clientset, _ *appsv1.DaemonSet, p *corev1.Pod) error {
			p.OwnerReferences[0].UID = "drift"
			_, err := c.CoreV1().Pods(p.Namespace).Update(ctx, p, metav1.UpdateOptions{})
			return err
		}, 1},
		{"node drift after second", 2, func(ctx context.Context, c *fake.Clientset, _ *appsv1.DaemonSet, p *corev1.Pod) error {
			p.Spec.NodeName = "node-2"
			_, err := c.CoreV1().Pods(p.Namespace).Update(ctx, p, metav1.UpdateOptions{})
			return err
		}, 2},
		{"readiness drift after first", 1, func(ctx context.Context, c *fake.Clientset, _ *appsv1.DaemonSet, p *corev1.Pod) error {
			p.Status.Conditions = nil
			_, err := c.CoreV1().Pods(p.Namespace).Update(ctx, p, metav1.UpdateOptions{})
			return err
		}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ds, pod := testAgentObjects("agent-a")
			c := fake.NewSimpleClientset(ds, pod)
			calls := 0
			exec := func(ctx context.Context, _, _, _ string, _ []string) (string, error) {
				calls++
				if calls == tc.afterCalls {
					if err := tc.mutate(ctx, c, ds.DeepCopy(), pod.DeepCopy()); err != nil {
						return "", err
					}
				}
				return "", nil
			}
			mig := &nvidiaSMIMIG{run: execNodeRunner{client: c, exec: exec, policy: testAgentPolicy()}}
			prepared, err := mig.Prepare(context.Background(), "node-1")
			if err != nil {
				t.Fatal(err)
			}
			if tc.afterCalls == 0 {
				if err := tc.mutate(context.Background(), c, ds.DeepCopy(), pod.DeepCopy()); err != nil {
					t.Fatal(err)
				}
			}
			if err := prepared.Repartition(context.Background(), "0", "1g.10gb"); err == nil {
				t.Fatal("identity/read drift did not abort")
			}
			if calls != tc.wantCalls {
				t.Fatalf("exec calls=%d, want %d", calls, tc.wantCalls)
			}
		})
	}
}

func TestConcurrentPreparationsKeepIndependentAgentReferences(t *testing.T) {
	ds, first := testAgentObjects("agent-one")
	_, second := testAgentObjects("agent-two")
	second.Spec.NodeName = "node-2"
	c := fake.NewSimpleClientset(ds, first, second)
	var mu sync.Mutex
	var targets []string
	r := execNodeRunner{client: c, policy: testAgentPolicy(), exec: func(_ context.Context, _, pod, _ string, _ []string) (string, error) {
		mu.Lock()
		targets = append(targets, pod)
		mu.Unlock()
		return "", nil
	}}
	var wg sync.WaitGroup
	for _, node := range []string{"node-1", "node-2"} {
		node := node
		wg.Add(1)
		go func() {
			defer wg.Done()
			prepared, err := r.Prepare(context.Background(), node)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := prepared.Run(context.Background(), "nvidia-smi"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(targets) != 2 || targets[0] == targets[1] {
		t.Fatalf("concurrent references crossed: %v", targets)
	}
}

func TestMIGRebindPreparationRefusalDoesNotMutateWorkload(t *testing.T) {
	pod := migPod("ns", "infer")
	c := fakeC(pod)
	ds, _ := testAgentObjects("agent-a")
	mig := &nvidiaSMIMIG{run: execNodeRunner{client: fake.NewSimpleClientset(ds), exec: noopExec, policy: testAgentPolicy()}}
	_, err := migRebindHandler{}.Enact(context.Background(), EnactCtx{Client: c, MIG: mig}, Request{Namespace: "ns", Pod: "infer", Action: model.ActionMIGRebind})
	if err == nil {
		t.Fatal("selection refusal accepted")
	}
	var got corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), &got); err != nil {
		t.Fatalf("workload was deleted: %v", err)
	}
	if got.Labels[labelRole] != roleLeader {
		t.Fatalf("workload relabelled before preparation: %v", got.Labels)
	}
}

func noopExec(context.Context, string, string, string, []string) (string, error) { return "", nil }

func TestPreparedNodeRunnerAppliesExecTimeout(t *testing.T) {
	ds, pod := testAgentObjects("agent-a")
	policy := testAgentPolicy()
	policy.ExecTimeout = 20 * time.Millisecond
	exec := func(ctx context.Context, _, _, _ string, _ []string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	r := execNodeRunner{client: fake.NewSimpleClientset(ds, pod), exec: exec, policy: policy}
	prepared, err := r.Prepare(context.Background(), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Run(context.Background(), "nvidia-smi"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exec timeout error=%v", err)
	}
}
