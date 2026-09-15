/*
 * Phorvex — MIG node-exec transport tests (mocked exec/agent; no real GPU). Proves: the nvidia-smi MIG
 * repartition SEQUENCE + ORDERING; the transport RESOLVES the node-agent pod and dispatches the exec;
 * and it FAIL-CLOSES when the exec is unwired or no agent pod is Running on the node. The live SPDY exec
 * + real GPU result are [PENDING-GPU-VALIDATION].
 */

package actuator

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// seqRunner records every Run() argv so the test can assert the MIG command sequence + ordering.
type seqRunner struct {
	calls [][]string
	avail error
}

func (r *seqRunner) Run(_ context.Context, argv ...string) (string, error) {
	r.calls = append(r.calls, append([]string(nil), argv...))
	return "", nil
}
func (r *seqRunner) Prepare(context.Context, string) (preparedNodeRunner, error) {
	return r, r.avail
}

func TestMIG_RepartitionSequenceAndOrdering(t *testing.T) {
	rec := &seqRunner{}
	mig := &nvidiaSMIMIG{run: rec}
	prepared, err := mig.Prepare(context.Background(), "node-1")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if _, err := prepared.Repartition(context.Background(), migTestPrior(), "1g.10gb", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("repartition: %v", err)
	}
	want := [][]string{
		{"nvidia-smi", "mig", "-i", "0", "-dci"},                  // destroy compute instances
		{"nvidia-smi", "mig", "-i", "0", "-dgi"},                  // destroy GPU instances
		{"nvidia-smi", "mig", "-i", "0", "-cgi", "1g.10gb", "-C"}, // create new geometry + CIs
	}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Errorf("MIG sequence/ordering wrong:\n got %v\nwant %v", rec.calls, want)
	}
}

func TestMIG_RepartitionEmptyProfileRejected(t *testing.T) {
	prepared, err := (&nvidiaSMIMIG{run: &seqRunner{}}).Prepare(context.Background(), "n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepared.Repartition(context.Background(), migTestPrior(), "", func(context.Context) error { return nil }); err == nil {
		t.Error("empty target profile must be rejected")
	}
}

func testAgentPolicy() MIGAgentPolicy {
	return MIGAgentPolicy{Namespace: "gpu-system", ServiceAccounts: []string{"mig-agent"}, DaemonSet: "mig-agent", Container: "agent", ExecTimeout: time.Second}
}

func testAgentObjects(name string) (*appsv1.DaemonSet, *corev1.Pod) {
	controller := true
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-agent", Namespace: "gpu-system", UID: types.UID("ds-uid")},
		Spec:       appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "mig-agent"}}},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "gpu-system", UID: types.UID(name + "-uid"), Labels: map[string]string{"app": "mig-agent", migAgentLabelKey: "true"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: ds.Name, UID: ds.UID, Controller: &controller}}},
		Spec:       corev1.PodSpec{NodeName: "node-1", ServiceAccountName: "mig-agent", Containers: []corev1.Container{{Name: "agent"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	return ds, pod
}

func TestExecNodeRunner_FailClosedWhenExecUnwired(t *testing.T) {
	r := execNodeRunner{client: fake.NewSimpleClientset(), policy: testAgentPolicy()}
	if _, err := r.Prepare(context.Background(), "node-1"); err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Fatalf("unwired exec must fail-closed; got %v", err)
	}
}

func TestExecNodeRunner_FailClosedWhenNoAgentOnNode(t *testing.T) {
	ds, _ := testAgentObjects("agent-a")
	called := false
	r := execNodeRunner{client: fake.NewSimpleClientset(ds), exec: func(context.Context, string, string, string, []string) (string, error) { called = true; return "", nil }, policy: testAgentPolicy()}
	if _, err := r.Prepare(context.Background(), "node-1"); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("no agent pod must fail-closed; got %v", err)
	}
	if called {
		t.Error("exec invoked without an agent")
	}
}

func TestExecNodeRunner_ResolvesAgentAndDispatchesExec(t *testing.T) {
	ds, agent := testAgentObjects("mig-agent-xyz")
	c := fake.NewSimpleClientset(ds, agent)
	lists := 0
	c.PrependReactor("list", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		lists++
		return false, nil, nil
	})
	var gotNS, gotPod string
	var gotArgv []string
	rec := func(_ context.Context, ns, pod, _ string, argv []string) (string, error) {
		gotNS, gotPod, gotArgv = ns, pod, argv
		return "ok", nil
	}
	r := execNodeRunner{client: c, exec: rec, policy: testAgentPolicy()}
	prepared, err := r.Prepare(context.Background(), "node-1")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	out, err := prepared.Run(context.Background(), "nvidia-smi", "mig", "-lgip")
	if err != nil || out != "ok" {
		t.Fatalf("run: out=%q err=%v", out, err)
	}
	if gotNS != "gpu-system" || gotPod != "mig-agent-xyz" || !reflect.DeepEqual(gotArgv, []string{"nvidia-smi", "mig", "-lgip"}) {
		t.Errorf("exec dispatched to wrong target: ns=%s pod=%s argv=%v", gotNS, gotPod, gotArgv)
	}
	if lists != 1 {
		t.Fatalf("agent discovery lists=%d, want exactly one", lists)
	}
}

func TestRemoteNodeExec_NilConfigFailsClosed(t *testing.T) {
	fn := newRemoteNodeExec(RemoteExecConfig{}) // nil clientset/config
	if _, err := fn(context.Background(), "ns", "pod", "c", []string{"nvidia-smi"}); err == nil {
		t.Error("a nil-config remote node-exec must fail-closed (never fabricate)")
	}
	if NodeExecWired() {
		t.Error("NodeExecWired must be false until WireRemoteNodeExec is called")
	}
}
