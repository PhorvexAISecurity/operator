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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// seqRunner records every Run() argv so the test can assert the MIG command sequence + ordering.
type seqRunner struct {
	calls [][]string
	avail error
}

func (r *seqRunner) Run(_ context.Context, _ string, argv ...string) (string, error) {
	r.calls = append(r.calls, argv)
	return "", nil
}
func (r *seqRunner) Available(context.Context, string) error { return r.avail }

func TestMIG_RepartitionSequenceAndOrdering(t *testing.T) {
	rec := &seqRunner{}
	mig := &nvidiaSMIMIG{run: rec}
	if err := mig.Repartition(context.Background(), "node-1", "0", "1g.10gb"); err != nil {
		t.Fatalf("repartition: %v", err)
	}
	want := [][]string{
		{"nvidia-smi", "mig", "-i", "0", "-dci"},        // destroy compute instances
		{"nvidia-smi", "mig", "-i", "0", "-dgi"},        // destroy GPU instances
		{"nvidia-smi", "mig", "-i", "0", "-cgi", "1g.10gb", "-C"}, // create new geometry + CIs
	}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Errorf("MIG sequence/ordering wrong:\n got %v\nwant %v", rec.calls, want)
	}
}

func TestMIG_RepartitionEmptyProfileRejected(t *testing.T) {
	if err := (&nvidiaSMIMIG{run: &seqRunner{}}).Repartition(context.Background(), "n", "0", ""); err == nil {
		t.Error("empty target profile must be rejected")
	}
}

func actuatorScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestExecNodeRunner_FailClosedWhenExecUnwired(t *testing.T) {
	c := ctrlfake.NewClientBuilder().WithScheme(actuatorScheme(t)).Build()
	r := execNodeRunner{c: c, exec: nil, label: migAgentLabelKey} // exec nil => not wired
	if err := r.Available(context.Background(), "node-1"); err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Fatalf("unwired exec must fail-closed; got %v", err)
	}
	if _, err := r.Run(context.Background(), "node-1", "nvidia-smi"); err == nil {
		t.Error("Run must fail-closed when exec is unwired")
	}
}

func TestExecNodeRunner_FailClosedWhenNoAgentOnNode(t *testing.T) {
	called := false
	rec := func(context.Context, string, string, string, []string) (string, error) { called = true; return "", nil }
	c := ctrlfake.NewClientBuilder().WithScheme(actuatorScheme(t)).Build() // no agent pods
	r := execNodeRunner{c: c, exec: rec, label: migAgentLabelKey}
	if err := r.Available(context.Background(), "node-1"); err == nil || !strings.Contains(err.Error(), "no MIG node-agent") {
		t.Fatalf("no agent pod must fail-closed; got %v", err)
	}
	if _, err := r.Run(context.Background(), "node-1", "nvidia-smi"); err == nil {
		t.Error("Run must fail-closed with no agent pod")
	}
	if called {
		t.Error("the exec must NOT be invoked when the agent is absent (fail-closed before exec)")
	}
}

func TestExecNodeRunner_ResolvesAgentAndDispatchesExec(t *testing.T) {
	agent := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "mig-agent-xyz", Namespace: "gpu-system", Labels: map[string]string{migAgentLabelKey: "true"}},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := ctrlfake.NewClientBuilder().WithScheme(actuatorScheme(t)).WithObjects(agent).Build()
	var gotNS, gotPod string
	var gotArgv []string
	rec := func(_ context.Context, ns, pod, _ string, argv []string) (string, error) {
		gotNS, gotPod, gotArgv = ns, pod, argv
		return "ok", nil
	}
	r := execNodeRunner{c: c, exec: rec, label: migAgentLabelKey}
	out, err := r.Run(context.Background(), "node-1", "nvidia-smi", "mig", "-lgip")
	if err != nil || out != "ok" {
		t.Fatalf("run: out=%q err=%v", out, err)
	}
	if gotNS != "gpu-system" || gotPod != "mig-agent-xyz" || !reflect.DeepEqual(gotArgv, []string{"nvidia-smi", "mig", "-lgip"}) {
		t.Errorf("exec dispatched to wrong target: ns=%s pod=%s argv=%v", gotNS, gotPod, gotArgv)
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
