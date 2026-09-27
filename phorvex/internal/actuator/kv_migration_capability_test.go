package actuator

import (
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type testReviewedKVConnector struct{ *mockKVXfer }

func (testReviewedKVConnector) RemoteMigrationReady() bool { return true }

func TestKVMigrationDefaultTransferIsUnavailableBeforeDispatch(t *testing.T) {
	n := NewNativeActuator(nil)
	target := Target{Namespace: "vllm", Pod: "vllm", UID: "pod-uid"}
	if ok, why := n.SupportsAction(t.Context(), model.ActionKVMigrateInvalidate, target); ok || why != ReasonKVMigrationConnectorUnavailable {
		t.Fatalf("default migration capability = (%v, %q)", ok, why)
	}
	result, err := n.Actuate(t.Context(), Request{Tenant: "vllm", Namespace: "vllm", Pod: "vllm", TargetUID: "pod-uid", Action: model.ActionKVMigrateInvalidate})
	if err == nil || !strings.Contains(err.Error(), ReasonKVMigrationConnectorUnavailable) || result.Emitted || result.MutationKind != "none" || result.NoEffect != NoEffectRefused {
		t.Fatalf("default migration dispatch = (%+v, %v)", result, err)
	}
	if kvMigrationConnectorReady(httpKVTransfer{v: newHTTPVLLM()}) {
		t.Fatal("local-only HTTP transfer claimed remote support")
	}
	if !kvMigrationConnectorReady(testReviewedKVConnector{&mockKVXfer{}}) {
		t.Fatal("an explicitly ready future connector could not be distinguished")
	}
}

func TestUnavailableKVMigrationCannotRewritePendingReceipt(t *testing.T) {
	pod := aiPod("vllm", "serving", map[string]string{"app": "vllm"})
	receipt := m064PreparedReceipt(pod, model.ActionKVMigrateInvalidate, "existing-tick")
	receipt.Phase = "dispatching"
	reader := fakeC(m064LiteralReceipt(receipt))
	n := NewNativeActuator(reader)
	before := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: "operator", Name: receiptName(receipt)}
	if err := reader.Get(t.Context(), key, before); err != nil {
		t.Fatal(err)
	}
	_, _ = n.Actuate(t.Context(), Request{Tenant: "vllm", Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionKVMigrateInvalidate})
	after := &corev1.ConfigMap{}
	if err := reader.Get(t.Context(), key, after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("unavailable migration dispatch changed protected history")
	}
}
