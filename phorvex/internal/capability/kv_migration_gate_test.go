package capability

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

func TestDefaultKVMigrationExcludedBeforeDecisionWhileKVResetRemainsEligible(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	reader := fake.NewClientBuilder().WithScheme(scheme).Build()
	security, err := actuator.LoadServingSecurityFile("", actuator.ServingSecurityLegacyPlaintext, "phorvex-system")
	if err != nil {
		t.Fatal(err)
	}
	native := actuator.NewNativeActuator(reader)
	native.SetBoundaryReader(reader)
	native.JournalNamespace = "phorvex-system"
	native.SetServingSecurity(security)
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "vllm", Name: "serving", UID: "exact-pod-uid", Ready: true, ServingEndpointReady: true}}
	witness := BuildWitness(t.Context(), BuildIndex(nil, nil, nil), nil, nil, native).WithPolicyIdentity("vllm-defense", "policy-uid")
	reason := witness.Eligible(view, model.ActionKVMigrateInvalidate, []string{"session-cache"})
	if reason == nil || !reason.Excluded || reason.Kind != ReasonCapability || reason.Detail != actuator.ReasonKVMigrationConnectorUnavailable {
		t.Fatalf("migration candidate was not excluded before decision: %+v", reason)
	}
	if reason := witness.Eligible(view, model.ActionKVReset, []string{"session-cache"}); reason != nil {
		t.Fatalf("the independent KV reset capability changed: %+v", reason)
	}
}
