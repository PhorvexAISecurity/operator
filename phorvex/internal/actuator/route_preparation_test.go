package actuator

import (
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

// A native backend prepares no Phoenix route. Its rotate and quarantine dispatch on the
// native route; reading its preparation with the hybrid routing refused every
// quarantine as "Phoenix route was not prepared" (staging, 2026-10-23).
func TestNativePreparationDispatchesOnItsOwnRoutes(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	target := TenantTarget{Tenant: "tenant", Namespace: "ns", PolicyName: "policy", PolicyUID: "owner",
		EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionQuarantine: true}}
	prep := NewNativeActuator(c).ReconcileStandingPolicy(t.Context(), target).Preparation
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		if err := prep.ForAction(BackendNative, a); err != nil {
			t.Fatalf("native %s refused: %v", a, err)
		}
	}
	if err := prep.ForAction(BackendHybrid, model.ActionQuarantine); err == nil {
		t.Fatal("a hybrid quarantine dispatched without its Phoenix route")
	}
}
