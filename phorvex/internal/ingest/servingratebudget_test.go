package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/eventtrust"
	"github.com/phorvex/phorvex/internal/model"
	b "github.com/phorvex/phorvex/internal/servingbudget"
	bt "github.com/phorvex/phorvex/internal/servingbudget/budgettest"
)

func TestServingRateBudgetTrustedAndNegativeBindings(t *testing.T) {
	for _, kind := range []string{"valid", "untrusted", "targetless", "stale", "wrong-pod", "wrong-policy", "missing-limiter"} {
		t.Run(kind, func(t *testing.T) {
			t.Setenv("PHORVEX_THROTTLE_SOURCE_SHA256", bt.SHA)
			t.Setenv("PHORVEX_THROTTLE_PROXY_IMAGE", bt.Image)
			c, o := bt.Fixture()
			e := model.SecurityEventInfo{Name: o.EventName, UID: o.EventUID, CreatorIdentity: o.CreatorIdentity, Type: model.AttackVectorServingCostHarvest, Trust: eventtrust.TrustTrusted, TargetsPod: true, ConsoleTargetPodUID: o.TargetPodUID, Age: time.Second, CreatedAt: o.ObservedAt, ServingRateBudgetRaw: b.Encode(o)}
			switch kind {
			case "untrusted":
				e.Trust = eventtrust.TrustUntrusted
			case "targetless":
				e.TargetsPod = false
			case "stale":
				e.Age = time.Minute
			case "wrong-pod":
				o.TargetPodUID = "other"
			case "wrong-policy":
				o.PolicyGeneration++
			case "missing-limiter":
				o.LimiterConfigMapUID = "other"
			}
			e.ServingRateBudgetRaw = b.Encode(o)
			p := model.Pod{Namespace: bt.Namespace, Name: "cost-target-test", UID: "target-uid", ControllerUID: "target-rs-uid"}
			bindServingRateBudgetObservation(context.Background(), c, &p, []model.SecurityEventInfo{e})
			if p.HasBoundServingRateBudgetObservation() != (kind == "valid") {
				t.Fatalf("kind=%s binding=%+v", kind, p.ServingRateBudgetObservation)
			}
		})
	}
}
