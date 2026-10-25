package recon

import (
	"github.com/phorvex/phorvex/internal/model"
	"testing"
	"time"
)

func boundServingRateView() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "serving", UID: "target", ControllerUID: "rs", ServingRateBudgetObservation: &model.ServingRateBudgetObservation{EventName: "event", EventUID: "event-uid", CreatorIdentity: "detector", TargetPodUID: "target", ControllerUID: "rs", PolicyName: "defense", PolicyUID: "policy", PolicyGeneration: 1, ServiceUID: "svc", LimiterDeploymentUID: "dep", LimiterConfigMapUID: "cm", LimiterSourceSHA256: "sha", LimiterBootID: "boot", OffendingCallerScope: "caller|/", BaselineReqPerSec: 42, ReservedReqPerSec: 42, ObservedReqPerSec: 1821, WindowSeconds: 60, ObservedAt: time.Now()}}}
}
func TestServingRateBudgetCoverOnlyOverBudgetPath(t *testing.T) {
	for _, profile := range Registry.All() {
		v := boundServingRateView()
		af := profile.AssetFacts(v, FactContext{AssetValue: 1, PHold: 1, StageUrgency: 1})
		keys := af.CoverByAction[model.ActionThrottle]
		if len(keys) != 1 {
			t.Fatalf("%s: keys=%v", profile.Name(), keys)
		}
		for _, f := range af.Facts {
			if f.Key() == keys[0] && f.Kind != FactServingRateBudget {
				t.Fatal("overbroad cover")
			}
		}
		v.Pod.ServingRateBudgetObservation = nil
		if keys = profile.AssetFacts(v, FactContext{AssetValue: 1, PHold: 1, StageUrgency: 1}).CoverByAction[model.ActionThrottle]; len(keys) != 0 {
			t.Fatal("unbound cover")
		}
	}
}
