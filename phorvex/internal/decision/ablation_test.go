/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func lowValueView(name string) *model.WorkloadView {
	return &model.WorkloadView{
		Pod: model.Pod{
			Namespace: "ns", Name: name, UID: "u-" + name,
			DesiredReplicas: 3, ReadyReplicas: 3, Ready: true,
		},
		Phase:              model.PhaseWarm,
		BlastRadius:        0.05,
		ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 2 * time.Hour},
	}
}

// THE STEP-3 IP GATE (deterministic, in-repo): the P1 optimizer must invalidate more
// recon-weight PER DOLLAR than random selection over the identical feasible set. The
// fleet mixes high-value (secret-bearing, high-blast, crown-jewel neighbor) and
// low-value pods, so targeting matters.
func TestAblationP1BeatsRandomPerDollar(t *testing.T) {
	e := NewCoverageEngine()
	views := []*model.WorkloadView{
		covView("crown1", true, 3*time.Hour, false),
		covView("crown2", true, 3*time.Hour, false),
		lowValueView("cheap1"),
		lowValueView("cheap2"),
		lowValueView("cheap3"),
		lowValueView("cheap4"),
	}
	seeds := make([]int64, 40)
	for i := range seeds {
		seeds[i] = int64(i + 1)
	}
	res := e.Ablate(views, covPolicy(2), seeds)

	if res.P1PerDollar <= 0 || res.RandomPerDollar <= 0 {
		t.Fatalf("both arms must spend and invalidate something: %+v", res)
	}
	if res.Ratio <= 1.0 {
		t.Errorf("P1 must invalidate MORE recon-per-dollar than random (ratio>1): ratio=%.3f p1=%.3f random=%.3f",
			res.Ratio, res.P1PerDollar, res.RandomPerDollar)
	}
}
