/*
 * Phorvex — reactiveOnly: calm baseline (no proactive churn) until a real attack signal
 * targets the asset, then a clean attributable reaction. Default (reactiveOnly=false) is
 * the proactive moving-target path and is covered byte-identically by the O1 golden.
 */

package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestReactiveOnlyCalmUntilAttacked(t *testing.T) {
	fixedNow := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	// An OVERDUE pod: exposure (2h) >> proactiveFloor (1h) => genuinely due for the
	// hygiene-floor proactive rotation (prov=1, no decoy discount).
	aged := func() *model.WorkloadView { return covView("web1", true, 2*time.Hour, false) }

	// (1) DEFAULT (reactiveOnly=false): the overdue pod IS proactively rotated.
	{
		e := NewCoverageEngine()
		e.Now = fixedNow
		pol := covPolicy(2)
		var last model.Decision
		for i := 0; i < 6; i++ { // let the dual λ descend under slack
			last = e.Decide([]*model.WorkloadView{aged()}, pol)[0]
		}
		if last.Action == model.ActionNoop {
			t.Fatalf("default path: expected PROACTIVE rotate on an overdue pod, got noop (reactiveOnly gate must not fire when off)")
		}
	}

	// (2) reactiveOnly, NO attack => CALM. The same overdue pod must NOOP — proactive churn suppressed.
	{
		e := NewCoverageEngine()
		e.Now = fixedNow
		pol := covPolicy(2)
		pol.ReactiveOnly = true
		for i := 0; i < 6; i++ {
			d := e.Decide([]*model.WorkloadView{aged()}, pol)[0]
			if d.Action != model.ActionNoop || d.Selected {
				t.Fatalf("reactiveOnly calm: expected noop/unselected with NO attack, got action=%s selected=%v", d.Action, d.Selected)
			}
		}
	}

	// (3) reactiveOnly + a real targeting SecurityEvent => REACTS (rotate selected).
	{
		e := NewCoverageEngine()
		e.Now = fixedNow
		pol := covPolicy(2)
		pol.ReactiveOnly = true
		attacked := func() *model.WorkloadView {
			v := aged()
			v.Events = []model.SecurityEventInfo{{Type: "Panic", ThreatLevel: "critical", TargetsPod: true}}
			return v
		}
		var last model.Decision
		for i := 0; i < 6; i++ {
			last = e.Decide([]*model.WorkloadView{attacked()}, pol)[0]
		}
		if last.Action == model.ActionNoop || !last.Selected {
			t.Fatalf("reactiveOnly reactive: expected rotate/selected UNDER ATTACK, got action=%s selected=%v", last.Action, last.Selected)
		}
	}
}
