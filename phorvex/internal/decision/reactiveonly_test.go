/*
 * Phorvex — reactiveOnly: calm baseline (no proactive churn) until a real attack signal
 * targets the asset, then a clean attributable reaction. Default (reactiveOnly=false) is
 * the proactive moving-target path and is covered byte-identically by the O1 golden.
 */

package decision

import (
	"math"
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

func TestReactiveOnlyAblationUsesTheSameAttackBackedSubstrate(t *testing.T) {
	calm := covView("calm", true, 2*time.Hour, false)
	attacked := covView("attacked", true, 2*time.Hour, false)
	attacked.Events = []model.SecurityEventInfo{{Type: "Panic", ThreatLevel: "critical", TargetsPod: true}}

	pol := covPolicy(2)
	pol.ReactiveOnly = true

	res := NewCoverageEngine().Ablate([]*model.WorkloadView{calm, attacked}, pol, []int64{1, 2, 3})
	if res.Assets != 1 {
		t.Fatalf("benchmark substrate assets=%d, want only the one directly attacked asset", res.Assets)
	}
	if res.ExactSkipped || !res.CoversDisjoint || math.Abs(res.OptimalityRatio-1) > 1e-12 {
		t.Fatalf("reactive-only exact comparison is not like-for-like: %+v", res.OptimalityOut)
	}
	if res.GreedyObjective <= 0 || math.Abs(res.GreedyObjective-res.ExactObjective) > 1e-12 {
		t.Fatalf("greedy/exact objective mismatch: greedy=%v exact=%v", res.GreedyObjective, res.ExactObjective)
	}

	calmOnly := NewCoverageEngine().Ablate([]*model.WorkloadView{calm}, pol, []int64{1})
	if calmOnly.Assets != 0 || calmOnly.Candidates != 0 || calmOnly.GreedyObjective != 0 ||
		calmOnly.ExactObjective != 0 || calmOnly.OptimalityRatio != 1 {
		t.Fatalf("calm reactive-only benchmark must compare two empty selections: %+v", calmOnly)
	}
}

// The containment must isolate the COMPROMISED node, not a clean neighbor of it. broker-0 carries the
// DIRECT foothold (TargetsPod=true) but a modest lateral edge; broker-2 is a clean NEIGHBOR (only a
// propagated TargetsPod=false event) with a FATTER edge — so a coverage-only greedy would wrongly pick
// broker-2 (the pre-fix bug: attack on nats-0, quarantine of nats-2). Only the compromised broker-0 may
// be contained. This test FAILS on the pre-fix gate (which backed neighbors too).
func TestReactiveOnly_ContainsCompromisedNodeNotNeighbor(t *testing.T) {
	fixedNow := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	mk := func(name string, direct bool, nbVal float64) *model.WorkloadView {
		v := covView(name, true, time.Hour, true) // stateful broker, secrets, aged
		v.Neighbors = []model.NeighborRef{{Key: "ns/peer", Value: nbVal}}
		v.Events = []model.SecurityEventInfo{{Type: "Panic", ThreatLevel: "critical", TargetsPod: direct}}
		return v
	}
	views := []*model.WorkloadView{
		mk("broker-0", true, 5.0),  // the real foothold
		mk("broker-1", false, 5.0), // clean neighbor
		mk("broker-2", false, 9.0), // clean neighbor with the fattest edge (would win a coverage-only pick)
	}
	e := NewCoverageEngine()
	e.Now = fixedNow
	pol := covPolicy(1)
	pol.ReactiveOnly = true

	var decs []model.Decision
	for i := 0; i < 4; i++ {
		decs = e.Decide(views, pol)
	}
	byPod := map[string]model.Decision{}
	for _, d := range decs {
		byPod[d.Pod] = d
	}
	if !byPod["broker-0"].Selected || byPod["broker-0"].Action == model.ActionNoop {
		t.Fatalf("the COMPROMISED node broker-0 must be contained; got selected=%v action=%s", byPod["broker-0"].Selected, byPod["broker-0"].Action)
	}
	if byPod["broker-0"].Action != model.ActionQuarantine {
		t.Fatalf("stateful broker-0 must be QUARANTINED (rotate vetoed), got %s", byPod["broker-0"].Action)
	}
	for _, n := range []string{"broker-1", "broker-2"} {
		if byPod[n].Selected {
			t.Fatalf("%s is a clean NEIGHBOR (TargetsPod=false) — must NOT be quarantined; got action=%s", n, byPod[n].Action)
		}
	}
	t.Logf("contained the compromised node: broker-0 -> quarantine; clean neighbors broker-1/broker-2 untouched")
}
