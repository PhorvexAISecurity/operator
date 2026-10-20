package decision

import (
	"encoding/json"
	"github.com/phorvex/phorvex/internal/model"
	"testing"
	"time"
)

func TestColocationAssessmentNeverEntersScoreOrCover(t *testing.T) {
	v := covView("colocation", true, time.Hour, false)
	v.Pod.Node = "n1"
	pol := covPolicy(2)
	pol.TraceEnabled = true
	makeDecisions := func() []model.Decision {
		e := NewCoverageEngine()
		e.Now = func() time.Time { return time.Unix(123, 0) }
		return e.Decide([]*model.WorkloadView{v}, pol)
	}
	baseline, _ := json.Marshal(makeDecisions())
	for _, flag := range []bool{false, true} {
		assessment := model.AssessColocation(model.ColocationInput{Target: v.Pod, TargetKnown: true, Pods: []model.Pod{v.Pod, {Namespace: "other", Name: "p", Node: "n1"}}, PodsComplete: true, PoliciesComplete: true, EventsComplete: true, NamespaceLabels: map[string]map[string]string{"other": {}}, CoverEnabled: flag})
		if assessment.State != "present" || assessment.ScoringAdmitted || assessment.Weight.Value != nil {
			t.Fatalf("bad assessment: %+v", assessment)
		}
		decisions := makeDecisions()
		actual, _ := json.Marshal(decisions)
		if string(actual) != string(baseline) {
			t.Fatal("observational assessment changed decisions")
		}
		for _, d := range decisions {
			if d.Selected && d.Action == model.ActionWarmSwap {
				t.Fatal("unresolved colocation admitted warm-swap")
			}
		}
	}
}
