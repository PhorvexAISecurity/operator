package belief

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// event_horizon_test.go — PHORVEXSEC-188 / M-29: the event-decay horizon is τ_ev
// (Policy.EventAgeHorizon), not the move-cadence knob (ProactiveFloor), at ALL three sites.

func agedEventView() *model.WorkloadView {
	return &model.WorkloadView{Events: []model.SecurityEventInfo{{ThreatLevel: "high", TargetsPod: true, Age: 30 * time.Minute}}}
}

// Changing ProactiveFloor alone leaves the belief decay unchanged; changing EventAgeHorizon
// alone changes it. Fails on the old code (belief decayed over ProactiveFloor).
func TestBeliefDecayFollowsEventAgeHorizonNotFloor(t *testing.T) {
	base := model.Policy{EventDriven: true, ProactiveFloor: time.Hour, EventAgeHorizon: time.Hour}
	ref := (reconExposure{}).Belief(agedEventView(), base)

	floorOnly := base
	floorOnly.ProactiveFloor = 2 * time.Hour
	if got := (reconExposure{}).Belief(agedEventView(), floorOnly); got != ref {
		t.Fatalf("changing proactiveFloor alone moved the belief decay: %.6f -> %.6f (old behaviour: decay over the floor)", ref, got)
	}
	horizonOnly := base
	horizonOnly.EventAgeHorizon = 10 * time.Minute // 30 m event is past a 10 m horizon: weight 0
	if got := (reconExposure{}).Belief(agedEventView(), horizonOnly); !(got < ref) {
		t.Fatalf("changing eventAgeHorizon alone did not move the belief decay: %.6f vs %.6f", got, ref)
	}
	// Unset horizon uses the independent inherited one-hour default even when cadence differs.
	legacy := model.Policy{EventDriven: true, ProactiveFloor: 10 * time.Minute}
	if got := (reconExposure{}).Belief(agedEventView(), legacy); got != ref {
		t.Fatalf("unset horizon must use the one-hour default: %.6f vs %.6f", got, ref)
	}
}

// Static: no event-age decay at any of the three sites divides by ProactiveFloor. (The
// exposure clock legitimately reads ProactiveFloor; the pattern targets `e.Age` only.)
func TestNoEventDecaySiteReadsProactiveFloor(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..")
	bad := regexp.MustCompile(`e\.Age[^\n]*ProactiveFloor`)
	good := regexp.MustCompile(`EventAgeWeight\(e\.Age,`)
	for _, f := range []string{"belief/reconexposure.go", "ctxprov/sensed.go", "killchain/hazard.go"} {
		src, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if bad.Match(src) {
			t.Fatalf("%s still decays event age over ProactiveFloor", f)
		}
		if !good.Match(src) {
			t.Fatalf("%s does not use the shared EventAgeWeight over the event horizon", f)
		}
	}
}
