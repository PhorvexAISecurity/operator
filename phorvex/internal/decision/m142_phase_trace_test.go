package decision

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM142DecisionTraceSerializesUncertainPhaseReason(t *testing.T) {
	view := covView("uncertain", true, 2*time.Hour, false)
	view.Phase = model.PhaseWarm
	view.PhaseReason = ingest.PhaseReasonWarmUncertain
	view.Telemetry.ReqRate = model.Signal{State: model.Stale, Src: "prometheus-http", Reason: model.ReasonStale}

	decisions := fixedTraceEngine().Decide([]*model.WorkloadView{view}, decisionTracePolicy(1, true))
	if len(decisions) != 1 || decisions[0].Trace == nil {
		t.Fatalf("decision trace missing: %+v", decisions)
	}
	trace := decisions[0].Trace
	if trace.Inputs.Phase != string(model.PhaseWarm) || trace.Inputs.PhaseReason != ingest.PhaseReasonWarmUncertain {
		t.Fatalf("trace phase/reason = %q/%q", trace.Inputs.Phase, trace.Inputs.PhaseReason)
	}
	raw, err := json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"phase":"Warm"`) || !strings.Contains(string(raw), `"phaseReason":"warm-uncertain-app-signal"`) {
		t.Fatalf("serialized trace omitted phase/reason: %s", raw)
	}
}
