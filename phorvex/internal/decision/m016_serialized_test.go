package decision

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM016SerializedFallbackAndSelection(t *testing.T) {
	views := []*model.WorkloadView{covView("a", true, 2*time.Hour, false), covView("b", true, 2*time.Hour, false), covView("c", true, 2*time.Hour, false)}
	pol := covPolicy(1)
	pol.Lambda = 0
	decisions := NewCoverageEngine().Decide(views, pol)
	var buf bytes.Buffer
	logger := audit.New(logr.Discard(), &buf)
	for _, d := range decisions {
		logger.Record(d)
	}
	dec := json.NewDecoder(&buf)
	selected, fallback := 0, 0
	var signature []map[string]any
	for _, d := range decisions {
		var r audit.Record
		if err := dec.Decode(&r); err != nil {
			t.Fatal(err)
		}
		if r.Pod != d.Pod || r.Action != string(d.Action) || r.Selected != d.Selected || r.Actuated != d.Actuated || r.Feasible != d.Feasible || r.Cost != math.Round(d.Cost*1e4)/1e4 || r.Net != math.Round(d.Net*1e4)/1e4 || r.CoverageValue != math.Round(d.CoverageValue*1e4)/1e4 {
			t.Fatal("serialization changed structured facts")
		}
		signature = append(signature, map[string]any{"pod": r.Pod, "action": r.Action, "selected": r.Selected, "actuated": r.Actuated, "feasible": r.Feasible, "cost": r.Cost, "net": r.Net, "coverageValue": r.CoverageValue, "lambda": r.Lambda, "rawCost": d.Cost, "rawNet": d.Net, "rawCoverage": d.CoverageValue})
		if r.Selected {
			selected++
			if !strings.Contains(r.Reason, "strict gain") || strings.Contains(r.Reason, "considered") {
				t.Fatal(r.Reason)
			}
		} else {
			fallback++
			if r.Action == "noop" || !r.Feasible || r.Actuated {
				t.Fatal("fixture did not reach feasible unselected fallback")
			}
			if !strings.HasPrefix(r.Reason, r.Action+": considered (") {
				t.Error("fallback mislabeled:", r.Reason)
			}
		}
	}
	if selected != 1 || fallback != 2 {
		t.Fatalf("positive controls: selected=%d fallback=%d", selected, fallback)
	}
	if path := os.Getenv("M016_SIGNATURE"); path != "" {
		raw, _ := json.MarshalIndent(signature, "", "  ")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("actual engine -> audit JSONL: selected=%d fallback=%d", selected, fallback)
}

func TestM016NoCandidateDoesNotInventAction(t *testing.T) {
	pol := covPolicy(1)
	pol.EnabledActions = map[model.Action]bool{model.ActionRotate: false, model.ActionQuarantine: false}
	ds := NewCoverageEngine().Decide([]*model.WorkloadView{covView("none", true, 2*time.Hour, false)}, pol)
	if len(ds) != 1 {
		t.Fatal("missing noop positive control")
	}
	var buf bytes.Buffer
	audit.New(logr.Discard(), &buf).Record(ds[0])
	var r audit.Record
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &r); err != nil {
		t.Fatal(err)
	}
	if r.Action != "noop" || r.Selected || r.Actuated || strings.Contains(r.Reason, "considered") {
		t.Fatalf("fabricated candidate: %+v", r)
	}
}
