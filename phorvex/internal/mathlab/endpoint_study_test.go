package mathlab

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/cost/endpoint"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

const studyCaptureSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const studyReplaySHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// The source is a real recorder/engine tick, not a fabricated final selection.
func recordStudyTick(t *testing.T, reactive bool) *Snapshot {
	t.Helper()
	recon.Registry.SetDefault("ucw-recon")
	engine := decision.NewCoverageEngine()
	engine.Capability, engine.ShadowCapability = capabilityGate, capabilityGate
	engine.FailureExclusion = func(*model.WorkloadView, model.Action) (string, bool) { return "", false }
	pol, spec := fixturePolicy()
	pol.GitSHA, pol.ReactiveOnly = studyCaptureSHA, reactive
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	engine.Now = func() time.Time { return now }
	views := fleet()
	for _, v := range views {
		v.Pod.WorkloadSpec = model.WorkloadSpecObservation{Known: true, PodUID: v.Pod.UID, ObservedAt: now,
			Source: "test-controller-read", Workload: model.ObjectIdentity{Kind: "Deployment", Namespace: "vllm", Name: "fixture", UID: "workload-uid"}, SpecReplicas: 3}
	}
	sink := &memorySink{}
	r, err := NewRecorder(Config{Policies: []string{"vllm/vllm-defense"}, GPUEnvelopeMax: cost.GPUEnvelopeMax()}, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	capture := r.Begin(engine, spec, views, pol, now.Add(-time.Second))
	decisions, err := engine.DecideChecked(views, pol)
	capture.Decided(decisions, err)
	capture.Finalize(decisions)
	capture.Close()
	if err != nil || len(sink.items) != 1 {
		t.Fatalf("record tick: %v, items=%d", err, len(sink.items))
	}
	raw, err := assemble(sink.items[0].Header, sink.items[0].Stream)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func studyTrace(ex StudyCandidates) endpoint.Trace {
	tick := endpoint.Tick{ID: ex.SnapshotDigest, At: ex.At, PolicyUID: ex.PolicyUID, WorkloadUID: ex.WorkloadUID,
		SpecReplicas: ex.SpecReplicas, CandidateSetComplete: ex.CandidateSetComplete, MandatoryID: ex.MandatoryID,
		SLO:    &endpoint.SLO{Target: .5, Window: 600, StudyAssumption: true},
		Ledger: &endpoint.Ledger{At: ex.At, CompleteFrom: f(ex.At - 3600), Measurement: "watch-observed-service-ready-backends", Moves: []endpoint.Move{}}}
	for _, c := range ex.Candidates {
		one := 1
		c.K, c.WorthThreshold, c.HistoryKnown = &one, f(0), true
		c.HoldCap = f(30)
		tick.Candidates = append(tick.Candidates, c)
	}
	return endpoint.Trace{Schema: endpoint.TraceSchema, SourceRevision: ex.SourceRevision, Evidence: "recorded", Ticks: []endpoint.Tick{tick}}
}

func studyConfig() endpoint.Config {
	cfg := endpoint.Defaults()
	cfg.Lookback = 60 // explicit short fixture study, never claimed as a day of history
	return cfg
}

func TestEndpointStudyUsesRealPreCostPopulationAndExactBaseline(t *testing.T) {
	s := recordStudyTick(t, false)
	source := StudySource{ReplayGitSHA: studyCaptureSHA}
	ex := ExportStudyCandidates(s, source)
	if !ex.BaselineReproduced || !ex.CandidateSetComplete {
		t.Fatalf("source unavailable: %+v", ex)
	}
	retained, vetoed := false, false
	for _, c := range ex.Candidates {
		if c.PodUID == "uid-unmeasured" && c.Action == "rotate" {
			retained = len(c.Gates) == 0 && len(c.Facts) > 0
		}
		if c.PodUID == "uid-gated" && c.Action == "kv-reset" {
			vetoed = len(c.Gates) > 0
		}
		if c.HistoryKnown || c.K != nil {
			t.Fatal("source invented endpoint evidence")
		}
	}
	if !retained || !vetoed {
		t.Fatalf("cost-only survivor/non-cost veto missing: %+v", ex.Candidates)
	}
	trace := studyTrace(ex)
	result, err := RunEndpointStudy([]*Snapshot{s}, trace, studyConfig(), endpoint.FileStore{Dir: t.TempDir()}, source)
	if err != nil {
		t.Fatal(err)
	}
	if result.Mode != "PAIRED_BRAIN_REPLAY" || result.BaselineExactCount != 1 || !result.BrainParity || result.Comparable != 1 || result.Ticks[0].V2.Pick == nil {
		t.Fatalf("real brain study did not run both arms: %+v", result)
	}
	if result.CrossVersion || result.Observational || result.ActualCharges != nil || result.VerifiedFacts != nil {
		t.Fatal("source/counterfactual claims changed")
	}
	baseline, err := Replay(s, ReplayOptions{Arms: []Arm{{ID: "baseline"}}})
	if err != nil || !baseline[0].Baseline.Reproduced {
		t.Fatalf("study mutated production replay: %v", err)
	}
}

func TestEndpointStudyCrossSourceIsExplicitAndRetainsBothIdentities(t *testing.T) {
	s := recordStudyTick(t, false)
	source := StudySource{ReplayGitSHA: studyReplaySHA}
	ex := ExportStudyCandidates(s, source)
	if ex.CandidateSetComplete || !reflect.DeepEqual(ex.Missing, []string{"VERSION_MISMATCH"}) {
		t.Fatal(ex)
	}
	source.AllowCrossVersion = true
	ex = ExportStudyCandidates(s, source)
	if !ex.CandidateSetComplete || !ex.BaselineReproduced || !ex.CrossVersion || !ex.Observational || ex.SourceRevision != studyReplaySHA || ex.SnapshotSourceRevision != studyCaptureSHA {
		t.Fatal(ex)
	}
	result, err := RunEndpointStudy([]*Snapshot{s}, studyTrace(ex), studyConfig(), endpoint.FileStore{Dir: t.TempDir()}, source)
	if err != nil || result.ReplayGitSHA != studyReplaySHA || result.SnapshotSourceRevision != studyCaptureSHA || !result.CrossVersion || !result.Observational {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestEndpointStudyRejectsChangedSourceFieldsAndMissingControls(t *testing.T) {
	for _, change := range []string{"fact", "gate", "population", "tick", "workload", "baseline", "spec", "source"} {
		t.Run(change, func(t *testing.T) {
			s := recordStudyTick(t, false)
			source := StudySource{ReplayGitSHA: studyCaptureSHA}
			ex := ExportStudyCandidates(s, source)
			trace := studyTrace(ex)
			switch change {
			case "fact":
				trace.Ticks[0].Candidates[0].Facts = []endpoint.Fact{{ID: "invented", Weight: 999}}
			case "gate":
				trace.Ticks[0].Candidates[0].Gates = []string{"changed"}
			case "population":
				trace.Ticks[0].Candidates = trace.Ticks[0].Candidates[1:]
			case "tick":
				trace.Ticks[0].ID = "different"
			case "workload":
				trace.Ticks[0].WorkloadUID = "different"
			case "baseline":
				s.Outcome.Production = nil
			case "spec":
				s.Inputs.Views[0].Pod.WorkloadSpec.Known = false
			case "source":
				trace.SourceRevision = studyReplaySHA
			}
			_, err := RunEndpointStudy([]*Snapshot{s}, trace, studyConfig(), endpoint.FileStore{Dir: t.TempDir()}, source)
			if err == nil {
				t.Fatal("altered/missing source evidence accepted")
			}
		})
	}
}

func TestEndpointStudyDoesNotBackdateHistory(t *testing.T) {
	s := recordStudyTick(t, false)
	source := StudySource{ReplayGitSHA: studyCaptureSHA}
	trace := studyTrace(ExportStudyCandidates(s, source))
	result, err := RunEndpointStudy([]*Snapshot{s}, trace, endpoint.Defaults(), endpoint.FileStore{Dir: t.TempDir()}, source)
	if err != nil || result.State != "BLOCKED" || result.Comparable != 0 || result.MissingReasons["LOOKBACK_HISTORY_INCOMPLETE"] != 1 {
		t.Fatalf("short history was accepted for a day-long lookback: state=%s missing=%v err=%v", result.State, result.MissingReasons, err)
	}
}

func TestEndpointStudyMissingPriceCannotBeComparable(t *testing.T) {
	for _, missing := range []string{"censored-duration", "quarantine-hold"} {
		t.Run(missing, func(t *testing.T) {
			s := recordStudyTick(t, false)
			source := StudySource{ReplayGitSHA: studyCaptureSHA}
			trace := studyTrace(ExportStudyCandidates(s, source))
			for i := range trace.Ticks[0].Candidates {
				c := &trace.Ticks[0].Candidates[i]
				if missing == "quarantine-hold" && c.Action == "quarantine" {
					c.HoldCap = nil
				}
				if missing == "censored-duration" {
					c.Samples = []endpoint.Sample{{ID: "unfinished-calibration", WorkloadUID: trace.Ticks[0].WorkloadUID,
						Action: "rotate", At: trace.Ticks[0].At - 1, Censored: true}}
				}
			}
			result, err := RunEndpointStudy([]*Snapshot{s}, trace, studyConfig(), endpoint.FileStore{Dir: t.TempDir()}, source)
			if err != nil || result.State != "BLOCKED" || result.Comparable != 0 || len(result.MissingReasons) == 0 || !result.BrainParity {
				t.Fatalf("unknown price was comparable: state=%s count=%d missing=%v err=%v", result.State, result.Comparable, result.MissingReasons, err)
			}
		})
	}
}

func TestEndpointStudyRetainsReactiveOnlyGate(t *testing.T) {
	s := recordStudyTick(t, true)
	ex := ExportStudyCandidates(s, StudySource{ReplayGitSHA: studyCaptureSHA})
	if !ex.CandidateSetComplete {
		t.Fatal(ex.Missing)
	}
	found := false
	for _, c := range ex.Candidates {
		if c.PodUID == "uid-unmeasured" && c.Action == "rotate" {
			found = strings.Contains(strings.Join(c.Gates, ","), "reactive-only")
		}
	}
	if !found {
		t.Fatal("actual reactive-only veto not exported")
	}
}
