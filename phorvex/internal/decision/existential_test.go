package decision

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

func m99Fixture() (*model.WorkloadView, model.Policy) {
	v := covView("protected", true, 2*time.Hour, false)
	p := covPolicy(1)
	p.PolicyUID = "policy-v1"
	p.TrustBoundaryReady = true
	r := model.ProtectedOutcome{ID: "r", PolicyUID: p.PolicyUID, DecisionAsset: "ns/protected", DecisionAssetUID: v.Pod.UID, ProtectedAsset: "dataset", Version: "v1", Portion: "undisclosed-records", Property: "confidentiality", Outcome: "unauthorized-disclosure", ClassBasis: "protected customer data", ScopeBasis: "this scope contains every relevant copy", LossState: "at-risk", StateBasis: "trusted detector confirms preventable exfiltration", RequiredKeys: []string{"e"}, MappingComplete: true, MappingBasis: "invalidation interrupts this scoped channel"}
	ev := model.SecurityEventInfo{Name: "detector-evidence", Trust: "trusted", CreatorIdentity: "system:serviceaccount:ns:detector", ResolvedTargets: []string{"ns/protected"}, TargetsPod: true, Outcomes: []model.ProtectedOutcome{r}}
	v.OutcomeEvents = []model.SecurityEventInfo{ev}
	v.Events = []model.SecurityEventInfo{ev}
	return v, p
}

func pickM99(set actionset.ActionSet, states map[string]*model.ExistentialDecision, lambda float64, covered, selected map[string]bool) int {
	attack := map[string]bool{}
	for _, c := range set.Candidates {
		attack[c.Key] = true
	}
	i, _, _ := chooseRound(set, states, covered, selected, attack, lambda, func(string) float64 { return 1 }, map[string]float64{})
	return i
}

func TestM99RulingNumericCounterexample(t *testing.T) {
	v, p := m99Fixture()
	active := assessOutcomes(v, p)
	set := actionset.ActionSet{FactWeights: map[string]float64{"u": 100, "e": 10}, Candidates: []actionset.Candidate{
		{Key: "ns/protected", Action: model.ActionQuarantine, CoverKeys: []string{"u"}, ECost: 1},
		{Key: "ns/protected", Action: model.ActionRotate, CoverKeys: []string{"u", "e"}, ECost: 5, GenerationRank: 1}}}
	for _, lambda := range []float64{0, 1, 10, 22, 30, 100} {
		t.Run(fmt.Sprint(lambda), func(t *testing.T) {
			if i := pickM99(set, map[string]*model.ExistentialDecision{"ns/protected": active}, lambda, nil, nil); i != 1 {
				t.Fatalf("M99 selected %d, want full-containing B", i)
			}
			legacy := pickM99(set, map[string]*model.ExistentialDecision{"ns/protected": {}}, lambda, nil, nil)
			want := 1
			if lambda >= 10 {
				want = 0
			}
			if lambda >= 100 {
				want = -1
			}
			if legacy != want {
				t.Fatalf("legacy=%d want %d", legacy, want)
			}
		})
	}
	for _, cost := range []float64{0, 1, 5, 1e9} {
		set.Candidates[1].ECost = cost
		if pickM99(set, map[string]*model.ExistentialDecision{"ns/protected": active}, 10, nil, nil) != 1 {
			t.Fatal("finite cost outbid containment")
		}
	}
}

func TestM99EvidenceClassificationAndBinding(t *testing.T) {
	cases := []struct {
		name            string
		mutate          func(*model.WorkloadView, *model.Policy)
		active, trusted bool
	}{
		{"qualified", func(*model.WorkloadView, *model.Policy) {}, true, true},
		{"forged-source", func(v *model.WorkloadView, p *model.Policy) {
			v.OutcomeEvents[0].Trust = "untrusted-identity"
			v.OutcomeEvents[0].Source = "TrustedDetector"
		}, false, false},
		{"missing-stamp", func(v *model.WorkloadView, p *model.Policy) { v.OutcomeEvents[0].CreatorIdentity = "" }, false, false},
		{"missing-time", func(v *model.WorkloadView, p *model.Policy) { v.OutcomeEvents[0].TimestampMissing = true }, false, false},
		{"expired-evidence", func(v *model.WorkloadView, p *model.Policy) { v.OutcomeEvents[0].Age = 2 * time.Hour }, false, false},
		{"boundary-absent", func(v *model.WorkloadView, p *model.Policy) {
			p.TrustBoundaryReady = false
			p.TrustBoundaryReason = "webhook-absent"
		}, false, false},
		{"unrelated-event-target", func(v *model.WorkloadView, p *model.Policy) {
			v.OutcomeEvents[0].ResolvedTargets = []string{"ns/other"}
		}, false, false},
		{"wrong-version", func(v *model.WorkloadView, p *model.Policy) {
			v.OutcomeEvents[0].Outcomes[0].DecisionAssetUID = "old-pod"
		}, false, false},
		{"scope-unresolved", func(v *model.WorkloadView, p *model.Policy) { v.OutcomeEvents[0].Outcomes[0].ScopeBasis = "" }, false, false},
		{"already-lost", func(v *model.WorkloadView, p *model.Policy) {
			v.OutcomeEvents[0].Outcomes[0].LossState = "already-lost"
		}, false, true},
		{"unknown", func(v *model.WorkloadView, p *model.Policy) { v.OutcomeEvents[0].Outcomes[0].LossState = "unknown" }, false, true},
		{"recoverable-persistence", func(v *model.WorkloadView, p *model.Policy) {
			r := &v.OutcomeEvents[0].Outcomes[0]
			r.Outcome = "control-integrity-loss"
			r.Recovery = "trusted-rebuild-restore"
		}, false, true},
		{"unrecoverable-control", func(v *model.WorkloadView, p *model.Policy) {
			r := &v.OutcomeEvents[0].Outcomes[0]
			r.Outcome = "control-integrity-loss"
			r.Recovery = "no-trustworthy-recovery"
		}, true, true},
		{"recovery-unknown", func(v *model.WorkloadView, p *model.Policy) {
			v.OutcomeEvents[0].Outcomes[0].Outcome = "control-integrity-loss"
		}, false, true},
		{"model-identity-not-theft", func(v *model.WorkloadView, p *model.Policy) { v.OutcomeEvents[0].Outcomes[0].Outcome = "modelIdentity" }, false, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v, p := m99Fixture()
			tt.mutate(v, &p)
			d := assessOutcomes(v, p)
			if d.Present != tt.active || d.TrustedEvidence != tt.trusted {
				t.Fatalf("got %+v", d)
			}
		})
	}
}

func TestM99MixedLossCannotSuppressRisk(t *testing.T) {
	v, p := m99Fixture()
	ev := v.OutcomeEvents[0]
	for _, state := range []string{"already-lost", "unknown"} {
		r := ev.Outcomes[0]
		r.Portion = state
		r.LossState = state
		v.OutcomeEvents[0].Outcomes = append(v.OutcomeEvents[0].Outcomes, r)
	}
	forged := ev
	forged.Outcomes = append([]model.ProtectedOutcome(nil), ev.Outcomes...)
	forged.Outcomes[0].LossState = "already-lost"
	forged.Trust = "untrusted-identity"
	v.OutcomeEvents = append(v.OutcomeEvents, forged)
	d := assessOutcomes(v, p)
	if !d.Present || len(d.Evidence) != 4 {
		t.Fatalf("lost/unknown erased remaining risk: %+v", d)
	}
	if !containment(actionset.Candidate{CoverKeys: []string{"e"}}, d).Contains {
		t.Fatal("untrusted/lost records incorrectly expanded forcing set")
	}
}

func TestM99PartialAuditOnlyAndEmptyMapping(t *testing.T) {
	for _, mode := range []string{"two-partial", "audit-only", "empty", "unmapped"} {
		t.Run(mode, func(t *testing.T) {
			v, p := m99Fixture()
			r := &v.OutcomeEvents[0].Outcomes[0]
			switch mode {
			case "two-partial":
				r.RequiredKeys = []string{"e", "f"}
			case "audit-only":
				r.RequiredKeys = []string{"audit-only"}
			case "empty":
				r.RequiredKeys = nil
			case "unmapped":
				r.MappingComplete = false
			}
			d := assessOutcomes(v, p)
			set := actionset.ActionSet{FactWeights: map[string]float64{"e": 100, "f": 1}, Candidates: []actionset.Candidate{{Key: "ns/protected", CoverKeys: []string{"e"}}, {Key: "ns/protected", CoverKeys: []string{"f"}}}}
			if !d.Present || pickM99(set, map[string]*model.ExistentialDecision{"ns/protected": d}, 0, nil, nil) != -1 {
				t.Fatal("missing/partial representation received containment")
			}
			finishExistential(d, set, "ns/protected", false, 1, nil)
			if d.Result != "uncontainable" {
				t.Fatal(d.Result)
			}
		})
	}
}

func TestM99SharedBudgetSLOTiesAndPredictedCover(t *testing.T) {
	v, p := m99Fixture()
	d := assessOutcomes(v, p)
	states := map[string]*model.ExistentialDecision{"ns/protected": d, "ordinary": {}}
	set := actionset.ActionSet{FactWeights: map[string]float64{"e": 10, "ordinary": 10000}, Candidates: []actionset.Candidate{{Key: "ordinary", CoverKeys: []string{"ordinary"}}, {Key: "ns/protected", CoverKeys: []string{"e"}, ECost: 50, GenerationRank: 1}}}
	if pickM99(set, states, 10, nil, nil) != 1 {
		t.Fatal("ordinary action consumed priority slot")
	}
	if pickM99(set, states, 10, map[string]bool{"e": true}, nil) != 1 {
		t.Fatal("predicted cover erased exposure")
	}
	if pickM99(set, states, 10, nil, map[string]bool{"ns/protected": true}) != 0 {
		t.Fatal("partition allowed second action")
	}
	set.Candidates[0] = set.Candidates[1]
	set.Candidates[0].ECost = 0
	set.Candidates[0].SLOExclusions = []string{"conformal-slo"}
	if pickM99(set, states, 10, nil, nil) != 1 {
		t.Fatal("cheap breaching candidate beat SLO-safe containment")
	}
	set.Candidates[0] = set.Candidates[1]
	set.Candidates[0].GenerationRank = 0
	if pickM99(set, states, 10, nil, nil) != 0 {
		t.Fatal("exact tie did not retain generation order")
	}
	finishExistential(d, set, "ns/protected", false, 0, []string{"other:rotate"})
	if d.Result != "uncontainable" || len(d.Reasons) < 1 {
		t.Fatal("budget bound missing")
	}
}

// Real production generator/engine fixture: required key comes from the existing
// SOUND rotate grant, not a manufactured grant in the M99 implementation.
func bindRotate(t *testing.T, e *CoverageEngine, v *model.WorkloadView, p model.Policy) {
	t.Helper()
	set, _ := e.AssembleSet([]*model.WorkloadView{v}, p)
	for _, c := range set.Candidates {
		if c.Action == model.ActionRotate {
			v.OutcomeEvents[0].Outcomes[0].RequiredKeys = append([]string(nil), c.CoverKeys...)
			return
		}
	}
	t.Fatal("fixture has no rotate grant")
}

func TestM99ProductionEngineSLOAndRetainedGates(t *testing.T) {
	for _, mode := range []string{"slo-off", "slo-on", "slo-stateful", "slo-rotation", "slo-no-trust", "no-budget", "rbac-unknown"} {
		t.Run(mode, func(t *testing.T) {
			v, p := m99Fixture()
			e := NewCoverageEngine()
			bindRotate(t, e, v, p)
			p.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
			p.CostCeiling = 1e-9
			p.MayBreachSLO = mode != "slo-off"
			switch mode {
			case "slo-stateful":
				v.Pod.Stateful = true
			case "slo-rotation":
				v.ExposureByVariable = allVarsAt(time.Second)
			case "slo-no-trust":
				v.OutcomeEvents[0].Trust = "untrusted-identity"
			case "no-budget":
				p.MaxMovesPerTick = 0
			case "rbac-unknown":
				e.Capability = func(*model.WorkloadView, model.Action, []string) *actionset.Eligibility {
					return &actionset.Eligibility{RBACUnknown: true}
				}
			}
			ds, err := e.DecideChecked([]*model.WorkloadView{v}, p)
			if err != nil {
				t.Fatal(err)
			}
			d := ds[0]
			if d.Selected != (mode == "slo-on") {
				t.Fatalf("selection=%v reason=%s existential=%+v", d.Selected, d.InfeasibleWhy, d.Existential)
			}
			if mode == "slo-on" && (!d.Existential.Candidates[0].SLORelaxed || d.Existential.EffectStatus != "not-attempted") {
				t.Fatal("missing SLO exception or fabricated effect")
			}
			if mode != "slo-on" && mode != "slo-no-trust" && d.Existential.Result != "uncontainable" {
				t.Fatal("missing uncontainable result")
			}
		})
	}
}

func TestM99InactiveProductionControl(t *testing.T) {
	v, p := m99Fixture()
	v.OutcomeEvents = nil
	e := NewCoverageEngine()
	e.Now = func() time.Time { return time.Unix(123, 0) }
	before := e.Decide([]*model.WorkloadView{v}, p)[0]
	v, p = m99Fixture()
	v.OutcomeEvents[0].Trust = "untrusted-identity"
	p.MayBreachSLO = true
	e = NewCoverageEngine()
	e.Now = func() time.Time { return time.Unix(123, 0) }
	after := e.Decide([]*model.WorkloadView{v}, p)[0]
	before.Existential = nil
	after.Existential = nil
	if !reflect.DeepEqual(before, after) {
		t.Fatal("inactive override changed baseline decision or numerical fields")
	}
	// Physics/severity do not create an outcome record.
	v.OutcomeEvents = nil
	v.Physics = model.NeutralPhysics()
	if assessOutcomes(v, p).Present {
		t.Fatal("physics-only trigger")
	}
}

func TestM99EstablishedLossAndPreBoundaryForgery(t *testing.T) {
	v, p := m99Fixture()
	lost := v.OutcomeEvents[0]
	lost.Outcomes = append([]model.ProtectedOutcome(nil), lost.Outcomes...)
	lost.Outcomes[0].LossState = "already-lost"
	v.OutcomeEvents = append(v.OutcomeEvents, lost)
	d := assessOutcomes(v, p)
	if d.Present {
		t.Fatal("established loss got prevention credit")
	}
	v, p = m99Fixture()
	p.TrustBoundarySince = time.Unix(100, 0)
	v.OutcomeEvents[0].CreatedAt = time.Unix(99, 0)
	if assessOutcomes(v, p).Present {
		t.Fatal("pre-boundary event could carry forged stamp")
	}
	v.OutcomeEvents[0].CreatedAt = time.Unix(101, 0)
	if !assessOutcomes(v, p).Present {
		t.Fatal("post-boundary supported event inactive")
	}
}

func TestM99TraceAndRepresentativeRecords(t *testing.T) {
	var records []json.RawMessage
	for _, state := range []string{"at-risk", "already-lost", "unknown", "uncontainable", "slo-opt-in"} {
		t.Run(state, func(t *testing.T) {
			v, p := m99Fixture()
			e := NewCoverageEngine()
			bindRotate(t, e, v, p)
			p.TraceEnabled = true
			p.PolicyName = "synthetic-m99"
			p.TickID = "synthetic-tick"
			p.BrainImage = "test-only-not-deployed"
			p.GitSHA = os.Getenv("M99_RECORD_SHA")
			if p.GitSHA == "" {
				p.GitSHA = "synthetic-test"
			}
			p.EnabledActions = map[model.Action]bool{model.ActionRotate: true}
			p.Lambda = model.MaxDisruptionAversion
			switch state {
			case "uncontainable":
				v.OutcomeEvents[0].Outcomes[0].RequiredKeys = []string{"audit-only-unrepresented"}
			case "slo-opt-in":
				p.MayBreachSLO = true
				p.CostCeiling = 1e-9
			default:
				v.OutcomeEvents[0].Outcomes[0].LossState = state
			}
			e.Now = func() time.Time { return time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC) }
			d := e.Decide([]*model.WorkloadView{v}, p)[0]
			if err := d.Trace.Validate(); err != nil {
				t.Fatal(err)
			}
			if d.Existential.Present && d.Trace.SelectorComparator != model.SelectorM99Containment {
				t.Fatal("trace falsely describes positive-gain comparator")
			}
			b, err := json.Marshal(audit.ToRecord(d))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), `"existential"`) {
				t.Fatal("lost audit payload")
			}
			records = append(records, json.RawMessage(b))
		})
	}
	if path := os.Getenv("M99_RECORD_PATH"); path != "" {
		b, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestM99GenerationFailureRecordsObligation(t *testing.T) {
	v, p := m99Fixture()
	ds := ExistentialRejectedDecisions([]*model.WorkloadView{v}, p, "cross-block-collision", time.Unix(1, 0))
	if len(ds) != 1 || ds[0].Selected || ds[0].Existential.Result != "uncontainable" {
		t.Fatalf("rejection erased obligation: %+v", ds)
	}
	v.OutcomeEvents = nil
	if len(ExistentialRejectedDecisions([]*model.WorkloadView{v}, p, "cross-block-collision", time.Unix(1, 0))) != 0 {
		t.Fatal("baseline error path changed")
	}
}
