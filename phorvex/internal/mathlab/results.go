package mathlab

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
)

// Gate statuses (math-lab.gate.v1). A diagnostic is never an actual status.
const (
	GatePass          = "PASS"
	GateFail          = "FAIL"
	GateNotEvaluated  = "NOT_EVALUATED"
	GateUnavailable   = "UNAVAILABLE"
	GateNotApplicable = "NOT_APPLICABLE"

	DiagPass    = "DIAGNOSTIC_PASS"
	DiagFail    = "DIAGNOSTIC_FAIL"
	DiagUnknown = "UNKNOWN"

	G9Pass             = "G9_PASS"
	G9SoleVetoVerified = "G9_SOLE_VETO_VERIFIED"
	G9MultiVeto        = "G9_MULTI_VETO_VERIFIED"
	G9WouldPassAfter   = "G9_WOULD_PASS_AFTER_EARLIER_VETO"
	G9Unknown          = "G9_UNKNOWN_OTHER_GATES"

	NoopSelected               = ""
	NoopNoFeasibleCandidate    = "NO_FEASIBLE_CANDIDATE"
	NoopNonPositiveGain        = "FEASIBLE_NONPOSITIVE_GAIN"
	NoopPositiveNotSelected    = "FEASIBLE_POSITIVE_BUT_NOT_SELECTED"
	NoopReactiveOnly           = "REACTIVE_ONLY_NOT_ATTACK_BACKED"
	NoopTickRejected           = "TICK_REJECTED"
	NoopUnknown                = "UNKNOWN"
	DispatchCounterfactualOnly = "COUNTERFACTUAL_NOT_DISPATCHED"
)

// SnapshotRef identifies the snapshot every row came from.
type SnapshotRef struct {
	Digest                string    `json:"snapshot_digest"`
	CapturedAt            time.Time `json:"captured_at"`
	GitSHA                string    `json:"git_sha"`
	BrainImage            string    `json:"brain_image"`
	TickID                string    `json:"tick_id"`
	Namespace             string    `json:"namespace"`
	PolicyName            string    `json:"policy_name"`
	PolicyUID             string    `json:"policy_uid"`
	ParameterManifestHash string    `json:"parameter_manifest_hash"`
	PolicyOverridesHash   string    `json:"policy_overrides_hash"`
	ProcessConfigHash     string    `json:"process_config_hash"`
	EconomicsMode         string    `json:"economics_mode"`
}

func (s *Snapshot) ref() SnapshotRef {
	h := s.Header
	return SnapshotRef{Digest: s.Digest, CapturedAt: h.CapturedAt, GitSHA: h.GitSHA, BrainImage: h.BrainImage, TickID: h.TickID,
		Namespace: h.Namespace, PolicyName: h.PolicyName, PolicyUID: h.PolicyUID, ParameterManifestHash: h.ParameterManifestHash,
		PolicyOverridesHash: h.PolicyOverridesHash, ProcessConfigHash: h.ProcessConfigHash, EconomicsMode: h.EconomicsMode}
}

// ArmResult is the complete replay output for one (snapshot, arm).
type ArmResult struct {
	Schema              string           `json:"schema_version"`
	Snapshot            SnapshotRef      `json:"snapshot"`
	ArmID               string           `json:"arm_id"`
	Overrides           []Override       `json:"overrides,omitempty"`
	Status              string           `json:"status"`
	Reasons             []string         `json:"reasons,omitempty"`
	PolicyDiff          []FieldDiff      `json:"policy_diff,omitempty"`
	ArmPolicyOverrides  string           `json:"arm_policy_overrides_hash,omitempty"`
	EconomicsMode       string           `json:"arm_economics_mode,omitempty"`
	CostCoefficient     *float64         `json:"arm_effective_cost_coefficient,omitempty"`
	CostCeiling         float64          `json:"arm_cost_ceiling_effective,omitempty"`
	MaxMovesPerTick     int              `json:"arm_max_moves_per_tick"`
	ReplayError         string           `json:"replay_error,omitempty"`
	ReplaySeconds       float64          `json:"replay_seconds"`
	FactWeightsMatch    *bool            `json:"fact_weights_match_baseline,omitempty"`
	Baseline            *BaselineCheck   `json:"baseline_check,omitempty"`
	ChangedVsBaseline   *bool            `json:"selected_set_changed_vs_baseline,omitempty"`
	SelectedSet         []string         `json:"selected_set"`
	EstimatedObjective  float64          `json:"estimated_objective_m_p18"`
	CommonWeightCovered float64          `json:"common_weight_covered"`
	Decisions           []DecisionRow    `json:"decisions"`
	Candidates          []CandidateRow   `json:"candidates"`
	Gates               []GateRow        `json:"gates"`
	Costs               []CostRow        `json:"costs"`
	Funnel              Funnel           `json:"funnel"`
	Dispatch            []DispatchRecord `json:"dispatch,omitempty"`
}

// BaselineCheck is the R-01 exact-reproduction verdict.
type BaselineCheck struct {
	Reproduced      bool     `json:"reproduced"`
	ComparedRecords int      `json:"compared_records"`
	Mismatches      []string `json:"mismatches,omitempty"`
	ExcludedFields  []string `json:"excluded_fields"`
	ProductionError string   `json:"production_error,omitempty"`
}

// DecisionRow is one asset's decision under one arm (math-lab.decision.v1).
type DecisionRow struct {
	Asset                string   `json:"asset"`
	AssetUID             string   `json:"asset_uid"`
	Action               string   `json:"action"`
	Selected             bool     `json:"selected"`
	Feasible             bool     `json:"feasible"`
	AttackBacked         bool     `json:"attack_backed"`
	Admitted             int      `json:"admitted_candidates"`
	PositiveGain         int      `json:"positive_gain_candidates"`
	NoopReason           string   `json:"noop_reason,omitempty"`
	EngineNoopReason     string   `json:"engine_noop_reason,omitempty"`
	CoverageValue        float64  `json:"coverage_value"`
	CommonWeightCovered  float64  `json:"common_weight_covered"`
	ExpectedCost         *float64 `json:"expected_cost,omitempty"`
	CostHigh             *float64 `json:"c_hi,omitempty"`
	CNorm                *float64 `json:"c_norm,omitempty"`
	CFlow                *float64 `json:"c_flow,omitempty"`
	NetGain              *float64 `json:"net_gain,omitempty"`
	ObjectivePenalty     *float64 `json:"objective_penalty,omitempty"`
	DispatchStatus       string   `json:"dispatch_status"`
	ConfirmationStatus   string   `json:"confirmation_status"`
	SecurityVerified     bool     `json:"security_outcome_verified"`
	ExistentialQualified bool     `json:"existential_qualified"`
}

// CandidateRow summarizes one enabled (asset, action) pair.
type CandidateRow struct {
	Asset           string   `json:"asset"`
	Action          string   `json:"action"`
	FirstVetoGate   string   `json:"first_veto_gate,omitempty"`
	FirstVetoReason string   `json:"first_veto_reason,omitempty"`
	EligibilityKind string   `json:"eligibility_kind,omitempty"`
	FeasibilityLaw  string   `json:"feasibility_law,omitempty"`
	Admitted        bool     `json:"admitted"`
	Scored          bool     `json:"scored"`
	NetGain         *float64 `json:"net_gain,omitempty"`
	Selected        bool     `json:"selected"`
	G9Category      string   `json:"g9_category"`
	ExpectedCost    *float64 `json:"expected_cost,omitempty"`
	CostHigh        *float64 `json:"c_hi,omitempty"`
}

// GateRow is one (candidate, gate) observation (math-lab.gate.v1).
type GateRow struct {
	Asset               string `json:"asset"`
	AssetUID            string `json:"asset_uid"`
	Action              string `json:"action"`
	GateID              string `json:"gate_id"`
	Law                 string `json:"law,omitempty"`
	ActualStatus        string `json:"actual_status"`
	FirstVeto           bool   `json:"first_veto"`
	ReasonCode          string `json:"reason_code,omitempty"`
	Reason              string `json:"reason,omitempty"`
	TelemetryStatus     string `json:"telemetry_status,omitempty"`
	DiagnosticStatus    string `json:"diagnostic_status,omitempty"`
	CounterfactualOnly  bool   `json:"counterfactual_only"`
	DiagnosticEvaluator string `json:"diagnostic_evaluator,omitempty"`
	WouldPassAllOther   string `json:"would_pass_all_other_gates,omitempty"`
}

// CostRow is one costed candidate's expected cost terms (math-lab.cost.v1). Replay never
// observes a realized cost, so realized fields are always NOT_OBSERVED here.
type CostRow struct {
	Asset                string  `json:"asset"`
	Action               string  `json:"action"`
	ActionFamily         string  `json:"action_family"`
	CNormExpected        float64 `json:"c_norm_expected"`
	CFlowExpected        float64 `json:"c_flow_expected"`
	ExpectedCostWeighted float64 `json:"expected_cost_weighted"`
	CHi                  float64 `json:"c_hi"`
	CostCeilingEffective float64 `json:"cost_ceiling_effective"`
	FlowRegime           string  `json:"flow_regime,omitempty"`
	FlowPredictedMean    float64 `json:"flow_predicted_mean"`
	FlowFloorApplied     bool    `json:"flow_floor_applied"`
	FlowUncertainty      bool    `json:"flow_uncertainty_applied"`
	ConformalReady       bool    `json:"conformal_window_ready"`
	GPUEnvelopeApplied   bool    `json:"gpu_envelope_applied"`
	MissingLoadRegime    bool    `json:"missing_load_regime"`
	NaNCategory          string  `json:"unactionable_category,omitempty"`
	RealizedStatus       string  `json:"realized_status"`
	CompatibleComparison bool    `json:"compatible_comparison"`
}

// Funnel holds the disjoint population counts for one (snapshot, arm).
type Funnel struct {
	Assets               int            `json:"assets"`
	AttackBackedAssets   int            `json:"attack_backed_assets"`
	EnabledPairs         int            `json:"enabled_pairs"`
	FirstVetoByGate      map[string]int `json:"first_veto_by_gate"`
	Admitted             int            `json:"admitted"`
	Scored               int            `json:"scored"`
	PositiveGain         int            `json:"positive_gain"`
	Selected             int            `json:"selected"`
	NoopByReason         map[string]int `json:"noop_by_reason"`
	UsefulFeasibleAssets int            `json:"attack_backed_assets_with_positive_gain_feasible"`
	CompleteEvidence     bool           `json:"complete_feasible_evidence"`
	G9Categories         map[string]int `json:"g9_categories"`
	UnassessedGatePairs  int            `json:"unassessed_gate_pairs"`
	ApplicableGatePairs  int            `json:"applicable_gate_pairs"`
}

// DispatchRecord is the production dispatch evidence for one asset (baseline only).
type DispatchRecord struct {
	Asset           string `json:"asset"`
	Selected        bool   `json:"selected"`
	DryRun          bool   `json:"dry_run"`
	KillSwitch      bool   `json:"kill_switch"`
	Actuated        bool   `json:"actuated"`
	DispatchOutcome string `json:"dispatch_outcome"`
	DispatchReason  string `json:"dispatch_reason,omitempty"`
}

type armContext struct {
	snapshot *Snapshot
	arm      Arm
	eval     evaluation
}

func optional(f model.OptionalFloat) *float64 {
	if !f.Present {
		return nil
	}
	v := f.Value
	return &v
}

func attackBacked(v *model.WorkloadView, pol model.Policy) bool {
	horizon := pol.EffectiveEventAgeHorizon()
	for _, e := range v.Events {
		if e.TargetsPod && e.Trust == "trusted" && !e.TimestampMissing && e.Age <= horizon {
			return true
		}
	}
	return false
}

func enabledInOrder(pol model.Policy) []model.Action {
	out := make([]model.Action, 0, len(pol.EnabledActions))
	for _, a := range actionset.GeneratableActions() {
		if pol.EnabledActions[a] {
			out = append(out, a)
		}
	}
	return out
}

func (c *armContext) result(res ArmResult, baseline *armContext) ArmResult {
	ev := c.eval
	s := c.snapshot
	pol := ev.policy
	res.ReplaySeconds = ev.seconds
	if hash, err := decisionParameterSet(pol); err == nil {
		res.ArmPolicyOverrides = hash
	}
	lambda := pol.Lambda
	if st := s.Inputs.Engine; st.HasBucket && st.Bucket.HasDual {
		lambda = st.Bucket.Dual.RuntimeLegacy
	}
	if economics, err := pol.Economics(lambda); err == nil {
		res.EconomicsMode = economics.Version
		coef := economics.EffectiveCostCoefficient
		res.CostCoefficient = &coef
	}
	res.CostCeiling = cost.EffectiveCostCeiling(pol)
	res.MaxMovesPerTick = pol.MaxMovesPerTick
	if len(ev.missed) > 0 {
		res.Status = StatusUnreplayable
		res.Reasons = prefix("unrecorded-verdict:", ev.missed)
	} else {
		res.Status = StatusOK
	}
	if ev.err != nil {
		res.ReplayError = ev.err.Error()
	}
	if baseline == c {
		res.Baseline = compareBaseline(s, ev)
		if !res.Baseline.Reproduced && res.Status == StatusOK {
			res.Status = StatusUnreplayable
			res.Reasons = append(res.Reasons, "baseline-not-reproduced")
		}
	} else if baseline != nil {
		match := factWeightsEqual(baseline.eval.set.FactWeights, ev.set.FactWeights)
		res.FactWeightsMatch = &match
	}
	commonWeights := ev.set.FactWeights
	if baseline != nil {
		commonWeights = baseline.eval.set.FactWeights
	}
	c.fill(&res, commonWeights)
	if baseline != nil && baseline != c {
		changed := !equalStrings(res.SelectedSet, selectedKeys(baseline.eval.decisions))
		res.ChangedVsBaseline = &changed
	}
	if baseline == c && s.Final != nil {
		for _, d := range s.Final.Decisions {
			rec := DispatchRecord{Asset: d.Namespace + "/" + d.Pod, Selected: d.Selected, DryRun: d.DryRun, Actuated: d.Actuated}
			if d.Measurements != nil && d.Measurements.KillSwitch.Present {
				rec.KillSwitch = d.Measurements.KillSwitch.Value
			}
			if d.Trace != nil {
				rec.DispatchOutcome, rec.DispatchReason = d.Trace.DispatchOutcome, d.Trace.DispatchReason
			}
			res.Dispatch = append(res.Dispatch, rec)
		}
	}
	return res
}

func selectedKeys(ds []model.Decision) []string {
	out := []string{}
	for _, d := range ds {
		if d.Selected {
			out = append(out, d.Namespace+"/"+d.Pod+":"+string(d.Action))
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func factWeightsEqual(a, b map[string]float64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func (c *armContext) fill(res *ArmResult, commonWeights map[string]float64) {
	ev := c.eval
	pol := ev.policy
	res.SelectedSet = selectedKeys(ev.decisions)
	res.Funnel = Funnel{FirstVetoByGate: map[string]int{}, NoopByReason: map[string]int{}, G9Categories: map[string]int{}, CompleteEvidence: len(ev.missed) == 0}
	exclusions := map[string]actionset.Exclusion{}
	for _, ex := range ev.set.Excluded {
		exclusions[ex.Key+"\x00"+string(ex.Action)] = ex
	}
	candidates := map[string]actionset.Candidate{}
	for _, cand := range ev.set.Candidates {
		candidates[cand.Key+"\x00"+string(cand.Action)] = cand
	}
	decisionByAsset := map[string]model.Decision{}
	for _, d := range ev.decisions {
		decisionByAsset[d.Namespace+"/"+d.Pod] = d
	}
	tcost := ev.cost
	ceiling := cost.EffectiveCostCeiling(pol)
	for _, v := range c.snapshot.Inputs.Views {
		key := v.Pod.Namespace + "/" + v.Pod.Name
		backed := attackBacked(v, pol)
		res.Funnel.Assets++
		if backed {
			res.Funnel.AttackBackedAssets++
		}
		d, hasDecision := decisionByAsset[key]
		traceCands := map[string]model.DecisionCandidateV2{}
		if hasDecision && d.Trace != nil {
			for _, tc := range d.Trace.Candidates {
				if _, seen := traceCands[tc.Action]; !seen || tc.Selected {
					traceCands[tc.Action] = tc
				}
			}
		}
		admitted, positive := 0, 0
		reactiveFiltered := false
		if hasDecision && d.Trace != nil {
			for _, st := range d.Trace.ActionStatus {
				if st.ExclusionKind == model.ExclusionReactiveOnly {
					reactiveFiltered = true
				}
			}
		}
		for _, action := range enabledInOrder(pol) {
			res.Funnel.EnabledPairs++
			pairKey := key + "\x00" + string(action)
			row := CandidateRow{Asset: key, Action: string(action)}
			ex, excluded := exclusions[pairKey]
			cand, isCand := candidates[pairKey]
			tc, hasTrace := traceCands[string(action)]
			if hasTrace {
				row.NetGain = optional(tc.NetGain)
				row.Scored = tc.NetGain.Present
				row.Selected = tc.Selected
			}
			firstGate := ""
			switch {
			case excluded:
				firstGate = ex.Gate
				row.FirstVetoGate, row.FirstVetoReason, row.EligibilityKind = ex.Gate, model.RedactTraceString(ex.Reason), ex.EligibilityKind
			case isCand:
				row.Admitted = true
				admitted++
				res.Funnel.Admitted++
				ec, ch := cand.ECost, cand.CHi
				row.ExpectedCost, row.CostHigh = &ec, &ch
				if row.Scored {
					res.Funnel.Scored++
				}
				if row.NetGain != nil && *row.NetGain > 0 {
					positive++
					res.Funnel.PositiveGain++
				}
			default:
				firstGate = actionset.GateReconAbsent
				if reason, ok := ev.set.FactsAbsent[key]; ok {
					row.FirstVetoGate, row.FirstVetoReason = firstGate, reason
				} else {
					row.FirstVetoGate, row.FirstVetoReason = "UNATTRIBUTED", "pair absent from the generated set"
				}
			}
			if firstGate != "" {
				res.Funnel.FirstVetoByGate[firstGate]++
			}
			gv := v
			if stamped, ok := ev.gateViews[key]; ok {
				gv = stamped
			}
			gates, law, g9 := gateRows(gv, action, pol, firstGate, ex, isCand, cand, tcost, ceiling)
			row.FeasibilityLaw, row.G9Category = law, g9
			res.Funnel.G9Categories[g9]++
			for _, g := range gates {
				res.Funnel.ApplicableGatePairs++
				if g.ActualStatus == GateNotEvaluated {
					res.Funnel.UnassessedGatePairs++
				}
			}
			res.Gates = append(res.Gates, gates...)
			res.Candidates = append(res.Candidates, row)
			if isCand || (excluded && (ex.CostEvaluated || ex.Gate == actionset.GateCostNaN)) {
				res.Costs = append(res.Costs, costRow(v, action, pol, tcost, ceiling))
			}
		}
		if backed && positive > 0 {
			res.Funnel.UsefulFeasibleAssets++
		}
		drow := DecisionRow{Asset: key, AssetUID: v.Pod.UID, AttackBacked: backed, Admitted: admitted, PositiveGain: positive,
			DispatchStatus: DispatchCounterfactualOnly, ConfirmationStatus: "UNVERIFIED"}
		if hasDecision {
			drow.Action, drow.Selected, drow.Feasible = string(d.Action), d.Selected, d.Feasible
			drow.CoverageValue = d.CoverageValue
			drow.ExistentialQualified = d.Existential != nil && d.Existential.Present
			if d.Trace != nil {
				drow.EngineNoopReason = d.Trace.NoopReason
			}
			if d.Selected {
				res.Funnel.Selected++
				if tc, ok := traceCands[string(d.Action)]; ok {
					drow.ExpectedCost, drow.CostHigh, drow.CNorm, drow.CFlow, drow.NetGain = optional(tc.ExpectedCost), optional(tc.CostHigh), optional(tc.CNorm), optional(tc.CFlow), optional(tc.NetGain)
					if tc.ObjectiveCostContribution != nil {
						drow.ObjectivePenalty = optional(*tc.ObjectiveCostContribution)
					} else {
						drow.ObjectivePenalty = optional(tc.LambdaContribution)
					}
					if drow.NetGain != nil {
						res.EstimatedObjective += *drow.NetGain
					}
				}
				if cand, ok := candidates[key+"\x00"+string(d.Action)]; ok {
					for _, k := range cand.CoverKeys {
						drow.CommonWeightCovered += commonWeights[k]
					}
					res.CommonWeightCovered += drow.CommonWeightCovered
				}
			}
		}
		switch {
		case ev.err != nil:
			drow.NoopReason = NoopTickRejected
		case drow.Selected:
		case admitted == 0:
			drow.NoopReason = NoopNoFeasibleCandidate
		case reactiveFiltered && !backed:
			drow.NoopReason = NoopReactiveOnly
		case positive == 0:
			drow.NoopReason = NoopNonPositiveGain
		case positive > 0:
			drow.NoopReason = NoopPositiveNotSelected
		default:
			drow.NoopReason = NoopUnknown
		}
		if !drow.Selected {
			res.Funnel.NoopByReason[drow.NoopReason]++
		}
		res.Decisions = append(res.Decisions, drow)
	}
}

func telemetryState(s model.Signal) string { return s.State.String() }

// gateRows derives the per-gate rows for one enabled pair. Actual statuses follow the
// generator's short-circuit order exactly; downstream gates the candidate never reached
// are NOT_EVALUATED and carry only counterfactual diagnostics from pure evaluators.
func gateRows(v *model.WorkloadView, action model.Action, pol model.Policy, firstGate string, ex actionset.Exclusion,
	admitted bool, cand actionset.Candidate, tcost *cost.P1Cost, ceiling float64) ([]GateRow, string, string) {
	key := v.Pod.Namespace + "/" + v.Pod.Name
	base := GateRow{Asset: key, AssetUID: v.Pod.UID, Action: string(action)}
	firstIdx := len(actionset.CandidateGateOrder) // admitted: every gate passed
	if firstGate == actionset.GateReconAbsent || firstGate == "UNATTRIBUTED" {
		firstIdx = -1
	}
	for i, g := range actionset.CandidateGateOrder {
		if g == firstGate {
			firstIdx = i
		}
	}
	move := model.Move{Action: action}
	var rows []GateRow
	law := ""
	// Pure diagnostics for downstream cost gates.
	var eval *cost.P1Evaluation
	if tcost != nil {
		e := tcost.Evaluation(v, move, pol)
		eval = &e
	}
	for i, g := range actionset.CandidateGateOrder {
		r := base
		r.GateID = g
		switch {
		case firstIdx < 0:
			r.ActualStatus, r.ReasonCode = GateNotEvaluated, "ASSET_FACTS_ABSENT"
		case i < firstIdx:
			r.ActualStatus = GatePass
		case i == firstIdx:
			r.ActualStatus, r.FirstVeto, r.Reason = GateFail, true, model.RedactTraceString(ex.Reason)
			r.ReasonCode = ex.EligibilityKind
			if r.ReasonCode == "" {
				r.ReasonCode = ex.StructuralKind
			}
		default:
			r.ActualStatus, r.ReasonCode = GateNotEvaluated, "SHORT_CIRCUIT_EARLIER_GATE"
		}
		if r.ActualStatus == GateNotEvaluated {
			r.CounterfactualOnly = true
			r.DiagnosticStatus = DiagUnknown
			switch g {
			case actionset.GateCostNaN:
				if eval != nil {
					r.DiagnosticEvaluator = "PURE_SNAPSHOT"
					r.DiagnosticStatus = DiagPass
					if eval.UnactionableCategory != "" {
						r.DiagnosticStatus = DiagFail
					}
				}
			case actionset.GateCHiCeiling:
				if eval != nil && eval.UnactionableCategory == "" {
					r.DiagnosticEvaluator = "PURE_SNAPSHOT"
					r.DiagnosticStatus = DiagPass
					if ceiling > 0 && eval.CHi > ceiling {
						r.DiagnosticStatus = DiagFail
					}
				}
			}
		}
		rows = append(rows, r)
		if g == actionset.GateFeasibility {
			lawRows, firstLaw := feasibilityRows(base, v, move, pol, r.ActualStatus, firstGate == actionset.GateFeasibility, ex.Reason)
			rows = append(rows, lawRows...)
			if firstGate == actionset.GateFeasibility {
				law = firstLaw
			}
		}
	}
	// G9 categorization (only the G9 row decides it).
	g9 := G9Unknown
	for i := range rows {
		if rows[i].GateID != actionset.GateCHiCeiling || rows[i].Law != "" {
			continue
		}
		r := &rows[i]
		switch {
		case admitted:
			g9, r.WouldPassAllOther = G9Pass, "YES"
		case r.FirstVeto:
			g9, r.WouldPassAllOther = G9SoleVetoVerified, "YES"
		case r.DiagnosticStatus == DiagFail:
			g9, r.WouldPassAllOther = G9MultiVeto, "NO"
		case r.DiagnosticStatus == DiagPass:
			g9, r.WouldPassAllOther = G9WouldPassAfter, "NO"
		default:
			g9, r.WouldPassAllOther = G9Unknown, "UNKNOWN"
		}
	}
	return rows, law, g9
}

func feasibilityRows(base GateRow, v *model.WorkloadView, move model.Move, pol model.Policy, gateStatus string, vetoedHere bool, vetoReason string) ([]GateRow, string) {
	verdicts := feasibility.EvaluateEach(v, move, pol)
	rows := make([]GateRow, 0, len(verdicts))
	firstLaw := ""
	reached := gateStatus == GatePass || gateStatus == GateFail
	vetoSeen := false
	for _, lv := range verdicts {
		r := base
		r.GateID, r.Law = actionset.GateFeasibility, lv.Law
		applicable, telemetry := lawApplicability(lv.Law, v, pol)
		r.TelemetryStatus = telemetry
		switch {
		case !reached:
			r.ActualStatus, r.ReasonCode, r.CounterfactualOnly = GateNotEvaluated, "SHORT_CIRCUIT_EARLIER_GATE", true
			r.DiagnosticEvaluator = "PURE_SNAPSHOT"
			r.DiagnosticStatus = DiagPass
			if !lv.Verdict.Feasible {
				r.DiagnosticStatus = DiagFail
			}
		case vetoSeen:
			r.ActualStatus, r.ReasonCode, r.CounterfactualOnly = GateNotEvaluated, "SHORT_CIRCUIT_EARLIER_LAW", true
			r.DiagnosticEvaluator = "PURE_SNAPSHOT"
			r.DiagnosticStatus = DiagPass
			if !lv.Verdict.Feasible {
				r.DiagnosticStatus = DiagFail
			}
		case !lv.Verdict.Feasible:
			r.ActualStatus, r.Reason = GateFail, model.RedactTraceString(lv.Verdict.Reason)
			if vetoedHere && lv.Verdict.Reason == vetoReason {
				r.FirstVeto = true
				firstLaw = lv.Law
			} else if lv.Relaxable {
				r.ReasonCode = "RELAXED_BY_MAY_BREACH_SLO"
			}
			if vetoedHere {
				vetoSeen = true
			}
		case !applicable:
			r.ActualStatus, r.ReasonCode = GateNotApplicable, "LAW_NOT_CONFIGURED"
		case telemetry != "" && telemetry != model.Present.String():
			r.ActualStatus, r.ReasonCode = GateUnavailable, "SKIPPED_UNUSABLE"
		default:
			r.ActualStatus = GatePass
		}
		rows = append(rows, r)
	}
	return rows, firstLaw
}

// lawApplicability reports whether a configurable SLO law is switched on, and the state of
// the telemetry signal it reads (empty when the law reads none).
func lawApplicability(law string, v *model.WorkloadView, pol model.Policy) (bool, string) {
	switch law {
	case "slo-headroom":
		return pol.P99Ms > 0, telemetryState(v.Telemetry.P99Ms)
	case "tokens-floor":
		return pol.MinTokensPerSec > 0, telemetryState(v.Telemetry.TokensPerSec)
	}
	return true, ""
}

func costRow(v *model.WorkloadView, action model.Action, pol model.Policy, tcost *cost.P1Cost, ceiling float64) CostRow {
	row := CostRow{Asset: v.Pod.Namespace + "/" + v.Pod.Name, Action: string(action), ActionFamily: cost.ActionFlowFamily(action),
		CostCeilingEffective: ceiling, RealizedStatus: "NOT_OBSERVED"}
	if tcost == nil {
		return row
	}
	e := tcost.Evaluation(v, model.Move{Action: action}, pol)
	row.CNormExpected, row.CFlowExpected, row.ExpectedCostWeighted, row.CHi = e.Norm, e.Flow, e.Total, e.CHi
	row.FlowRegime, row.FlowPredictedMean = string(e.FlowRegime), e.FlowPredictedMean
	row.FlowFloorApplied, row.FlowUncertainty = e.FlowFloorApplied, e.FlowUncertaintyApplied
	row.ConformalReady, row.GPUEnvelopeApplied = e.ConformalWindowReady, e.GPUEnvelopeApplied
	row.MissingLoadRegime = !v.Telemetry.ReqRate.Usable()
	row.NaNCategory = e.UnactionableCategory
	if row.NaNCategory != "" {
		row.CNormExpected, row.CFlowExpected, row.ExpectedCostWeighted, row.CHi = math.NaN(), math.NaN(), math.NaN(), math.NaN()
	}
	return row
}

// excludedBaselineFields are omitted from the exact baseline comparison, with reasons.
var excludedBaselineFields = []string{
	"ScopedOutcomes: reporting-only cohort report keyed by process lifetime (owner count, epoch); never read by selection",
}

func normalizedDecisionJSON(ds []model.Decision) ([][]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(ds); err != nil {
		return nil, err
	}
	var round []model.Decision
	if err := gob.NewDecoder(&buf).Decode(&round); err != nil {
		return nil, err
	}
	out := make([][]byte, len(round))
	for i := range round {
		round[i].ScopedOutcomes = nil
		raw, err := json.Marshal(round[i])
		if err != nil {
			return nil, err
		}
		out[i] = raw
	}
	return out, nil
}

func compareBaseline(s *Snapshot, ev evaluation) *BaselineCheck {
	bc := &BaselineCheck{ExcludedFields: excludedBaselineFields, ProductionError: s.Outcome.ProductionError}
	replayErr := ""
	if ev.err != nil {
		replayErr = ev.err.Error()
	}
	if replayErr != s.Outcome.ProductionError {
		bc.Mismatches = append(bc.Mismatches, fmt.Sprintf("tick error: production=%q replay=%q", s.Outcome.ProductionError, replayErr))
	}
	want, err := normalizedDecisionJSON(s.Outcome.Production)
	if err != nil {
		bc.Mismatches = append(bc.Mismatches, "normalize production: "+err.Error())
		return bc
	}
	got, err := normalizedDecisionJSON(ev.decisions)
	if err != nil {
		bc.Mismatches = append(bc.Mismatches, "normalize replay: "+err.Error())
		return bc
	}
	bc.ComparedRecords = len(want)
	if len(want) != len(got) {
		bc.Mismatches = append(bc.Mismatches, fmt.Sprintf("decision count: production=%d replay=%d", len(want), len(got)))
	} else {
		for i := range want {
			if !bytes.Equal(want[i], got[i]) {
				bc.Mismatches = append(bc.Mismatches, fmt.Sprintf("decision %d: %s", i, firstJSONDifference(want[i], got[i])))
				if len(bc.Mismatches) >= 20 {
					break
				}
			}
		}
	}
	bc.Reproduced = len(bc.Mismatches) == 0
	return bc
}

// firstJSONDifference returns the first differing JSON path.
func firstJSONDifference(a, b []byte) string {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return "unparseable record"
	}
	if p, ok := diffPath("$", x, y); ok {
		return p
	}
	return "byte difference"
}

func diffPath(path string, x, y any) (string, bool) {
	switch xv := x.(type) {
	case map[string]any:
		yv, ok := y.(map[string]any)
		if !ok {
			return path, true
		}
		keys := make([]string, 0, len(xv)+len(yv))
		for k := range xv {
			keys = append(keys, k)
		}
		for k := range yv {
			if _, ok := xv[k]; !ok {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			if p, ok := diffPath(path+"."+k, xv[k], yv[k]); ok {
				return p, true
			}
		}
		return "", false
	case []any:
		yv, ok := y.([]any)
		if !ok || len(xv) != len(yv) {
			return path, true
		}
		for i := range xv {
			if p, ok := diffPath(fmt.Sprintf("%s[%d]", path, i), xv[i], yv[i]); ok {
				return p, true
			}
		}
		return "", false
	default:
		xb, _ := json.Marshal(x)
		yb, _ := json.Marshal(y)
		if !bytes.Equal(xb, yb) {
			return fmt.Sprintf("%s (production=%s replay=%s)", path, xb, yb), true
		}
		return "", false
	}
}
