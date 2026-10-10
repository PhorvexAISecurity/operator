package mathlab

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// Replay schema and statuses.
const (
	ReplaySchema = "math-lab.replay.v1"

	StatusOK           = "OK"
	StatusUnreplayable = "UNREPLAYABLE"
	StatusInvalidArm   = "INVALID_ARM"
	StatusError        = "ERROR"

	// Parameter identifiers the replay can override. They are registry param_ids.
	ParamDisruptionAversion = "P-OBJ-003"
	ParamCostCeiling        = "P-FEA-006"
	ParamProactiveFloor     = "P-FEA-005"

	// MaxReplayCostCeiling bounds a hypothetical ceiling; the CRD has no upper bound.
	MaxReplayCostCeiling = 1000.0

	// The proactive floor is replayed in whole seconds within [1s, 7d]; the CRD only
	// requires a positive duration.
	MinReplayProactiveFloorSeconds = 1.0
	MaxReplayProactiveFloorSeconds = 7 * 24 * 3600.0

	unrecordedKind = "math-lab-unrecorded-verdict"
)

// Override sets one registry parameter for an arm. Unset is only meaningful for
// disruption aversion, where it selects the policy's own economics mode.
type Override struct {
	ParamID string   `json:"param_id"`
	Unset   bool     `json:"unset,omitempty"`
	Value   *float64 `json:"value,omitempty"`
}

// Arm is one counterfactual configuration. An arm with no overrides is the recorded
// baseline.
type Arm struct {
	ID        string     `json:"arm_id"`
	Overrides []Override `json:"overrides"`
}

// ValidateArm rejects unknown parameters, duplicates and out-of-domain values before any
// replay is scheduled.
func ValidateArm(a Arm) error {
	if strings.TrimSpace(a.ID) == "" {
		return errors.New("arm_id is required")
	}
	seen := map[string]bool{}
	for _, o := range a.Overrides {
		if seen[o.ParamID] {
			return fmt.Errorf("parameter %s is overridden twice", o.ParamID)
		}
		seen[o.ParamID] = true
		switch o.ParamID {
		case ParamDisruptionAversion:
			if o.Unset {
				if o.Value != nil {
					return fmt.Errorf("%s: unset and value are exclusive", o.ParamID)
				}
				continue
			}
			if o.Value == nil {
				return fmt.Errorf("%s: value or unset is required", o.ParamID)
			}
			if v := *o.Value; math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > model.MaxDisruptionAversion {
				return fmt.Errorf("%s: value %v outside [0,%v]", o.ParamID, v, model.MaxDisruptionAversion)
			}
		case ParamCostCeiling:
			if o.Unset || o.Value == nil {
				return fmt.Errorf("%s: an explicit value is required", o.ParamID)
			}
			if v := *o.Value; math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || v > MaxReplayCostCeiling {
				return fmt.Errorf("%s: value %v outside (0,%v]", o.ParamID, v, MaxReplayCostCeiling)
			}
		case ParamProactiveFloor:
			if o.Unset || o.Value == nil {
				return fmt.Errorf("%s: an explicit value in seconds is required", o.ParamID)
			}
			v := *o.Value
			if math.IsNaN(v) || math.IsInf(v, 0) || v < MinReplayProactiveFloorSeconds || v > MaxReplayProactiveFloorSeconds {
				return fmt.Errorf("%s: value %v outside [%v,%v] seconds", o.ParamID, v, MinReplayProactiveFloorSeconds, MaxReplayProactiveFloorSeconds)
			}
			if v != math.Trunc(v) {
				return fmt.Errorf("%s: value %v is not a whole number of seconds", o.ParamID, v)
			}
		default:
			return fmt.Errorf("parameter %q is not replay-overridable", o.ParamID)
		}
	}
	return nil
}

// FieldDiff is one effective-policy difference between the recorded policy and an arm.
type FieldDiff struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

func applyArm(pol *model.Policy, a Arm) ([]FieldDiff, error) {
	var diffs []FieldDiff
	for _, o := range a.Overrides {
		switch o.ParamID {
		case ParamDisruptionAversion:
			before := fmt.Sprintf("configured=%v value=%v", pol.DisruptionAversionConfigured, pol.DisruptionAversion)
			if o.Unset {
				pol.DisruptionAversionConfigured, pol.DisruptionAversion = false, 0
			} else {
				if pol.CostPreferencesConfigured {
					return nil, errors.New("policy uses costPreferences, which is mutually exclusive with disruptionAversion")
				}
				pol.DisruptionAversionConfigured, pol.DisruptionAversion = true, *o.Value
			}
			diffs = append(diffs, FieldDiff{Field: "policy.disruptionAversion", Before: before,
				After: fmt.Sprintf("configured=%v value=%v", pol.DisruptionAversionConfigured, pol.DisruptionAversion)})
		case ParamCostCeiling:
			before := fmt.Sprintf("%v", cost.EffectiveCostCeiling(*pol))
			pol.CostCeiling = *o.Value
			diffs = append(diffs, FieldDiff{Field: "policy.costCeiling", Before: before, After: fmt.Sprintf("%v", *o.Value)})
		case ParamProactiveFloor:
			// spec.budget.proactiveFloor has coupled roles: buildPolicy sets both the hygiene
			// cadence (T_cad) and the exposure-pressure horizon (T_exp) from it. The arm models
			// that spec change, so it moves both, and refuses a recorded policy whose horizon was
			// set independently (that policy was not produced by the coupling being modelled).
			if pol.ExposurePressureScale != 0 && pol.ExposurePressureScale != pol.ProactiveFloor {
				return nil, fmt.Errorf("recorded exposure pressure scale %v is decoupled from the proactive floor %v",
					pol.ExposurePressureScale, pol.ProactiveFloor)
			}
			before := fmt.Sprintf("proactiveFloor=%v exposurePressureScale=%v", pol.ProactiveFloor, pol.ExposurePressureScale)
			floor := time.Duration(*o.Value) * time.Second
			pol.ProactiveFloor, pol.ExposurePressureScale = floor, floor
			diffs = append(diffs, FieldDiff{Field: "policy.proactiveFloor", Before: before,
				After: fmt.Sprintf("proactiveFloor=%v exposurePressureScale=%v", floor, floor)})
		}
	}
	return diffs, nil
}

// globals serializes replays: the recon default profile and the GPU envelope are
// process-wide in the production code.
var globals sync.Mutex

func withGlobals(h Header, fn func() error) error {
	globals.Lock()
	defer globals.Unlock()
	prevProfile := recon.Registry.DefaultName()
	prevEnvelope := cost.GPUEnvelopeMax()
	defer func() {
		recon.Registry.SetDefault(prevProfile)
		_ = cost.ConfigureGPUEnvelopeMax(prevEnvelope)
	}()
	if !recon.Registry.SetDefault(h.ReconProfile) {
		return fmt.Errorf("recon profile %q is not registered in this build", h.ReconProfile)
	}
	if err := cost.ConfigureGPUEnvelopeMax(h.GPUEnvelopeMax); err != nil {
		return err
	}
	return fn()
}

// Completeness lists every reason a snapshot cannot be replayed exactly. Empty means
// replayable.
func Completeness(s *Snapshot) []string {
	var missing []string
	missing = append(missing, s.Header.UnreplayableFields...)
	if s.Header.DecidedAt.IsZero() && s.Outcome.ProductionError == "" {
		missing = append(missing, "decidedAt")
	}
	if len(s.Inputs.SpecJSON) == 0 {
		missing = append(missing, "policySpec")
	}
	if s.Inputs.Engine.Owner == "" || s.Inputs.Engine.Owner != s.Inputs.Policy.Owner() {
		missing = append(missing, "engineOwnerState")
	}
	if len(s.Inputs.Views) != len(s.Header.Assets) {
		missing = append(missing, "views")
	}
	if s.Outcome.ProductionError == "" && len(s.Outcome.Production) != len(s.Inputs.Views) {
		missing = append(missing, "productionDecisions")
	}
	return missing
}

// playback answers the engine's impure collaborators from recorded production verdicts.
type playback struct {
	mu       sync.Mutex
	caps     map[string]CapabilityVerdict
	fails    map[string]FailureVerdict
	missing  map[string]bool
	capWired bool
}

func newPlayback(o Outcome) *playback {
	p := &playback{caps: map[string]CapabilityVerdict{}, fails: map[string]FailureVerdict{}, missing: map[string]bool{}, capWired: o.CapabilityWired}
	for _, v := range o.Capability {
		p.caps[v.Namespace+"\x00"+v.PodUID+"\x00"+string(v.Action)+"\x00"+v.CoverKeys] = v
	}
	for _, v := range o.Failures {
		p.fails[v.Namespace+"\x00"+v.PodUID+"\x00"+string(v.Action)] = v
	}
	return p
}

func (p *playback) capability(v *model.WorkloadView, a model.Action, keys []string) *actionset.Eligibility {
	k := v.Pod.Namespace + "\x00" + v.Pod.UID + "\x00" + string(a) + "\x00" + coverKey(keys)
	rec, ok := p.caps[k]
	if !ok {
		p.mu.Lock()
		p.missing["capability:"+v.Pod.Namespace+"/"+v.Pod.Name+":"+string(a)] = true
		p.mu.Unlock()
		return &actionset.Eligibility{Excluded: true, Kind: unrecordedKind, Detail: "math-lab: production never evaluated this capability query"}
	}
	if rec.Nil {
		return nil
	}
	out := rec.Eligibility
	return &out
}

func (p *playback) failure(v *model.WorkloadView, a model.Action) (string, bool) {
	rec, ok := p.fails[v.Pod.Namespace+"\x00"+v.Pod.UID+"\x00"+string(a)]
	if !ok {
		p.mu.Lock()
		p.missing["failure-cooldown:"+v.Pod.Namespace+"/"+v.Pod.Name+":"+string(a)] = true
		p.mu.Unlock()
		return "math-lab: production never evaluated this cooldown query", true
	}
	return rec.Detail, rec.Excluded
}

func (p *playback) missed() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.missing))
	for k := range p.missing {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// cloneViews returns a private deep copy of the recorded views for one evaluation.
func cloneViews(in []*model.WorkloadView) ([]*model.WorkloadView, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(in); err != nil {
		return nil, err
	}
	var out []*model.WorkloadView
	if err := gob.NewDecoder(&buf).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// evaluation is everything one arm computed.
type evaluation struct {
	policy    model.Policy
	set       actionset.ActionSet
	// gateViews are the views as the generator read them (event-evidence stamped), keyed by
	// asset; per-law rows are evaluated on these.
	gateViews map[string]*model.WorkloadView
	decisions []model.Decision
	cost      *cost.P1Cost
	err       error
	missed    []string
	seconds   float64
}

func evaluate(s *Snapshot, pol model.Policy) (evaluation, error) {
	var out evaluation
	out.policy = pol
	engine := decision.NewCoverageEngine()
	if engine.Recon == nil || engine.Recon.Name() != s.Header.ReconProfile {
		return out, fmt.Errorf("replay engine recon profile does not match %q", s.Header.ReconProfile)
	}
	if engine.Context == nil || engine.Context.Name() != s.Header.ContextProvider {
		return out, fmt.Errorf("replay engine context provider does not match %q", s.Header.ContextProvider)
	}
	decidedAt := s.Header.DecidedAt
	if decidedAt.IsZero() {
		decidedAt = s.Header.CapturedAt
	}
	engine.Now = func() time.Time { return decidedAt }
	if err := engine.RestoreOwnerState(s.Inputs.Engine); err != nil {
		return out, fmt.Errorf("restore owner state: %w", err)
	}
	out.cost = engine.CostForShadow(pol)
	pb := newPlayback(s.Outcome)
	if s.Outcome.CapabilityWired {
		engine.Capability = pb.capability
		engine.ShadowCapability = pb.capability
	}
	if s.Outcome.FailureWired {
		engine.FailureExclusion = pb.failure
	}
	diagViews, err := cloneViews(s.Inputs.Views)
	if err != nil {
		return out, err
	}
	decideViews, err := cloneViews(s.Inputs.Views)
	if err != nil {
		return out, err
	}
	start := time.Now()
	set, gateViews, setErr := engine.AssembleSetShadow(diagViews, pol)
	if setErr == nil {
		out.set, out.gateViews = set, gateViews
	}
	out.decisions, out.err = engine.DecideChecked(decideViews, pol)
	out.seconds = time.Since(start).Seconds()
	out.missed = pb.missed()
	return out, nil
}

// ReplayOptions controls one replay run.
type ReplayOptions struct {
	Arms []Arm
}

// Replay evaluates every arm against one snapshot. The first arm must be the baseline
// (no overrides); it is compared byte-for-byte with what production decided.
func Replay(s *Snapshot, opts ReplayOptions) ([]ArmResult, error) {
	if len(opts.Arms) == 0 || len(opts.Arms[0].Overrides) != 0 {
		return nil, errors.New("the first arm must be the baseline with no overrides")
	}
	for _, a := range opts.Arms {
		if err := ValidateArm(a); err != nil {
			return nil, fmt.Errorf("arm %q: %w", a.ID, err)
		}
	}
	results := make([]ArmResult, 0, len(opts.Arms))
	missing := Completeness(s)
	var spec v1alpha1.PhorvexPolicySpec
	if len(missing) == 0 {
		if err := json.Unmarshal(s.Inputs.SpecJSON, &spec); err != nil {
			missing = append(missing, "policySpec")
		}
	}
	if len(missing) > 0 {
		for _, a := range opts.Arms {
			results = append(results, ArmResult{Schema: ReplaySchema, Snapshot: s.ref(), ArmID: a.ID,
				Status: StatusUnreplayable, Reasons: prefix("missing:", missing)})
		}
		return results, nil
	}
	err := withGlobals(s.Header, func() error {
		var baseline *armContext
		for i, a := range opts.Arms {
			pol := s.Inputs.Policy
			pol.AssetWeightFromLabels = spec.AssetWeightFromLabels
			diffs, armErr := applyArm(&pol, a)
			res := ArmResult{Schema: ReplaySchema, Snapshot: s.ref(), ArmID: a.ID, Overrides: a.Overrides, PolicyDiff: diffs}
			if armErr != nil {
				res.Status, res.Reasons = StatusInvalidArm, []string{armErr.Error()}
				results = append(results, res)
				continue
			}
			ev, err := evaluate(s, pol)
			if err != nil {
				res.Status, res.Reasons = StatusError, []string{err.Error()}
				results = append(results, res)
				if i == 0 {
					return nil
				}
				continue
			}
			ctx := &armContext{snapshot: s, arm: a, eval: ev}
			if i == 0 {
				baseline = ctx
			}
			res = ctx.result(res, baseline)
			results = append(results, res)
		}
		return nil
	})
	if err != nil {
		for i := range results {
			results[i].Status, results[i].Reasons = StatusError, []string{err.Error()}
		}
		if len(results) == 0 {
			for _, a := range opts.Arms {
				results = append(results, ArmResult{Schema: ReplaySchema, Snapshot: s.ref(), ArmID: a.ID, Status: StatusError, Reasons: []string{err.Error()}})
			}
		}
	}
	return results, nil
}

func prefix(p string, in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = p + s
	}
	return out
}

func decisionParameterSet(pol model.Policy) (string, error) {
	ref, _, _, err := decision.ParameterSetForPolicy(pol)
	if err != nil {
		return "", err
	}
	return ref.PolicyOverridesHash, nil
}
