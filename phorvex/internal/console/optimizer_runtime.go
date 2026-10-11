/*
 * Phorvex Console — runtime optimizer parameters (Optimizer Bench, live section).
 *
 * The Optimizer Bench used to tune parameters only inside an in-process simulation. This file
 * makes the same economic knobs editable on the LIVE PhorvexPolicy of every app and proves, from
 * the brain's own decision records, that the brain is deciding with the new values:
 *
 *   GET  /api/optimizer/runtime          every visible app policy: the value each knob is set to
 *                                        (spec, resolved exactly as the operator resolves it), the
 *                                        value the brain's newest decision trace carries, and a
 *                                        per-knob verdict (VERIFIED / PENDING / MISMATCH / ...).
 *   POST /api/optimizer/runtime/apply    an audited merge patch of those knobs (or a restore of the
 *                                        values a previous change replaced).
 *   GET  /api/optimizer/parameter-log    the audited change log, newest first.
 *
 * Only economic and pacing knobs are offered. Mode, the enabled actuator set, reactive-only and
 * the availability floor stay out on purpose: those decide WHICH actuators may run, and that is
 * the brain's choice, not a console scenario's.
 *
 * VERIFIED means: a decision record whose policy generation is at least the policy's current
 * generation carries exactly the configured value. It is evidence that the brain priced with the
 * value; it says nothing about whether the value is better.
 */

package console

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	optimizerApplyRoute = "/api/optimizer/runtime/apply"

	// Verdicts for one knob on one policy.
	paramVerified         = "VERIFIED"
	paramPending          = "PENDING"
	paramMismatch         = "MISMATCH"
	paramNoRecentDecision = "NO_RECENT_DECISION"
	paramNotApplicable    = "NOT_APPLICABLE"

	economicsLegacy      = "legacy"
	economicsFixed       = "fixed"
	economicsIndependent = "independent"

	optimizerLogTailBytes = 8 << 20
)

// runtimeParam describes one editable knob: where it lives in the spec, its admissible domain and
// what it does in the brain, in one honest sentence.
type runtimeParam struct {
	Key           string  `json:"key"`
	Label         string  `json:"label"`
	Symbol        string  `json:"symbol"`
	SpecPath      string  `json:"specPath"`
	Unit          string  `json:"unit"`
	Min           float64 `json:"min"`
	Max           float64 `json:"max"`
	MinExclusive  bool    `json:"minExclusive,omitempty"`
	Integer       bool    `json:"integer,omitempty"`
	Protected     bool    `json:"protected,omitempty"`
	SafeDirection string  `json:"safeDirection,omitempty"` // lower | higher
	Effect        string  `json:"effect"`
}

// runtimeParams is the knob catalogue, in display order. The economics mode (legacy runtime λ,
// fixed β, independent β_N/β_F) is chosen separately; beta and the two preferences apply only in
// their own mode.
var runtimeParams = []runtimeParam{
	{Key: "normWeight", Label: "c_norm weight", Symbol: "w_N", SpecPath: "spec.objective.costWeights.normSparsity", Min: 0, Max: 10,
		Effect: "Weights CNorm in the cost total. It always enters the CHi ceiling gate; it moves the objective only while the cost coefficient is above 0 (fixed β > 0, or a runtime λ > 0)."},
	{Key: "flowWeight", Label: "c_flow weight", Symbol: "w_F", SpecPath: "spec.objective.costWeights.flowDisruption", Min: 0, Max: 10,
		Effect: "Weights CFlow in the cost total. It always enters the CHi ceiling gate (and scales its GPU and regime slack); it moves the objective only while the cost coefficient is above 0."},
	{Key: "lambdaSeed", Label: "λ seed", Symbol: "λ₀", SpecPath: "spec.objective.lambda", Min: 0, Max: 10,
		Effect: "Legacy mode only. Seeds the runtime λ once, when the brain creates this policy's cost bucket (operator start or policy recreate). A patch updates the configured seed the trace reports, not the running λ."},
	{Key: "beta", Label: "β (fixed price)", Symbol: "β", SpecPath: "spec.objective.disruptionAversion", Min: 0, Max: 10,
		Effect: "Fixed-β mode. Replaces the runtime λ as the cost coefficient: gain = coverage·prov − β·ECost. Takes effect on the next tick."},
	{Key: "normPreference", Label: "β_N (norm preference)", Symbol: "β_N", SpecPath: "spec.objective.costPreferences.norm", Min: 0, Max: 10,
		Effect: "Independent mode. Multiplies the unweighted CNorm in the objective (not w_N·CNorm). The CHi gate is unaffected."},
	{Key: "flowPreference", Label: "β_F (flow preference)", Symbol: "β_F", SpecPath: "spec.objective.costPreferences.flow", Min: 0, Max: 10,
		Effect: "Independent mode. Multiplies the unweighted CFlow in the objective (not w_F·CFlow). The CHi gate is unaffected."},
	{Key: "costCeiling", Label: "Cost ceiling", Symbol: "c̄", SpecPath: "spec.slo.costCeiling", Min: 0, Max: 1000, MinExclusive: true, Unit: "normalized disruption",
		Protected: true, SafeDirection: "lower",
		Effect: "Hard gate G9: a candidate whose robust cost CHi exceeds c̄ is excluded. Independent of the economics mode."},
	{Key: "maxMovesPerTick", Label: "Moves per tick", Symbol: "B", SpecPath: "spec.budget.maxMovesPerTick", Min: 0, Max: 100, Integer: true, Unit: "moves",
		Protected: true, SafeDirection: "lower",
		Effect: "Move budget per tick. 0 = decide and log only. In legacy mode the dual λ reacts to budget pressure."},
	{Key: "proactiveFloorSeconds", Label: "Proactive floor", Symbol: "T_cad", SpecPath: "spec.budget.proactiveFloor", Min: 1, Max: 604800, Integer: true, Unit: "seconds",
		Effect: "Hygiene cadence (G6 proactive-cadence) and the exposure-pressure horizon. Moves backed by a fresh trusted event are never capped by it."},
	{Key: "antiOverRotationSeconds", Label: "Anti-over-rotation window", Symbol: "T_aor", SpecPath: "spec.budget.antiOverRotationWindow", Min: 1, Max: 86400, Integer: true, Unit: "seconds",
		Protected: true, SafeDirection: "higher",
		Effect: "G6 anti-over-rotation: the same pod/action is not repeated inside this window."},
}

func runtimeParamByKey(key string) (runtimeParam, bool) {
	for _, p := range runtimeParams {
		if p.Key == key {
			return p, true
		}
	}
	return runtimeParam{}, false
}

// optionalValue is a knob value that may be absent (beta outside fixed mode, the preferences
// outside independent mode).
type optionalValue struct {
	Present bool    `json:"present"`
	Value   float64 `json:"value"`
}

// runtimeValues is one full assignment of the knobs plus the economics mode.
type runtimeValues struct {
	EconomicsMode string                   `json:"economicsMode"`
	Values        map[string]optionalValue `json:"values"`
}

// optimizerPolicyClient is the narrow cluster surface this file needs; tests substitute it.
type optimizerPolicyClient interface {
	List(ctx context.Context) ([]v1alpha1.PhorvexPolicy, error)
	Get(ctx context.Context, namespace, name string) (*v1alpha1.PhorvexPolicy, error)
	Patch(ctx context.Context, namespace, name string, patch []byte) (*v1alpha1.PhorvexPolicy, error)
}

type dynamicPolicyClient struct{ client dynamic.Interface }

func newDynamicPolicyClient() (optimizerPolicyClient, error) {
	rc, err := restConfigFor("")
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	return dynamicPolicyClient{client: dyn}, nil
}

func policyFromUnstructured(u *unstructured.Unstructured) (*v1alpha1.PhorvexPolicy, error) {
	var p v1alpha1.PhorvexPolicy
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &p); err != nil {
		return nil, fmt.Errorf("decode PhorvexPolicy %s/%s: %w", u.GetNamespace(), u.GetName(), err)
	}
	return &p, nil
}

func (c dynamicPolicyClient) List(ctx context.Context) ([]v1alpha1.PhorvexPolicy, error) {
	list, err := c.client.Resource(phorvexPolicyGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]v1alpha1.PhorvexPolicy, 0, len(list.Items))
	for i := range list.Items {
		p, err := policyFromUnstructured(&list.Items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

func (c dynamicPolicyClient) Get(ctx context.Context, namespace, name string) (*v1alpha1.PhorvexPolicy, error) {
	u, err := c.client.Resource(phorvexPolicyGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return policyFromUnstructured(u)
}

func (c dynamicPolicyClient) Patch(ctx context.Context, namespace, name string, patch []byte) (*v1alpha1.PhorvexPolicy, error) {
	u, err := c.client.Resource(phorvexPolicyGVR).Namespace(namespace).Patch(ctx, name, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: "phorvex-console-optimizer"})
	if err != nil {
		return nil, err
	}
	return policyFromUnstructured(u)
}

func (s *Server) optimizerPolicies() (optimizerPolicyClient, error) {
	if s.optimizerClient != nil {
		return s.optimizerClient, nil
	}
	return newDynamicPolicyClient()
}

func (s *Server) optimizerDecisionRecords(ctx context.Context) ([]audit.Record, error) {
	if s.optimizerRecords != nil {
		return s.optimizerRecords(ctx)
	}
	return s.readDecisionWindow(ctx, "")
}

// verificationFixture reports the throw-away verification tenants owned by other harnesses; the
// console never edits them.
func verificationFixture(namespace string) bool {
	return strings.HasPrefix(namespace, "phorvex-verify-")
}

// specValues resolves the configured knobs exactly as the operator's buildPolicy does.
func specValues(spec *v1alpha1.PhorvexPolicySpec) (runtimeValues, error) {
	out := runtimeValues{Values: map[string]optionalValue{}}
	set := func(key string, v float64) { out.Values[key] = optionalValue{Present: true, Value: v} }
	beta, betaConfigured, betaErr := spec.EffectiveDisruptionAversion()
	norm, flow, prefsConfigured, prefsErr := spec.EffectiveCostPreferences()
	if betaErr != nil {
		return out, betaErr
	}
	if prefsErr != nil {
		return out, prefsErr
	}
	switch {
	case prefsConfigured:
		out.EconomicsMode = economicsIndependent
		set("normPreference", norm)
		set("flowPreference", flow)
	case betaConfigured:
		out.EconomicsMode = economicsFixed
		set("beta", beta)
	default:
		out.EconomicsMode = economicsLegacy
	}
	set("normWeight", spec.EffectiveNormSparsity())
	set("flowWeight", spec.EffectiveFlowDisruption())
	set("lambdaSeed", spec.EffectiveLambda())
	set("costCeiling", spec.EffectiveCostCeiling())
	set("maxMovesPerTick", float64(spec.EffectiveMaxMovesPerTick()))
	set("proactiveFloorSeconds", spec.EffectiveProactiveFloor().Seconds())
	set("antiOverRotationSeconds", spec.EffectiveAntiOverRotationWindow().Seconds())
	for _, key := range []string{"beta", "normPreference", "flowPreference"} {
		if _, ok := out.Values[key]; !ok {
			out.Values[key] = optionalValue{}
		}
	}
	return out, nil
}

// brainObservation is what the newest decision record of a policy says the brain used.
type brainObservation struct {
	DecisionTime             string                   `json:"decisionTime"`
	DecisionID               string                   `json:"decisionId,omitempty"`
	Action                   string                   `json:"action"`
	Pod                      string                   `json:"pod,omitempty"`
	Generation               int64                    `json:"generation"`
	EconomicsMode            string                   `json:"economicsMode"`
	EconomicsVersion         string                   `json:"economicsVersion,omitempty"`
	EffectiveCostCoefficient float64                  `json:"effectiveCostCoefficient"`
	CostCoefficientSource    string                   `json:"costCoefficientSource,omitempty"`
	LambdaRuntime            float64                  `json:"lambdaRuntime"`
	LambdaSeedConsumed       float64                  `json:"lambdaSeedConsumed"`
	PolicyOverridesHash      string                   `json:"policyOverridesHash,omitempty"`
	Values                   map[string]optionalValue `json:"values"`
}

func economicsModeOf(version string) string {
	switch version {
	case model.EconomicsFixedDisruptionAversionV1:
		return economicsFixed
	case model.EconomicsIndependentPreferencesV1:
		return economicsIndependent
	case model.EconomicsLegacyRuntimeLambdaV1:
		return economicsLegacy
	}
	return ""
}

// recordGeneration reads the policy generation a decision was made under. The parameter-set
// identity is "<ns>/<name>@<uid>:<generation>"; the scoped-outcome report carries it as well.
func recordGeneration(rec *audit.Record) (int64, string) {
	if rec.ParameterSet != nil {
		id := rec.ParameterSet.PolicyOverridesID
		if at := strings.LastIndex(id, "@"); at >= 0 {
			if colon := strings.LastIndex(id, ":"); colon > at {
				if g, err := strconv.ParseInt(id[colon+1:], 10, 64); err == nil {
					return g, id[at+1 : colon]
				}
			}
		}
	}
	if rec.ScopedOutcomes != nil {
		return rec.ScopedOutcomes.Policy.Generation, rec.ScopedOutcomes.Policy.UID
	}
	return 0, ""
}

func optional(o *model.OptionalFloat) optionalValue {
	if o == nil || !o.Present {
		return optionalValue{}
	}
	return optionalValue{Present: true, Value: o.Value}
}

func observe(rec *audit.Record) (brainObservation, bool) {
	t := rec.DecisionTrace
	if t == nil {
		return brainObservation{}, false
	}
	generation, _ := recordGeneration(rec)
	obs := brainObservation{
		DecisionTime: rec.Time.UTC().Format(time.RFC3339Nano), DecisionID: t.DecisionID, Action: rec.Action, Pod: rec.Pod,
		Generation: generation, EconomicsVersion: t.EconomicsVersion, EconomicsMode: economicsModeOf(t.EconomicsVersion),
		EffectiveCostCoefficient: t.EffectiveCostCoefficient, CostCoefficientSource: t.CostCoefficientSource,
		LambdaRuntime: t.LambdaRuntime, LambdaSeedConsumed: t.LambdaSeedConsumed,
		Values: map[string]optionalValue{
			"normWeight":              {Present: true, Value: t.NormWeight},
			"flowWeight":              {Present: true, Value: t.FlowWeight},
			"lambdaSeed":              {Present: true, Value: t.LambdaConfiguredSeed},
			"beta":                    optional(t.DisruptionAversion),
			"normPreference":          optional(t.NormPreference),
			"flowPreference":          optional(t.FlowPreference),
			"costCeiling":             {Present: true, Value: t.CostCeiling},
			"maxMovesPerTick":         {Present: true, Value: float64(t.Budget)},
			"proactiveFloorSeconds":   {Present: true, Value: t.Inputs.ProactiveFloorSec},
			"antiOverRotationSeconds": {Present: true, Value: t.Inputs.AntiOverRotateSec},
		},
	}
	if rec.ParameterSet != nil {
		obs.PolicyOverridesHash = rec.ParameterSet.PolicyOverridesHash
	}
	return obs, true
}

// newestObservations returns, per policy UID, the newest decision record that carries a trace.
func newestObservations(records []audit.Record) map[string]brainObservation {
	out := map[string]brainObservation{}
	newest := map[string]time.Time{}
	for i := range records {
		rec := &records[i]
		if rec.DecisionTrace == nil {
			continue
		}
		uid := rec.DecisionTrace.PolicyUID
		if uid == "" {
			_, uid = recordGeneration(rec)
		}
		if uid == "" || !rec.Time.After(newest[uid]) && !newest[uid].IsZero() {
			continue
		}
		if obs, ok := observe(rec); ok {
			out[uid], newest[uid] = obs, rec.Time
		}
	}
	return out
}

func sameValue(a, b optionalValue) bool {
	if a.Present != b.Present {
		return false
	}
	if !a.Present {
		return true
	}
	return math.Abs(a.Value-b.Value) <= 1e-9*math.Max(1, math.Max(math.Abs(a.Value), math.Abs(b.Value)))
}

// paramStatus is the verdict for one knob on one policy.
type paramStatus struct {
	Key        string         `json:"key"`
	Configured optionalValue  `json:"configured"`
	Observed   *optionalValue `json:"observed,omitempty"`
	Status     string         `json:"status"`
	Note       string         `json:"note,omitempty"`
}

func paramApplies(key, mode string) bool {
	switch key {
	case "beta":
		return mode == economicsFixed
	case "normPreference", "flowPreference":
		return mode == economicsIndependent
	case "lambdaSeed":
		return mode == economicsLegacy
	}
	return true
}

func verdicts(configured runtimeValues, generation int64, obs *brainObservation) []paramStatus {
	out := make([]paramStatus, 0, len(runtimeParams))
	for _, p := range runtimeParams {
		st := paramStatus{Key: p.Key, Configured: configured.Values[p.Key]}
		switch {
		case obs == nil:
			st.Status = paramNoRecentDecision
			st.Note = "no decision of this policy in the newest audit window"
		default:
			v := obs.Values[p.Key]
			st.Observed = &v
			switch {
			case obs.Generation < generation:
				st.Status = paramPending
				st.Note = fmt.Sprintf("newest decision is from policy generation %d; waiting for generation %d", obs.Generation, generation)
			case !paramApplies(p.Key, configured.EconomicsMode) && !st.Configured.Present && !v.Present:
				st.Status = paramNotApplicable
			case sameValue(st.Configured, v):
				st.Status = paramVerified
			default:
				st.Status = paramMismatch
				st.Note = "the brain's decision at the current generation carries a different value"
			}
		}
		if p.Key == "lambdaSeed" && obs != nil && configured.EconomicsMode == economicsLegacy {
			st.Note = strings.TrimSpace(st.Note + fmt.Sprintf(" running λ=%g (seed consumed at bucket creation: %g)", obs.LambdaRuntime, obs.LambdaSeedConsumed))
		}
		out = append(out, st)
	}
	return out
}

// runtimePolicyView is one app policy in GET /api/optimizer/runtime.
type runtimePolicyView struct {
	Namespace     string            `json:"namespace"`
	Name          string            `json:"name"`
	UID           string            `json:"uid"`
	Tenant        string            `json:"tenant"`
	Mode          string            `json:"mode"`
	Generation    int64             `json:"generation"`
	EconomicsMode string            `json:"economicsMode"`
	Configured    runtimeValues     `json:"configured"`
	Brain         *brainObservation `json:"brain,omitempty"`
	Parameters    []paramStatus     `json:"parameters"`
	ModeMatches   *bool             `json:"economicsModeMatches,omitempty"`
	Error         string            `json:"error,omitempty"`
}

func (s *Server) optimizerRuntime(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	client, err := s.optimizerPolicies()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "cluster access unavailable: " + err.Error()})
		return
	}
	policies, err := client.List(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "list PhorvexPolicies: " + err.Error()})
		return
	}
	records, recErr := s.optimizerDecisionRecords(ctx)
	observations := newestObservations(records)
	p := principalOf(r)
	views := []runtimePolicyView{}
	for i := range policies {
		pol := &policies[i]
		if verificationFixture(pol.Namespace) || (!p.TenantWildcard() && !p.AllowsTenant(pol.Namespace)) {
			continue
		}
		view := runtimePolicyView{Namespace: pol.Namespace, Name: pol.Name, UID: string(pol.UID), Tenant: pol.Spec.Tenant,
			Mode: string(pol.Spec.EffectiveMode()), Generation: pol.Generation}
		configured, err := specValues(&pol.Spec)
		if err != nil {
			view.Error = err.Error()
		}
		view.Configured, view.EconomicsMode = configured, configured.EconomicsMode
		var obs *brainObservation
		if o, ok := observations[string(pol.UID)]; ok {
			obs = &o
			view.Brain = obs
			if o.Generation >= pol.Generation {
				matches := o.EconomicsMode == configured.EconomicsMode
				view.ModeMatches = &matches
			}
		}
		view.Parameters = verdicts(configured, pol.Generation, obs)
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool {
		return views[i].Namespace+"/"+views[i].Name < views[j].Namespace+"/"+views[j].Name
	})
	resp := map[string]any{"schemaVersion": "phorvex.optimizer-runtime.v1", "generatedAt": time.Now().UTC().Format(time.RFC3339Nano),
		"catalogue": runtimeParams, "policies": views, "decisionRecordsScanned": len(records)}
	if recErr != nil {
		resp["decisionAuditError"] = recErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// optimizerApplyReq sets knobs on one policy, or restores the values a previous change replaced.
type optimizerApplyReq struct {
	Namespace          string             `json:"namespace"`
	Name               string             `json:"name"`
	ExpectedGeneration int64              `json:"expectedGeneration,omitempty"`
	Set                map[string]float64 `json:"set,omitempty"`
	EconomicsMode      string             `json:"economicsMode,omitempty"`
	ConfirmProtected   bool               `json:"confirmProtected,omitempty"`
	RestoreChangeID    string             `json:"restoreChangeId,omitempty"`
	Note               string             `json:"note,omitempty"`
}

// parameterChange is one knob's before/after in the audit record.
type parameterChange struct {
	Key      string        `json:"key"`
	SpecPath string        `json:"specPath"`
	Before   optionalValue `json:"before"`
	After    optionalValue `json:"after"`
}

func decimalString(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

func validateKnob(p runtimeParam, v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Errorf("%s must be finite", p.Key)
	}
	if v < p.Min || (p.MinExclusive && v == p.Min) || v > p.Max {
		lo := "["
		if p.MinExclusive {
			lo = "("
		}
		return fmt.Errorf("%s=%g is outside %s%g, %g]", p.Key, v, lo, p.Min, p.Max)
	}
	if p.Integer && v != math.Trunc(v) {
		return fmt.Errorf("%s must be a whole number", p.Key)
	}
	return nil
}

// targetValues applies a request to the current assignment and validates the result as a whole.
func targetValues(current runtimeValues, mode string, set map[string]float64) (runtimeValues, error) {
	next := runtimeValues{EconomicsMode: current.EconomicsMode, Values: map[string]optionalValue{}}
	for k, v := range current.Values {
		next.Values[k] = v
	}
	if mode != "" {
		if mode != economicsLegacy && mode != economicsFixed && mode != economicsIndependent {
			return next, fmt.Errorf("economicsMode must be legacy, fixed or independent")
		}
		next.EconomicsMode = mode
	}
	for key, v := range set {
		p, ok := runtimeParamByKey(key)
		if !ok {
			return next, fmt.Errorf("%q is not a runtime optimizer parameter", key)
		}
		if err := validateKnob(p, v); err != nil {
			return next, err
		}
		next.Values[key] = optionalValue{Present: true, Value: v}
	}
	switch next.EconomicsMode {
	case economicsLegacy:
		next.Values["beta"], next.Values["normPreference"], next.Values["flowPreference"] = optionalValue{}, optionalValue{}, optionalValue{}
	case economicsFixed:
		if !next.Values["beta"].Present {
			return next, fmt.Errorf("fixed mode needs beta")
		}
		next.Values["normPreference"], next.Values["flowPreference"] = optionalValue{}, optionalValue{}
	case economicsIndependent:
		if !next.Values["normPreference"].Present || !next.Values["flowPreference"].Present {
			return next, fmt.Errorf("independent mode needs normPreference and flowPreference")
		}
		next.Values["beta"] = optionalValue{}
	}
	for key, v := range set {
		if !paramApplies(key, next.EconomicsMode) && key != "lambdaSeed" {
			return next, fmt.Errorf("%s does not apply in %s mode", key, next.EconomicsMode)
		}
		_ = v
	}
	return next, nil
}

// buildRuntimePatch turns the changed knobs into a merge patch and the audit's change list.
func buildRuntimePatch(current, next runtimeValues, resourceVersion string) ([]byte, []parameterChange) {
	changes := []parameterChange{}
	objective, costWeights, prefs, slo, budget := map[string]any{}, map[string]any{}, map[string]any{}, map[string]any{}, map[string]any{}
	for _, p := range runtimeParams {
		before, after := current.Values[p.Key], next.Values[p.Key]
		if sameValue(before, after) {
			continue
		}
		changes = append(changes, parameterChange{Key: p.Key, SpecPath: p.SpecPath, Before: before, After: after})
		switch p.Key {
		case "normWeight":
			costWeights["normSparsity"] = decimalString(after.Value)
		case "flowWeight":
			costWeights["flowDisruption"] = decimalString(after.Value)
		case "lambdaSeed":
			objective["lambda"] = decimalString(after.Value)
		case "costCeiling":
			slo["costCeiling"] = decimalString(after.Value)
		case "maxMovesPerTick":
			budget["maxMovesPerTick"] = int64(after.Value)
		case "proactiveFloorSeconds":
			budget["proactiveFloor"] = fmt.Sprintf("%ds", int64(after.Value))
		case "antiOverRotationSeconds":
			budget["antiOverRotationWindow"] = fmt.Sprintf("%ds", int64(after.Value))
		}
	}
	// The economics mode is written as a whole so the CRD's mutual-exclusion rule always holds:
	// a merge-patch null removes the field that the new mode does not use.
	modeChanged := current.EconomicsMode != next.EconomicsMode
	betaChanged := !sameValue(current.Values["beta"], next.Values["beta"])
	prefsChanged := !sameValue(current.Values["normPreference"], next.Values["normPreference"]) ||
		!sameValue(current.Values["flowPreference"], next.Values["flowPreference"])
	if modeChanged || betaChanged || prefsChanged {
		switch next.EconomicsMode {
		case economicsLegacy:
			objective["disruptionAversion"], objective["costPreferences"] = nil, nil
		case economicsFixed:
			objective["disruptionAversion"], objective["costPreferences"] = decimalString(next.Values["beta"].Value), nil
		case economicsIndependent:
			prefs["norm"] = decimalString(next.Values["normPreference"].Value)
			prefs["flow"] = decimalString(next.Values["flowPreference"].Value)
			objective["disruptionAversion"], objective["costPreferences"] = nil, prefs
		}
	}
	if len(costWeights) > 0 {
		objective["costWeights"] = costWeights
	}
	spec := map[string]any{}
	if len(objective) > 0 {
		spec["objective"] = objective
	}
	if len(slo) > 0 {
		spec["slo"] = slo
	}
	if len(budget) > 0 {
		spec["budget"] = budget
	}
	if len(spec) == 0 {
		return nil, changes
	}
	patch := map[string]any{"spec": spec}
	if resourceVersion != "" {
		patch["metadata"] = map[string]any{"resourceVersion": resourceVersion}
	}
	b, _ := json.Marshal(patch)
	return b, changes
}

// loosensProtected lists the protected knobs a change moves away from their safe direction.
func loosensProtected(changes []parameterChange) []string {
	out := []string{}
	for _, c := range changes {
		p, ok := runtimeParamByKey(c.Key)
		if !ok || !p.Protected || !c.Before.Present || !c.After.Present {
			continue
		}
		if (p.SafeDirection == "lower" && c.After.Value > c.Before.Value) || (p.SafeDirection == "higher" && c.After.Value < c.Before.Value) {
			out = append(out, c.Key)
		}
	}
	return out
}

func newChangeID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

func (s *Server) optimizerApply(w http.ResponseWriter, r *http.Request) {
	var req optimizerApplyReq
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad JSON: " + err.Error()})
		return
	}
	ns, name := strings.TrimSpace(req.Namespace), strings.TrimSpace(req.Name)
	if !nsRe.MatchString(ns) || !nsRe.MatchString(name) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid namespace or policy name"})
		return
	}
	if verificationFixture(ns) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "verification fixture policies are owned by their harness and are not edited from the console"})
		return
	}
	if len(req.Note) > 500 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "note is limited to 500 characters"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	client, err := s.optimizerPolicies()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "cluster access unavailable: " + err.Error()})
		return
	}
	current, err := client.Get(ctx, ns, name)
	if err != nil {
		status := http.StatusBadGateway
		if apierrors.IsNotFound(err) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": "read policy: " + err.Error()})
		return
	}
	if req.ExpectedGeneration != 0 && req.ExpectedGeneration != current.Generation {
		writeJSON(w, http.StatusConflict, map[string]any{"error": fmt.Sprintf("policy changed since it was read: generation %d, expected %d — reload and retry", current.Generation, req.ExpectedGeneration),
			"generation": current.Generation})
		return
	}
	currentValues, err := specValues(&current.Spec)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the live policy's economics are invalid; fix them with kubectl first: " + err.Error()})
		return
	}
	mode, set := req.EconomicsMode, req.Set
	restoring := strings.TrimSpace(req.RestoreChangeID) != ""
	if restoring {
		if len(set) > 0 || mode != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "restoreChangeId cannot be combined with set or economicsMode"})
			return
		}
		prior, ok := s.findAppliedChange(req.RestoreChangeID)
		if !ok || prior.Namespace != ns || prior.Policy != name {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no applied change " + req.RestoreChangeID + " for " + ns + "/" + name})
			return
		}
		mode, set = prior.BeforeMode, map[string]float64{}
		for _, c := range prior.Parameters {
			if c.Before.Present {
				set[c.Key] = c.Before.Value
			}
		}
	}
	next, err := targetValues(currentValues, mode, set)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	patch, changes := buildRuntimePatch(currentValues, next, current.ResourceVersion)
	if patch == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unchanged": true, "generation": current.Generation})
		return
	}
	if loosened := loosensProtected(changes); len(loosened) > 0 && !req.ConfirmProtected {
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": "this change loosens protected parameters (" + strings.Join(loosened, ", ") +
			"); loosening needs SRE/security approval — resend with confirmProtected once it is approved", "protected": loosened})
		return
	}
	mutation := consoleMutation{Actor: actorOf(r), Endpoint: optimizerApplyRoute, Namespace: ns, Policy: name, Field: "spec", Patch: string(patch),
		ChangeID: newChangeID(), PolicyUID: string(current.UID), PreviousGeneration: current.Generation, Parameters: changes,
		BeforeMode: currentValues.EconomicsMode, AfterMode: next.EconomicsMode, Note: strings.TrimSpace(req.Note), RestoreOf: strings.TrimSpace(req.RestoreChangeID)}
	intent := mutation
	intent.Verdict = "intent"
	if err := s.auditConsoleMutation(intent); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mutation refused before effect: " + err.Error(), "verdict": "refused-evidence-unavailable"})
		return
	}
	updated, err := client.Patch(ctx, ns, name, patch)
	if err != nil {
		status, verdict := http.StatusBadGateway, "effect-unknown"
		switch {
		case apierrors.IsConflict(err):
			status, verdict = http.StatusConflict, "rejected-conflict"
		case apierrors.IsInvalid(err), apierrors.IsBadRequest(err), apierrors.IsForbidden(err), apierrors.IsNotFound(err):
			status, verdict = http.StatusUnprocessableEntity, "rejected-by-apiserver"
		}
		mutation.Verdict, mutation.Message = verdict, err.Error()
		if auditErr := s.auditConsoleMutation(mutation); auditErr != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "unsafeToRetry": true, "error": "patch outcome and evidence are unavailable: " + auditErr.Error()})
			return
		}
		writeJSON(w, status, map[string]any{"ok": false, "verdict": verdict, "unsafeToRetry": verdict == "effect-unknown", "error": "patch " + verdict + ": " + err.Error()})
		return
	}
	mutation.Verdict, mutation.Generation = "applied", updated.Generation
	if auditErr := s.auditConsoleMutation(mutation); auditErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "applied": true, "unsafeToRetry": true, "changeId": mutation.ChangeID,
			"error": "patch applied but outcome evidence is unavailable: " + auditErr.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changeId": mutation.ChangeID, "namespace": ns, "name": name,
		"previousGeneration": current.Generation, "generation": updated.Generation, "economicsMode": next.EconomicsMode,
		"changes": changes, "patch": json.RawMessage(patch)})
}

// readMutationLog returns the optimizer changes in the console mutation log, oldest first.
func (s *Server) readMutationLog() ([]consoleMutation, error) {
	path := s.cfg.mutationAuditPath()
	if path == "" {
		return nil, errors.New("console state path is not configured")
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if st.Size() > optimizerLogTailBytes {
		start = st.Size() - optimizerLogTailBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	out := []consoleMutation{}
	first := start > 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if first {
			first = false // a tail read starts mid-line
			continue
		}
		if len(line) == 0 {
			continue
		}
		var m consoleMutation
		if json.Unmarshal(line, &m) != nil || m.Endpoint != optimizerApplyRoute {
			continue
		}
		out = append(out, m)
	}
	return out, sc.Err()
}

func (s *Server) findAppliedChange(changeID string) (consoleMutation, bool) {
	log, err := s.readMutationLog()
	if err != nil {
		return consoleMutation{}, false
	}
	for i := len(log) - 1; i >= 0; i-- {
		if log[i].ChangeID == changeID && log[i].Verdict == "applied" {
			return log[i], true
		}
	}
	return consoleMutation{}, false
}

func (s *Server) optimizerParameterLog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 1000"})
			return
		}
		limit = n
	}
	log, err := s.readMutationLog()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "console mutation log unavailable: " + err.Error()})
		return
	}
	p := principalOf(r)
	entries := []consoleMutation{}
	for i := len(log) - 1; i >= 0 && len(entries) < limit; i-- {
		if p.TenantWildcard() || p.AllowsTenant(log[i].Namespace) {
			entries = append(entries, log[i])
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"schemaVersion": "phorvex.optimizer-parameter-log.v1", "entries": entries,
		"note": "Every console write of a runtime optimizer parameter, newest first. An intent is written before the cluster write; this log carries the outcomes (applied, rejected-*, effect-unknown)."})
}
