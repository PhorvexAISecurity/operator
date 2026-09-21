package decision

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/platform"
	"github.com/phorvex/phorvex/internal/recon"
)

func manifestValue(t *testing.T, manifest model.DecisionParameterManifest, name string) float64 {
	t.Helper()
	for _, parameter := range manifest.Parameters {
		if parameter.Name == name {
			return parameter.Default
		}
	}
	t.Fatalf("manifest has no %q", name)
	return 0
}

func TestPost25M108RegistryReadsProductionSourcesAndExportsExactly(t *testing.T) {
	manifest := ProductionParameterManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	checks := map[string]float64{
		"recon.dispersion.maximum":                  recon.MaxDispersionMult,
		"platform.co-residency.namespace-count-cap": platform.CoResidencyCap,
		"decision.provenance-floor":                 provFloor,
		"cost.lambda.seed":                          cost.DefaultLambdaSeed,
		"cost.gpu-envelope.configured":              cost.GPUEnvelopeMax(),
		"cost.ready-delay-reference-seconds":        cost.ReadyDelayReference.Seconds(),
		"cost.default-ceiling":                      cost.DefaultCostCeiling,
		"killchain.exposure-pressure-cap":           killchain.DefaultExposurePressureCap,
		"killchain.baseline-stage-urgency":          killchain.BaselineStageUrgency,
		"economics.fixed-beta.maximum":              model.MaxDisruptionAversion,
	}
	for name, want := range checks {
		if got := manifestValue(t, manifest, name); got != want {
			t.Fatalf("%s=%g, producer=%g", name, got, want)
		}
	}
	canonical := manifest.Canonical()
	raw, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	var restored model.DecisionParameterManifest
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	left, _ := canonical.CanonicalHash()
	right, _ := restored.CanonicalHash()
	if left != right || !reflect.DeepEqual(canonical, restored) {
		t.Fatalf("exact retained export changed: hash %s/%s", left, right)
	}
}

func TestPost25M108AllP1DecisionsCarryCompactExactParameterIdentity(t *testing.T) {
	pol := decisionTracePolicy(1, false)
	pol.DisruptionAversionConfigured = true
	pol.DisruptionAversion = 0.00004
	decisions := fixedTraceEngine().Decide([]*model.WorkloadView{covView("trace-off-parameters", true, 2*time.Hour, false)}, pol)
	if len(decisions) != 1 || decisions[0].Trace != nil || decisions[0].ParameterSet == nil {
		t.Fatalf("trace-off decision lost compact provenance: %+v", decisions)
	}
	ref, manifest, overrides, err := ParameterSetForPolicy(pol)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decisions[0].ParameterSet, ref) {
		t.Fatalf("decision reference mismatch: got=%+v want=%+v", decisions[0].ParameterSet, ref)
	}
	if err := model.VerifyParameterSet(decisions[0].ParameterSet, &manifest, &overrides); err != nil {
		t.Fatal(err)
	}
	changed := pol
	changed.DisruptionAversion = 0.00005
	changedRef, _, _, err := ParameterSetForPolicy(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedRef.ManifestHash != ref.ManifestHash || changedRef.PolicyOverridesHash == ref.PolicyOverridesHash {
		t.Fatalf("effective change did not isolate override hash: before=%+v after=%+v", ref, changedRef)
	}
}

func TestPost25M108RejectedExistentialDecisionCarriesParameterIdentity(t *testing.T) {
	view, pol := m99Fixture()
	decisions, err := ExistentialRejectedDecisionsChecked([]*model.WorkloadView{view}, pol, "collision", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].ParameterSet == nil {
		t.Fatalf("rejected production decision lost compact parameter provenance: %+v", decisions)
	}
	_, manifest, overrides, err := ParameterSetForPolicy(pol)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.VerifyParameterSet(decisions[0].ParameterSet, &manifest, &overrides); err != nil {
		t.Fatal(err)
	}
}

func TestPost25M108EffectivePolicyHashCoversConsumersAndRejectsInvalidInputs(t *testing.T) {
	pol := decisionTracePolicy(1, false)
	ref, _, _, err := ParameterSetForPolicy(pol)
	if err != nil {
		t.Fatal(err)
	}
	changed := pol
	changed.WeightSecrets += 0.125
	changedRef, _, _, err := ParameterSetForPolicy(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedRef.PolicyOverridesHash == ref.PolicyOverridesHash {
		t.Fatal("decision-consumed secret weight did not change effective-policy hash")
	}

	bad := []func(*model.Policy){
		func(p *model.Policy) { p.Lambda = math.NaN() },
		func(p *model.Policy) { p.DisruptionAversionConfigured, p.DisruptionAversion = true, math.Inf(1) },
		func(p *model.Policy) { p.CostCeiling = math.NaN() },
		func(p *model.Policy) { p.MaxMovesPerTick = -1 },
		func(p *model.Policy) { p.ProactiveFloor = -time.Second },
		func(p *model.Policy) { p.KillChainSojournScaleSeconds = map[string]float64{"unknown": 1} },
	}
	for i, mutate := range bad {
		candidate := pol
		mutate(&candidate)
		if _, _, _, err := ParameterSetForPolicy(candidate); err == nil {
			t.Fatalf("invalid policy case %d received a provenance hash", i)
		}
	}
}

func TestPost25M108SensitivityUsesActualShadowDecisionAndPreservesHardGates(t *testing.T) {
	view := covView("sensitivity", true, 2*time.Hour, false)
	view.Neighbors[0].Value = 0.5
	pol := economicsPolicy(0, true, 1)
	engine := fixedTraceEngine()

	var switched SensitivityResult
	found := false
	for _, beta := range []float64{0.25, 0.5, 1, 2, 4, 6, 8, 10} {
		result, err := EvaluateSensitivity(engine, []*model.WorkloadView{view}, pol,
			SensitivityRequest{Parameter: "economics.fixed-beta", Value: beta, Unit: "dimensionless"})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rows) == 1 && result.Rows[0].ActionSwitched {
			switched, found = result, true
			break
		}
	}
	if !found || !switched.DependenceOnly || switched.Rows[0].BaselineBenefit <= 0 || switched.Rows[0].VariantCost < 0 {
		t.Fatalf("actual shadow producer exposed no bounded choice dependence: %+v", switched)
	}

	blocked := pol
	blocked.CostCeiling = 1e-9
	blockedResult, err := EvaluateSensitivity(fixedTraceEngine(), []*model.WorkloadView{view}, blocked,
		SensitivityRequest{Parameter: "economics.fixed-beta", Value: 10, Unit: "dimensionless"})
	if err != nil {
		t.Fatal(err)
	}
	if len(blockedResult.Rows) != 1 || blockedResult.Rows[0].BaselineFeasible || blockedResult.Rows[0].VariantFeasible ||
		blockedResult.Rows[0].BaselineSelected || blockedResult.Rows[0].VariantSelected {
		t.Fatalf("objective shadow bypassed hard cost gate: %+v", blockedResult)
	}
}

func TestPost25M108SensitivityNoopGPUCPUUnitsAndInvalidInputs(t *testing.T) {
	cpu := covView("cpu", true, 2*time.Hour, false)
	gpu := covView("gpu", true, 2*time.Hour, false)
	gpu.Pod.HasGPU = true
	for _, view := range []*model.WorkloadView{cpu, gpu} {
		view.Physics = model.NeutralPhysics()
		view.Physics.ImageRarity = 1.1
		view.Physics.EPSSMultiplier = 1.1
		view.Physics.CoResidency = 1.1
		view.Physics.ModelRarity = 1.1
	}
	pol := decisionTracePolicy(1, false)
	result, err := EvaluateSensitivity(fixedTraceEngine(), []*model.WorkloadView{cpu, gpu}, pol,
		SensitivityRequest{Parameter: "recon.dispersion.maximum", Value: recon.MaxDispersionMult, Unit: "multiplier"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 2 {
		t.Fatalf("GPU/non-GPU rows missing: %+v", result)
	}
	for _, row := range result.Rows {
		if row.ActionSwitched || row.BaselineCost != row.VariantCost || row.BaselineBenefit != row.VariantBenefit || row.BaselineFeasible != row.VariantFeasible {
			t.Fatalf("default-value sensitivity was not a no-op: %+v", row)
		}
	}

	seconds, err := EvaluateSensitivity(fixedTraceEngine(), []*model.WorkloadView{cpu}, pol,
		SensitivityRequest{Parameter: "killchain.sojourn.recon.seconds", Value: 600, Unit: "seconds"})
	if err != nil {
		t.Fatal(err)
	}
	millis, err := EvaluateSensitivity(fixedTraceEngine(), []*model.WorkloadView{cpu}, pol,
		SensitivityRequest{Parameter: "killchain.sojourn.recon.seconds", Value: 600000, Unit: "milliseconds"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(seconds, millis) {
		t.Fatalf("equivalent time units changed shadow output:\nseconds=%+v\nmilliseconds=%+v", seconds, millis)
	}

	bad := []SensitivityRequest{
		{Parameter: "missing", Value: 1, Unit: "ratio"},
		{Parameter: "economics.fixed-beta", Value: math.NaN(), Unit: "dimensionless"},
		{Parameter: "economics.fixed-beta", Value: 11, Unit: "dimensionless"},
		{Parameter: "killchain.sojourn.unknown.seconds", Value: 1, Unit: "seconds"},
	}
	for _, req := range bad {
		if _, err := EvaluateSensitivity(fixedTraceEngine(), []*model.WorkloadView{cpu}, pol, req); err == nil {
			t.Fatalf("invalid sensitivity accepted: %+v", req)
		}
	}
	if _, err := EvaluateSensitivity(fixedTraceEngine(), nil, pol, SensitivityRequest{Parameter: "economics.fixed-beta", Value: 1, Unit: "dimensionless"}); err == nil {
		t.Fatal("missing snapshot accepted")
	}
}

func TestPost25M108SensitivityRetainsMissingAndHighLoadDistinction(t *testing.T) {
	missing := covView("missing-load", true, 2*time.Hour, false)
	loaded := covView("high-load", true, 2*time.Hour, false)
	loaded.Telemetry.ReqRate = model.PresentSignal(100000, "m108-fixture")
	loaded.Telemetry.ConnCount = model.PresentSignal(10000, "m108-fixture")
	pol := decisionTracePolicy(2, false)
	result, err := EvaluateSensitivity(fixedTraceEngine(), []*model.WorkloadView{missing, loaded}, pol,
		SensitivityRequest{Parameter: "economics.fixed-beta", Value: 0.5, Unit: "dimensionless"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rows) != 2 || result.Rows[0].Pod != missing.Pod.Name || result.Rows[1].Pod != loaded.Pod.Name {
		t.Fatalf("missing/high-load snapshots were not evaluated by the actual shadow path: %+v", result)
	}
	if missing.Telemetry.ReqRate.State == model.Present || loaded.Telemetry.ReqRate.Value != 100000 {
		t.Fatal("sensitivity mutated its caller-owned frozen snapshots")
	}
}

func TestPost25M108SensitivityLeavesNextProductionDecisionIdentical(t *testing.T) {
	view := covView("isolation", true, 2*time.Hour, false)
	pol := decisionTracePolicy(1, true)
	withSensitivity := fixedTraceEngine()
	withoutSensitivity := fixedTraceEngine()
	if _, err := EvaluateSensitivity(withSensitivity, []*model.WorkloadView{view}, pol,
		SensitivityRequest{Parameter: "killchain.exposure-pressure-cap", Value: 0.25, Unit: "ratio"}); err != nil {
		t.Fatal(err)
	}
	got := withSensitivity.Decide([]*model.WorkloadView{view}, pol)
	want := withoutSensitivity.Decide([]*model.WorkloadView{view}, pol)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shadow sensitivity mutated production state:\nwith=%+v\nwithout=%+v", got, want)
	}
	if _, allocated := withSensitivity.PersistenceLearningStatusFor(pol.Owner()); allocated {
		t.Fatal("sensitivity seeded observed-label or dedup state")
	}
}

func TestPost25M108SensitivityFreezesClockAndOwnsNestedInputs(t *testing.T) {
	view := covView("nested-snapshot", true, 2*time.Hour, false)
	view.Pod.MountedSecrets = []string{"secret-a"}
	view.Pod.AdapterObservation = &model.AdapterObservation{EventName: "event-a"}
	view.OutcomeEvents = []model.SecurityEventInfo{{
		Name: "outcome-event", ResolvedTargets: []string{"ns/pod"}, UnresolvedTargets: []string{"pod"},
		Outcomes: []model.ProtectedOutcome{{ID: "outcome-a", RequiredKeys: []string{"key-a"}}},
	}}
	view.Events = []model.SecurityEventInfo{{Name: "belief-event", ResolvedTargets: []string{"ns/pod"}}}
	pol := decisionTracePolicy(1, false)
	pol.DecisionAssets = map[string]string{"asset": "uid-a"}

	clonedViews := cloneSensitivityViews([]*model.WorkloadView{view})
	clonedPolicy := cloneSensitivityPolicy(pol)
	clonedViews[0].Pod.MountedSecrets[0] = "changed"
	clonedViews[0].Pod.AdapterObservation.EventName = "changed"
	clonedViews[0].OutcomeEvents[0].ResolvedTargets[0] = "changed"
	clonedViews[0].OutcomeEvents[0].UnresolvedTargets[0] = "changed"
	clonedViews[0].OutcomeEvents[0].Outcomes[0].RequiredKeys[0] = "changed"
	clonedViews[0].Events[0].ResolvedTargets[0] = "changed"
	clonedPolicy.DecisionAssets["asset"] = "changed"
	if view.Pod.MountedSecrets[0] != "secret-a" || view.Pod.AdapterObservation.EventName != "event-a" ||
		view.OutcomeEvents[0].ResolvedTargets[0] != "ns/pod" || view.OutcomeEvents[0].UnresolvedTargets[0] != "pod" ||
		view.OutcomeEvents[0].Outcomes[0].RequiredKeys[0] != "key-a" || view.Events[0].ResolvedTargets[0] != "ns/pod" ||
		pol.DecisionAssets["asset"] != "uid-a" {
		t.Fatal("sensitivity snapshot clone retained caller-owned nested references")
	}

	engine := fixedTraceEngine()
	clockReads := 0
	engine.Now = func() time.Time {
		clockReads++
		return time.Unix(int64(clockReads), 0)
	}
	if _, err := EvaluateSensitivity(engine, []*model.WorkloadView{view}, pol,
		SensitivityRequest{Parameter: "economics.fixed-beta", Value: 1, Unit: "dimensionless"}); err != nil {
		t.Fatal(err)
	}
	if clockReads != 1 {
		t.Fatalf("sensitivity read a moving production clock %d times", clockReads)
	}
	if _, err := EvaluateSensitivity(engine, []*model.WorkloadView{nil}, pol,
		SensitivityRequest{Parameter: "economics.fixed-beta", Value: 1, Unit: "dimensionless"}); err == nil {
		t.Fatal("nil snapshot entry accepted")
	}
}
