/*
 * Phorvex — COST MODEL AUDIT (unitless side).
 *
 * Executable verification of the decision-cost contract: C_norm, C_flow, ECost, CHi and the
 * always-true invariants. Every assertion here is the SPEC, not a snapshot of current behaviour —
 * if the code drifts, these fail.
 */

package cost

import (
	"math"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

const eps = 1e-9

func defaultPolicy() model.Policy {
	return model.Policy{NormSparsity: 0.4, FlowDisruption: 0.6}
}

// bareView is a view with NO telemetry — the "missing data is neutral, not garbage" case.
func bareView() *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{Namespace: "ns", Name: "p"}}
}

// ---------- Part 1 — C_norm ----------

func TestPart1_CNorm(t *testing.T) {
	if got := len(structuralComponents); got != 3 {
		t.Fatalf("structural component registry has %d entries, want 3", got)
	}
	view := bareView()
	if got := normCostP1(view, model.Move{Action: model.ActionRotate}); got != 1.0 {
		t.Errorf("C_norm(rotate) = %v, want exactly 1.0", got)
	}
	wantQ := 1.0 / float64(len(structuralComponents))
	got := normCostP1(view, model.Move{Action: model.ActionQuarantine})
	if math.Abs(got-wantQ) > eps {
		t.Errorf("C_norm(quarantine) = %v, want 1/registered-components = %v", got, wantQ)
	}
	if math.Abs(got-0.3333333333333333) > 1e-9 {
		t.Errorf("C_norm(quarantine) = %v, want 0.333… at live=2", got)
	}
	if got := normCostP1(view, model.Move{Action: model.ActionNoop}); got != 0 {
		t.Errorf("C_norm(noop) = %v, want exactly 0", got)
	}
}

// C_norm may read structural workload context, but never telemetry.
func TestPart1_CNormIsPurelyStructural(t *testing.T) {
	bare := bareView()
	rich := bareView()
	rich.Telemetry = model.Telemetry{ConnCount: model.PresentSignal(88, "test"), ReqRate: model.PresentSignal(144, "test")}
	for _, a := range append([]model.Action{model.ActionNoop}, model.MutatingActions...) {
		got := normCostP1(bare, model.Move{Action: a})
		if got < 0 || math.IsNaN(got) || math.IsInf(got, 0) {
			t.Errorf("C_norm(%s) = %v, want finite non-negative", a, got)
		}
		if richGot := normCostP1(rich, model.Move{Action: a}); richGot != got {
			t.Errorf("C_norm(%s) changed with telemetry: bare=%v rich=%v", a, got, richGot)
		}
	}
	// Repeated calls are deterministic (no hidden state).
	for i := 0; i < 100; i++ {
		if normCostP1(bare, model.Move{Action: model.ActionQuarantine}) != 1.0/3.0 {
			t.Fatal("C_norm(quarantine) is not deterministic")
		}
	}
}

func TestPart1_AllMutatingActionsHaveProvisionalStructuralCost(t *testing.T) {
	view := bareView()
	view.Pod.RouteService = "model-route"
	view.Pod.RouteServiceReady = true
	view.Pod.ParallelSize = 4
	want := map[model.Action]float64{
		model.ActionRotate:                        1.00,
		model.ActionQuarantine:                    1.0 / 3.0,
		model.ActionDebugger:                      0.10,
		model.ActionCustomInject:                  0.10,
		model.ActionIdentityRotate:                0.15,
		model.ActionRouteRotate:                   0.10,
		model.ActionWarmSwap:                      1.00,
		model.ActionMIGRebind:                     1.25,
		model.ActionKVReset:                       0.20,
		model.ActionEndpointRotate:                0.35,
		model.ActionModelShardReplace:             4.00,
		model.ActionAdapterRotate:                 0.25,
		model.ActionSensitiveOutputPolicyActivate: 0.25,
		model.ActionVoiceMemoryNoteRevoke:         0.25,
		model.ActionVoiceRefundPairDeny:           0.25,
		model.ActionVoiceOutputPolicyActivate:     0.25,
		model.ActionVoiceMCPToolPin:               0.25,
		model.ActionVoiceSessionAdmissionEnforce:  0.25,
		model.ActionLiteLLMClientRevoke:           0.25,
		model.ActionEndpointLeaseRevoke:           0.25,
		model.ActionCRMRefundRevoke:               0.25,
		model.ActionThrottle:                      0.25,
		model.ActionRequestDrain:                  0.10,
		model.ActionGuardrailRotate:               0.20,
		model.ActionKVMigrateInvalidate:           0.20,
		// Bare view: owner desired 0 and no observation => 1 logical workload replacement.
		model.ActionControllerStop: 1.00,
		// Combined in-place actuators (serving-configuration / channel-deny tier, replica-retaining).
		model.ActionK8sObjectRevert:  0.20,
		model.ActionDatastoreRestore: 0.25,
		model.ActionNetworkIsolate:   0.25,
		model.ActionCredentialRevoke: 0.25,
		model.ActionAgentActionDeny:  0.25,
		// node-cordon-drain-replace recycles the node (pod replacement scaled to a node).
		model.ActionNodeCordonDrainReplace: 1.25,
		// registry-rollback resets the owning controller image (one logical workload replacement).
		model.ActionRegistryRollback: 1.00,
	}
	for _, action := range model.MutatingActions {
		got := normCostP1(view, model.Move{Action: action})
		if got <= 0 {
			t.Errorf("mutating action %s has non-positive C_norm %v", action, got)
		}
		if got != want[action] {
			t.Errorf("C_norm(%s)=%v, want %v", action, got, want[action])
		}
	}
	if normCostP1(view, model.Move{Action: model.ActionMIGRebind}) <= normCostP1(view, model.Move{Action: model.ActionRotate}) {
		t.Error("mig-rebind must remain structurally above the rotate anchor")
	}
	if normCostP1(view, model.Move{Action: model.ActionKVReset}) >= normCostP1(view, model.Move{Action: model.ActionMIGRebind}) {
		t.Error("kv-reset must remain structurally below mig-rebind")
	}
}

func TestPart1_ContextDependentStructuralCosts(t *testing.T) {
	view := bareView()
	if got := normCostP1(view, model.Move{Action: model.ActionEndpointRotate}); got != 0.10 {
		t.Fatalf("label-only endpoint path C_norm=%v, want 0.10", got)
	}
	view.Pod.RouteService = "model-route"
	view.Pod.RouteServiceReady = true
	if got := normCostP1(view, model.Move{Action: model.ActionEndpointRotate}); got != 0.35 {
		t.Fatalf("effective Service re-key C_norm=%v, want 0.35", got)
	}
	for _, size := range []int{-1, 0, 1, 2, 8} {
		view.Pod.ParallelSize = size
		want := float64(size)
		if want < 1 {
			want = 1
		}
		if got := normCostP1(view, model.Move{Action: model.ActionModelShardReplace}); got != want {
			t.Errorf("parallelSize=%d C_norm=%v, want %v", size, got, want)
		}
	}
}

// ---------- Part 2 — C_flow ----------

func TestPart2_CFlowQuarantineNoTelemetry(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	v := bareView()
	// ECost = 0.4*C_norm + 0.6*C_flow  =>  C_flow = (ECost - 0.4*C_norm)/0.6
	e := c.ECost(v, model.Move{Action: model.ActionQuarantine}, pol)
	cFlow := (e - pol.NormSparsity*(1.0/3.0)) / pol.FlowDisruption
	if math.Abs(cFlow-0.25) > 1e-9 {
		t.Errorf("C_flow(quarantine, no telemetry) = %v, want exactly 0.25 (no phantom load term)", cFlow)
	}
}

func TestPart2_CFlowQuarantineLoadTermBounded(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	for _, conn := range []float64{0, 1, 50, 100, 1000, 1e9} {
		v := bareView()
		v.Telemetry = model.Telemetry{ConnCount: model.PresentSignal(conn, "test")}
		e := c.ECost(v, model.Move{Action: model.ActionQuarantine}, pol)
		cFlow := (e - pol.NormSparsity*(1.0/3.0)) / pol.FlowDisruption
		if cFlow < 0.25-1e-9 || cFlow > 0.40+1e-9 {
			t.Errorf("C_flow(quarantine, conn=%v) = %v, want within [0.25, 0.40]", conn, cFlow)
		}
	}
	// monotone non-decreasing in ConnCount
	prev := -1.0
	for _, conn := range []float64{0, 10, 25, 50, 75, 100, 200} {
		v := bareView()
		v.Telemetry = model.Telemetry{ConnCount: model.PresentSignal(conn, "test")}
		e := c.ECost(v, model.Move{Action: model.ActionQuarantine}, pol)
		cFlow := (e - pol.NormSparsity*(1.0/3.0)) / pol.FlowDisruption
		if cFlow < prev-1e-12 {
			t.Errorf("C_flow(quarantine) decreased as ConnCount rose to %v", conn)
		}
		prev = cFlow
	}
}

// Feed a KNOWN phi and assert the dot product against the documented prior theta.
func TestPart2_CFlowRotateDotProduct(t *testing.T) {
	wantTheta := [featureDim]float64{0.15, 0.85, 0.55, 0.0, 0.45, 0.20}
	if got := priorTheta(); got != wantTheta {
		t.Fatalf("prior theta = %v, want %v", got, wantTheta)
	}
	r := NewRLS()
	cases := []struct {
		name string
		f    [featureDim]float64
		want float64
	}{
		{"bias only (idle-ish, no gpu, no load)", [featureDim]float64{1, 0, 0, 0, 0, 0}, 0.15},
		{"cold start", [featureDim]float64{1, 1, 0, 0, 0, 0}, 0.15 + 0.85},
		{"warm", [featureDim]float64{1, 0, 1, 0, 0, 0}, 0.15 + 0.55},
		{"idle (zero weight)", [featureDim]float64{1, 0, 0, 1, 0, 0}, 0.15},
		{"cold + gpu + full load", [featureDim]float64{1, 1, 0, 0, 1, 1}, 0.15 + 0.85 + 0.45 + 0.20},
		{"clamp high", [featureDim]float64{10, 10, 10, 10, 10, 10}, 2.0},
	}
	for _, tc := range cases {
		if got := r.Predict(tc.f); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: Predict = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPart2_CFlowRotateClampedToRange(t *testing.T) {
	r := NewRLS()
	// force a negative theta to prove the lower clamp
	r.theta = [featureDim]float64{-5, 0, 0, 0, 0, 0}
	if got := r.Predict([featureDim]float64{1, 0, 0, 0, 0, 0}); got != 0 {
		t.Errorf("negative prediction not clamped: %v, want 0", got)
	}
	r.theta = [featureDim]float64{99, 0, 0, 0, 0, 0}
	if got := r.Predict([featureDim]float64{1, 0, 0, 0, 0, 0}); got != 2 {
		t.Errorf("large prediction not clamped: %v, want 2", got)
	}
}

func TestPart2_CFlowNoopIsZero(t *testing.T) {
	c := NewP1Cost()
	if got := c.ECost(bareView(), model.Move{Action: model.ActionNoop}, defaultPolicy()); got != 0 {
		t.Errorf("ECost(noop) = %v, want exactly 0", got)
	}
}

// Without a completed rotation observation, identical inputs must keep an identical
// prior C_flow. The live runner wiring is covered separately in runner tests.
func TestPart2_RLSIsFrozenPriorUnlessObserved(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	v := bareView()
	v.Phase = model.PhaseWarm
	first := c.ECost(v, model.Move{Action: model.ActionRotate}, pol)
	for i := 0; i < 500; i++ {
		if got := c.ECost(v, model.Move{Action: model.ActionRotate}, pol); got != first {
			t.Fatalf("C_flow(rotate) drifted without ObserveRotation: %v -> %v", first, got)
		}
	}
	if c.RLS.Primed() {
		t.Error("RLS reports primed with no observations")
	}
	// It DOES move when explicitly observed. The live runner wiring is covered in
	// runner/rotation_observation_test.go.
	c.ObserveRotation(v, 1.9)
	if got := c.ECost(v, model.Move{Action: model.ActionRotate}, pol); got == first {
		t.Error("ObserveRotation did not change respawn C_flow")
	}
}

// ---------- Part 3 — ECost / CHi ----------

func TestPart3_ECostWeightsAndSanityExample(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	v := bareView()
	// quarantine, no telemetry: 0.4*0.3333 + 0.6*0.25 = 0.283333
	want := 0.4*(1.0/3.0) + 0.6*0.25
	got := c.ECost(v, model.Move{Action: model.ActionQuarantine}, pol)
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("ECost(quarantine) = %v, want %v", got, want)
	}
	if math.Abs(got-0.2833333333333333) > 1e-9 {
		t.Errorf("ECost(quarantine) = %v, want 0.2833…", got)
	}
	// An unknown phase with missing load preserves the raw bias as provenance but
	// cannot be priced below the source-owned Unknown floor.
	wantRot := 0.4*1.0 + 0.6*0.5
	gotRot := c.ECost(v, model.Move{Action: model.ActionRotate}, pol)
	if math.Abs(gotRot-wantRot) > 1e-9 {
		t.Errorf("ECost(rotate, bare) = %v, want %v", gotRot, wantRot)
	}
}

func TestPart3_WeightsComeFromPolicy(t *testing.T) {
	c := NewP1Cost()
	v := bareView()
	pol := model.Policy{NormSparsity: 1.0, FlowDisruption: 0.0}
	if got := c.ECost(v, model.Move{Action: model.ActionRotate}, pol); math.Abs(got-1.0) > 1e-9 {
		t.Errorf("with weights (1,0) ECost(rotate) = %v, want C_norm = 1.0", got)
	}
	pol = model.Policy{NormSparsity: 0.0, FlowDisruption: 1.0}
	if got := c.ECost(v, model.Move{Action: model.ActionRotate}, pol); math.Abs(got-0.5) > 1e-9 {
		t.Errorf("with weights (0,1) ECost(rotate) = %v, want conservative C_flow = 0.5", got)
	}
}

func TestPart3_CHiNeverBelowECost(t *testing.T) {
	pol := defaultPolicy()
	for _, gpu := range []bool{false, true} {
		for _, ph := range []model.WorkloadPhase{model.PhaseColdStarting, model.PhaseWarm, model.PhaseIdle} {
			c := NewP1Cost()
			v := bareView()
			v.Pod.HasGPU = gpu
			v.Phase = ph
			for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine, model.ActionNoop} {
				m := model.Move{Action: a}
				e, hi := c.ECost(v, m, pol), c.CHi(v, m, pol)
				if hi < e-eps {
					t.Errorf("CHi < ECost for action=%s gpu=%v phase=%v: %v < %v", a, gpu, ph, hi, e)
				}
			}
		}
	}
}

func TestPart3_CostCeilingValue(t *testing.T) {
	pol := defaultPolicy()
	ceiling := EffectiveCostCeiling(pol)
	if ceiling != DefaultCostCeiling {
		t.Errorf("cost ceiling = %v, want imported default %v", ceiling, DefaultCostCeiling)
	}
	// A GPU rotate gets the configured worst-case envelope: assert it is the case that
	// actually approaches/【exceeds】the ceiling, which is what the SLO gate is there to catch.
	c := NewP1Cost()
	v := bareView()
	v.Pod.HasGPU = true
	v.Phase = model.PhaseColdStarting
	hi := c.CHi(v, model.Move{Action: model.ActionRotate}, pol)
	if hi <= 0 || math.IsNaN(hi) || math.IsInf(hi, 0) {
		t.Fatalf("CHi not finite/positive: %v", hi)
	}
	if hi <= ceiling {
		t.Fatalf("GPU cold rotate CHi %.4f must exceed ceiling %.2f", hi, ceiling)
	}
}

// ---------- Always-true invariants ----------

func TestInvariants_NonNegativeFiniteDeterministic(t *testing.T) {
	pol := defaultPolicy()
	views := []*model.WorkloadView{}
	for _, gpu := range []bool{false, true} {
		for _, ph := range []model.WorkloadPhase{"", model.PhaseColdStarting, model.PhaseWarm, model.PhaseIdle} {
			for _, tel := range []bool{false, true} {
				v := bareView()
				v.Pod.HasGPU = gpu
				v.Phase = ph
				if tel {
					v.Telemetry = model.Telemetry{ConnCount: model.PresentSignal(137, "test"), ReqRate: model.PresentSignal(321, "test")}
				}
				views = append(views, v)
			}
		}
	}
	for i, v := range views {
		c := NewP1Cost()
		for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine, model.ActionNoop} {
			m := model.Move{Action: a}
			e := c.ECost(v, m, pol)
			hi := c.CHi(v, m, pol)
			if e < 0 || math.IsNaN(e) || math.IsInf(e, 0) {
				t.Errorf("view#%d %s: ECost not finite/non-negative: %v", i, a, e)
			}
			if hi < 0 || math.IsNaN(hi) || math.IsInf(hi, 0) {
				t.Errorf("view#%d %s: CHi not finite/non-negative: %v", i, a, hi)
			}
			// determinism: same view + same policy -> identical cost
			c2 := NewP1Cost()
			if e2 := c2.ECost(v, m, pol); e2 != e {
				t.Errorf("view#%d %s: non-deterministic ECost %v vs %v", i, a, e, e2)
			}
		}
	}
}

// A NaN/Inf in telemetry must not poison the cost (missing/garbage data => neutral, not garbage).
func TestInvariants_GarbageTelemetryDoesNotPoisonCost(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	for _, bad := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), -1} {
		v := bareView()
		v.Telemetry = model.Telemetry{ConnCount: telSig(bad), ReqRate: telSig(bad)}
		for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
			got := c.ECost(v, model.Move{Action: a}, pol)
			if math.IsNaN(got) || math.IsInf(got, 0) || got < 0 {
				t.Errorf("telemetry=%v action=%s: ECost = %v, want finite non-negative", bad, a, got)
			}
		}
	}
}

func TestNaNFeatureFailsConservativeWithDistinctCategory(t *testing.T) {
	c := NewP1Cost()
	pol := defaultPolicy()
	view := bareView()
	view.Telemetry = model.Telemetry{ReqRate: model.Signal{Value: math.NaN(), State: model.Error}}
	eval := c.Evaluation(view, model.Move{Action: model.ActionRotate}, pol)
	if eval.Total != NaNFailConservativeCost || eval.CHi != NaNFailConservativeCost {
		t.Fatalf("NaN evaluation did not use max cost: %+v", eval)
	}
	if eval.UnactionableCategory != UnactionableNaNCategory || eval.NaNFeature != "telemetry.reqRate" {
		t.Fatalf("NaN classification lost: %+v", eval)
	}
}

// The CHi >= ECost contract rests on the conformal slack never being negative. Verify the
// mechanism rather than assuming it: ConformalBound.Observe stores max(0, residual), so the
// quantile is an order statistic over non-negative values no matter what is observed.
func TestPart3_ConformalSlackIsNeverNegative(t *testing.T) {
	c := NewP1Cost()
	for _, r := range []float64{-0.9, -5, -1e6, 0, 0.3, 7} {
		c.Conformal.Observe(r)
	}
	if q := c.Conformal.Quantile(); q < 0 {
		t.Errorf("conformal quantile = %v after negative observations, want >= 0 (Observe must clamp residuals at 0)", q)
	}
	// and the end-to-end contract still holds on that populated window
	pol := defaultPolicy()
	v := bareView()
	v.Phase = model.PhaseWarm
	m := model.Move{Action: model.ActionRotate}
	if e, hi := c.ECost(v, m, pol), c.CHi(v, m, pol); hi < e-eps {
		t.Errorf("CHi (%v) below ECost (%v)", hi, e)
	}
}

// telSig mirrors ingest typing for tests: non-finite => State=Error, finite => Present. (T1-C)
func telSig(v float64) model.Signal {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return model.Signal{Value: v, State: model.Error}
	}
	return model.PresentSignal(v, "test")
}
