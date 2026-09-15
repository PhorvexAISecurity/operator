/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-CONTEXT)
 */

package killchain

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/r6security/phoenix/api/v1beta1"
)

func ctxPolicy() model.Policy {
	return model.Policy{Tenant: "t", Namespace: "t", ProactiveFloor: 3600 * 1e9}
}

// TestAIStageClassification verifies the supported event-backed AI branches and that namespace
// dispersion cannot manufacture GPU attack evidence.
func TestAIStageClassification(t *testing.T) {
	m := NewModel()
	panicEvt := model.SecurityEventInfo{Type: v1beta1.TypePanic, ThreatLevel: "high", TargetsPod: true}

	// non-AI pod: no AI stage, generic path.
	gen := &model.WorkloadView{Pod: model.Pod{Namespace: "t", Name: "web"}, Physics: model.NeutralPhysics(),
		Events: []model.SecurityEventInfo{panicEvt}}
	a := m.Assess(gen, ctxPolicy(), 60, 3600)
	if a.AIClassified || a.Stage != StagePersist {
		t.Fatalf("non-AI pod must use generic chain, got stage=%s ai=%v", a.StageName, a.AIClassified)
	}

	// model server + persist event => prompt-injection persistence.
	ai := &model.WorkloadView{Pod: model.Pod{Namespace: "t", Name: "nim", ModelID: "llama-70b"},
		Physics: model.NeutralPhysics(), Events: []model.SecurityEventInfo{panicEvt}}
	a = m.Assess(ai, ctxPolicy(), 60, 3600)
	if !a.AIClassified || a.Stage != StagePromptInjectPersist {
		t.Fatalf("model server + persist event must classify prompt-inject-persist, got %s ai=%v", a.StageName, a.AIClassified)
	}
	if a.NextStage != StageLateral {
		t.Fatalf("prompt-inject successor must be lateral, got %s", a.NextStageName)
	}

	// A GPU plus the historical namespace-count proxy is context only. It is not proof that
	// another workload shares this device or that a side-channel exists.
	ph := model.NeutralPhysics()
	ph.CoResidency, ph.ModelRarity = 1.5, 1.4
	gpu := &model.WorkloadView{Pod: model.Pod{Namespace: "t", Name: "nim2", HasGPU: true}, Physics: ph}
	a = m.Assess(gpu, ctxPolicy(), 60, 3600)
	if a.AIClassified || a.Stage != StageRecon {
		t.Fatalf("namespace dispersion must not classify a GPU attack, got %s ai=%v", a.StageName, a.AIClassified)
	}

	// Exposed endpoint plus a trusted exploit signal retains the LLM-jacking branch.
	jack := &model.WorkloadView{Pod: model.Pod{Namespace: "t", Name: "api", ModelID: "m", EndpointPath: "/v1"},
		Physics: model.NeutralPhysics(), Events: []model.SecurityEventInfo{{Type: v1beta1.TypeDisable, ThreatLevel: "high", TargetsPod: true}}}
	a = m.Assess(jack, ctxPolicy(), 60, 3600)
	if !a.AIClassified || a.Stage != StageLLMJacking {
		t.Fatalf("trusted exploit event on a model endpoint must classify llm-jacking, got %s ai=%v", a.StageName, a.AIClassified)
	}
}

// TestPredictiveHorizonFields: PreemptMargin is a survival prob in [0,1] decreasing with
// exposure; ProjectedNextStageSec decreases with exposure and goes negative when overdue.
func TestPredictiveHorizonFields(t *testing.T) {
	m := NewModel()
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "t", Name: "web"}, Physics: model.NeutralPhysics()}
	early := m.Assess(v, ctxPolicy(), 60, 3600)
	late := m.Assess(v, ctxPolicy(), 1700, 3600)
	if early.PreemptMargin <= late.PreemptMargin {
		t.Fatalf("preempt margin must fall with exposure: early=%.3f late=%.3f", early.PreemptMargin, late.PreemptMargin)
	}
	if early.PreemptMargin < 0 || early.PreemptMargin > 1 {
		t.Fatalf("preempt margin out of [0,1]: %.3f", early.PreemptMargin)
	}
	if early.ProjectedNextStageSec <= late.ProjectedNextStageSec {
		t.Fatalf("projected-next must shrink with exposure: early=%.0f late=%.0f", early.ProjectedNextStageSec, late.ProjectedNextStageSec)
	}
}

// TestKVRecoverScale: a prompt-injection-persisted agent with a KV implant recovers
// P(hold) over KVRebuildSec, so right after a wipe it is NOT damped to ~0 like a
// generic foothold (the persisted state survives the rotation).
func TestKVRecoverScale(t *testing.T) {
	m := NewModel()
	panicEvt := model.SecurityEventInfo{Type: v1beta1.TypePanic, ThreatLevel: "high", TargetsPod: true}
	ph := model.NeutralPhysics()
	ph.KVRebuildSec = 300
	v := &model.WorkloadView{Pod: model.Pod{Namespace: "t", Name: "nim", ModelID: "m"}, Physics: ph,
		Events: []model.SecurityEventInfo{panicEvt}}
	// generic foothold just after a wipe (exposure 5s) is heavily damped (<0.2);
	gen := &model.WorkloadView{Pod: model.Pod{Namespace: "t", Name: "web"}, Physics: model.NeutralPhysics(),
		Events: []model.SecurityEventInfo{panicEvt}}
	aGen := m.Assess(gen, ctxPolicy(), 5, 3600)
	aKV := m.Assess(v, ctxPolicy(), 5, 3600)
	if aKV.PHold <= aGen.PHold {
		t.Fatalf("KV-persisted agent must retain more P(hold) after a wipe than a generic foothold: kv=%.3f gen=%.3f", aKV.PHold, aGen.PHold)
	}
}

// TestNegativeEvidenceFallsPrior: the symmetric memory feedback lets the per-tenant
// prior FALL on negative evidence (fixing the monotone confirmation-bias ratchet).
func TestNegativeEvidenceFallsPrior(t *testing.T) {
	mem := NewConjugateMemory()
	start := mem.PriorMean("t")
	mem.Observe("t", 0.5) // positive evidence: prior rises
	up := mem.PriorMean("t")
	mem.Observe("t", -1.0) // negative evidence: prior must FALL (was impossible before)
	down := mem.PriorMean("t")
	if up <= start {
		t.Fatalf("positive evidence must raise prior: %.3f -> %.3f", start, up)
	}
	if down >= up {
		t.Fatalf("NEGATIVE evidence must lower prior (ratchet fixed): %.3f -> %.3f", up, down)
	}
}

// TestHierarchicalColdTenant: a cold tenant inherits the FLEET base-rate, not the fixed
// 0.2 — after the fleet has learned footholds-persist, a brand-new tenant starts higher.
// TestHierarchicalColdTenant — [P-VCLUSTER O3] the cross-tenant prior is OFF by default (a cold tenant
// must NOT inherit another tenant's evidence — exact isolation), and ON only when opted in.
func TestHierarchicalColdTenant(t *testing.T) {
	// DEFAULT (cross-feed OFF): a busy tenant's evidence must NOT move a cold tenant's prior at all.
	mem := NewConjugateMemory()
	cold0 := mem.PriorMean("brand-new-0")
	for i := 0; i < 20; i++ {
		mem.Observe("busy-tenant", 1.0)
	}
	cold1 := mem.PriorMean("brand-new-1")
	if cold1 != cold0 {
		t.Fatalf("O3 LEAK: a cold tenant inherited another tenant's evidence by default: empty=%.6f after-fleet=%.6f (must be EXACTLY equal — isolated)", cold0, cold1)
	}

	// OPT-IN (a trusted tenant-group): the hierarchical fleet prior inheritance still works.
	shared := NewConjugateMemory().SetCrossTenantPrior(true)
	c0 := shared.PriorMean("nb-0")
	for i := 0; i < 20; i++ {
		shared.Observe("busy", 1.0)
	}
	c1 := shared.PriorMean("nb-1")
	if c1 <= c0 {
		t.Fatalf("opt-in hierarchical prior must inherit the elevated fleet base-rate: empty=%.3f after=%.3f", c0, c1)
	}
}
