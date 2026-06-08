package scenarios

import (
	"context"
	"fmt"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai1LLMJacking{}) }

// ai1LLMJacking: LLM-Jacking — hijack GPU compute on the mock inference server.
// SPLIT ORACLE:
//   (a) in-request: a shadow-compute job accrued work units (work_accrued>0). The
//       GPU-util detector is RECEIVER-ONLY (no emitter) -> MTD-CANNOT-HELP; the
//       headline GPU number is CAPABILITY-PENDING (CPU stand-in runs everywhere).
//   (b) persistence: the shadow foothold survives a rotation. An injected panic
//       SecurityEvent (zero-GPU quarantine / pod evict) BOUNDS the foothold.
type ai1LLMJacking struct {
	infer *mocks.MockInferenceServer
}

func (s *ai1LLMJacking) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:     "ai1-llm-jacking",
		Category: core.CategoryR6Claimed,
		Source:   "R6 Phoenix-for-AI (LLM-Jacking); AI-MTD-AUDIT #8 GPU-util RECEIVER-ONLY; ATLAS",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1496.001", "T1610", "T1059.013"},
		CapabilityRequirements: []core.Capability{core.CapGPU},
		R6Justification:        "GPU-utilization detector is RECEIVER-ONLY (no emitter wired); rotation cannot stop in-request shadow compute. An injected panic only bounds the foothold (zero-GPU quarantine / evict). Headline GPU-util SLO is GPU-PENDING. Partial.",
	}
}

func (s *ai1LLMJacking) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	return nil
}

func (s *ai1LLMJacking) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// In-request: a hijacked shadow-compute job accrues GPU-seconds (CPU proxy).
	s.infer.AccrueShadowCompute(ctx, env, 50)
	stages := []string{
		"llm-jacking: hijack GPU compute on the inference endpoint (T1496.001)",
		"shadow-compute: accrue work units on the mock model (work_accrued += shadow marker)",
	}
	cmds := []string{"shadow job -> /tmp/work_accrued += 50; /tmp/shadow=" + mocks.ShadowComputeMarker}
	// Genuine matcher path (FullPhoenix): inject a panic to bound the foothold.
	if emitGenuineTrigger(ctx, env, s.infer.PodName, amtdv1beta1.TypePanic) {
		cmds = append(cmds, "emit panic SecurityEvent -> matcher -> Delete (zero-GPU quarantine)")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai1LLMJacking) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// (a) in-request: work accrued by the shadow job (CPU proxy for GPU-util).
	work, _ := s.infer.WorkAccrued(ctx, env)
	shadowSeen := s.infer.MarkerPresent(ctx, env, "/tmp/shadow", mocks.ShadowComputeMarker)
	inReq := work > 0 && shadowSeen

	// (b) persistence: does the shadow marker survive a rotation? Allow a window.
	time.Sleep(6 * time.Second)
	persisted := s.infer.MarkerPresent(ctx, env, "/tmp/shadow", mocks.ShadowComputeMarker)
	// A rotating arm (or the injected panic) should bound the foothold.
	disrupted := armRotates(env) && !persisted

	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted, // attacker "wins" iff foothold survived
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: disrupted,
		neutralized:          armIsFullPhoenix(env) && !persisted,
		triggerAttribution:   core.TriggerReceiverOnly, // GPU-util detector is receiver-only
		detectorAbsent:       true,                     // no autonomous detector for in-request
		capabilityPending:    true,
		capabilityNote:       "headline GPU-utilization SLO is GPU-PENDING (CapGPU); CPU work_accrued proxy ran",
		atlas:                []string{"AML.T0011", "AML.T0034", "AML.T0024.001", "AML.T0029"},
		owasp:                []string{"LLM10:2025"},
		state:                fmt.Sprintf("in-request work_accrued=%d shadow=%v; persisted-after-rotation=%v (MTD bounds foothold, GPU number pending)", work, inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai1LLMJacking) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
