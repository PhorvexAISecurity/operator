package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2UnboundedConsumption{}) }

// ai2UnboundedConsumption: OWASP LLM10 — unbounded query volume drains cost. SPLIT
// ORACLE: (a) work_accrued above budget (GPU-util detector RECEIVER-ONLY ->
// CANNOT-HELP autonomously; headline GPU-$ number CAPABILITY-PENDING);
// (b) the consuming client keeps its accrual channel across a rotation -> BOUNDS-ONLY.
type ai2UnboundedConsumption struct{ infer *mocks.MockInferenceServer }

// consumptionBudget is the work-unit budget above which the wallet-drain marker
// fires (the pure threshold the oracle compares against).
const consumptionBudget int64 = 25

func (s *ai2UnboundedConsumption) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-unbounded-consumption",
		Category:           core.CategoryR6Claimed,
		Source:             "OWASP LLM10:2025 Unbounded Consumption; CPU stand-in for GPU",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1496.001", "T1499"},
		CapabilityRequirements: []core.Capability{core.CapGPU},
		R6Justification:        "GPU-util detector is RECEIVER-ONLY — rotation cannot autonomously stop accrual. Rotation bounds the accrual channel only with an injected trigger. Headline GPU-$ number is GPU-PENDING. Partial.",
	}
}

func (s *ai2UnboundedConsumption) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	return nil
}

func (s *ai2UnboundedConsumption) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.infer.AccrueShadowCompute(ctx, env, 40) // drive accrual above the budget
	return core.AttackResult{
		Stages:   []string{"unbounded-consumption: high query volume accrues cost above budget (T1496.001)"},
		Commands: []string{fmt.Sprintf("accrue 40 work units (budget=%d) -> wallet-drain", consumptionBudget)},
	}, nil
}

func (s *ai2UnboundedConsumption) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	work, _ := s.infer.WorkAccrued(ctx, env)
	inReq := work > consumptionBudget
	time.Sleep(6 * time.Second)
	persisted := s.infer.MarkerPresent(ctx, env, "/tmp/shadow", mocks.ShadowComputeMarker)
	disrupted := armRotates(env) && !persisted
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerReceiverOnly,
		detectorAbsent:       true,
		capabilityPending:    true,
		capabilityNote:       "headline GPU-cost $ number is GPU-PENDING (CapGPU); CPU work_accrued proxy ran",
		atlas:                []string{"AML.T0034", "AML.T0029", "AML.T0024.002"},
		owasp:                []string{"LLM10:2025"},
		state:                fmt.Sprintf("work_accrued=%d > budget=%d in-request=%v; accrual channel survived rotation=%v", work, consumptionBudget, inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2UnboundedConsumption) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
