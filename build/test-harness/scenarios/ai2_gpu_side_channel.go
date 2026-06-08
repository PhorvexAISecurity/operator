package scenarios

import (
	"context"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&ai2GPUSideChannel{}) }

// ai2GPUSideChannel: model theft via a GPU side-channel (timing/contention
// leakage). MTD-CANNOT-HELP (a hardware side-channel below the infra-MTD layer);
// the headline number is CAPABILITY-PENDING. On a no-GPU kind node it SKIPS-WITH-
// NOTE (CapGPU+CapMultiNode unmet) — never a failure, marked capability-pending.
type ai2GPUSideChannel struct{}

func (s *ai2GPUSideChannel) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:                   "ai2-gpu-side-channel",
		Category:               core.CategoryModernUnsupported,
		Source:                 "Model theft via GPU side-channel (timing/contention); GPU-PENDING per AUDIT",
		R6ResponseTag:          core.R6CannotRespond,
		AttackTechniqueIDs:     []string{"T1530"},
		CapabilityRequirements: []core.Capability{core.CapGPU, core.CapMultiNode},
		R6Justification:        "A hardware side-channel sits below the infra-MTD layer; rotation cannot touch it. Headline number is GPU-PENDING. Skip-with-note on kind (no GPU).",
	}
}

func (s *ai2GPUSideChannel) Setup(ctx context.Context, env *core.Env) error { return nil }

func (s *ai2GPUSideChannel) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// Reached only if CapGPU+CapMultiNode are present; on kind the runner skips
	// before this via the capability gate. Provide a containment-safe stub.
	return core.AttackResult{
		Stages:     []string{"gpu-side-channel: timing/contention observation (GPU number capability-pending)"},
		Commands:   []string{"side-channel observation (mocked marker on GPU)"},
		Skipped:    true,
		SkipReason: "GPU side-channel headline number is capability-pending (CapGPU/CapMultiNode); validated on AWS/CoreWeave",
	}, nil
}

func (s *ai2GPUSideChannel) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	return aiSkip(core.SplitInRequest,
		"GPU side-channel below the infra-MTD layer; REAL recovery number capability-pending (CapGPU/CapMultiNode)",
		[]string{"AML.T0024.001", "AML.T0035", "AML.T0040"}, []string{"LLM02:2025"}), nil
}

func (s *ai2GPUSideChannel) Teardown(ctx context.Context, env *core.Env) error { return nil }
