package scenarios

import (
	"context"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

func init() { core.RegisterScenario(&ai2CoLocationCrossTenant{}) }

// ai2CoLocationCrossTenant: cross-tenant co-location (noisy-neighbor / co-residency
// on a shared GPU). SPLIT ORACLE: (a) co-residency achieved (CANNOT-HELP
// autonomously); (b) co-residency persisted — BOUNDS-ONLY via node-rotation (BUILT
// #6) breaking co-location. True relocation is CAPABILITY-PENDING (CapMultiNode/
// CapGPU). Skip-with-note on kind (no GPU, single node).
type ai2CoLocationCrossTenant struct{}

func (s *ai2CoLocationCrossTenant) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:                   "ai2-co-location-cross-tenant",
		Category:               core.CategoryModernUnsupported,
		Source:                 "Cross-tenant co-location (co-residency on shared GPU); GPU-PENDING",
		R6ResponseTag:          core.R6Partial,
		AttackTechniqueIDs:     []string{"T1530", "T1610"},
		CapabilityRequirements: []core.Capability{core.CapGPU, core.CapMultiNode},
		R6Justification:        "Co-residency is achieved autonomously. Node-rotation (BUILT #6) breaks co-location, but true relocation MTTR is CapMultiNode/CapGPU-pending. Skip-with-note on kind. Partial.",
	}
}

func (s *ai2CoLocationCrossTenant) Setup(ctx context.Context, env *core.Env) error { return nil }

func (s *ai2CoLocationCrossTenant) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	return core.AttackResult{
		Stages:     []string{"co-location: achieve co-residency with the victim on a shared node/GPU (capability-pending)"},
		Commands:   []string{"co-residency marker (capability-pending)"},
		Skipped:    true,
		SkipReason: "co-residency requires a shared GPU + multiple nodes (CapGPU/CapMultiNode); validated on AWS/CoreWeave",
	}, nil
}

func (s *ai2CoLocationCrossTenant) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	return aiSkip(core.SplitPersistence,
		"co-residency + node-relocation number capability-pending (CapGPU/CapMultiNode); node-rotation action BUILT (#6)",
		[]string{"AML.T0024.002", "AML.T0040", "AML.T0029"}, []string{"LLM02:2025", "LLM10:2025"}), nil
}

func (s *ai2CoLocationCrossTenant) Teardown(ctx context.Context, env *core.Env) error { return nil }
