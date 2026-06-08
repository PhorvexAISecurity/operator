package scenarios

import (
	"context"
	"fmt"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2PoisonedModelRegistry{}) }

// ai2PoisonedModelRegistry: AI supply chain — a malicious model/version pushed to
// the registry. SPLIT ORACLE: (a) poisoned model pulled+served (no benignity check
// -> CANNOT-HELP autonomously); (b) restore-to-golden — an INJECTED drift ->
// Regenerate (BUILT #5) restores the signed golden digest -> MTD-NEUTRALIZES.
// Signing proves provenance NOT benignity (audit caveat carried).
type ai2PoisonedModelRegistry struct{ reg *mocks.MockModelRegistry }

func (s *ai2PoisonedModelRegistry) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-poisoned-model-registry",
		Category:           core.CategoryR6Claimed,
		Source:             "AI supply chain: poisoned model registry; mock model registry",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1195", "T1525"},
		R6Justification:    "No benignity check, so the poisoned pull+serve is not prevented autonomously. An injected drift -> Regenerate (BUILT #5) restores the signed golden digest. Signing proves provenance not benignity (caveat carried). Covers via injected drift.",
	}
}

func (s *ai2PoisonedModelRegistry) Setup(ctx context.Context, env *core.Env) error {
	reg, err := mocks.DeployMockModelRegistry(ctx, env)
	if err != nil {
		return err
	}
	s.reg = reg
	return nil
}

func (s *ai2PoisonedModelRegistry) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.reg.PoisonManifest(ctx, env)
	stages := []string{"supply-chain: poisoned model artifact pulled from the registry and served (T1195)"}
	cmds := []string{"served digest -> " + mocks.PoisonedModelDigest}
	if emitGenuineTrigger(ctx, env, s.reg.PodName, amtdv1beta1.TypeTimed) {
		s.reg.RestoreGolden(ctx, env)
		cmds = append(cmds, "emit drift(timed) -> Regenerate -> golden digest restored")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai2PoisonedModelRegistry) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	digest := s.reg.ServedDigest(ctx, env)
	inReq := digest == mocks.PoisonedModelDigest
	time.Sleep(4 * time.Second)
	digest = s.reg.ServedDigest(ctx, env)
	poisonGone := digest == mocks.GoldenModelDigest
	neutralized := armIsFullPhoenix(env) && poisonGone
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             !poisonGone,
		inRequestAchieved:    inReq,
		persistenceAchieved:  !poisonGone,
		persistenceDisrupted: neutralized,
		neutralized:          neutralized,
		triggerAttribution:   core.TriggerHarnessInjected,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0019", "AML.T0018", "AML.T0020"},
		owasp:                []string{"LLM03:2025", "LLM04:2025"},
		state:                fmt.Sprintf("poisoned model served=%v; served digest after drift=%s golden-restored=%v (signing=provenance not benignity)", inReq, digest, poisonGone),
	}
	return o.result(), nil
}

func (s *ai2PoisonedModelRegistry) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-model-registry")
}
