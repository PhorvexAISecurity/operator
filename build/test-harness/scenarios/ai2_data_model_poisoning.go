package scenarios

import (
	"context"
	"fmt"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2DataModelPoisoning{}) }

// ai2DataModelPoisoning: OWASP LLM04 — poisoned model data loaded. SPLIT ORACLE:
//   (a) in-request: poisoned artifact served (no benignity check -> CANNOT-HELP
//       autonomously; signing proves provenance not benignity, audit #5).
//   (b) persistence: restore-from-golden on drift — an INJECTED drift (timed)
//       SecurityEvent -> Regenerate (BUILT) restores the signed golden digest
//       (poison gone) -> MTD-NEUTRALIZES.
type ai2DataModelPoisoning struct{ reg *mocks.MockModelRegistry }

func (s *ai2DataModelPoisoning) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-data-model-poisoning",
		Category:           core.CategoryR6Claimed,
		Source:             "OWASP LLM04:2025 Data and Model Poisoning; AUDIT #5 Regenerate drift path",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1565.001", "T1195"},
		R6Justification:    "No benignity check, so the poisoned load is not prevented autonomously (signing proves provenance not benignity, audit #5). But an injected drift -> Regenerate (BUILT) restores the signed golden digest. Covers via injected drift.",
	}
}

func (s *ai2DataModelPoisoning) Setup(ctx context.Context, env *core.Env) error {
	reg, err := mocks.DeployMockModelRegistry(ctx, env)
	if err != nil {
		return err
	}
	s.reg = reg
	return nil
}

func (s *ai2DataModelPoisoning) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.reg.PoisonManifest(ctx, env) // served digest -> poisoned
	stages := []string{"poisoning: poisoned model data loaded (T1565.001)"}
	cmds := []string{"served digest -> " + mocks.PoisonedModelDigest}
	if emitGenuineTrigger(ctx, env, s.reg.PodName, amtdv1beta1.TypeTimed) {
		// Genuine Regenerate-on-drift: restore golden (models the BUILT action).
		s.reg.RestoreGolden(ctx, env)
		cmds = append(cmds, "emit drift(timed) SecurityEvent -> Regenerate -> golden digest restored")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai2DataModelPoisoning) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	digest := s.reg.ServedDigest(ctx, env)
	inReq := digest == mocks.PoisonedModelDigest // poison was loadable in-request
	time.Sleep(4 * time.Second)
	digest = s.reg.ServedDigest(ctx, env)
	poisonGone := digest == mocks.GoldenModelDigest
	neutralized := armIsFullPhoenix(env) && poisonGone
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             !poisonGone, // attacker wins iff poison persists
		inRequestAchieved:    inReq,
		persistenceAchieved:  !poisonGone,
		persistenceDisrupted: neutralized,
		neutralized:          neutralized,
		triggerAttribution:   core.TriggerHarnessInjected,
		detectorAbsent:       true, // no autonomous benignity detector
		atlas:                []string{"AML.T0020", "AML.T0018", "AML.T0019"},
		owasp:                []string{"LLM04:2025"},
		state:                fmt.Sprintf("in-request poison loaded=%v; served digest after drift=%s golden-restored=%v", inReq, digest, poisonGone),
	}
	return o.result(), nil
}

func (s *ai2DataModelPoisoning) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-model-registry")
}
