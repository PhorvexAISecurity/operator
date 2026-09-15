package scenarios

import (
	"context"
	"fmt"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2DataModelPoisoning{}) }

// ai2DataModelPoisoning observes a poisoned digest before trigger delivery and
// the same registry substrate after the response window. Event delivery alone
// has no model-data repair effect.
type ai2DataModelPoisoning struct {
	reg                               *mocks.MockModelRegistry
	initialDigest, targetUID, attempt string
	emitted                           bool
}

func (s *ai2DataModelPoisoning) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-data-model-poisoning",
		Category:           core.CategoryR6Claimed,
		Source:             "OWASP LLM04:2025 Data and Model Poisoning; AUDIT #5 Regenerate drift path",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1565.001", "T1195"},
		R6Justification:    "The synthetic served-digest marker has no benignity check. Regenerate repairs a workload baseline, not the mock registry digest; event delivery cannot establish model-data repair.",
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
	var err error
	s.initialDigest, s.targetUID, err = s.reg.ObservedServedDigestWithUID(ctx, env)
	if err != nil {
		return core.AttackResult{}, fmt.Errorf("initial poison observation: %w", err)
	}
	if s.initialDigest != mocks.PoisonedModelDigest {
		return core.AttackResult{}, fmt.Errorf("poison stimulus did not land: %s", s.initialDigest)
	}
	s.attempt = aiEffectAttempt(env, s.targetUID)
	env.EffectAttemptID = s.attempt
	stages := []string{"synthetic poisoning: mock registry served-digest marker changed (T1565.001)"}
	cmds := []string{"mock served-digest file -> " + mocks.PoisonedModelDigest}
	s.emitted = emitGenuineTrigger(ctx, env, s.reg.PodName, amtdv1beta1.TypeTimed)
	if s.emitted {
		cmds = append(cmds, "emit drift(timed) SecurityEvent")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai2DataModelPoisoning) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.initialDigest == mocks.PoisonedModelDigest
	observationPause(aiPersistenceWindow)
	digest, observedUID, err := s.reg.ObservedServedDigestWithUID(ctx, env)
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("post-response poison observation: %w", err)
	}
	if observedUID != s.targetUID {
		return core.OracleResult{}, fmt.Errorf("registry target incarnation changed from %s to %s", s.targetUID, observedUID)
	}
	poisonGone := digest == mocks.GoldenModelDigest
	effect := aiDefenderEffect(ctx, env, s.targetUID, s.attempt, poisonGone)
	attributed := effect["defensiveEffectAttributed"] == "true"
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             !poisonGone, // attacker wins iff poison persists
		inRequestAchieved:    inReq,
		persistenceAchieved:  !poisonGone,
		persistenceDisrupted: poisonGone && attributed,
		triggerAttribution:   aiEventAttribution(s.emitted),
		detectorAbsent:       true, // no autonomous benignity detector
		atlas:                []string{"AML.T0020", "AML.T0018", "AML.T0019"},
		owasp:                []string{"LLM04:2025"},
		state:                fmt.Sprintf("initial served digest=%s; post-response digest=%s; golden observed=%v; event emitted=%v; defender effect attributed=%v", s.initialDigest, digest, poisonGone, s.emitted, attributed),
		extra:                aiMergeEvidence(map[string]string{"initialServedDigest": s.initialDigest, "postResponseServedDigest": digest, "eventEmitted": b2s(s.emitted), "originalPodUID": s.targetUID, "observedPodUID": observedUID, "initialTargetUID": s.targetUID}, effect),
	}
	return o.result(), nil
}

func (s *ai2DataModelPoisoning) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-model-registry")
}
