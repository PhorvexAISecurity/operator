package scenarios

import (
	"context"
	"fmt"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2PoisonedModelRegistry{}) }

// ai2PoisonedModelRegistry observes a poisoned model digest before trigger
// delivery and again after the response window. Regenerate does not restore
// the registry substrate; signing proves provenance, not benignity.
type ai2PoisonedModelRegistry struct {
	reg                               *mocks.MockModelRegistry
	initialDigest, targetUID, attempt string
	emitted                           bool
}

func (s *ai2PoisonedModelRegistry) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-poisoned-model-registry",
		Category:           core.CategoryR6Claimed,
		Source:             "AI supply chain: poisoned model registry; mock model registry",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1195", "T1525"},
		R6Justification:    "The synthetic served-digest marker has no benignity check. Regenerate repairs a workload baseline, not this registry digest; signing proves provenance, not benignity.",
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
	stages := []string{"synthetic supply-chain: mock registry served-digest marker changed (T1195)"}
	cmds := []string{"mock served-digest file -> " + mocks.PoisonedModelDigest}
	s.emitted = emitGenuineTrigger(ctx, env, s.reg.PodName, amtdv1beta1.TypeTimed)
	if s.emitted {
		cmds = append(cmds, "emit drift(timed) SecurityEvent")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai2PoisonedModelRegistry) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.initialDigest == mocks.PoisonedModelDigest
	observationPause(aiPersistenceWindow)
	digest, observedUID, err := s.reg.ObservedServedDigestWithUID(ctx, env)
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("post-response registry observation: %w", err)
	}
	if observedUID != s.targetUID {
		return core.OracleResult{}, fmt.Errorf("registry target incarnation changed from %s to %s", s.targetUID, observedUID)
	}
	poisonGone := digest == mocks.GoldenModelDigest
	effect := aiDefenderEffect(ctx, env, s.targetUID, s.attempt, poisonGone)
	attributed := effect["defensiveEffectAttributed"] == "true"
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             !poisonGone,
		inRequestAchieved:    inReq,
		persistenceAchieved:  !poisonGone,
		persistenceDisrupted: poisonGone && attributed,
		triggerAttribution:   aiEventAttribution(s.emitted),
		detectorAbsent:       true,
		atlas:                []string{"AML.T0019", "AML.T0018", "AML.T0020"},
		owasp:                []string{"LLM03:2025", "LLM04:2025"},
		state:                fmt.Sprintf("initial served digest=%s; post-response digest=%s; golden observed=%v; event emitted=%v; defender effect attributed=%v", s.initialDigest, digest, poisonGone, s.emitted, attributed),
		extra:                aiMergeEvidence(map[string]string{"initialServedDigest": s.initialDigest, "postResponseServedDigest": digest, "eventEmitted": b2s(s.emitted), "originalPodUID": s.targetUID, "observedPodUID": observedUID, "initialTargetUID": s.targetUID}, effect),
	}
	return o.result(), nil
}

func (s *ai2PoisonedModelRegistry) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-model-registry")
}
