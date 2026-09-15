package scenarios

import (
	"context"
	"fmt"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2AgentRogueToolPersistence{}) }

// ai2AgentRogueToolPersistence observes registration in the tools ConfigMap
// before trigger delivery and reads the same substrate after the response
// window. Regenerate does not restore the tool registry.
type ai2AgentRogueToolPersistence struct {
	agent                            *mocks.MockAgentRuntime
	initialTools, targetUID, attempt string
	emitted                          bool
}

func (s *ai2AgentRogueToolPersistence) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-agent-rogue-tool-persistence",
		Category:           core.CategoryR6Claimed,
		Source:             "Agentic: rogue tool persistence; agent-tools ConfigMap",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1059.013", "T1195"},
		R6Justification:    "The synthetic rogue-tool entry is ConfigMap membership only, with no tool invocation. Regenerate repairs a workload baseline, not agent-tools; a drift event does not remove that entry.",
	}
}

func (s *ai2AgentRogueToolPersistence) Setup(ctx context.Context, env *core.Env) error {
	agent, err := mocks.DeployMockAgentRuntime(ctx, env)
	if err != nil {
		return err
	}
	s.agent = agent
	return nil
}

func (s *ai2AgentRogueToolPersistence) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if err := s.agent.RegisterRogueTool(ctx, env); err != nil {
		return core.AttackResult{}, fmt.Errorf("register rogue tool: %w", err)
	}
	var err error
	s.initialTools, s.targetUID, err = s.agent.ObservedToolsWithUID(ctx, env)
	if err != nil {
		return core.AttackResult{}, fmt.Errorf("initial tools observation: %w", err)
	}
	if !containsMarker(s.initialTools, mocks.RogueToolMarker) {
		return core.AttackResult{}, fmt.Errorf("rogue tool stimulus did not land: %s", s.initialTools)
	}
	s.attempt = aiEffectAttempt(env, s.targetUID)
	env.EffectAttemptID = s.attempt
	stages := []string{"synthetic rogue-tool: agent-tools ConfigMap membership changed (T1195)"}
	cmds := []string{"agent-tools ConfigMap value <- " + mocks.RogueToolMarker}
	s.emitted = emitGenuineTrigger(ctx, env, s.agent.PodName, amtdv1beta1.TypeTimed)
	if s.emitted {
		cmds = append(cmds, "emit drift(timed) SecurityEvent")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai2AgentRogueToolPersistence) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := containsMarker(s.initialTools, mocks.RogueToolMarker)
	observationPause(aiPersistenceWindow)
	tools, observedUID, err := s.agent.ObservedToolsWithUID(ctx, env)
	if err != nil {
		return core.OracleResult{}, fmt.Errorf("post-response tools observation: %w", err)
	}
	if observedUID != s.targetUID {
		return core.OracleResult{}, fmt.Errorf("tools ConfigMap incarnation changed from %s to %s", s.targetUID, observedUID)
	}
	stillRogue := containsMarker(tools, mocks.RogueToolMarker)
	effect := aiDefenderEffect(ctx, env, s.targetUID, s.attempt, !stillRogue)
	attributed := effect["defensiveEffectAttributed"] == "true"
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             stillRogue,
		inRequestAchieved:    inReq,
		persistenceAchieved:  stillRogue,
		persistenceDisrupted: !stillRogue && attributed,
		triggerAttribution:   aiEventAttribution(s.emitted),
		detectorAbsent:       true,
		atlas:                []string{"AML.T0053", "AML.T0048", "AML.T0020"},
		owasp:                []string{"LLM06:2025", "LLM03:2025"},
		state:                fmt.Sprintf("initial tools=%s; post-response tools=%s; rogue persisted=%v; event emitted=%v; defender effect attributed=%v", s.initialTools, tools, stillRogue, s.emitted, attributed),
		extra:                aiMergeEvidence(map[string]string{"initialAgentTools": s.initialTools, "postResponseAgentTools": tools, "eventEmitted": b2s(s.emitted), "originalConfigMapUID": s.targetUID, "observedConfigMapUID": observedUID, "initialTargetUID": s.targetUID}, effect),
	}
	return o.result(), nil
}

func (s *ai2AgentRogueToolPersistence) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-agent")
}
