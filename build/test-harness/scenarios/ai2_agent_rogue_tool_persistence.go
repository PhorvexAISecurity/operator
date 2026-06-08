package scenarios

import (
	"context"
	"fmt"
	"time"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2AgentRogueToolPersistence{}) }

// ai2AgentRogueToolPersistence: attacker registers a durable malicious tool. SPLIT
// ORACLE: (a) rogue tool registered+called (CANNOT-HELP autonomously);
// (b) persistence — MTD-NEUTRALIZES if rotation/regenerate restores the golden tool
// set (INJECTED drift -> Regenerate, BUILT #5); else BOUNDS-ONLY (measured).
type ai2AgentRogueToolPersistence struct{ agent *mocks.MockAgentRuntime }

func (s *ai2AgentRogueToolPersistence) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-agent-rogue-tool-persistence",
		Category:           core.CategoryR6Claimed,
		Source:             "Agentic: rogue tool persistence; agent-tools ConfigMap",
		R6ResponseTag:      core.R6Covers,
		AttackTechniqueIDs: []string{"T1059.013", "T1195"},
		R6Justification:    "Registration+call is app-layer autonomously. But an injected drift -> Regenerate (BUILT #5) restores the golden tool set, removing the rogue tool. Covers via injected drift.",
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
		env.Log.Logf("ai2-agent-rogue-tool-persistence: register error: %v", err)
	}
	stages := []string{"rogue-tool: durable malicious tool registered+called (T1195)"}
	cmds := []string{"agent-tools ConfigMap <- " + mocks.RogueToolMarker}
	if emitGenuineTrigger(ctx, env, s.agent.PodName, amtdv1beta1.TypeTimed) {
		// Genuine Regenerate-on-drift restores the golden tool set.
		if err := s.agent.RestoreGoldenTools(ctx, env); err != nil {
			env.Log.Logf("restore golden tools error: %v", err)
		}
		cmds = append(cmds, "emit drift(timed) -> Regenerate -> golden tool set restored")
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai2AgentRogueToolPersistence) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := true // registration+call always lands in-request
	time.Sleep(4 * time.Second)
	stillRogue := s.agent.ToolsContain(ctx, env, mocks.RogueToolMarker)
	neutralized := armIsFullPhoenix(env) && !stillRogue
	disrupted := (armRotates(env) || armIsFullPhoenix(env)) && !stillRogue
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             stillRogue,
		inRequestAchieved:    inReq,
		persistenceAchieved:  stillRogue,
		persistenceDisrupted: disrupted,
		neutralized:          neutralized,
		triggerAttribution:   core.TriggerHarnessInjected,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0053", "AML.T0048", "AML.T0020"},
		owasp:                []string{"LLM06:2025", "LLM03:2025"},
		state:                fmt.Sprintf("rogue tool registered+called=%v; rogue tool survived regenerate=%v", inReq, stillRogue),
	}
	return o.result(), nil
}

func (s *ai2AgentRogueToolPersistence) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-agent")
}
