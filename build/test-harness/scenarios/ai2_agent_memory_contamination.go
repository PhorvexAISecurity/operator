package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2AgentMemoryContamination{}) }

// ai2AgentMemoryContamination: cross-session memory contamination. SPLIT ORACLE:
// (a) contamination in-session (CANNOT-HELP); (b) cross-session persistence — a
// rotation that also deletes the agent-memory ConfigMap clears it (BOUNDS-ONLY);
// if memory is external/PVC-backed it survives (measured, may flip to CANNOT-HELP).
type ai2AgentMemoryContamination struct{ agent *mocks.MockAgentRuntime }

func (s *ai2AgentMemoryContamination) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-agent-memory-contamination",
		Category:           core.CategoryR6Claimed,
		Source:             "Agentic: cross-session memory contamination; agent-memory ConfigMap",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1059.013", "T1565"},
		R6Justification:    "Contamination in-session is app-layer. A rotation that also deletes the agent-memory ConfigMap clears the contamination; an external/PVC-backed memory survives. Measured per arm. Partial.",
	}
}

func (s *ai2AgentMemoryContamination) Setup(ctx context.Context, env *core.Env) error {
	agent, err := mocks.DeployMockAgentRuntime(ctx, env)
	if err != nil {
		return err
	}
	s.agent = agent
	return nil
}

func (s *ai2AgentMemoryContamination) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	if err := s.agent.ContaminateMemory(ctx, env); err != nil {
		env.Log.Logf("ai2-agent-memory-contamination: contaminate error: %v", err)
	}
	return core.AttackResult{
		Stages:   []string{"memory-contamination: contaminated cross-session memory (T1565)"},
		Commands: []string{"agent-memory ConfigMap <- " + mocks.MemoryContaminationMarker},
	}, nil
}

func (s *ai2AgentMemoryContamination) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.agent.MemoryContains(ctx, env, mocks.MemoryContaminationMarker)
	time.Sleep(6 * time.Second)
	persisted := s.agent.MemoryContains(ctx, env, mocks.MemoryContaminationMarker)
	disrupted := armRotates(env) && !persisted
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0051", "AML.T0054", "AML.T0061"},
		owasp:                []string{"LLM01:2025", "LLM04:2025"},
		state:                fmt.Sprintf("in-session contamination=%v; crossed into new session after rotation=%v", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2AgentMemoryContamination) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-agent")
}
