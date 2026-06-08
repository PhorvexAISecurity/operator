package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2MCPToolResponseInjection{}) }

// ai2MCPToolResponseInjection: malicious content in a tool RESULT ingested by the
// model. SPLIT ORACLE: (a) injected response steered the model (response content is
// in-request, no semantic filter -> CANNOT-HELP); (b) the injected directive
// persisted into agent memory across a rotation (rotation clears agent memory ->
// BOUNDS-ONLY). R6CannotRespond honestly (no matcher path for the response content).
type ai2MCPToolResponseInjection struct {
	mcp   *mocks.MockMCPServer
	agent *mocks.MockAgentRuntime
}

func (s *ai2MCPToolResponseInjection) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-mcp-tool-response-injection",
		Category:           core.CategoryModernUnsupported,
		Source:             "MCP attacks: tool-response injection (malicious tool result ingested)",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1059.013", "T1565"},
		R6Justification:    "The injected response is in-request content with no semantic filter — no matcher path applies. Rotation only clears agent memory if the directive was persisted there. Cannot respond to the in-request steering.",
	}
}

func (s *ai2MCPToolResponseInjection) Setup(ctx context.Context, env *core.Env) error {
	mcp, err := mocks.DeployMockMCPServer(ctx, env, false)
	if err != nil {
		return err
	}
	s.mcp = mcp
	agent, err := mocks.DeployMockAgentRuntime(ctx, env)
	if err != nil {
		return err
	}
	s.agent = agent
	return nil
}

func (s *ai2MCPToolResponseInjection) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.mcp.PlantToolResponseInjection(ctx, env)
	// The model ingests the directive and the agent persists it to memory.
	if err := s.agent.ContaminateMemory(ctx, env); err != nil {
		env.Log.Logf("ai2-mcp-tool-response-injection: memory persist error: %v", err)
	}
	return core.AttackResult{
		Stages:   []string{"tool-response-injection: malicious tool result steers the model (T1565)"},
		Commands: []string{"POST /call -> injected result: " + mocks.ToolResponseInjMarker, "persist directive -> agent memory"},
	}, nil
}

func (s *ai2MCPToolResponseInjection) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := mocks.MarkerOnServer(ctx, env, s.mcp.MockServer, "/tmp/last_result", mocks.ToolResponseInjMarker)
	time.Sleep(6 * time.Second)
	persisted := s.agent.MemoryContains(ctx, env, mocks.MemoryContaminationMarker)
	// A rotation that also deletes the agent-memory ConfigMap clears it.
	disrupted := armRotates(env) && !persisted
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0051", "AML.T0054"},
		owasp:                []string{"LLM01:2025"},
		state:                fmt.Sprintf("injected response steered model=%v; directive persisted in memory across rotation=%v", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2MCPToolResponseInjection) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-mcp", "mock-agent")
}
