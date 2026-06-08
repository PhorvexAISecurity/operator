package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2MCPToolPoisoning{}) }

// ai2MCPToolPoisoning: MCP tool-poisoning — a poisoned tool description/schema
// steers the agent. SPLIT ORACLE: (a) poisoned description executed (MCP content
// is app-layer -> CANNOT-HELP); (b) the poisoned tool definition survives a
// rotation — BOUNDS-ONLY if the tool registry is pod/ConfigMap-backed and rotated.
type ai2MCPToolPoisoning struct{ mcp *mocks.MockMCPServer }

func (s *ai2MCPToolPoisoning) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-mcp-tool-poisoning",
		Category:           core.CategoryModernUnsupported,
		Source:             "MCP attacks: tool-poisoning (poisoned tool description/schema)",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1059.013", "T1195"},
		R6Justification:    "MCP tool content is app-layer — rotation cannot stop the poisoned description from steering the agent. If the tool registry is pod/ConfigMap-backed and rotated, rotation bounds it. Measured. Partial.",
	}
}

func (s *ai2MCPToolPoisoning) Setup(ctx context.Context, env *core.Env) error {
	mcp, err := mocks.DeployMockMCPServer(ctx, env, false)
	if err != nil {
		return err
	}
	s.mcp = mcp
	return nil
}

func (s *ai2MCPToolPoisoning) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.mcp.PoisonToolDescription(ctx, env)
	return core.AttackResult{
		Stages:   []string{"mcp-tool-poisoning: poisoned tool description steers the agent (T1059.013)"},
		Commands: []string{"GET /tools -> poisoned: " + mocks.ToolPoisonMarker},
	}, nil
}

func (s *ai2MCPToolPoisoning) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.mcp.ToolManifestContains(ctx, env, mocks.ToolPoisonMarker)
	time.Sleep(6 * time.Second)
	persisted := s.mcp.ToolManifestContains(ctx, env, mocks.ToolPoisonMarker)
	disrupted := armRotates(env) && !persisted
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0051", "AML.T0053", "AML.T0048"},
		owasp:                []string{"LLM01:2025", "LLM06:2025"},
		state:                fmt.Sprintf("poisoned tool description executed=%v; poisoned tool survived rotation=%v", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2MCPToolPoisoning) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-mcp")
}
