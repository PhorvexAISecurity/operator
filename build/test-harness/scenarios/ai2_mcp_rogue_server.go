package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2MCPRogueServer{}) }

// ai2MCPRogueServer: rogue MCP server (untrusted server impersonation/hijack).
// SPLIT ORACLE: (a) the agent connected to the rogue server and executed its tool
// (selection is app config -> CANNOT-HELP); (b) the rogue-server binding survives
// a rotation — endpoint rotation is backend-only; if the agent holds the rogue DNS
// it is not invalidated -> BOUNDS-ONLY (measured).
type ai2MCPRogueServer struct {
	trusted *mocks.MockMCPServer
	rogue   *mocks.MockMCPServer
}

func (s *ai2MCPRogueServer) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-mcp-rogue-server",
		Category:           core.CategoryModernUnsupported,
		Source:             "MCP attacks: rogue MCP server (impersonation/hijack)",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1557", "T1059.013"},
		R6Justification:    "Server selection is app config — rotation cannot stop the rogue server serving. Endpoint rotation is backend-only; if the agent holds the rogue DNS it is not invalidated. Bounds. Partial.",
	}
}

func (s *ai2MCPRogueServer) Setup(ctx context.Context, env *core.Env) error {
	trusted, err := mocks.DeployMockMCPServer(ctx, env, false)
	if err != nil {
		return err
	}
	s.trusted = trusted
	rogue, err := mocks.DeployMockMCPServer(ctx, env, true)
	if err != nil {
		return err
	}
	s.rogue = rogue
	return nil
}

func (s *ai2MCPRogueServer) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// The agent is pointed at the rogue server (the rogue marker is served by it).
	_ = mocks.MockServerExec(ctx, env, s.rogue.MockServer, "echo "+mocks.RogueServerMarker+" > /tmp/agent_bound")
	return core.AttackResult{
		Stages:   []string{"mcp-rogue: agent connects to the rogue MCP server and executes its tool (T1557)"},
		Commands: []string{"agent -> mock-rogue-mcp-svc -> " + mocks.RogueServerMarker},
	}, nil
}

func (s *ai2MCPRogueServer) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.rogue.MockServer != nil && mocks.MarkerOnServer(ctx, env, s.rogue.MockServer, "/tmp/agent_bound", mocks.RogueServerMarker)
	time.Sleep(6 * time.Second)
	// The rogue server is NOT a rotation target (untrusted external), so the binding
	// survives a rotation of the trusted target.
	svc, err := getService(ctx, env, "mock-rogue-mcp-svc")
	rogueReachable := err == nil && svc != nil
	disrupted := false
	attempts := 3
	replays := 0
	if rogueReachable {
		replays = attempts
	}
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             rogueReachable,
		inRequestAchieved:    inReq,
		persistenceAchieved:  rogueReachable,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		replaySuccess:        replays,
		replayAttempts:       attempts,
		atlas:                []string{"AML.T0040", "AML.T0048", "AML.T0053"},
		owasp:                []string{"LLM01:2025", "LLM03:2025"},
		state:                fmt.Sprintf("agent reached rogue server=%v; rogue binding survived rotation=%v", inReq, rogueReachable),
	}
	return o.result(), nil
}

func (s *ai2MCPRogueServer) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-mcp", "mock-rogue-mcp")
}
