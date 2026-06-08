package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2AgentExcessiveAgency{}) }

// ai2AgentExcessiveAgency: in-depth confused-deputy variant (beyond the OWASP map).
// SPLIT ORACLE: (a) deputy action executed against a sandbox resource (CANNOT-HELP);
// (b) persisted privilege across a rotation (rotation drops the session-scoped grant
// -> BOUNDS-ONLY).
type ai2AgentExcessiveAgency struct{ agent *mocks.MockAgentRuntime }

func (s *ai2AgentExcessiveAgency) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-agent-excessive-agency",
		Category:           core.CategoryR6Claimed,
		Source:             "Agentic: excessive agency / confused-deputy (in-depth variant)",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1059.013", "T1078"},
		R6Justification:    "Deputy action is app-layer. Rotation drops the session-scoped grant, bounding the persisted privilege. Partial.",
	}
}

func (s *ai2AgentExcessiveAgency) Setup(ctx context.Context, env *core.Env) error {
	agent, err := mocks.DeployMockAgentRuntime(ctx, env)
	if err != nil {
		return err
	}
	s.agent = agent
	return nil
}

func (s *ai2AgentExcessiveAgency) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.agent.CallPrivilegedTool(ctx, env)
	return core.AttackResult{
		Stages:   []string{"confused-deputy: agent tricked into a privileged action against a sandbox resource (T1078)"},
		Commands: []string{"agent -> privileged action -> " + mocks.ConfusedDeputyMarker},
	}, nil
}

func (s *ai2AgentExcessiveAgency) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.agent.ActionLogContains(ctx, env, mocks.ConfusedDeputyMarker)
	time.Sleep(6 * time.Second)
	persisted := s.agent.ActionLogContains(ctx, env, mocks.ConfusedDeputyMarker)
	disrupted := armRotates(env) && !persisted
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0053", "AML.T0048", "AML.T0054"},
		owasp:                []string{"LLM06:2025"},
		state:                fmt.Sprintf("deputy action executed=%v; deputy capability survived rotation=%v", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2AgentExcessiveAgency) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-agent")
}
