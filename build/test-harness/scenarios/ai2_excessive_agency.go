package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2ExcessiveAgency{}) }

// ai2ExcessiveAgency: OWASP LLM06 — confused-deputy: the agent invokes a
// high-privilege tool it should not. SPLIT ORACLE: (a) over-privileged action
// executed (agency is app-layer -> CANNOT-HELP); (b) the agency foothold persists
// across a rotation (rotation drops the agent's session/tool grant -> BOUNDS-ONLY).
type ai2ExcessiveAgency struct{ agent *mocks.MockAgentRuntime }

func (s *ai2ExcessiveAgency) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-excessive-agency",
		Category:           core.CategoryR6Claimed,
		Source:             "OWASP LLM06:2025 Excessive Agency (confused-deputy)",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1059.013", "T1078"},
		R6Justification:    "Agency is app-layer — rotation cannot stop the over-privileged action. Rotation drops the agent's session/tool grant, bounding the foothold. Partial.",
	}
}

func (s *ai2ExcessiveAgency) Setup(ctx context.Context, env *core.Env) error {
	agent, err := mocks.DeployMockAgentRuntime(ctx, env)
	if err != nil {
		return err
	}
	s.agent = agent
	return nil
}

func (s *ai2ExcessiveAgency) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.agent.CallPrivilegedTool(ctx, env)
	return core.AttackResult{
		Stages:   []string{"excessive-agency: agent calls a high-privilege tool it should not (T1078)"},
		Commands: []string{"agent -> privileged tool -> " + mocks.ConfusedDeputyMarker},
	}, nil
}

func (s *ai2ExcessiveAgency) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.agent.ActionLogContains(ctx, env, mocks.ConfusedDeputyMarker)
	time.Sleep(6 * time.Second)
	// The grant lives in the agent pod; a rotation that replaces the pod drops it.
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
		state:                fmt.Sprintf("over-privileged action executed=%v; foothold survived rotation=%v", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2ExcessiveAgency) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-agent")
}
