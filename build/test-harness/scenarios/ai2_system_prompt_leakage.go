package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2SystemPromptLeakage{}) }

// ai2SystemPromptLeakage: OWASP LLM07 — the system prompt (with a planted secret)
// is leaked. SPLIT ORACLE: (a) leak in-request (no semantic filter -> CANNOT-HELP);
// (b) a credential from the leaked prompt still works after a rotation (rotation
// churns the serving pod/secret -> BOUNDS-ONLY).
type ai2SystemPromptLeakage struct{ infer *mocks.MockInferenceServer }

func (s *ai2SystemPromptLeakage) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-system-prompt-leakage",
		Category:           core.CategoryR6Claimed,
		Source:             "OWASP LLM07:2025 System Prompt Leakage",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1552", "T1530"},
		R6Justification:    "No semantic filter — rotation cannot stop an in-request leak. Rotation churns the serving pod/secret embedded in the system prompt, bounding a leaked-credential foothold. Partial.",
	}
}

func (s *ai2SystemPromptLeakage) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	return nil
}

func (s *ai2SystemPromptLeakage) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.infer.PlantSystemPromptSecret(ctx, env)
	return core.AttackResult{
		Stages:   []string{"system-prompt-leak: planted secret returned via the system prompt (T1552)"},
		Commands: []string{"GET system prompt -> " + mocks.SystemPromptMarker},
	}, nil
}

func (s *ai2SystemPromptLeakage) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.infer.MarkerPresent(ctx, env, "/tmp/system_prompt", mocks.SystemPromptMarker)
	time.Sleep(6 * time.Second)
	credValid := s.infer.MarkerPresent(ctx, env, "/tmp/secret", mocks.SensitiveSecretMarker)
	disrupted := armRotates(env) && !credValid
	attempts := 3
	replays := 0
	if credValid {
		replays = attempts
	}
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             credValid,
		inRequestAchieved:    inReq,
		persistenceAchieved:  credValid,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		replaySuccess:        replays,
		replayAttempts:       attempts,
		atlas:                []string{"AML.T0056", "AML.T0051"},
		owasp:                []string{"LLM07:2025"},
		state:                fmt.Sprintf("in-request prompt leak=%v; extracted credential replay-valid after rotation=%v", inReq, credValid),
	}
	return o.result(), nil
}

func (s *ai2SystemPromptLeakage) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
