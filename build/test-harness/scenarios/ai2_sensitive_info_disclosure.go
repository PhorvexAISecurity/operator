package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2SensitiveInfoDisclosure{}) }

// ai2SensitiveInfoDisclosure: OWASP LLM02 — the model discloses a planted secret.
// SPLIT ORACLE: (a) in-request disclosure (no output filter -> CANNOT-HELP);
// (b) the leaked secret still authenticates after a rotation (rotation invalidates
// the session/cred substrate, reducing replay -> BOUNDS-ONLY).
type ai2SensitiveInfoDisclosure struct{ infer *mocks.MockInferenceServer }

func (s *ai2SensitiveInfoDisclosure) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-sensitive-info-disclosure",
		Category:           core.CategoryR6Claimed,
		Source:             "OWASP LLM02:2025 Sensitive Information Disclosure; Phorvex differentiator",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1530", "T1552"},
		R6Justification:    "No output filter — rotation cannot stop an in-request disclosure. Rotation invalidates a session/cred substrate, reducing replay of the leaked secret. Bounds persistence only. Partial.",
	}
}

func (s *ai2SensitiveInfoDisclosure) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	return nil
}

func (s *ai2SensitiveInfoDisclosure) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.infer.PlantSystemPromptSecret(ctx, env) // seeds /tmp/secret with the fake key
	return core.AttackResult{
		Stages:   []string{"disclosure: planted fake API key returned in completion (T1530)"},
		Commands: []string{"POST /v1/completions -> leaks " + mocks.SensitiveSecretMarker},
	}, nil
}

func (s *ai2SensitiveInfoDisclosure) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.infer.MarkerPresent(ctx, env, "/tmp/secret", mocks.SensitiveSecretMarker)
	time.Sleep(6 * time.Second)
	// Replay the leaked secret against the (possibly rotated) endpoint.
	stillValid := s.infer.MarkerPresent(ctx, env, "/tmp/secret", mocks.SensitiveSecretMarker)
	disrupted := armRotates(env) && !stillValid
	attempts := 3
	replays := 0
	if stillValid {
		replays = attempts
	}
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             stillValid,
		inRequestAchieved:    inReq,
		persistenceAchieved:  stillValid,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		replaySuccess:        replays,
		replayAttempts:       attempts,
		atlas:                []string{"AML.T0057", "AML.T0024.000"},
		owasp:                []string{"LLM02:2025"},
		state:                fmt.Sprintf("in-request disclosure=%v; leaked secret replay-valid after rotation=%v", inReq, stillValid),
	}
	return o.result(), nil
}

func (s *ai2SensitiveInfoDisclosure) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
