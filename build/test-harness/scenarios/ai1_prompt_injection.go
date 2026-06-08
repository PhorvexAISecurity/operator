package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai1PromptInjection{}) }

// ai1PromptInjection: prompt injection across multiple requests. SPLIT ORACLE:
//   (a) in-request: the injected instruction produced the injected behavior in the
//       same request (NeMo semantic filter ABSENT, audit #10 -> MTD-CANNOT-HELP).
//   (b) persistence: a session/memory-persisted injected instruction survives a
//       rotation. Pod rotation invalidates the session -> MTD-BOUNDS-ONLY.
type ai1PromptInjection struct {
	infer   *mocks.MockInferenceServer
	session string
}

func (s *ai1PromptInjection) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai1-prompt-injection",
		Category:           core.CategoryR6Claimed,
		Source:             "R6 Phoenix-for-AI Pillar 01 (rotate AI-request pods); AUDIT #10 NeMo ABSENT",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1059.013", "T1565"},
		R6Justification:    "NeMo semantic filter is ABSENT (audit #10) — rotation cannot stop a single-request injection. Pod rotation invalidates a session/memory-persisted instruction. Bounds persistence only. Partial.",
	}
}

func (s *ai1PromptInjection) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	s.session = "sess-pi"
	return nil
}

func (s *ai1PromptInjection) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.infer.PlantInjection(ctx, env, s.session)
	stages := []string{
		"prompt-injection: override instruction in the request (T1059.013)",
		"persist: write the override into the session/memory substrate",
	}
	return core.AttackResult{Stages: stages, Commands: []string{
		"POST /v1/completions {inject:" + mocks.InjectionMarker + "}",
		"session_" + s.session + " <- override",
	}}, nil
}

func (s *ai1PromptInjection) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// (a) in-request: the override is present in the model's served substrate.
	inReq := s.infer.MarkerPresent(ctx, env, "/tmp/inject", mocks.InjectionMarker)

	// (b) persistence: after a rotation window, does the session override survive?
	time.Sleep(6 * time.Second)
	persisted := s.infer.MarkerPresent(ctx, env, "/tmp/session_"+s.session, mocks.InjectionMarker)
	disrupted := armRotates(env) && !persisted

	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: disrupted,
		neutralized:          false, // pod-rotation bounds the session; no genuine detector for the injection
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0051", "AML.T0051.000", "AML.T0054", "AML.T0061"},
		owasp:                []string{"LLM01:2025"},
		state:                fmt.Sprintf("in-request injection fired=%v; session override survived rotation=%v (rotation bounds session)", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai1PromptInjection) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
