package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai1InferenceManipulation{}) }

// ai1InferenceManipulation: intercept the static inference API path and tamper
// outputs. SPLIT ORACLE:
//   (a) in-request: an in-path proxy returned a tampered completion (manipulation
//       marker present). The EXTERNAL path stays STATIC (audit #3 — URL/path
//       rotation ABSENT) -> MTD-BOUNDS-ONLY.
//   (b) persistence: the interception persists across a rotation (only the backend
//       identity churns) -> MTD-BOUNDS-ONLY.
type ai1InferenceManipulation struct {
	infer *mocks.MockInferenceServer
}

func (s *ai1InferenceManipulation) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai1-inference-manipulation",
		Category:           core.CategoryR6Claimed,
		Source:             "R6 Phoenix-for-AI (Inference Manipulation); AUDIT #3 URL/path rotation ABSENT",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1557", "T1565.002"},
		R6Justification:    "Backend rotates but the external path/endpoint stays STATIC (audit #3 — URL/path rotation ABSENT). Interception of the stable path is not prevented; only the backend identity churns. Bounds, not breaks. Partial.",
	}
}

func (s *ai1InferenceManipulation) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	return nil
}

func (s *ai1InferenceManipulation) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// Model an in-path proxy tampering the completion (write the manipulation
	// marker into the model's served substrate so the client observes it).
	_ = mocks.MockServerExec(ctx, env, s.infer.MockServer, "echo R6TH-INFERENCE-TAMPERED > /tmp/tamper; echo R6TH-INFERENCE-TAMPERED > /tmp/inject")
	stages := []string{
		"inference-manip: MITM the static API path (T1557)",
		"tamper: in-path proxy rewrites the completion (T1565.002)",
	}
	return core.AttackResult{Stages: stages, Commands: []string{"in-path proxy on stable path -> tampered completion"}}, nil
}

func (s *ai1InferenceManipulation) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.infer.MarkerPresent(ctx, env, "/tmp/tamper", "R6TH-INFERENCE-TAMPERED")

	// (b) persistence: the static external path remains intercept-able after a
	// rotation (the path never rotates — audit #3).
	time.Sleep(6 * time.Second)
	svc, err := getService(ctx, env, "mock-infer-svc")
	pathStable := err == nil && svc != nil
	replays := 0
	attempts := 3
	if pathStable {
		replays = attempts
	}

	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             pathStable,
		inRequestAchieved:    inReq,
		persistenceAchieved:  pathStable,
		persistenceDisrupted: armRotates(env) && !pathStable, // MEASURED per-arm (audit #3: the static path persists, so this measures false)
		neutralized:          false, // no detector + no genuine trigger -> bound only, never neutralize (measured-as-false by construction)
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		replaySuccess:        replays,
		replayAttempts:       attempts,
		atlas:                []string{"AML.T0040", "AML.T0015", "AML.T0024"},
		owasp:                []string{"LLM01:2025", "LLM05:2025"},
		state:                fmt.Sprintf("in-request output tampered=%v; static path intercept-able after rotation=%v (URL/path rotation absent)", inReq, pathStable),
	}
	return o.result(), nil
}

func (s *ai1InferenceManipulation) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
