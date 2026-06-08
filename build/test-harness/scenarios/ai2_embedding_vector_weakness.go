package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2EmbeddingVectorWeakness{}) }

// ai2EmbeddingVectorWeakness: OWASP LLM08 — vector/embedding weakness. SPLIT
// ORACLE: (a) cross-context leak in-request (data-plane store untouched by pod
// rotation -> CANNOT-HELP); (b) tamper persistence — BOUNDS-ONLY only if the store
// is pod-backed and rotated; the mock store is a separate pod, so a rotation of
// the INFERENCE target does not touch it -> measured (often CANNOT-HELP).
type ai2EmbeddingVectorWeakness struct{ ret *mocks.MockRetriever }

func (s *ai2EmbeddingVectorWeakness) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-embedding-vector-weakness",
		Category:           core.CategoryModernUnsupported,
		Source:             "OWASP LLM08:2025 Vector and Embedding Weaknesses",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1565", "T1530"},
		R6Justification:    "The embedding store is data-plane and untouched by reactive pod rotation; only if the store is pod-backed AND rotated does rotation bound it. Measured per arm — may stay CANNOT-HELP. Partial.",
	}
}

func (s *ai2EmbeddingVectorWeakness) Setup(ctx context.Context, env *core.Env) error {
	ret, err := mocks.DeployMockRetriever(ctx, env)
	if err != nil {
		return err
	}
	s.ret = ret
	return nil
}

func (s *ai2EmbeddingVectorWeakness) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.ret.TamperEmbedding(ctx, env)
	return core.AttackResult{
		Stages:   []string{"embedding-weakness: crafted query retrieves cross-context/poisoned vectors (T1530)"},
		Commands: []string{"POST /query -> tamper doc top-k: " + mocks.EmbeddingTamperMarker},
	}, nil
}

func (s *ai2EmbeddingVectorWeakness) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.ret.TopKContains(ctx, env, mocks.EmbeddingTamperMarker)
	time.Sleep(6 * time.Second)
	// The retriever pod is NOT a rotation target, so the tamper survives.
	persisted := s.ret.StoreContains(ctx, env, mocks.EmbeddingTamperMarker)
	disrupted := false // data-plane store survives pod rotation (genuine differentiator)
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0024.001", "AML.T0048", "AML.T0020"},
		owasp:                []string{"LLM08:2025"},
		state:                fmt.Sprintf("in-request cross-context leak=%v; tampered vector survived rotation=%v (data-plane store outside pod rotation)", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2EmbeddingVectorWeakness) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-retriever")
}
