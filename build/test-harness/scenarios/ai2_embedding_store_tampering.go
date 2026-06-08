package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2EmbeddingStoreTampering{}) }

// ai2EmbeddingStoreTampering: RAG/data-plane embedding store tampering (vector index
// mutation). SPLIT ORACLE: (a) a tampered embedding biased retrieval (CANNOT-HELP);
// (b) the tampered vector survives a rotation — CANNOT-HELP if the store is
// PVC/external (the mock store pod is not a rotation target). Data-plane
// differentiator.
type ai2EmbeddingStoreTampering struct{ ret *mocks.MockRetriever }

func (s *ai2EmbeddingStoreTampering) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-embedding-store-tampering",
		Category:           core.CategoryModernUnsupported,
		Source:             "RAG/data-plane: embedding store tampering (vector index mutation); mock embedding store",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1565", "T1530"},
		R6Justification:    "The embedding store is data-plane (PVC/external); pod rotation does not touch it, so the tampered vector survives. Only a pod-backed-and-rotated store would be bounded. Cannot respond. Data-plane differentiator.",
	}
}

func (s *ai2EmbeddingStoreTampering) Setup(ctx context.Context, env *core.Env) error {
	ret, err := mocks.DeployMockRetriever(ctx, env)
	if err != nil {
		return err
	}
	s.ret = ret
	return nil
}

func (s *ai2EmbeddingStoreTampering) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.ret.TamperEmbedding(ctx, env)
	return core.AttackResult{
		Stages:   []string{"embedding-tamper: vector index mutated so a tamper doc returns for an unrelated query (T1565)"},
		Commands: []string{"mutate vector -> top-k tamper doc: " + mocks.EmbeddingTamperMarker},
	}, nil
}

func (s *ai2EmbeddingStoreTampering) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.ret.TopKContains(ctx, env, mocks.EmbeddingTamperMarker)
	time.Sleep(6 * time.Second)
	persisted := s.ret.StoreContains(ctx, env, mocks.EmbeddingTamperMarker)
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: armRotates(env) && !persisted, // MEASURED per-arm (data-plane store survives pod rotation, so this measures false)
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0020", "AML.T0048", "AML.T0024.001"},
		owasp:                []string{"LLM08:2025"},
		state:                fmt.Sprintf("tampered vector returned=%v; tampered vector survived rotation=%v (data-plane store)", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2EmbeddingStoreTampering) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-retriever")
}
