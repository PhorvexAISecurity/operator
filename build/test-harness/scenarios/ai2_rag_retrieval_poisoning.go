package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2RAGRetrievalPoisoning{}) }

// ai2RAGRetrievalPoisoning: RAG/data-plane retrieval poisoning (a malicious doc
// injected into the corpus). SPLIT ORACLE: (a) a poisoned retrieved document
// steered the model output (CANNOT-HELP); (b) the poisoned document persists in the
// corpus across a rotation — CANNOT-HELP if the store survives rotation (a genuine
// Phorvex differentiator: the data-plane is outside reactive pod-rotation).
type ai2RAGRetrievalPoisoning struct{ ret *mocks.MockRetriever }

func (s *ai2RAGRetrievalPoisoning) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-rag-retrieval-poisoning",
		Category:           core.CategoryModernUnsupported,
		Source:             "RAG/data-plane: retrieval poisoning (malicious doc in corpus); mock retriever",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1565", "T1195"},
		R6Justification:    "The corpus is data-plane and untouched by pod rotation. The poisoned doc persists across a rotation — a genuine Phorvex differentiator (data-plane outside reactive pod-rotation). Cannot respond.",
	}
}

func (s *ai2RAGRetrievalPoisoning) Setup(ctx context.Context, env *core.Env) error {
	ret, err := mocks.DeployMockRetriever(ctx, env)
	if err != nil {
		return err
	}
	s.ret = ret
	return nil
}

func (s *ai2RAGRetrievalPoisoning) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.ret.PoisonCorpus(ctx, env)
	return core.AttackResult{
		Stages:   []string{"rag-poisoning: poisoned doc injected into the corpus steers the output (T1565)"},
		Commands: []string{"upsert poison doc -> top-k: " + mocks.RAGPoisonMarker},
	}, nil
}

func (s *ai2RAGRetrievalPoisoning) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.ret.TopKContains(ctx, env, mocks.RAGPoisonMarker)
	time.Sleep(6 * time.Second)
	persisted := s.ret.StoreContains(ctx, env, mocks.RAGPoisonMarker)
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: armRotates(env) && !persisted, // MEASURED per-arm (data-plane corpus survives pod rotation, so this measures false)
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		atlas:                []string{"AML.T0051", "AML.T0020", "AML.T0048"},
		owasp:                []string{"LLM08:2025", "LLM04:2025"},
		state:                fmt.Sprintf("poisoned doc retrieved+acted=%v; poisoned doc persisted in corpus after rotation=%v (data-plane differentiator)", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2RAGRetrievalPoisoning) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-retriever")
}
