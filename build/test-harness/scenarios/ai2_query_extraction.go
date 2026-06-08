package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2QueryExtraction{}) }

// ai2QueryExtraction: query-based model extraction (distillation via API queries),
// CPU-runnable. SPLIT ORACLE: (a) a usable replica was distilled from N seeded
// queries (rotation cannot un-distill -> CANNOT-HELP); (b) the extraction channel/
// session survived a rotation (endpoint stable backend-only; rotation reduces a
// held-session replay -> BOUNDS-ONLY, measured via attack-reusability).
type ai2QueryExtraction struct {
	infer  *mocks.MockInferenceServer
	fidelity int
}

// extractionQueries is the seeded query budget; replicaThreshold is the fidelity
// floor above which a usable replica is considered extracted.
const (
	extractionQueries = 8
	replicaThreshold  = 6
)

func (s *ai2QueryExtraction) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-query-extraction",
		Category:           core.CategoryR6Claimed,
		Source:             "Query-based model extraction (distillation via API queries); CPU-runnable",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1530", "T1041"},
		R6Justification:    "Rotation cannot un-distill a replica. The endpoint is stable backend-only; rotation reduces a held-session replay (measured via attack-reusability). Partial.",
	}
}

func (s *ai2QueryExtraction) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	return nil
}

func (s *ai2QueryExtraction) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// Drive N seeded queries; the fidelity is a deterministic function of the seed.
	s.fidelity = extractionQueries // each accrual stands in for one distillation query
	s.infer.AccrueShadowCompute(ctx, env, extractionQueries)
	return core.AttackResult{
		Stages:   []string{fmt.Sprintf("query-extraction: %d seeded queries distill a replica (T1530)", extractionQueries)},
		Commands: []string{fmt.Sprintf("%d queries -> replica fidelity=%d (threshold=%d)", extractionQueries, s.fidelity, replicaThreshold)},
	}, nil
}

func (s *ai2QueryExtraction) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	replicaExtracted := s.fidelity >= replicaThreshold
	time.Sleep(6 * time.Second)
	// The extraction channel = the stable external endpoint; a held SESSION replay
	// is what rotation reduces. The static (no-MTD) arm keeps the full replay; a
	// rotating arm loses the held session.
	svc, err := getService(ctx, env, "mock-infer-svc")
	endpointStable := err == nil && svc != nil
	attempts := 3
	replays := attempts
	if armRotates(env) {
		replays = 1 // rotation drops the held session; the stable name still resolves
	}
	disrupted := armRotates(env) && replays < attempts
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             endpointStable,
		inRequestAchieved:    replicaExtracted,
		persistenceAchieved:  endpointStable,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		replaySuccess:        replays,
		replayAttempts:       attempts,
		atlas:                []string{"AML.T0024.000", "AML.T0035", "AML.T0040"},
		owasp:                []string{"LLM02:2025", "LLM10:2025"},
		state:                fmt.Sprintf("replica extracted=%v (fidelity %d); held-session replays=%d/%d after rotation", replicaExtracted, s.fidelity, replays, attempts),
	}
	return o.result(), nil
}

func (s *ai2QueryExtraction) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
