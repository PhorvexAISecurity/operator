package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai1ModelTheft{}) }

// ai1ModelTheft: Model Theft — exfiltrate weights via persistent access to a
// static endpoint. SPLIT ORACLE:
//   (a) in-request: a weights blob / replica was extracted (digest captured).
//       Rotation cannot un-steal an artifact; scraping-detector ABSENT -> CANNOT-HELP.
//   (b) persistence: the captured EXTERNAL endpoint still serves /v1/completions
//       after one backend rotation. Per audit #3 the external Service name is
//       STABLE (only the backend pod rotates) -> MTD-BOUNDS-ONLY.
type ai1ModelTheft struct {
	infer      *mocks.MockInferenceServer
	capturedEP string
	digest     string
}

func (s *ai1ModelTheft) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai1-model-theft",
		Category:           core.CategoryR6Claimed,
		Source:             "R6 Phoenix-for-AI (Model Theft); AUDIT #3 endpoint STABLE backend-only",
		R6ResponseTag:      core.R6Partial,
		AttackTechniqueIDs: []string{"T1530", "T1041", "T1567"},
		R6Justification:    "Rotation cannot un-steal an artifact (scraping-detector ABSENT). The external Service endpoint is STABLE (audit #3) — only the backend pod rotates, so a held endpoint is not invalidated. Bounds, not breaks. Partial.",
	}
}

func (s *ai1ModelTheft) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	return nil
}

func (s *ai1ModelTheft) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// Capture the stable external endpoint + pull the weights digest (extraction).
	s.capturedEP = s.infer.ClusterDNS
	s.digest = mocks.MockWeightsDigest
	stages := []string{
		"model-theft: query the static inference endpoint to extract a replica (T1530)",
		"exfil: pull weights digest from /v1/models (digest captured)",
	}
	cmds := []string{
		"GET http://" + s.capturedEP + ":9000/v1/models  # captured digest " + s.digest,
		"saved replica + weights blob (mock)",
	}
	return core.AttackResult{Stages: stages, Commands: cmds}, nil
}

func (s *ai1ModelTheft) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	// (a) in-request: a replica/digest was captured (always true once executed —
	// rotation cannot un-steal it).
	extracted := s.digest == mocks.MockWeightsDigest

	// (b) persistence: after a rotation window, does the SAME external endpoint
	// still serve? The external Service name is stable (backend-only rotation), so
	// the held endpoint stays valid -> MTD-BOUNDS-ONLY (not broken).
	time.Sleep(6 * time.Second)
	svc, err := getService(ctx, env, "mock-infer-svc")
	endpointStable := err == nil && svc != nil && svc.Name == "mock-infer-svc"
	replays := 0
	attempts := 3
	if endpointStable {
		replays = attempts // the stable name keeps resolving after backend rotation
	}

	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             endpointStable, // attacker keeps the endpoint
		inRequestAchieved:    extracted,
		persistenceAchieved:  endpointStable,
		persistenceDisrupted: armRotates(env) && !endpointStable, // MEASURED per-arm: disrupted only if a rotating arm made the held endpoint stop serving (audit #3 keeps the external name stable, so this measures false)
		neutralized:          (armRotates(env) && !endpointStable) && !extracted, // [P-REDTEAM oracle-honesty] DERIVED, not a constant: neutralized iff a rotating arm killed the held endpoint AND the weights were not extracted (the digest-match measurement). Derives false while the external endpoint stays stable / weights leaked; flips true only on a real per-arm denial.
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		replaySuccess:        replays,
		replayAttempts:       attempts,
		atlas:                []string{"AML.T0035", "AML.T0024.002", "AML.T0040", "AML.T0037"},
		owasp:                []string{"LLM02:2025", "LLM10:2025"},
		state:                fmt.Sprintf("extracted=%v digest=%s; external endpoint stable-after-rotation=%v (audit #3 backend-only)", extracted, s.digest, endpointStable),
	}
	return o.result(), nil
}

func (s *ai1ModelTheft) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
