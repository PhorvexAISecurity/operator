package scenarios

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

func init() { core.RegisterScenario(&ai2KVCachePoisoning{}) }

// ai2KVCachePoisoning: KV-cache poisoning / cross-session leak (audit #11 KV-cache
// ABSENT/GPU-PENDING, mocked on CPU as /tmp/kv_<session>). SPLIT ORACLE:
//   (a) cross-session KV leak in-request (KV isolation ABSENT -> CANNOT-HELP);
//   (b) the poisoned cache entry survives a rotation — a rotation that drops the
//       pod clears the mocked /tmp/kv cache -> BOUNDS-ONLY. REAL KV-cache behavior
//       is CAPABILITY-PENDING (CapGPU). Runs on CPU but the headline is pending.
type ai2KVCachePoisoning struct {
	infer   *mocks.MockInferenceServer
	session string
}

func (s *ai2KVCachePoisoning) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:               "ai2-kvcache-poisoning-cross-session-leak",
		Category:           core.CategoryModernUnsupported,
		Source:             "KV-cache poisoning / cross-session leak; AUDIT #11 KV-cache ABSENT/GPU-PENDING (mocked)",
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1530", "T1565"},
		CapabilityRequirements: []core.Capability{core.CapGPU},
		R6Justification:        "KV-cache isolation is ABSENT (audit #11) — rotation cannot stop a cross-session leak. A rotation that drops the pod clears the MOCKED /tmp/kv cache; REAL KV-cache behavior is GPU-PENDING. Cannot respond autonomously.",
	}
}

func (s *ai2KVCachePoisoning) Setup(ctx context.Context, env *core.Env) error {
	infer, err := mocks.DeployMockInferenceServer(ctx, env)
	if err != nil {
		return err
	}
	s.infer = infer
	s.session = "sess-kv"
	return nil
}

func (s *ai2KVCachePoisoning) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	s.infer.PlantInjection(ctx, env, s.session) // writes /tmp/kv_<session> with the KV leak marker
	return core.AttackResult{
		Stages:   []string{"kvcache-poisoning: poisoned KV entry leaks another session's content (T1530)"},
		Commands: []string{"poison /tmp/kv_" + s.session + " -> " + mocks.KVLeakMarker},
	}, nil
}

func (s *ai2KVCachePoisoning) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.infer.MarkerPresent(ctx, env, "/tmp/kv_"+s.session, mocks.KVLeakMarker)
	time.Sleep(6 * time.Second)
	persisted := s.infer.MarkerPresent(ctx, env, "/tmp/kv_"+s.session, mocks.KVLeakMarker)
	disrupted := armRotates(env) && !persisted
	o := aiOracle{
		half:                 core.SplitPersistence,
		achieved:             persisted,
		inRequestAchieved:    inReq,
		persistenceAchieved:  persisted,
		persistenceDisrupted: disrupted,
		triggerAttribution:   core.TriggerReceiverOnly,
		detectorAbsent:       true,
		capabilityPending:    true,
		capabilityNote:       "REAL KV-cache behavior is GPU-PENDING (CapGPU); /tmp/kv mock ran on CPU",
		atlas:                []string{"AML.T0024.001", "AML.T0051", "AML.T0048"},
		owasp:                []string{"LLM08:2025", "LLM02:2025"},
		state:                fmt.Sprintf("in-request cross-session KV leak=%v; poisoned cache survived rotation=%v (real number pending)", inReq, persisted),
	}
	return o.result(), nil
}

func (s *ai2KVCachePoisoning) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-infer")
}
