package scenarios

// ────────────────────────────────────────────────────────────────────────────
// ai2_embedding_tamper_reuse.go  —  YOUR FIRST ATTACK AGENT (annotated).
//
// WHAT THIS ATTACKS (in plain English):
//   An AI system that answers questions by first looking things up in a little
//   "memory" (a vector store / embedding store — the data behind RAG). The
//   attacker sneaks a tampered document into that memory so the AI keeps
//   retrieving the attacker's content on future questions.
//
// WHY IT MATTERS FOR PHORVEX:
//   The memory lives OUTSIDE the AI's pod (it's a data store, not the workload).
//   Phoenix's whole trick is rotating the pod — killing + replacing it. But
//   rotating the pod does NOTHING to a poisoned data store sitting beside it.
//   So this is a "rotation is useless here" attack  →  tag = R6CannotRespond.
//   That is the honest differentiator argument, and it's the interesting case.
//
// WHAT MAKES THIS ONE A NOTCH MORE CAPABLE than ai2-rag-retrieval-poisoning:
//   it doesn't just check "did the poison persist once?" — it REPLAYS the
//   retrieval several times and counts how many still return the tampered doc.
//   That measures ATTACK REUSABILITY: the poison keeps firing on every request,
//   and (against a rotating defense) that number is UNCHANGED — quantifying the
//   differentiator instead of just asserting it.
// ────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"fmt"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/mocks"
)

// LINE 1 — register. This single line is what makes the harness find + run your
// attack. There is no list to edit anywhere else.
func init() { core.RegisterScenario(&ai2EmbeddingTamperReuse{}) }

// Your attack's private memory: a handle to the fake retriever + how many replays
// re-fired. `ret` is set in Setup and reused in Execute/Oracle.
type ai2EmbeddingTamperReuse struct {
	ret          *mocks.MockRetriever
	replayHits   int
	replayTries  int
}

// The number of times we re-issue the retrieval to prove the poison keeps firing.
const embedReplayCount = 4

// ── METHOD 1/5: Metadata — the ID card (no action happens here) ──────────────
func (s *ai2EmbeddingTamperReuse) Metadata() core.ScenarioMeta {
	return core.ScenarioMeta{
		Name:     "ai2-embedding-tamper-reuse", // unique name (dup = startup crash)
		Category: core.CategoryModernUnsupported,
		Source:   "data-plane: embedding-store tampering with reuse measurement (mock retriever)",
		// HONEST verdict: pod rotation cannot touch a data store beside the pod.
		R6ResponseTag:      core.R6CannotRespond,
		AttackTechniqueIDs: []string{"T1565", "T1195"}, // Data Manipulation / Supply-Chain
		R6Justification: "The embedding store is data-plane and untouched by pod rotation. The " +
			"tampered doc persists across a rotation and keeps re-firing on every retrieval — a " +
			"genuine Phorvex differentiator (data-plane is outside reactive pod-rotation).",
	}
}

// ── METHOD 2/5: Setup — put the victim on the table ──────────────────────────
// DeployMockRetriever stands up a tiny fake vector store (a busybox pod that
// serves a top-k result and keeps its "corpus" in /tmp/store.jsonl). All the
// Kubernetes work is done for you.
func (s *ai2EmbeddingTamperReuse) Setup(ctx context.Context, env *core.Env) error {
	ret, err := mocks.DeployMockRetriever(ctx, env)
	if err != nil {
		return err
	}
	s.ret = ret
	return nil
}

// ── METHOD 3/5: Execute — DO the attack ──────────────────────────────────────
// Step 1: tamper the store (inject a doc that will surface top-k).
// Step 2: replay the retrieval a few times, counting how many still return the
//         tampered doc. Each replay is one "would a fresh question return the
//         poison?" check against the persistent store.
//
// NOTE (honest mock caveat, house style): on this CPU mock the top-k is a cached
// marker file, so the replay demonstrates PERSISTENCE-OF-EFFECT rather than a
// fresh vector search. On a real retriever each replay would be a live query.
func (s *ai2EmbeddingTamperReuse) Execute(ctx context.Context, env *core.Env) (core.AttackResult, error) {
	// Step 1 — the tamper.
	s.ret.TamperEmbedding(ctx, env)

	// Step 2 — replay and count re-fires.
	s.replayTries = embedReplayCount
	s.replayHits = 0
	for i := 0; i < embedReplayCount; i++ {
		if s.ret.TopKContains(ctx, env, mocks.EmbeddingTamperMarker) {
			s.replayHits++
		}
		// small beat between replays; respect cancellation
		select {
		case <-ctx.Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
	env.Log.Logf("ai2-embedding-tamper-reuse: %d/%d replays re-fired (attack reusability)", s.replayHits, s.replayTries)

	return core.AttackResult{
		Stages: []string{
			"embedding-tamper: inject a tampered doc into the store (T1565)",
			fmt.Sprintf("reuse: replay retrieval x%d, count re-fires", embedReplayCount),
		},
		Commands: []string{"append tamper doc -> /tmp/store.jsonl : " + mocks.EmbeddingTamperMarker},
		Notes: map[string]string{
			"replaySuccess":  fmt.Sprintf("%d", s.replayHits),
			"replayAttempts": fmt.Sprintf("%d", s.replayTries),
		},
	}, nil
}

// ── METHOD 4/5: SuccessOracle — did it WORK? (concrete facts only) ───────────
// SPLIT ORACLE — two SEPARATE questions, because rotation can only ever touch
// the second one:
//   (a) in-request: did the tampered doc surface in the retrieval right now?
//   (b) persistence: is the tampered doc STILL in the store after a wait (i.e.
//       did it survive whatever the defense did)?
func (s *ai2EmbeddingTamperReuse) SuccessOracle(ctx context.Context, env *core.Env) (core.OracleResult, error) {
	inReq := s.ret.TopKContains(ctx, env, mocks.EmbeddingTamperMarker) // (a)
	time.Sleep(6 * time.Second)                                        // give a rotating arm time to react
	persisted := s.ret.StoreContains(ctx, env, mocks.EmbeddingTamperMarker) // (b)

	o := aiOracle{
		half:                core.SplitPersistence,
		achieved:            persisted, // attacker "wins" this half iff the tamper survived
		inRequestAchieved:   inReq,
		persistenceAchieved: persisted,
		// MEASURED per-arm: a rotating arm that actually removed the tamper would make
		// this true. For a data-plane store beside the (unrotated) workload it stays
		// false — that's the differentiator, measured not assumed.
		persistenceDisrupted: armRotates(env) && !persisted,
		triggerAttribution:   core.TriggerDetectorAbsent,
		detectorAbsent:       true,
		// the reuse numbers we counted in Execute → feed the attack-reusability metric
		replaySuccess:  s.replayHits,
		replayAttempts: s.replayTries,
		atlas:          []string{"AML.T0051", "AML.T0020", "AML.T0048"},
		owasp:          []string{"LLM08:2025", "LLM04:2025"},
		state: fmt.Sprintf("tamper surfaced in-request=%v; tamper persisted after rotation=%v; re-fired %d/%d replays (data-plane differentiator)",
			inReq, persisted, s.replayHits, s.replayTries),
	}
	return o.result(), nil
}

// ── METHOD 5/5: Teardown — clean up (idempotent, safe to re-run) ─────────────
func (s *ai2EmbeddingTamperReuse) Teardown(ctx context.Context, env *core.Env) error {
	return teardownByApp(ctx, env, "mock-retriever")
}
