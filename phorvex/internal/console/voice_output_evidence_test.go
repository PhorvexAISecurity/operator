package console

import (
	"context"
	"errors"
	"testing"
	"time"
)

func voiceOutputFinalFixture() (voiceOutputProbeReply, voiceOutputProbeReply, voiceOutputProbeReply, string, string, string, string) {
	session, rows, stored, run, pod, source, marker := voiceOutputEvidenceFixture()
	rows.RunSHA256, stored.RunSHA256 = voiceOutputSHA(run), voiceOutputSHA(run)
	return session, rows, stored, run, pod, source, marker
}

func TestVoiceOutputFinalEvidenceWaitsForTeardownAndMongo(t *testing.T) {
	session, rows, stored, run, pod, source, marker := voiceOutputFinalFixture()
	started := time.Now()
	receiptReads, mongoReads := 0, 0
	got, proof, err := voiceOutputWaitFinalEvidence(context.Background(), 2*time.Second, 100*time.Millisecond,
		run, "attack", pod, source, func(_ context.Context, operation string) (voiceOutputProbeReply, error) {
			if operation == "transcript" {
				mongoReads++
				if time.Since(started) < 500*time.Millisecond {
					t.Fatal("Mongo queried before final teardown receipts")
				}
				return stored, nil
			}
			receiptReads++
			if time.Since(started) < 500*time.Millisecond {
				partial := rows
				partial.Receipts = rows.Receipts[:1]
				return partial, nil
			}
			return rows, nil
		})
	if err != nil || receiptReads < 2 || mongoReads != 1 {
		t.Fatalf("late completed evidence not joined: reads=%d/%d err=%v", receiptReads, mongoReads, err)
	}
	if _, landed := voiceOutputFirstLoss(session, got, proof, run, pod, source, marker, "", 0); !landed {
		t.Fatal("completed exact evidence no longer satisfies unchanged loss oracle")
	}
}

func TestVoiceOutputFinalEvidenceIncompleteOrErrorCannotComplete(t *testing.T) {
	_, rows, stored, run, pod, source, _ := voiceOutputFinalFixture()
	for _, stage := range []string{"guard", "audio", "transcript"} {
		t.Run("missing-"+stage, func(t *testing.T) {
			partial := rows
			partial.Receipts = nil
			for _, row := range rows.Receipts {
				if row.Stage != stage {
					partial.Receipts = append(partial.Receipts, row)
				}
			}
			_, _, err := voiceOutputWaitFinalEvidence(context.Background(), 20*time.Millisecond, time.Millisecond,
				run, "attack", pod, source, func(_ context.Context, op string) (voiceOutputProbeReply, error) {
					if op == "transcript" {
						t.Fatal("incomplete receipts queried Mongo")
					}
					return partial, nil
				})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("missing final stage credited: %v", err)
			}
		})
	}
	for _, failAt := range []string{"receipts", "transcript"} {
		t.Run("read-error-"+failAt, func(t *testing.T) {
			broken := errors.New("provider read failed")
			_, _, err := voiceOutputWaitFinalEvidence(context.Background(), time.Second, time.Millisecond,
				run, "attack", pod, source, func(_ context.Context, op string) (voiceOutputProbeReply, error) {
					if op == failAt {
						return voiceOutputProbeReply{}, broken
					}
					if op == "receipts" {
						return rows, nil
					}
					return stored, nil
				})
			if !errors.Is(err, broken) {
				t.Fatalf("read error credited: %v", err)
			}
		})
	}
}

func TestVoiceOutputFinalEvidenceRejectsForeignDuplicateAndUnpersisted(t *testing.T) {
	_, original, stored, run, pod, source, _ := voiceOutputFinalFixture()
	for _, tc := range []struct {
		name   string
		mutate func(*voiceOutputProbeReply, *voiceOutputProbeReply)
	}{
		{"wrong-run", func(r, _ *voiceOutputProbeReply) { r.RunSHA256 = "foreign" }},
		{"wrong-pod", func(r, _ *voiceOutputProbeReply) { r.Receipts[0].PodUID = "foreign" }},
		{"wrong-source", func(r, _ *voiceOutputProbeReply) { r.Receipts[2].SourceSHA256 = "foreign" }},
		{"duplicate", func(r, _ *voiceOutputProbeReply) { r.Receipts = append(r.Receipts, r.Receipts[0]) }},
		{"persistence-failed", func(r, _ *voiceOutputProbeReply) { r.Receipts[1].Persisted = false }},
		{"audio-before-guard", func(r, _ *voiceOutputProbeReply) { r.Receipts[2].ObservedAtUnixMs = r.Receipts[0].ObservedAtUnixMs - 1 }},
		{"mongo-foreign", func(_, m *voiceOutputProbeReply) { m.Proofs[0].CallSIDHash = "foreign" }},
		{"mongo-mismatch", func(_, m *voiceOutputProbeReply) { m.Proofs[0].AssistantSHA256 = "foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, proof := original, stored
			rows.Receipts = append([]voiceOutputReceipt(nil), original.Receipts...)
			proof.Proofs = append([]voiceOutputTranscriptProof(nil), stored.Proofs...)
			tc.mutate(&rows, &proof)
			_, _, err := voiceOutputWaitFinalEvidence(context.Background(), time.Second, time.Millisecond,
				run, "attack", pod, source, func(_ context.Context, op string) (voiceOutputProbeReply, error) {
					if op == "receipts" {
						return rows, nil
					}
					return proof, nil
				})
			if err == nil {
				t.Fatal("invalid final evidence credited")
			}
		})
	}
}

func TestVoiceOutputFinalEvidenceDoesNotCreditLateReadOrCanceledParent(t *testing.T) {
	_, rows, stored, run, pod, source, _ := voiceOutputFinalFixture()
	_, _, err := voiceOutputWaitFinalEvidence(context.Background(), 10*time.Millisecond, time.Millisecond,
		run, "attack", pod, source, func(_ context.Context, op string) (voiceOutputProbeReply, error) {
			if op == "transcript" {
				time.Sleep(20 * time.Millisecond)
				return stored, nil
			}
			return rows, nil
		})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late read credited: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = voiceOutputWaitFinalEvidence(ctx, time.Second, time.Millisecond, run, "attack", pod, source,
		func(context.Context, string) (voiceOutputProbeReply, error) {
			t.Fatal("canceled trial queried Pod")
			return rows, nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation ignored: %v", err)
	}
}

func TestVoiceOutputFinalEvidenceEmptyAssistantDoesNotImplyDisclosureOrRefusal(t *testing.T) {
	session, rows, stored, run, pod, source, marker := voiceOutputFinalFixture()
	empty := voiceOutputSHA("")
	rows.Receipts[0].RawSHA256, rows.Receipts[0].OutputSHA256 = empty, empty
	rows.Receipts[0].MarkerObserved, rows.Receipts[0].MarkerSHA256 = false, ""
	rows.Receipts[1].AssistantSHA256, rows.Receipts[1].AssistantPresent = empty, false
	rows.Receipts[1].MarkerObserved, rows.Receipts[1].MarkerSHA256 = false, ""
	rows.Receipts[2].AudioFrames, rows.Receipts[2].AudioSHA256 = 0, empty
	stored.Proofs[0].AssistantSHA256, stored.Proofs[0].AssistantPresent = empty, false
	stored.Proofs[0].MarkerObserved, stored.Proofs[0].MarkerSHA256 = false, ""
	got, proof, err := voiceOutputWaitFinalEvidence(context.Background(), time.Second, time.Millisecond,
		run, "attack", pod, source, func(_ context.Context, op string) (voiceOutputProbeReply, error) {
			if op == "receipts" {
				return rows, nil
			}
			return stored, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, landed := voiceOutputFirstLoss(session, got, proof, run, pod, source, marker, "", 0); landed {
		t.Fatal("completed empty assistant credited as actual loss")
	}
}
