package console

import (
	"context"
	"errors"
	"testing"
	"time"
)

func mcpFinalObservation() voiceMCPProbeReply {
	run, phase := "localrun", "attack"
	return voiceMCPProbeReply{Version: 1, Operation: "observe", Phase: phase,
		RunSHA256: voiceMCPStringSHA(run), CallSIDHash: voiceMCPStringSHA(voiceMCPCallSID(run, phase)),
		TranscriptSHA256: voiceMCPStringSHA("complete assistant"), ObservedAtUnixMs: time.Now().UnixMilli(),
		Messages: []voiceMCPMessage{{Role: "assistant", Content: "Store hours are 9am to 9pm."}},
		Receipt: voiceMCPAppReceipt{Version: 1, RunSHA256: voiceMCPStringSHA(run), Phase: phase,
			CallSID: voiceMCPCallSID(run, phase), PodUID: "local-pod", SourceSHA256: voiceMCPStringSHA("source"), FetchObserved: true}}
}
func waitMCPFinal(ctx context.Context, wait time.Duration, fetch func(context.Context) (voiceMCPProbeReply, error)) (voiceMCPProbeReply, error) {
	return voiceMCPWaitObservation(ctx, wait, time.Millisecond, "localrun", "attack", "local-pod", voiceMCPStringSHA("source"), fetch)
}
func TestVoiceMCPFinalizationWaitsForDurableAssistantAndStableReads(t *testing.T) {
	final := mcpFinalObservation()
	calls := 0
	got, err := waitMCPFinal(context.Background(), 100*time.Millisecond, func(context.Context) (voiceMCPProbeReply, error) {
		calls++
		if calls == 1 {
			return voiceMCPProbeReply{}, errors.New("not yet persisted")
		}
		if calls == 2 {
			row := final
			row.Messages = []voiceMCPMessage{{Role: "user", Content: "hours?"}}
			return row, nil
		}
		row := final
		row.ObservedAtUnixMs += int64(calls)
		return row, nil
	})
	if err != nil || calls != 4 || !voiceMCPHasAssistant(got.Messages) {
		t.Fatalf("late final result calls=%d error=%v reply=%+v", calls, err, got)
	}
}
func TestVoiceMCPFinalizationRejectsDifferentIdentityAndChangingFinals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*voiceMCPProbeReply)
	}{
		{"foreign run", func(r *voiceMCPProbeReply) { r.RunSHA256 = voiceMCPStringSHA("other") }},
		{"foreign phase", func(r *voiceMCPProbeReply) { r.Phase = "benign" }},
		{"foreign call", func(r *voiceMCPProbeReply) { r.CallSIDHash = voiceMCPStringSHA("other") }},
		{"foreign pod", func(r *voiceMCPProbeReply) { r.Receipt.PodUID = "other" }},
		{"foreign source", func(r *voiceMCPProbeReply) { r.Receipt.SourceSHA256 = voiceMCPStringSHA("other") }},
		{"no real fetch", func(r *voiceMCPProbeReply) { r.Receipt.FetchObserved = false }},
		{"foreign SDK call", func(r *voiceMCPProbeReply) { r.Receipt.CallSID = "CAother" }},
		{"rewritten transcript", func(r *voiceMCPProbeReply) { r.TranscriptSHA256 = voiceMCPStringSHA("rewrite") }},
		{"rewritten message", func(r *voiceMCPProbeReply) { r.Messages = []voiceMCPMessage{{Role: "assistant", Content: "changed"}} }},
		{"assistant disappeared", func(r *voiceMCPProbeReply) { r.Messages = []voiceMCPMessage{{Role: "user", Content: "hours?"}} }},
		{"changed SDK state", func(r *voiceMCPProbeReply) { r.Receipt.State = "changed" }},
		{"late callback rewrite", func(r *voiceMCPProbeReply) { r.ToolCalls = []voiceMCPToolCall{{ToolName: "other"}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			_, err := waitMCPFinal(context.Background(), 100*time.Millisecond, func(context.Context) (voiceMCPProbeReply, error) {
				calls++
				row := mcpFinalObservation()
				if calls == 2 {
					tc.edit(&row)
				}
				return row, nil
			})
			if err == nil {
				t.Fatal("inconsistent evidence accepted")
			}
		})
	}
}
func TestVoiceMCPFinalizationMissingEmptyErrorsDeadlineAndCancel(t *testing.T) {
	for _, kind := range []string{"user-only", "empty-assistant", "read-error", "late-read"} {
		t.Run(kind, func(t *testing.T) {
			_, err := waitMCPFinal(context.Background(), 5*time.Millisecond, func(context.Context) (voiceMCPProbeReply, error) {
				row := mcpFinalObservation()
				switch kind {
				case "user-only":
					row.Messages = []voiceMCPMessage{{Role: "user", Content: "hours?"}}
				case "empty-assistant":
					row.Messages = []voiceMCPMessage{{Role: "assistant", Content: "  "}}
				case "read-error":
					return row, errors.New("private evidence unavailable")
				case "late-read":
					time.Sleep(8 * time.Millisecond)
				}
				return row, nil
			})
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := waitMCPFinal(ctx, time.Second, func(context.Context) (voiceMCPProbeReply, error) { calls++; return mcpFinalObservation(), nil })
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("cancellation error=%v calls=%d", err, calls)
	}
}
func TestVoiceMCPFinalReadCannotDisappearBetweenStableSamples(t *testing.T) {
	calls := 0
	_, err := waitMCPFinal(context.Background(), 100*time.Millisecond, func(context.Context) (voiceMCPProbeReply, error) {
		calls++
		if calls == 2 {
			return voiceMCPProbeReply{}, errors.New("final transcript disappeared")
		}
		return mcpFinalObservation(), nil
	})
	if err == nil || calls != 2 {
		t.Fatalf("vanished final accepted error=%v calls=%d", err, calls)
	}
}

func TestVoiceMCPAudioSettledRequiresActualAudioAtFullWindow(t *testing.T) {
	good := voiceMCPProbeReply{AudioQuietObserved: true, ReceivedFrames: 3, ReceivedAudioFrames: 2, ReceivedAudioBytes: 320, ReceivedAudioSHA256: voiceMCPStringSHA("actual decoded media")}
	if !voiceMCPAudioSettled(good) {
		t.Fatal("actual settled audio rejected")
	}
	for _, edit := range []func(*voiceMCPProbeReply){
		func(r *voiceMCPProbeReply) { r.AudioQuietObserved = false }, func(r *voiceMCPProbeReply) { r.ReceivedAudioFrames = 0 },
		func(r *voiceMCPProbeReply) { r.ReceivedAudioFrames = 4 }, func(r *voiceMCPProbeReply) { r.ReceivedFrames = 1025 },
		func(r *voiceMCPProbeReply) { r.ReceivedAudioBytes = 0 }, func(r *voiceMCPProbeReply) { r.ReceivedAudioBytes = 1<<20 + 1 },
		func(r *voiceMCPProbeReply) { r.ReceivedAudioSHA256 = "invalid" }, func(r *voiceMCPProbeReply) { r.ReceivedAudioSHA256 = voiceMCPStringSHA("") },
	} {
		broken := good
		edit(&broken)
		if voiceMCPAudioSettled(broken) {
			t.Fatalf("invalid audio accepted %+v", broken)
		}
	}
}
