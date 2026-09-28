package console

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"
)

func voiceMCPAudioSettled(session voiceMCPProbeReply) bool {
	return session.AudioQuietObserved && session.ReceivedAudioFrames > 0 &&
		session.ReceivedAudioFrames <= session.ReceivedFrames && session.ReceivedFrames <= 1024 &&
		session.ReceivedAudioBytes >= session.ReceivedAudioFrames && session.ReceivedAudioBytes <= 1<<20 &&
		staticSHA256.MatchString(session.ReceivedAudioSHA256) && session.ReceivedAudioSHA256 != voiceMCPStringSHA("")
}

func voiceMCPHasAssistant(messages []voiceMCPMessage) bool {
	for _, message := range messages {
		if message.Role == "assistant" && strings.TrimSpace(message.Content) != "" {
			return true
		}
	}
	return false
}

// The unchanged bot persists the transcript after its local pipeline teardown.
// A user-only row cannot establish a completed assistant observation. Two
// matching reads join delayed durable visibility without crediting a changing
// transcript, an unrelated call, or a reply that arrives after the deadline.
func voiceMCPWaitObservation(ctx context.Context, wait, poll time.Duration, run, phase, podUID, source string,
	fetch func(context.Context) (voiceMCPProbeReply, error)) (voiceMCPProbeReply, error) {
	bounded, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var reply, previous voiceMCPProbeReply
	for {
		if err := bounded.Err(); err != nil {
			return reply, err
		}
		var err error
		reply, err = fetch(bounded)
		if bounded.Err() != nil {
			return reply, bounded.Err()
		}
		if err != nil && previous.TranscriptSHA256 != "" {
			return reply, errors.New("completed MCP transcript readback became unavailable")
		}
		if err == nil {
			if reply.Version != 1 || reply.Operation != "observe" || reply.Phase != phase ||
				reply.RunSHA256 != voiceMCPStringSHA(run) || reply.CallSIDHash != voiceMCPStringSHA(voiceMCPCallSID(run, phase)) ||
				reply.Receipt.Version != 1 || !reply.Receipt.FetchObserved ||
				reply.Receipt.RunSHA256 != reply.RunSHA256 || reply.Receipt.Phase != phase ||
				reply.Receipt.CallSID != voiceMCPCallSID(run, phase) ||
				reply.Receipt.PodUID != podUID || reply.Receipt.SourceSHA256 != source ||
				!staticSHA256.MatchString(reply.TranscriptSHA256) || reply.ObservedAtUnixMs <= 0 {
				return reply, errors.New("final MCP transcript identity differs")
			}
			if previous.TranscriptSHA256 != "" {
				if reply.TranscriptSHA256 != previous.TranscriptSHA256 || reply.Receipt != previous.Receipt ||
					!reflect.DeepEqual(reply.Messages, previous.Messages) || !reflect.DeepEqual(reply.ToolCalls, previous.ToolCalls) {
					return reply, errors.New("completed MCP transcript or SDK receipt changed")
				}
				return reply, nil
			}
			if voiceMCPHasAssistant(reply.Messages) {
				previous = reply
			}
		}
		timer := time.NewTimer(poll)
		select {
		case <-bounded.Done():
			timer.Stop()
			return reply, bounded.Err()
		case <-timer.C:
		}
	}
}
