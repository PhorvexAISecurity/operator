package console

import (
	"context"
	"errors"
	"time"
)

const (
	voiceOutputFinalEvidenceWait = 10 * time.Second
	voiceOutputFinalEvidencePoll = 250 * time.Millisecond
)

// Final audio and transcript receipts are written during bot teardown, after
// the caller WebSocket closes. An empty early read is not a completed negative.
func voiceOutputFinalReceiptsReady(rows voiceOutputProbeReply, run, phase, podUID, source string) (bool, error) {
	call := voiceOutputSHA(voiceOutputCallSID(run, phase))
	if rows.Version != 1 || rows.Operation != "receipts" || rows.Phase != phase ||
		rows.RunSHA256 != voiceOutputSHA(run) || rows.CallSIDHash != call {
		return false, errors.New("final Voice output receipt identity differs")
	}
	seen := make(map[string]map[int]bool)
	finalTimes := make(map[string]int64)
	for _, row := range rows.Receipts {
		if row.Version != 1 || row.CallSIDHash != call || row.PodUID != podUID || row.SourceSHA256 != source ||
			row.ObservedAtUnixMs <= 0 || row.Sequence < 0 || row.Sequence >= 8 ||
			(row.Stage != "guard" && row.Stage != "audio" && row.Stage != "transcript") ||
			(row.Stage != "guard" && row.Sequence != 0) {
			return false, errors.New("final Voice output receipt provenance differs")
		}
		if seen[row.Stage] == nil {
			seen[row.Stage] = make(map[int]bool)
		}
		if seen[row.Stage][row.Sequence] {
			return false, errors.New("duplicate final Voice output receipt")
		}
		seen[row.Stage][row.Sequence] = true
		if row.Sequence == 0 {
			finalTimes[row.Stage] = row.ObservedAtUnixMs
		}
		if row.Stage == "transcript" && !row.Persisted {
			return false, errors.New("final Voice output transcript persistence failed")
		}
	}
	ready := seen["guard"][0] && seen["audio"][0] && seen["transcript"][0]
	if ready && (finalTimes["audio"] < finalTimes["guard"] || finalTimes["transcript"] < finalTimes["guard"]) {
		return false, errors.New("final Voice output receipt chronology differs")
	}
	return ready, nil
}

// Waiting establishes completed evidence only. The existing first-loss, replay
// and benign predicates remain responsible for every behavioral requirement.
func voiceOutputWaitFinalEvidence(ctx context.Context, wait, poll time.Duration, run, phase, podUID, source string,
	fetch func(context.Context, string) (voiceOutputProbeReply, error)) (voiceOutputProbeReply, voiceOutputProbeReply, error) {
	deadline, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var rows, stored voiceOutputProbeReply
	for {
		if err := deadline.Err(); err != nil {
			return rows, stored, err
		}
		var err error
		rows, err = fetch(deadline, "receipts")
		if err != nil {
			return rows, stored, err
		}
		if err = deadline.Err(); err != nil {
			return rows, stored, err
		}
		ready, err := voiceOutputFinalReceiptsReady(rows, run, phase, podUID, source)
		if err != nil {
			return rows, stored, err
		}
		if ready {
			stored, err = fetch(deadline, "transcript")
			if err != nil {
				return rows, stored, err
			}
			if err = deadline.Err(); err != nil {
				return rows, stored, err
			}
			if stored.Version != 1 || stored.Operation != "transcript" || stored.Phase != phase ||
				stored.RunSHA256 != voiceOutputSHA(run) || len(stored.Proofs) != 1 ||
				stored.Proofs[0].Phase != phase || stored.Proofs[0].CallSIDHash != rows.CallSIDHash {
				return rows, stored, errors.New("final independent Voice output transcript identity differs")
			}
			for _, row := range rows.Receipts {
				if row.Stage == "transcript" && (row.AssistantSHA256 != stored.Proofs[0].AssistantSHA256 ||
					row.AssistantPresent != stored.Proofs[0].AssistantPresent || row.MarkerObserved != stored.Proofs[0].MarkerObserved ||
					row.MarkerSHA256 != stored.Proofs[0].MarkerSHA256) {
					return rows, stored, errors.New("final Voice output transcript readback differs")
				}
			}
			return rows, stored, nil
		}
		timer := time.NewTimer(poll)
		select {
		case <-deadline.Done():
			timer.Stop()
			return rows, stored, deadline.Err()
		case <-timer.C:
		}
	}
}

func voiceOutputPhaseFinalEvidence(ctx context.Context, target voiceAgencyPodPin, run, phase, source string) (voiceOutputProbeReply, voiceOutputProbeReply, error) {
	return voiceOutputWaitFinalEvidence(ctx, voiceOutputFinalEvidenceWait, voiceOutputFinalEvidencePoll, run, phase, target.UID, source,
		func(probeCtx context.Context, operation string) (voiceOutputProbeReply, error) {
			if operation == "receipts" {
				return voiceOutputProbe(probeCtx, target, operation, run, phase, source, "")
			}
			return voiceOutputProbe(probeCtx, target, operation, run, phase, "", "")
		})
}
