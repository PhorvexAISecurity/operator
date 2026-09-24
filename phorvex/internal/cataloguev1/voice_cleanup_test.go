package cataloguev1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kfake "k8s.io/client-go/kubernetes/fake"
)

const cleanupFirstSID = "CA11111111111111111111111111111111"
const cleanupSecondSID = "CA22222222222222222222222222222222"

type voiceCleanupObservation struct {
	outcome        VoiceCleanup
	queries        int
	deletes        []string
	intents        []string
	results        []string
	deleteAttempts int
}

func runVoiceCleanupSchedule(t *testing.T, secondAt int, deleteError bool) voiceCleanupObservation {
	return runVoiceCleanupScheduleWithReappearance(t, secondAt, deleteError, false)
}

func runVoiceCleanupScheduleWithReappearance(t *testing.T, secondAt int, deleteError, reappear bool) voiceCleanupObservation {
	t.Helper()
	firstRef := TranscriptRef{CallSID: cleanupFirstSID, ObjectID: strings.Repeat("1", 24), ContentSHA256: strings.Repeat("a", 64)}
	secondRef := TranscriptRef{CallSID: cleanupSecondSID, ObjectID: strings.Repeat("2", 24), ContentSHA256: strings.Repeat("b", 64)}
	present := map[string]TranscriptRef{cleanupFirstSID: firstRef}
	observed := voiceCleanupObservation{}
	secondAdded := false
	firstDeleted := false
	firstReappeared := false
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-a", Namespace: "voice", UID: types.UID("pod-a"), Labels: map[string]string{"app": "voice-bot"}}}
	runtime := &kubeVoiceRuntime{kube: kfake.NewSimpleClientset(pod), voice: VoiceRuntime{TranscriptPodSelector: "app=voice-bot", TranscriptContainer: "bot"}}
	runtime.execOverride = func(_ context.Context, namespace, name, container string, command []string) (string, error) {
		if namespace != "voice" || name != "voice-bot-a" || container != "bot" || len(command) < 3 || command[0] != "python3" || command[1] != "-c" {
			return "", errors.New("unexpected owned exec route")
		}
		switch command[2] {
		case transcriptQueryProgram:
			observed.queries++
			if reappear && firstDeleted && !firstReappeared {
				present[cleanupFirstSID] = firstRef
				firstReappeared = true
			}
			if observed.queries >= secondAt && !secondAdded {
				present[cleanupSecondSID] = secondRef
				secondAdded = true
			}
			refs := make([]TranscriptRef, 0, len(present))
			for _, sid := range []string{cleanupFirstSID, cleanupSecondSID} {
				if ref, ok := present[sid]; ok {
					refs = append(refs, ref)
				}
			}
			raw, err := json.Marshal(refs)
			return "OWNED_TRANSCRIPTS=" + string(raw) + "\n", err
		case transcriptDeleteProgram:
			if len(command) != 6 {
				return "", errors.New("delete command shape differs")
			}
			observed.deleteAttempts++
			if deleteError {
				return "", context.DeadlineExceeded
			}
			sid := command[3]
			ref, ok := present[sid]
			if !ok || ref.ObjectID != command[4] || ref.ContentSHA256 != command[5] {
				return "", errors.New("delete target or hash differs")
			}
			observed.deletes = append(observed.deletes, sid)
			delete(present, sid)
			if sid == cleanupFirstSID {
				firstDeleted = true
			}
			return "OWNED_DELETE={\"deletedCount\":1,\"alreadyAbsent\":false,\"remaining\":0}\n", nil
		default:
			return "", fmt.Errorf("unexpected fixed script")
		}
	}
	runtime.pauseOverride = func(context.Context, time.Duration) error { return nil }
	observed.outcome = runtime.CleanupTranscripts(context.Background(), testVoiceConfig(VoiceReplacementRecovery),
		VoicePod{Name: "voice-bot-a", UID: "pod-a"}, []string{cleanupFirstSID, cleanupSecondSID},
		func(ref TranscriptRef) error { observed.intents = append(observed.intents, ref.CallSID); return nil },
		func(ref TranscriptRef) error { observed.results = append(observed.results, ref.CallSID); return nil })
	sort.Strings(observed.intents)
	sort.Strings(observed.results)
	return observed
}

func TestVoiceCleanupLateSecondSID(t *testing.T) {
	observed := runVoiceCleanupSchedule(t, 2, false)
	if observed.outcome.Status != "PASS" || observed.outcome.UnsafeToRetry || observed.outcome.DocumentsRemaining != 0 ||
		len(observed.deletes) != 2 || strings.Join(observed.intents, ",") != cleanupFirstSID+","+cleanupSecondSID ||
		strings.Join(observed.results, ",") != cleanupFirstSID+","+cleanupSecondSID {
		t.Fatalf("late second SID not cleaned exactly once: %+v", observed)
	}
}

func TestVoiceCleanupLateDuringZeroChecks(t *testing.T) {
	observed := runVoiceCleanupSchedule(t, 12, false) // after ten settle queries and one zero check
	if observed.outcome.Status != "PASS" || len(observed.deletes) != 2 || observed.queries < 15 {
		t.Fatalf("new exact ref during zero checks not CAS-deleted: %+v", observed)
	}
}

func TestVoiceCleanupAbsentSecondSID(t *testing.T) {
	observed := runVoiceCleanupSchedule(t, 100, false)
	if observed.outcome.Status != "PASS" || len(observed.deletes) != 1 || observed.deletes[0] != cleanupFirstSID {
		t.Fatalf("bounded absent second SID refused or invented a delete: %+v", observed)
	}
}

func TestVoiceCleanupAmbiguousDeleteNeverRetries(t *testing.T) {
	observed := runVoiceCleanupSchedule(t, 100, true)
	if observed.outcome.Status != "FAIL" || !observed.outcome.UnsafeToRetry || observed.deleteAttempts != 1 ||
		len(observed.intents) != 1 || len(observed.results) != 0 {
		t.Fatalf("ambiguous exact delete was retried or accepted: %+v", observed)
	}
}

func TestVoiceCleanupAcknowledgedObjectReappearsWithoutSecondDelete(t *testing.T) {
	observed := runVoiceCleanupScheduleWithReappearance(t, 100, false, true)
	if observed.outcome.Status != "FAIL" || !observed.outcome.UnsafeToRetry || observed.deleteAttempts != 1 ||
		len(observed.intents) != 1 || len(observed.results) != 1 || observed.outcome.Error != "acknowledged Voice transcript reappeared" {
		t.Fatalf("acknowledged object reappearance triggered another delete or was accepted: %+v", observed)
	}
}

func TestVoiceCleanupCancelledAfterFirstResultStopsNextDelete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	refs := []TranscriptRef{
		{CallSID: cleanupFirstSID, ObjectID: strings.Repeat("1", 24), ContentSHA256: strings.Repeat("a", 64)},
		{CallSID: cleanupSecondSID, ObjectID: strings.Repeat("2", 24), ContentSHA256: strings.Repeat("b", 64)},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-a", Namespace: "voice", UID: types.UID("pod-a"), Labels: map[string]string{"app": "voice-bot"}}}
	runtime := &kubeVoiceRuntime{kube: kfake.NewSimpleClientset(pod), voice: VoiceRuntime{TranscriptPodSelector: "app=voice-bot", TranscriptContainer: "bot"}}
	deleteAttempts := 0
	runtime.execOverride = func(_ context.Context, _, _, _ string, command []string) (string, error) {
		switch command[2] {
		case transcriptQueryProgram:
			raw, _ := json.Marshal(refs)
			return "OWNED_TRANSCRIPTS=" + string(raw) + "\n", nil
		case transcriptDeleteProgram:
			deleteAttempts++
			return "OWNED_DELETE={\"deletedCount\":1,\"alreadyAbsent\":false,\"remaining\":1}\n", nil
		default:
			return "", errors.New("unexpected fixed script")
		}
	}
	runtime.pauseOverride = func(context.Context, time.Duration) error { return nil }
	results := 0
	outcome := runtime.CleanupTranscripts(ctx, testVoiceConfig(VoiceReplacementRecovery), VoicePod{Name: "voice-bot-a", UID: "pod-a"}, []string{cleanupFirstSID, cleanupSecondSID},
		func(TranscriptRef) error { return nil }, func(TranscriptRef) error { results++; cancel(); return nil })
	if outcome.Status != "FAIL" || !outcome.UnsafeToRetry || deleteAttempts != 1 || results != 1 {
		t.Fatalf("cancelled cleanup dispatched another delete: outcome=%+v deletes=%d results=%d", outcome, deleteAttempts, results)
	}
}
