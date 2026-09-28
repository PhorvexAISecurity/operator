package console

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/voicerefundpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The timing probe consumes the real canonical refund journal validator, not
// a preselected success flag. Recovery changes prepared to terminal-full.
func voiceEffectJournalProbe(t *testing.T, terminalAfter time.Duration, foreignEvent bool) func(context.Context) bool {
	t.Helper()
	uid := "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	policyUID := "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
	source, caller, order := strings.Repeat("c", 64), strings.Repeat("d", 64), voiceAgencyStringDigest("9142")
	prior := voicerefundpolicy.Rule{Version: 1, DeploymentUID: uid, PolicyUID: policyUID, SourceSHA256: source,
		Entries: []voicerefundpolicy.Entry{}}
	before := voiceAgencySnapshot{DeploymentUID: uid, PolicyUID: policyUID, PolicyGeneration: 3,
		ConfigMapUID: "cccccccc-cccc-4ccc-cccc-cccccccccccc", Rule: prior,
		EventCreator: "system:serviceaccount:phorvex-system:phorvex-phorvex-console"}
	event := &attackStimulusEvidence{EventName: "voice-refund-test", EventUID: "dddddddd-dddd-4ddd-dddd-dddddddddddd"}
	target := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-1", UID: "eeeeeeee-eeee-4eee-eeee-eeeeeeeeeeee"}}
	decision := voiceMemoryDecision{Action: voiceAgencyAction, Selected: true, TickID: "tick-1", DecisionID: "decision-1"}
	op := voiceAgencyOperationID(policyUID, uid, string(target.UID), event.EventUID, decision.TickID, decision.DecisionID)
	desired, err := voicerefundpolicy.Append(prior, voicerefundpolicy.Entry{AssertedCallerSHA256: caller, OrderSHA256: order}, op)
	if err != nil {
		t.Fatal(err)
	}
	receipt := voiceAgencyJournalReceipt{Version: 1, PolicyName: voiceAgencyPolicyName, PolicyUID: policyUID,
		PolicyGeneration: 3, DeploymentUID: uid, TargetName: target.Name, TargetPodUID: string(target.UID),
		EventName: event.EventName, EventUID: event.EventUID, CreatorIdentity: before.EventCreator,
		TickID: decision.TickID, SelectionDecisionID: decision.DecisionID, ConfigMapUID: before.ConfigMapUID,
		Prior: prior, Desired: desired, OperationID: op}
	if foreignEvent {
		receipt.EventUID = "ffffffff-ffff-4fff-ffff-ffffffffffff"
	}
	started := time.Now()
	return func(context.Context) bool {
		receipt.Phase = "prepared"
		if time.Since(started) >= terminalAfter {
			receipt.Phase = "terminal-full"
		}
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voiceAgencyJournalName(uid, 1), Namespace: "phorvex-system",
			Labels: map[string]string{"phorvex.ai/voice-refund-journal": "v1"}},
			Data: map[string]string{"receipt.json": string(voiceAgencyCanonicalReceipt(receipt))}}
		_, err := voiceAgencyValidateJournal(cm, before, decision, event, target, caller, order)
		return err == nil
	}
}

func TestVoicePolicyEffectWaitAcceptsDelayedExactTerminalJournal(t *testing.T) {
	probe := voiceEffectJournalProbe(t, 350*time.Millisecond, false)
	if err := waitVoicePolicyEffect(context.Background(), 200*time.Millisecond, 5*time.Millisecond, probe); !errors.Is(err, errVoicePolicyEffectTimeout) {
		t.Fatalf("old window credited unfinished journal: %v", err)
	}
	if err := waitVoicePolicyEffect(context.Background(), 400*time.Millisecond, 5*time.Millisecond, probe); err != nil {
		t.Fatalf("longer window missed delayed exact terminal journal: %v", err)
	}
}

func TestVoicePolicyEffectWaitRejectsForeignTerminalJournal(t *testing.T) {
	probe := voiceEffectJournalProbe(t, 0, true)
	if err := waitVoicePolicyEffect(context.Background(), 30*time.Millisecond, time.Millisecond, probe); !errors.Is(err, errVoicePolicyEffectTimeout) {
		t.Fatalf("foreign event became confirmation: %v", err)
	}
}

func TestVoicePolicyEffectWaitParentDeadlineBoundsSlowProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := waitVoicePolicyEffect(ctx, time.Second, time.Millisecond, func(probeCtx context.Context) bool {
		<-probeCtx.Done()
		return true // Even a late positive result cannot escape the parent deadline.
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late confirmation escaped parent run deadline: %v", err)
	}
}

func TestVoicePolicyEffectWaitOwnTimeoutBoundsSlowProbe(t *testing.T) {
	err := waitVoicePolicyEffect(context.Background(), 20*time.Millisecond, time.Millisecond, func(ctx context.Context) bool {
		<-ctx.Done()
		return true
	})
	if !errors.Is(err, errVoicePolicyEffectTimeout) {
		t.Fatalf("late confirmation escaped effect deadline: %v", err)
	}
}
