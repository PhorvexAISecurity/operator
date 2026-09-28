package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/phorvex/phorvex/internal/voicerefundpolicy"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type voiceAgencyJournalReceipt struct {
	Version             int             `json:"version"`
	Phase               string          `json:"phase"`
	PolicyName          string          `json:"policyName"`
	PolicyUID           string          `json:"policyUID"`
	PolicyGeneration    int64           `json:"policyGeneration"`
	DeploymentUID       string          `json:"deploymentUID"`
	TargetName          string          `json:"targetName"`
	TargetPodUID        string          `json:"targetPodUID"`
	EventName           string          `json:"eventName"`
	EventUID            string          `json:"eventUID"`
	CreatorIdentity     string          `json:"creatorIdentity"`
	TickID              string          `json:"tickId"`
	SelectionDecisionID string          `json:"selectionDecisionId"`
	ConfigMapUID        string          `json:"configMapUID"`
	Prior               voiceAgencyRule `json:"prior"`
	Desired             voiceAgencyRule `json:"desired"`
	OperationID         string          `json:"operationId"`
}

func voiceAgencyOperationID(policyUID, deploymentUID, podUID, eventUID, tickID, decisionID string) string {
	sum := sha256.Sum256([]byte("phorvex-voice-refund-v1\x00" + policyUID + "\x00" + deploymentUID + "\x00" + podUID + "\x00" + eventUID + "\x00" + tickID + "\x00" + decisionID))
	return hex.EncodeToString(sum[:])
}
func voiceAgencyJournalName(deploymentUID string, revision uint64) string {
	sum := sha256.Sum256([]byte(deploymentUID))
	return "phorvex-voice-refund-" + hex.EncodeToString(sum[:16]) + "-" + strconv.FormatUint(revision, 10)
}
func voiceAgencyRuleBytes(r voiceAgencyRule) string {
	return string(r.Bytes())
}
func voiceAgencyHasPair(rule voiceAgencyRule, callerSHA, orderSHA, operationID string) bool {
	for _, entry := range rule.Entries {
		if entry.AssertedCallerSHA256 == callerSHA && entry.OrderSHA256 == orderSHA && entry.OperationID == operationID {
			return true
		}
	}
	return false
}

func (s *Server) voiceAgencyJournal(ctx context.Context, before voiceAgencySnapshot, decision voiceMemoryDecision,
	event *attackStimulusEvidence, target corev1.Pod, callerSHA, orderSHA string) (voiceAgencyJournalReceipt, error) {
	var out voiceAgencyJournalReceipt
	if !decision.Selected || decision.Action != voiceAgencyAction || decision.TickID == "" || decision.DecisionID == "" ||
		event == nil || event.EventUID == "" {
		return out, errors.New("exact Voice refund selection unavailable")
	}
	kube, e := clientForContext("")
	if e != nil {
		return out, e
	}
	cm, e := kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, voiceAgencyJournalName(before.DeploymentUID, before.Rule.Revision+1), metav1.GetOptions{})
	if e != nil {
		return out, e
	}
	return voiceAgencyValidateJournal(cm, before, decision, event, target, callerSHA, orderSHA)
}

func voiceAgencyValidateJournal(cm *corev1.ConfigMap, before voiceAgencySnapshot, decision voiceMemoryDecision,
	event *attackStimulusEvidence, target corev1.Pod, callerSHA, orderSHA string) (voiceAgencyJournalReceipt, error) {
	var out voiceAgencyJournalReceipt
	if cm == nil || !decision.Selected || decision.Action != voiceAgencyAction || decision.TickID == "" || decision.DecisionID == "" ||
		event == nil || event.EventUID == "" || cm.Name != voiceAgencyJournalName(before.DeploymentUID, before.Rule.Revision+1) ||
		cm.Namespace != "phorvex-system" {
		return out, errors.New("Voice refund journal scope differs")
	}
	raw := cm.Data["receipt.json"]
	if cm.Labels["phorvex.ai/voice-refund-journal"] != "v1" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 ||
		len(raw) == 0 || len(raw) > 150000 || json.Unmarshal([]byte(raw), &out) != nil || out.Version != 1 || out.Phase != "terminal-full" ||
		out.PolicyName != voiceAgencyPolicyName || out.PolicyUID != before.PolicyUID || out.PolicyGeneration != before.PolicyGeneration ||
		out.DeploymentUID != before.DeploymentUID || out.TargetName != target.Name || out.TargetPodUID != string(target.UID) ||
		out.EventName != event.EventName || out.EventUID != event.EventUID || out.CreatorIdentity != before.EventCreator ||
		out.TickID != decision.TickID || out.SelectionDecisionID != decision.DecisionID || out.ConfigMapUID != before.ConfigMapUID ||
		voiceAgencyRuleBytes(out.Prior) != voiceAgencyRuleBytes(before.Rule) || out.Desired.Revision != before.Rule.Revision+1 ||
		out.OperationID != voiceAgencyOperationID(before.PolicyUID, before.DeploymentUID, string(target.UID), event.EventUID, decision.TickID, decision.DecisionID) ||
		out.Desired.OperationID != out.OperationID || !voiceAgencyHasPair(out.Desired, callerSHA, orderSHA, out.OperationID) {
		return voiceAgencyJournalReceipt{}, errors.New("Voice refund terminal journal does not join exact selection and pair")
	}
	if string(voiceAgencyCanonicalReceipt(out)) != raw {
		return voiceAgencyJournalReceipt{}, errors.New("Voice refund terminal journal noncanonical")
	}
	want, appendErr := voicerefundpolicy.Append(before.Rule,
		voicerefundpolicy.Entry{AssertedCallerSHA256: callerSHA, OrderSHA256: orderSHA}, out.OperationID)
	if appendErr != nil || voiceAgencyRuleBytes(out.Desired) != voiceAgencyRuleBytes(want) {
		return voiceAgencyJournalReceipt{}, errors.New("Voice refund journal desired rule is not exact append")
	}
	return out, nil
}
func voiceAgencyCanonicalReceipt(value any) []byte { raw, _ := json.Marshal(value); return raw }

func (s *Server) waitVoiceAgencyDecision(ctx context.Context, record *attackRecord, before voiceAgencySnapshot, eventUID string) (voiceMemoryDecision, error) {
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var observed voiceMemoryDecision
	for {
		rows, e := s.readDecisionWindow(ctx, "")
		if e == nil {
			for _, row := range rows {
				candidate, ok := voiceMemorySelectedDecision(row, record, voiceMemorySnapshot{PolicyUID: before.PolicyUID}, eventUID)
				if !ok {
					continue
				}
				if !observed.Selected {
					observed = candidate
				} else if observed.DecisionID == candidate.DecisionID && observed.TickID == candidate.TickID && candidate.Actuated {
					observed.Actuated = true
				}
				if observed.Selected {
					return observed, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return observed, ctx.Err()
		case <-deadline.C:
			return observed, errors.New("Voice agency exact brain selection absent")
		case <-ticker.C:
		}
	}
}

func (s *Server) waitVoiceAgencyEffect(ctx context.Context, p voiceAgencyProfile, before voiceAgencySnapshot,
	decision voiceMemoryDecision, event *attackStimulusEvidence, target corev1.Pod, callerSHA, orderSHA string) (voiceAgencySnapshot, voiceAgencyJournalReceipt, error) {
	var receipt voiceAgencyJournalReceipt
	if decision.Action != voiceAgencyAction || !decision.Selected {
		return voiceAgencySnapshot{}, receipt, errors.New("brain selected another action")
	}
	var after voiceAgencySnapshot
	err := waitVoicePolicyEffect(ctx, voicePolicyEffectWait, voicePolicyEffectPoll, func(ctx context.Context) bool {
		journal, e := s.voiceAgencyJournal(ctx, before, decision, event, target, callerSHA, orderSHA)
		if e == nil {
			current, readErr := s.voiceAgencySnapshot(ctx, p)
			if readErr == nil && current.DeploymentUID == before.DeploymentUID && current.PolicyUID == before.PolicyUID &&
				current.PolicyGeneration == before.PolicyGeneration && current.ConfigMapUID == before.ConfigMapUID &&
				current.RuleSHA256 == voiceAgencyStringDigest(voiceAgencyRuleBytes(journal.Desired)) &&
				current.Rule.Revision == journal.Desired.Revision && voiceAgencySnapshotHasPod(current, target.Name, string(target.UID)) {
				after, receipt = current, journal
				return true
			}
		}
		return false
	})
	if errors.Is(err, errVoicePolicyEffectTimeout) {
		err = errors.New("Voice refund protected effect/readback unavailable")
	}
	if err != nil {
		return voiceAgencySnapshot{}, voiceAgencyJournalReceipt{}, err
	}
	return after, receipt, nil
}
