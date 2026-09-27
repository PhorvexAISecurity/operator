package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/phorvex/phorvex/internal/voiceoutputpolicy"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const voiceOutputJournalName = "phorvex-voice-output-journal"

type voiceOutputJournalReceipt struct {
	Version             int    `json:"version"`
	Phase               string `json:"phase"`
	PolicyName          string `json:"policyName"`
	PolicyUID           string `json:"policyUID"`
	PolicyGeneration    int64  `json:"policyGeneration"`
	DeploymentUID       string `json:"deploymentUID"`
	TargetName          string `json:"targetName"`
	TargetPodUID        string `json:"targetPodUID"`
	EventName           string `json:"eventName"`
	EventUID            string `json:"eventUID"`
	CreatorIdentity     string `json:"creatorIdentity"`
	TickID              string `json:"tickId"`
	SelectionDecisionID string `json:"selectionDecisionId"`
	ConfigMapUID        string `json:"configMapUID"`
	MarkerSHA256        string `json:"markerSHA256"`
	SourceSHA256        string `json:"sourceSHA256"`
	PriorRuleSHA256     string `json:"priorRuleSHA256"`
	DesiredRuleSHA256   string `json:"desiredRuleSHA256"`
	PriorRevision       uint64 `json:"priorRevision"`
	DesiredRevision     uint64 `json:"desiredRevision"`
	OperationID         string `json:"operationId"`
}
type voiceOutputJournal struct {
	Receipts []voiceOutputJournalReceipt `json:"receipts"`
	Version  int                         `json:"version"`
}

func voiceOutputOperationID(policyUID, deploymentUID, podUID, eventUID, tickID, decisionID string) string {
	h := sha256.Sum256([]byte("phorvex-voice-output-v1\x00" + policyUID + "\x00" + deploymentUID + "\x00" + podUID + "\x00" + eventUID + "\x00" + tickID + "\x00" + decisionID))
	return hex.EncodeToString(h[:])
}

func voiceOutputJournalRead(cm *corev1.ConfigMap) (voiceOutputJournal, error) {
	var j voiceOutputJournal
	if cm == nil || cm.Namespace != "phorvex-system" || cm.Name != voiceOutputJournalName ||
		cm.Labels["phorvex.ai/voice-output-journal"] != "v1" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 ||
		len(cm.Data["receipts.json"]) == 0 || len(cm.Data["receipts.json"]) > 262144 ||
		json.Unmarshal([]byte(cm.Data["receipts.json"]), &j) != nil || j.Version != 1 || j.Receipts == nil || len(j.Receipts) > voiceoutputpolicy.MaxEntries {
		return j, errors.New("Voice output protected journal invalid")
	}
	canonical, _ := json.Marshal(j)
	if string(canonical) != cm.Data["receipts.json"] {
		return voiceOutputJournal{}, errors.New("Voice output protected journal noncanonical")
	}
	prior := voiceoutputpolicy.Rule{}
	for i, r := range j.Receipts {
		if r.Version != 1 || (r.Phase != "prepared" && r.Phase != "terminal-full") ||
			(r.Phase == "prepared" && i != len(j.Receipts)-1) || r.PolicyName != voiceAgencyPolicyName ||
			!voiceoutputpolicy.ValidUID(r.PolicyUID) || r.PolicyGeneration <= 0 || !voiceoutputpolicy.ValidUID(r.DeploymentUID) ||
			r.TargetName == "" || !voiceoutputpolicy.ValidUID(r.TargetPodUID) || r.EventName == "" || !voiceoutputpolicy.ValidUID(r.EventUID) ||
			r.CreatorIdentity == "" || r.TickID == "" || r.SelectionDecisionID == "" || !voiceoutputpolicy.ValidUID(r.ConfigMapUID) ||
			!voiceoutputpolicy.ValidSHA(r.MarkerSHA256) || !voiceoutputpolicy.ValidSHA(r.SourceSHA256) ||
			!voiceoutputpolicy.ValidSHA(r.PriorRuleSHA256) || !voiceoutputpolicy.ValidSHA(r.DesiredRuleSHA256) ||
			r.PriorRevision != uint64(i) || r.DesiredRevision != uint64(i+1) ||
			r.OperationID != voiceOutputOperationID(r.PolicyUID, r.DeploymentUID, r.TargetPodUID, r.EventUID, r.TickID, r.SelectionDecisionID) {
			return voiceOutputJournal{}, errors.New("Voice output protected receipt invalid")
		}
		if i == 0 {
			prior = voiceoutputpolicy.Rule{Version: 1, ConfigMapUID: r.ConfigMapUID, DeploymentUID: r.DeploymentUID,
				PolicyUID: r.PolicyUID, SourceSHA256: r.SourceSHA256, Entries: []voiceoutputpolicy.Entry{}}
		}
		if prior.SHA256() != r.PriorRuleSHA256 || prior.ConfigMapUID != r.ConfigMapUID || prior.DeploymentUID != r.DeploymentUID ||
			prior.PolicyUID != r.PolicyUID || prior.SourceSHA256 != r.SourceSHA256 {
			return voiceOutputJournal{}, errors.New("Voice output protected history differs")
		}
		next, e := voiceoutputpolicy.Append(prior, r.MarkerSHA256, r.OperationID)
		if e != nil || next.SHA256() != r.DesiredRuleSHA256 {
			return voiceOutputJournal{}, errors.New("Voice output protected append differs")
		}
		prior = next
	}
	return j, nil
}

func voiceOutputSelectedReceipt(j voiceOutputJournal, before voiceOutputSnapshot, decision voiceMemoryDecision,
	event *attackStimulusEvidence, target corev1.Pod, markerSHA string) (voiceOutputJournalReceipt, voiceoutputpolicy.Rule, error) {
	if !decision.Selected || decision.Action != voiceOutputAction || decision.TickID == "" || decision.DecisionID == "" ||
		event == nil || event.EventUID == "" || len(j.Receipts) != int(before.Rule.Revision)+1 {
		return voiceOutputJournalReceipt{}, voiceoutputpolicy.Rule{}, errors.New("Voice output selected receipt absent")
	}
	for _, prior := range j.Receipts[:len(j.Receipts)-1] {
		if prior.Phase != "terminal-full" {
			return voiceOutputJournalReceipt{}, voiceoutputpolicy.Rule{}, errors.New("Voice output prior receipt pending")
		}
	}
	r := j.Receipts[len(j.Receipts)-1]
	if r.Phase != "terminal-full" || r.PolicyName != voiceAgencyPolicyName || r.PolicyUID != before.PolicyUID ||
		r.PolicyGeneration != before.PolicyGeneration || r.DeploymentUID != before.DeploymentUID ||
		r.TargetName != target.Name || r.TargetPodUID != string(target.UID) || r.EventName != event.EventName ||
		r.EventUID != event.EventUID || r.CreatorIdentity != before.EventCreator || r.TickID != decision.TickID ||
		r.SelectionDecisionID != decision.DecisionID || r.ConfigMapUID != before.ConfigMapUID ||
		r.MarkerSHA256 != markerSHA || r.SourceSHA256 != before.SourceSHA256 ||
		r.PriorRuleSHA256 != before.RuleSHA256 || r.PriorRevision != before.Rule.Revision ||
		r.DesiredRevision != before.Rule.Revision+1 ||
		r.OperationID != voiceOutputOperationID(before.PolicyUID, before.DeploymentUID, string(target.UID), event.EventUID, decision.TickID, decision.DecisionID) {
		return voiceOutputJournalReceipt{}, voiceoutputpolicy.Rule{}, errors.New("Voice output terminal receipt does not join exact selection")
	}
	want, e := voiceoutputpolicy.Append(before.Rule, markerSHA, r.OperationID)
	if e != nil || want.SHA256() != r.DesiredRuleSHA256 {
		return voiceOutputJournalReceipt{}, voiceoutputpolicy.Rule{}, errors.New("Voice output desired rule differs")
	}
	return r, want, nil
}

func (s *Server) waitVoiceOutputDecision(ctx context.Context, record *attackRecord, before voiceOutputSnapshot, eventUID string) (voiceMemoryDecision, error) {
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
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
		case <-timer.C:
			return observed, errors.New("Voice output exact brain decision absent")
		case <-ticker.C:
		}
	}
}

func (s *Server) waitVoiceOutputEffect(ctx context.Context, p voiceOutputProfile, before voiceOutputSnapshot,
	decision voiceMemoryDecision, event *attackStimulusEvidence, target corev1.Pod, markerSHA string) (voiceOutputSnapshot, voiceOutputJournalReceipt, error) {
	var empty voiceOutputJournalReceipt
	if decision.Action != voiceOutputAction || !decision.Selected {
		return voiceOutputSnapshot{}, empty, errors.New("brain selected another action")
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	for {
		kube, e := clientForContext("")
		if e == nil {
			cm, getErr := kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, voiceOutputJournalName, metav1.GetOptions{})
			if getErr == nil {
				j, readErr := voiceOutputJournalRead(cm)
				if readErr == nil {
					receipt, want, joinErr := voiceOutputSelectedReceipt(j, before, decision, event, target, markerSHA)
					if joinErr == nil {
						after, snapErr := s.voiceOutputSnapshot(ctx, p, markerSHA)
						if snapErr == nil && after.DeploymentUID == before.DeploymentUID && after.PolicyUID == before.PolicyUID &&
							after.PolicyGeneration == before.PolicyGeneration && after.ConfigMapUID == before.ConfigMapUID &&
							after.RuleSHA256 == want.SHA256() && after.Rule.Revision == want.Revision &&
							voiceOutputSnapshotHasPod(after, target.Name, string(target.UID)) {
							return after, receipt, nil
						}
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return voiceOutputSnapshot{}, empty, ctx.Err()
		case <-timer.C:
			return voiceOutputSnapshot{}, empty, fmt.Errorf("Voice output protected effect or all-Pod state unavailable")
		case <-ticker.C:
		}
	}
}
