package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type voiceMCPDecision struct {
	voiceMemoryDecision
	NoopReason      string `json:"noopReason,omitempty"`
	ActionExclusion string `json:"actionExclusion,omitempty"`
}

func voiceMCPBoundedDiagnostic(value string) string {
	if len(value) > 240 {
		return value[:240]
	}
	return value
}

func voiceMCPMatchedAudit(row audit.Record, record *attackRecord, before voiceMCPSnapshot, eventUID string) bool {
	trace := row.DecisionTrace
	if row.Kind != "phorvex.decision" || row.Namespace != "voice" || row.Pod != record.Pod ||
		row.Time.Before(record.started) || trace == nil || trace.Validate() != nil || trace.DecisionID == "" || trace.TickID == "" ||
		trace.AssetNamespace != "voice" || trace.AssetName != record.Pod || trace.AssetUID != record.TargetUID ||
		trace.PolicyNamespace != "voice" || trace.PolicyName != voiceMCPPolicyName || trace.PolicyUID != before.PolicyUID ||
		trace.SelectedAction != row.Action {
		return false
	}
	trusted, matched := 0, false
	for _, event := range row.Events {
		if event.TrustVerdict == "trusted" && event.Weight > 0 {
			trusted++
			matched = matched || event.EventUID == eventUID && event.TargetPodUID == record.TargetUID
		}
	}
	return trusted == 1 && matched
}

func (s *Server) waitVoiceMCPDecision(ctx context.Context, record *attackRecord, before voiceMCPSnapshot, eventUID string) (voiceMCPDecision, error) {
	var noop voiceMCPDecision
	timer := time.NewTimer(90 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		rows, err := s.readDecisionWindow(ctx, "")
		if err == nil {
			for _, row := range rows {
				if !voiceMCPMatchedAudit(row, record, before, eventUID) {
					continue
				}
				trace := row.DecisionTrace
				if row.Selected {
					return voiceMCPDecision{voiceMemoryDecision: voiceMemoryDecision{Action: row.Action, DecisionID: trace.DecisionID,
						TickID: trace.TickID, SelectedAt: row.Time, Selected: true, Actuated: row.Actuated &&
							row.DispatchOutcome == model.DispatchEmitted && trace.DispatchOutcome == model.DispatchEmitted}}, nil
				}
				if row.Action == "noop" {
					candidate := voiceMCPDecision{voiceMemoryDecision: voiceMemoryDecision{Action: row.Action, DecisionID: trace.DecisionID,
						TickID: trace.TickID, SelectedAt: row.Time}, NoopReason: voiceMCPBoundedDiagnostic(trace.NoopReason)}
					for _, status := range trace.ActionStatus {
						if status.Action == voiceMCPAction {
							candidate.ActionExclusion = voiceMCPBoundedDiagnostic(status.Status + ":" + status.ExclusionKind + ":" + status.Reason)
						}
					}
					if noop.TickID == "" || row.Time.After(noop.SelectedAt) {
						noop = candidate
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return noop, ctx.Err()
		case <-timer.C:
			if noop.TickID != "" {
				return noop, errors.New("exact event-bound NOOP; no MCP pin selected")
			}
			return noop, errors.New("exact MCP brain decision unavailable")
		case <-ticker.C:
		}
	}
}

type voiceMCPJournalReceipt struct {
	Version                  int          `json:"version"`
	Phase                    string       `json:"phase"`
	PolicyName               string       `json:"policyName"`
	PolicyUID                string       `json:"policyUID"`
	PolicyGeneration         int64        `json:"policyGeneration"`
	DeploymentUID            string       `json:"deploymentUID"`
	TargetName               string       `json:"targetName"`
	TargetPodUID             string       `json:"targetPodUID"`
	EventName                string       `json:"eventName"`
	EventUID                 string       `json:"eventUID"`
	RunSHA256                string       `json:"runSHA256"`
	CreatorIdentity          string       `json:"creatorIdentity"`
	TickID                   string       `json:"tickId"`
	SelectionDecisionID      string       `json:"selectionDecisionId"`
	ConfigMapUID             string       `json:"configMapUID"`
	SourceConfigMapUID       string       `json:"sourceConfigMapUID"`
	MCPServiceName           string       `json:"mcpServiceName"`
	MCPServiceUID            string       `json:"mcpServiceUID"`
	MCPPodName               string       `json:"mcpPodName"`
	MCPPodUID                string       `json:"mcpPodUID"`
	MCPDeploymentUID         string       `json:"mcpDeploymentUID"`
	MCPConfigMapUID          string       `json:"mcpConfigMapUID"`
	MCPSourceSHA256          string       `json:"mcpSourceSHA256"`
	MCPApprovedImage         string       `json:"mcpApprovedImage"`
	ObservedDescriptorSHA256 string       `json:"observedDescriptorSHA256"`
	ToolName                 string       `json:"toolName"`
	Prior                    voiceMCPRule `json:"prior"`
	Desired                  voiceMCPRule `json:"desired"`
	OperationID              string       `json:"operationId"`
}

func voiceMCPJournalName(deploymentUID string, revision uint64) string {
	return "phorvex-voice-mcp-" + voiceMCPStringSHA(deploymentUID)[:32] + "-" + strconv.FormatUint(revision, 10)
}

func voiceMCPOperationID(before voiceMCPSnapshot, podUID, eventUID, runSHA, tickID, decisionID string) string {
	parts := []string{"phorvex-voice-mcp-v1", before.PolicyUID, before.DeploymentUID, podUID, eventUID, runSHA,
		"store_directory", before.MCPServiceUID, before.MCPPodUID, before.MCPDeploymentUID, before.MCPConfigMapUID,
		before.MCPSourceSHA256, tickID, decisionID}
	return voiceMCPStringSHA(strings.Join(parts, "\x00"))
}

func voiceMCPAppend(prior voiceMCPRule, operationID string) (voiceMCPRule, error) {
	if prior.Revision >= 2 || !staticSHA256.MatchString(operationID) {
		return voiceMCPRule{}, errors.New("MCP pin capacity unavailable")
	}
	for _, entry := range prior.Entries {
		if entry.ToolName == "store_directory" {
			return voiceMCPRule{}, errors.New("MCP tool already pinned")
		}
	}
	next := prior
	next.Revision++
	next.OperationID = operationID
	next.Entries = append(append([]voiceMCPEntry{}, prior.Entries...), voiceMCPEntry{ToolName: "store_directory", GoodDescriptorSHA256: voiceMCPGoodStoreSHA, OperationID: operationID})
	sort.Slice(next.Entries, func(i, j int) bool { return next.Entries[i].ToolName < next.Entries[j].ToolName })
	if _, err := parseVoiceMCPRule(string(next.bytes())); err != nil {
		return voiceMCPRule{}, err
	}
	return next, nil
}

func voiceMCPValidateJournal(cm *corev1.ConfigMap, before voiceMCPSnapshot, decision voiceMCPDecision, event *attackStimulusEvidence,
	target corev1.Pod, runSHA, observedSHA string) (voiceMCPJournalReceipt, error) {
	var receipt voiceMCPJournalReceipt
	if cm == nil || event == nil || !decision.Selected || decision.Action != voiceMCPAction || event.EventUID == "" ||
		cm.Name != voiceMCPJournalName(before.DeploymentUID, before.Rule.Revision+1) || cm.Namespace != "phorvex-system" ||
		cm.UID == "" ||
		cm.Labels["phorvex.ai/voice-mcp-journal"] != "v1" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return receipt, errors.New("MCP journal identity differs")
	}
	raw := cm.Data["receipt.json"]
	if len(raw) == 0 || len(raw) > 150000 {
		return receipt, errors.New("MCP journal bytes unavailable")
	}
	if rejectNATSNestedDuplicates([]byte(raw)) != nil {
		return receipt, errors.New("MCP journal has duplicate fields")
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&receipt) != nil || dec.Decode(new(any)) != io.EOF {
		return receipt, errors.New("MCP journal schema invalid")
	}
	var canonical any
	if json.Unmarshal([]byte(raw), &canonical) != nil {
		return receipt, errors.New("MCP journal JSON invalid")
	}
	canon, _ := json.Marshal(canonical)
	if !bytes.Equal(canon, []byte(raw)) {
		return receipt, errors.New("MCP journal noncanonical")
	}
	wantOp := voiceMCPOperationID(before, string(target.UID), event.EventUID, runSHA, decision.TickID, decision.DecisionID)
	wantRule, err := voiceMCPAppend(before.Rule, wantOp)
	if err != nil || receipt.Version != 1 || receipt.Phase != "terminal-full" || receipt.PolicyName != voiceMCPPolicyName ||
		receipt.PolicyUID != before.PolicyUID || receipt.PolicyGeneration != before.PolicyGeneration ||
		receipt.DeploymentUID != before.DeploymentUID || receipt.TargetName != target.Name || receipt.TargetPodUID != string(target.UID) ||
		receipt.EventName != event.EventName || receipt.EventUID != event.EventUID || receipt.RunSHA256 != runSHA ||
		receipt.CreatorIdentity != before.EventCreator || receipt.TickID != decision.TickID || receipt.SelectionDecisionID != decision.DecisionID ||
		receipt.ConfigMapUID != before.ConfigMapUID || receipt.SourceConfigMapUID != before.SourceConfigMapUID ||
		receipt.MCPServiceName != "mcp-server" || receipt.MCPServiceUID != before.MCPServiceUID ||
		receipt.MCPPodName != before.MCPPodName || receipt.MCPPodUID != before.MCPPodUID ||
		receipt.MCPDeploymentUID != before.MCPDeploymentUID || receipt.MCPConfigMapUID != before.MCPConfigMapUID ||
		receipt.MCPSourceSHA256 != before.MCPSourceSHA256 || receipt.MCPApprovedImage != before.MCPApprovedImage || receipt.ObservedDescriptorSHA256 != observedSHA ||
		receipt.ToolName != "store_directory" || receipt.OperationID != wantOp ||
		!bytes.Equal(receipt.Prior.bytes(), before.Rule.bytes()) || !bytes.Equal(receipt.Desired.bytes(), wantRule.bytes()) {
		return voiceMCPJournalReceipt{}, errors.New("MCP terminal journal does not join exact selection and source")
	}
	return receipt, nil
}

func (s *Server) waitVoiceMCPEffect(ctx context.Context, p voiceMCPProfile, before voiceMCPSnapshot, decision voiceMCPDecision,
	event *attackStimulusEvidence, target corev1.Pod, runSHA, observedSHA string) (voiceMCPSnapshot, voiceMCPJournalReceipt, error) {
	var empty voiceMCPJournalReceipt
	if !decision.Selected || decision.Action != voiceMCPAction {
		return voiceMCPSnapshot{}, empty, errors.New("brain selected another action")
	}
	kube, err := clientForContext("")
	if err != nil {
		return voiceMCPSnapshot{}, empty, err
	}
	timer := time.NewTimer(180 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		cm, e := kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, voiceMCPJournalName(before.DeploymentUID, before.Rule.Revision+1), metav1.GetOptions{})
		if e == nil {
			receipt, checkErr := voiceMCPValidateJournal(cm, before, decision, event, target, runSHA, observedSHA)
			if checkErr == nil {
				after, readErr := s.voiceMCPSnapshot(ctx, p)
				if readErr == nil && after.DeploymentUID == before.DeploymentUID && after.PolicyUID == before.PolicyUID &&
					after.PolicyGeneration == before.PolicyGeneration && after.ConfigMapUID == before.ConfigMapUID &&
					after.SourceConfigMapUID == before.SourceConfigMapUID && after.MCPDeploymentUID == before.MCPDeploymentUID &&
					after.MCPPodUID == before.MCPPodUID && after.MCPConfigMapUID == before.MCPConfigMapUID &&
					after.MCPServiceUID == before.MCPServiceUID && after.RuleSHA256 == receipt.Desired.sha() &&
					len(after.Pins) == len(before.Pins) {
					stable := true
					for i := range before.Pins {
						stable = stable && before.Pins[i] == after.Pins[i]
					}
					if stable {
						return after, receipt, nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return voiceMCPSnapshot{}, empty, ctx.Err()
		case <-timer.C:
			return voiceMCPSnapshot{}, empty, fmt.Errorf("MCP protected terminal journal and all serving Pod readbacks unavailable")
		case <-ticker.C:
		}
	}
}
