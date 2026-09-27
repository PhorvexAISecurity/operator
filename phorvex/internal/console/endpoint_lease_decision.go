package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type endpointLeaseDecision struct {
	Action, DecisionID, TickID string
	Selected, Actuated         bool
	NoopReason, Exclusion      string
}

func endpointLeaseBoundedDiagnostic(value string) string {
	if len(value) > 240 {
		return value[:240]
	}
	return value
}

func endpointLeaseMatchedAudit(row audit.Record, record *attackRecord, snap endpointLeaseSnapshot,
	eventUID, eventName, creator string) bool {
	trace := row.DecisionTrace
	if row.Kind != "phorvex.decision" || row.Namespace != "vllm" || row.Pod != record.Pod ||
		row.Time.Before(record.started) || trace == nil || trace.Validate() != nil || trace.DecisionID == "" || trace.TickID == "" ||
		trace.AssetNamespace != "vllm" || trace.AssetName != record.Pod || trace.AssetUID != record.TargetUID ||
		trace.PolicyNamespace != "vllm" || trace.PolicyName != "vllm-defense" || trace.PolicyUID != snap.PolicyUID ||
		trace.SelectedAction != row.Action {
		return false
	}
	trusted, matched := 0, false
	for _, event := range row.Events {
		if event.TrustVerdict == "trusted" && event.Weight > 0 {
			trusted++
			matched = matched || event.EventUID == eventUID && event.Name == eventName &&
				event.TargetPodUID == record.TargetUID && event.Type == endpointLeaseEventType &&
				event.Source == "redteam" && event.CreatorIdentity == creator && event.TargetsPod
		}
	}
	return trusted == 1 && matched
}

func (s *Server) waitEndpointLeaseDecision(ctx context.Context, record *attackRecord,
	snap endpointLeaseSnapshot, eventUID, eventName, creator string) (endpointLeaseDecision, error) {
	var noop endpointLeaseDecision
	timer := time.NewTimer(120 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		rows, err := s.readDecisionWindow(ctx, "")
		if err == nil {
			for _, row := range rows {
				if !endpointLeaseMatchedAudit(row, record, snap, eventUID, eventName, creator) {
					continue
				}
				trace := row.DecisionTrace
				if row.Selected {
					return endpointLeaseDecision{Action: row.Action, DecisionID: trace.DecisionID, TickID: trace.TickID,
						Selected: true, Actuated: row.Actuated && row.DispatchOutcome == model.DispatchEmitted &&
							trace.DispatchOutcome == model.DispatchEmitted}, nil
				}
				if row.Action == "noop" {
					candidate := endpointLeaseDecision{Action: "noop", DecisionID: trace.DecisionID,
						TickID: trace.TickID, NoopReason: endpointLeaseBoundedDiagnostic(trace.NoopReason)}
					for _, status := range trace.ActionStatus {
						if status.Action == endpointLeaseAction {
							candidate.Exclusion = endpointLeaseBoundedDiagnostic(status.Status + ":" + status.ExclusionKind + ":" + status.Reason)
						}
					}
					noop = candidate
				}
			}
		}
		select {
		case <-ctx.Done():
			return noop, ctx.Err()
		case <-timer.C:
			if noop.TickID != "" {
				return noop, errors.New("exact event-bound NOOP; no endpoint lease revocation selected")
			}
			return noop, errors.New("endpoint lease brain decision unavailable")
		case <-ticker.C:
		}
	}
}

type endpointLeaseJournalReceipt struct {
	AbortReason             string   `json:"abortReason"`
	DecisionID              string   `json:"decisionID"`
	EventName               string   `json:"eventName"`
	EventUID                string   `json:"eventUID"`
	Namespace               string   `json:"namespace"`
	NewRevision             uint64   `json:"newRevision"`
	NewStateSHA256          string   `json:"newStateSHA256"`
	OldRevision             uint64   `json:"oldRevision"`
	OldStateSHA256          string   `json:"oldStateSHA256"`
	OperationID             string   `json:"operationID"`
	Phase                   string   `json:"phase"`
	PolicyConfigMapUID      string   `json:"policyConfigMapUID"`
	PolicyGeneration        int64    `json:"policyGeneration"`
	PolicyName              string   `json:"policyName"`
	PolicyUID               string   `json:"policyUID"`
	PreCASPodUIDs           []string `json:"preCASPodUIDs"`
	PreCASProxyContainerIDs []string `json:"preCASProxyContainerIDs"`
	ProxySourceSHA256       string   `json:"proxySourceSHA256"`
	RetainedClientHMAC      string   `json:"retainedClientHMAC"`
	RevokedClientHMAC       string   `json:"revokedClientHMAC"`
	SecretUID               string   `json:"secretUID"`
	SeedSHA256              string   `json:"seedSHA256"`
	ServiceUID              string   `json:"serviceUID"`
	TargetPodName           string   `json:"targetPodName"`
	TargetPodUID            string   `json:"targetPodUID"`
	TickID                  string   `json:"tickID"`
}

type endpointLeaseJournal struct {
	Receipts []endpointLeaseJournalReceipt `json:"receipts"`
	Version  int                           `json:"version"`
}

func parseEndpointLeaseJournal(raw []byte) (endpointLeaseJournal, error) {
	var doc endpointLeaseJournal
	if endpointLeaseStrictJSON(raw, &doc, 256<<10) != nil || doc.Version != 1 ||
		doc.Receipts == nil || len(doc.Receipts) > 256 {
		return doc, errors.New("endpoint lease protected journal invalid")
	}
	for _, row := range doc.Receipts {
		if row.Phase != "terminal-full" && row.Phase != "aborted" && row.Phase != "prepared" {
			return doc, errors.New("endpoint lease journal phase invalid")
		}
	}
	return doc, nil
}

func endpointLeasePreflightJournal(doc endpointLeaseJournal, state endpointLeaseState) bool {
	for _, row := range doc.Receipts {
		if row.Phase == "prepared" {
			return false
		}
	}
	if state.Revision == 0 {
		for _, row := range doc.Receipts {
			if row.Phase != "aborted" {
				return false
			}
		}
	}
	return true
}

func endpointLeaseTerminalRow(after endpointLeaseJournal, before endpointLeaseJournal, snap endpointLeaseSnapshot,
	p endpointLeaseProfile, event *attackStimulusEvidence, decision endpointLeaseDecision,
	target corev1.Pod, desired endpointLeaseState) bool {
	if event == nil || !decision.Selected || decision.Action != endpointLeaseAction ||
		!endpointLeaseOperationID.MatchString(decision.DecisionID) || len(after.Receipts) != len(before.Receipts)+1 {
		return false
	}
	for i := range before.Receipts {
		a, _ := json.Marshal(after.Receipts[i])
		b, _ := json.Marshal(before.Receipts[i])
		if !bytes.Equal(a, b) {
			return false
		}
	}
	r := after.Receipts[len(after.Receipts)-1]
	preUIDs := make([]string, len(snap.Pods))
	preContainers := make([]string, len(snap.Pods))
	for i, pod := range snap.Pods {
		preUIDs[i] = string(pod.UID)
		preContainers[i] = endpointLeaseProxyContainerID(pod)
	}
	indices := make([]int, len(preUIDs))
	for i := range indices {
		indices[i] = i
	}
	sort.Slice(indices, func(i, j int) bool { return preUIDs[indices[i]] < preUIDs[indices[j]] })
	if len(r.PreCASPodUIDs) != len(preUIDs) || len(r.PreCASProxyContainerIDs) != len(preUIDs) {
		return false
	}
	for i, index := range indices {
		if preContainers[index] == "" || r.PreCASPodUIDs[i] != preUIDs[index] || r.PreCASProxyContainerIDs[i] != preContainers[index] {
			return false
		}
	}
	return r.Phase == "terminal-full" && r.AbortReason == "" && r.Namespace == "vllm" &&
		r.EventName == event.EventName && r.EventUID == event.EventUID &&
		r.DecisionID == decision.DecisionID && r.OperationID == decision.DecisionID && r.TickID == decision.TickID &&
		r.PolicyName == p.PolicyName && r.PolicyUID == p.PolicyUID && r.PolicyGeneration == p.PolicyGeneration &&
		r.TargetPodName == target.Name && r.TargetPodUID == string(target.UID) &&
		r.ServiceUID == p.ServiceUID && r.ProxySourceSHA256 == p.ProxySourceSHA256 &&
		r.PolicyConfigMapUID == p.PolicyConfigMapUID && r.SecretUID == p.TenantSecretUID && r.SeedSHA256 == p.SeedSHA256 &&
		r.RevokedClientHMAC == p.ClientAHMAC && r.RetainedClientHMAC == p.ClientBHMAC &&
		r.OldRevision == snap.State.Revision && r.NewRevision == desired.Revision &&
		r.OldStateSHA256 == snap.StateSHA256 && r.NewStateSHA256 == endpointLeaseSHA(endpointLeaseStateBytes(desired))
}

func (s *Server) waitEndpointLeaseEffect(ctx context.Context, kube kubernetes.Interface,
	p endpointLeaseProfile, before endpointLeaseSnapshot, prior endpointLeaseJournal,
	decision endpointLeaseDecision, event *attackStimulusEvidence, target corev1.Pod,
	tokens endpointLeaseTokens) (endpointLeaseSnapshot, error) {
	var empty endpointLeaseSnapshot
	desired, err := endpointLeaseDesired(before.State, p, decision.DecisionID)
	if err != nil {
		return empty, err
	}
	config, err := restConfigFor("")
	if err != nil {
		return empty, err
	}
	timer := time.NewTimer(240 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		journalCM, getErr := kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, endpointLeaseJournalCM, metav1.GetOptions{})
		if getErr == nil && string(journalCM.UID) == p.JournalUID && len(journalCM.Data) == 1 {
			doc, parseErr := parseEndpointLeaseJournal([]byte(journalCM.Data["receipts.json"]))
			if parseErr == nil && endpointLeaseTerminalRow(doc, prior, before, p, event, decision, target, desired) {
				after, snapErr := s.endpointLeaseSnapshot(ctx, kube, p, tokens)
				if snapErr == nil && after.ConfigMapUID == before.ConfigMapUID && after.ServiceUID == before.ServiceUID &&
					after.SecretUID == before.SecretUID && after.JournalUID == before.JournalUID &&
					endpointLeaseSameProxyIncarnations(before.Pods, after.Pods) &&
					bytes.Equal(endpointLeaseStateBytes(after.State), endpointLeaseStateBytes(desired)) {
					complete := true
					for _, pod := range after.Pods {
						status, statusErr := endpointLeaseAdminState(ctx, config, kube, pod, p)
						complete = complete && statusErr == nil && endpointLeaseStatusMatches(status, p, after, pod, true)
					}
					if complete {
						return after, nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return empty, ctx.Err()
		case <-timer.C:
			return empty, errors.New("endpoint lease exact protected terminal and every proxy readback unavailable")
		case <-ticker.C:
		}
	}
}
