package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/litellmclient"
)

type litellmRevokeJournal struct {
	Version  int                    `json:"version"`
	Receipts []litellmRevokeReceipt `json:"receipts"`
}

// PendingLiteLLMClientOperation fences both Pod lifetimes bound to an unresolved
// prepared revoke. Other namespaces and unrelated Pod UIDs remain dispatchable.
// A malformed protected journal fails closed for the LiteLLM namespace only.
func PendingLiteLLMClientOperation(ctx context.Context, reader client.Reader, operatorNamespace, namespace, podUID string) (bool, error) {
	if namespace != litellmclient.Namespace || podUID == "" {
		return false, nil
	}
	if reader == nil || operatorNamespace == "" {
		return true, errors.New("owned-client pending journal authority unavailable")
	}
	cm := &corev1.ConfigMap{}
	e := reader.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: litellmclient.JournalName}, cm)
	if apierrors.IsNotFound(e) {
		// An absent journal is normal only before the source fixture exists.
		// Once the gateway source is installed, absence cannot prove that no
		// prepared operation was lost with the protected journal.
		for _, sha := range []string{litellmclient.ApprovedSourceSHA256, litellmclient.MetricsSourceSHA256} {
			source := &corev1.ConfigMap{}
			sourceErr := reader.Get(ctx, client.ObjectKey{Namespace: litellmclient.Namespace, Name: litellmclient.ApprovedSourceConfigMap(sha)}, source)
			if apierrors.IsNotFound(sourceErr) {
				continue
			}
			if sourceErr != nil {
				return true, sourceErr
			}
			return true, errors.New("owned-client protected journal absent with installed gateway source")
		}
		return false, nil
	}
	if e != nil {
		return true, e
	}
	doc, e := litellmReadJournal(cm)
	if e != nil {
		return true, e
	}
	for _, receipt := range doc.Receipts {
		if receipt.Phase == "prepared" && (receipt.TargetUID == podUID || receipt.PeerUID == podUID) {
			return true, nil
		}
	}
	return false, nil
}

func litellmReceiptMap(r litellmRevokeReceipt) map[string]any {
	return map[string]any{
		"version": r.Version, "phase": r.Phase, "abortReason": r.AbortReason,
		"policyName": r.PolicyName, "policyUID": r.PolicyUID,
		"policyGeneration": r.PolicyGeneration, "targetUID": r.TargetUID, "peerUID": r.PeerUID,
		"eventName": r.EventName, "eventUID": r.EventUID, "clientSHA256": r.ClientSHA256,
		"configMapUID": r.ConfigMapUID, "clientsConfigMapUID": r.ClientsConfigMapUID,
		"seedSHA256": r.SeedSHA256, "serviceUID": r.ServiceUID, "sourceSHA256": r.SourceSHA256,
		"operationId": r.OperationID, "selectionDecisionId": r.SelectionDecisionID, "tickId": r.TickID,
	}
}

func litellmJournalRaw(j litellmRevokeJournal) string {
	rows := make([]map[string]any, 0, len(j.Receipts))
	for _, receipt := range j.Receipts {
		rows = append(rows, litellmReceiptMap(receipt))
	}
	raw, _ := json.Marshal(map[string]any{"version": j.Version, "receipts": rows})
	return string(raw)
}

func litellmValidateReceipt(r litellmRevokeReceipt) error {
	if r.Version != 2 || (r.Phase != "prepared" && r.Phase != "terminal-full" && r.Phase != "aborted") ||
		(r.Phase != "aborted" && r.AbortReason != "") ||
		(r.Phase == "aborted" && r.AbortReason != "pre-cas-authority-changed" && r.AbortReason != "definitive-policy-conflict") ||
		!litellmclient.ValidSHA(r.ClientSHA256) || !litellmclient.ValidSHA(r.SeedSHA256) ||
		!litellmclient.ApprovedSource(r.SourceSHA256) || r.PolicyName == "" || r.PolicyUID == "" ||
		r.PolicyGeneration < 1 || r.TargetUID == "" || r.PeerUID == "" || r.TargetUID == r.PeerUID ||
		r.ConfigMapUID == "" || r.ClientsConfigMapUID == "" || r.ServiceUID == "" ||
		r.OperationID == "" || len(r.OperationID) > 128 || r.SelectionDecisionID != r.OperationID ||
		r.EventName == "" || r.EventUID == "" || r.TickID == "" {
		return errors.New("owned-client journal receipt invalid")
	}
	return nil
}

func litellmReadJournal(cm *corev1.ConfigMap) (litellmRevokeJournal, error) {
	var j litellmRevokeJournal
	if cm == nil || cm.Name != litellmclient.JournalName ||
		len(cm.Data) != 1 || len(cm.BinaryData) != 0 ||
		cm.Labels[litellmclient.JournalLabel] != "v2" {
		return j, errors.New("owned-client protected journal identity or data keys differ")
	}
	raw := cm.Data[litellmclient.JournalKey]
	if len(raw) == 0 || len(raw) > 256<<10 || json.Unmarshal([]byte(raw), &j) != nil ||
		j.Version != 2 || j.Receipts == nil || len(j.Receipts) > 256 ||
		raw != litellmJournalRaw(j) {
		return litellmRevokeJournal{}, errors.New("owned-client protected journal noncanonical or exceeds bound")
	}
	prev := ""
	seenOperations := map[string]bool{}
	seenEvents := map[string]bool{}
	for _, receipt := range j.Receipts {
		if e := litellmValidateReceipt(receipt); e != nil {
			return litellmRevokeJournal{}, e
		}
		if receipt.ClientSHA256 <= prev || seenOperations[receipt.OperationID] || seenEvents[receipt.EventUID] {
			return litellmRevokeJournal{}, errors.New("owned-client protected journal order or unique operation differs")
		}
		prev = receipt.ClientSHA256
		seenOperations[receipt.OperationID] = true
		seenEvents[receipt.EventUID] = true
	}
	return j, nil
}

func (j litellmRevokeJournal) index(clientSHA string) int {
	for i, receipt := range j.Receipts {
		if receipt.ClientSHA256 == clientSHA {
			return i
		}
	}
	return -1
}

func (j litellmRevokeJournal) matchesPolicy(state litellmclient.State) bool {
	terminal := 0
	for _, receipt := range j.Receipts {
		entry, exists := state.Entry(receipt.ClientSHA256)
		if receipt.Phase == "aborted" {
			if exists {
				return false
			}
			continue
		}
		if receipt.Phase != "terminal-full" || !exists || !entry.Active || entry.OperationID != receipt.OperationID {
			return false
		}
		terminal++
	}
	return terminal == len(state.Entries)
}

func (j litellmRevokeJournal) append(r litellmRevokeReceipt) (litellmRevokeJournal, error) {
	if e := litellmValidateReceipt(r); e != nil {
		return litellmRevokeJournal{}, e
	}
	if len(j.Receipts) >= 256 || j.index(r.ClientSHA256) >= 0 {
		return litellmRevokeJournal{}, errors.New("owned-client protected journal capacity or repeated credential")
	}
	for _, prior := range j.Receipts {
		if prior.OperationID == r.OperationID || prior.EventUID == r.EventUID {
			return litellmRevokeJournal{}, errors.New("owned-client protected journal decision or event replay")
		}
	}
	next := litellmRevokeJournal{Version: 2, Receipts: append([]litellmRevokeReceipt(nil), j.Receipts...)}
	next.Receipts = append(next.Receipts, r)
	sort.Slice(next.Receipts, func(i, k int) bool { return next.Receipts[i].ClientSHA256 < next.Receipts[k].ClientSHA256 })
	if len(litellmJournalRaw(next)) > 256<<10 {
		return litellmRevokeJournal{}, errors.New("owned-client protected journal byte capacity")
	}
	return next, nil
}
