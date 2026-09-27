package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/endpointlease"
)

type endpointLeaseReceipt struct {
	Phase                   string   `json:"phase"`
	AbortReason             string   `json:"abortReason"`
	OperationID             string   `json:"operationID"`
	EventName               string   `json:"eventName"`
	EventUID                string   `json:"eventUID"`
	DecisionID              string   `json:"decisionID"`
	TickID                  string   `json:"tickID"`
	PolicyName              string   `json:"policyName"`
	PolicyUID               string   `json:"policyUID"`
	PolicyGeneration        int64    `json:"policyGeneration"`
	Namespace               string   `json:"namespace"`
	TargetPodName           string   `json:"targetPodName"`
	TargetPodUID            string   `json:"targetPodUID"`
	ServiceUID              string   `json:"serviceUID"`
	ProxySourceSHA256       string   `json:"proxySourceSHA256"`
	PolicyConfigMapUID      string   `json:"policyConfigMapUID"`
	SecretUID               string   `json:"secretUID"`
	SeedSHA256              string   `json:"seedSHA256"`
	OldRevision             uint64   `json:"oldRevision"`
	NewRevision             uint64   `json:"newRevision"`
	OldStateSHA256          string   `json:"oldStateSHA256"`
	NewStateSHA256          string   `json:"newStateSHA256"`
	RevokedClientHMAC       string   `json:"revokedClientHMAC"`
	RetainedClientHMAC      string   `json:"retainedClientHMAC"`
	PreCASPodUIDs           []string `json:"preCASPodUIDs"`
	PreCASProxyContainerIDs []string `json:"preCASProxyContainerIDs"`
}

type endpointLeaseJournal struct {
	Version  int                    `json:"version"`
	Receipts []endpointLeaseReceipt `json:"receipts"`
}

func endpointLeaseCanonical(v any) string {
	raw, _ := json.Marshal(v)
	var generic any
	_ = json.Unmarshal(raw, &generic)
	ordered, _ := json.Marshal(generic)
	return string(ordered)
}

func endpointLeaseReceiptMap(r endpointLeaseReceipt) map[string]any {
	return map[string]any{
		"phase": r.Phase, "abortReason": r.AbortReason, "operationID": r.OperationID, "eventName": r.EventName, "eventUID": r.EventUID,
		"decisionID": r.DecisionID, "tickID": r.TickID, "policyName": r.PolicyName, "policyUID": r.PolicyUID, "policyGeneration": r.PolicyGeneration,
		"namespace": r.Namespace, "targetPodName": r.TargetPodName, "targetPodUID": r.TargetPodUID, "serviceUID": r.ServiceUID,
		"proxySourceSHA256": r.ProxySourceSHA256, "policyConfigMapUID": r.PolicyConfigMapUID, "secretUID": r.SecretUID, "seedSHA256": r.SeedSHA256,
		"oldRevision": r.OldRevision, "newRevision": r.NewRevision, "oldStateSHA256": r.OldStateSHA256, "newStateSHA256": r.NewStateSHA256,
		"revokedClientHMAC": r.RevokedClientHMAC, "retainedClientHMAC": r.RetainedClientHMAC, "preCASPodUIDs": r.PreCASPodUIDs,
		"preCASProxyContainerIDs": r.PreCASProxyContainerIDs,
	}
}

func endpointLeaseJournalRaw(doc endpointLeaseJournal) string {
	rows := make([]map[string]any, 0, len(doc.Receipts))
	for _, r := range doc.Receipts {
		rows = append(rows, endpointLeaseReceiptMap(r))
	}
	return endpointLeaseCanonical(map[string]any{"version": doc.Version, "receipts": rows})
}

func endpointLeaseValidateReceipt(r endpointLeaseReceipt) error {
	if (r.Phase != "prepared" && r.Phase != "terminal-full" && r.Phase != "aborted") ||
		(r.Phase != "aborted" && r.AbortReason != "") ||
		(r.Phase == "aborted" && r.AbortReason != "pre-cas-authority-changed" && r.AbortReason != "definitive-policy-conflict") ||
		!endpointlease.ValidOperationID(r.OperationID) || r.DecisionID != r.OperationID || r.TickID == "" || len(r.TickID) > 128 ||
		r.EventName == "" || !endpointlease.ValidUID(r.EventUID) || r.PolicyName == "" || !endpointlease.ValidUID(r.PolicyUID) || r.PolicyGeneration < 1 ||
		r.Namespace != endpointlease.Namespace || r.TargetPodName == "" || !endpointlease.ValidUID(r.TargetPodUID) ||
		!endpointlease.ValidUID(r.ServiceUID) || !endpointlease.ValidSHA(r.ProxySourceSHA256) || !endpointlease.ValidUID(r.PolicyConfigMapUID) ||
		!endpointlease.ValidUID(r.SecretUID) || !endpointlease.ValidSHA(r.SeedSHA256) || r.OldRevision >= endpointlease.MaxRevision ||
		r.NewRevision != r.OldRevision+1 || !endpointlease.ValidSHA(r.OldStateSHA256) || !endpointlease.ValidSHA(r.NewStateSHA256) ||
		!endpointlease.ValidSHA(r.RevokedClientHMAC) || !endpointlease.ValidSHA(r.RetainedClientHMAC) || r.RevokedClientHMAC == r.RetainedClientHMAC ||
		len(r.PreCASPodUIDs) == 0 || len(r.PreCASPodUIDs) > 16 || len(r.PreCASPodUIDs) != len(r.PreCASProxyContainerIDs) {
		return errors.New("endpoint lease protected receipt invalid")
	}
	previous := ""
	targetFound := false
	for i, uid := range r.PreCASPodUIDs {
		if !endpointlease.ValidUID(uid) || uid <= previous {
			return errors.New("endpoint lease pre-CAS Pod order invalid")
		}
		if r.PreCASProxyContainerIDs[i] == "" || len(r.PreCASProxyContainerIDs[i]) > 256 {
			return errors.New("endpoint lease pre-CAS proxy incarnation invalid")
		}
		if uid == r.TargetPodUID {
			targetFound = true
		}
		previous = uid
	}
	if !targetFound {
		return errors.New("endpoint lease target absent from pre-CAS Pod set")
	}
	if r.OldRevision == 0 {
		allowed := []string{r.RevokedClientHMAC, r.RetainedClientHMAC}
		sort.Strings(allowed)
		initial := endpointlease.State{Version: 1, Revision: 0, ServiceUID: r.ServiceUID, ProxySourceSHA256: r.ProxySourceSHA256,
			SecretUID: r.SecretUID, SeedSHA256: r.SeedSHA256, AllowedClientHMACs: allowed, RevokedClientHMACs: []string{}, LastOperationID: ""}
		encoded, err := endpointlease.EncodeState(initial)
		if err != nil || endpointlease.SHA256([]byte(encoded)) != r.OldStateSHA256 {
			return errors.New("endpoint lease first receipt does not bind initial A/B policy")
		}
		next, nextErr := initial.Revoke(r.RevokedClientHMAC, r.RetainedClientHMAC, r.OperationID)
		nextRaw, encodeErr := endpointlease.EncodeState(next)
		if nextErr != nil || encodeErr != nil || endpointlease.SHA256([]byte(nextRaw)) != r.NewStateSHA256 {
			return errors.New("endpoint lease first receipt does not bind exact cutover state")
		}
	}
	return nil
}

func endpointLeaseReadJournal(cm *corev1.ConfigMap) (endpointLeaseJournal, error) {
	var doc endpointLeaseJournal
	if cm == nil || cm.Namespace == "" || cm.Name != endpointlease.JournalName || cm.UID == "" || cm.ResourceVersion == "" ||
		cm.Labels[endpointlease.JournalLabel] != "v1" || len(cm.Data) != 1 || len(cm.BinaryData) != 0 {
		return doc, errors.New("endpoint lease protected journal identity or keyset invalid")
	}
	raw := cm.Data[endpointlease.JournalKey]
	if len(raw) == 0 || len(raw) > 256<<10 || json.Unmarshal([]byte(raw), &doc) != nil || doc.Version != 1 || doc.Receipts == nil || len(doc.Receipts) > 256 ||
		raw != endpointLeaseJournalRaw(doc) {
		return endpointLeaseJournal{}, errors.New("endpoint lease protected journal noncanonical or unbounded")
	}
	operations := map[string]bool{}
	events := map[string]bool{}
	prepared := 0
	lineageRevision := uint64(0)
	lineageHash := ""
	for _, r := range doc.Receipts {
		if err := endpointLeaseValidateReceipt(r); err != nil {
			return endpointLeaseJournal{}, err
		}
		if operations[r.OperationID] || events[r.EventUID] {
			return endpointLeaseJournal{}, errors.New("endpoint lease protected operation or event replay")
		}
		operations[r.OperationID] = true
		events[r.EventUID] = true
		if r.OldRevision != lineageRevision || lineageHash != "" && r.OldStateSHA256 != lineageHash {
			return endpointLeaseJournal{}, errors.New("endpoint lease protected history lineage discontinuity")
		}
		if r.Phase == "prepared" {
			prepared++
		}
		if r.Phase == "terminal-full" {
			lineageRevision, lineageHash = r.NewRevision, r.NewStateSHA256
		}
	}
	if prepared > 1 {
		return endpointLeaseJournal{}, errors.New("endpoint lease concurrent prepared operations")
	}
	return doc, nil
}

func (j endpointLeaseJournal) index(op string) int {
	for i, r := range j.Receipts {
		if r.OperationID == op {
			return i
		}
	}
	return -1
}
func (j endpointLeaseJournal) pending() bool {
	for _, r := range j.Receipts {
		if r.Phase == "prepared" {
			return true
		}
	}
	return false
}
func (j endpointLeaseJournal) matchesState(live endpointlease.Live) bool {
	if j.pending() {
		return false
	}
	lastRevision := uint64(0)
	lastHash := ""
	for _, r := range j.Receipts {
		if r.Phase == "terminal-full" {
			lastRevision = r.NewRevision
			lastHash = r.NewStateSHA256
		}
	}
	if lastHash == "" {
		if live.State.Revision != 0 {
			return false
		}
		for _, r := range j.Receipts {
			if r.Phase == "aborted" && r.OldStateSHA256 != live.StateSHA256 {
				return false
			}
		}
		return true
	}
	return live.State.Revision == lastRevision && live.StateSHA256 == lastHash
}
func (j endpointLeaseJournal) append(r endpointLeaseReceipt) (endpointLeaseJournal, error) {
	if err := endpointLeaseValidateReceipt(r); err != nil {
		return endpointLeaseJournal{}, err
	}
	if j.pending() || len(j.Receipts) >= 256 || j.index(r.OperationID) >= 0 {
		return endpointLeaseJournal{}, errors.New("endpoint lease prior protected operation unresolved")
	}
	for _, old := range j.Receipts {
		if old.EventUID == r.EventUID || old.RevokedClientHMAC == r.RevokedClientHMAC {
			return endpointLeaseJournal{}, errors.New("endpoint lease event or client replay")
		}
	}
	next := endpointLeaseJournal{Version: 1, Receipts: append(append([]endpointLeaseReceipt(nil), j.Receipts...), r)}
	if len(endpointLeaseJournalRaw(next)) > 256<<10 {
		return endpointLeaseJournal{}, errors.New("endpoint lease protected journal byte bound")
	}
	return next, nil
}

// PendingEndpointLeaseOperation fences an unresolved operation on the exact old
// proxy Pod set. Other namespaces and Pods remain eligible for unrelated work.
func PendingEndpointLeaseOperation(ctx context.Context, reader client.Reader, operatorNamespace, namespace, podUID string) (bool, error) {
	if namespace != endpointlease.Namespace || podUID == "" {
		return false, nil
	}
	if reader == nil || operatorNamespace == "" {
		return true, errors.New("endpoint lease journal authority unavailable")
	}
	inScope, scopeErr := endpointLeasePossiblyTarget(ctx, reader, podUID)
	if scopeErr != nil {
		return true, scopeErr
	}
	if !inScope {
		return false, nil
	}
	cm := &corev1.ConfigMap{}
	err := reader.Get(ctx, client.ObjectKey{Namespace: operatorNamespace, Name: endpointlease.JournalName}, cm)
	if apierrors.IsNotFound(err) {
		policy := &corev1.ConfigMap{}
		policyErr := reader.Get(ctx, client.ObjectKey{Namespace: endpointlease.Namespace, Name: endpointlease.PolicyConfigMapName}, policy)
		if apierrors.IsNotFound(policyErr) {
			return false, nil
		}
		if policyErr != nil {
			return true, policyErr
		}
		return true, errors.New("endpoint lease protected journal absent with installed durable policy")
	}
	if err != nil {
		return true, err
	}
	doc, err := endpointLeaseReadJournal(cm)
	if err != nil {
		return true, err
	}
	for _, r := range doc.Receipts {
		if r.Phase == "prepared" {
			for _, uid := range r.PreCASPodUIDs {
				if uid == podUID {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// A malformed or missing lease journal must fence serving Pods, without
// globally blocking an unrelated Pod that happens to share namespace vllm.
func endpointLeasePossiblyTarget(ctx context.Context, reader client.Reader, podUID string) (bool, error) {
	pods := &corev1.PodList{}
	if err := reader.List(ctx, pods, client.InNamespace(endpointlease.Namespace), client.Limit(129)); err != nil {
		return true, err
	}
	if pods.Continue != "" || len(pods.Items) > 128 {
		return true, errors.New("endpoint lease fence Pod inventory incomplete")
	}
	var selected *corev1.Pod
	for i := range pods.Items {
		if string(pods.Items[i].UID) == podUID {
			selected = &pods.Items[i]
			break
		}
	}
	if selected == nil {
		return true, errors.New("endpoint lease fence exact Pod UID unavailable")
	}
	svc := &corev1.Service{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: endpointlease.Namespace, Name: endpointlease.ServiceName}, svc); err != nil {
		return true, err
	}
	matches := len(svc.Spec.Selector) > 0
	for k, v := range svc.Spec.Selector {
		actual, ok := selected.Labels[k]
		if !ok || actual != v {
			matches = false
			break
		}
	}
	if matches {
		return true, nil
	}
	owner := metav1.GetControllerOf(selected)
	if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
		return false, nil
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: endpointlease.Namespace, Name: owner.Name}, rs); err != nil {
		return true, err
	}
	if rs.UID != owner.UID {
		return true, errors.New("endpoint lease fence ReplicaSet UID differs")
	}
	parent := metav1.GetControllerOf(rs)
	return parent != nil && parent.Kind == "Deployment" && parent.APIVersion == "apps/v1" && parent.Name == endpointlease.ServiceName, nil
}

func endpointLeaseProtectedJournal(ctx context.Context, reader client.Reader, ns string) (*corev1.ConfigMap, endpointLeaseJournal, error) {
	cm := &corev1.ConfigMap{}
	if reader == nil || ns == "" {
		return nil, endpointLeaseJournal{}, errors.New("endpoint lease protected journal reader unavailable")
	}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: ns, Name: endpointlease.JournalName}, cm); err != nil {
		return nil, endpointLeaseJournal{}, err
	}
	doc, err := endpointLeaseReadJournal(cm)
	if err != nil {
		return nil, endpointLeaseJournal{}, fmt.Errorf("protected journal: %w", err)
	}
	return cm, doc, nil
}

func endpointLeasePreCASUIDs(pods []endpointlease.Pod) []string {
	result := make([]string, 0, len(pods))
	for _, p := range pods {
		result = append(result, p.UID)
	}
	sort.Strings(result)
	return result
}
func endpointLeasePreCASContainerIDs(pods []endpointlease.Pod) []string {
	copyPods := append([]endpointlease.Pod(nil), pods...)
	sort.Slice(copyPods, func(i, j int) bool { return copyPods[i].UID < copyPods[j].UID })
	result := make([]string, 0, len(copyPods))
	for _, p := range copyPods {
		result = append(result, p.ProxyContainerID)
	}
	return result
}
