package actuator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	RecoveryPlanVersion     = 1
	RecoveryContractVersion = "phorvex-recovery/v1"
	RecoveryOperation       = "quarantine-readmit"
	RecoveryHoldName        = "phorvex-killswitch"
	RecoveryMaxItems        = 100
	RecoveryPlanMaxBytes    = 1 << 20
	RecoveryJournalScanMax  = 1000
	recoveryJournalPageSize = 100
	recoveryMIGLabel        = "phorvex.ai/mig-recovery"
)

type RecoveryScope struct {
	OperatorNamespace string `json:"operatorNamespace"`
	Namespace         string `json:"namespace"`
	PolicyName        string `json:"policyName"`
	MaxItems          int    `json:"maxItems"`
}

type RecoveryInventory struct {
	Contract  string                  `json:"contract"`
	Cluster   ObjectBinding           `json:"cluster"`
	Operator  ObjectBinding           `json:"operatorNamespace"`
	Scope     RecoveryScope           `json:"scope"`
	Generated time.Time               `json:"generatedAt"`
	Items     []RecoveryInventoryItem `json:"items"`
}

type RecoveryInventoryItem struct {
	Receipt            ObjectBinding `json:"receipt"`
	ReceiptSHA256      string        `json:"receiptSHA256,omitempty"`
	Kind               string        `json:"kind,omitempty"`
	Phase              string        `json:"phase,omitempty"`
	PolicyNamespace    string        `json:"policyNamespace,omitempty"`
	PolicyName         string        `json:"policyName,omitempty"`
	PolicyUID          string        `json:"policyUID,omitempty"`
	TargetName         string        `json:"targetName,omitempty"`
	TargetUID          string        `json:"targetUID,omitempty"`
	Node               string        `json:"node,omitempty"`
	GPUUUID            string        `json:"gpuUUID,omitempty"`
	SupportedOperation string        `json:"supportedOperation,omitempty"`
	Status             string        `json:"status"`
	Reason             string        `json:"reason,omitempty"`
}

type ObjectBinding struct {
	APIVersion      string `json:"apiVersion"`
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
	SHA256          string `json:"sha256,omitempty"`
}

type RecoveryPlan struct {
	Version   int                `json:"version"`
	Contract  string             `json:"contract"`
	Operation string             `json:"operation"`
	Cluster   ObjectBinding      `json:"cluster"`
	Operator  ObjectBinding      `json:"operatorNamespace"`
	Scope     RecoveryScope      `json:"scope"`
	Created   time.Time          `json:"createdAt"`
	Items     []RecoveryPlanItem `json:"items"`
	SHA256    string             `json:"sha256"`
}

type RecoveryPlanItem struct {
	Receipt       ObjectBinding `json:"receipt"`
	ReceiptSHA256 string        `json:"receiptSHA256"`
	Policy        ObjectBinding `json:"policy"`
	Pod           ObjectBinding `json:"pod"`
	NetworkPolicy ObjectBinding `json:"networkPolicy"`
	RollbackRef   string        `json:"rollbackRef"`
	TargetLabels  string        `json:"targetLabelsSHA256"`
	OwnerRefs     string        `json:"ownerRefsSHA256"`
}

type RecoveryApplyResult struct {
	Contract string              `json:"contract"`
	PlanHash string              `json:"planSHA256"`
	State    string              `json:"state"`
	Hold     ObjectBinding       `json:"hold"`
	Items    []RecoveryApplyItem `json:"items"`
	Complete bool                `json:"complete"`
}

type RecoveryApplyItem struct {
	Receipt   string `json:"receipt"`
	Namespace string `json:"namespace"`
	Target    string `json:"target"`
	TargetUID string `json:"targetUID"`
	Outcome   string `json:"outcome"`
	Reason    string `json:"reason,omitempty"`
}

func digestJSON(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func binding(obj client.Object, apiVersion, kind string) ObjectBinding {
	return ObjectBinding{APIVersion: apiVersion, Kind: kind, Namespace: obj.GetNamespace(), Name: obj.GetName(), UID: string(obj.GetUID()), ResourceVersion: obj.GetResourceVersion(), SHA256: digestJSON(obj)}
}

func recoveryIdentities(ctx context.Context, r client.Reader, operatorNS string) (ObjectBinding, ObjectBinding, error) {
	if r == nil || operatorNS == "" {
		return ObjectBinding{}, ObjectBinding{}, fmt.Errorf("authoritative reader and operator namespace are required")
	}
	cluster := &corev1.Namespace{}
	if err := r.Get(ctx, client.ObjectKey{Name: metav1.NamespaceSystem}, cluster); err != nil {
		return ObjectBinding{}, ObjectBinding{}, fmt.Errorf("read cluster identity: %w", err)
	}
	op := &corev1.Namespace{}
	if err := r.Get(ctx, client.ObjectKey{Name: operatorNS}, op); err != nil {
		return ObjectBinding{}, ObjectBinding{}, fmt.Errorf("read operator namespace identity: %w", err)
	}
	if cluster.UID == "" || cluster.ResourceVersion == "" || cluster.DeletionTimestamp != nil || op.UID == "" || op.ResourceVersion == "" || op.DeletionTimestamp != nil {
		return ObjectBinding{}, ObjectBinding{}, fmt.Errorf("cluster/operator namespace identity incomplete")
	}
	return binding(cluster, "v1", "Namespace"), binding(op, "v1", "Namespace"), nil
}

func validateRecoveryScope(s RecoveryScope) error {
	if s.OperatorNamespace == "" || s.Namespace == "" || s.PolicyName == "" || s.OperatorNamespace == s.Namespace {
		return fmt.Errorf("operator namespace and distinct target namespace/policy are required")
	}
	if s.MaxItems <= 0 || s.MaxItems > RecoveryMaxItems {
		return fmt.Errorf("maxItems must be between 1 and %d", RecoveryMaxItems)
	}
	return nil
}

func validateProtectedReceipt(cm *corev1.ConfigMap, operatorNS string) (operationReceipt, error) {
	var r operationReceipt
	if cm == nil || cm.Namespace != operatorNS || cm.Name == "" || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Labels[journalLabel] != "v1" {
		return r, fmt.Errorf("protected receipt metadata is invalid")
	}
	if err := json.Unmarshal([]byte(cm.Data["receipt"]), &r); err != nil || !r.valid() || cm.Name != receiptName(r) {
		return operationReceipt{}, fmt.Errorf("protected receipt body or canonical identity is invalid")
	}
	return r, nil
}

type recoveryMIGSummary struct {
	Version         int    `json:"version"`
	Phase           string `json:"phase"`
	PolicyNamespace string `json:"policyNamespace"`
	PolicyName      string `json:"policyName"`
	PolicyUID       string `json:"policyUID"`
	TargetName      string `json:"targetName"`
	TargetUID       string `json:"targetUID"`
	Node            string `json:"node"`
	GPUUUID         string `json:"gpuUUID"`
}

func (r recoveryMIGSummary) validSummary() bool {
	return (r.Version == 1 || r.Version == 2) && (r.Phase == "prepared" || r.Phase == "destructive" || r.Phase == "unresolved") && r.PolicyNamespace != "" && r.PolicyName != "" && r.PolicyUID != "" && r.TargetName != "" && r.TargetUID != "" && r.Node != "" && r.GPUUUID != ""
}

func recoveryMIGName(node, gpuUUID string) string {
	h := sha256.Sum256([]byte(node + "\x00" + gpuUUID))
	return fmt.Sprintf("phorvex-mig-recovery-%x", h[:20])
}

func (n *NativeActuator) listRecoveryLabel(ctx context.Context, operatorNS, label, value string) ([]corev1.ConfigMap, error) {
	items := make([]corev1.ConfigMap, 0)
	continueToken := ""
	seenTokens := map[string]bool{}
	for {
		var page corev1.ConfigMapList
		opts := []client.ListOption{client.InNamespace(operatorNS), client.MatchingLabels{label: value}, client.Limit(recoveryJournalPageSize)}
		if continueToken != "" {
			opts = append(opts, client.Continue(continueToken))
		}
		if err := n.Reader.List(ctx, &page, opts...); err != nil {
			return nil, fmt.Errorf("read protected journal: %w", err)
		}
		items = append(items, page.Items...)
		if len(items) > RecoveryJournalScanMax || (len(items) == RecoveryJournalScanMax && page.Continue != "") {
			return nil, fmt.Errorf("protected receipt collection for label %s exceeds fixed scan cap=%d", label, RecoveryJournalScanMax)
		}
		if page.Continue == "" {
			return items, nil
		}
		if page.Continue == continueToken || seenTokens[page.Continue] {
			return nil, fmt.Errorf("protected journal pagination did not advance")
		}
		seenTokens[page.Continue] = true
		continueToken = page.Continue
	}
}

// InventoryRecovery reads the protected journal and authoritative objects. It never writes.
func (n *NativeActuator) InventoryRecovery(ctx context.Context, scope RecoveryScope) (RecoveryInventory, error) {
	if err := validateRecoveryScope(scope); err != nil {
		return RecoveryInventory{}, err
	}
	cluster, operator, err := recoveryIdentities(ctx, n.Reader, scope.OperatorNamespace)
	if err != nil {
		return RecoveryInventory{}, err
	}
	journalCMs, err := n.listRecoveryLabel(ctx, scope.OperatorNamespace, journalLabel, "v1")
	if err != nil {
		return RecoveryInventory{}, err
	}
	migV1, err := n.listRecoveryLabel(ctx, scope.OperatorNamespace, recoveryMIGLabel, "v1")
	if err != nil {
		return RecoveryInventory{}, err
	}
	migV2, err := n.listRecoveryLabel(ctx, scope.OperatorNamespace, recoveryMIGLabel, "v2")
	if err != nil {
		return RecoveryInventory{}, err
	}
	migCMs := append(migV1, migV2...)
	if len(journalCMs)+len(migCMs) > RecoveryJournalScanMax {
		return RecoveryInventory{}, fmt.Errorf("combined protected receipt scan exceeds fixed cap=%d", RecoveryJournalScanMax)
	}
	type discovered struct {
		cm           corev1.ConfigMap
		journal, mig bool
	}
	byKey := map[string]discovered{}
	for _, source := range []struct {
		items   []corev1.ConfigMap
		journal bool
	}{{journalCMs, true}, {migCMs, false}} {
		for i := range source.items {
			cm := source.items[i]
			key := cm.Namespace + "/" + cm.Name
			d := byKey[key]
			if d.cm.Name == "" {
				d.cm = cm
			}
			if source.journal {
				d.journal = true
			} else {
				d.mig = true
			}
			byKey[key] = d
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	inv := RecoveryInventory{Contract: RecoveryContractVersion, Cluster: cluster, Operator: operator, Scope: scope, Generated: time.Now().UTC()}
	appendScoped := func(item RecoveryInventoryItem) error {
		inv.Items = append(inv.Items, item)
		if len(inv.Items) > scope.MaxItems {
			return fmt.Errorf("scoped inventory exceeds maxItems=%d", scope.MaxItems)
		}
		return nil
	}
	for _, key := range keys {
		d := byKey[key]
		cm := &d.cm
		raw := cm.Data["receipt"]
		item := RecoveryInventoryItem{Receipt: binding(cm, "v1", "ConfigMap"), ReceiptSHA256: digestJSON(raw), Status: "refused"}
		if d.journal && d.mig {
			item.Reason = "protected receipt has conflicting operation labels"
			if err := appendScoped(item); err != nil {
				return RecoveryInventory{}, err
			}
			continue
		}
		if d.mig {
			var summary recoveryMIGSummary
			if cm.Namespace != scope.OperatorNamespace || cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || (cm.Labels[recoveryMIGLabel] != "v1" && cm.Labels[recoveryMIGLabel] != "v2") || json.Unmarshal([]byte(raw), &summary) != nil || !summary.validSummary() || cm.Name != recoveryMIGName(summary.Node, summary.GPUUUID) {
				item.Reason = "malformed or identity-invalid protected MIG receipt"
				if err := appendScoped(item); err != nil {
					return RecoveryInventory{}, err
				}
				continue
			}
			if summary.PolicyNamespace != scope.Namespace || summary.PolicyName != scope.PolicyName {
				continue
			}
			item.Kind, item.Phase, item.PolicyNamespace, item.PolicyName, item.PolicyUID = "mig-rebind", summary.Phase, summary.PolicyNamespace, summary.PolicyName, summary.PolicyUID
			item.TargetName, item.TargetUID, item.Node, item.GPUUUID = summary.TargetName, summary.TargetUID, summary.Node, summary.GPUUUID
			item.Status, item.Reason = "manual", "MIG hardware recovery is unavailable through quarantine recovery; use operation-specific investigation"
			if err := appendScoped(item); err != nil {
				return RecoveryInventory{}, err
			}
			continue
		}
		receipt, receiptErr := validateProtectedReceipt(cm, scope.OperatorNamespace)
		if receiptErr != nil {
			item.Reason = "malformed or identity-invalid protected receipt"
			if err := appendScoped(item); err != nil {
				return RecoveryInventory{}, err
			}
			continue
		}
		if receipt.PolicyNamespace != scope.Namespace || receipt.PolicyName != scope.PolicyName {
			continue
		}
		item.Kind, item.Phase, item.PolicyNamespace, item.PolicyName, item.PolicyUID = receipt.Kind, receipt.Phase, receipt.PolicyNamespace, receipt.PolicyName, receipt.PolicyUID
		item.TargetName, item.TargetUID = receipt.TargetName, receipt.TargetUID
		if receipt.Kind != "quarantine" {
			item.Status, item.Reason = "manual", "forward recovery only; generic undo is unavailable"
		} else if receipt.Phase != "policy-bound" {
			item.Reason = "quarantine receipt is not policy-bound"
		} else if _, err := n.recoveryPlanItem(ctx, cm, receipt); err != nil {
			item.Reason = err.Error()
		} else {
			item.Status, item.SupportedOperation = "ready", RecoveryOperation
		}
		if err := appendScoped(item); err != nil {
			return RecoveryInventory{}, err
		}
	}
	return inv, nil
}

func (n *NativeActuator) recoveryPlanItem(ctx context.Context, cm *corev1.ConfigMap, r operationReceipt) (RecoveryPlanItem, error) {
	if _, err := receiptAuthority(ctx, n.Reader, r, model.ActionQuarantine); err != nil {
		return RecoveryPlanItem{}, err
	}
	pol := &v1alpha1.PhorvexPolicy{}
	if err := n.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.PolicyName}, pol); err != nil {
		return RecoveryPlanItem{}, err
	}
	pod := &corev1.Pod{}
	if err := n.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod); err != nil {
		return RecoveryPlanItem{}, err
	}
	if string(pod.UID) != r.TargetUID || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil {
		return RecoveryPlanItem{}, fmt.Errorf("target Pod UID/resourceVersion mismatch")
	}
	var snap qtnSnapshot
	if err := json.Unmarshal([]byte(pod.Annotations[quarantineSnapAnno]), &snap); err != nil || !validQuarantineSnapshot(pod, &snap) {
		return RecoveryPlanItem{}, fmt.Errorf("current quarantine snapshot invalid")
	}
	if snap.PolicyName != r.NPName || string(snap.PolicyUID) != r.NPUID {
		return RecoveryPlanItem{}, fmt.Errorf("snapshot/receipt NetworkPolicy identity mismatch")
	}
	np := &networkingv1.NetworkPolicy{}
	if err := n.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NPName}, np); err != nil {
		return RecoveryPlanItem{}, err
	}
	if string(np.UID) != r.NPUID || np.ResourceVersion == "" || np.DeletionTimestamp != nil {
		return RecoveryPlanItem{}, fmt.Errorf("NetworkPolicy UID/resourceVersion mismatch")
	}
	if _, err := recordedQuarantinePolicies(ctx, EnactCtx{Reader: n.Reader}, pod, &snap); err != nil {
		return RecoveryPlanItem{}, err
	}
	return RecoveryPlanItem{Receipt: binding(cm, "v1", "ConfigMap"), ReceiptSHA256: digestJSON(cm.Data["receipt"]), Policy: binding(pol, v1alpha1.GroupVersion.String(), "PhorvexPolicy"), Pod: binding(pod, "v1", "Pod"), NetworkPolicy: binding(np, "networking.k8s.io/v1", "NetworkPolicy"), RollbackRef: pod.Namespace + "/" + pod.Name + "@" + string(pod.UID), TargetLabels: digestJSON(r.TargetLabels), OwnerRefs: digestJSON(pod.OwnerReferences)}, nil
}

func (n *NativeActuator) PlanRecovery(ctx context.Context, scope RecoveryScope) (RecoveryPlan, error) {
	inv, err := n.InventoryRecovery(ctx, scope)
	if err != nil {
		return RecoveryPlan{}, err
	}
	plan := RecoveryPlan{Version: RecoveryPlanVersion, Contract: RecoveryContractVersion, Operation: RecoveryOperation, Cluster: inv.Cluster, Operator: inv.Operator, Scope: scope, Created: time.Now().UTC()}
	for _, item := range inv.Items {
		if item.Status != "ready" {
			continue
		}
		cm := &corev1.ConfigMap{}
		if err := n.Reader.Get(ctx, client.ObjectKey{Namespace: scope.OperatorNamespace, Name: item.Receipt.Name}, cm); err != nil {
			return RecoveryPlan{}, err
		}
		if !sameBinding(binding(cm, "v1", "ConfigMap"), item.Receipt) || digestJSON(cm.Data["receipt"]) != item.ReceiptSHA256 {
			return RecoveryPlan{}, fmt.Errorf("protected receipt changed after inventory")
		}
		r, err := validateProtectedReceipt(cm, scope.OperatorNamespace)
		if err != nil || r.PolicyNamespace != scope.Namespace || r.PolicyName != scope.PolicyName || r.Kind != "quarantine" || r.Phase != "policy-bound" {
			return RecoveryPlan{}, fmt.Errorf("protected receipt left selected recovery scope")
		}
		pi, err := n.recoveryPlanItem(ctx, cm, r)
		if err != nil {
			return RecoveryPlan{}, err
		}
		plan.Items = append(plan.Items, pi)
	}
	if len(plan.Items) == 0 {
		return RecoveryPlan{}, fmt.Errorf("no supported quarantine re-admissions in scope")
	}
	plan.SHA256 = recoveryPlanHash(plan)
	return plan, nil
}

func recoveryPlanHash(p RecoveryPlan) string { p.SHA256 = ""; return digestJSON(p) }

func sameBinding(a, b ObjectBinding) bool {
	return a.APIVersion == b.APIVersion && a.Kind == b.Kind && a.Namespace == b.Namespace && a.Name == b.Name && a.UID == b.UID && a.ResourceVersion == b.ResourceVersion && a.SHA256 == b.SHA256
}

func validatePlanStructure(plan RecoveryPlan) error {
	if plan.Version != RecoveryPlanVersion || plan.Contract != RecoveryContractVersion || plan.Operation != RecoveryOperation || recoveryPlanHash(plan) != plan.SHA256 || validateRecoveryScope(plan.Scope) != nil || len(plan.Items) == 0 || len(plan.Items) > plan.Scope.MaxItems {
		return fmt.Errorf("recovery plan is malformed, tampered, oversized, or incompatible")
	}
	seenReceipt, seenTarget := map[string]bool{}, map[string]bool{}
	for _, item := range plan.Items {
		if item.Receipt.APIVersion != "v1" || item.Receipt.Kind != "ConfigMap" || item.Receipt.Namespace != plan.Scope.OperatorNamespace || item.Receipt.Name == "" || item.Receipt.UID == "" || item.Receipt.ResourceVersion == "" || item.Receipt.SHA256 == "" || item.ReceiptSHA256 == "" ||
			item.Policy.Namespace != plan.Scope.Namespace || item.Policy.Name != plan.Scope.PolicyName || item.Policy.UID == "" || item.Pod.Namespace != plan.Scope.Namespace || item.Pod.Name == "" || item.Pod.UID == "" || item.NetworkPolicy.Namespace != plan.Scope.Namespace || item.NetworkPolicy.Name == "" || item.NetworkPolicy.UID == "" || item.RollbackRef != item.Pod.Namespace+"/"+item.Pod.Name+"@"+item.Pod.UID {
			return fmt.Errorf("recovery plan item has invalid protected scope or identity")
		}
		if seenReceipt[item.Receipt.Name] || seenTarget[item.Pod.Namespace+"/"+item.Pod.Name+"@"+item.Pod.UID] {
			return fmt.Errorf("recovery plan contains duplicate receipt or target")
		}
		seenReceipt[item.Receipt.Name], seenTarget[item.Pod.Namespace+"/"+item.Pod.Name+"@"+item.Pod.UID] = true, true
	}
	return nil
}

func (n *NativeActuator) requireRecoveryHold(ctx context.Context, operatorNS string) (ObjectBinding, error) {
	cm := &corev1.ConfigMap{}
	if err := n.Reader.Get(ctx, client.ObjectKey{Namespace: operatorNS, Name: RecoveryHoldName}, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return ObjectBinding{}, fmt.Errorf("administrative actuation hold is absent")
		}
		return ObjectBinding{}, fmt.Errorf("administrative actuation hold read failed: %w", err)
	}
	if cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil {
		return ObjectBinding{}, fmt.Errorf("administrative actuation hold identity incomplete")
	}
	switch cm.Data["engaged"] {
	case "true", "True", "1", "yes":
	default:
		return ObjectBinding{}, fmt.Errorf("administrative actuation hold is not engaged")
	}
	return binding(cm, "v1", "ConfigMap"), nil
}

// ApplyRecovery revalidates the reviewed plan before each write and stops at the first failure.
func (n *NativeActuator) ApplyRecovery(ctx context.Context, plan RecoveryPlan) (RecoveryApplyResult, error) {
	return n.ApplyRecoveryWithRecorder(ctx, plan, nil)
}

// ApplyRecoveryWithRecorder durably exposes intent/progress when record is non-nil.
func (n *NativeActuator) ApplyRecoveryWithRecorder(ctx context.Context, plan RecoveryPlan, record func(RecoveryApplyResult) error) (RecoveryApplyResult, error) {
	result := RecoveryApplyResult{Contract: RecoveryContractVersion, PlanHash: plan.SHA256, State: "refused"}
	if err := validatePlanStructure(plan); err != nil {
		return result, err
	}
	cluster, operator, err := recoveryIdentities(ctx, n.Reader, plan.Scope.OperatorNamespace)
	if err != nil {
		return result, fmt.Errorf("recovery plan cluster/operator identity: %w", err)
	}
	if !sameBinding(cluster, plan.Cluster) || !sameBinding(operator, plan.Operator) {
		return result, fmt.Errorf("recovery plan cluster/operator identity is stale or mismatched")
	}
	if n.JournalNamespace != plan.Scope.OperatorNamespace {
		return result, fmt.Errorf("native actuator journal namespace does not match plan")
	}
	if n.DryRun {
		return result, errDryRunGuard
	}
	hold, err := n.requireRecoveryHold(ctx, plan.Scope.OperatorNamespace)
	if err != nil {
		return result, err
	}
	result.Hold = hold
	result.State = "applying"
	if record != nil {
		if err := record(result); err != nil {
			result.State = "result-write-failed-before-effects"
			return result, fmt.Errorf("persist recovery intent before effects: %w", err)
		}
	}
	persistProgress := func() error {
		if record == nil {
			return nil
		}
		if err := record(result); err != nil {
			result.State = "result-write-failed-after-possible-effects"
			return fmt.Errorf("persist recovery progress after possible effects: %w", err)
		}
		return nil
	}
	for _, item := range plan.Items {
		out := RecoveryApplyItem{Receipt: item.Receipt.Name, Namespace: item.Pod.Namespace, Target: item.Pod.Name, TargetUID: item.Pod.UID, Outcome: "refused"}
		currentHold, holdErr := n.requireRecoveryHold(ctx, plan.Scope.OperatorNamespace)
		if holdErr != nil || !sameBinding(currentHold, hold) {
			if holdErr != nil {
				out.Reason = holdErr.Error()
			} else {
				out.Reason = "administrative actuation hold identity changed during apply"
			}
			result.Items = append(result.Items, out)
			if writeErr := persistProgress(); writeErr != nil {
				return result, writeErr
			}
			return result, errors.New(out.Reason)
		}
		cm := &corev1.ConfigMap{}
		if err = n.Reader.Get(ctx, client.ObjectKey{Namespace: plan.Scope.OperatorNamespace, Name: item.Receipt.Name}, cm); err != nil {
			out.Reason = err.Error()
			result.Items = append(result.Items, out)
			if writeErr := persistProgress(); writeErr != nil {
				return result, writeErr
			}
			return result, err
		}
		receipt, receiptErr := validateProtectedReceipt(cm, plan.Scope.OperatorNamespace)
		if !sameBinding(binding(cm, "v1", "ConfigMap"), item.Receipt) || digestJSON(cm.Data["receipt"]) != item.ReceiptSHA256 || receiptErr != nil || receipt.Kind != "quarantine" || receipt.Phase != "policy-bound" || receipt.PolicyNamespace != plan.Scope.Namespace || receipt.PolicyName != plan.Scope.PolicyName {
			out.Reason = "protected receipt changed or left scope"
			result.Items = append(result.Items, out)
			if writeErr := persistProgress(); writeErr != nil {
				return result, writeErr
			}
			return result, errors.New(out.Reason)
		}
		current, e := n.recoveryPlanItem(ctx, cm, receipt)
		if e != nil || !sameBinding(current.Policy, item.Policy) || !sameBinding(current.Pod, item.Pod) || !sameBinding(current.NetworkPolicy, item.NetworkPolicy) || current.TargetLabels != item.TargetLabels || current.OwnerRefs != item.OwnerRefs || current.RollbackRef != item.RollbackRef {
			out.Reason = "planned policy/Pod/NetworkPolicy preconditions changed"
			if e != nil {
				out.Reason += ": " + e.Error()
			}
			result.Items = append(result.Items, out)
			if writeErr := persistProgress(); writeErr != nil {
				return result, writeErr
			}
			return result, errors.New(out.Reason)
		}
		req := Request{Namespace: receipt.PolicyNamespace, Pod: receipt.TargetName, TargetUID: receipt.TargetUID, Action: model.ActionQuarantine, PolicyName: receipt.PolicyName, PolicyUID: receipt.PolicyUID}
		if err = n.Rollback(ctx, req, item.RollbackRef); err != nil {
			out.Outcome, out.Reason = "partial-or-unknown", err.Error()
			result.Items = append(result.Items, out)
			result.State = "partial-or-unknown"
			if writeErr := persistProgress(); writeErr != nil {
				return result, errors.Join(err, writeErr)
			}
			return result, err
		}
		out.Outcome = "restored"
		result.Items = append(result.Items, out)
		if record != nil {
			if err := record(result); err != nil {
				result.State = "result-write-failed-after-effects"
				return result, fmt.Errorf("persist recovery progress after possible effects: %w", err)
			}
		}
	}
	result.Complete = true
	result.State = "complete"
	if record != nil {
		if err := record(result); err != nil {
			result.State = "result-write-failed-after-effects"
			return result, fmt.Errorf("persist final recovery result after effects: %w", err)
		}
	}
	return result, nil
}

// RecoveryPlanFromJSON rejects unknown fields so newer or misspelled contracts fail closed.
func RecoveryPlanFromJSON(data []byte) (RecoveryPlan, error) {
	var p RecoveryPlan
	if len(data) == 0 || len(data) > RecoveryPlanMaxBytes {
		return p, fmt.Errorf("recovery plan size must be 1..%d bytes", RecoveryPlanMaxBytes)
	}
	if err := rejectDuplicateJSONFields(data); err != nil {
		return p, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return p, fmt.Errorf("trailing recovery plan data")
	}
	return p, nil
}

func rejectDuplicateJSONFields(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var parse func() error
	parse = func() error {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("invalid JSON object key")
				}
				if seen[key] {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = true
				if err := parse(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err := parse(); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
	}
	if err := parse(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing recovery plan data")
	}
	return nil
}
