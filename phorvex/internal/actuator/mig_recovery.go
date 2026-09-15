package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

const migRecoveryLabel = "phorvex.ai/mig-recovery"

type migRecoveryReceipt struct {
	Version         int               `json:"version"`
	Phase           string            `json:"phase"`
	PolicyNamespace string            `json:"policyNamespace"`
	PolicyName      string            `json:"policyName"`
	PolicyUID       string            `json:"policyUID"`
	TargetName      string            `json:"targetName"`
	TargetUID       string            `json:"targetUID"`
	TargetLabels    map[string]string `json:"targetLabels"`
	Node            string            `json:"node"`
	GPUUUID         string            `json:"gpuUUID"`
	TargetProfile   string            `json:"targetProfile"`
	Prior           migGeometry       `json:"prior"`
	Outcome         string            `json:"outcome,omitempty"`
}

func (r migRecoveryReceipt) valid() bool {
	return r.Version == 1 && (r.Phase == "prepared" || r.Phase == "destructive" || r.Phase == "unresolved") &&
		r.PolicyNamespace != "" && r.PolicyName != "" && r.PolicyUID != "" && r.TargetName != "" && r.TargetUID != "" && r.TargetLabels != nil &&
		r.Node != "" && r.GPUUUID == r.Prior.GPUUUID && validMIGGeometry(r.Prior) &&
		profilePattern.MatchString(r.TargetProfile)
}

func migRecoveryName(node, uuid string) string {
	h := sha256.Sum256([]byte(node + "\x00" + uuid))
	return fmt.Sprintf("phorvex-mig-recovery-%x", h[:20])
}

func migRecoveryWrite(ctx context.Context, ec EnactCtx, r migRecoveryReceipt) (*corev1.ConfigMap, error) {
	if ec.JournalNamespace == "" || ec.JournalNamespace == r.PolicyNamespace || ec.Client == nil || ec.Reader == nil || !r.valid() {
		return nil, fmt.Errorf("protected MIG recovery store unavailable or invalid")
	}
	name := migRecoveryName(r.Node, r.GPUUUID)
	existing := &corev1.ConfigMap{}
	err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: ec.JournalNamespace, Name: name}, existing)
	if err == nil {
		return nil, fmt.Errorf("pending MIG operation already exists for node %s GPU %s", r.Node, r.GPUUUID)
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("check pending MIG operation: %w", err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: ec.JournalNamespace, Name: name, Labels: map[string]string{migRecoveryLabel: "v1"}}, Data: map[string]string{"receipt": string(b)}}
	if err := ec.Client.Create(ctx, cm); err != nil {
		return nil, err
	}
	if cm.UID == "" || cm.ResourceVersion == "" {
		return nil, fmt.Errorf("MIG recovery receipt create not acknowledged")
	}
	return cm, nil
}

func migRecoveryAdvance(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r migRecoveryReceipt) error {
	if cm == nil || cm.UID == "" || cm.ResourceVersion == "" || !r.valid() {
		return fmt.Errorf("MIG recovery receipt identity invalid")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	next := cm.DeepCopy()
	next.Data["receipt"] = string(b)
	if err := ec.Client.Update(ctx, next); err != nil {
		return err
	}
	if next.UID != cm.UID || next.ResourceVersion == "" {
		return fmt.Errorf("MIG recovery receipt update unconfirmed")
	}
	*cm = *next
	return nil
}

func migRecoveryRequireOwned(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, expected migRecoveryReceipt, targetLabels map[string]string) error {
	if ec.Reader == nil || cm == nil || cm.UID == "" || cm.ResourceVersion == "" || !expected.valid() {
		return fmt.Errorf("MIG recovery ownership unavailable")
	}
	if ec.JournalNamespace == "" || ec.JournalNamespace == expected.PolicyNamespace || cm.Namespace != ec.JournalNamespace {
		return fmt.Errorf("MIG recovery receipt outside protected namespace")
	}
	current := &corev1.ConfigMap{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: cm.Namespace, Name: cm.Name}, current); err != nil {
		return err
	}
	if current.UID != cm.UID || current.ResourceVersion != cm.ResourceVersion || current.DeletionTimestamp != nil || current.Labels[migRecoveryLabel] != "v1" || current.Name != migRecoveryName(expected.Node, expected.GPUUUID) {
		return fmt.Errorf("MIG recovery receipt identity changed")
	}
	var recorded migRecoveryReceipt
	if err := json.Unmarshal([]byte(current.Data["receipt"]), &recorded); err != nil {
		return err
	}
	want, _ := json.Marshal(expected)
	got, _ := json.Marshal(recorded)
	if string(got) != string(want) {
		return fmt.Errorf("MIG recovery receipt content changed")
	}
	return migRecoveryAuthority(ctx, ec, recorded, targetLabels)
}

func migRecoveryFinish(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap) error {
	if cm == nil || cm.UID == "" || cm.ResourceVersion == "" {
		return fmt.Errorf("MIG recovery receipt identity invalid")
	}
	uid, rv := cm.UID, cm.ResourceVersion
	return ec.Client.Delete(ctx, cm, client.Preconditions{UID: &uid, ResourceVersion: &rv})
}

func migRecoveryAuthority(ctx context.Context, ec EnactCtx, r migRecoveryReceipt, targetLabels map[string]string) error {
	pol, err := receiptAuthority(ctx, ec.Reader, operationReceipt{PolicyNamespace: r.PolicyNamespace, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, TargetName: r.TargetName, TargetUID: r.TargetUID}, model.ActionMIGRebind)
	if err != nil {
		return err
	}
	sel, err := metav1.LabelSelectorAsSelector(&pol.Spec.Selector)
	if err != nil {
		return err
	}
	if !sel.Matches(labels.Set(targetLabels)) {
		return fmt.Errorf("current target outside policy selector")
	}
	return nil
}
