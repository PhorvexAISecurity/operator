package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type quarantineHandler struct{}

func (quarantineHandler) Name() string { return "quarantine" }

const (
	quarantineLabel      = "phorvex.ai/quarantined"
	quarantineSnapAnno   = "phorvex.ai/quarantine-snapshot"
	quarantineEpochLabel = "phorvex.ai/quarantine-epoch"
)

type labelState struct {
	Value   string `json:"value"`
	Present bool   `json:"present"`
}
type qtnSnapshot struct {
	Version       int                     `json:"version"`
	UID           types.UID               `json:"uid"`
	Before        map[string]labelState   `json:"before"`
	Applied       map[string]labelState   `json:"applied"`
	OwnerRefs     []metav1.OwnerReference `json:"ownerRefs"`
	AppliedOwners []metav1.OwnerReference `json:"appliedOwners"`
	PolicyName    string                  `json:"policyName"`
	PolicyUID     types.UID               `json:"policyUID"`
	LegacyName    string                  `json:"legacyName,omitempty"`
	LegacyUID     types.UID               `json:"legacyUID,omitempty"`
	Released      bool                    `json:"released,omitempty"`
}

func labelAt(m map[string]string, k string) labelState { v, ok := m[k]; return labelState{v, ok} }
func quarantinePod(ctx context.Context, ec EnactCtx, req Request) (*corev1.Pod, error) {
	if ec.DryRun {
		return nil, errDryRunGuard
	}
	if ec.Reader == nil {
		return nil, fmt.Errorf("quarantine: authoritative reader unavailable")
	}
	p := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, p); err != nil {
		return nil, err
	}
	if p.UID == "" || (req.TargetUID != "" && req.TargetUID != string(p.UID)) {
		return nil, fmt.Errorf("quarantine: target UID unavailable or mismatched")
	}
	return p, nil
}
func quarantineTargetLabel(p *corev1.Pod) string {
	if len(p.Name) <= 63 {
		return p.Name
	}
	// Pod names can exceed the label value limit; ownerRef retains the full name.
	digest := sha256.Sum256([]byte(p.Name))
	return fmt.Sprintf("h-%x", digest[:30])
}
func quarantinePolicy(p *corev1.Pod) *networkingv1.NetworkPolicy {
	// Hash the complete UID, not a truncated prefix; authority is checked separately.
	name := fmt.Sprintf("phorvex-quarantine-%x", sha256.Sum256([]byte(p.UID)))
	return &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: p.Namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/quarantine-of": quarantineTargetLabel(p)}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: p.Name, UID: p.UID}}}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{quarantineLabel: string(p.UID)}}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}}
}
func verifyQuarantinePolicy(got, want *networkingv1.NetworkPolicy) error {
	if !reflect.DeepEqual(got.Spec.PodSelector.MatchLabels, want.Spec.PodSelector.MatchLabels) || len(got.Spec.PodSelector.MatchExpressions) != 0 || len(got.Spec.Ingress) != 0 || len(got.Spec.Egress) != 0 || len(got.Spec.PolicyTypes) != 2 || got.Labels["app.kubernetes.io/managed-by"] != "phorvex" {
		return fmt.Errorf("quarantine: existing NetworkPolicy is incompatible")
	}
	types := map[networkingv1.PolicyType]bool{}
	for _, v := range got.Spec.PolicyTypes {
		types[v] = true
	}
	if !types[networkingv1.PolicyTypeIngress] || !types[networkingv1.PolicyTypeEgress] {
		return fmt.Errorf("quarantine: missing ingress/egress policy type")
	}
	return nil
}
func (quarantineHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (out HandlerResult, failure error) {
	defer func() {
		if failure != nil && out.Emitted {
			out.Note = "partial quarantine: accepted writes retained; " + out.Note + "; " + failure.Error()
		}
	}()
	p, err := quarantinePod(ctx, ec, req)
	if err != nil {
		return HandlerResult{}, err
	}
	// Inventory legacy occupancy independently of canonical ensure. An unproven
	// old incarnation cannot authorize cleanup, nor veto a fresh target's policy.
	legacy := &networkingv1.NetworkPolicy{}
	legacyName := "phorvex-quarantine-" + p.Name
	if len(legacyName) <= 253 {
		err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: legacyName}, legacy)
		if err != nil && !apierrors.IsNotFound(err) {
			return HandlerResult{}, err
		}
		if err == nil {
			var recorded qtnSnapshot
			_ = json.Unmarshal([]byte(p.Annotations[quarantineSnapAnno]), &recorded)
			provenRecord := validQuarantineSnapshot(p, &recorded) && ((recorded.Version == 2 && recorded.PolicyName == legacy.Name && recorded.PolicyUID == legacy.UID) || (recorded.LegacyName == legacy.Name && recorded.LegacyUID == legacy.UID))
			if !provenRecord {
				defer func() {
					out.Note += "; legacy policy " + legacy.Name + " UID=" + string(legacy.UID) + " retained unchanged; inventory/cleanup unresolved"
				}()
			}
		}
	}
	if p.Labels[quarantineLabel] != "" || p.Annotations[quarantineSnapAnno] != "" {
		return retryQuarantine(ctx, ec, req, p)
	}
	plan, err := planQuarantine(ctx, ec.Reader, p)
	if err != nil {
		return HandlerResult{}, err
	}
	snap := qtnSnapshot{Version: 3, UID: p.UID, Before: map[string]labelState{}, Applied: map[string]labelState{}, OwnerRefs: p.OwnerReferences, PolicyName: quarantinePolicy(p).Name}
	after := p.DeepCopy()
	after.Labels = plan.labels
	for _, o := range p.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			snap.AppliedOwners = append(snap.AppliedOwners, o)
		}
	}
	after.OwnerReferences = snap.AppliedOwners
	keys := map[string]bool{}
	for k := range p.Labels {
		keys[k] = true
	}
	for k := range after.Labels {
		keys[k] = true
	}
	for k := range keys {
		before, applied := labelAt(p.Labels, k), labelAt(after.Labels, k)
		if before != applied {
			snap.Before[k] = before
			snap.Applied[k] = applied
		}
	}
	result := quarantineResult(p)
	np, err := ensureQuarantinePolicy(ctx, ec, p, &snap, &result)
	if err != nil {
		return result, err
	}
	snap.PolicyUID = np.UID
	data, err := json.Marshal(snap)
	if err != nil {
		return result, err
	}
	after.Annotations = ensureMap(after.Annotations)
	after.Annotations[quarantineSnapAnno] = string(data)
	// The full update carries the freshly observed UID/resourceVersion. No blind retry.
	if err = ec.Client.Update(ctx, after); err != nil {
		result.Note = "partial quarantine: isolation policy retained, Pod detach outcome unconfirmed: " + err.Error()
		return result, fmt.Errorf("quarantine detach: %w", err)
	}
	result.Emitted = true
	result.ObjectsTouched = append(result.ObjectsTouched, objRef("Pod", p.Namespace, p.Name))
	if err = verifyQuarantineTarget(ctx, ec, after, np); err != nil {
		result.Note = "partial quarantine: accepted writes, readback failed: " + err.Error()
		return result, err
	}
	result.Note = "metadata detach acknowledged for UID=" + string(p.UID) + "; " + strings.Join(plan.via, ",") + "; selectors checked against observed inputs; selectorless/manual routing, endpoint convergence and network enforcement unverified"
	return result, nil
}

// Rollback is explicit re-admission, never automatic. Ref and snapshot bind the UID.
// Only fields changed by quarantine are restored, and concurrent edits cause refusal.
func (quarantineHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	p, err := quarantinePod(ctx, ec, req)
	if err != nil {
		return err
	}
	var snap qtnSnapshot
	if err = json.Unmarshal([]byte(p.Annotations[quarantineSnapAnno]), &snap); err != nil {
		return err
	}
	if !validQuarantineSnapshot(p, &snap) || ref != p.Namespace+"/"+p.Name+"@"+string(p.UID) {
		return fmt.Errorf("quarantine rollback: unverified/legacy snapshot or identity mismatch")
	}
	if snap.Released {
		return finishQuarantineRelease(ctx, ec, p, &snap)
	}
	for k, want := range snap.Applied {
		if labelAt(p.Labels, k) != want {
			return fmt.Errorf("quarantine rollback: label %s changed concurrently", k)
		}
	}
	if !reflect.DeepEqual(p.OwnerReferences, snap.AppliedOwners) {
		return fmt.Errorf("quarantine rollback: owner references changed concurrently")
	}
	restored := p.DeepCopy()
	restored.OwnerReferences = snap.OwnerRefs
	// Validate the original controller still has the same identity before reattaching.
	if _, err = quarantineOwnerSelector(ctx, ec.Reader, restored); err != nil {
		return err
	}
	for k, v := range snap.Before {
		if v.Present {
			restored.Labels[k] = v.Value
		} else {
			delete(restored.Labels, k)
		}
	}
	// Validate every recorded policy before re-admission. Keep the durable recovery
	// record until cleanup completes, so a lost delete response is retryable.
	if _, err = recordedQuarantinePolicies(ctx, ec, p, &snap); err != nil {
		return err
	}
	// A migration may have crashed after creating the canonical policy but before
	// checkpointing it. Explicit release inventories that exclusively owned object.
	if snap.Version == 2 {
		canonical := &networkingv1.NetworkPolicy{}
		err = ec.Reader.Get(ctx, client.ObjectKeyFromObject(quarantinePolicy(p)), canonical)
		if err == nil {
			if err = quarantineAuthority(canonical, p, "", false); err != nil {
				return err
			}
			snap.LegacyName, snap.LegacyUID = snap.PolicyName, snap.PolicyUID
			snap.Version, snap.PolicyName, snap.PolicyUID = 3, canonical.Name, canonical.UID
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	}
	snap.Released = true
	data, _ := json.Marshal(snap)
	restored.Annotations[quarantineSnapAnno] = string(data)
	if err = ec.Client.Update(ctx, restored); err != nil {
		return err
	}
	return finishQuarantineRelease(ctx, ec, restored, &snap)
}
