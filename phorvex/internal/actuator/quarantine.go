package actuator

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
func quarantinePolicy(p *corev1.Pod) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "phorvex-quarantine-" + p.Name, Namespace: p.Namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/quarantine-of": p.Name}}, Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{quarantineLabel: string(p.UID)}}, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}}
}
func verifyQuarantinePolicy(got, want *networkingv1.NetworkPolicy) error {
	if !reflect.DeepEqual(got.Spec.PodSelector, want.Spec.PodSelector) || len(got.Spec.Ingress) != 0 || len(got.Spec.Egress) != 0 || len(got.Spec.PolicyTypes) != 2 || got.Labels["app.kubernetes.io/managed-by"] != "phorvex" {
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
func (quarantineHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	p, err := quarantinePod(ctx, ec, req)
	if err != nil {
		return HandlerResult{}, err
	}
	if p.Labels[quarantineLabel] != "" {
		var snap qtnSnapshot
		if err = json.Unmarshal([]byte(p.Annotations[quarantineSnapAnno]), &snap); err != nil || snap.Version != 2 || snap.UID != p.UID {
			return HandlerResult{}, fmt.Errorf("quarantine: existing marker has no verified recovery baseline")
		}
		for k, want := range snap.Applied {
			if labelAt(p.Labels, k) != want {
				return HandlerResult{}, fmt.Errorf("quarantine: applied labels drifted, inspection required")
			}
		}
		if !reflect.DeepEqual(p.OwnerReferences, snap.AppliedOwners) {
			return HandlerResult{}, fmt.Errorf("quarantine: owner references drifted")
		}
		got := &networkingv1.NetworkPolicy{}
		if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: snap.PolicyName}, got); err != nil {
			return HandlerResult{}, err
		}
		if got.UID != snap.PolicyUID {
			return HandlerResult{}, fmt.Errorf("quarantine: isolation policy identity changed")
		}
		if err = verifyQuarantinePolicy(got, quarantinePolicy(p)); err != nil {
			return HandlerResult{}, err
		}
		return HandlerResult{MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod + "@" + string(p.UID), Note: "already quarantined; no new mutation; endpoint convergence and enforcement unverified"}, nil
	}
	if p.Annotations[quarantineSnapAnno] != "" {
		return HandlerResult{}, fmt.Errorf("quarantine: existing recovery baseline requires inspection")
	}
	plan, err := planQuarantine(ctx, ec.Reader, p)
	if err != nil {
		return HandlerResult{}, err
	}
	snap := qtnSnapshot{Version: 2, UID: p.UID, Before: map[string]labelState{}, Applied: map[string]labelState{}, OwnerRefs: p.OwnerReferences, PolicyName: "phorvex-quarantine-" + p.Name}
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
	np := quarantinePolicy(p)
	result := HandlerResult{MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod + "@" + string(p.UID)}
	if err = ec.Client.Create(ctx, np); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return result, err
		}
		if err = ec.Reader.Get(ctx, client.ObjectKeyFromObject(np), np); err != nil {
			return result, err
		}
		if err = verifyQuarantinePolicy(np, quarantinePolicy(p)); err != nil {
			return result, err
		}
	} else {
		result.Emitted = true
		result.ObjectsTouched = append(result.ObjectsTouched, objRef("NetworkPolicy", p.Namespace, np.Name))
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
		result.Note = "partial quarantine: isolation policy retained, Pod detach not acknowledged"
		return result, fmt.Errorf("quarantine detach: %w", err)
	}
	result.Emitted = true
	result.ObjectsTouched = append(result.ObjectsTouched, objRef("Pod", p.Namespace, p.Name))
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
	if snap.Version != 2 || snap.UID != p.UID || ref != p.Namespace+"/"+p.Name+"@"+string(p.UID) {
		return fmt.Errorf("quarantine rollback: unverified/legacy snapshot or identity mismatch")
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
	np := &networkingv1.NetworkPolicy{}
	if err = ec.Reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: snap.PolicyName}, np); err != nil {
		return err
	}
	if np.UID != snap.PolicyUID {
		return fmt.Errorf("quarantine rollback: NetworkPolicy identity changed")
	}
	if err = verifyQuarantinePolicy(np, quarantinePolicy(p)); err != nil {
		return err
	}
	delete(restored.Annotations, quarantineSnapAnno)
	if err = ec.Client.Update(ctx, restored); err != nil {
		return err
	}
	uid, rv := np.UID, np.ResourceVersion
	if err = ec.Client.Delete(ctx, np, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("quarantine rollback: Pod restored but policy cleanup failed: %w", err)
	}
	return nil
}
