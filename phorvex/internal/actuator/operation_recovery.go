package actuator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

// RecoveryEvent describes one administrative attempt, including refusals and partial effects.
type RecoveryEvent struct {
	Receipt, Kind, Phase, Tenant, PolicyNamespace, PolicyName, PolicyUID, TargetName, TargetUID, Outcome, Effect string
	Err                                                                                                          error
}

// RecoverOperations reads only the protected administrative journal. It never scans
// tenant labels for candidates. Each record is revalidated against live API objects.
func (n *NativeActuator) RecoverOperations(ctx context.Context, globalKill bool) ([]RecoveryEvent, error) {
	return n.recoverOperations(ctx, globalKill, nil)
}

func (n *NativeActuator) recoverOperations(ctx context.Context, globalKill bool, allow func(model.Action) bool) ([]RecoveryEvent, error) {
	ec := EnactCtx{Client: n.Client, Reader: n.Reader, DryRun: n.DryRun, JournalNamespace: n.JournalNamespace, VLLM: n.RecoveryVLLM}
	if globalKill || n.DryRun {
		return nil, nil
	}
	entries, err := journalList(ctx, ec)
	if err != nil {
		return nil, err
	}
	events := make([]RecoveryEvent, 0, len(entries))
	for i := range entries {
		entry := &entries[i]
		r := entry.Receipt
		ev := RecoveryEvent{Receipt: entry.CM.Name, Kind: r.Kind, Phase: r.Phase, PolicyNamespace: r.PolicyNamespace, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, TargetName: r.TargetName, TargetUID: r.TargetUID, Outcome: "refused"}
		action := model.Action(r.Kind)
		if r.Kind == "quarantine" {
			action = model.ActionQuarantine
		}
		if allow != nil && !allow(action) {
			ev.Err = fmt.Errorf("native recovery refused: action routed to Phoenix")
			events = append(events, ev)
			continue
		}
		var pol *v1alpha1.PhorvexPolicy
		pol, ev.Err = receiptAuthority(ctx, ec.Reader, r, action)
		if ev.Err == nil {
			ev.Tenant = pol.EffectiveTenant()
			switch r.Kind {
			case "warm-swap", "model-shard-replace":
				ev.Effect, ev.Err = recoverScalarCutover(ctx, ec, &entry.CM, &r)
			case "quarantine":
				ev.Effect, ev.Err = recoverQuarantineGC(ctx, ec, &entry.CM, &r)
			}
		}
		if ev.Err == nil {
			if r.Kind == "quarantine" && ev.Effect == "" {
				ev.Outcome = "retained"
				ev.Effect = fmt.Sprintf("target %s/%s UID %s still present; receipt retained without mutation", r.PolicyNamespace, r.TargetName, r.TargetUID)
			} else {
				ev.Outcome = "confirmed"
			}
		} else if ev.Effect != "" {
			ev.Outcome = "partial"
		}
		events = append(events, ev)
	}
	return events, nil
}

func recoverScalarCutover(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, error) {
	newPod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NewName}, newPod); err != nil {
		return "", err
	}
	if string(newPod.UID) != r.NewUID || newPod.DeletionTimestamp != nil || newPod.Labels[r.GroupKey] != r.GroupValue {
		return "", fmt.Errorf("recorded promoted leader missing, changed or unhealthy")
	}
	old := &corev1.Pod{}
	err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.OldName}, old)
	if err != nil && !apierrors.IsNotFound(err) {
		return "", err
	}
	if err == nil && (string(old.UID) != r.OldUID || old.DeletionTimestamp != nil || old.Labels[r.GroupKey] != r.GroupValue) {
		return "", fmt.Errorf("recorded old leader missing identity or scope")
	}
	if err == nil && (r.Phase == "prepared" || r.Phase == "promoted") && old.Labels[labelRole] == roleLeader && podReady(old) && newPod.Labels[labelRole] == roleShadow {
		pol, e := receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
		if e != nil {
			return "", e
		}
		if e := warmCurrentScope(pol, *r, old, newPod); e != nil {
			return "", e
		}
		if e := journalFinish(ctx, ec, cm); e != nil {
			return "", e
		}
		return "unpromoted or rolled-back pair confirmed; receipt finished", nil
	}
	if newPod.Labels[labelRole] != roleLeader || !podReady(newPod) {
		return "", fmt.Errorf("recorded promoted leader missing, changed or unhealthy")
	}
	effect := ""
	if apierrors.IsNotFound(err) {
		effect = "old leader already absent; prior in-flight drain unverified"
	}
	if err == nil {
		pol, e := receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
		if e != nil {
			return effect, e
		}
		if e := warmCurrentScope(pol, *r, old, newPod); e != nil {
			return effect, e
		}
		if old.Labels[labelRole] == roleLeader {
			before := old.DeepCopy()
			old.Labels[labelRole] = roleRetiring
			if e := ec.Client.Patch(ctx, old, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); e != nil {
				return effect, e
			}
			effect = "old leader route removed"
			fresh := &corev1.Pod{}
			if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.OldName}, fresh); e != nil {
				return effect, e
			}
			if fresh.UID != old.UID || fresh.Labels[labelRole] != roleRetiring {
				return effect, fmt.Errorf("old leader changed after route removal")
			}
			old = fresh
		} else if old.Labels[labelRole] != roleRetiring {
			return effect, fmt.Errorf("old leader role ambiguous")
		}
		pol, e = receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
		if e != nil {
			return effect, e
		}
		if e := warmCurrentScope(pol, *r, old, newPod); e != nil {
			return effect, e
		}
		_, drainPending, e := drainInflight(ctx, ec, old)
		if e != nil {
			return effect, e
		}
		pol, e = receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
		if e != nil {
			return effect, e
		}
		freshOld, freshNew := &corev1.Pod{}, &corev1.Pod{}
		if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.OldName}, freshOld); e != nil {
			return effect, e
		}
		if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NewName}, freshNew); e != nil {
			return effect, e
		}
		if e := warmCurrentScope(pol, *r, freshOld, freshNew); e != nil {
			return effect, e
		}
		if freshOld.Labels[labelRole] != roleRetiring || freshOld.DeletionTimestamp != nil || freshNew.Labels[labelRole] != roleLeader || !podReady(freshNew) || freshNew.DeletionTimestamp != nil {
			return effect, fmt.Errorf("recorded pair changed before retirement")
		}
		if e := ec.Client.Delete(ctx, freshOld, uidPrecondition(freshOld)); e != nil && !apierrors.IsNotFound(e) {
			return effect, e
		}
		if drainPending {
			effect = "old leader route removed and retired; in-flight abort unverified (serving stack unreachable)"
		} else {
			effect = "old leader in-flight drained and retired"
		}
	}
	if r.Phase != "rewarmed" && r.Phase != "rewarm-intent" && r.Phase != "retired" {
		r.Phase = "retired"
		if e := journalAdvance(ctx, ec, cm, *r); e != nil {
			return effect, e
		}
	}
	pol, e := receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
	if e != nil {
		return effect, e
	}
	freshNew := &corev1.Pod{}
	if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NewName}, freshNew); e != nil {
		return effect, e
	}
	if freshNew.UID != newPod.UID || freshNew.Labels[labelRole] != roleLeader || !podReady(freshNew) {
		return effect, fmt.Errorf("survivor changed before rewarm")
	}
	if e := warmSurvivorScope(pol, *r, freshNew); e != nil {
		return effect, e
	}
	if r.Phase == "rewarmed" {
		bound := &corev1.Pod{}
		if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.RewarmName}, bound); e != nil {
			return effect, e
		}
		if string(bound.UID) != r.RewarmUID || bound.Labels[r.GroupKey] != r.GroupValue || bound.Labels[labelRole] != roleShadow || bound.Labels[labelModelLoaded] != "false" || rewarmSpecDigest(bound) != r.RewarmSpecHash {
			return effect, fmt.Errorf("recorded replacement shadow identity/spec drift")
		}
	} else {
		if r.Phase != "rewarm-intent" {
			r.RewarmName = truncName(freshNew.Name + "-rw-" + freshNew.ResourceVersion)
			r.RewarmSpecHash = rewarmSpecDigest(freshNew)
			r.Phase = "rewarm-intent"
			if e := journalAdvance(ctx, ec, cm, *r); e != nil {
				return effect, fmt.Errorf("rewarm intent not persisted; replacement not created: %w", e)
			}
		}
		if rewarmSpecDigest(freshNew) != r.RewarmSpecHash {
			return effect, fmt.Errorf("rewarm source spec differs from persisted intent")
		}
		existing := &corev1.Pod{}
		if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.RewarmName}, existing); !apierrors.IsNotFound(e) {
			return effect, fmt.Errorf("replacement intent name occupied or read uncertain; UID not bound: %v", e)
		}
		uid, e := rewarmShadowNamed(ctx, ec, freshNew, r.RewarmName, r.GroupKey, r.GroupValue)
		if e != nil {
			return effect, fmt.Errorf("retired; rewarm unresolved: %w", e)
		}
		bound := &corev1.Pod{}
		if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.RewarmName}, bound); e != nil {
			return effect, e
		}
		if string(bound.UID) != uid || bound.Labels[r.GroupKey] != r.GroupValue || bound.Labels[labelRole] != roleShadow || bound.Labels[labelModelLoaded] != "false" || rewarmSpecDigest(bound) != r.RewarmSpecHash {
			return effect, fmt.Errorf("replacement shadow readback identity/scope mismatch")
		}
		r.RewarmUID, r.Phase = uid, "rewarmed"
		if e := journalAdvance(ctx, ec, cm, *r); e != nil {
			return effect, e
		}
		effect += "; replacement shadow created"
	}
	effect += "; replacement shadow UID/spec verified"
	if e := journalFinish(ctx, ec, cm); e != nil {
		return effect, e
	}
	return effect, nil
}

func recoverQuarantineGC(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, error) {
	if r.Phase == "prepared" && r.NPUID == "" {
		target := &corev1.Pod{}
		if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, target); err != nil {
			return "", err
		}
		if string(target.UID) != r.TargetUID || target.DeletionTimestamp != nil || target.Labels[quarantineLabel] != "" || target.Annotations[quarantineSnapAnno] != "" {
			return "", fmt.Errorf("prepared quarantine outcome uncertain")
		}
		unused := &networkingv1.NetworkPolicy{}
		if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NPName}, unused); !apierrors.IsNotFound(err) {
			return "", fmt.Errorf("prepared quarantine policy outcome uncertain: %v", err)
		}
		if err := journalFinish(ctx, ec, cm); err != nil {
			return "", err
		}
		return "no quarantine mutation confirmed; receipt finished", nil
	}
	if r.NPUID == "" || r.Phase != "policy-bound" {
		return "", fmt.Errorf("quarantine policy identity unbound")
	}
	target := &corev1.Pod{}
	err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, target)
	if err == nil {
		if string(target.UID) != r.TargetUID {
			return "", fmt.Errorf("target name recreated; GC refused")
		}
		return "", nil // still protected; retain receipt
	}
	if !apierrors.IsNotFound(err) {
		return "", err
	}
	np := &networkingv1.NetworkPolicy{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NPName}, np); err != nil {
		if apierrors.IsNotFound(err) {
			if e := journalFinish(ctx, ec, cm); e != nil {
				return "NP already absent", e
			}
			return "NP already absent; receipt finished", nil
		}
		return "", err
	}
	p := &corev1.Pod{}
	p.Namespace, p.Name, p.UID = r.PolicyNamespace, r.TargetName, types.UID(r.TargetUID)
	if np.Name != quarantinePolicy(p).Name || np.UID == "" || string(np.UID) != r.NPUID || np.ResourceVersion == "" || np.DeletionTimestamp != nil || len(np.OwnerReferences) != 1 {
		return "", fmt.Errorf("quarantine NP identity ambiguous")
	}
	o := np.OwnerReferences[0]
	if o.APIVersion != "v1" || o.Kind != "Pod" || o.Name != p.Name || o.UID != p.UID || np.Labels[npManagedByLabel] != npManagedByValue || np.Labels[npQuarantineOfKey] != quarantineTargetLabel(p) {
		return "", fmt.Errorf("quarantine NP owner or marker mismatch")
	}
	if err := verifyQuarantinePolicy(np, quarantinePolicy(p)); err != nil {
		return "", err
	}
	if len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 {
		return "", fmt.Errorf("quarantine NP is not deny-all")
	}
	uid := np.UID
	rv := np.ResourceVersion
	if err := ec.Client.Delete(ctx, np, client.Preconditions{UID: &uid, ResourceVersion: &rv}); err != nil && !apierrors.IsNotFound(err) {
		return "", err
	}
	if err := journalFinish(ctx, ec, cm); err != nil {
		return "NP deleted", err
	}
	return "NP deleted", nil
}
