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
	ec := EnactCtx{Client: n.Client, Reader: n.Reader, DryRun: n.DryRun, JournalNamespace: n.JournalNamespace, VLLM: n.RecoveryVLLM, AdapterSources: n.AdapterSources, ServingSecurity: n.servingSecurity, RouteObservationTimeout: n.RouteObservationTimeout, RouteObservationInterval: n.RouteObservationInterval, VoiceMemoryTransport: n.VoiceMemoryTransport, VoiceRefundTransport: n.VoiceRefundTransport, VoiceMCPTransport: n.VoiceMCPTransport, VoiceMCPApprovedImage: n.VoiceMCPApprovedImage}
	if globalKill || n.DryRun {
		return nil, nil
	}
	guardEvents, err := cleanupOrphanRouteGuards(ctx, ec)
	if err != nil {
		return nil, err
	}
	outputEvents, err := recoverOutputPolicyOperations(ctx, ec, allow)
	if err != nil {
		return nil, err
	}
	voiceEvents, err := recoverVoiceMemoryOperations(ctx, ec, allow)
	if err != nil {
		return nil, err
	}
	refundEvents, err := recoverVoiceRefundOperations(ctx, ec, allow)
	if err != nil {
		return nil, err
	}
	mcpEvents, err := recoverVoiceMCPOperations(ctx, ec, allow)
	if err != nil {
		return nil, err
	}
	litellmEvents, err := recoverLiteLLMClientOperations(ctx, ec, allow)
	if err != nil {
		return nil, err
	}
	entries, err := journalList(ctx, ec)
	if err != nil {
		return nil, err
	}
	events := append(make([]RecoveryEvent, 0, len(guardEvents)+len(outputEvents)+len(voiceEvents)+len(refundEvents)+len(mcpEvents)+len(litellmEvents)+len(entries)), guardEvents...)
	events = append(events, outputEvents...)
	events = append(events, voiceEvents...)
	events = append(events, refundEvents...)
	events = append(events, mcpEvents...)
	events = append(events, litellmEvents...)
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
		if r.Version == servingEffectReceiptVersion {
			handled, effect, gcErr := gcCompletedServingReceipt(ctx, ec, &entry.CM, r)
			if handled {
				ev.Effect, ev.Err = effect, gcErr
				if gcErr == nil {
					ev.Outcome = "confirmed"
				}
				events = append(events, ev)
				continue
			}
		}
		entryEC := ec
		entryEC.ServingRequest = Request{Namespace: r.PolicyNamespace, Pod: r.TargetName, TargetUID: r.TargetUID, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, Action: action}
		if servingHTTPAction(action) {
			if ec.ServingSecurity != nil {
				snapshot, prepareErr := ec.ServingSecurity.prepareRecovery(ctx, ec.Reader, r)
				if prepareErr == nil {
					entryEC.ServingAttempt = snapshot
				} else if secureServingReceipt(r) {
					ev.Err = prepareErr
					events = append(events, ev)
					continue
				}
			} else if secureServingReceipt(r) {
				ev.Err = fmt.Errorf("serving security configuration is not wired")
				events = append(events, ev)
				continue
			}
		}
		if r.Kind == string(model.ActionRouteRotate) || r.Kind == string(model.ActionEndpointRotate) {
			ev.Effect, ev.Err = recoverRouteCutover(ctx, entryEC, &entry.CM, &r)
		} else {
			var pol *v1alpha1.PhorvexPolicy
			pol, ev.Err = receiptAuthority(ctx, entryEC.Reader, r, action)
			if ev.Err == nil {
				ev.Tenant = pol.EffectiveTenant()
				switch r.Kind {
				case "warm-swap", "model-shard-replace":
					ev.Effect, ev.Err = recoverScalarCutover(ctx, entryEC, &entry.CM, &r)
				case "quarantine":
					ev.Effect, ev.Err = recoverQuarantineGC(ctx, entryEC, &entry.CM, &r)
				case "request-drain":
					ev.Effect, _, ev.Err = recoverRequestDrain(ctx, entryEC, &entry.CM, &r)
				case "adapter-rotate":
					ev.Effect, ev.Err = recoverAdapterRotate(ctx, entryEC, &entry.CM, &r)
				case string(model.ActionKVReset), string(model.ActionKVMigrateInvalidate), string(model.ActionGuardrailRotate):
					ev.Effect, ev.Err = recoverProtectedServingEffect(ctx, entryEC, &entry.CM, &r)
				}
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

func gcCompletedServingReceipt(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r operationReceipt) (bool, string, error) {
	if r.Version != servingEffectReceiptVersion || !terminalServingPhase(r.Phase) {
		return false, "", nil
	}
	if ec.Reader == nil {
		return true, "", fmt.Errorf("protected serving terminal target cannot be classified without an authoritative reader")
	}
	pod := &corev1.Pod{}
	err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.TargetName}, pod)
	switch {
	case err == nil && string(pod.UID) == r.TargetUID:
		return false, "", nil
	case err == nil:
		// A same-name successor is not the exact old target. The receipt remains
		// bound to the absent UID and may be retired without touching the successor.
	case apierrors.IsNotFound(err):
	case err != nil:
		return true, "", fmt.Errorf("protected serving terminal target absence is unconfirmed: %w", err)
	}
	if err := journalFinish(ctx, ec, cm); err != nil {
		return true, "", fmt.Errorf("protected serving terminal receipt GC was not acknowledged: %w", err)
	}
	return true, fmt.Sprintf("terminal protected %s receipt garbage-collected after exact target UID absence", r.Kind), nil
}

func recoverScalarCutover(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, error) {
	if r.Version == warmDrainReceiptVersion || r.Version == operationDrainReceiptVersion {
		return recoverWarmDrainCutover(ctx, ec, cm, r)
	}
	if r.Version == 1 {
		return recoverLegacyScalarCutover(ctx, ec, cm, r)
	}
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
	if apierrors.IsNotFound(err) {
		// v2/v6 receipts have no durable send claim or confirmation. Absence of
		// the old UID therefore cannot prove a drain result or authorize receipt
		// advancement/cleanup, even when the survivor and controller pool look
		// healthy.
		return "old leader absent; prior in-flight drain unverified", fmt.Errorf("legacy warm receipt has ambiguous drain history; external resolution required")
	}
	if err == nil && (r.Phase == "prepared" || r.Phase == "promoted") && old.Labels[labelRole] == roleLeader && podReady(old) && newPod.Labels[labelRole] == roleShadow {
		pol, e := receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
		if e != nil {
			return "", e
		}
		if e := warmCurrentScope(pol, *r, old, newPod); e != nil {
			return "", e
		}
		if e := warmPoolRecheck(ctx, ec.Reader, *r, old, newPod); e != nil {
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
	if err == nil {
		// v2/v6 receipts predate the durable pre-POST claim. Once the new
		// leader is selected they cannot prove that no drain was sent, so do
		// not change either route, POST, delete or compensate from their bytes.
		return effect, fmt.Errorf("legacy warm receipt has ambiguous drain history; external resolution required")
	}
	if r.Phase == "prepared" || r.Phase == "promoted" || r.Phase == "retiring" {
		r.Phase = "retired-awaiting-controller"
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
		return effect, fmt.Errorf("recorded serving survivor changed")
	}
	if e := warmSurvivorScope(pol, *r, freshNew); e != nil {
		return effect, e
	}
	if e := warmPoolRecheck(ctx, ec.Reader, *r, nil, freshNew); e != nil {
		return effect, e
	}
	var candidate *corev1.Pod
	if r.Phase == "pool-observed" || r.Phase == "pool-warm-ready" {
		candidate = &corev1.Pod{}
		if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.RewarmName}, candidate); e != nil {
			return effect, e
		}
		if string(candidate.UID) != r.RewarmUID {
			return effect, fmt.Errorf("recorded controller member UID changed")
		}
	}
	observed, e := warmPoolObserve(ctx, ec.Reader, *r)
	if e != nil {
		return effect + "; controller pool observation pending", e
	}
	if candidate != nil && candidate.UID != observed.UID {
		return effect, fmt.Errorf("recorded controller member identity drift")
	}
	if r.Phase == "retired-awaiting-controller" {
		r.RewarmName, r.RewarmUID, r.Phase = observed.Name, string(observed.UID), "pool-observed"
		if e := journalAdvance(ctx, ec, cm, *r); e != nil {
			return effect, e
		}
	}
	ready, fallback := shadowModelReady(ctx, ec, observed)
	if !ready {
		return effect + "; controller Pod observed; warm capacity pending", fmt.Errorf("controller Pod observed but warm capacity not ready")
	}
	if r.Phase != "pool-warm-ready" {
		r.Phase = "pool-warm-ready"
		if e := journalAdvance(ctx, ec, cm, *r); e != nil {
			return effect, e
		}
	}
	if e := journalFinish(ctx, ec, cm); e != nil {
		return effect, e
	}
	effect += "; controller pool replenished and warm capacity ready"
	if fallback {
		effect += " [PENDING-GPU-VALIDATION]: K8s/model-loaded fallback"
	}
	return effect, nil
}

// Legacy warm receipts are kept as evidence. They never acquire a missing
// pre-retirement controller intent or replay the unsafe synthetic Pod Create.
func recoverLegacyScalarCutover(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, error) {
	old, next := &corev1.Pod{}, &corev1.Pod{}
	if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NewName}, next); e != nil {
		return "", e
	}
	if string(next.UID) != r.NewUID {
		return "", fmt.Errorf("legacy survivor UID changed")
	}
	oldErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.OldName}, old)
	if oldErr == nil && string(old.UID) != r.OldUID {
		return "", fmt.Errorf("legacy old UID changed")
	}
	if oldErr != nil && !apierrors.IsNotFound(oldErr) {
		return "", oldErr
	}
	if (r.Phase == "prepared" || r.Phase == "promoted") && oldErr == nil && old.Labels[labelRole] == roleLeader && podReady(old) && next.Labels[labelRole] == roleShadow {
		pol, e := receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
		if e != nil {
			return "", e
		}
		if e := warmCurrentScope(pol, *r, old, next); e != nil {
			return "", e
		}
		if e := journalFinish(ctx, ec, cm); e != nil {
			return "", e
		}
		return "legacy pair UID-verified unpromoted/rolled back; receipt finished", nil
	}
	if r.Phase == "rewarmed" && r.RewarmUID != "" {
		bound := &corev1.Pod{}
		if e := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.RewarmName}, bound); e == nil && string(bound.UID) == r.RewarmUID {
			return "legacy UID-bound clone observed; lifecycle safety uncertified", fmt.Errorf("legacy warm receipt requires explicit reconciliation")
		}
	}
	return "legacy serving survivor retained; no synthetic clone retry", fmt.Errorf("legacy warm receipt requires explicit reconciliation")
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
