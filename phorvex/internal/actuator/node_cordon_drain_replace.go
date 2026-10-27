/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * node-cordon-drain-replace: the node RECYCLE for a container→host escape (AML.T0105). It
 * cordons the compromised node (spec.unschedulable=true, so no new workload lands on the hostile
 * host), gracefully DRAINS it (Eviction API on the node's controller-owned, reschedulable pods —
 * DaemonSet/mirror/terminating pods skipped, exactly as `kubectl drain`), then triggers REPLACEMENT
 * by deleting the Node object (in a managed node group / with a node-termination handler this
 * recycles the underlying instance). The node is DERIVED from the bound Pod's live spec.nodeName —
 * never from attacker-influenceable event free-text — so a forged event cannot name an arbitrary
 * node. Cordon is reversible; the node delete is terminal (like rotate's eviction, scaled to a node).
 */

package actuator

import (
	"context"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

type nodeCordonDrainReplaceHandler struct{}

func (nodeCordonDrainReplaceHandler) Name() string { return string(model.ActionNodeCordonDrainReplace) }

const (
	// nodeRecycleSnap records the node's prior spec.unschedulable so an uncordon rollback is exact.
	nodeRecycleSnap  = "phorvex.ai/node-recycle-snapshot"
	nodeRecycleEpoch = "phorvex.ai/node-recycle-epoch"
	nodeRecycleOf    = "phorvex.ai/node-recycle-of" // target pod UID whose host-escape triggered the recycle
	// nodeDrainGraceSeconds bounds the graceful eviction; the owning controllers respawn the pods.
	nodeDrainGraceSeconds int64 = 30
)

type nodeRecycleSnapshot struct {
	Version           int    `json:"version"`
	NodeName          string `json:"nodeName"`
	NodeUID           string `json:"nodeUID"`
	UnschedulBefore   bool   `json:"unschedulableBefore"`
	TargetPodUID      string `json:"targetPodUID"`
}

func (nodeCordonDrainReplaceHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	if ec.Reader == nil {
		return HandlerResult{}, fmt.Errorf("node-cordon-drain-replace: authoritative reader unavailable")
	}
	if ec.Client == nil {
		return HandlerResult{}, fmt.Errorf("node-cordon-drain-replace: mutation client unavailable")
	}
	o := req.NodeEscapeObservation
	if o == nil || o.NodeName == "" {
		return HandlerResult{}, fmt.Errorf("node-cordon-drain-replace: no bound node/host-escape observation on the request")
	}

	// Enact-time authority re-check: the selection-time observation must still bind THIS exact live
	// Pod UID, and the node to recycle is DERIVED from the live Pod's spec.nodeName (never the event).
	pod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return HandlerResult{NoEffect: NoEffectSatisfied, Note: "node-cordon-drain-replace: target pod already gone"}, nil
		}
		return HandlerResult{}, err
	}
	if pod.UID == "" || o.TargetPodUID != string(pod.UID) || (req.TargetUID != "" && req.TargetUID != string(pod.UID)) {
		return HandlerResult{NoEffect: NoEffectRefused, Note: "node-cordon-drain-replace: target UID unavailable or mismatched"}, nil
	}
	if pod.Spec.NodeName == "" || pod.Spec.NodeName != o.NodeName {
		// SAFETY GATE: the recycle target must be the node the pod ACTUALLY runs on. Refuse any
		// drift between the bound observation and the live pod→node binding — never recycle an
		// attacker-chosen or stale node.
		return HandlerResult{NoEffect: NoEffectRefused, Note: "node-cordon-drain-replace: live pod node is empty or differs from the bound node; refusing"}, nil
	}
	nodeName := pod.Spec.NodeName

	node := &corev1.Node{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: nodeName}, node); err != nil {
		if apierrors.IsNotFound(err) {
			return HandlerResult{NoEffect: NoEffectSatisfied, Note: "node-cordon-drain-replace: node " + nodeName + " already gone (already recycled)"}, nil
		}
		return HandlerResult{}, err
	}
	nodeUID := string(node.UID)

	result := HandlerResult{
		MutationKind: "forward-only",
		RollbackRef:  "node/" + nodeName + "@" + nodeUID,
	}

	// 1) CORDON — mark unschedulable so no new workload lands on the hostile host. Reversible; a
	//    snapshot of the prior state is stamped for an exact uncordon rollback.
	if !node.Spec.Unschedulable {
		snap := nodeRecycleSnapshot{Version: 1, NodeName: nodeName, NodeUID: nodeUID, UnschedulBefore: node.Spec.Unschedulable, TargetPodUID: string(pod.UID)}
		data, _ := json.Marshal(snap)
		after := node.DeepCopy()
		after.Spec.Unschedulable = true
		after.Annotations = ensureMap(after.Annotations)
		after.Annotations[nodeRecycleSnap] = string(data)
		after.Annotations[nodeRecycleEpoch] = node.ResourceVersion
		after.Annotations[nodeRecycleOf] = string(pod.UID)
		if err := ec.Client.Update(ctx, after); err != nil {
			return result, fmt.Errorf("node-cordon-drain-replace: cordon %s: %w", nodeName, err)
		}
	}
	result.ObjectsTouched = append(result.ObjectsTouched, objRef("Node", "", nodeName))

	// 2) DRAIN — gracefully evict the node's controller-owned, reschedulable pods. DaemonSet/mirror/
	//    already-terminating pods are skipped (standard `kubectl drain` semantics). PDB backpressure
	//    (429) is recorded, not fatal: the node delete below is the backstop that evacuates residuals.
	evicted, skipped, blocked := 0, 0, 0
	var podList corev1.PodList
	if err := ec.Reader.List(ctx, &podList); err != nil {
		return result, fmt.Errorf("node-cordon-drain-replace: list pods for drain: %w", err)
	}
	for i := range podList.Items {
		p := &podList.Items[i]
		if p.Spec.NodeName != nodeName {
			continue
		}
		if !drainEligible(p) {
			skipped++
			continue
		}
		grace := nodeDrainGraceSeconds
		if p.Spec.TerminationGracePeriodSeconds != nil && *p.Spec.TerminationGracePeriodSeconds >= 0 && *p.Spec.TerminationGracePeriodSeconds < grace {
			grace = *p.Spec.TerminationGracePeriodSeconds
		}
		evPod := p
		eviction := &policyv1.Eviction{
			ObjectMeta:    metav1.ObjectMeta{Namespace: p.Namespace, Name: p.Name},
			DeleteOptions: &metav1.DeleteOptions{GracePeriodSeconds: &grace},
		}
		if err := ec.Client.SubResource("eviction").Create(ctx, evPod, eviction); err != nil {
			if apierrors.IsTooManyRequests(err) {
				blocked++
				continue
			}
			if apierrors.IsNotFound(err) {
				continue // raced away
			}
			if apierrors.IsForbidden(err) {
				return result, fmt.Errorf("node-cordon-drain-replace: eviction permission denied for %s/%s: %w", p.Namespace, p.Name, err)
			}
			return result, fmt.Errorf("node-cordon-drain-replace: evict %s/%s: %w", p.Namespace, p.Name, err)
		}
		evicted++
		result.ObjectsTouched = append(result.ObjectsTouched, objRef("Pod", p.Namespace, p.Name))
	}

	// 3) REPLACE — delete the Node object (UID-guarded), triggering its replacement. In a managed
	//    node group / with a node-termination handler this recycles the underlying instance; here it
	//    is the terminal "recycle this host" signal and the backstop that evacuates any residual pods.
	delNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}
	delOpts := &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: nodeUIDPtr(nodeUID)}}
	if err := ec.Client.Delete(ctx, delNode, delOpts); err != nil {
		if apierrors.IsNotFound(err) || apierrors.IsConflict(err) {
			result.Note = fmt.Sprintf("node %s cordoned; drained evicted=%d skipped=%d pdb-blocked=%d; node already gone/changed before delete", nodeName, evicted, skipped, blocked)
			result.Emitted = true
			return result, nil
		}
		return result, fmt.Errorf("node-cordon-drain-replace: delete node %s: %w", nodeName, err)
	}

	result.Emitted = true
	result.Note = fmt.Sprintf("node %s recycled: cordoned + drained (evicted=%d skipped-daemonset/mirror=%d pdb-blocked=%d) + Node deleted (replacement is node-group/instance-lifecycle driven)", nodeName, evicted, skipped, blocked)
	return result, nil
}

// Rollback uncordons the node IF it still exists (cordon is reversible until the delete). Once the
// Node is deleted the recycle is terminal — like rotate's eviction — so rollback is a safe no-op.
func (nodeCordonDrainReplaceHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	if ec.DryRun {
		return errDryRunGuard
	}
	o := req.NodeEscapeObservation
	if o == nil || o.NodeName == "" {
		return nil
	}
	node := &corev1.Node{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Name: o.NodeName}, node); err != nil {
		if apierrors.IsNotFound(err) {
			return nil // node gone: replace is terminal, nothing to roll back
		}
		return err
	}
	var snap nodeRecycleSnapshot
	if err := json.Unmarshal([]byte(node.Annotations[nodeRecycleSnap]), &snap); err != nil {
		return nil // no snapshot we wrote; leave the node as-is
	}
	if snap.UnschedulBefore {
		return nil // was already unschedulable before us; nothing to restore
	}
	restored := node.DeepCopy()
	restored.Spec.Unschedulable = false
	delete(restored.Annotations, nodeRecycleSnap)
	delete(restored.Annotations, nodeRecycleEpoch)
	delete(restored.Annotations, nodeRecycleOf)
	return ec.Client.Update(ctx, restored)
}

func nodeUIDPtr(uid string) *types.UID {
	u := types.UID(uid)
	return &u
}

// drainEligible reports whether a pod should be gracefully evicted during a node drain: it must be
// controller-owned and reschedulable. DaemonSet-owned, static/mirror, and already-terminating pods
// are skipped — exactly `kubectl drain --ignore-daemonsets` semantics.
func drainEligible(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil && !p.DeletionTimestamp.IsZero() {
		return false
	}
	if _, isMirror := p.Annotations["kubernetes.io/config.mirror"]; isMirror {
		return false
	}
	owner := metav1.GetControllerOf(p)
	if owner == nil {
		return false // bare pod: not auto-rescheduled; drain skips it (would need --force)
	}
	if owner.Kind == "DaemonSet" {
		return false
	}
	return true
}

func init() { HandlerRegistry.Register(nodeCordonDrainReplaceHandler{}) }
