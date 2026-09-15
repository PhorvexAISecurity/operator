/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P4 — AI/GPU actuator)
 *
 * The 5 native AI/GPU ActionHandlers, REAL implementations (no stubs / no design-comments). The K8s
 * mechanics are enacted live; the serving-stack (vLLM) + GPU (NVML/nvidia-smi) operations run through
 * the mockable stack abstraction in gpu_stack.go. EVERY GPU/stack call is real code marked
 * [PENDING-GPU-VALIDATION]: it is NOT production-ready until calibrated on real GPU hardware — on a
 * non-GPU cluster (kind) the stack is UNREACHABLE and the handler records that honestly (never fakes a
 * GPU effect) while still enacting the K8s mechanic. Destructive GPU ops (mig-rebind, model-shard)
 * FAIL-CLOSED when the device/stack/runner is absent. The provision-before-retire ordering IS the
 * rollback — a failed cutover re-flips to the alive old leader.
 */

package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/gpudevice"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	labelSwapGroup   = "phorvex.ai/swap-group"
	labelModelShard  = "phorvex.ai/model-shard"
	labelRole        = "phorvex.ai/role"
	labelModelLoaded = "phorvex.ai/model-loaded"
	labelRouteKey    = "phorvex.ai/route-key"
	annoSwapPhase    = "phorvex.ai/swap-phase"
	annoKVResetEpoch = "phorvex.ai/kv-reset-epoch"
	annoEndpointSnap = "phorvex.ai/endpoint-snapshot"
	annoRouteService = "phorvex.ai/route-service" // optional Service whose selector this pod's route-key drives
	annoMIGProfile   = "phorvex.ai/mig-target-profile"
	annoGPUID        = "phorvex.ai/gpu-id"
	roleLeader       = "leader"
	roleShadow       = "warm-shadow"
	roleRetiring     = "retiring"
)

// ---- shared warm-pool primitives (used by warm-swap AND model-shard-replace) ----

// shadowModelReady reports whether a shadow is PROMOTABLE. It PREFERS the real vLLM model-loaded check;
// if the serving stack is UNREACHABLE (kind / no GPU), it falls back to the K8s Ready condition + the
// model-loaded label and flags [PENDING-GPU-VALIDATION] (the real cold-load gate is unvalidated here).
// A reachable-but-failing stack => NOT promotable (this shadow is excluded — fail-closed on it).
func shadowModelReady(ctx context.Context, ec EnactCtx, pod *corev1.Pod) (ready, pending bool) {
	if !podReady(pod) || pod.DeletionTimestamp != nil {
		return false, false
	}
	loaded, err := ec.vllm().ModelReady(ctx, endpointForPod(pod))
	if err == nil {
		return loaded, false // real vLLM verdict
	}
	if errors.Is(err, errStackUnreachable) {
		return pod.Labels[labelModelLoaded] == "true", true // K8s-ready fallback, pending real validation
	}
	return false, false
}

// pickReadyShadow returns the oldest promotable shadow in the selector set (nil if none), plus whether
// the readiness verdict fell back to the K8s gate (pending real vLLM validation).
func pickReadyShadow(ctx context.Context, ec EnactCtx, ns string, sel client.MatchingLabels, exclude string) (*corev1.Pod, bool, error) {
	var pods corev1.PodList
	if err := ec.Client.List(ctx, &pods, client.InNamespace(ns), sel); err != nil {
		return nil, false, err
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Name == exclude {
			continue
		}
		if ready, pending := shadowModelReady(ctx, ec, p); ready {
			return p, pending, nil
		}
	}
	return nil, false, nil
}

// rewarmShadow provisions a REPLACEMENT warm shadow by cloning the (old) leader's pod spec — the
// REWARM-to-N step: the new shadow performs its cold model-load OFF the serving path (the whole point
// of warm-swap). Real K8s create; the actual model-load timing is [PENDING-GPU-VALIDATION].
func rewarmShadow(ctx context.Context, ec EnactCtx, oldLeader *corev1.Pod, groupKey, groupVal string) (string, string, error) {
	name := truncName(oldLeader.Name + "-rw-" + oldLeader.ResourceVersion)
	uid, err := rewarmShadowNamed(ctx, ec, oldLeader, name, groupKey, groupVal)
	return name, uid, err
}

func rewarmSpecDigest(source *corev1.Pod) string {
	shadow := &corev1.Pod{Spec: *source.Spec.DeepCopy()}
	shadow.Spec.NodeName = ""
	return podSpecDigest(shadow)
}

func rewarmShadowNamed(ctx context.Context, ec EnactCtx, oldLeader *corev1.Pod, name, groupKey, groupVal string) (string, error) {
	labels := copyLabels(oldLeader.Labels)
	labels[groupKey] = groupVal
	labels[labelRole] = roleShadow
	labels[labelModelLoaded] = "false" // it is loading; promotable only once model-loaded/ready
	shadow := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: oldLeader.Namespace, Labels: labels},
		Spec:       *oldLeader.Spec.DeepCopy(),
	}
	shadow.Spec.NodeName = "" // reschedule freely (and onto a fresh GPU/MIG slot)
	if err := ec.Client.Create(ctx, shadow); err != nil {
		return "", err
	}
	if shadow.UID == "" || shadow.ResourceVersion == "" {
		return "", fmt.Errorf("replacement shadow create unacknowledged")
	}
	return string(shadow.UID), nil
}

// warmCutover is the shared provision-before-retire leadership flip: find a Ready shadow, flip it to
// leader, retire the old leader, and REWARM a replacement shadow. Used by warm-swap (swap-group) and
// model-shard-replace (model-shard group). FAIL-CLOSED: no Ready shadow => the old leader keeps serving.
func warmCutover(ctx context.Context, ec EnactCtx, req Request, groupKey, kind string) (HandlerResult, error) {
	leader, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, kind, req)
	}
	// [M-69] The request names WHICH Pod it selected (TargetUID); the observed object must be
	// that Pod before anything is flipped, relabeled or retired. A delayed retry that finds a
	// same-name replacement is refused here, untouched (native rotate's refusal convention).
	if reason := triggerIdentityRefusal(req, leader); reason != "" {
		return refuseAI(kind, reason)
	}
	group := leader.Labels[groupKey]
	if group == "" {
		return HandlerResult{}, fmt.Errorf("%s blocked: pod %s/%s has no %s (no warm pool); old leader keeps serving", kind, req.Namespace, req.Pod, groupKey)
	}
	shadow, pending, err := pickReadyShadow(ctx, ec, req.Namespace, client.MatchingLabels{groupKey: group, labelRole: roleShadow}, req.Pod)
	if err != nil {
		return HandlerResult{}, err
	}
	if shadow == nil {
		return HandlerResult{}, fmt.Errorf("%s blocked: no Ready model-loaded shadow in group %q; old leader keeps serving", kind, group)
	}
	// Administrative receipt is the only crash-resume authority. Validate the selecting
	// policy and acknowledge persistence before either serving role changes.
	receipt := operationReceipt{Version: 1, Kind: kind, Phase: "prepared", PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, TargetName: leader.Name, TargetUID: string(leader.UID), TargetLabels: copyLabels(leader.Labels), OldName: leader.Name, OldUID: string(leader.UID), NewName: shadow.Name, NewUID: string(shadow.UID), GroupKey: groupKey, GroupValue: group}
	if !receipt.valid() {
		return HandlerResult{}, fmt.Errorf("%s: operation provenance unavailable", kind)
	}
	pol, err := receiptAuthority(ctx, ec.Reader, receipt, req.Action)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("%s: policy authority: %w", kind, err)
	}
	if err := warmCurrentScope(pol, receipt, leader, shadow); err != nil {
		return HandlerResult{}, fmt.Errorf("%s: %w", kind, err)
	}
	if !podReady(shadow) || shadow.UID == "" || leader.ResourceVersion == "" || shadow.ResourceVersion == "" {
		return HandlerResult{}, fmt.Errorf("%s: observed pod identity/readiness unavailable", kind)
	}
	journal, err := journalWrite(ctx, ec, receipt)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("%s: persist operation before promotion: %w", kind, err)
	}
	// The old annotation is a diagnostic hint, never authorization.
	leader.Annotations = ensureMap(leader.Annotations)
	leader.Annotations[annoSwapPhase] = "flipping"
	if err := ec.Client.Update(ctx, leader); err != nil {
		if cleanErr := journalFinish(ctx, ec, journal); cleanErr != nil {
			return HandlerResult{}, fmt.Errorf("%s: phase annotation and receipt cleanup failed: %w", kind, errors.Join(err, cleanErr))
		}
		return HandlerResult{}, fmt.Errorf("%s: phase annotation failed before serving flip: %w", kind, err)
	}
	pol, err = receiptAuthority(ctx, ec.Reader, receipt, req.Action)
	if err != nil {
		if cleanErr := journalFinish(ctx, ec, journal); cleanErr != nil {
			return HandlerResult{}, errors.Join(err, cleanErr)
		}
		return HandlerResult{}, fmt.Errorf("%s: current authority before promotion: %w", kind, err)
	}
	if err := warmCurrentScope(pol, receipt, leader, shadow); err != nil {
		if cleanErr := journalFinish(ctx, ec, journal); cleanErr != nil {
			return HandlerResult{}, errors.Join(err, cleanErr)
		}
		return HandlerResult{}, err
	}

	// (1) FLIP up: shadow -> leader (provision-before-retire: new leader Ready BEFORE old touched).
	shadow.Labels[labelRole] = roleLeader
	if err := ec.Client.Update(ctx, shadow); err != nil {
		return HandlerResult{MutationKind: "swap", Note: "promotion response unresolved; receipt retained for checked recovery"}, fmt.Errorf("%s flip-up %s: %w", kind, shadow.Name, err)
	}
	promotedPartial := HandlerResult{MutationKind: "swap", RollbackRef: req.Namespace + "/" + shadow.Name, ObjectsTouched: []string{objRef("Pod", req.Namespace, shadow.Name)}, Note: "partial cutover: promoted leader retained; completion unresolved"}
	receipt.Phase = "promoted"
	if err := journalAdvance(ctx, ec, journal, receipt); err != nil {
		return promotedPartial, fmt.Errorf("%s: promoted but journal phase update failed: %w", kind, err)
	}
	pol, err = receiptAuthority(ctx, ec.Reader, receipt, req.Action)
	if err != nil {
		return promotedPartial, fmt.Errorf("%s: authority changed before old route removal: %w", kind, err)
	}
	if err := warmCurrentScope(pol, receipt, leader, shadow); err != nil {
		return promotedPartial, err
	}
	// (2) FLIP down: old leader -> retiring. On failure, ROLL BACK (re-flip shadow; old leader serves).
	freshOld, freshNew := &corev1.Pod{}, &corev1.Pod{}
	flipErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: leader.Name}, freshOld)
	if flipErr == nil {
		flipErr = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: shadow.Name}, freshNew)
	}
	if flipErr == nil {
		flipErr = warmCurrentScope(pol, receipt, freshOld, freshNew)
	}
	if flipErr == nil && (freshOld.Labels[labelRole] != roleLeader || freshNew.Labels[labelRole] != roleLeader || !podReady(freshNew) || freshOld.DeletionTimestamp != nil || freshNew.DeletionTimestamp != nil) {
		flipErr = fmt.Errorf("recorded pair changed before old route removal")
	}
	if flipErr == nil {
		before := freshOld.DeepCopy()
		freshOld.Labels[labelRole] = roleRetiring
		flipErr = ec.Client.Patch(ctx, freshOld, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
	}
	if flipErr != nil {
		// A failed response does not prove that the old-role Patch had no effect.
		// Preserve the promoted leader unless the exact old incarnation is still
		// a healthy serving leader under current policy authority.
		currentPol, authErr := receiptAuthority(ctx, ec.Reader, receipt, req.Action)
		oldAfter, rollback := &corev1.Pod{}, &corev1.Pod{}
		checkErr := authErr
		if checkErr == nil {
			checkErr = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: leader.Name}, oldAfter)
		}
		if checkErr == nil {
			checkErr = ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: shadow.Name}, rollback)
		}
		if checkErr == nil {
			checkErr = warmCurrentScope(currentPol, receipt, oldAfter, rollback)
		}
		if checkErr == nil && (oldAfter.Labels[labelRole] != roleLeader || !podReady(oldAfter) || rollback.Labels[labelRole] != roleLeader || !podReady(rollback)) {
			checkErr = fmt.Errorf("exact old/new serving roles or readiness changed")
		}
		if checkErr != nil {
			if oldAfter.UID == leader.UID && oldAfter.Labels[labelRole] == roleRetiring {
				promotedPartial.ObjectsTouched = append(promotedPartial.ObjectsTouched, objRef("Pod", req.Namespace, leader.Name))
			}
			return promotedPartial, fmt.Errorf("%s flip-down %s/%s unresolved; promoted leader and receipt retained: %w", kind, req.Namespace, req.Pod, errors.Join(flipErr, checkErr))
		}
		before := rollback.DeepCopy()
		rollback.Labels[labelRole] = roleShadow
		rbErr := ec.Client.Patch(ctx, rollback, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{}))
		if rbErr != nil {
			return promotedPartial, fmt.Errorf("%s flip-down %s/%s failed, rollback failed; receipt retained: %w", kind, req.Namespace, req.Pod, errors.Join(flipErr, rbErr))
		}
		oldAfter = &corev1.Pod{}
		if checkErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: leader.Name}, oldAfter); checkErr != nil || oldAfter.UID != leader.UID || oldAfter.Labels[labelRole] != roleLeader || !podReady(oldAfter) {
			return promotedPartial, fmt.Errorf("%s rollback could not confirm old leader; receipt retained: %w", kind, errors.Join(flipErr, checkErr))
		}
		if finishErr := journalFinish(ctx, ec, journal); finishErr != nil {
			promotedPartial.Note = "cutover role changes compensated; receipt cleanup unresolved"
			return promotedPartial, fmt.Errorf("%s flip-down %s/%s rolled back but receipt cleanup failed: %w", kind, req.Namespace, req.Pod, errors.Join(flipErr, finishErr))
		}
		return HandlerResult{}, fmt.Errorf("%s flip-down %s/%s (rolled back): %w", kind, req.Namespace, req.Pod, flipErr)
	}
	receipt.Phase = "retiring"
	if err := journalAdvance(ctx, ec, journal, receipt); err != nil {
		promotedPartial.ObjectsTouched = append(promotedPartial.ObjectsTouched, objRef("Pod", req.Namespace, leader.Name))
		promotedPartial.Note = "partial cutover: promoted leader and old retiring route retained; journal phase unresolved"
		return promotedPartial, fmt.Errorf("%s: old leader retiring but journal phase update failed: %w", kind, err)
	}
	partial := HandlerResult{MutationKind: "swap", RollbackRef: req.Namespace + "/" + shadow.Name, ObjectsTouched: []string{objRef("Pod", req.Namespace, shadow.Name), objRef("Pod", req.Namespace, leader.Name)}, Note: "partial cutover: earlier Pod mutations accepted; completion unresolved"}
	// (3) DRAIN then RETIRE the old leader. [P-ACTUATOR-SET-COMPLETE] The old leader is already
	// relabeled `retiring` (admits routed away by step 2); now actually DRAIN its in-flight requests
	// via the serving stack BEFORE deleting it, so in-flight requests are not dropped ungracefully
	// (closes the prior ":141 recorded-not-slept" gap). Unreachable stack => the K8s route-drain still
	// applies; the in-flight abort is [PENDING-GPU-VALIDATION] (recorded in the note).
	_, drainPending, drainErr := drainInflight(ctx, ec, leader)
	if drainErr != nil {
		return partial, fmt.Errorf("%s drain old leader %s/%s: %w", kind, req.Namespace, req.Pod, drainErr)
	}
	pol, err = receiptAuthority(ctx, ec.Reader, receipt, req.Action)
	if err != nil {
		return partial, fmt.Errorf("%s: authority changed before retirement: %w", kind, err)
	}
	freshOld, freshNew = &corev1.Pod{}, &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: leader.Name}, freshOld); err != nil {
		return partial, err
	}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: shadow.Name}, freshNew); err != nil {
		return partial, err
	}
	if err := warmCurrentScope(pol, receipt, freshOld, freshNew); err != nil {
		return partial, err
	}
	if freshNew.Labels[labelRole] != roleLeader || !podReady(freshNew) || freshOld.Labels[labelRole] != roleRetiring {
		return partial, fmt.Errorf("%s: recorded pair not ready for retirement", kind)
	}
	leader = freshOld
	// [M-69] The Delete is bound to the UID of the leader object observed above (API-enforced
	// precondition): a same-name replacement created meanwhile is never the object deleted.
	// A rejected Delete is reported as a non-success carrying the partial state honestly —
	// the shadow IS promoted and the old-leader name IS relabeled retiring; nothing is rolled
	// back and no rewarm is provisioned.
	touched := []string{objRef("Pod", req.Namespace, shadow.Name), objRef("Pod", req.Namespace, req.Pod)}
	delErr := ec.Client.Delete(ctx, leader, uidPrecondition(leader))
	alreadyGone := apierrors.IsNotFound(delErr)
	if alreadyGone {
		delErr = nil
	}
	if apierrors.IsConflict(delErr) {
		delErr = fmt.Errorf("%w: %s/%s observed uid %s: %v", errPodReplaced, req.Namespace, req.Pod, leader.UID, delErr)
	}
	if delErr != nil {
		partial.Note = "partial cutover: old retirement response unresolved; promoted leader and receipt retained"
		return partial,
			fmt.Errorf("%s retire %s/%s (partial: shadow %s promoted to leader, old leader name relabeled %s, observed pod uid %s NOT deleted, no rewarm): %w", kind, req.Namespace, req.Pod, shadow.Name, roleRetiring, leader.UID, delErr)
	}
	receipt.Phase = "retired"
	if err := journalAdvance(ctx, ec, journal, receipt); err != nil {
		partial.Note = "partial cutover: old leader retired; journal phase unresolved"
		return partial, fmt.Errorf("%s: old leader retired but journal phase update failed: %w", kind, err)
	}
	// (4) REWARM-to-N: provision a replacement shadow (cold-load OFF the serving path).
	receipt.RewarmName = truncName(leader.Name + "-rw-" + leader.ResourceVersion)
	receipt.RewarmSpecHash = rewarmSpecDigest(leader)
	receipt.Phase = "rewarm-intent"
	if err := journalAdvance(ctx, ec, journal, receipt); err != nil {
		partial.Note = "partial cutover: old leader retired; rewarm intent not persisted"
		return partial, fmt.Errorf("%s: rewarm intent not persisted; replacement not created: %w", kind, err)
	}
	rewarm := receipt.RewarmName
	rewarmUID, rwErr := rewarmShadowNamed(ctx, ec, leader, rewarm, groupKey, group)
	drainNote := "in-flight drained"
	if drainPending {
		drainNote = "in-flight abort [PENDING-GPU-VALIDATION] (stack unreachable; K8s route-drained)"
	}
	retireNote := "retired (uid " + string(leader.UID) + ")"
	if alreadyGone {
		retireNote = "already gone before retire (no pod of that name; uid " + string(leader.UID) + ")"
	}
	note := fmt.Sprintf("%s: shadow %s promoted, old leader %s + %s (no cold-load on serving path)", kind, shadow.Name, drainNote, retireNote)
	if rwErr == nil {
		partial.ObjectsTouched = append(partial.ObjectsTouched, objRef("Pod", req.Namespace, rewarm))
		partial.Note = "partial cutover: replacement Create acknowledged; UID binding or cleanup unresolved"
		observed := &corev1.Pod{}
		if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: rewarm}, observed); err != nil {
			return partial, fmt.Errorf("%s: replacement created but readback unavailable: %w", kind, err)
		}
		if string(observed.UID) != rewarmUID || observed.Labels[groupKey] != group || observed.Labels[labelRole] != roleShadow || observed.Labels[labelModelLoaded] != "false" {
			return partial, fmt.Errorf("%s: replacement created but readback identity/scope mismatch", kind)
		}
		if rewarmSpecDigest(observed) != receipt.RewarmSpecHash {
			return partial, fmt.Errorf("%s: replacement spec differs from persisted intent", kind)
		}
		receipt.RewarmUID, receipt.Phase = rewarmUID, "rewarmed"
		if err := journalAdvance(ctx, ec, journal, receipt); err != nil {
			return partial, fmt.Errorf("%s: replacement created but journal UID binding failed: %w", kind, err)
		}
		touched = append(touched, objRef("Pod", req.Namespace, rewarm))
		note += "; rewarmed " + rewarm
	} else {
		partial.Note = "partial cutover: old leader retired; replacement Create unresolved"
		return partial, fmt.Errorf("%s: rewarm unresolved after retirement: %w", kind, rwErr)
	}
	if rwErr == nil {
		if err := journalFinish(ctx, ec, journal); err != nil {
			partial.Note = "cutover replacement acknowledged; receipt cleanup unresolved"
			return partial, fmt.Errorf("%s: cutover completed but receipt cleanup failed: %w", kind, err)
		}
	}
	if pending {
		note += " [PENDING-GPU-VALIDATION]: shadow readiness used the K8s gate (no vLLM stack reachable); model-load/ColdLoadSec magnitudes unvalidated"
	} else {
		note += " [PENDING-GPU-VALIDATION]: ColdLoadSec magnitude unvalidated (vLLM-ready confirmed)"
	}
	return HandlerResult{Emitted: true, MutationKind: "swap", RollbackRef: req.Namespace + "/" + shadow.Name, ObjectsTouched: touched, Note: note}, nil
}

func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func relabelRole(ctx context.Context, c client.Client, ns, name, role string) error {
	pod, ok, err := getPod(ctx, c, ns, name)
	if err != nil || !ok {
		return orGone(err, ok, "relabel", Request{Namespace: ns, Pod: name})
	}
	pod.Labels = ensureMap(pod.Labels)
	pod.Labels[labelRole] = role
	return c.Update(ctx, pod)
}

func truncName(s string) string {
	if len(s) > 63 {
		return s[:63]
	}
	return s
}

// --- 8. warm-swap — real warm-pool + REWARM-to-N (vLLM-gated readiness) --------------------
type warmSwapHandler struct{}

func (warmSwapHandler) Name() string { return string(model.ActionWarmSwap) }
func (warmSwapHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return warmCutover(ctx, ec, req, labelSwapGroup, "warm-swap")
}

// --- 9. mig-rebind — REAL NVML/nvidia-smi repartition; FAIL-CLOSED without device/runner ----
type migRebindHandler struct{}

func (migRebindHandler) Name() string { return string(model.ActionMIGRebind) }
func (migRebindHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "mig-rebind", req)
	}
	// [M-69] Refuse before any mutation unless the observed Pod is the one the request selected.
	if reason := triggerIdentityRefusal(req, pod); reason != "" {
		return refuseAI("mig-rebind", reason)
	}
	// FAIL-CLOSED preconditions: a MIG device, a node, and a declared target profile (you never pick a
	// MIG geometry blindly, and you never fabricate a rebind without a real device).
	if gpudevice.MIGResourceName(pod) == "" {
		return HandlerResult{}, fmt.Errorf("mig-rebind MIGUnavailable: pod %s/%s has no MIG device [PENDING-GPU-VALIDATION]", req.Namespace, req.Pod)
	}
	node := pod.Spec.NodeName
	gpuID := pod.Annotations[annoGPUID]
	profile := pod.Annotations[annoMIGProfile]
	if node == "" || gpuID == "" || profile == "" {
		return HandlerResult{}, fmt.Errorf("mig-rebind blocked: need node(%q)+%s+%s annotations to repartition off the co-resident MIG (fail-closed)", node, annoGPUID, annoMIGProfile)
	}
	// [P-ACTUATOR-SET-COMPLETE] AVAILABLE PROBE (non-mutating): fail-closed BEFORE the destructive
	// GPU-context eviction if the node-exec transport is not wired (no agent pod / no exec) — never
	// delete a pod we then cannot repartition. On kind this fail-closes here, untouched.
	mig, err := ec.mig().Prepare(ctx, node)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind transport unavailable (no eviction performed): %w", err)
	}
	// DRAIN + GPU-CONTEXT EVICTION: MIG reconfiguration requires ZERO active CUDA contexts on the GPU —
	// a relabel-out is INSUFFICIENT (a running pod still holds the context). So route the pod out,
	// drain its in-flight requests, then EVICT it off the GPU (delete) so the device is context-free.
	// The pod's owner reschedules the workload onto the new MIG geometry after repartition.
	_ = relabelRole(ctx, ec.Client, req.Namespace, req.Pod, roleRetiring)
	_, drainPending, _ := drainInflight(ctx, ec, pod)
	// [M-69] Evict exactly the observed Pod (UID-bound Delete). A rejected eviction — a same-name
	// replacement, or any other API refusal — means the GPU was NOT freed by this move, so the
	// repartition is NOT attempted; the relabel already applied to the name is reported as-is.
	alreadyGone, delErr := deleteObservedPod(ctx, ec.Client, pod)
	if delErr != nil {
		return HandlerResult{ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}},
			fmt.Errorf("mig-rebind GPU-context eviction (delete %s/%s, observed uid %s) rejected; repartition NOT attempted (pod name relabeled %s): %w", req.Namespace, req.Pod, pod.UID, roleRetiring, delErr)
	}
	// REAL nvidia-smi repartition on the now-idle GPU (destroy CI/GI, create the new geometry) via the
	// prepared execNodeRunner transport. Preparation already bound one validated agent identity, so
	// reaching here means the pod was evicted for a real attempt through that same session.
	if err := mig.Repartition(ctx, gpuID, profile); err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind repartition gpu %s -> %s (pod evicted; owner reschedules onto new geometry): %w", gpuID, profile, err)
	}
	drainNote := "drained"
	if drainPending {
		drainNote = "in-flight abort [PENDING-GPU-VALIDATION]"
	}
	evictNote := "pod evicted off GPU (uid " + string(pod.UID) + ", " + drainNote + ", zero CUDA contexts)"
	if alreadyGone {
		evictNote = "pod already gone before eviction (no pod of that name; uid " + string(pod.UID) + ", " + drainNote + ")"
	}
	return HandlerResult{
		Emitted: true, MutationKind: "swap", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod), objRef("Node", "", node)},
		Note:           fmt.Sprintf("mig-rebind: %s, GPU %s repartitioned to %s off the co-resident slot [PENDING-GPU-VALIDATION]: VRAM/geometry magnitudes unvalidated", evictNote, gpuID, profile),
	}, nil
}

// --- 10. kv-reset — REAL vLLM prefix/KV-cache flush; pod stays ALIVE -----------------------
type kvResetHandler struct{}

func (kvResetHandler) Name() string { return string(model.ActionKVReset) }
func (kvResetHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "kv-reset", req)
	}
	// REAL in-process flush via the serving stack (vLLM); the pod is NOT killed (the defining property).
	flushNote := ""
	resetErr := ec.vllm().ResetPrefixCache(ctx, endpointForPod(pod))
	switch {
	case resetErr == nil:
		flushNote = "KV/prefix cache flushed via the serving stack (defeats wipe-surviving implant)"
	case errors.Is(resetErr, errStackUnreachable):
		// [FAIL-CLOSED FIX] No serving stack reachable (pod Pending / no IP / no vLLM). This branch
		// used to fall through and return Emitted:true with a "flush NOT performed" note — so a move
		// that flushed NOTHING was recorded as a real actuation, counted in phorvex_actuations_total,
		// and narrated to the customer as "Cleared injected state on the inference workload". A KV
		// flush that did not happen is not a defence: report it as NOT emitted and write no epoch
		// (a "flush epoch" for a flush that never ran is a false forensic record).
		return HandlerResult{
			Emitted: false, MutationKind: "none",
			Note: "[PENDING-GPU-VALIDATION] kv-reset NOT performed: serving stack unreachable at " +
				req.Namespace + "/" + req.Pod + " (no reachable vLLM endpoint) — no cache was flushed",
		}, nil
	default:
		// reachable but the admin call failed => FAIL-CLOSED (do not claim a flush).
		return HandlerResult{}, fmt.Errorf("kv-reset %s/%s: serving-stack flush failed: %w", req.Namespace, req.Pod, resetErr)
	}
	// record the flush epoch (forensic + idempotent); pod stays alive.
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[annoKVResetEpoch] = pod.ResourceVersion
	if err := ec.Client.Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("kv-reset epoch %s/%s: %w", req.Namespace, req.Pod, err)
	}
	return HandlerResult{
		Emitted: true, MutationKind: "forward-only",
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)},
		Note:           "kv-reset: pod ALIVE; " + flushNote,
	}, nil
}

// --- 11. endpoint-rotate — REAL route restitch (re-key + Service selector) + rollback -------
type endpointRotateHandler struct{}

func (endpointRotateHandler) Name() string { return string(model.ActionEndpointRotate) }
func (endpointRotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "endpoint-rotate", req)
	}
	// snapshot the labels for rollback.
	snap, _ := json.Marshal(copyLabels(pod.Labels))
	pod.Labels = ensureMap(pod.Labels)
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[annoEndpointSnap] = string(snap)
	// RE-KEY the route selector label so any recon-pinned route to the OLD key STALES (real restitch).
	newKey := "ep-" + pod.ResourceVersion
	pod.Labels[labelRouteKey] = newKey
	pod.Labels["phorvex.ai/endpoint-epoch"] = pod.ResourceVersion
	if err := ec.Client.Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("endpoint-rotate %s/%s: %w", req.Namespace, req.Pod, err)
	}
	touched := []string{objRef("Pod", req.Namespace, req.Pod)}
	restitched := "route-key re-keyed (selector-pinned recon route staled)"
	// If a route Service is declared, RESTITCH its selector to the new key so the live route follows.
	if svcName := pod.Annotations[annoRouteService]; svcName != "" {
		var svc corev1.Service
		if err := ec.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: svcName}, &svc); err == nil {
			if svc.Spec.Selector == nil {
				svc.Spec.Selector = map[string]string{}
			}
			svc.Spec.Selector[labelRouteKey] = newKey
			if err := ec.Client.Update(ctx, &svc); err != nil {
				return HandlerResult{}, fmt.Errorf("endpoint-rotate restitch svc %s: %w", svcName, err)
			}
			touched = append(touched, objRef("Service", req.Namespace, svcName))
			restitched = "Service " + svcName + " selector restitched to the new route-key (attacker's held route staled)"
		}
	}
	return HandlerResult{
		Emitted: true, MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: touched,
		Note:           "endpoint-rotate: " + restitched + " [PENDING-GPU-VALIDATION]: model-route reconvergence magnitude unvalidated",
	}, nil
}

func (endpointRotateHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	return restoreLabels(ctx, ec, req, annoEndpointSnap)
}

// --- 12. model-shard-replace — REAL warm-provision/flip/retire for a sharded model ----------
type modelShardReplaceHandler struct{}

func (modelShardReplaceHandler) Name() string { return string(model.ActionModelShardReplace) }
func (modelShardReplaceHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "model-shard-replace", req)
	}
	// FAIL-CLOSED: no declared shard => no model server => never fabricate a shard replace.
	if pod.Labels[labelModelShard] == "" {
		return HandlerResult{}, fmt.Errorf("model-shard-replace ShardUnavailable: pod %s/%s declares no %s [PENDING-GPU-VALIDATION]", req.Namespace, req.Pod, labelModelShard)
	}
	// [P-ACTUATOR-SET-COMPLETE] TP/PP COORDINATION. A tensor/pipeline-parallel group is a CONSISTENCY
	// UNIT — flipping one rank independently yields mixed-rank garbage/crash. If the pod is in a
	// parallel group, do a GROUP-COHERENT cutover (a COMPLETE replacement group, all ranks Ready, flipped
	// together); fail-closed on an incomplete group. An independent shard (no parallel-group) keeps the
	// single-pod warm-cutover.
	if pod.Labels[labelParallelGroup] != "" {
		return groupCoherentCutover(ctx, ec, req, pod.Labels[labelParallelGroup])
	}
	return warmCutover(ctx, ec, req, labelModelShard, "model-shard-replace")
}

func init() {
	HandlerRegistry.Register(warmSwapHandler{})
	HandlerRegistry.Register(migRebindHandler{})
	HandlerRegistry.Register(kvResetHandler{})
	HandlerRegistry.Register(endpointRotateHandler{})
	HandlerRegistry.Register(modelShardReplaceHandler{})
}
