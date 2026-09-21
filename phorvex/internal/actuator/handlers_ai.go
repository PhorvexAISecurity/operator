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
	"errors"
	"fmt"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/gpudevice"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/servingcontext"
)

const (
	labelSwapGroup   = "phorvex.ai/swap-group"
	labelModelShard  = "phorvex.ai/model-shard"
	labelRole        = "phorvex.ai/role"
	labelModelLoaded = "phorvex.ai/model-loaded"
	labelRouteKey    = "phorvex.ai/route-key"
	annoSwapPhase    = "phorvex.ai/swap-phase"
	annoKVResetEpoch = "phorvex.ai/kv-reset-epoch"
	annoRouteService = "phorvex.ai/route-service" // optional Service whose selector this pod's route-key drives
	annoMIGProfile   = "phorvex.ai/mig-target-profile"
	annoGPUID        = "phorvex.ai/gpu-id"
	roleLeader       = "leader"
	roleShadow       = "warm-shadow"
	roleRetiring     = "retiring"

	warmCandidateAttemptLimit = 4
)

var errWarmCandidateAttemptBudget = errors.New("warm candidate readiness attempt budget exhausted")

// ---- shared warm-pool primitives (used by warm-swap AND model-shard-replace) ----

// shadowModelReady reports whether a shadow is PROMOTABLE. It PREFERS the real vLLM model-loaded check;
// if the serving stack is UNREACHABLE (kind / no GPU), it falls back to the K8s Ready condition + the
// model-loaded label and flags [PENDING-GPU-VALIDATION] (the real cold-load gate is unvalidated here).
// A reachable-but-failing stack => NOT promotable (this shadow is excluded — fail-closed on it).
func shadowModelReady(ctx context.Context, ec EnactCtx, pod *corev1.Pod) (ready, pending bool) {
	if !podReady(pod) || pod.DeletionTimestamp != nil {
		return false, false
	}
	req := ec.ServingRequest
	if req.Action == "" {
		req.Action = model.ActionWarmSwap
	}
	ep, endpointErr := servingEndpointForPod(ctx, ec, req, pod)
	if endpointErr != nil {
		return false, false
	}
	loaded, pending, _ := shadowModelReadyAtEndpoint(ctx, ec, pod, ep)
	return loaded, pending
}

// shadowModelReadyAtEndpoint preserves cancellation for bounded candidate traversal. Other
// readiness failures retain the existing meaning: this candidate is not promotable, while only a
// definitely unreachable stack may use the documented Kubernetes/model-loaded fallback.
func shadowModelReadyAtEndpoint(ctx context.Context, ec EnactCtx, pod *corev1.Pod, ep servingEndpoint) (ready, pending bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	loaded, err := ec.vllm().ModelReady(ctx, ep)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, false, ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false, false, err
	}
	if err == nil {
		return loaded, false, nil // real vLLM verdict
	}
	if errors.Is(err, errStackUnreachable) {
		return pod.Labels[labelModelLoaded] == "true", true, nil // K8s-ready fallback, pending real validation
	}
	return false, false, nil
}

// pickReadyShadow returns the oldest promotable shadow in the selector set (nil if none), plus whether
// the readiness verdict fell back to the K8s gate (pending real vLLM validation). Candidate inventory
// is an authoritative, complete bounded snapshot. Traversal is deterministic and refuses an unfinished
// candidate set rather than reporting that no Ready candidate exists.
func pickReadyShadow(ctx context.Context, ec EnactCtx, ns string, sel client.MatchingLabels, exclude string) (*corev1.Pod, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if ec.Reader == nil {
		return nil, false, fmt.Errorf("warm candidate authoritative reader unavailable")
	}
	var pods corev1.PodList
	if err := ec.Reader.List(ctx, &pods, client.InNamespace(ns), sel, client.Limit(warmPoolMaxMembers+1)); err != nil {
		return nil, false, err
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if pods.Continue != "" || len(pods.Items) > warmPoolMaxMembers {
		return nil, false, fmt.Errorf("warm candidate inventory incomplete/overflow")
	}

	candidates := make([]corev1.Pod, 0, len(pods.Items))
	seenKeys := make(map[string]struct{}, len(pods.Items))
	seenUIDs := make(map[string]struct{}, len(pods.Items))
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Name == exclude {
			continue
		}
		if p.Namespace != ns || p.Name == "" || p.UID == "" || p.ResourceVersion == "" || p.CreationTimestamp.IsZero() {
			return nil, false, fmt.Errorf("warm candidate inventory contains incomplete identity")
		}
		for key, value := range sel {
			if p.Labels[key] != value {
				return nil, false, fmt.Errorf("warm candidate inventory violates selector authority")
			}
		}
		key, uid := p.Namespace+"/"+p.Name, string(p.UID)
		if _, exists := seenKeys[key]; exists {
			return nil, false, fmt.Errorf("warm candidate inventory contains duplicate identity")
		}
		if _, exists := seenUIDs[uid]; exists {
			return nil, false, fmt.Errorf("warm candidate inventory contains duplicate UID")
		}
		seenKeys[key], seenUIDs[uid] = struct{}{}, struct{}{}
		candidates = append(candidates, *p.DeepCopy())
	}
	sort.Slice(candidates, func(i, j int) bool { return warmCandidateLess(&candidates[i], &candidates[j]) })

	attempts := 0
	for i := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		p := &candidates[i]
		ep, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, p)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, false, ctxErr
			}
			return nil, false, fmt.Errorf("warm candidate serving endpoint configuration: %w", err)
		}
		if !podReady(p) || p.DeletionTimestamp != nil {
			continue
		}
		if attempts == warmCandidateAttemptLimit {
			return nil, false, fmt.Errorf("%w after %d candidates; candidate set incomplete", errWarmCandidateAttemptBudget, attempts)
		}
		attempts++
		ready, pending, err := shadowModelReadyAtEndpoint(ctx, ec, p, ep)
		if err != nil {
			return nil, false, err
		}
		if ready {
			return p, pending, nil
		}
	}
	return nil, false, nil
}

func warmCandidateLess(a, b *corev1.Pod) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return string(a.UID) < string(b.UID)
}

// warmCutover is the shared provision-before-retire leadership flip: find a Ready shadow, flip it to
// leader, retire the old leader, and REWARM a replacement shadow. Used by warm-swap (swap-group) and
// model-shard-replace (model-shard group). FAIL-CLOSED: no Ready shadow => the old leader keeps serving.
func warmCutover(ctx context.Context, ec EnactCtx, req Request, groupKey, kind string) (HandlerResult, error) {
	req.Action = model.Action(kind)
	ec.ServingRequest = req
	leaderReader := client.Reader(ec.Client)
	if req.Action == model.ActionModelShardReplace {
		leaderReader = ec.Reader
	}
	leader, ok, err := getPod(ctx, leaderReader, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, kind, req)
	}
	// [M-69] The request names WHICH Pod it selected (TargetUID); the observed object must be
	// that Pod before anything is flipped, relabeled or retired. A delayed retry that finds a
	// same-name replacement is refused here, untouched (native rotate's refusal convention).
	if reason := triggerIdentityRefusal(req, leader); reason != "" {
		return refuseAI(kind, reason)
	}
	if req.Action == model.ActionModelShardReplace && leader.Labels[labelParallelGroup] != "" {
		return refuseAI(kind, ReasonParallelGroupUnavailable)
	}
	if _, err := servingEndpointForPod(ctx, ec, req, leader); err != nil {
		return refuseAI(kind, err.Error())
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
	// A picked shadow is only a candidate. Re-read both identities through the
	// authoritative Reader and persist the complete controller intent first.
	currentOld, currentNew := &corev1.Pod{}, &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: leader.Name}, currentOld); err != nil {
		return HandlerResult{}, err
	}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: shadow.Name}, currentNew); err != nil {
		return HandlerResult{}, err
	}
	if currentOld.UID != leader.UID || currentNew.UID != shadow.UID {
		return HandlerResult{}, fmt.Errorf("%s: warm pair UID changed before intent", kind)
	}
	if req.Action == model.ActionModelShardReplace && (currentOld.Labels[labelParallelGroup] != "" || currentNew.Labels[labelParallelGroup] != "") {
		return refuseAI(kind, ReasonParallelGroupUnavailable)
	}
	leader, shadow = currentOld, currentNew
	servingLegacy := true
	if ec.ServingSecurity != nil && ec.ServingSecurity.Mode() == ServingSecuritySecureRequired {
		servingLegacy = false
	}
	leader, oldEndpointDigest, err := warmDrainServingContractCurrent(ctx, ec, leader, servingLegacy)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("%s: current leader serving identity: %w", kind, err)
	}
	shadow, newEndpointDigest, err := warmDrainServingContractCurrent(ctx, ec, shadow, servingLegacy)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("%s: current shadow serving identity: %w", kind, err)
	}
	pool, err := warmPoolCapture(ctx, ec.Reader, leader, shadow, groupKey, group)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("%s: unsupported warm pool: %w", kind, err)
	}
	selectedUIDs, err := captureWarmSelectedUIDs(ctx, ec.Reader, pool, leader, shadow, groupKey, group)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("%s: pre-cutover route inventory: %w", kind, err)
	}
	bindingDigest := ""
	bindingServiceAccount := normalizeServiceAccount(leader.Spec.ServiceAccountName)
	if normalizeServiceAccount(shadow.Spec.ServiceAccountName) != bindingServiceAccount {
		return HandlerResult{}, fmt.Errorf("%s: warm pair ServiceAccount differs at admission", kind)
	}
	if !servingLegacy {
		bindingDigest = ec.ServingAttempt.digest
	} else if ec.ServingSecurity != nil || ec.VLLM == nil {
		return HandlerResult{}, fmt.Errorf("%s: operation-bound drain v11 requires secure serving credentials", kind)
	}
	authoritySeed := operationReceipt{Kind: kind, PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID}
	admittedPolicy, err := receiptAuthority(ctx, ec.Reader, authoritySeed, req.Action)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("%s: policy authority before availability admission: %w", kind, err)
	}
	admittedFloor := admittedPolicy.Spec.EffectiveMinAvailableReplicas()
	if admittedFloor <= 0 || admittedFloor > int(pool.Desired) || admittedFloor > len(selectedUIDs) {
		return HandlerResult{}, fmt.Errorf("%s: availability floor %d cannot be admitted by recorded serving set size %d", kind, admittedFloor, len(selectedUIDs))
	}
	drainReceipt, _, err := prepareDrainV11(ctx, ec, req, leader, pool.ServiceUID, 3*time.Minute)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("%s: operation-bound drain capability: %w", kind, err)
	}
	receipt := operationReceipt{Version: operationDrainReceiptVersion, Kind: kind, Phase: "prepared", PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, TargetName: leader.Name, TargetUID: string(leader.UID), TargetLabels: copyLabels(leader.Labels), OldName: leader.Name, OldUID: string(leader.UID), NewName: shadow.Name, NewUID: string(shadow.UID), GroupKey: groupKey, GroupValue: group, Pool: &pool, ServingBindingSHA256: bindingDigest, ServingServiceAccount: bindingServiceAccount, ServingLegacy: servingLegacy, EndpointConfigSHA256: oldEndpointDigest, NewEndpointConfigSHA256: newEndpointDigest, WarmSelectedUIDs: selectedUIDs, AdmittedFloor: admittedFloor, DrainV11: drainReceipt}
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
	if err := warmPoolRecheck(ctx, ec.Reader, receipt, leader, shadow); err != nil {
		return HandlerResult{}, err
	}
	if !podReady(shadow) || shadow.UID == "" || leader.ResourceVersion == "" || shadow.ResourceVersion == "" {
		return HandlerResult{}, fmt.Errorf("%s: observed pod identity/readiness unavailable", kind)
	}
	if err := warmDrainAvailabilityCurrent(ctx, ec.Reader, receipt, warmOriginalServingSet, warmProspectiveServingSet); err != nil {
		return HandlerResult{}, fmt.Errorf("%s: availability admission: %w", kind, err)
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
	if err := warmPoolRecheck(ctx, ec.Reader, receipt, leader, shadow); err != nil {
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
	if err := warmPoolRecheck(ctx, ec.Reader, receipt, leader, shadow); err != nil {
		return promotedPartial, err
	}
	// (2) FLIP down: old leader -> retiring. The exact promoted bridge must be
	// visible through the recorded Service before old route removal. On failure,
	// ROLL BACK (re-flip shadow; old leader serves).
	freshOld, _, flipErr := warmDrainPromotionRouteCurrent(ctx, ec, receipt)
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
		if checkErr == nil {
			checkErr = warmPoolRecheck(ctx, ec.Reader, receipt, oldAfter, rollback)
		}
		if checkErr == nil && (oldAfter.Labels[labelRole] != roleLeader || !podReady(oldAfter) || rollback.Labels[labelRole] != roleLeader || !podReady(rollback)) {
			checkErr = fmt.Errorf("exact old/new serving roles or readiness changed")
		}
		if checkErr == nil {
			checkErr = warmDrainAvailabilityCurrent(ctx, ec.Reader, receipt, warmOriginalServingSet)
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
		if availabilityErr := warmDrainAvailabilityCurrent(ctx, ec.Reader, receipt, warmOriginalServingSet); availabilityErr != nil {
			return promotedPartial, fmt.Errorf("%s rollback availability unconfirmed; receipt retained: %w", kind, errors.Join(flipErr, availabilityErr))
		}
		if routeErr := warmDrainOriginalRouteCurrent(ctx, ec, receipt); routeErr != nil {
			promotedPartial.Note = "cutover role changes compensated; original route observation unresolved"
			return promotedPartial, fmt.Errorf("%s rollback route unconfirmed; receipt retained: %w", kind, errors.Join(flipErr, routeErr))
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
	// (3) Claim one serving send before POST. Only a durable exact-200 result
	// authorizes retirement. A typed definitely-unsent result may restore the
	// recorded route in old-first order; every possible-send result is retained.
	drainResult, drainErr := executeWarmDrainAttempt(ctx, ec, journal, &receipt)
	if drainErr != nil {
		return partial, fmt.Errorf("%s drain old leader %s/%s: %w", kind, req.Namespace, req.Pod, drainErr)
	}
	if drainResult == warmDrainRestored {
		partial.Note = "drain was definitely unsent; exact old-first routing roles restored"
		return partial, fmt.Errorf("%s drain old leader %s/%s definitely unsent; routing restored without retirement", kind, req.Namespace, req.Pod)
	}
	if drainResult != warmDrainConfirmed {
		return partial, fmt.Errorf("%s drain old leader %s/%s retained without confirmed completion", kind, req.Namespace, req.Pod)
	}
	freshOld, _, err = warmDrainProspectiveRouteCurrent(ctx, ec, receipt)
	if err != nil {
		return partial, fmt.Errorf("%s: route/authority changed before confirmed retirement: %w", kind, err)
	}
	if err := ensureWarmDrainV11Current(ctx, ec, journal, &receipt, freshOld); err != nil {
		return partial, fmt.Errorf("%s: backend incarnation changed before confirmed retirement: %w", kind, err)
	}
	freshOld, _, err = warmDrainProspectiveRouteCurrent(ctx, ec, receipt)
	if err != nil {
		return partial, fmt.Errorf("%s: route/authority changed after backend revalidation: %w", kind, err)
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
	receipt.Phase = "retired-awaiting-controller"
	if err := journalAdvance(ctx, ec, journal, receipt); err != nil {
		partial.Note = "partial cutover: old leader retired; journal phase unresolved"
		return partial, fmt.Errorf("%s: old leader retired but journal phase update failed: %w", kind, err)
	}
	drainNote := fmt.Sprintf("in-flight drained (aborted=%d)", receipt.Aborted)
	retireNote := "retired (uid " + string(leader.UID) + ")"
	if alreadyGone {
		retireNote = "already gone before retire (no pod of that name; uid " + string(leader.UID) + ")"
	}
	note := fmt.Sprintf("%s: shadow %s promoted, old leader %s + %s; controller replenishment pending", kind, shadow.Name, drainNote, retireNote)
	if pending {
		note += " [PENDING-GPU-VALIDATION]: promoted shadow used K8s/model-loaded fallback"
	}
	// One immediate authoritative observation keeps the handler tick bounded. The
	// real ReplicaSet, never Phorvex, supplies the new Pod.
	freshSurvivor := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: receipt.NewName}, freshSurvivor); err != nil {
		partial.Note = note
		return partial, err
	}
	if string(freshSurvivor.UID) != receipt.NewUID || freshSurvivor.Labels[labelRole] != roleLeader || !podReady(freshSurvivor) {
		partial.Note = note
		return partial, fmt.Errorf("%s: serving survivor changed after retirement", kind)
	}
	if err := warmSurvivorScope(pol, receipt, freshSurvivor); err != nil {
		partial.Note = note
		return partial, err
	}
	if err := warmPoolRecheck(ctx, ec.Reader, receipt, nil, freshSurvivor); err != nil {
		partial.Note = note
		return partial, err
	}
	oldAfterDelete := &corev1.Pod{}
	oldReadErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: receipt.OldName}, oldAfterDelete)
	if oldReadErr != nil && !apierrors.IsNotFound(oldReadErr) {
		partial.Note = note
		return partial, oldReadErr
	}
	if oldReadErr == nil && string(oldAfterDelete.UID) == receipt.OldUID {
		partial.Note = note
		return partial, fmt.Errorf("%s: retired old UID still present; controller observation pending", kind)
	}
	candidate, observeErr := warmPoolObserve(ctx, ec.Reader, receipt)
	if observeErr != nil {
		partial.Note = note
		return partial, fmt.Errorf("%s: serving cutover submitted; pool replenishment pending: %w", kind, observeErr)
	}
	if _, err := servingEndpointForPod(ctx, ec, req, candidate); err != nil {
		partial.Note = note + "; replacement Pod serving endpoint configuration invalid"
		return partial, fmt.Errorf("%s: replacement Pod serving endpoint configuration: %w", kind, err)
	}
	receipt.RewarmName, receipt.RewarmUID, receipt.Phase = candidate.Name, string(candidate.UID), "pool-observed"
	if err := journalAdvance(ctx, ec, journal, receipt); err != nil {
		partial.Note = note
		return partial, err
	}
	ready, fallback := shadowModelReady(ctx, ec, candidate)
	if !ready {
		partial.Note = note + "; replacement Pod observed; warm capacity not ready"
		return partial, fmt.Errorf("%s: replacement Pod observed; warm capacity pending", kind)
	}
	receipt.Phase = "pool-warm-ready"
	if err := journalAdvance(ctx, ec, journal, receipt); err != nil {
		partial.Note = note
		return partial, err
	}
	if err := journalFinish(ctx, ec, journal); err != nil {
		partial.Note = note
		return partial, err
	}
	note += "; controller Pod observed and warm capacity ready"
	if fallback {
		note += " [PENDING-GPU-VALIDATION]: K8s/model-loaded fallback used"
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
	req.Action = model.ActionMIGRebind
	ec.ServingRequest = req
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "mig-rebind", req)
	}
	// [M-69] Refuse before any mutation unless the observed Pod is the one the request selected.
	if reason := triggerIdentityRefusal(req, pod); reason != "" {
		return refuseAI("mig-rebind", reason)
	}
	if _, err := servingEndpointForPod(ctx, ec, req, pod); err != nil {
		return refuseAI("mig-rebind", err.Error())
	}
	// The current resource request identifies the device-plugin class. Desired geometry comes only
	// from the operator-owned exact namespace/resource policy below.
	resource := gpudevice.MIGResourceName(pod)
	if resource == "" {
		return HandlerResult{}, fmt.Errorf("mig-rebind MIGUnavailable: pod %s/%s has no MIG device [PENDING-GPU-VALIDATION]", req.Namespace, req.Pod)
	}
	node := pod.Spec.NodeName
	if node == "" {
		return HandlerResult{}, fmt.Errorf("mig-rebind blocked: target has no scheduled node")
	}
	rule, err := ec.MIGProfiles.Resolve(req.Namespace, resource)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind profile authority (no workload mutation): %w", err)
	}
	profile := rule.Profile
	if ec.Reader == nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind blocked: authoritative reader unavailable (no workload mutation)")
	}
	// [P-ACTUATOR-SET-COMPLETE] AVAILABLE PROBE (non-mutating): fail-closed BEFORE the destructive
	// GPU-context eviction if the node-exec transport is not wired (no agent pod / no exec) — never
	// delete a pod we then cannot repartition. On kind this fail-closes here, untouched.
	mig, err := ec.mig().Prepare(ctx, node)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind transport unavailable (no eviction performed): %w", err)
	}
	auth, ok := mig.(migAllocationAuthority)
	if !ok {
		return HandlerResult{}, fmt.Errorf("mig-rebind allocation authority unavailable (no workload mutation)")
	}
	binding, err := auth.BindAllocation(ctx, migAllocationTarget{Namespace: pod.Namespace, Pod: pod.Name, UID: string(pod.UID), Node: node, Resource: resource}, rule)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind allocation authority (no workload mutation): %w", err)
	}
	if asserted := pod.Annotations[annoGPUID]; asserted != "" && asserted != binding.DeviceID && asserted != binding.GPUUUID {
		return HandlerResult{}, fmt.Errorf("mig-rebind legacy GPU assertion %q conflicts with allocated device %q", asserted, binding.DeviceID)
	}
	if asserted := pod.Annotations[annoMIGProfile]; asserted != "" && asserted != profile {
		return HandlerResult{}, fmt.Errorf("mig-rebind tenant profile assertion %q conflicts with operator profile %q", asserted, profile)
	}
	prior, err := mig.Capture(ctx, binding.GPUUUID, profile)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind unsupported or unavailable geometry (no workload mutation): %w", err)
	}
	receipt := migRecoveryReceipt{Version: 2, Phase: "prepared", PolicyNamespace: req.Namespace, PolicyName: req.PolicyName, PolicyUID: req.PolicyUID, TargetName: pod.Name, TargetUID: string(pod.UID), TargetLabels: copyLabels(pod.Labels), Node: node, GPUUUID: prior.GPUUUID, TargetProfile: profile, Binding: binding, Prior: prior}
	fresh := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, fresh); err != nil || fresh.UID != pod.UID || fresh.Spec.NodeName != node || gpudevice.MIGResourceName(fresh) != resource {
		return HandlerResult{}, fmt.Errorf("mig-rebind target identity/configuration changed before recovery intent (no workload mutation): %v", err)
	}
	if err := auth.RevalidateAllocation(ctx, binding, true); err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind allocation changed before recovery intent: %w", err)
	}
	receipt.TargetLabels = copyLabels(fresh.Labels)
	if err := migRecoveryAuthority(ctx, ec, receipt, receipt.TargetLabels); err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind policy authority (no workload mutation): %w", err)
	}
	journal, err := migRecoveryWrite(ctx, ec, receipt)
	if err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind persist recovery intent (no workload mutation): %w", err)
	}
	if err := migRecoveryRequireOwned(ctx, ec, journal, receipt, receipt.TargetLabels); err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind recovery ownership before route removal: %w", err)
	}
	if err := auth.RevalidateAllocation(ctx, binding, true); err != nil {
		return HandlerResult{}, errors.Join(fmt.Errorf("mig-rebind allocation changed before route removal: %w", err), migRecoveryFinish(ctx, ec, journal))
	}
	// Route out, confirm the serving drain, then submit the UID-bound Pod deletion before the GPU
	// operation. Pod deletion is workload evidence only; it does not prove CUDA process state.
	// The pod's owner reschedules the workload onto the new MIG geometry after repartition.
	originalRole := fresh.Labels[labelRole]
	fresh.Labels = ensureMap(fresh.Labels)
	fresh.Labels[labelRole] = roleRetiring
	if err := ec.Client.Update(ctx, fresh); err != nil {
		observed := &corev1.Pod{}
		readErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, observed)
		effected := readErr == nil && observed.UID == fresh.UID && observed.Labels[labelRole] == roleRetiring
		var cleanupErr error
		if readErr == nil && observed.UID == fresh.UID && observed.Labels[labelRole] == originalRole {
			cleanupErr = migRecoveryFinish(ctx, ec, journal)
		}
		return HandlerResult{Emitted: effected, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "route-removal update uncertain; GPU untouched"}, errors.Join(fmt.Errorf("mig-rebind UID-bound route removal failed; repartition not attempted: %w", err), readErr, cleanupErr)
	}
	pod = fresh
	_, drainPending, drainErr := drainInflight(ctx, ec, pod)
	if drainErr != nil {
		receipt.Phase, receipt.Outcome = "unresolved", "pod-relabeled-drain-failed"
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "pod relabeled retiring; recovery receipt retained; GPU untouched"}, errors.Join(fmt.Errorf("mig-rebind request drain failed; repartition not attempted: %w", drainErr), migRecoveryAdvance(ctx, ec, journal, receipt))
	}
	if drainPending {
		receipt.Phase, receipt.Outcome = "unresolved", "pod-relabeled-drain-unconfirmed"
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "pod relabeled retiring; serving drain unconfirmed; recovery receipt retained; GPU untouched"}, errors.Join(fmt.Errorf("mig-rebind serving drain unconfirmed; eviction and repartition not attempted"), migRecoveryAdvance(ctx, ec, journal, receipt))
	}
	if err := migRecoveryRequireOwned(ctx, ec, journal, receipt, receipt.TargetLabels); err != nil {
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "pod relabeled and drained; recovery ownership lost; eviction and GPU repartition refused"}, fmt.Errorf("mig-rebind recovery ownership before eviction: %w", err)
	}
	current := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: req.Pod}, current); err != nil || current.UID != pod.UID || current.Spec.NodeName != node || gpudevice.MIGResourceName(current) != resource {
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "pod relabeled and drained; target identity changed; eviction and GPU repartition refused"}, fmt.Errorf("mig-rebind target identity/configuration changed before eviction: %v", err)
	}
	if err := auth.RevalidateAllocation(ctx, binding, true); err != nil {
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "pod relabeled and drained; allocation authority changed; eviction and GPU repartition refused"}, fmt.Errorf("mig-rebind allocation authority before eviction: %w", err)
	}
	// [M-69] Evict exactly the observed Pod (UID-bound Delete). A rejected eviction — a same-name
	// replacement, or any other API refusal — means the GPU was NOT freed by this move, so the
	// repartition is NOT attempted; the relabel already applied to the name is reported as-is.
	alreadyGone, delErr := deleteObservedPod(ctx, ec.Client, current)
	if delErr != nil {
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "pod relabeled retiring; recovery receipt retained; GPU untouched"},
			fmt.Errorf("mig-rebind GPU-context eviction (delete %s/%s, observed uid %s) rejected; repartition NOT attempted (pod name relabeled %s): %w", req.Namespace, req.Pod, pod.UID, roleRetiring, delErr)
	}
	receipt.Phase = "destructive"
	if err := migRecoveryAdvance(ctx, ec, journal, receipt); err != nil {
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "pod eviction submitted; recovery phase acknowledgement failed; GPU untouched"}, fmt.Errorf("mig-rebind recovery phase update after eviction: %w", err)
	}
	releaseTimeout := defaultAllocationWait
	if provider, ok := auth.(interface{ allocationReleaseTimeout() time.Duration }); ok {
		releaseTimeout = provider.allocationReleaseTimeout()
	}
	if err := waitAllocationRelease(ctx, auth, binding, releaseTimeout); err != nil {
		receipt.Phase, receipt.Outcome = "unresolved", "allocation-release-unconfirmed"
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "pod eviction submitted; allocation release unconfirmed; GPU untouched"}, errors.Join(err, migRecoveryAdvance(ctx, ec, journal, receipt))
	}
	recheck, err := mig.Capture(ctx, prior.GPUUUID, profile)
	if err != nil || !sameMIGGeometry(recheck, prior) {
		receipt.Phase, receipt.Outcome = "unresolved", "identity-or-geometry-drift-before-destroy"
		persistErr := migRecoveryAdvance(ctx, ec, journal, receipt)
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)}, Note: "pod eviction submitted; GPU destroy refused because identity/geometry changed; recovery receipt retained or persistence uncertain"}, errors.Join(fmt.Errorf("mig-rebind geometry changed before destroy: %w", err), persistErr)
	}
	// REAL nvidia-smi repartition (destroy CI/GI, create the new geometry) via the
	// prepared execNodeRunner transport. Preparation already bound one validated agent identity, so
	// reaching here means the pod was evicted for a real attempt through that same session.
	stillOwned := func(guardCtx context.Context) error {
		if err := migRecoveryRequireOwned(guardCtx, ec, journal, receipt, receipt.TargetLabels); err != nil {
			return err
		}
		return auth.RevalidateAllocation(guardCtx, binding, false)
	}
	effect, repErr := mig.Repartition(ctx, prior, profile, stillOwned)
	if repErr != nil {
		receipt.Outcome = effect.Outcome
		if effect.Outcome == "prior-geometry-restored" {
			if finishErr := migRecoveryFinish(ctx, ec, journal); finishErr != nil {
				repErr = errors.Join(repErr, fmt.Errorf("verified restored but receipt cleanup failed: %w", finishErr))
			}
		} else {
			receipt.Phase = "unresolved"
			if e := migRecoveryAdvance(ctx, ec, journal, receipt); e != nil {
				repErr = errors.Join(repErr, fmt.Errorf("persist unresolved recovery outcome: %w", e))
			}
		}
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod), objRef("Node", "", node)}, Note: fmt.Sprintf("pod deletion submitted; GPU outcome %s; protected recovery receipt retained when unresolved", effect.Outcome)}, fmt.Errorf("mig-rebind repartition gpu %s -> %s: %w", prior.GPUUUID, profile, repErr)
	}
	if effect.Outcome != "new-geometry-verified" {
		return HandlerResult{Emitted: true, MutationKind: "partial", Note: "pod deletion submitted; GPU outcome unknown; recovery receipt retained"}, fmt.Errorf("mig-rebind unexpected GPU outcome %q", effect.Outcome)
	}
	if err := migRecoveryFinish(ctx, ec, journal); err != nil {
		return HandlerResult{Emitted: true, MutationKind: "partial", ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod), objRef("Node", "", node)}, Note: "new GPU geometry verified; recovery receipt cleanup failed"}, err
	}
	drainNote := "drained"
	if drainPending {
		drainNote = "in-flight abort [PENDING-GPU-VALIDATION]"
	}
	evictNote := "pod eviction submitted (uid " + string(pod.UID) + ", " + drainNote + "; CUDA process state and serving capacity not verified)"
	if alreadyGone {
		evictNote = "pod already gone before eviction (no pod of that name; uid " + string(pod.UID) + ", " + drainNote + ")"
	}
	return HandlerResult{
		Emitted: true, MutationKind: "swap", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod), objRef("Node", "", node)},
		Note:           fmt.Sprintf("mig-rebind: %s, allocated device %s on physical GPU %s verified as %s [PENDING-GPU-VALIDATION]: allocation observation is not an atomic scheduler reservation; workload placement, CUDA state, serving health, and VRAM magnitudes unvalidated", evictNote, binding.DeviceID, binding.GPUUUID, profile),
	}, nil
}

// --- 10. kv-reset — REAL vLLM prefix/KV-cache flush; pod stays ALIVE -----------------------
type kvResetHandler struct{}

func (kvResetHandler) Name() string { return string(model.ActionKVReset) }

func authoritativeRawKVPod(ctx context.Context, ec EnactCtx, req Request, kind string) (*corev1.Pod, HandlerResult, error) {
	if ec.Reader == nil || ec.Client == nil {
		result, err := refuseAI(kind, "authoritative reader or writer unavailable")
		return nil, result, err
	}
	pod, ok, err := getPod(ctx, ec.Reader, req.Namespace, req.Pod)
	if err != nil || !ok {
		return nil, HandlerResult{}, orGone(err, ok, kind, req)
	}
	if pod.UID == "" || pod.ResourceVersion == "" {
		result, refusalErr := refuseAI(kind, "authoritative target identity or resource version unavailable")
		return nil, result, refusalErr
	}
	return pod, HandlerResult{}, nil
}

func declaredKVEndpoint(ctx context.Context, ec EnactCtx, req Request, pod *corev1.Pod) (servingEndpoint, string) {
	if reason := triggerIdentityRefusal(req, pod); reason != "" {
		return servingEndpoint{}, reason
	}
	ep, err := servingEndpointForPod(ctx, ec, req, pod)
	if err != nil {
		return servingEndpoint{}, err.Error()
	}
	if !servingcontext.FromAnnotations(pod.Annotations).Declared() {
		return servingEndpoint{}, "target Pod has no model-id or valid serving-port declaration"
	}
	return ep, ""
}

func (kvResetHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	req.Action = model.ActionKVReset
	ec.ServingRequest = req
	return enactProtectedKVReset(ctx, ec, req)
}

// --- 11. endpoint-rotate — REAL route restitch (re-key + Service selector) + rollback -------
type endpointRotateHandler struct{}

func (endpointRotateHandler) Name() string { return string(model.ActionEndpointRotate) }

func (endpointRotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return enactRouteCutover(ctx, ec, req)
}

func (endpointRotateHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	return rollbackRouteCutover(ctx, ec, req, ref)
}

// --- 12. model-shard-replace — controller-owned scalar replacement --------------------------
type modelShardReplaceHandler struct{}

func (modelShardReplaceHandler) Name() string { return string(model.ActionModelShardReplace) }
func (modelShardReplaceHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.Reader == nil || ec.Client == nil {
		return refuseAI("model-shard-replace", "authoritative reader or writer unavailable")
	}
	pod, ok, err := getPod(ctx, ec.Reader, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "model-shard-replace", req)
	}
	if reason := triggerIdentityRefusal(req, pod); reason != "" {
		return refuseAI("model-shard-replace", reason)
	}
	// FAIL-CLOSED: no declared shard => no model server => never fabricate a shard replace.
	if pod.Labels[labelModelShard] == "" {
		return HandlerResult{}, fmt.Errorf("model-shard-replace ShardUnavailable: pod %s/%s declares no %s [PENDING-GPU-VALIDATION]", req.Namespace, req.Pod, labelModelShard)
	}
	if pod.Labels[labelParallelGroup] != "" {
		return refuseAI("model-shard-replace", ReasonParallelGroupUnavailable)
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
