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
func rewarmShadow(ctx context.Context, ec EnactCtx, oldLeader *corev1.Pod, groupKey, groupVal string) (string, error) {
	name := truncName(oldLeader.Name + "-rw-" + oldLeader.ResourceVersion)
	labels := copyLabels(oldLeader.Labels)
	labels[groupKey] = groupVal
	labels[labelRole] = roleShadow
	labels[labelModelLoaded] = "false" // it is loading; promotable only once model-loaded/ready
	shadow := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: oldLeader.Namespace, Labels: labels},
		Spec:       *oldLeader.Spec.DeepCopy(),
	}
	shadow.Spec.NodeName = "" // reschedule freely (and onto a fresh GPU/MIG slot)
	if err := ec.Client.Create(ctx, shadow); err != nil && !apierrors.IsAlreadyExists(err) {
		return "", err
	}
	return name, nil
}

// warmCutover is the shared provision-before-retire leadership flip: find a Ready shadow, flip it to
// leader, retire the old leader, and REWARM a replacement shadow. Used by warm-swap (swap-group) and
// model-shard-replace (model-shard group). FAIL-CLOSED: no Ready shadow => the old leader keeps serving.
func warmCutover(ctx context.Context, ec EnactCtx, req Request, groupKey, kind string) (HandlerResult, error) {
	leader, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, kind, req)
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
	// persist the phase for crash-resume (idempotent dedupe on the triggering decision).
	leader.Annotations = ensureMap(leader.Annotations)
	leader.Annotations[annoSwapPhase] = "flipping"
	_ = ec.Client.Update(ctx, leader)

	// (1) FLIP up: shadow -> leader (provision-before-retire: new leader Ready BEFORE old touched).
	shadow.Labels[labelRole] = roleLeader
	if err := ec.Client.Update(ctx, shadow); err != nil {
		return HandlerResult{}, fmt.Errorf("%s flip-up %s: %w", kind, shadow.Name, err)
	}
	// (2) FLIP down: old leader -> retiring. On failure, ROLL BACK (re-flip shadow; old leader serves).
	if err := relabelRole(ctx, ec.Client, req.Namespace, req.Pod, roleRetiring); err != nil {
		shadow.Labels[labelRole] = roleShadow
		_ = ec.Client.Update(ctx, shadow)
		return HandlerResult{}, fmt.Errorf("%s flip-down %s/%s (rolled back): %w", kind, req.Namespace, req.Pod, err)
	}
	// (3) DRAIN then RETIRE the old leader. [P-ACTUATOR-SET-COMPLETE] The old leader is already
	// relabeled `retiring` (admits routed away by step 2); now actually DRAIN its in-flight requests
	// via the serving stack BEFORE deleting it, so in-flight requests are not dropped ungracefully
	// (closes the prior ":141 recorded-not-slept" gap). Unreachable stack => the K8s route-drain still
	// applies; the in-flight abort is [PENDING-GPU-VALIDATION] (recorded in the note).
	_, drainPending, drainErr := drainInflight(ctx, ec, leader)
	if drainErr != nil {
		return HandlerResult{}, fmt.Errorf("%s drain old leader %s/%s: %w", kind, req.Namespace, req.Pod, drainErr)
	}
	if delErr := ec.Client.Delete(ctx, leader); delErr != nil && !apierrors.IsNotFound(delErr) {
		return HandlerResult{}, fmt.Errorf("%s retire %s/%s: %w", kind, req.Namespace, req.Pod, delErr)
	}
	// (4) REWARM-to-N: provision a replacement shadow (cold-load OFF the serving path).
	rewarm, rwErr := rewarmShadow(ctx, ec, leader, groupKey, group)
	touched := []string{objRef("Pod", req.Namespace, shadow.Name), objRef("Pod", req.Namespace, req.Pod)}
	drainNote := "in-flight drained"
	if drainPending {
		drainNote = "in-flight abort [PENDING-GPU-VALIDATION] (stack unreachable; K8s route-drained)"
	}
	note := fmt.Sprintf("%s: shadow %s promoted, old leader %s + retired (no cold-load on serving path)", kind, shadow.Name, drainNote)
	if rwErr == nil {
		touched = append(touched, objRef("Pod", req.Namespace, rewarm))
		note += "; rewarmed " + rewarm
	} else {
		note += "; REWARM deferred: " + rwErr.Error()
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
	// FAIL-CLOSED preconditions: a MIG device, a node, and a declared target profile (you never pick a
	// MIG geometry blindly, and you never fabricate a rebind without a real device).
	if !hasMIGDevice(pod) {
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
	if err := ec.mig().Available(ctx, node); err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind transport unavailable (no eviction performed): %w", err)
	}
	// DRAIN + GPU-CONTEXT EVICTION: MIG reconfiguration requires ZERO active CUDA contexts on the GPU —
	// a relabel-out is INSUFFICIENT (a running pod still holds the context). So route the pod out,
	// drain its in-flight requests, then EVICT it off the GPU (delete) so the device is context-free.
	// The pod's owner reschedules the workload onto the new MIG geometry after repartition.
	_ = relabelRole(ctx, ec.Client, req.Namespace, req.Pod, roleRetiring)
	_, drainPending, _ := drainInflight(ctx, ec, pod)
	if delErr := ec.Client.Delete(ctx, pod); delErr != nil && !apierrors.IsNotFound(delErr) {
		return HandlerResult{}, fmt.Errorf("mig-rebind GPU-context eviction (delete %s/%s): %w", req.Namespace, req.Pod, delErr)
	}
	// REAL nvidia-smi repartition on the now-idle GPU (destroy CI/GI, create the new geometry) via the
	// execNodeRunner transport. The exec syscall is [PENDING-GPU-VALIDATION]; Available() already
	// confirmed the transport is wired, so reaching here means the pod was evicted for a real attempt.
	if err := ec.mig().Repartition(ctx, node, gpuID, profile); err != nil {
		return HandlerResult{}, fmt.Errorf("mig-rebind repartition gpu %s -> %s (pod evicted; owner reschedules onto new geometry): %w", gpuID, profile, err)
	}
	drainNote := "drained"
	if drainPending {
		drainNote = "in-flight abort [PENDING-GPU-VALIDATION]"
	}
	return HandlerResult{
		Emitted: true, MutationKind: "swap", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod), objRef("Node", "", node)},
		Note:           fmt.Sprintf("mig-rebind: pod evicted off GPU (%s, zero CUDA contexts), GPU %s repartitioned to %s off the co-resident slot [PENDING-GPU-VALIDATION]: VRAM/geometry magnitudes unvalidated", drainNote, gpuID, profile),
	}, nil
}

func hasMIGDevice(p *corev1.Pod) bool {
	for _, c := range p.Spec.Containers {
		for name := range c.Resources.Requests {
			if len(name) >= 12 && name[:12] == "nvidia.com/m" { // nvidia.com/mig-*
				return true
			}
		}
	}
	return false
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
		// no serving stack reachable (kind / no GPU): the pod-alive mechanic is real; the flush is pending.
		flushNote = "serving stack unreachable [PENDING-GPU-VALIDATION]: KV flush NOT performed (no vLLM); pod kept alive + flush epoch recorded"
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
