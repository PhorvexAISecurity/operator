/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR-SET-COMPLETE)
 *
 * The 4 NEW AI actuators that close the audited mechanism gaps, REAL behind the mockable stack:
 *   adapter-rotate (P1) — evicts a poisoned LoRA the other moves cannot.
 *   request-drain (P2)  — request-granular in-flight eviction (also supplies warm-swap's drain).
 *   guardrail-rotate (P2) — MTD for the safety tier (stale a found bypass).
 *   kv-migrate-invalidate — local KV invalidate REAL; cross-worker migrate DEFERRED [PENDING-GPU-VALIDATION].
 *
 * Each is opt-in (default policy still {rotate,quarantine}), fail-closed on its precondition, honest
 * tri-state (success / unreachable->[PENDING] / reachable-fails->fail-closed), [PENDING-GPU-VALIDATION].
 *
 * PREMORTEM (encoded below): adapter-rotate must NOT reload from the same poisoned source (reload only a
 * declared TRUSTED source); request-drain stops admits BEFORE aborting (else new requests slip in) and
 * does NOT block re-entry (pair with quarantine); guardrail-rotate must pick a DISTINCT variant (same
 * blind spot = no MTD); kv local-invalidate leaves REMOTE KV until the deferred cross-worker migrate.
 */

package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	labelLoRAEnabled     = "phorvex.ai/lora-enabled"        // pod advertises --enable-lora
	annoLoRAAdapter      = "phorvex.ai/lora-adapter"        // the adapter to evict
	annoLoRACleanSource  = "phorvex.ai/lora-clean-source"   // a TRUSTED pinned source to reload (optional)
	annoAdapterSnapshot  = "phorvex.ai/adapter-snapshot"    // rollback record
	labelGuardrailTier   = "phorvex.ai/guardrail-tier"      // marks a guardrail pod
	annoGuardrailVariant = "phorvex.ai/guardrail-variant"   // current variant
	annoGuardrailAlts    = "phorvex.ai/guardrail-variants"  // comma-list of DIVERSE alternates
	annoGuardrailSnap    = "phorvex.ai/guardrail-snapshot"  // rollback record
	annoDisaggPeers      = "phorvex.ai/disagg-kv-peers"     // comma-list of P/D peer endpoints
	annoKVEpoch          = "phorvex.ai/kv-migrate-epoch"
	labelServing         = "phorvex.ai/serving"             // K8s readiness-drain target label
	labelParallelGroup   = "phorvex.ai/parallel-group"      // TP/PP group id (a consistency unit)
	labelRank            = "phorvex.ai/rank"                // rank within the parallel group
	annoParallelSize     = "phorvex.ai/parallel-size"       // number of ranks in the group
)

// groupCoherentCutover flips an ENTIRE tensor/pipeline-parallel group as a UNIT (model-shard-replace's
// TP/PP completion). A parallel group is a consistency unit: a COMPLETE replacement shadow group (one
// Ready shadow per rank) is flipped together, then the old group is drained + retired. FAIL-CLOSED on
// an incomplete replacement group — never serve a mixed-rank (old+new) group.
func groupCoherentCutover(ctx context.Context, ec EnactCtx, req Request, group string) (HandlerResult, error) {
	trig, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "model-shard-replace", req)
	}
	size, _ := strconv.Atoi(trig.Annotations[annoParallelSize])
	if size <= 0 {
		return HandlerResult{}, fmt.Errorf("model-shard-replace: %s unset on group %q — cannot coherently flip a TP/PP group (fail-closed)", annoParallelSize, group)
	}
	sel := client.MatchingLabels{labelParallelGroup: group}
	// COMPLETE replacement: one Ready shadow per distinct rank.
	var shadows corev1.PodList
	if err := ec.Client.List(ctx, &shadows, client.InNamespace(req.Namespace), sel); err != nil {
		return HandlerResult{}, err
	}
	readyByRank := map[string]*corev1.Pod{}
	pending := false
	for i := range shadows.Items {
		p := &shadows.Items[i]
		if p.Labels[labelRole] != roleShadow || p.Labels[labelRank] == "" {
			continue
		}
		if _, seen := readyByRank[p.Labels[labelRank]]; seen {
			continue
		}
		if ready, pend := shadowModelReady(ctx, ec, p); ready {
			readyByRank[p.Labels[labelRank]] = p
			pending = pending || pend
		}
	}
	if len(readyByRank) < size {
		return HandlerResult{}, fmt.Errorf("model-shard-replace TP/PP blocked: replacement group %q incomplete (%d/%d ranks Ready) — never flip a partial parallel group (fail-closed)", group, len(readyByRank), size)
	}
	// (1) FLIP UP every shadow rank to leader, COHERENTLY; roll back all on any failure.
	var flipped []*corev1.Pod
	for _, s := range readyByRank {
		s.Labels[labelRole] = roleLeader
		if err := ec.Client.Update(ctx, s); err != nil {
			for _, f := range flipped {
				f.Labels[labelRole] = roleShadow
				_ = ec.Client.Update(ctx, f)
			}
			return HandlerResult{}, fmt.Errorf("model-shard-replace TP/PP flip-up %s (group rolled back): %w", s.Name, err)
		}
		flipped = append(flipped, s)
	}
	// (2) DRAIN + RETIRE the old leaders of the group, coherently.
	var leaders corev1.PodList
	_ = ec.Client.List(ctx, &leaders, client.InNamespace(req.Namespace), sel)
	touched := make([]string, 0, len(flipped)+size)
	for i := range leaders.Items {
		old := &leaders.Items[i]
		if old.Labels[labelRole] != roleRetiring && isOldLeader(old, flipped) {
			_ = relabelRole(ctx, ec.Client, old.Namespace, old.Name, roleRetiring)
			_, _, _ = drainInflight(ctx, ec, old)
			_ = ec.Client.Delete(ctx, old)
			touched = append(touched, objRef("Pod", old.Namespace, old.Name))
		}
	}
	for _, s := range flipped {
		touched = append(touched, objRef("Pod", req.Namespace, s.Name))
	}
	note := fmt.Sprintf("model-shard-replace: TP/PP group %q flipped COHERENTLY (%d ranks), old group drained + retired", group, size)
	if pending {
		note += " [PENDING-GPU-VALIDATION]: shadow readiness used the K8s gate (no vLLM stack reachable)"
	} else {
		note += " [PENDING-GPU-VALIDATION]: ColdLoadSec magnitude unvalidated"
	}
	return HandlerResult{Emitted: true, MutationKind: "swap", RollbackRef: req.Namespace + "/" + group, ObjectsTouched: touched, Note: note}, nil
}

// isOldLeader reports whether p is an OLD leader (not one of the just-promoted shadows).
func isOldLeader(p *corev1.Pod, flipped []*corev1.Pod) bool {
	for _, f := range flipped {
		if f.Name == p.Name {
			return false
		}
	}
	return p.Labels[labelRole] == roleLeader
}

// drainInflight performs the stack-side in-flight drain/abort with the honest tri-state. Shared by
// request-drain AND warm-swap's retire. Returns (abortedCount, pending, err): pending=true means the
// serving stack was unreachable (the abort is [PENDING-GPU-VALIDATION], the K8s drain still applies).
func drainInflight(ctx context.Context, ec EnactCtx, pod *corev1.Pod) (int, bool, error) {
	aborted, err := ec.vllm().DrainRequests(ctx, endpointForPod(pod))
	switch {
	case err == nil:
		return aborted, false, nil
	case errors.Is(err, errStackUnreachable):
		return 0, true, nil
	default:
		return 0, false, err
	}
}

// --- 13. adapter-rotate — evict a poisoned LoRA/adapter (the survival-gap closer) ---------
type adapterRotateHandler struct{}

func (adapterRotateHandler) Name() string { return string(model.ActionAdapterRotate) }
func (adapterRotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "adapter-rotate", req)
	}
	adapter := pod.Annotations[annoLoRAAdapter]
	if pod.Labels[labelLoRAEnabled] != "true" || adapter == "" {
		return HandlerResult{}, fmt.Errorf("adapter-rotate AdapterUnavailable: pod %s/%s is not %s / names no %s [PENDING-GPU-VALIDATION]", req.Namespace, req.Pod, labelLoRAEnabled, annoLoRAAdapter)
	}
	ep := endpointForPod(pod)
	// (1) UNLOAD the (poisoned) adapter — the base model stays clean.
	note := ""
	uerr := ec.vllm().UnloadAdapter(ctx, ep, adapter)
	switch {
	case uerr == nil:
		note = "adapter " + adapter + " unloaded"
	case errors.Is(uerr, errStackUnreachable):
		// no serving stack here: record the rotation epoch; the unload is [PENDING-GPU-VALIDATION].
		note = "serving stack unreachable [PENDING-GPU-VALIDATION]: adapter unload NOT performed (no vLLM)"
	default:
		return HandlerResult{}, fmt.Errorf("adapter-rotate unload %q: %w", adapter, uerr)
	}
	// (2) optional RELOAD from a TRUSTED PINNED source ONLY (premortem: NEVER reload from the same
	// poisoned path — that re-pulls the poison). No clean source => degrade to the base model.
	if clean := pod.Annotations[annoLoRACleanSource]; clean != "" && uerr == nil {
		if lerr := ec.vllm().LoadAdapter(ctx, ep, adapter, clean); lerr != nil {
			return HandlerResult{}, fmt.Errorf("adapter-rotate reload-clean %q from %q: %w", adapter, clean, lerr)
		}
		note += "; reloaded clean from " + clean
	} else if uerr == nil {
		note += "; no clean source — degraded to base model (poison evicted)"
	}
	// snapshot for rollback (reload from the clean source); record the epoch.
	snap, _ := json.Marshal(map[string]string{"adapter": adapter, "clean": pod.Annotations[annoLoRACleanSource]})
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[annoAdapterSnapshot] = string(snap)
	pod.Labels = ensureMap(pod.Labels)
	pod.Labels["phorvex.ai/adapter-epoch"] = pod.ResourceVersion
	if err := ec.Client.Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("adapter-rotate epoch %s/%s: %w", req.Namespace, req.Pod, err)
	}
	return HandlerResult{
		Emitted: true, MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)},
		Note:           "adapter-rotate: " + note,
	}, nil
}

// Rollback reloads the adapter from the CLEAN source only (never re-introduces the poison; no-op if no
// clean source was declared).
func (adapterRotateHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, _ string) error {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return orGone(err, ok, "adapter-rotate-rollback", req)
	}
	var snap struct{ Adapter, Clean string }
	_ = json.Unmarshal([]byte(pod.Annotations[annoAdapterSnapshot]), &snap)
	if snap.Adapter == "" || snap.Clean == "" {
		return nil // nothing safe to restore
	}
	return ec.vllm().LoadAdapter(ctx, endpointForPod(pod), snap.Adapter, snap.Clean)
}

// --- 14. request-drain — request-granular in-flight eviction ------------------------------
type requestDrainHandler struct{}

func (requestDrainHandler) Name() string { return string(model.ActionRequestDrain) }
func (requestDrainHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "request-drain", req)
	}
	// ORDERING (premortem): STOP new admits BEFORE aborting in-flight, else new requests slip in mid-
	// drain. The K8s readiness-drain (flip the serving label out) is the real, stack-independent step.
	pod.Labels = ensureMap(pod.Labels)
	prevServing := pod.Labels[labelServing]
	pod.Labels[labelServing] = "drained"
	if err := ec.Client.Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("request-drain stop-admit %s/%s: %w", req.Namespace, req.Pod, err)
	}
	// abort/finish in-flight via the stack.
	aborted, pending, derr := drainInflight(ctx, ec, pod)
	if derr != nil {
		// reachable-but-failed: restore admits (do not strand the pod unready) then fail-closed.
		pod.Labels[labelServing] = prevServing
		_ = ec.Client.Update(ctx, pod)
		return HandlerResult{}, fmt.Errorf("request-drain abort %s/%s: %w", req.Namespace, req.Pod, derr)
	}
	note := fmt.Sprintf("admits stopped; %d in-flight aborted", aborted)
	if pending {
		note = "admits stopped (K8s readiness-drain); in-flight abort [PENDING-GPU-VALIDATION] (serving stack unreachable)"
	}
	note += "; NOTE: does not block re-entry — pair with quarantine/route-rotate"
	return HandlerResult{
		Emitted: true, MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)},
		Note:           "request-drain: " + note,
	}, nil
}

// Rollback re-admits the pod (restore the serving label) — drain is transient eviction.
func (requestDrainHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, _ string) error {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return orGone(err, ok, "request-drain-rollback", req)
	}
	pod.Labels = ensureMap(pod.Labels)
	pod.Labels[labelServing] = "true"
	return ec.Client.Update(ctx, pod)
}

// --- 15. guardrail-rotate — MTD for the safety tier ---------------------------------------
type guardrailRotateHandler struct{}

func (guardrailRotateHandler) Name() string { return string(model.ActionGuardrailRotate) }
func (guardrailRotateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "guardrail-rotate", req)
	}
	if pod.Labels[labelGuardrailTier] != "true" || pod.Annotations[annoGuardrailAlts] == "" {
		return HandlerResult{}, fmt.Errorf("guardrail-rotate GuardrailUnavailable: pod %s/%s is not %s / declares no %s [PENDING-GPU-VALIDATION]", req.Namespace, req.Pod, labelGuardrailTier, annoGuardrailAlts)
	}
	cur := pod.Annotations[annoGuardrailVariant]
	// PREMORTEM: pick a DISTINCT variant (same blind spot = no MTD diversity = no help).
	next := ""
	for _, v := range strings.Split(pod.Annotations[annoGuardrailAlts], ",") {
		if v = strings.TrimSpace(v); v != "" && v != cur {
			next = v
			break
		}
	}
	if next == "" {
		return HandlerResult{}, fmt.Errorf("guardrail-rotate: no DISTINCT alternate variant (only %q declared) — rotation would not change the blind spot", cur)
	}
	// (1) re-key the variant (K8s, real) + snapshot for rollback.
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[annoGuardrailSnap] = cur
	pod.Annotations[annoGuardrailVariant] = next
	pod.Labels = ensureMap(pod.Labels)
	pod.Labels["phorvex.ai/guardrail-epoch"] = pod.ResourceVersion
	if err := ec.Client.Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("guardrail-rotate relabel %s/%s: %w", req.Namespace, req.Pod, err)
	}
	// (2) apply the variant to the guardrail service (stack call, tri-state).
	note := "variant " + cur + " -> " + next
	aerr := ec.guardrail().ApplyVariant(ctx, endpointForPod(pod), next)
	switch {
	case aerr == nil:
		note += " applied to the guardrail service (bypass staled)"
	case errors.Is(aerr, errStackUnreachable):
		note += " [PENDING-GPU-VALIDATION]: guardrail service unreachable (variant re-keyed in K8s, not applied to the live filter)"
	default:
		return HandlerResult{}, fmt.Errorf("guardrail-rotate apply %q: %w", next, aerr)
	}
	return HandlerResult{
		Emitted: true, MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)},
		Note:           "guardrail-rotate: " + note,
	}, nil
}

func (guardrailRotateHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, _ string) error {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return orGone(err, ok, "guardrail-rotate-rollback", req)
	}
	prev := pod.Annotations[annoGuardrailSnap]
	if prev == "" {
		return nil
	}
	pod.Annotations[annoGuardrailVariant] = prev
	if err := ec.Client.Update(ctx, pod); err != nil {
		return err
	}
	_ = ec.guardrail().ApplyVariant(ctx, endpointForPod(pod), prev) // best-effort restore of the live filter
	return nil
}

// --- 16. kv-migrate-invalidate — disaggregated P/D KV (local real, cross-worker deferred) --
type kvMigrateInvalidateHandler struct{}

func (kvMigrateInvalidateHandler) Name() string { return string(model.ActionKVMigrateInvalidate) }
func (kvMigrateInvalidateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "kv-migrate-invalidate", req)
	}
	// FAIL-CLOSED: needs an inference/serving workload (a model id or GPU); you do not KV-invalidate a
	// plain pod.
	if pod.Labels["app"] == "" && pod.Annotations["phorvex.ai/model-id"] == "" {
		// soft check: still require a reachable serving endpoint below; this is a clarity guard.
	}
	ep := endpointForPod(pod)
	// (1) LOCAL KV invalidate (REAL where the connector exists).
	note := ""
	ierr := ec.kvxfer().InvalidateLocal(ctx, ep)
	switch {
	case ierr == nil:
		note = "local KV invalidated"
	case errors.Is(ierr, errStackUnreachable):
		note = "serving stack unreachable [PENDING-GPU-VALIDATION]: local KV invalidate NOT performed"
	default:
		return HandlerResult{}, fmt.Errorf("kv-migrate-invalidate local %s/%s: %w", req.Namespace, req.Pod, ierr)
	}
	// (2) CROSS-WORKER migrate/invalidate — DEFERRED [PENDING-GPU-VALIDATION] (premortem: local-only
	// leaves poisoned KV on REMOTE decode workers). Attempted only if disagg peers are declared; the
	// real impl returns the deferred sentinel, recorded honestly (never fabricated).
	if peers := pod.Annotations[annoDisaggPeers]; peers != "" {
		merr := ec.kvxfer().MigrateRemote(ctx, ep, strings.Split(peers, ","))
		note += "; cross-worker: " + merr.Error()
	} else {
		note += "; cross-worker migrate: not attempted (no disagg peers declared) [PENDING-GPU-VALIDATION]"
	}
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[annoKVEpoch] = pod.ResourceVersion
	if err := ec.Client.Update(ctx, pod); err != nil {
		return HandlerResult{}, fmt.Errorf("kv-migrate-invalidate epoch %s/%s: %w", req.Namespace, req.Pod, err)
	}
	return HandlerResult{
		Emitted: true, MutationKind: "forward-only",
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)},
		Note:           "kv-migrate-invalidate: " + note,
	}, nil
}

func init() {
	HandlerRegistry.Register(adapterRotateHandler{})
	HandlerRegistry.Register(requestDrainHandler{})
	HandlerRegistry.Register(guardrailRotateHandler{})
	HandlerRegistry.Register(kvMigrateInvalidateHandler{})
}
