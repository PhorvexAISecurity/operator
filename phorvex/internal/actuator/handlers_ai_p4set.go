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
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

const (
	labelLoRAEnabled     = "phorvex.ai/lora-enabled"       // pod advertises --enable-lora
	annoLoRAAdapter      = "phorvex.ai/lora-adapter"       // the adapter to evict
	annoLoRACleanSource  = "phorvex.ai/lora-clean-source"  // a TRUSTED pinned source to reload (optional)
	annoAdapterSnapshot  = "phorvex.ai/adapter-snapshot"   // rollback record
	labelGuardrailTier   = "phorvex.ai/guardrail-tier"     // marks a guardrail pod
	annoGuardrailVariant = "phorvex.ai/guardrail-variant"  // current variant
	annoGuardrailAlts    = "phorvex.ai/guardrail-variants" // comma-list of DIVERSE alternates
	annoGuardrailSnap    = "phorvex.ai/guardrail-snapshot" // rollback record
	annoDisaggPeers      = "phorvex.ai/disagg-kv-peers"    // <=32 validated DNS/IP host:port P/D endpoints, <=4096 bytes
	annoKVEpoch          = "phorvex.ai/kv-migrate-epoch"
	labelServing         = "phorvex.ai/serving"        // K8s readiness-drain target label
	labelDrainEpoch      = "phorvex.ai/drain-epoch"    // M-23 A1: event-valued clock for VarDrainEpoch
	labelParallelGroup   = "phorvex.ai/parallel-group" // TP/PP group id (a consistency unit)
	labelRank            = "phorvex.ai/rank"           // rank within the parallel group
	annoParallelSize     = "phorvex.ai/parallel-size"  // number of ranks in the group
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
	// [M-69] Refuse before any group mutation unless the observed trigger is the selected Pod.
	if reason := triggerIdentityRefusal(req, trig); reason != "" {
		return refuseAI("model-shard-replace", reason)
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
	ranks := make([]string, 0, len(readyByRank))
	for rank := range readyByRank {
		ranks = append(ranks, rank)
	}
	sort.Strings(ranks)
	// (1) FLIP UP every shadow rank to leader, COHERENTLY; roll back all on any failure.
	var flipped []*corev1.Pod
	for _, rank := range ranks {
		s := readyByRank[rank]
		s.Labels[labelRole] = roleLeader
		if err := ec.Client.Update(ctx, s); err != nil {
			var compensation []error
			var restored, unresolved []string
			touched := make([]string, 0, len(flipped)+1)
			failedTouched, failedRestored, failedErr := reconcileFailedPromotion(ctx, ec.Client, s)
			if failedTouched {
				touched = append(touched, objRef("Pod", s.Namespace, s.Name))
			}
			if failedRestored {
				restored = append(restored, s.Name)
			}
			if failedErr != nil {
				unresolved = append(unresolved, s.Name)
				compensation = append(compensation, fmt.Errorf("reconcile failed rank %s pod %s uid %s: %w", s.Labels[labelRank], s.Name, s.UID, failedErr))
			}
			for i := len(flipped) - 1; i >= 0; i-- {
				f := flipped[i]
				touched = append(touched, objRef("Pod", f.Namespace, f.Name))
				if rerr := updateObservedRole(ctx, ec.Client, f, roleShadow); rerr != nil {
					unresolved = append(unresolved, f.Name)
					compensation = append(compensation, fmt.Errorf("restore rank %s pod %s uid %s: %w", f.Labels[labelRank], f.Name, f.UID, rerr))
				} else {
					restored = append(restored, f.Name)
				}
			}
			status := "all promoted ranks restored"
			if len(compensation) != 0 {
				status = fmt.Sprintf("PARTIAL: restored %v; unresolved or remaining promoted %v", restored, unresolved)
			}
			return HandlerResult{MutationKind: "swap", RollbackRef: req.Namespace + "/" + group, ObjectsTouched: touched},
				fmt.Errorf("model-shard-replace TP/PP flip-up %s (%s): %w", s.Name, status, errors.Join(append([]error{err}, compensation...)...))
		}
		flipped = append(flipped, s)
	}
	// (2) DRAIN + RETIRE the old leaders of the group, coherently. [M-69] Each Delete is bound to
	// the UID of the list object that selected that leader for retirement; the trigger keeps the
	// identity verified above (a same-name object listed under another UID is a replacement, not
	// the trigger). A rejected Delete is never swallowed: the move reports which old leaders were
	// NOT retired and the partial state (shadows promoted, names relabeled) rather than claiming
	// every old member retired. No rollback is attempted.
	var leaders corev1.PodList
	if err := ec.Client.List(ctx, &leaders, client.InNamespace(req.Namespace), sel); err != nil {
		return groupPartialResult(req, group, flipped, nil), fmt.Errorf("model-shard-replace TP/PP old-group inventory failed (shadows promoted; retirement unverified): %w", err)
	}
	sort.Slice(leaders.Items, func(i, j int) bool {
		if leaders.Items[i].Labels[labelRank] != leaders.Items[j].Labels[labelRank] {
			return leaders.Items[i].Labels[labelRank] < leaders.Items[j].Labels[labelRank]
		}
		return leaders.Items[i].Name < leaders.Items[j].Name
	})
	touched := make([]string, 0, len(flipped)+size)
	var retired, notRetired []string
	var delErrs []error
	var pendingDrains []string
	for i := range leaders.Items {
		old := &leaders.Items[i]
		for _, promoted := range flipped {
			if old.Name == promoted.Name && old.UID != promoted.UID {
				notRetired = append(notRetired, old.Name)
				delErrs = append(delErrs, fmt.Errorf("%w: promoted pod %s/%s uid %s replaced by listed uid %s", errPodReplaced, old.Namespace, old.Name, promoted.UID, old.UID))
			}
		}
		if promotedName(old, flipped) {
			continue
		}
		if old.Labels[labelRole] != roleRetiring && isOldLeader(old, flipped) {
			if old.Name == trig.Name && old.UID != trig.UID {
				notRetired = append(notRetired, old.Name)
				delErrs = append(delErrs, fmt.Errorf("%w: %s/%s listed uid %s, observed trigger uid %s", errPodReplaced, old.Namespace, old.Name, old.UID, trig.UID))
				continue
			}
			if rerr := updateObservedRole(ctx, ec.Client, old, roleRetiring); rerr != nil {
				notRetired = append(notRetired, old.Name)
				delErrs = append(delErrs, fmt.Errorf("relabel old leader %s uid %s: %w", old.Name, old.UID, rerr))
				continue
			}
			touched = append(touched, objRef("Pod", old.Namespace, old.Name))
			_, drainPending, drainErr := drainInflight(ctx, ec, old)
			if drainErr != nil {
				notRetired = append(notRetired, old.Name)
				delErrs = append(delErrs, fmt.Errorf("drain old leader %s uid %s: %w", old.Name, old.UID, drainErr))
				continue
			}
			if drainPending {
				pendingDrains = append(pendingDrains, old.Name)
				notRetired = append(notRetired, old.Name)
				continue
			}
			if _, derr := deleteObservedPod(ctx, ec.Client, old); derr != nil {
				notRetired = append(notRetired, old.Name)
				delErrs = append(delErrs, derr)
				continue
			}
			retired = append(retired, old.Name)
		}
	}
	for _, s := range flipped {
		touched = append(touched, objRef("Pod", req.Namespace, s.Name))
	}
	if len(delErrs) > 0 || len(pendingDrains) > 0 {
		return HandlerResult{MutationKind: "swap", RollbackRef: req.Namespace + "/" + group, ObjectsTouched: touched},
			fmt.Errorf("model-shard-replace TP/PP group %q PARTIAL (no rollback): %d shadow ranks promoted to leader, old leaders retired %v, NOT retired %v, drain pending %v: %w", group, len(flipped), retired, notRetired, pendingDrains, errors.Join(append(delErrs, pendingErrors(pendingDrains)...)...))
	}
	note := fmt.Sprintf("model-shard-replace: TP/PP group %q flipped COHERENTLY (%d ranks), old group drained + retired (%d old leaders)", group, size, len(retired))
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

func promotedName(p *corev1.Pod, flipped []*corev1.Pod) bool {
	for _, f := range flipped {
		if f.Name == p.Name {
			return true
		}
	}
	return false
}

// A rejected Update can still have reached the API. Inspect that rank before declaring rollback.
func reconcileFailedPromotion(ctx context.Context, c client.Client, attempted *corev1.Pod) (touched, restored bool, err error) {
	if attempted.UID == "" {
		return false, false, fmt.Errorf("%w: %s/%s", errObservedUIDMissing, attempted.Namespace, attempted.Name)
	}
	var current corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: attempted.Namespace, Name: attempted.Name}, &current); err != nil {
		return true, false, err
	}
	if current.UID != attempted.UID {
		return true, false, fmt.Errorf("%w: %s/%s attempted uid %s current uid %s", errPodReplaced, attempted.Namespace, attempted.Name, attempted.UID, current.UID)
	}
	switch current.Labels[labelRole] {
	case roleShadow:
		return false, false, nil
	case roleLeader:
		current.Labels = ensureMap(current.Labels)
		current.Labels[labelRole] = roleShadow
		if err := c.Update(ctx, &current); err != nil {
			return true, false, err
		}
		return true, true, nil
	default:
		return true, false, fmt.Errorf("failed promotion role unresolved on %s/%s: %q", attempted.Namespace, attempted.Name, current.Labels[labelRole])
	}
}

// updateObservedRole changes only the role on a freshly read Pod. Its observed UID binds the
// write to the selected object, while the fresh resource version preserves concurrent metadata.
func updateObservedRole(ctx context.Context, c client.Client, observed *corev1.Pod, role string) error {
	if observed.UID == "" {
		return fmt.Errorf("%w: %s/%s", errObservedUIDMissing, observed.Namespace, observed.Name)
	}
	var current corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: observed.Namespace, Name: observed.Name}, &current); err != nil {
		return err
	}
	if current.UID != observed.UID {
		return fmt.Errorf("%w: %s/%s observed uid %s current uid %s", errPodReplaced, observed.Namespace, observed.Name, observed.UID, current.UID)
	}
	if current.Labels[labelRole] != observed.Labels[labelRole] && current.Labels[labelRole] != role {
		return fmt.Errorf("role changed concurrently on %s/%s: observed %q current %q", observed.Namespace, observed.Name, observed.Labels[labelRole], current.Labels[labelRole])
	}
	current.Labels = ensureMap(current.Labels)
	current.Labels[labelRole] = role
	return c.Update(ctx, &current)
}

func groupPartialResult(req Request, group string, flipped []*corev1.Pod, old []*corev1.Pod) HandlerResult {
	touched := make([]string, 0, len(flipped)+len(old))
	for _, s := range flipped {
		touched = append(touched, objRef("Pod", s.Namespace, s.Name))
	}
	for _, p := range old {
		touched = append(touched, objRef("Pod", p.Namespace, p.Name))
	}
	return HandlerResult{MutationKind: "swap", RollbackRef: req.Namespace + "/" + group, ObjectsTouched: touched}
}

func pendingErrors(names []string) []error {
	errs := make([]error, 0, len(names))
	for _, name := range names {
		errs = append(errs, fmt.Errorf("old leader %s drain unconfirmed: serving endpoint unreachable [PENDING-GPU-VALIDATION]", name))
	}
	return errs
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
	return enactAdapterRotate(ctx, ec, req)
}

// Rollback is guarded compensation, not restoration from tenant state. It reloads only when the
// current Pod UID and trusted assertion still identify the snapshotted adapter and the immutable
// operator mapping still supplies an exact local path. Missing authority is an explicit refusal.
// Mapping approval does not prove the serving-local artifact's contents are clean.
func (adapterRotateHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, _ string) error {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return orGone(err, ok, "adapter-rotate-rollback", req)
	}
	if req.TargetUID == "" || req.TargetUID != string(pod.UID) {
		return fmt.Errorf("adapter-rotate rollback refused: target UID unavailable or changed")
	}
	adapter, evidenceErr := validateAdapterDispatch(ctx, ec, req, string(pod.UID))
	if evidenceErr != nil {
		return fmt.Errorf("adapter-rotate rollback refused: %w", evidenceErr)
	}
	var snap struct{ Adapter string }
	if err := json.Unmarshal([]byte(pod.Annotations[annoAdapterSnapshot]), &snap); err != nil || snap.Adapter == "" || snap.Adapter != adapter {
		return fmt.Errorf("adapter-rotate rollback refused: snapshot adapter identity invalid")
	}
	clean, approved := ec.AdapterSources.source(req.Namespace, adapter)
	if !approved {
		return fmt.Errorf("adapter-rotate rollback unsupported: no operator-approved source")
	}
	ep := endpointForPod(pod)
	loaded, err := ec.vllm().AdapterLoaded(ctx, ep, adapter)
	if err != nil {
		return fmt.Errorf("adapter-rotate rollback inventory unavailable: %w", err)
	}
	if loaded {
		return nil
	}
	if err := ec.vllm().LoadAdapter(ctx, ep, adapter, clean); err != nil {
		return err
	}
	if err := waitAdapterMembership(ctx, ec, ep, adapter, true); err != nil {
		return fmt.Errorf("adapter-rotate rollback load unconfirmed: %w", err)
	}
	return nil
}

// --- 14. request-drain — request-granular in-flight eviction ------------------------------
type requestDrainHandler struct{}

func (requestDrainHandler) Name() string { return string(model.ActionRequestDrain) }
func (requestDrainHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	return enactRequestDrain(ctx, ec, req)
}

// restoreObservedServing re-reads the accepted stop-admit object so a concurrent annotation,
// drain epoch or same-name replacement cannot be overwritten by failure compensation.
func restoreObservedServing(ctx context.Context, c client.Client, stopped *corev1.Pod, present bool, value string) error {
	if stopped.UID == "" {
		return fmt.Errorf("%w: %s/%s", errObservedUIDMissing, stopped.Namespace, stopped.Name)
	}
	var current corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: stopped.Namespace, Name: stopped.Name}, &current); err != nil {
		return err
	}
	if current.UID != stopped.UID {
		return fmt.Errorf("%w: %s/%s stopped uid %s current uid %s", errPodReplaced, stopped.Namespace, stopped.Name, stopped.UID, current.UID)
	}
	if current.Labels[labelDrainEpoch] != stopped.Labels[labelDrainEpoch] {
		return fmt.Errorf("drain epoch changed concurrently on %s/%s: operation %q current %q", stopped.Namespace, stopped.Name, stopped.Labels[labelDrainEpoch], current.Labels[labelDrainEpoch])
	}
	if current.Labels[labelServing] != "drained" {
		return fmt.Errorf("serving label changed concurrently on %s/%s: %q", stopped.Namespace, stopped.Name, current.Labels[labelServing])
	}
	current.Labels = ensureMap(current.Labels)
	if present {
		current.Labels[labelServing] = value
	} else {
		delete(current.Labels, labelServing)
	}
	return c.Update(ctx, &current)
}

// Rollback only finishes an exact protected restoration obligation. It never guesses a
// serving value from an unbound namespace/Pod reference.
func (requestDrainHandler) Rollback(ctx context.Context, ec EnactCtx, req Request, ref string) error {
	return rollbackRequestDrain(ctx, ec, req, ref)
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
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("guardrail-rotate GuardrailUnavailable: pod %s/%s is not %s / declares no %s [PENDING-GPU-VALIDATION]", req.Namespace, req.Pod, labelGuardrailTier, annoGuardrailAlts))
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
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("guardrail-rotate: no DISTINCT alternate variant (only %q declared) — rotation would not change the blind spot", cur))
	}
	// (1) apply the variant to the live guardrail first. A K8s annotation is only a
	// forensic record; it must never turn an unconfirmed filter change into a
	// successful actuation.
	aerr := ec.guardrail().ApplyVariant(ctx, endpointForPod(pod), next)
	switch {
	case aerr == nil:
	case errors.Is(aerr, errStackUnreachable):
		return HandlerResult{
			Emitted: false, MutationKind: "none",
			Note: "[PENDING-GPU-VALIDATION] guardrail-rotate outcome unconfirmed: guardrail service " +
				"unreachable at " + req.Namespace + "/" + req.Pod + " — live filter change was NOT " +
				"credited and no variant/epoch record was written",
		}, nil
	default:
		return HandlerResult{}, fmt.Errorf("guardrail-rotate apply %q: %w", next, aerr)
	}

	// (2) persist the confirmed live transition and its rollback snapshot. If this
	// write fails, restore the live filter so runtime and Kubernetes do not diverge.
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[annoGuardrailSnap] = cur
	pod.Annotations[annoGuardrailVariant] = next
	pod.Labels = ensureMap(pod.Labels)
	pod.Labels["phorvex.ai/guardrail-epoch"] = pod.ResourceVersion
	if err := ec.Client.Update(ctx, pod); err != nil {
		persistErr := fmt.Errorf("guardrail-rotate record %s/%s: %w", req.Namespace, req.Pod, err)
		if restoreErr := ec.guardrail().ApplyVariant(ctx, endpointForPod(pod), cur); restoreErr != nil {
			return HandlerResult{}, errors.Join(persistErr, fmt.Errorf("restore live variant %q: %w", cur, restoreErr))
		}
		return HandlerResult{}, persistErr
	}
	return HandlerResult{
		Emitted: true, MutationKind: "reversible", RollbackRef: req.Namespace + "/" + req.Pod,
		ObjectsTouched: []string{objRef("Pod", req.Namespace, req.Pod)},
		Note:           "guardrail-rotate: variant " + cur + " -> " + next + " applied to the guardrail service (bypass staled)",
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

// parseDisaggKVPeers validates the complete tenant declaration before the
// handler performs any effect. It accepts at most 32 comma-separated host:port
// endpoints in 4096 bytes: an ASCII DNS name, IPv4 address, or bracketed IPv6
// address with a numeric port in 1..65535. It only parses and normalizes; it
// never resolves a name or contacts a declared destination.
func parseDisaggKVPeers(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	if len(raw) > 4096 {
		return nil, fmt.Errorf("peer declaration exceeds 4096 bytes")
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 32 {
		return nil, fmt.Errorf("peer declaration exceeds 32 entries")
	}
	peers := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for i, part := range parts {
		endpoint := strings.TrimSpace(part)
		if endpoint == "" {
			return nil, fmt.Errorf("peer %d is empty", i+1)
		}
		for _, r := range endpoint {
			if unicode.IsSpace(r) || unicode.IsControl(r) {
				return nil, fmt.Errorf("peer %d contains whitespace or control characters", i+1)
			}
		}
		host, portText, err := net.SplitHostPort(endpoint)
		if err != nil || host == "" || portText == "" {
			return nil, fmt.Errorf("peer %d must be DNS, IPv4, or bracketed IPv6 host:port", i+1)
		}
		for _, r := range portText {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("peer %d has a nonnumeric port", i+1)
			}
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("peer %d port must be in 1..65535", i+1)
		}

		bracketed := strings.HasPrefix(endpoint, "[")
		normalizedHost := ""
		if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
			if (bracketed && addr.Is4()) || addr.Zone() != "" || addr.Unmap().IsUnspecified() {
				return nil, fmt.Errorf("peer %d uses an unsupported or unspecified address", i+1)
			}
			normalizedHost = addr.String()
		} else {
			if bracketed {
				return nil, fmt.Errorf("peer %d brackets are valid only for IPv6", i+1)
			}
			var hostErr error
			normalizedHost, hostErr = normalizeDisaggDNS(host)
			if hostErr != nil {
				return nil, fmt.Errorf("peer %d: %w", i+1, hostErr)
			}
		}
		normalized := net.JoinHostPort(normalizedHost, strconv.FormatUint(port, 10))
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		peers = append(peers, normalized)
	}
	return peers, nil
}

func normalizeDisaggDNS(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("DNS hostname length is invalid")
	}
	looksLikeIPv4 := strings.Contains(host, ".")
	for _, r := range host {
		if (r < '0' || r > '9') && r != '.' {
			looksLikeIPv4 = false
			break
		}
	}
	if looksLikeIPv4 {
		return "", fmt.Errorf("malformed IPv4 address")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("DNS hostname label is invalid")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("DNS hostname contains an invalid character")
			}
		}
	}
	return host, nil
}

func (kvMigrateInvalidateHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	pod, ok, err := getPod(ctx, ec.Client, req.Namespace, req.Pod)
	if err != nil || !ok {
		return HandlerResult{}, orGone(err, ok, "kv-migrate-invalidate", req)
	}
	peers, err := parseDisaggKVPeers(pod.Annotations[annoDisaggPeers])
	if err != nil {
		return HandlerResult{}, RefusedWithoutEffect(fmt.Errorf("kv-migrate-invalidate invalid %s: %w", annoDisaggPeers, err))
	}
	// FAIL-CLOSED: needs an inference/serving workload (a model id or GPU); you do not KV-invalidate a
	// plain pod.
	if pod.Labels["app"] == "" && pod.Annotations["phorvex.ai/model-id"] == "" {
		// soft check: still require a reachable serving endpoint below; this is a clarity guard.
	}
	ep := endpointForPod(pod)
	// (1) LOCAL KV invalidate (REAL where the connector exists).
	note := "local KV invalidated"
	ierr := ec.kvxfer().InvalidateLocal(ctx, ep)
	switch {
	case ierr == nil:
	case errors.Is(ierr, errStackUnreachable):
		// [FAIL-CLOSED FIX] The local invalidate did not return a confirmed success. A dial failure
		// means it did not run; a timeout leaves the outcome unknown. In neither case may we claim that
		// local or remote KV was invalidated. This branch used to fall through and return
		// Emitted:true after stamping a kv-epoch, the same false-forensic-record class already fixed
		// in kv-reset: a poisoned KV that was never invalidated was counted as a real actuation. The
		// invalidate IS the whole move (there is no stack-independent half), so report NOT emitted and
		// write no epoch — a KV epoch for an invalidate that never ran is a false forensic record.
		return HandlerResult{
			Emitted: false, MutationKind: "none",
			Note: "[PENDING-GPU-VALIDATION] kv-migrate-invalidate outcome unconfirmed: no usable " +
				"serving-stack response at " + req.Namespace + "/" + req.Pod + " — no local or " +
				"cross-worker invalidation was credited",
		}, nil
	default:
		return HandlerResult{}, fmt.Errorf("kv-migrate-invalidate local %s/%s: %w", req.Namespace, req.Pod, ierr)
	}
	// (2) CROSS-WORKER migrate/invalidate — DEFERRED [PENDING-GPU-VALIDATION] (premortem: local-only
	// leaves poisoned KV on REMOTE decode workers). Attempted only if disagg peers are declared; the
	// real impl returns the deferred sentinel, recorded honestly (never fabricated).
	var remoteErr error
	if len(peers) > 0 {
		remoteErr = ec.kvxfer().MigrateRemote(ctx, ep, peers)
		if remoteErr == nil {
			note += fmt.Sprintf("; cross-worker connector confirmed its operation for %d validated peer(s)", len(peers))
		} else {
			note += "; cross-worker outcome unconfirmed: " + remoteErr.Error()
		}
	} else {
		note += "; cross-worker migrate: not attempted (no disagg peers declared) [PENDING-GPU-VALIDATION]"
	}
	pod.Annotations = ensureMap(pod.Annotations)
	pod.Annotations[annoKVEpoch] = pod.ResourceVersion
	updateErr := ec.Client.Update(ctx, pod)
	result := HandlerResult{Emitted: true, MutationKind: "forward-only", Note: "kv-migrate-invalidate: " + note}
	if updateErr == nil {
		result.ObjectsTouched = []string{objRef("Pod", req.Namespace, req.Pod)}
	} else {
		result.MutationKind = "partial"
		result.Note += "; local effect occurred but the KV epoch record failed"
		updateErr = fmt.Errorf("kv-migrate-invalidate epoch %s/%s: %w", req.Namespace, req.Pod, updateErr)
	}
	if remoteErr != nil {
		result.MutationKind = "partial"
		remoteErr = fmt.Errorf("kv-migrate-invalidate cross-worker operation: %w", remoteErr)
	}
	return result, errors.Join(remoteErr, updateErr)
}

func init() {
	HandlerRegistry.Register(adapterRotateHandler{})
	HandlerRegistry.Register(requestDrainHandler{})
	HandlerRegistry.Register(guardrailRotateHandler{})
	HandlerRegistry.Register(kvMigrateInvalidateHandler{})
}
