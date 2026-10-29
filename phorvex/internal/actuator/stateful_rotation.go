/*
 * Phorvex — native stateful rotation (P-ACTUATOR).
 *
 * One handler flow, three classes. Every class runs the same bounded sequence, so the
 * safety argument is made once:
 *
 *   1. read the exact live target (UID-bound) and re-observe its StatefulSet + claims;
 *   2. re-admit the class with the SAME statefulrotation.Admit law the brain used;
 *   3. bind the exact selecting-policy epoch and grace cap (shared with rotate);
 *   4. DRY-RUN the Eviction: PodDisruptionBudget admission is proven before any
 *      preparatory step, so a budget refusal never leaves a half-prepared member;
 *   5. run the class's preparatory step (A: delete claims; B: ready snapshot; C: checkpoint);
 *   6. submit the real bounded Eviction under UID/resourceVersion preconditions;
 *   7. observe, within a bounded window, the replacement member Ready and the class's own
 *      continuity property (A: fresh claims; B: same claims; C: restored checkpoint digest).
 *
 * The StatefulSet controller performs the replacement; this handler never deletes a Pod
 * outside the Eviction API, never scales the owner, and never touches another member.
 */

package actuator

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/statefulrotation"
)

const (
	// statefulConfirmTimeout bounds the inline replacement observation (like controller-stop's
	// bounded window). A slower recovery is reported unconfirmed, never as failure or success.
	statefulConfirmTimeout  = 90 * time.Second
	statefulConfirmInterval = 2 * time.Second
)

// statefulClass is one stateful rotation class's preparatory and continuity steps.
type statefulClass interface {
	action() model.Action
	// prepare runs after admission and the PDB dry run, before the real Eviction. It returns
	// a refusal reason for a recognized pre-eviction stop and an error for unknown effect.
	prepare(ctx context.Context, ec EnactCtx, op *statefulOperation) (string, error)
	// confirm checks the class's continuity property on the Ready replacement.
	confirm(ctx context.Context, ec EnactCtx, op *statefulOperation, replacement *corev1.Pod) (string, bool)
}

// statefulOperation is the per-dispatch record shared by the flow and the class steps.
type statefulOperation struct {
	req     Request
	pod     *corev1.Pod
	obs     *model.StatefulRotationObservation
	touched []string
	// prepared is true once a preparatory step changed cluster state; a later stop is then a
	// confirmed partial mutation, never a clean refusal.
	prepared    bool
	rollbackRef string
	notes       []string
	checkpoint  statefulCheckpoint
}

func (op *statefulOperation) touch(kind, name string) {
	op.touched = append(op.touched, objRef(kind, op.req.Namespace, name))
}

type statefulRotationHandler struct{ class statefulClass }

func (h statefulRotationHandler) Name() string { return string(h.class.action()) }

func (h statefulRotationHandler) Enact(ctx context.Context, ec EnactCtx, req Request) (HandlerResult, error) {
	if ec.DryRun {
		return HandlerResult{}, errDryRunGuard
	}
	action := h.class.action()
	refuse := func(reason string) (HandlerResult, error) {
		disposition := NoEffectRefused
		if reason == "target-already-gone" {
			disposition = NoEffectSatisfied
		}
		return HandlerResult{NoEffect: disposition, Note: fmt.Sprintf("Stateful rotation (%s) not performed: %s", action, reason)}, nil
	}
	pod, refusal := readEvictionTarget(ctx, ec, req)
	if refusal != "" {
		return refuse(refusal)
	}
	obs := statefulrotation.Observe(ctx, ec.Reader, pod)
	if ok, why := statefulrotation.Admit(obs, statefulrotation.PodReady(pod), action); !ok {
		return refuse("stateful-admission: " + why)
	}
	grant, refusal := bindPolicyEviction(ctx, ec, req, pod, v1alpha1.ActionType(action))
	if refusal != "" {
		return refuse(refusal)
	}
	if refusal, err := evictBounded(ctx, ec, req, grant, true); refusal != "" || err != nil {
		if err != nil {
			return HandlerResult{}, fmt.Errorf("%s eviction dry run %s/%s: %w", action, req.Namespace, req.Pod, err)
		}
		return refuse(refusal)
	}

	op := &statefulOperation{req: req, pod: pod, obs: obs}
	if refusal, err := h.class.prepare(ctx, ec, op); refusal != "" || err != nil {
		return op.stopped(action, stepReason("preparation", refusal), err)
	}
	if refusal, err := evictBounded(ctx, ec, req, grant, false); refusal != "" || err != nil {
		return op.stopped(action, stepReason("eviction", refusal), err)
	}
	op.touch("Pod", req.Pod)
	confirmation := awaitStatefulReplacement(ctx, ec, op, h.class)
	return HandlerResult{
		Emitted: true, MutationKind: "forward-only",
		ObjectsTouched:      op.touched,
		RollbackRef:         op.rollbackRef,
		GracefulTermination: grant.receipt(req.Namespace),
		Note: fmt.Sprintf("%s: Pod Eviction accepted with policy grace cap %ds and effective grace %ds; %s; %s",
			action, grant.policyCap, grant.effectiveGrace, strings.Join(op.notes, "; "), confirmation),
	}, nil
}

// stopped reports a stop after admission. Before any preparatory mutation it is a clean
// refusal (or an unknown-effect error); after one it is a confirmed partial mutation whose
// touched objects and rollback reference are retained for the audit. A recognized refusal
// leaves the target Pod in place; an error leaves the stopped step's own effect unknown and
// is returned alongside the partial result, never folded into it.
func (op *statefulOperation) stopped(action model.Action, reason string, err error) (HandlerResult, error) {
	if !op.prepared {
		if err != nil {
			return HandlerResult{}, fmt.Errorf("%s %s/%s %s: %w", action, op.req.Namespace, op.req.Pod, reason, err)
		}
		return HandlerResult{NoEffect: NoEffectRefused, Note: fmt.Sprintf("Stateful rotation (%s) not performed: %s", action, reason)}, nil
	}
	outcome := "target Pod retained: " + reason
	if err != nil {
		outcome = "outcome of " + reason + " unknown: " + err.Error()
		err = fmt.Errorf("%s %s/%s %s: %w", action, op.req.Namespace, op.req.Pod, reason, err)
	}
	return HandlerResult{
		Emitted: true, MutationKind: "partial",
		ObjectsTouched: op.touched,
		RollbackRef:    op.rollbackRef,
		Note: fmt.Sprintf("Stateful rotation (%s) stopped after its preparatory step; %s; %s",
			action, outcome, strings.Join(op.notes, "; ")),
	}, err
}

func stepReason(step, refusal string) string {
	if refusal == "" {
		return step
	}
	return step + ": " + refusal
}

// awaitStatefulReplacement observes, within a bounded window, the StatefulSet's replacement
// for the evicted ordinal (same name, new UID) become Ready, then the class's continuity
// property. It never mutates; an expired window is reported as unconfirmed.
func awaitStatefulReplacement(ctx context.Context, ec EnactCtx, op *statefulOperation, class statefulClass) string {
	timeout, interval := statefulConfirmTimeout, statefulConfirmInterval
	if ec.StatefulConfirmTimeout > 0 {
		timeout = ec.StatefulConfirmTimeout
	}
	if ec.StatefulConfirmInterval > 0 {
		interval = ec.StatefulConfirmInterval
	}
	if declared := time.Duration(op.obs.Contract.RecoverySeconds) * time.Second; declared > 0 && declared < timeout {
		timeout = declared
	}
	deadline := time.Now().Add(timeout)
	last := "replacement not observed Ready"
	for {
		replacement := &corev1.Pod{}
		err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: op.req.Namespace, Name: op.req.Pod}, replacement)
		if err == nil && replacement.UID != op.pod.UID && replacement.DeletionTimestamp.IsZero() && statefulrotation.PodReady(replacement) {
			detail, ok := class.confirm(ctx, ec, op, replacement)
			if ok {
				return fmt.Sprintf("replacement %s Ready and confirmed: %s", replacement.UID, detail)
			}
			last = fmt.Sprintf("replacement %s Ready but continuity unconfirmed: %s", replacement.UID, detail)
		}
		if !time.Now().Before(deadline) {
			return fmt.Sprintf("%s within %s", last, timeout)
		}
		select {
		case <-ctx.Done():
			return "replacement unconfirmed: observation cancelled"
		case <-time.After(interval):
		}
	}
}

func init() {
	HandlerRegistry.Register(statefulRotationHandler{class: replicaRebuildClass{}})
	HandlerRegistry.Register(statefulRotationHandler{class: snapshotRotateClass{}})
	HandlerRegistry.Register(statefulRotationHandler{class: checkpointHandoffClass{}})
}
