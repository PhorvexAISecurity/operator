/*
 * Phorvex — warm-swap CRASH-RESUME reconciler (P4b fix).
 *
 * The 5-phase warm-swap (handlers_ai.go) persisted a 'phorvex.ai/swap-phase=flipping'
 * annotation but NOTHING read it — so an operator crash in the window AFTER the shadow is
 * promoted to role=leader but BEFORE the old leader is relabeled/deleted left a transient
 * DOUBLE-LEADER (the Service routes to both), and a crash between relabel-retiring and
 * delete left an un-reaped retiring pod. This reconciler CONVERGES those wedged states
 * idempotently: it is run each tick before any new decision, so a half-done swap completes
 * (single leader, old leader reaped) without re-deciding. Fail-safe: a single healthy leader
 * is left untouched; only its stale 'flipping' annotation is cleared.
 */

package actuator

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ResumeWarmSwaps converges any warm-swap left wedged by a crash in the given namespace.
// Returns the number of stuck pods reaped/relabeled. Read-mostly; mutates only to COMPLETE
// an interrupted swap (never starts a new one).
func ResumeWarmSwaps(ctx context.Context, c client.Client, namespace string) (int, error) {
	var pods corev1.PodList
	if err := c.List(ctx, &pods, client.InNamespace(namespace), client.HasLabels{labelSwapGroup}); err != nil {
		return 0, err
	}
	converged := 0

	// (1) reap any pod left in role=retiring (a crash between relabel-retiring and delete).
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp == nil && p.Labels[labelRole] == roleRetiring {
			if err := c.Delete(ctx, p); err == nil || apierrors.IsNotFound(err) {
				converged++
			}
		}
	}

	// (2) group the live leaders by swap-group; converge any DOUBLE-leader.
	byGroup := map[string][]*corev1.Pod{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil || p.Labels[labelRole] != roleLeader {
			continue
		}
		g := p.Labels[labelSwapGroup]
		byGroup[g] = append(byGroup[g], p)
	}
	for _, leaders := range byGroup {
		if len(leaders) <= 1 {
			if len(leaders) == 1 {
				clearFlipping(ctx, c, leaders[0]) // stale annotation on a healthy single leader
			}
			continue
		}
		survivor := pickSurvivor(leaders)
		for _, p := range leaders {
			if p.Name == survivor.Name {
				continue
			}
			// COMPLETE the interrupted retire: relabel the extra leader -> retiring, drop the
			// stale annotation, delete it. Idempotent (a re-run finds it already gone).
			p.Labels[labelRole] = roleRetiring
			delete(p.Annotations, annoSwapPhase)
			_ = c.Update(ctx, p)
			if err := c.Delete(ctx, p); err == nil || apierrors.IsNotFound(err) {
				converged++
			}
		}
		clearFlipping(ctx, c, survivor)
	}
	return converged, nil
}

// pickSurvivor deterministically chooses which leader to KEEP in a double-leader group: the
// new (shadow-promoted) leader, identified as the one NOT carrying swap-phase=flipping (the
// OLD leader was annotated 'flipping' before the flip). If that is ambiguous, keep the
// youngest Ready pod (newest CreationTimestamp), else the youngest.
func pickSurvivor(leaders []*corev1.Pod) *corev1.Pod {
	var noFlip []*corev1.Pod
	for _, p := range leaders {
		if p.Annotations[annoSwapPhase] != "flipping" {
			noFlip = append(noFlip, p)
		}
	}
	pool := leaders
	if len(noFlip) >= 1 {
		pool = noFlip // prefer the non-flipping (new) leader(s)
	}
	best := pool[0]
	for _, p := range pool[1:] {
		bReady, pReady := podReady(best), podReady(p)
		if pReady && !bReady {
			best = p
			continue
		}
		if pReady == bReady && p.CreationTimestamp.After(best.CreationTimestamp.Time) {
			best = p // youngest wins the tie (the freshly promoted shadow)
		}
	}
	return best
}

func clearFlipping(ctx context.Context, c client.Client, p *corev1.Pod) {
	if p.Annotations[annoSwapPhase] == "" {
		return
	}
	delete(p.Annotations, annoSwapPhase)
	_ = c.Update(ctx, p)
}
