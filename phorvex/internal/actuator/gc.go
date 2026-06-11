/*
 * Phorvex — orphaned-NetworkPolicy garbage collection (P4b fix).
 *
 * quarantine creates a deny-all NetworkPolicy labeled managed-by=phorvex +
 * phorvex.ai/quarantine-of=<pod>. If the target pod is deleted out from under us (a crash
 * mid-actuation, or an external delete) the NP is ORPHANED — never reaped. This GC reaps an
 * orphaned NP ONLY when its target pod is CONFIRMED gone (NotFound). FAIL-SAFE: on any other
 * Get error (API hiccup) it SKIPS — it never deletes a live quarantine's policy on uncertainty.
 */

package actuator

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	npManagedByLabel  = "app.kubernetes.io/managed-by"
	npManagedByValue  = "phorvex"
	npQuarantineOfKey = "phorvex.ai/quarantine-of"
)

// GCOrphanedQuarantineNPs deletes Phorvex deny-all NetworkPolicies whose target pod no longer
// exists, in the given namespace. Returns the count reaped. Fail-safe: a NP is reaped ONLY on
// a confirmed NotFound of its target pod.
func GCOrphanedQuarantineNPs(ctx context.Context, c client.Client, namespace string) (int, error) {
	var nps networkingv1.NetworkPolicyList
	if err := c.List(ctx, &nps, client.InNamespace(namespace), client.MatchingLabels{npManagedByLabel: npManagedByValue}); err != nil {
		return 0, err
	}
	reaped := 0
	for i := range nps.Items {
		np := &nps.Items[i]
		if np.DeletionTimestamp != nil {
			continue
		}
		target := np.Labels[npQuarantineOfKey]
		if target == "" {
			continue // not a per-pod quarantine NP; leave it
		}
		var pod corev1.Pod
		err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: target}, &pod)
		if err == nil {
			continue // target pod still exists => a live quarantine; keep the NP
		}
		if !apierrors.IsNotFound(err) {
			continue // FAIL-SAFE: uncertain (API hiccup) => do NOT delete
		}
		// target pod CONFIRMED gone => orphaned deny-all NP => reap it.
		if derr := c.Delete(ctx, np); derr == nil || apierrors.IsNotFound(derr) {
			reaped++
		}
	}
	return reaped, nil
}
