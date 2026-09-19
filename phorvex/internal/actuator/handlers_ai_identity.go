/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P4 — AI/GPU actuator)
 *
 * [M-69] Identity-bound AI Pod retirement. warm-swap, scalar model-shard-replace, and
 * mig-rebind retire Pods by DELETING them. Historical TP/PP helper tests retain these
 * guards, while production dispatch refuses grouped replacement. A Pod name is not an identity: the
 * owner respawns a replacement under the SAME namespace/name, so a delayed retry of the same
 * decision — or a Delete issued after the observed object was already replaced — would kill
 * the respawned Pod that nothing ever selected. Native rotate already binds its Delete to the
 * observed UID (+ResourceVersion); these helpers give the AI paths the same identity contract:
 *
 *   1. the trigger Pod must match Request.TargetUID (the identity the runner captured from
 *      the selecting snapshot) BEFORE anything is mutated — refusal follows native rotate's
 *      convention (not emitted, reason in the Note, no error);
 *   2. every Delete carries the UID of the observed object that planned that retirement,
 *      enforced by the API server, so a same-name replacement is NEVER deleted.
 *
 * Only the UID is pinned, not the ResourceVersion: the handlers legitimately relabel the old
 * leader `retiring` before deleting it, so a pre-relabel version would always be stale.
 */

package actuator

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Refusal reasons for the pre-mutation trigger identity check (native rotate vocabulary).
const (
	reasonTargetUIDUnavailable   = "target-uid-unavailable"
	reasonObservedUIDUnavailable = "observed-uid-unavailable"
	reasonTargetUIDMismatch      = "target-uid-mismatch"
)

// errPodReplaced marks a Delete rejected by the API server's UID precondition: an object of
// the observed name exists but it is NOT the observed Pod. The replacement is untouched.
var errPodReplaced = errors.New("same-name replacement detected; observed pod not deleted")

// errObservedUIDMissing marks an observed object that carries no UID; an identity-bound
// Delete cannot be formed for it, so it is refused before any Delete is issued.
var errObservedUIDMissing = errors.New("observed pod carries no UID; identity-bound delete refused")

// triggerIdentityRefusal compares the request's bound identity with the observed trigger Pod.
// It returns "" when they agree and a refusal reason otherwise. A missing request identity is
// refused as well: a request that names a Pod but not WHICH Pod cannot be told apart from a
// delayed retry against a same-name replacement.
func triggerIdentityRefusal(req Request, observed *corev1.Pod) string {
	switch {
	case req.TargetUID == "":
		return reasonTargetUIDUnavailable
	case observed.UID == "":
		return reasonObservedUIDUnavailable
	case string(observed.UID) != req.TargetUID:
		return reasonTargetUIDMismatch
	}
	return ""
}

// refuseAI is the native-rotate refusal shape for the AI destructive handlers: nothing was
// mutated, nothing is emitted, the reason is carried in the Note and no error is raised.
func refuseAI(kind, reason string) (HandlerResult, error) {
	return HandlerResult{NoEffect: NoEffectRefused, Note: kind + " not performed: " + reason}, nil
}

// deleteObservedPod deletes exactly the observed Pod object: the Delete carries the observed
// UID as an API-enforced precondition. Outcomes:
//   - (false, nil): the observed Pod's deletion was accepted;
//   - (true, nil):  no Pod of that name exists any more, so the observed one is already gone
//     (NotFound is truthful here — a same-name replacement would NOT be NotFound);
//   - (false, errPodReplaced): a same-name object with a different UID exists; it was left
//     untouched;
//   - (false, errObservedUIDMissing): the observed object has no UID; no Delete was issued;
//   - (false, err): any other API error.
func deleteObservedPod(ctx context.Context, c client.Client, observed *corev1.Pod) (alreadyGone bool, err error) {
	uid := observed.UID
	if uid == "" {
		return false, fmt.Errorf("%w: %s/%s", errObservedUIDMissing, observed.Namespace, observed.Name)
	}
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: observed.Namespace, Name: observed.Name, UID: uid}}
	err = c.Delete(ctx, target, &client.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
	switch {
	case err == nil:
		return false, nil
	case apierrors.IsNotFound(err):
		return true, nil
	case apierrors.IsConflict(err):
		return false, fmt.Errorf("%w: %s/%s observed uid %s: %v", errPodReplaced, observed.Namespace, observed.Name, uid, err)
	default:
		return false, err
	}
}
