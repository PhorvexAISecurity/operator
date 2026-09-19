package actuator

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

const warmDrainMaxAttempts = 2

type warmDrainResult int

const (
	warmDrainRetained warmDrainResult = iota
	warmDrainConfirmed
	warmDrainRestored
)

func warmDrainEndpointConfigDigest(pod *corev1.Pod, legacy bool) string {
	if legacy {
		return drainEndpointConfigDigest(pod)
	}
	return secureDrainEndpointConfigDigest(pod)
}

func captureWarmSelectedUIDs(ctx context.Context, reader client.Reader, pool warmPoolIntent, old, next *corev1.Pod, groupKey, groupValue string) ([]string, error) {
	svc := &corev1.Service{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: pool.ServiceName}, svc); err != nil {
		return nil, err
	}
	if string(svc.UID) != pool.ServiceUID || svc.ResourceVersion == "" || svc.DeletionTimestamp != nil || hashWarmObject(svc.Spec.Selector) != pool.ServiceSelectorHash {
		return nil, fmt.Errorf("warm route Service identity changed before intent")
	}
	members, err := routeEndpointMembers(ctx, reader, svc)
	if err != nil {
		return nil, err
	}
	poolMembers := make(map[string]bool, len(pool.Members))
	for _, uid := range pool.Members {
		poolMembers[uid] = true
	}
	for _, uid := range members {
		if !poolMembers[uid] {
			return nil, fmt.Errorf("warm route contains a Pod outside the recorded pool")
		}
	}
	if !containsUID(members, string(old.UID)) || containsUID(members, string(next.UID)) {
		return nil, fmt.Errorf("warm route does not match the pre-cutover old/new roles")
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: old.Namespace, Name: pool.RSName}, rs); err != nil {
		return nil, err
	}
	sel, err := warmPoolSelector(rs, groupKey, groupValue)
	if err != nil {
		return nil, err
	}
	pods, err := warmPoolListMembers(ctx, reader, old.Namespace, sel)
	if err != nil {
		return nil, err
	}
	selected := make(map[string]bool, len(members))
	for _, uid := range members {
		selected[uid] = true
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		want := roleShadow
		if selected[string(pod.UID)] {
			want = roleLeader
		}
		if pod.Labels[labelRole] != want {
			return nil, fmt.Errorf("warm route membership and current role disagree")
		}
	}
	return members, nil
}

func warmDrainRolesCurrent(ctx context.Context, reader client.Reader, r operationReceipt) error {
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.Pool.RSName}, rs); err != nil {
		return err
	}
	sel, err := warmPoolSelector(rs, r.GroupKey, r.GroupValue)
	if err != nil {
		return err
	}
	pods, err := warmPoolListMembers(ctx, reader, r.PolicyNamespace, sel)
	if err != nil {
		return err
	}
	selected := make(map[string]bool, len(r.WarmSelectedUIDs))
	for _, uid := range r.WarmSelectedUIDs {
		selected[uid] = true
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		uid, role := string(pod.UID), pod.Labels[labelRole]
		if uid == r.OldUID {
			allowed := role == roleLeader
			switch r.Phase {
			case "retiring", "drain-dispatching", "drain-unsent", "drain-confirmed":
				allowed = role == roleRetiring
			case "prepared", "promoted", "restore-old-claimed":
				allowed = role == roleLeader || role == roleRetiring
			case "old-route-observed", "restore-shadow-claimed", "routing-restored":
				allowed = role == roleLeader
			}
			if !allowed {
				return fmt.Errorf("recorded old warm role changed")
			}
			continue
		}
		if uid == r.NewUID {
			allowed := role == roleLeader
			switch r.Phase {
			case "prepared", "promoted":
				allowed = role == roleLeader || role == roleShadow
			case "restore-shadow-claimed":
				allowed = role == roleLeader || role == roleShadow
			case "routing-restored":
				allowed = role == roleShadow
			}
			if !allowed {
				return fmt.Errorf("recorded new warm role changed")
			}
			continue
		}
		want := roleShadow
		if selected[uid] {
			want = roleLeader
		}
		if role != want {
			return fmt.Errorf("unrelated warm member role changed")
		}
	}
	return nil
}

func warmDrainCurrentPair(ctx context.Context, ec EnactCtx, r operationReceipt) (*corev1.Pod, *corev1.Pod, error) {
	pol, err := receiptAuthority(ctx, ec.Reader, r, model.Action(r.Kind))
	if err != nil {
		return nil, nil, err
	}
	old, next := &corev1.Pod{}, &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.OldName}, old); err != nil {
		return nil, nil, err
	}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NewName}, next); err != nil {
		return nil, nil, err
	}
	if err := warmCurrentScope(pol, r, old, next); err != nil {
		return nil, nil, err
	}
	if err := warmPoolRecheck(ctx, ec.Reader, r, old, next); err != nil {
		return nil, nil, err
	}
	if err := warmDrainRolesCurrent(ctx, ec.Reader, r); err != nil {
		return nil, nil, err
	}
	if !podReady(old) || !podReady(next) || old.ResourceVersion == "" || next.ResourceVersion == "" {
		return nil, nil, fmt.Errorf("recorded warm pair identity/readiness changed")
	}
	if normalizeServiceAccount(old.Spec.ServiceAccountName) != r.ServingServiceAccount || normalizeServiceAccount(next.Spec.ServiceAccountName) != r.ServingServiceAccount {
		return nil, nil, fmt.Errorf("recorded warm pair ServiceAccount changed")
	}
	if _, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, old); err != nil {
		return nil, nil, fmt.Errorf("recorded old serving endpoint changed: %w", err)
	}
	if warmDrainEndpointConfigDigest(old, r.ServingLegacy) != r.EndpointConfigSHA256 {
		return nil, nil, fmt.Errorf("recorded old serving endpoint binding changed")
	}
	return old, next, nil
}

// executeWarmDrainAttempt grants exactly one send to the caller whose
// retiring/drain-unsent -> drain-dispatching journal CAS was acknowledged.
func executeWarmDrainAttempt(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (warmDrainResult, error) {
	if r.Version != warmDrainReceiptVersion || (r.Phase != "retiring" && r.Phase != "drain-unsent") || r.DrainAttempts >= warmDrainMaxAttempts {
		return warmDrainRetained, fmt.Errorf("warm drain send is not claimable")
	}
	old, next, err := warmDrainCurrentPair(ctx, ec, *r)
	if err != nil {
		return warmDrainRetained, err
	}
	if old.Labels[labelRole] != roleRetiring || next.Labels[labelRole] != roleLeader {
		return warmDrainRetained, fmt.Errorf("recorded pair is not in the drain routing state")
	}
	r.DrainAttempts++
	r.Phase = "drain-dispatching"
	if err := journalAdvance(ctx, ec, cm, *r); err != nil {
		return warmDrainRetained, fmt.Errorf("warm drain dispatch claim was not acknowledged: %w", err)
	}
	ep, err := servingEndpointForPod(ctx, ec, ec.ServingRequest, old)
	if err != nil {
		return warmDrainRetained, err
	}
	aborted, err := ec.vllm().DrainRequests(ctx, ep)
	if err == nil {
		if aborted < 0 {
			return warmDrainRetained, fmt.Errorf("warm drain returned a negative abort count")
		}
		r.Aborted, r.Phase = aborted, "drain-confirmed"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return warmDrainRetained, fmt.Errorf("warm drain confirmation was not acknowledged: %w", err)
		}
		return warmDrainConfirmed, nil
	}
	var unreachable *definiteServingUnreachableError
	if !errors.As(err, &unreachable) {
		return warmDrainRetained, fmt.Errorf("warm drain outcome retained as possibly sent: %w", err)
	}
	r.Aborted, r.Phase = 0, "drain-unsent"
	if err := journalAdvance(ctx, ec, cm, *r); err != nil {
		return warmDrainRetained, fmt.Errorf("definitely-unsent drain evidence was not acknowledged: %w", err)
	}
	if err := compensateWarmRouting(ctx, ec, cm, r); err != nil {
		return warmDrainRetained, err
	}
	return warmDrainRestored, nil
}

func warmExpectedBridge(r operationReceipt) []string {
	out := append([]string(nil), r.WarmSelectedUIDs...)
	out = append(out, r.NewUID)
	sort.Strings(out)
	return out
}

func waitWarmRouteMembers(ctx context.Context, ec EnactCtx, r operationReceipt, expected []string) error {
	timeout, interval := routeTiming(ec)
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	confirmed := false
	var last error
	for {
		svc := &corev1.Service{}
		last = ec.Reader.Get(waitCtx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.Pool.ServiceName}, svc)
		if last == nil && (string(svc.UID) != r.Pool.ServiceUID || svc.ResourceVersion == "" || svc.DeletionTimestamp != nil || hashWarmObject(svc.Spec.Selector) != r.Pool.ServiceSelectorHash) {
			last = fmt.Errorf("warm route Service authority changed")
		}
		if last == nil {
			var got []string
			got, last = routeEndpointMembers(waitCtx, ec.Reader, svc)
			if last == nil && reflect.DeepEqual(got, expected) {
				if confirmed {
					return nil
				}
				confirmed = true
			} else {
				confirmed = false
				if last == nil {
					last = fmt.Errorf("warm route members %v do not match %v", got, expected)
				}
			}
		}
		if last != nil {
			confirmed = false
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("warm route EndpointSlice convergence timed out: %w", errors.Join(last, waitCtx.Err()))
		case <-ticker.C:
		}
	}
}

func compensateWarmRouting(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) error {
	if r.Version != warmDrainReceiptVersion || r.DrainAttempts <= 0 || r.DrainAttempts > warmDrainMaxAttempts {
		return fmt.Errorf("warm routing restoration lacks definite-unsent provenance")
	}
	if r.Phase == "drain-unsent" {
		r.Phase = "restore-old-claimed"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return fmt.Errorf("old-route restoration claim was not acknowledged: %w", err)
		}
	}
	if r.Phase == "restore-old-claimed" {
		old, next, err := warmDrainCurrentPair(ctx, ec, *r)
		if err != nil {
			return err
		}
		if next.Labels[labelRole] != roleLeader || (old.Labels[labelRole] != roleRetiring && old.Labels[labelRole] != roleLeader) {
			return fmt.Errorf("recorded warm roles changed before old-route restoration")
		}
		if old.Labels[labelRole] == roleRetiring {
			before := old.DeepCopy()
			old.Labels[labelRole] = roleLeader
			if err := ec.Client.Patch(ctx, old, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
				return fmt.Errorf("restore exact old leader route: %w", err)
			}
		}
		if err := waitWarmRouteMembers(ctx, ec, *r, warmExpectedBridge(*r)); err != nil {
			return err
		}
		old, next, err = warmDrainCurrentPair(ctx, ec, *r)
		if err != nil {
			return fmt.Errorf("warm pair authority changed after old-route observation: %w", err)
		}
		if old.Labels[labelRole] != roleLeader || next.Labels[labelRole] != roleLeader {
			return fmt.Errorf("warm pair roles changed after old-route observation")
		}
		r.Phase = "old-route-observed"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return fmt.Errorf("old-route observation was not acknowledged: %w", err)
		}
	}
	if r.Phase == "old-route-observed" {
		r.Phase = "restore-shadow-claimed"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return fmt.Errorf("shadow restoration claim was not acknowledged: %w", err)
		}
	}
	if r.Phase == "restore-shadow-claimed" {
		old, next, err := warmDrainCurrentPair(ctx, ec, *r)
		if err != nil {
			return err
		}
		if old.Labels[labelRole] != roleLeader || (next.Labels[labelRole] != roleLeader && next.Labels[labelRole] != roleShadow) {
			return fmt.Errorf("recorded warm roles changed before shadow restoration")
		}
		if next.Labels[labelRole] == roleLeader {
			before := next.DeepCopy()
			next.Labels[labelRole] = roleShadow
			if err := ec.Client.Patch(ctx, next, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
				return fmt.Errorf("restore exact shadow route: %w", err)
			}
		}
		if err := waitWarmRouteMembers(ctx, ec, *r, r.WarmSelectedUIDs); err != nil {
			return err
		}
		old, next, err = warmDrainCurrentPair(ctx, ec, *r)
		if err != nil {
			return fmt.Errorf("warm pair authority changed after shadow-route observation: %w", err)
		}
		if old.Labels[labelRole] != roleLeader || next.Labels[labelRole] != roleShadow {
			return fmt.Errorf("warm pair roles changed after shadow-route observation")
		}
		r.Phase = "routing-restored"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return fmt.Errorf("routing restoration was not acknowledged: %w", err)
		}
	}
	if r.Phase != "routing-restored" {
		return fmt.Errorf("warm routing restoration phase %q is retained", r.Phase)
	}
	old, next, err := warmDrainCurrentPair(ctx, ec, *r)
	if err != nil {
		return fmt.Errorf("restored warm pair authority changed before receipt cleanup: %w", err)
	}
	if old.Labels[labelRole] != roleLeader || next.Labels[labelRole] != roleShadow {
		return fmt.Errorf("restored warm pair roles changed before receipt cleanup")
	}
	if err := waitWarmRouteMembers(ctx, ec, *r, r.WarmSelectedUIDs); err != nil {
		return err
	}
	if err := journalFinish(ctx, ec, cm); err != nil {
		return fmt.Errorf("restored warm operation receipt cleanup failed: %w", err)
	}
	return nil
}

func recoverWarmDrainCutover(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt) (string, error) {
	newPod := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NewName}, newPod); err != nil {
		return "", err
	}
	if string(newPod.UID) != r.NewUID || newPod.DeletionTimestamp != nil || newPod.Labels[r.GroupKey] != r.GroupValue {
		return "", fmt.Errorf("recorded promoted leader missing, changed or unhealthy")
	}
	old := &corev1.Pod{}
	oldErr := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.OldName}, old)
	if oldErr != nil && !apierrors.IsNotFound(oldErr) {
		return "", oldErr
	}
	if oldErr == nil && (string(old.UID) != r.OldUID || old.DeletionTimestamp != nil || old.Labels[r.GroupKey] != r.GroupValue) {
		return "", fmt.Errorf("recorded old leader identity or scope changed")
	}
	if oldErr == nil && (r.Phase == "prepared" || r.Phase == "promoted") && old.Labels[labelRole] == roleLeader && podReady(old) && newPod.Labels[labelRole] == roleShadow {
		pol, err := receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
		if err != nil {
			return "", err
		}
		if err := warmCurrentScope(pol, *r, old, newPod); err != nil {
			return "", err
		}
		if err := warmPoolRecheck(ctx, ec.Reader, *r, old, newPod); err != nil {
			return "", err
		}
		if err := warmDrainRolesCurrent(ctx, ec.Reader, *r); err != nil {
			return "", err
		}
		if err := journalFinish(ctx, ec, cm); err != nil {
			return "", err
		}
		return "unpromoted or rolled-back pair confirmed; receipt finished", nil
	}
	if oldErr != nil {
		if r.Phase != "drain-confirmed" && r.Phase != "retired-awaiting-controller" && r.Phase != "pool-observed" && r.Phase != "pool-warm-ready" {
			return "", fmt.Errorf("old leader absent without durable drain confirmation")
		}
		if r.Phase == "drain-confirmed" {
			r.Phase = "retired-awaiting-controller"
			if err := journalAdvance(ctx, ec, cm, *r); err != nil {
				return "old leader already absent after confirmed drain", err
			}
		}
		return recoverWarmControllerCompletion(ctx, ec, cm, r, "old leader already absent after confirmed drain")
	}
	if r.Phase == "prepared" || r.Phase == "promoted" {
		pol, err := receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
		if err != nil {
			return "", err
		}
		if err := warmCurrentScope(pol, *r, old, newPod); err != nil {
			return "", err
		}
		if err := warmPoolRecheck(ctx, ec.Reader, *r, old, newPod); err != nil {
			return "", err
		}
		if err := warmDrainRolesCurrent(ctx, ec.Reader, *r); err != nil {
			return "", err
		}
		if (old.Labels[labelRole] != roleLeader && old.Labels[labelRole] != roleRetiring) || newPod.Labels[labelRole] != roleLeader || !podReady(newPod) {
			return "", fmt.Errorf("recorded promoted warm roles changed")
		}
		if old.Labels[labelRole] == roleLeader {
			before := old.DeepCopy()
			old.Labels[labelRole] = roleRetiring
			if err := ec.Client.Patch(ctx, old, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
				return "", err
			}
		}
		old, newPod, err = warmDrainCurrentPair(ctx, ec, *r)
		if err != nil {
			return "old leader route removal pending", err
		}
		if old.Labels[labelRole] != roleRetiring || newPod.Labels[labelRole] != roleLeader {
			return "old leader route removal pending", fmt.Errorf("recorded warm roles changed after route removal")
		}
		r.Phase = "retiring"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return "old leader route removed", err
		}
	}
	switch r.Phase {
	case "retiring":
		result, err := executeWarmDrainAttempt(ctx, ec, cm, r)
		if err != nil {
			return "old leader route removed", err
		}
		if result == warmDrainRestored {
			return "definitely-unsent drain; exact old-first routing roles restored", nil
		}
	case "drain-dispatching":
		return "old leader route removed", fmt.Errorf("warm drain may have been sent; receipt retained without replay")
	case "drain-unsent":
		// A recovery that observed an unsent phase may make one final claimed
		// attempt. The bounded second unsent result compensates immediately.
		if r.DrainAttempts < warmDrainMaxAttempts {
			result, err := executeWarmDrainAttempt(ctx, ec, cm, r)
			if err != nil {
				return "old leader route removed", err
			}
			if result == warmDrainRestored {
				return "all admitted drains definitely unsent; exact old-first routing roles restored", nil
			}
		} else if err := compensateWarmRouting(ctx, ec, cm, r); err != nil {
			return "old leader route removed", err
		} else {
			return "all admitted drains definitely unsent; exact old-first routing roles restored", nil
		}
	case "restore-old-claimed", "old-route-observed", "restore-shadow-claimed", "routing-restored":
		if err := compensateWarmRouting(ctx, ec, cm, r); err != nil {
			return "definitely-unsent drain; routing restoration pending", err
		}
		return "definitely-unsent drain; exact old-first routing roles restored", nil
	}
	if r.Phase != "drain-confirmed" {
		return "old leader route removed", fmt.Errorf("warm drain completion is not durably confirmed")
	}
	old, newPod, err := warmDrainCurrentPair(ctx, ec, *r)
	if err != nil {
		return "confirmed warm drain; retirement pending", err
	}
	if old.Labels[labelRole] != roleRetiring || newPod.Labels[labelRole] != roleLeader {
		return "confirmed warm drain; retirement pending", fmt.Errorf("recorded pair changed before confirmed retirement")
	}
	if err := ec.Client.Delete(ctx, old, uidPrecondition(old)); err != nil && !apierrors.IsNotFound(err) {
		return "confirmed warm drain; retirement pending", err
	}
	r.Phase = "retired-awaiting-controller"
	if err := journalAdvance(ctx, ec, cm, *r); err != nil {
		return "confirmed warm drain; old leader retired", err
	}
	return recoverWarmControllerCompletion(ctx, ec, cm, r, fmt.Sprintf("confirmed warm drain (aborted=%d); old leader retired", r.Aborted))
}

func recoverWarmControllerCompletion(ctx context.Context, ec EnactCtx, cm *corev1.ConfigMap, r *operationReceipt, effect string) (string, error) {
	pol, err := receiptAuthority(ctx, ec.Reader, *r, model.Action(r.Kind))
	if err != nil {
		return effect, err
	}
	survivor := &corev1.Pod{}
	if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.NewName}, survivor); err != nil {
		return effect, err
	}
	if string(survivor.UID) != r.NewUID || survivor.Labels[labelRole] != roleLeader || !podReady(survivor) {
		return effect, fmt.Errorf("recorded serving survivor changed")
	}
	if err := warmSurvivorScope(pol, *r, survivor); err != nil {
		return effect, err
	}
	if err := warmPoolRecheck(ctx, ec.Reader, *r, nil, survivor); err != nil {
		return effect, err
	}
	var recorded *corev1.Pod
	if r.Phase == "pool-observed" || r.Phase == "pool-warm-ready" {
		recorded = &corev1.Pod{}
		if err := ec.Reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.RewarmName}, recorded); err != nil {
			return effect, err
		}
		if string(recorded.UID) != r.RewarmUID {
			return effect, fmt.Errorf("recorded controller member UID changed")
		}
	}
	observed, err := warmPoolObserve(ctx, ec.Reader, *r)
	if err != nil {
		return effect + "; controller pool observation pending", err
	}
	if recorded != nil && recorded.UID != observed.UID {
		return effect, fmt.Errorf("recorded controller member identity drift")
	}
	if r.Phase == "retired-awaiting-controller" {
		r.RewarmName, r.RewarmUID, r.Phase = observed.Name, string(observed.UID), "pool-observed"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return effect, err
		}
	}
	ready, fallback := shadowModelReady(ctx, ec, observed)
	if !ready {
		return effect + "; controller Pod observed; warm capacity pending", fmt.Errorf("controller Pod observed but warm capacity not ready")
	}
	if r.Phase != "pool-warm-ready" {
		r.Phase = "pool-warm-ready"
		if err := journalAdvance(ctx, ec, cm, *r); err != nil {
			return effect, err
		}
	}
	if err := journalFinish(ctx, ec, cm); err != nil {
		return effect, err
	}
	effect += "; controller pool replenished and warm capacity ready"
	if fallback {
		effect += " [PENDING-GPU-VALIDATION]: K8s/model-loaded fallback"
	}
	return effect, nil
}
