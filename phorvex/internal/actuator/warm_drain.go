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
	"k8s.io/apimachinery/pkg/labels"
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

type warmServingSet string

const (
	warmOriginalServingSet    warmServingSet = "original"
	warmProspectiveServingSet warmServingSet = "prospective"
)

func warmDrainRoleAllowed(r operationReceipt, uid, role string, selected map[string]bool) bool {
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
		return allowed
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
		return allowed
	}
	want := roleShadow
	if selected[uid] {
		want = roleLeader
	}
	return role == want
}

// warmDrainPoolSnapshot returns one complete authoritative view of the exact
// pool recorded by the receipt. Readiness checks consume this same view so a
// Ready Pod outside the recorded serving set cannot satisfy its floor.
func warmDrainPoolSnapshot(ctx context.Context, reader client.Reader, r operationReceipt) ([]corev1.Pod, error) {
	if reader == nil || r.Pool == nil {
		return nil, fmt.Errorf("warm availability inventory unavailable")
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.Pool.RSName}, rs); err != nil {
		return nil, err
	}
	if string(rs.UID) != r.Pool.RSUID || rs.DeletionTimestamp != nil || rs.Generation != r.Pool.RSGeneration || rs.Status.ObservedGeneration != rs.Generation || rs.Spec.Replicas == nil || *rs.Spec.Replicas != r.Pool.Desired || hashWarmObject(rs.Spec.Template) != r.Pool.RSTemplateHash || hashWarmObject(rs.Spec.Selector) != r.Pool.RSSelectorHash {
		return nil, fmt.Errorf("warm availability ReplicaSet intent drift")
	}
	sel, err := warmPoolSelector(rs, r.GroupKey, r.GroupValue)
	if err != nil {
		return nil, err
	}
	pods, err := warmPoolListMembers(ctx, reader, r.PolicyNamespace, sel)
	if err != nil {
		return nil, err
	}
	if len(pods.Items) != len(r.Pool.Members) {
		return nil, fmt.Errorf("warm availability pool membership count drift")
	}
	expected := make(map[string]bool, len(r.Pool.Members))
	for _, uid := range r.Pool.Members {
		if uid == "" || expected[uid] {
			return nil, fmt.Errorf("warm availability receipt member set invalid")
		}
		expected[uid] = true
	}
	selected := make(map[string]bool, len(r.WarmSelectedUIDs))
	for _, uid := range r.WarmSelectedUIDs {
		selected[uid] = true
	}
	seen := make(map[string]bool, len(pods.Items))
	for i := range pods.Items {
		pod := &pods.Items[i]
		uid := string(pod.UID)
		owner, ownerErr := controllingRS(pod)
		if pod.Namespace != r.PolicyNamespace || pod.Name == "" || uid == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil || !sel.Matches(labels.Set(pod.Labels)) || pod.Labels[r.GroupKey] != r.GroupValue || ownerErr != nil || string(owner.UID) != r.Pool.RSUID || owner.Name != r.Pool.RSName || !expected[uid] || seen[uid] {
			return nil, fmt.Errorf("warm availability pool member identity drift")
		}
		seen[uid] = true
		if !warmDrainRoleAllowed(r, uid, pod.Labels[labelRole], selected) {
			return nil, fmt.Errorf("recorded warm member role changed")
		}
	}
	if len(seen) != len(expected) {
		return nil, fmt.Errorf("warm availability pool member set incomplete")
	}
	return pods.Items, nil
}

func warmDrainRolesCurrent(ctx context.Context, reader client.Reader, r operationReceipt) error {
	_, err := warmDrainPoolSnapshot(ctx, reader, r)
	return err
}

// warmDrainAvailabilityCurrent requires every named serving set to retain the
// stricter of its admitted floor and the current policy floor. It deliberately
// counts only recorded serving UIDs; unrelated Ready shadows receive no credit.
func warmDrainAvailabilityCurrent(ctx context.Context, reader client.Reader, r operationReceipt, sets ...warmServingSet) error {
	if r.Version != warmDrainReceiptVersion || r.Pool == nil || r.AdmittedFloor <= 0 || r.AdmittedFloor > len(r.WarmSelectedUIDs) || r.AdmittedFloor > int(r.Pool.Desired) {
		return fmt.Errorf("warm availability receipt floor invalid")
	}
	pol, err := receiptAuthority(ctx, reader, r, model.Action(r.Kind))
	if err != nil {
		return err
	}
	floor := r.AdmittedFloor
	if current := pol.Spec.EffectiveMinAvailableReplicas(); current > floor {
		floor = current
	}
	pods, err := warmDrainPoolSnapshot(ctx, reader, r)
	if err != nil {
		return err
	}
	byUID := make(map[string]*corev1.Pod, len(pods))
	for i := range pods {
		byUID[string(pods[i].UID)] = &pods[i]
	}
	for _, set := range sets {
		members := make(map[string]bool, len(r.WarmSelectedUIDs)+1)
		for _, uid := range r.WarmSelectedUIDs {
			members[uid] = true
		}
		switch set {
		case warmOriginalServingSet:
		case warmProspectiveServingSet:
			delete(members, r.OldUID)
			members[r.NewUID] = true
		default:
			return fmt.Errorf("unknown warm serving set %q", set)
		}
		ready := 0
		for uid := range members {
			pod := byUID[uid]
			if pod != nil && pod.DeletionTimestamp == nil && podReady(pod) {
				ready++
			}
		}
		if ready < floor {
			return fmt.Errorf("%s Ready serving set %d below availability floor %d", set, ready, floor)
		}
	}
	return nil
}

// warmDrainRetiredAvailabilityCurrent validates the controller-replenished
// pool before a completed cutover receipt is removed. The replacement shadow
// restores pool size, but only the recorded prospective serving UIDs count
// toward availability.
func warmDrainRetiredAvailabilityCurrent(ctx context.Context, reader client.Reader, r operationReceipt) error {
	if r.Version != warmDrainReceiptVersion || r.Pool == nil || r.RewarmUID == "" || r.AdmittedFloor <= 0 || r.AdmittedFloor > len(r.WarmSelectedUIDs) {
		return fmt.Errorf("retired warm availability receipt invalid")
	}
	pol, err := receiptAuthority(ctx, reader, r, model.Action(r.Kind))
	if err != nil {
		return err
	}
	floor := r.AdmittedFloor
	if current := pol.Spec.EffectiveMinAvailableReplicas(); current > floor {
		floor = current
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: r.PolicyNamespace, Name: r.Pool.RSName}, rs); err != nil {
		return err
	}
	if string(rs.UID) != r.Pool.RSUID || rs.DeletionTimestamp != nil || rs.Generation != r.Pool.RSGeneration || rs.Status.ObservedGeneration != rs.Generation || rs.Spec.Replicas == nil || *rs.Spec.Replicas != r.Pool.Desired || hashWarmObject(rs.Spec.Template) != r.Pool.RSTemplateHash || hashWarmObject(rs.Spec.Selector) != r.Pool.RSSelectorHash {
		return fmt.Errorf("retired warm availability ReplicaSet intent drift")
	}
	sel, err := warmPoolSelector(rs, r.GroupKey, r.GroupValue)
	if err != nil {
		return err
	}
	pods, err := warmPoolListMembers(ctx, reader, r.PolicyNamespace, sel)
	if err != nil {
		return err
	}
	expected := make(map[string]bool, len(r.Pool.Members))
	for _, uid := range r.Pool.Members {
		if uid != r.OldUID {
			expected[uid] = true
		}
	}
	expected[r.RewarmUID] = true
	if len(pods.Items) != len(expected) || len(expected) != int(r.Pool.Desired) {
		return fmt.Errorf("retired warm availability pool membership count drift")
	}
	prospective := make(map[string]bool, len(r.WarmSelectedUIDs))
	for _, uid := range r.WarmSelectedUIDs {
		if uid != r.OldUID {
			prospective[uid] = true
		}
	}
	prospective[r.NewUID] = true
	seen, ready := make(map[string]bool, len(pods.Items)), 0
	for i := range pods.Items {
		pod := &pods.Items[i]
		uid := string(pod.UID)
		owner, ownerErr := controllingRS(pod)
		if pod.Namespace != r.PolicyNamespace || pod.Name == "" || uid == "" || pod.ResourceVersion == "" || pod.DeletionTimestamp != nil || !sel.Matches(labels.Set(pod.Labels)) || pod.Labels[r.GroupKey] != r.GroupValue || ownerErr != nil || string(owner.UID) != r.Pool.RSUID || owner.Name != r.Pool.RSName || !expected[uid] || seen[uid] {
			return fmt.Errorf("retired warm availability pool member identity drift")
		}
		seen[uid] = true
		wantRole := roleShadow
		if prospective[uid] {
			wantRole = roleLeader
		}
		if pod.Labels[labelRole] != wantRole {
			return fmt.Errorf("retired warm availability role drift")
		}
		if prospective[uid] && podReady(pod) {
			ready++
		}
	}
	if len(seen) != len(expected) || ready < floor {
		return fmt.Errorf("retired prospective Ready serving set %d below availability floor %d", ready, floor)
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
	old, next, err = warmDrainCurrentPair(ctx, ec, *r)
	if err != nil {
		return warmDrainRetained, fmt.Errorf("warm drain authority changed after dispatch claim: %w", err)
	}
	if old.Labels[labelRole] != roleRetiring || next.Labels[labelRole] != roleLeader {
		return warmDrainRetained, fmt.Errorf("recorded pair changed after warm drain dispatch claim")
	}
	if err := warmDrainAvailabilityCurrent(ctx, ec.Reader, *r, warmProspectiveServingSet); err != nil {
		return warmDrainRetained, fmt.Errorf("warm availability changed after dispatch claim: %w", err)
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
		if err := warmDrainAvailabilityCurrent(ctx, ec.Reader, *r, warmOriginalServingSet); err != nil {
			return fmt.Errorf("original availability insufficient before shadow restoration: %w", err)
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
	if err := warmDrainAvailabilityCurrent(ctx, ec.Reader, *r, warmOriginalServingSet); err != nil {
		return fmt.Errorf("restored availability insufficient before receipt cleanup: %w", err)
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
		if err := warmDrainAvailabilityCurrent(ctx, ec.Reader, *r, warmOriginalServingSet); err != nil {
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
			if err := warmDrainAvailabilityCurrent(ctx, ec.Reader, *r, warmProspectiveServingSet); err != nil {
				return "", fmt.Errorf("availability changed before recovered old route removal: %w", err)
			}
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
		if err := warmDrainAvailabilityCurrent(ctx, ec.Reader, *r, warmProspectiveServingSet); err != nil {
			return "old leader route removal pending", fmt.Errorf("availability changed at recovered route removal: %w", err)
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
	if err := warmDrainAvailabilityCurrent(ctx, ec.Reader, *r, warmProspectiveServingSet); err != nil {
		return "confirmed warm drain; retirement pending", fmt.Errorf("availability changed before confirmed retirement: %w", err)
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
	if err := warmDrainRetiredAvailabilityCurrent(ctx, ec.Reader, *r); err != nil {
		return effect + "; controller pool observed; serving availability pending", err
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
