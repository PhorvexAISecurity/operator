package console

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const podBoundCPUExpiryMargin = 30 * time.Second

func podBoundCPUReplayTimes(startText, endText string, expiry time.Time) bool {
	start, e1 := time.Parse(time.RFC3339Nano, startText)
	end, e2 := time.Parse(time.RFC3339Nano, endText)
	return e1 == nil && e2 == nil && !start.IsZero() && !end.Before(start) && end.Before(expiry.Add(-podBoundCPUExpiryMargin))
}

func podBoundCPURequestTimeValid(r podBoundTokenRequest, now time.Time) bool {
	sourceExpiry, e1 := time.Parse(time.RFC3339Nano, r.SourceExpiry)
	peerExpiry, e2 := time.Parse(time.RFC3339Nano, r.PeerExpiry)
	requested, e3 := time.Parse(time.RFC3339Nano, r.RequestedAt)
	if e1 != nil || e2 != nil || e3 != nil || requested.IsZero() || requested.After(now.Add(2*time.Second)) || now.Sub(requested) > 30*time.Second {
		return false
	}
	if !sourceExpiry.After(now.Add(330*time.Second)) || !peerExpiry.After(now.Add(330*time.Second)) {
		return false
	}
	return podBoundCPUReplayTimes(r.SourceBeforeRequestAt, r.SourceBeforeAt, sourceExpiry) &&
		podBoundCPUReplayTimes(r.PeerBeforeRequestAt, r.PeerBeforeAt, peerExpiry)
}

func podBoundCPUResultTimesValid(r PodBoundTokenResult) bool {
	sourceExpiry, e1 := time.Parse(time.RFC3339Nano, r.Replay.SourceExpiry)
	peerExpiry, e2 := time.Parse(time.RFC3339Nano, r.Replay.PeerExpiry)
	if e1 != nil || e2 != nil || r.Admission.Namespace != podBoundTokenCPUNamespace || r.CaseID != podBoundTokenCPUCaseID {
		return false
	}
	return podBoundCPUReplayTimes(r.Replay.SourceBeforeRequestAt, r.Replay.SourceBeforeAt, sourceExpiry) &&
		podBoundCPUReplayTimes(r.Replay.PeerBeforeRequestAt, r.Replay.PeerBeforeAt, peerExpiry) &&
		podBoundCPUReplayTimes(r.Replay.SourceAfterRequestAt, r.Replay.SourceAfterAt, sourceExpiry) &&
		podBoundCPUReplayTimes(r.Replay.PeerAfterRequestAt, r.Replay.PeerAfterAt, peerExpiry)
}

// The CPU fixture is disjoint from the retained failed Voice effect footprint.
// This is no general unsafe-history override: only the existing exact Voice
// original can be admitted and its failed status is never modified.
func (rm *RunManager) podBoundTokenCPUPriorAdmissionLocked(destination runDestination) error {
	if rm == nil || rm.runs == nil || rm.loadErr != nil || destination.ScopeTenant != podBoundTokenCPUNamespace ||
		len(destination.Tenants) != 1 || destination.Tenants[0] != podBoundTokenCPUNamespace ||
		len(destination.Targets) != 2 || destination.Targets[0] != hostTargetID ||
		destination.ScopeTarget == "" || destination.ScopeTarget != destination.Targets[1] || !mongoSHA.MatchString(destination.SuiteSHA256) {
		return errors.New("CPU token destination or retained run history unavailable")
	}
	var prior *RunStatus
	for _, status := range rm.runs {
		if status == nil {
			return errors.New("CPU token prior history ambiguous")
		}
		if status.UnsafeToRetry {
			if prior != nil {
				return errors.New("CPU token has multiple unsafe predecessors")
			}
			prior = status
		}
	}
	if prior == nil {
		return nil
	}
	if prior.ID != podBoundPriorVoiceID || prior.ExecutionKind != "fixed-suite" ||
		prior.Config != string(cataloguev1.VoiceRecovery) || prior.State != "partial" ||
		prior.Outcome != string(cataloguev1.OutcomeTestFailed) || prior.CleanupStatus != "FAIL" ||
		prior.ScopeTenant != podBoundTokenNamespace || prior.ScopeTarget != defaultTargetID ||
		prior.Finished == "" || prior.Owner == "" || rm.procs[prior.ID] != nil || rm.stopping[prior.ID] ||
		strings.Contains(prior.Error, "reconciliation pending") || !cataloguev1.ExecutionLockAvailable(rm.cfg.runOutputPath(prior.ID)) {
		return errors.New("CPU token unsafe predecessor differs from exact retained Voice run")
	}
	return rm.validatePriorVoiceFiles(prior)
}

// Before the CPU event, independently recheck all selectors in its dedicated
// namespace against both planned and current labels. The producer made the
// same pre-CREATE check; a controller or another owner can change labels later.
func podBoundCPUSelectorDisjoint(ctx context.Context, kc kubernetes.Interface, r podBoundTokenRequest, allowSourceLifecycle bool) error {
	if kc == nil || r.Namespace != podBoundTokenCPUNamespace || r.CaseID != podBoundTokenCPUCaseID {
		return errors.New("CPU token selector scope differs")
	}
	base := labels.Set{podBoundOwnerLabel: r.Nonce, "r6th.io/owned": "true", "r6th.io/scenario": r.CaseID, "r6th.io/trial": "0"}
	sourcePlanned := labels.Set{}
	for k, v := range base {
		sourcePlanned[k] = v
	}
	sourcePlanned[podBoundRoleLabel] = "source"
	source, err := kc.CoreV1().Pods(r.Namespace).Get(ctx, r.SourcePodName, metav1.GetOptions{})
	if err != nil && (!allowSourceLifecycle || !apierrors.IsNotFound(err)) {
		return errors.New("CPU token source labels unavailable")
	}
	sourcePresent := err == nil
	peer, err := kc.CoreV1().Pods(r.Namespace).Get(ctx, r.PeerPodName, metav1.GetOptions{})
	if err != nil {
		return errors.New("CPU token peer labels unavailable")
	}
	actual := []labels.Set{base, sourcePlanned, labels.Set(peer.Labels)}
	if sourcePresent {
		actual = append(actual, labels.Set(source.Labels))
	}
	overlaps := func(selector labels.Selector) bool {
		for _, candidate := range actual {
			if selector.Matches(candidate) {
				return true
			}
		}
		return false
	}
	deps, err := kc.AppsV1().Deployments(r.Namespace).List(ctx, metav1.ListOptions{Limit: 200})
	if err != nil || deps.Continue != "" {
		return errors.New("CPU token Deployment inventory incomplete")
	}
	for _, obj := range deps.Items {
		if obj.Name == r.ServiceName && string(obj.UID) == r.DeploymentUID {
			continue
		}
		if obj.UID == "" || obj.Spec.Selector == nil {
			return errors.New("CPU token foreign Deployment selector ambiguous")
		}
		selector, e := metav1.LabelSelectorAsSelector(obj.Spec.Selector)
		if e != nil || selector.Empty() || overlaps(selector) {
			return errors.New("CPU token foreign Deployment selector overlap")
		}
	}
	services, err := kc.CoreV1().Services(r.Namespace).List(ctx, metav1.ListOptions{Limit: 200})
	if err != nil || services.Continue != "" {
		return errors.New("CPU token Service inventory incomplete")
	}
	for _, obj := range services.Items {
		if obj.Name == r.ServiceName && string(obj.UID) == r.ServiceUID {
			continue
		}
		if obj.UID == "" || len(obj.Spec.Selector) > 0 && overlaps(labels.SelectorFromSet(obj.Spec.Selector)) {
			return errors.New("CPU token foreign Service selector overlap")
		}
	}
	budgets, err := kc.PolicyV1().PodDisruptionBudgets(r.Namespace).List(ctx, metav1.ListOptions{Limit: 200})
	if err != nil || budgets.Continue != "" {
		return errors.New("CPU token PDB inventory incomplete")
	}
	for _, obj := range budgets.Items {
		if obj.Name == r.ServiceName && string(obj.UID) == r.PDBUID && r.PDBUID != "" {
			continue
		}
		if obj.UID == "" || obj.Spec.Selector == nil {
			return errors.New("CPU token foreign PDB selector ambiguous")
		}
		selector, e := metav1.LabelSelectorAsSelector(obj.Spec.Selector)
		if e != nil || selector.Empty() || overlaps(selector) {
			return errors.New("CPU token foreign PDB selector overlap")
		}
	}
	return nil
}

func (s *Server) podBoundCPUGraph(ctx context.Context, kc kubernetes.Interface, r podBoundTokenRequest, allowSourceLifecycle bool) error {
	if err := podBoundCPUSelectorDisjoint(ctx, kc, r, allowSourceLifecycle); err != nil {
		return err
	}
	ns, err := kc.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.NamespaceUID || ns.Labels["phorvex.ai/cpu-token-fixture"] != "true" || ns.DeletionTimestamp != nil {
		return errors.New("CPU token owned namespace authority differs")
	}
	dep, err := kc.AppsV1().Deployments(r.Namespace).Get(ctx, r.ServiceName, metav1.GetOptions{})
	if err != nil || string(dep.UID) != r.DeploymentUID || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 2 || dep.DeletionTimestamp != nil ||
		dep.Spec.Selector == nil || len(dep.Spec.Selector.MatchLabels) != 1 || dep.Spec.Selector.MatchLabels[podBoundOwnerLabel] != r.Nonce {
		return errors.New("CPU token owned Deployment changed")
	}
	pdb, err := kc.PolicyV1().PodDisruptionBudgets(r.Namespace).Get(ctx, r.ServiceName, metav1.GetOptions{})
	if err != nil || string(pdb.UID) != r.PDBUID || pdb.DeletionTimestamp != nil || pdb.Spec.Selector == nil ||
		len(pdb.Spec.Selector.MatchLabels) != 1 || pdb.Spec.Selector.MatchLabels[podBoundOwnerLabel] != r.Nonce ||
		pdb.Status.DisruptionsAllowed < 1 && !allowSourceLifecycle {
		return errors.New("CPU token PDB identity or disruption headroom changed")
	}
	base := labels.Set{podBoundOwnerLabel: r.Nonce, "r6th.io/owned": "true", "r6th.io/scenario": r.CaseID, "r6th.io/trial": "0"}
	sourceLabels := labels.Set{}
	for k, v := range base {
		sourceLabels[k] = v
	}
	sourceLabels[podBoundRoleLabel] = "source"
	peerLabels := labels.Set{}
	for k, v := range base {
		peerLabels[k] = v
	}
	peer, err := kc.CoreV1().Pods(r.Namespace).Get(ctx, r.PeerPodName, metav1.GetOptions{})
	if err != nil || string(peer.UID) != r.PeerPodUID || !podReady(peer) {
		return errors.New("CPU token peer incarnation unavailable")
	}
	for k, v := range base {
		if peer.Labels[k] != v {
			return errors.New("CPU token peer labels differ")
		}
	}
	if peer.Labels[podBoundRoleLabel] != "" {
		return errors.New("CPU token peer acquired source role")
	}
	if !allowSourceLifecycle {
		source, e := kc.CoreV1().Pods(r.Namespace).Get(ctx, r.SourcePodName, metav1.GetOptions{})
		if e != nil || string(source.UID) != r.SourcePodUID || !podReady(source) {
			return errors.New("CPU token source incarnation unavailable")
		}
		for k, v := range sourceLabels {
			if source.Labels[k] != v {
				return errors.New("CPU token source labels differ")
			}
		}
		sourceLabels = labels.Set(source.Labels)
	}
	members, err := podBoundSelectedSliceUIDs(ctx, kc, r.Namespace, r.ServiceName, types.UID(r.ServiceUID))
	if err != nil || !members[types.UID(r.PeerPodUID)] || !allowSourceLifecycle && !members[types.UID(r.SourcePodUID)] {
		return errors.New("CPU token Ready Service membership differs")
	}
	pods, err := kc.CoreV1().Pods(r.Namespace).List(ctx, metav1.ListOptions{LabelSelector: podBoundOwnerLabel + "=" + r.Nonce, Limit: 10})
	if err != nil || pods.Continue != "" || len(pods.Items) < 1 || len(pods.Items) > 4 {
		return errors.New("CPU token Pod member inventory incomplete")
	}
	otherLabels := []labels.Set{base, peerLabels, labels.Set(peer.Labels)}
	for uid := range members {
		found := false
		for _, pod := range pods.Items {
			if pod.UID != uid {
				continue
			}
			if !podReady(&pod) || pod.Labels[podBoundOwnerLabel] != r.Nonce || pod.Labels["r6th.io/scenario"] != r.CaseID ||
				!podBoundController(pod.OwnerReferences, "ReplicaSet", types.UID(r.ReplicaSetUID)) {
				return errors.New("CPU token routed member not owned Ready Pod")
			}
			if uid != types.UID(r.SourcePodUID) {
				otherLabels = append(otherLabels, labels.Set(pod.Labels))
			}
			found = true
		}
		if !found {
			return errors.New("CPU token routed member absent from owned Pod inventory")
		}
	}
	if err := s.podBoundPolicyDisjoint(r, sourceLabels, otherLabels); err != nil {
		return err
	}
	return nil
}
