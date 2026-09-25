package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"strings"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/cataloguev1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const podBoundPriorVoiceID = "v1run-5"
const podBoundOwnerLabel = "fixture.phorvex.ai/token-response"
const podBoundRoleLabel = "fixture.phorvex.ai/role"

type podBoundPriorVoiceProof struct {
	Present                                         bool
	NamespaceUID, DeploymentUID, ServiceUID, PDBUID string
	TargetPodUID, ReplacementPodUID                 string
}

// Caller holds rm.mu. This grants no general Voice restart or reconciliation:
// only the captured, terminal v1run-5 producer may coexist with this one
// server-owned Pod-token suite. The unsafe predecessor remains unsafe.
func (rm *RunManager) podBoundTokenPriorAdmissionLocked(destination runDestination) error {
	_, err := rm.podBoundTokenPriorProofLocked(destination)
	return err
}

func (rm *RunManager) podBoundTokenPriorProofLocked(destination runDestination) (podBoundPriorVoiceProof, error) {
	var proof podBoundPriorVoiceProof
	if rm == nil || rm.runs == nil || rm.loadErr != nil || destination.ScopeTenant != podBoundTokenNamespace ||
		len(destination.Tenants) != 1 || destination.Tenants[0] != podBoundTokenNamespace ||
		len(destination.Targets) != 2 || destination.Targets[0] != hostTargetID ||
		destination.Targets[1] == "" || destination.ScopeTarget != destination.Targets[1] ||
		!mongoSHA.MatchString(destination.SuiteSHA256) {
		return proof, errors.New("Pod-bound token destination or retained run history unavailable")
	}
	var prior *RunStatus
	for _, status := range rm.runs {
		if status == nil {
			return proof, errors.New("prior run history is ambiguous")
		}
		if status.UnsafeToRetry {
			if prior != nil {
				return proof, errors.New("more than one unsafe predecessor requires reconciliation")
			}
			prior = status
		}
	}
	if prior == nil {
		return proof, nil
	}
	if prior.ID != podBoundPriorVoiceID || prior.ExecutionKind != "fixed-suite" ||
		prior.Config != string(cataloguev1.VoiceRecovery) || prior.State != "partial" ||
		prior.Outcome != string(cataloguev1.OutcomeTestFailed) || prior.CleanupStatus != "FAIL" ||
		!prior.UnsafeToRetry || prior.Finished == "" || prior.Owner == "" ||
		prior.ScopeTarget != defaultTargetID || prior.ScopeTenant != podBoundTokenNamespace ||
		rm.cfg.CatalogueV1.VoiceNamespace != podBoundTokenNamespace ||
		rm.procs[prior.ID] != nil || rm.stopping[prior.ID] ||
		strings.Contains(prior.Error, "reconciliation pending") ||
		!cataloguev1.ExecutionLockAvailable(rm.cfg.runOutputPath(prior.ID)) {
		return proof, errors.New("unsafe Voice predecessor is active or differs from reviewed v1run-5")
	}
	dir := rm.cfg.runOutputPath(prior.ID)
	if filepath.Base(dir) != prior.ID {
		return proof, errors.New("Voice run path differs")
	}
	return podBoundTokenPriorProofAt(prior, dir, dir, rm.cfg.StateDir)
}

// Production passes one private directory for both paths. The split permits
// the actual captured originals to prove this exact extraction offline while
// their job retains its on-cluster outputDir identity.
func podBoundTokenPriorProofAt(prior *RunStatus, storageDir, expectedDir, stateDir string) (podBoundPriorVoiceProof, error) {
	var proof podBoundPriorVoiceProof
	if err := validatePriorVoiceFilesAt(prior, storageDir, expectedDir, stateDir); err != nil {
		return proof, fmt.Errorf("reviewed Voice originals differ: %w", err)
	}
	resultRaw, err := cataloguev1.ReadPrivateArtifact(filepath.Join(storageDir, "result.json"), 64<<10)
	if err != nil {
		return proof, err
	}
	journalRaw, err := cataloguev1.ReadPrivateArtifact(filepath.Join(storageDir, "journal.jsonl"), 256*(64<<10))
	if err != nil {
		return proof, err
	}
	var result cataloguev1.Result
	if json.Unmarshal(resultRaw, &result) != nil {
		return proof, errors.New("Voice result identity unavailable")
	}
	proof.TargetPodUID = result.Evidence["targetPodUID"]
	proof.ReplacementPodUID = result.Evidence["replacementPodUID"]
	for _, line := range bytes.Split(bytes.TrimSuffix(journalRaw, []byte{'\n'}), []byte{'\n'}) {
		var record cataloguev1.JournalRecord
		if json.Unmarshal(line, &record) != nil {
			return podBoundPriorVoiceProof{}, errors.New("Voice authority journal unavailable")
		}
		if record.Event != nil && record.Event.Step == "voice.authority" {
			proof.NamespaceUID = record.Event.Identity["namespaceUID"]
			proof.DeploymentUID = record.Event.Identity["deploymentUID"]
			proof.ServiceUID = record.Event.Identity["serviceUID"]
			proof.PDBUID = record.Event.Identity["pdbUID"]
		}
	}
	if !voiceUID.MatchString(proof.NamespaceUID) || !voiceUID.MatchString(proof.DeploymentUID) ||
		!voiceUID.MatchString(proof.ServiceUID) || !voiceUID.MatchString(proof.PDBUID) ||
		!voiceUID.MatchString(proof.TargetPodUID) || !voiceUID.MatchString(proof.ReplacementPodUID) ||
		proof.TargetPodUID == proof.ReplacementPodUID {
		return podBoundPriorVoiceProof{}, errors.New("Voice authority or exact eviction UIDs differ")
	}
	// The extra read must not silently replace the originals accepted above.
	if err := validatePriorVoiceFilesAt(prior, storageDir, expectedDir, stateDir); err != nil {
		return podBoundPriorVoiceProof{}, err
	}
	proof.Present = true
	return proof, nil
}

func podBoundController(refs []metav1.OwnerReference, kind string, uid types.UID) bool {
	if len(refs) != 1 || refs[0].Kind != kind || refs[0].UID != uid || refs[0].Controller == nil || !*refs[0].Controller {
		return false
	}
	if kind == "Service" {
		return refs[0].APIVersion == "v1"
	}
	if kind == "Deployment" || kind == "ReplicaSet" {
		return refs[0].APIVersion == "apps/v1"
	}
	return false
}

func podBoundSelectedSliceUIDs(ctx context.Context, kc kubernetes.Interface, namespace, service string, serviceUID types.UID) (map[types.UID]bool, error) {
	slices, err := kc.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + service, Limit: 20})
	if err != nil || slices.Continue != "" || len(slices.Items) == 0 || len(slices.Items) > 20 {
		return nil, errors.New("Service EndpointSlice inventory is incomplete")
	}
	out := map[types.UID]bool{}
	for _, slice := range slices.Items {
		if slice.Labels[discoveryv1.LabelServiceName] != service || !podBoundController(slice.OwnerReferences, "Service", serviceUID) {
			return nil, errors.New("Service EndpointSlice label differs")
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Namespace != namespace || endpoint.TargetRef.UID == "" {
				return nil, errors.New("Service member UID is ambiguous")
			}
			out[endpoint.TargetRef.UID] = out[endpoint.TargetRef.UID] || endpoint.Conditions.Ready != nil && *endpoint.Conditions.Ready
		}
	}
	return out, nil
}

// The fixed fixture and old Voice producer share a namespace, so prove their
// actual Kubernetes selector, UID, owner and policy graphs are disjoint at the
// effect boundary. RunManager state is read under its lock; API reads are not.
func (s *Server) podBoundTokenDisjointLive(ctx context.Context, kc kubernetes.Interface, r podBoundTokenRequest, p podBoundTokenProfile) error {
	return s.podBoundTokenDisjointLiveMode(ctx, kc, r, p, false)
}

// Only an exact selected rotate request may end with the original source Pod
// absent. The coordinator's current-source check is repeated here so manager,
// policy and peer authority remain required at observation end.
func (s *Server) podBoundTokenDisjointAfterReceipt(ctx context.Context, kc kubernetes.Interface, r podBoundTokenRequest, p podBoundTokenProfile, barrier podBoundTokenBarrier) error {
	if barrier.RunID != r.RunID || barrier.Nonce != r.Nonce || barrier.Event.SourcePodUID != r.SourcePodUID {
		return errors.New("observation-end barrier identity differs")
	}
	if barrier.Decision.SelectedAction != "rotate" || barrier.Operation.TerminationStatus != "REQUEST_CONFIRMED" {
		return s.podBoundTokenDisjointLive(ctx, kc, r, p)
	}
	if !mongoSHA.MatchString(barrier.Operation.ReceiptSHA256) {
		return errors.New("exact rotate receipt hash unavailable")
	}
	if err := s.podBoundTokenCurrentSource(ctx, kc, r, p, true); err != nil {
		return err
	}
	return s.podBoundTokenDisjointLiveMode(ctx, kc, r, p, true)
}

func (s *Server) podBoundTokenDisjointLiveMode(ctx context.Context, kc kubernetes.Interface, r podBoundTokenRequest, p podBoundTokenProfile, allowSourceLifecycle bool) error {
	if s == nil || s.runs == nil || kc == nil || r.Namespace != p.Namespace ||
		r.RunID == "" || !podBoundTokenNonce.MatchString(r.Nonce) ||
		p.Fixture.RunID != r.RunID || p.Fixture.Nonce != r.Nonce ||
		p.Context == "" || p.Namespace != r.Namespace ||
		r.SourcePodUID == "" || r.PeerPodUID == "" || r.SourcePodUID == r.PeerPodUID ||
		r.DeploymentUID == "" || r.ReplicaSetUID == "" || r.ServiceUID == "" || r.PolicyUID == "" ||
		r.SourcePodName == "" || r.PeerPodName == "" || r.PolicyName == "" {
		return errors.New("Pod-bound token exact fixture identity unavailable")
	}
	dest := runDestination{Targets: []string{hostTargetID, p.Context}, Tenants: []string{r.Namespace}, ScopeTarget: p.Context, ScopeTenant: r.Namespace, SuiteSHA256: r.ProfileSHA256}
	if r.Namespace == podBoundTokenCPUNamespace {
		if r.CaseID != podBoundTokenCPUCaseID || r.PDBUID == "" {
			return errors.New("CPU token case or PDB UID absent")
		}
		s.runs.mu.Lock()
		err := s.runs.podBoundTokenCPUPriorAdmissionLocked(dest)
		s.runs.mu.Unlock()
		if err != nil {
			return err
		}
		return s.podBoundCPUGraph(ctx, kc, r, p.Context, allowSourceLifecycle)
	}
	if r.Namespace != podBoundTokenNamespace || r.CaseID != "" && r.CaseID != podBoundTokenVoiceCaseID {
		return errors.New("Voice token case identity differs")
	}
	s.runs.mu.Lock()
	proof, err := s.runs.podBoundTokenPriorProofLocked(dest)
	s.runs.mu.Unlock()
	if err != nil {
		return err
	}
	if !proof.Present {
		return nil
	}
	name := "pod-token-" + r.Nonce
	if r.ServiceName != name || r.PolicyName != name || r.SourcePodName == r.PeerPodName ||
		strings.HasPrefix(r.SourcePodName, "voice-bot-") || strings.HasPrefix(r.PeerPodName, "voice-bot-") {
		return errors.New("Pod-bound token names overlap Voice authority")
	}
	ns, err := kc.CoreV1().Namespaces().Get(ctx, r.Namespace, metav1.GetOptions{})
	if err != nil || string(ns.UID) != r.NamespaceUID || string(ns.UID) != proof.NamespaceUID || ns.DeletionTimestamp != nil {
		return errors.New("Voice namespace UID differs from retained authority")
	}
	oldDep, err := kc.AppsV1().Deployments(r.Namespace).Get(ctx, "voice-bot", metav1.GetOptions{})
	if err != nil || string(oldDep.UID) != proof.DeploymentUID || oldDep.DeletionTimestamp != nil || oldDep.Spec.Selector == nil {
		return errors.New("Voice Deployment authority differs")
	}
	oldSvc, err := kc.CoreV1().Services(r.Namespace).Get(ctx, "voice-bot", metav1.GetOptions{})
	if err != nil || string(oldSvc.UID) != proof.ServiceUID || oldSvc.DeletionTimestamp != nil || len(oldSvc.Spec.Selector) == 0 {
		return errors.New("Voice Service authority differs")
	}
	oldPDB, err := kc.PolicyV1().PodDisruptionBudgets(r.Namespace).Get(ctx, "voice-bot", metav1.GetOptions{})
	if err != nil || string(oldPDB.UID) != proof.PDBUID || oldPDB.DeletionTimestamp != nil || oldPDB.Spec.Selector == nil {
		return errors.New("Voice PDB authority differs")
	}
	oldSelector, err := metav1.LabelSelectorAsSelector(oldDep.Spec.Selector)
	if err != nil || oldSelector.Empty() || !reflect.DeepEqual(oldSvc.Spec.Selector, oldDep.Spec.Selector.MatchLabels) {
		return errors.New("Voice workload selector differs")
	}
	pdbSelector, err := metav1.LabelSelectorAsSelector(oldPDB.Spec.Selector)
	if err != nil || pdbSelector.Empty() || pdbSelector.String() != oldSelector.String() {
		return errors.New("Voice PDB selector differs")
	}
	fixtureLabels := map[string]string{podBoundOwnerLabel: r.Nonce, "r6th.io/owned": "true", "r6th.io/scenario": "c2-pod-bound-api-auth-response", "r6th.io/trial": "0"}
	for _, role := range []string{"", "source"} {
		set := labels.Set(maps.Clone(fixtureLabels))
		if role != "" {
			set[podBoundRoleLabel] = role
		}
		if oldSelector.Matches(set) || pdbSelector.Matches(set) || labels.SelectorFromSet(oldSvc.Spec.Selector).Matches(set) || set["app"] == "voice-bot" {
			return errors.New("proposed Pod-token labels overlap Voice selector")
		}
	}
	dep, err := kc.AppsV1().Deployments(r.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || string(dep.UID) != r.DeploymentUID || dep.DeletionTimestamp != nil || dep.Spec.Selector == nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 2 ||
		!reflect.DeepEqual(dep.Spec.Selector.MatchLabels, map[string]string{podBoundOwnerLabel: r.Nonce}) || len(dep.Spec.Selector.MatchExpressions) != 0 || !reflect.DeepEqual(dep.Spec.Template.Labels, fixtureLabels) {
		return errors.New("Pod-token Deployment selector or UID differs")
	}
	rsList, err := kc.AppsV1().ReplicaSets(r.Namespace).List(ctx, metav1.ListOptions{LabelSelector: podBoundOwnerLabel + "=" + r.Nonce, Limit: 10})
	if err != nil || rsList.Continue != "" || len(rsList.Items) != 1 || string(rsList.Items[0].UID) != r.ReplicaSetUID || !podBoundController(rsList.Items[0].OwnerReferences, "Deployment", dep.UID) {
		return errors.New("Pod-token ReplicaSet authority differs")
	}
	newSvc, err := kc.CoreV1().Services(r.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || string(newSvc.UID) != r.ServiceUID || newSvc.DeletionTimestamp != nil || !reflect.DeepEqual(newSvc.Spec.Selector, map[string]string{podBoundOwnerLabel: r.Nonce}) {
		return errors.New("Pod-token Service selector or UID differs")
	}
	newPDB, err := kc.PolicyV1().PodDisruptionBudgets(r.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil || newPDB.UID == "" || newPDB.DeletionTimestamp != nil || newPDB.Spec.Selector == nil || !reflect.DeepEqual(newPDB.Spec.Selector.MatchLabels, map[string]string{podBoundOwnerLabel: r.Nonce}) || len(newPDB.Spec.Selector.MatchExpressions) != 0 {
		return errors.New("Pod-token PDB selector differs")
	}
	newPods := map[types.UID]bool{}
	var actualSourceLabels, actualPeerLabels labels.Set
	for _, identity := range []struct{ name, uid, role string }{{r.SourcePodName, r.SourcePodUID, "source"}, {r.PeerPodName, r.PeerPodUID, ""}} {
		pod, e := kc.CoreV1().Pods(r.Namespace).Get(ctx, identity.name, metav1.GetOptions{})
		if allowSourceLifecycle && identity.role == "source" && apierrors.IsNotFound(e) {
			continue
		}
		if e != nil || string(pod.UID) != identity.uid || (pod.DeletionTimestamp != nil && (!allowSourceLifecycle || identity.role != "source")) || !podBoundController(pod.OwnerReferences, "ReplicaSet", rsList.Items[0].UID) ||
			pod.Labels[podBoundOwnerLabel] != r.Nonce || pod.Labels["r6th.io/owned"] != "true" || pod.Labels["r6th.io/scenario"] != "c2-pod-bound-api-auth-response" || pod.Labels["r6th.io/trial"] != "0" || pod.Labels[podBoundRoleLabel] != identity.role ||
			oldSelector.Matches(labels.Set(pod.Labels)) || pdbSelector.Matches(labels.Set(pod.Labels)) || labels.SelectorFromSet(oldSvc.Spec.Selector).Matches(labels.Set(pod.Labels)) ||
			identity.uid == proof.TargetPodUID || identity.uid == proof.ReplacementPodUID {
			return errors.New("Pod-token Pod identity overlaps Voice authority")
		}
		newPods[pod.UID] = true
		if identity.role == "source" {
			actualSourceLabels = labels.Set(maps.Clone(pod.Labels))
		} else {
			actualPeerLabels = labels.Set(maps.Clone(pod.Labels))
		}
	}
	newPods = map[types.UID]bool{}
	currentPods, err := kc.CoreV1().Pods(r.Namespace).List(ctx, metav1.ListOptions{LabelSelector: podBoundOwnerLabel + "=" + r.Nonce, Limit: 10})
	if err != nil || currentPods.Continue != "" || len(currentPods.Items) < 1 || len(currentPods.Items) > 4 || (!allowSourceLifecycle && len(currentPods.Items) != 2) {
		return errors.New("Pod-token Pod inventory incomplete")
	}
	policyOthers := []labels.Set{}
	seenCurrent := map[types.UID]bool{}
	for _, pod := range currentPods.Items {
		if pod.UID == "" || seenCurrent[pod.UID] || !podBoundController(pod.OwnerReferences, "ReplicaSet", rsList.Items[0].UID) ||
			pod.Labels[podBoundOwnerLabel] != r.Nonce || pod.Labels["r6th.io/owned"] != "true" || pod.Labels["r6th.io/scenario"] != "c2-pod-bound-api-auth-response" || pod.Labels["r6th.io/trial"] != "0" ||
			oldSelector.Matches(labels.Set(pod.Labels)) || pdbSelector.Matches(labels.Set(pod.Labels)) || labels.SelectorFromSet(oldSvc.Spec.Selector).Matches(labels.Set(pod.Labels)) ||
			string(pod.UID) == proof.TargetPodUID || string(pod.UID) == proof.ReplacementPodUID {
			return errors.New("Pod-token current Pod overlaps Voice authority")
		}
		if pod.UID != types.UID(r.SourcePodUID) && pod.Labels[podBoundRoleLabel] != "" {
			return errors.New("replacement or peer Pod has source policy role")
		}
		seenCurrent[pod.UID] = true
		newPods[pod.UID] = true
		if pod.UID != types.UID(r.SourcePodUID) {
			policyOthers = append(policyOthers, labels.Set(maps.Clone(pod.Labels)))
		}
	}
	if !seenCurrent[types.UID(r.PeerPodUID)] || (!allowSourceLifecycle && !seenCurrent[types.UID(r.SourcePodUID)]) {
		return errors.New("original Pod-token member missing from owned graph")
	}
	if actualSourceLabels == nil {
		actualSourceLabels = labels.Set(maps.Clone(fixtureLabels))
		actualSourceLabels[podBoundRoleLabel] = "source"
	}
	oldPods, err := kc.CoreV1().Pods(r.Namespace).List(ctx, metav1.ListOptions{LabelSelector: oldSelector.String(), Limit: 8})
	if err != nil || oldPods.Continue != "" || len(oldPods.Items) == 0 || len(oldPods.Items) > 8 {
		return errors.New("Voice Pod inventory incomplete")
	}
	oldUIDs := map[types.UID]bool{}
	for _, pod := range oldPods.Items {
		if pod.UID == "" || newPods[pod.UID] || !oldSelector.Matches(labels.Set(pod.Labels)) || len(pod.OwnerReferences) != 1 {
			return errors.New("Voice Pod selector or UID overlaps fixture")
		}
		ref := metav1.GetControllerOf(&pod)
		if ref == nil || ref.Kind != "ReplicaSet" || ref.UID == "" {
			return errors.New("Voice Pod owner differs")
		}
		rs, e := kc.AppsV1().ReplicaSets(r.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if e != nil || rs.UID != ref.UID || !podBoundController(rs.OwnerReferences, "Deployment", oldDep.UID) {
			return errors.New("Voice ReplicaSet owner differs")
		}
		if labels.SelectorFromSet(newSvc.Spec.Selector).Matches(labels.Set(pod.Labels)) {
			return errors.New("new Service selects Voice Pod")
		}
		oldUIDs[pod.UID] = true
	}
	newMembers, err := podBoundSelectedSliceUIDs(ctx, kc, r.Namespace, name, newSvc.UID)
	if err != nil || !newMembers[types.UID(r.PeerPodUID)] || (!allowSourceLifecycle && (len(newMembers) != 2 || !newMembers[types.UID(r.SourcePodUID)])) {
		return errors.New("Pod-token Service members differ")
	}
	for uid := range newMembers {
		if !newPods[uid] {
			return errors.New("Pod-token Service selects foreign or absent Pod")
		}
	}
	oldMembers, err := podBoundSelectedSliceUIDs(ctx, kc, r.Namespace, "voice-bot", oldSvc.UID)
	if err != nil || len(oldMembers) == 0 {
		return errors.New("Voice Service members unavailable")
	}
	for uid := range oldMembers {
		if uid == types.UID(r.SourcePodUID) || newPods[uid] || !oldUIDs[uid] {
			return errors.New("Voice Service routes into Pod-token fixture")
		}
	}
	policyOthers = append(policyOthers, actualPeerLabels)
	if err := s.podBoundPolicyDisjoint(r, actualSourceLabels, policyOthers); err != nil {
		return err
	}
	return nil
}

func (s *Server) podBoundPolicyDisjoint(r podBoundTokenRequest, sourceLabels labels.Set, otherLabels []labels.Set) error {
	var list v1alpha1.PhorvexPolicyList
	if err := s.scenarioObject(r.Namespace, "phorvexpolicy", "", &list); err != nil || list.Continue != "" || list.RemainingItemCount != nil || len(list.Items) > 256 {
		return errors.New("Pod-token policy inventory incomplete")
	}
	selected := 0
	for i := range list.Items {
		policy := &list.Items[i]
		if policy.Namespace != r.Namespace || policy.DeletionTimestamp != nil {
			return errors.New("Pod-token policy scope or lifetime differs")
		}
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.Selector)
		if err != nil || selector.Empty() {
			return errors.New("Pod-token policy selector invalid")
		}
		for _, set := range otherLabels {
			if selector.Matches(set) {
				return errors.New("peer or replacement Pod matches a policy")
			}
		}
		if selector.Matches(sourceLabels) {
			selected++
			if policy.Name != r.PolicyName || string(policy.UID) != r.PolicyUID || policy.Generation != r.PolicyGeneration || policy.EffectiveTenant() != r.Nonce || policy.Spec.EffectiveMode() != v1alpha1.ModeActive {
				return errors.New("source Pod matches foreign policy")
			}
		}
	}
	if selected != 1 {
		return errors.New("source Pod policy authority is ambiguous")
	}
	return nil
}
