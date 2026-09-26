package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/cataloguev1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const podBoundCPUExpiryMargin = 30 * time.Second

type mongoEarlyCleanupProof struct {
	Present                                   bool
	NamespaceUID, ClientPodName, ClientPodUID string
}

// This accepts only the early-client Mongo producer shape observed in run-20:
// its old artifact could not credit cleanup after a measurement error, but its
// create-once terminal and exact phase journal did confirm both owned absences.
// It does not change that run's partial/unsafe status or make a Mongo claim.
func mongoEarlyCleanupProofAt(prior *RunStatus, out, expectedTarget string) (mongoEarlyCleanupProof, error) {
	var proof mongoEarlyCleanupProof
	if expectedTarget == "" || expectedTarget == defaultTargetID {
		return proof, errors.New("CPU token reviewed cluster context unavailable")
	}
	if prior == nil || !prior.UnsafeToRetry || prior.Config != mongoExposureConfig || prior.ExecutionKind != "" ||
		prior.State != "partial" || prior.CleanupStatus != "UNVERIFIED" || prior.Namespace != mongoExposureNamespace ||
		prior.ScopeTenant != mongoExposureNamespace || prior.ScopeTarget != expectedTarget || prior.Finished == "" || prior.Owner == "" ||
		prior.Error != "Mongo measurement, audit join or exact cleanup unverified; original result remains partial" ||
		prior.ID == "" || filepath.Base(out) != prior.ID {
		return proof, errors.New("CPU token Mongo predecessor status differs")
	}
	read := func(name string, limit int) ([]byte, error) {
		raw, err := readNATSResponseSizedFile(out, name, int64(limit))
		if err != nil {
			return nil, errors.New("CPU token Mongo original unavailable or ambiguous")
		}
		if !strings.HasSuffix(name, ".jsonl") && rejectAmbiguousMongoJSON(raw) != nil {
			return nil, errors.New("CPU token Mongo original unavailable or ambiguous")
		}
		return raw, nil
	}
	claimRaw, e1 := read("mongo-exposure-claim.json", 4096)
	startRaw, e2 := read("mongo-exposure-audit-start.json", 4096)
	artifactRaw, e3 := read("mongo-exposure.json", 64<<10)
	terminalRaw, e4 := read("mongo-exposure-terminal.json", 4096)
	auditRaw, e5 := read("mongo-exposure-audit-terminal.json", 256<<10)
	phaseRaw, e6 := read("mongo-exposure-phases.jsonl", 64<<10)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || len(phaseRaw) == 0 || phaseRaw[len(phaseRaw)-1] != '\n' {
		return proof, errors.New("CPU token Mongo original cleanup chain incomplete")
	}
	var start mongoAuditStart
	var artifact mongoArtifactEvidence
	var terminal struct {
		mongoTerminalEvidence
		ObservedAt string `json:"observedAt"`
	}
	var auditEnd mongoAuditTerminal
	if json.Unmarshal(startRaw, &start) != nil ||
		json.Unmarshal(artifactRaw, &artifact) != nil || json.Unmarshal(terminalRaw, &terminal) != nil ||
		json.Unmarshal(auditRaw, &auditEnd) != nil {
		return proof, errors.New("CPU token Mongo original cleanup JSON invalid")
	}
	// Claim's persisted spelling is runId; decode it independently of the
	// in-memory Go field name to avoid silently dropping the run identity.
	var claimIdentity struct {
		Schema string `json:"schema"`
		RunID  string `json:"runId"`
		Nonce  string `json:"nonce"`
	}
	if json.Unmarshal(claimRaw, &claimIdentity) != nil || claimIdentity.Schema != "mongo-exposure-claim-v1" ||
		claimIdentity.RunID != prior.ID || !mongoNonce.MatchString(claimIdentity.Nonce) ||
		start.Schema != "mongo-exposure-audit-start-v1" || start.RunID != prior.ID || !mongoSHA.MatchString(start.ConfigSHA256) ||
		start.Segment.ID != "live" || strings.TrimSpace(start.SourceIdentity) == "" ||
		strings.TrimSpace(start.Segment.Generation) == "" || strings.TrimSpace(start.Segment.Anchor) == "" ||
		start.Offset != start.Segment.Size ||
		artifact.Schema != "mongo-exposure-artifact-v1" || artifact.RunID != prior.ID || artifact.Nonce != claimIdentity.Nonce ||
		artifact.Namespace != mongoExposureNamespace || artifact.Database != "cc_"+artifact.Nonce || artifact.Collection != "owned_"+artifact.Nonce ||
		artifact.ClientPodName != "cat-mongo-read-"+artifact.Nonce[:12] || !mongoKubeUID.MatchString(string(artifact.ClientPodUID)) ||
		!mongoNonce.MatchString(artifact.CollectionUUID) || !mongoKubeUID.MatchString(string(artifact.Source.NamespaceUID)) ||
		artifact.Source.PodUID == "" || artifact.Source.PolicyUID == "" || artifact.SecurityOutcome != "NOT_EVALUATED" ||
		artifact.ClientRead != "UNKNOWN" || artifact.LegitimateBefore != "EXACT_READ" || artifact.LegitimateAfter != "UNKNOWN" ||
		artifact.ObservedFinding != "UNKNOWN" || artifact.Validity != "INCONCLUSIVE" || artifact.Cleanup != "UNCONFIRMED" ||
		artifact.ObservationEndedAt != "" || artifact.RawReplyBytes != 0 || artifact.RawReplySHA256 != "" ||
		artifact.ClientContainerID != "" || artifact.ClientImageID != "" ||
		terminal.Schema != "mongo-exposure-terminal-v1" || terminal.RunID != prior.ID || terminal.Nonce != artifact.Nonce ||
		terminal.NamespaceUID != artifact.Source.NamespaceUID || terminal.ArtifactSHA256 != mongoHash(artifactRaw) ||
		terminal.Cleanup != "UNCONFIRMED" || !terminal.ClientPodAbsent || !terminal.CollectionAbsent || !terminal.NamespacePreserved ||
		auditEnd.Schema != "mongo-exposure-audit-terminal-v1" || auditEnd.RunID != prior.ID ||
		auditEnd.StartSHA256 != mongoHash(startRaw) || auditEnd.ArtifactSHA256 != mongoHash(artifactRaw) ||
		auditEnd.SourceIdentity != start.SourceIdentity || auditEnd.ObservationEnd != "" ||
		auditEnd.BrainTrace != "GAP" || auditEnd.IssueCode != "AUDIT_GAP" || len(auditEnd.BrainDecisions) != 0 {
		return proof, errors.New("CPU token Mongo original identities or exact cleanup differ")
	}
	startAt, e1 := time.Parse(time.RFC3339Nano, start.ObservedAt)
	started, e2 := time.Parse(time.RFC3339Nano, artifact.StartedAt)
	finished, e3 := time.Parse(time.RFC3339Nano, artifact.FinishedAt)
	terminalAt, e4 := time.Parse(time.RFC3339Nano, terminal.ObservedAt)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || startAt.IsZero() || startAt.After(started) ||
		finished.Before(started) || terminalAt.Before(finished) {
		return proof, errors.New("CPU token Mongo original chronology differs")
	}
	lines := bytes.Split(phaseRaw[:len(phaseRaw)-1], []byte{'\n'})
	if len(lines) != 12 {
		return proof, errors.New("CPU token Mongo exact cleanup phases incomplete")
	}
	collection := artifact.Database + "." + artifact.Collection
	want := []struct{ phase, resource, name, identity string }{
		{"CREATE_INTENT", "collection", collection, ""}, {"CREATE_ACK", "collection", collection, ""},
		{"UUID_CONFIRMED", "collection", collection, artifact.CollectionUUID}, {"INSERT_INTENT", "document", artifact.Nonce, ""},
		{"INSERT_ACK", "document", artifact.Nonce, artifact.Nonce}, {"CREATE_INTENT", "pod", artifact.ClientPodName, ""},
		{"CREATED", "pod", artifact.ClientPodName, string(artifact.ClientPodUID)},
		{"DELETE_INTENT", "pod", artifact.ClientPodName, string(artifact.ClientPodUID)},
		{"ABSENT", "pod", artifact.ClientPodName, string(artifact.ClientPodUID)},
		{"DROP_INTENT", "collection", collection, artifact.CollectionUUID},
		{"DROP_ACK", "collection", collection, artifact.CollectionUUID},
		{"ABSENT", "collection", collection, artifact.CollectionUUID},
	}
	previous := started
	for i, line := range lines {
		var got mongoPhaseEvidence
		if rejectAmbiguousMongoJSON(line) != nil || json.Unmarshal(line, &got) != nil ||
			got.Schema != "mongo-exposure-phase-v1" || got.RunID != prior.ID || got.Nonce != artifact.Nonce ||
			got.Phase != want[i].phase || got.Resource != want[i].resource || got.Name != want[i].name || got.Identity != want[i].identity {
			return proof, errors.New("CPU token Mongo exact cleanup phase identity differs")
		}
		at, err := time.Parse(time.RFC3339Nano, got.At)
		if err != nil || at.Before(previous) || at.After(finished) {
			return proof, errors.New("CPU token Mongo exact cleanup phase chronology differs")
		}
		previous = at
	}
	proof.Present, proof.NamespaceUID, proof.ClientPodName, proof.ClientPodUID = true, string(artifact.Source.NamespaceUID), artifact.ClientPodName, string(artifact.ClientPodUID)
	return proof, nil
}

// Caller holds rm.mu. A second Mongo unsafe run, a live process, or any
// changed original refuses CPU admission; historical run status is untouched.
func (rm *RunManager) mongoEarlyCleanupProofLocked(expectedTarget string) (mongoEarlyCleanupProof, error) {
	var proof mongoEarlyCleanupProof
	var prior *RunStatus
	for _, status := range rm.runs {
		if status == nil {
			return proof, errors.New("CPU token prior run history ambiguous")
		}
		if status.UnsafeToRetry && status.Config == mongoExposureConfig {
			if prior != nil {
				return proof, errors.New("CPU token has multiple unsafe Mongo predecessors")
			}
			prior = status
		}
	}
	if prior == nil {
		return proof, nil
	}
	if rm.procs[prior.ID] != nil || rm.stopping[prior.ID] || strings.Contains(prior.Error, "reconciliation pending") ||
		!cataloguev1.ExecutionLockAvailable(rm.cfg.runOutputPath(prior.ID)) {
		return proof, errors.New("CPU token Mongo predecessor is active or unresolved")
	}
	return mongoEarlyCleanupProofAt(prior, rm.cfg.runOutputPath(prior.ID), expectedTarget)
}

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
	var voice, mongo *RunStatus
	for _, status := range rm.runs {
		if status == nil {
			return errors.New("CPU token prior history ambiguous")
		}
		if status.UnsafeToRetry {
			switch status.Config {
			case podBoundTokenCPUConfig:
				// Exact pre-event CPU originals are checked below, one by one.
			case string(cataloguev1.VoiceRecovery):
				if voice != nil {
					return errors.New("CPU token has multiple unsafe Voice predecessors")
				}
				voice = status
			case mongoExposureConfig:
				if mongo != nil {
					return errors.New("CPU token has multiple unsafe Mongo predecessors")
				}
				mongo = status
			default:
				return errors.New("CPU token has unclassified unsafe predecessor")
			}
		}
	}
	if mongo != nil {
		if _, err := rm.mongoEarlyCleanupProofLocked(destination.ScopeTarget); err != nil {
			return err
		}
	}
	if _, err := rm.cpuCleanupProofsLocked(destination.ScopeTarget); err != nil {
		return err
	}
	if voice == nil {
		return nil
	}
	if voice.ID != podBoundPriorVoiceID || voice.ExecutionKind != "fixed-suite" ||
		voice.Config != string(cataloguev1.VoiceRecovery) || voice.State != "partial" ||
		voice.Outcome != string(cataloguev1.OutcomeTestFailed) || voice.CleanupStatus != "FAIL" ||
		voice.ScopeTenant != podBoundTokenNamespace || voice.ScopeTarget != defaultTargetID ||
		voice.Finished == "" || voice.Owner == "" || rm.procs[voice.ID] != nil || rm.stopping[voice.ID] ||
		strings.Contains(voice.Error, "reconciliation pending") || !cataloguev1.ExecutionLockAvailable(rm.cfg.runOutputPath(voice.ID)) {
		return errors.New("CPU token unsafe predecessor differs from exact retained Voice run")
	}
	return rm.validatePriorVoiceFiles(voice)
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

func podBoundCPUMongoLiveAbsence(ctx context.Context, kc kubernetes.Interface, proof mongoEarlyCleanupProof) error {
	if !proof.Present {
		return nil
	}
	if kc == nil || !mongoKubeUID.MatchString(proof.NamespaceUID) || !mongoKubeUID.MatchString(proof.ClientPodUID) || proof.ClientPodName == "" {
		return errors.New("CPU token prior Mongo cleanup source incomplete")
	}
	mongoNS, err := kc.CoreV1().Namespaces().Get(ctx, mongoExposureNamespace, metav1.GetOptions{})
	if err != nil || string(mongoNS.UID) != proof.NamespaceUID || mongoNS.DeletionTimestamp != nil {
		return errors.New("CPU token prior Mongo namespace identity changed")
	}
	_, err = kc.CoreV1().Pods(mongoExposureNamespace).Get(ctx, proof.ClientPodName, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		return errors.New("CPU token prior Mongo owned client Pod absence unconfirmed")
	}
	return nil
}

// A parsed predecessor proof is only evidence of historical cleanup. Each new
// admission and the event boundary must confirm the exact old footprint is
// still absent in the current cluster before a different nonce can proceed.
func (s *Server) podBoundCPUPriorLiveAbsence(ctx context.Context, expectedTarget, ledgerNamespace, ledgerName string) error {
	if s == nil || s.runs == nil || expectedTarget == "" || ledgerNamespace == "" || ledgerName == "" {
		return errors.New("CPU token prior cleanup authority unavailable")
	}
	s.runs.mu.Lock()
	proofs, err := s.runs.cpuCleanupProofsLocked(expectedTarget)
	s.runs.mu.Unlock()
	if err != nil || len(proofs) == 0 {
		return err
	}
	restCfg, err := s.podBoundRESTConfig()
	if err != nil {
		return err
	}
	kc, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return err
	}
	dc, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return err
	}
	for _, proof := range proofs {
		if err := podBoundCPUCleanupLiveAbsence(ctx, kc, dc, proof, ledgerNamespace, ledgerName); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) podBoundCPUGraph(ctx context.Context, kc kubernetes.Interface, r podBoundTokenRequest, p podBoundTokenProfile, allowSourceLifecycle bool) error {
	expectedTarget := p.Context
	if err := s.podBoundCPUPriorLiveAbsence(ctx, expectedTarget, p.Fixture.ManagerNamespace, p.Fixture.ProtectedLedgerName); err != nil {
		return err
	}
	s.runs.mu.Lock()
	mongoProof, mongoErr := s.runs.mongoEarlyCleanupProofLocked(expectedTarget)
	s.runs.mu.Unlock()
	if mongoErr != nil {
		return mongoErr
	}
	if err := podBoundCPUMongoLiveAbsence(ctx, kc, mongoProof); err != nil {
		return err
	}
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
