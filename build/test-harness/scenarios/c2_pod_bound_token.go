package scenarios

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const podTokenScenario = "c2-pod-bound-api-auth-response"

var podTokenStageNames = [...]string{"ADMISSION", "OWNED_FIXTURE", "CREDENTIAL_AND_ROUTE_BASELINE", "AUDIT_START", "SOLE_TYPED_SIGNAL", "BRAIN_DECISION", "NATIVE_OPERATION", "INDEPENDENT_OUTCOME", "CLEANUP"}

func podTokenVerifySourceManifest(env *core.Env) error {
	cfg := env.Config.PodBoundTokenFixture
	info, err := os.Lstat(cfg.SourceManifestPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16<<10 {
		return errors.New("reviewed manager source manifest unavailable")
	}
	raw, err := os.ReadFile(cfg.SourceManifestPath)
	if err != nil || podTokenHash(raw) != cfg.SourceManifestSHA256 {
		return errors.New("reviewed manager source manifest SHA differs")
	}
	var manifest struct {
		Schema              string `json:"schema"`
		SourceCommit        string `json:"sourceCommit"`
		ManagerImageID      string `json:"managerImageID"`
		BuildEvidenceRef    string `json:"buildEvidenceRef"`
		BuildEvidenceSHA256 string `json:"buildEvidenceSHA256"`
		ReviewRecordRef     string `json:"reviewRecordRef"`
		ReviewRecordSHA256  string `json:"reviewRecordSHA256"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF ||
		manifest.Schema != "phorvex.manager-source-image.v1" || manifest.ManagerImageID != cfg.ManagerImageID ||
		manifest.BuildEvidenceRef == "" || manifest.ReviewRecordRef == "" {
		return errors.New("reviewed manager source manifest fields differ")
	}
	for _, value := range []struct {
		raw   string
		bytes int
	}{{manifest.SourceCommit, 20}, {manifest.BuildEvidenceSHA256, 32}, {manifest.ReviewRecordSHA256, 32}} {
		decoded, e := hex.DecodeString(value.raw)
		if e != nil || len(decoded) != value.bytes || value.raw != string(bytes.ToLower([]byte(value.raw))) {
			return errors.New("reviewed manager source manifest digest invalid")
		}
	}
	return nil
}

// An early mutation failure cannot satisfy the normal request/barrier/seal
// contract. Preserve its exact created identities and cleanup debt separately;
// this receipt is never a mechanism result or permission to retry.
type podTokenUnsafeReceipt struct {
	Schema             string   `json:"schema"`
	RunID              string   `json:"runID"`
	Nonce              string   `json:"nonce"`
	NamespaceUID       string   `json:"namespaceUID"`
	CreatedUIDs        []string `json:"createdUIDs"`
	DeploymentUID      string   `json:"deploymentUID"`
	ReplicaSetUID      string   `json:"replicaSetUID"`
	SourcePodUID       string   `json:"sourcePodUID"`
	PeerPodUID         string   `json:"peerPodUID"`
	PhaseJournalSHA256 string   `json:"phaseJournalSHA256"`
	CleanupStatus      string   `json:"cleanupStatus"`
	InventorySHA256    string   `json:"inventorySHA256"`
	ErrorSHA256        string   `json:"errorSHA256"`
	RecordedAt         string   `json:"recordedAt"`
}

func podTokenWriteUnsafe(env *core.Env, f podTokenFixture, cleanup podTokenCleanup, cause error) error {
	journal, err := os.ReadFile(filepath.Join(env.Config.OutDir, podTokenPhaseFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(journal) > 256<<10 {
		return errors.New("Pod token phase journal too large for unsafe receipt")
	}
	if cleanup.Status == "" {
		cleanup.Status = "UNCONFIRMED"
	}
	unsafe := podTokenUnsafeReceipt{
		Schema: "pod-bound-token-unsafe-v1", RunID: env.Config.PodBoundTokenFixture.RunID,
		Nonce: env.Config.PodBoundTokenFixture.Nonce, NamespaceUID: string(f.namespaceUID),
		CreatedUIDs: podTokenSortedUIDs(f.created), DeploymentUID: string(f.deploymentUID),
		ReplicaSetUID: string(f.replicaSetUID), SourcePodUID: string(f.source.UID), PeerPodUID: string(f.peer.UID),
		PhaseJournalSHA256: podTokenHash(journal), CleanupStatus: cleanup.Status,
		InventorySHA256: cleanup.InventorySHA256, ErrorSHA256: podTokenHash([]byte(cause.Error())),
		RecordedAt: podTokenUTC(),
	}
	_, err = writePodTokenFile(env.Config.OutDir, "pod-bound-token-unsafe.json", unsafe)
	return err
}

type podTokenObservationEnd struct {
	Schema             string `json:"schema"`
	RunID              string `json:"runID"`
	Nonce              string `json:"nonce"`
	RequestSHA256      string `json:"requestSHA256"`
	BarrierSHA256      string `json:"barrierSHA256"`
	ObservationEndedAt string `json:"observationEndedAt"`
}
type podTokenObservationCommitted struct {
	Schema               string          `json:"schema"`
	RunID                string          `json:"runID"`
	Nonce                string          `json:"nonce"`
	ObservationEndSHA256 string          `json:"observationEndSHA256"`
	RequestSHA256        string          `json:"requestSHA256"`
	BarrierSHA256        string          `json:"barrierSHA256"`
	SourceIdentity       string          `json:"sourceIdentity"`
	Commitment           json.RawMessage `json:"commitment"`
}
type podTokenEventCleanupReceipt struct {
	Schema     string `json:"schema"`
	RunID      string `json:"runID"`
	Nonce      string `json:"nonce"`
	EventUID   string `json:"eventUID"`
	Status     string `json:"status"`
	ObservedAt string `json:"observedAt"`
}

func podTokenStageSet(r *podTokenResult, index int, status, evidence, reason string) {
	if index < 0 || index >= len(r.Stages) {
		return
	}
	at := time.Now().UTC()
	if index > 0 {
		prior, e := time.Parse(time.RFC3339Nano, r.Stages[index-1].ObservedAt)
		if e == nil && !at.After(prior) {
			at = prior.Add(time.Nanosecond)
		}
	}
	if len(reason) > 256 {
		reason = reason[:256]
	}
	r.Stages[index] = podTokenStage{Name: podTokenStageNames[index], Status: status, ObservedAt: at.Format(time.RFC3339Nano), EvidenceSHA256: evidence, Reason: reason}
}
func podTokenWaitBarrier(ctx context.Context, dir string, req podTokenRequest, reqSHA string) (podTokenBarrier, string, error) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		b, hash, err := readPodTokenBarrier(dir, req, reqSHA)
		if err == nil {
			return b, hash, nil
		}
		if !os.IsNotExist(err) {
			return b, "", err
		}
		select {
		case <-ctx.Done():
			return b, "", ctx.Err()
		case <-tick.C:
		}
	}
}
func podTokenWaitCommit(ctx context.Context, dir string, req podTokenRequest, reqSHA, barrierSHA, endSHA string) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "pod-bound-token-observation-committed.json"))
		if err == nil {
			if len(raw) == 0 || len(raw) > 256<<10 {
				return errors.New("Pod token observation commitment oversized")
			}
			var ack podTokenObservationCommitted
			if json.Unmarshal(raw, &ack) != nil || ack.Schema != "pod-bound-token-observation-committed-v1" || ack.RunID != req.RunID || ack.Nonce != req.Nonce || ack.RequestSHA256 != reqSHA || ack.BarrierSHA256 != barrierSHA || ack.ObservationEndSHA256 != endSHA || ack.SourceIdentity == "" || len(ack.Commitment) < 2 {
				return errors.New("Pod token observation commitment identity differs")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
func podTokenWaitEventCleanup(ctx context.Context, dir string, req podTokenRequest, eventUID string) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "pod-bound-token-event-cleanup.json"))
		if err == nil {
			if len(raw) == 0 || len(raw) > 8<<10 {
				return errors.New("Pod token event cleanup receipt oversized")
			}
			var ack podTokenEventCleanupReceipt
			if json.Unmarshal(raw, &ack) != nil || ack.Schema != "pod-bound-token-event-cleanup-v1" || ack.RunID != req.RunID || ack.Nonce != req.Nonce || ack.EventUID != eventUID || ack.Status != "CONFIRMED_ABSENT" || ack.ObservedAt == "" {
				return errors.New("Pod token event cleanup identity differs")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
func podTokenManager(ctx context.Context, env *core.Env) (string, string, string, error) {
	cfg := env.Config.PodBoundTokenFixture
	dep, err := env.Kube.AppsV1().Deployments(cfg.ManagerNamespace).Get(ctx, cfg.ManagerDeployment, metav1.GetOptions{})
	if err != nil || dep.UID == "" || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 || dep.Status.ReadyReplicas != 1 || dep.Status.ObservedGeneration < dep.Generation {
		return "", "", "", errors.New("Pod token manager Deployment not current singleton")
	}
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || selector.Empty() {
		return "", "", "", errors.New("Pod token manager selector unavailable")
	}
	pods, err := env.Kube.CoreV1().Pods(cfg.ManagerNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 10})
	if err != nil || pods.Continue != "" || len(pods.Items) != 1 {
		return "", "", "", errors.New("Pod token manager Pod ambiguous")
	}
	p := pods.Items[0]
	if !podTokenReady(p) || len(p.OwnerReferences) != 1 || len(p.Status.ContainerStatuses) != 1 || p.Status.ContainerStatuses[0].RestartCount != 0 || p.Status.ContainerStatuses[0].ImageID != cfg.ManagerImageID {
		return "", "", "", errors.New("Pod token manager process changed")
	}
	rs, err := env.Kube.AppsV1().ReplicaSets(cfg.ManagerNamespace).Get(ctx, p.OwnerReferences[0].Name, metav1.GetOptions{})
	if err != nil || rs.UID != p.OwnerReferences[0].UID || len(rs.OwnerReferences) != 1 || rs.OwnerReferences[0].UID != dep.UID {
		return "", "", "", errors.New("Pod token manager owner graph differs")
	}
	return string(p.UID), p.Status.ContainerStatuses[0].ContainerID, p.Status.ContainerStatuses[0].ImageID, nil
}
func podTokenOriginalAbsent(ctx context.Context, env *core.Env, f podTokenFixture) bool {
	p, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, f.source.Name, metav1.GetOptions{})
	return err != nil && podTokenIsNotFound(err) || err == nil && p.UID != f.source.UID
}
func podTokenReplayPhase(env *core.Env, phase string, status int, at time.Time, captureID string) error {
	row := struct {
		Schema    string `json:"schema"`
		RunID     string `json:"runID"`
		Nonce     string `json:"nonce"`
		Phase     string `json:"phase"`
		HTTP      int    `json:"http"`
		At        string `json:"at"`
		CaptureID string `json:"captureID"`
	}{"pod-bound-token-replay-v1", env.Config.PodBoundTokenFixture.RunID, env.Config.PodBoundTokenFixture.Nonce, phase, status, at.Format(time.RFC3339Nano), captureID}
	raw, e := json.Marshal(row)
	if e != nil {
		return e
	}
	file, e := os.OpenFile(filepath.Join(env.Config.OutDir, "pod-bound-token-replays.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	defer file.Close()
	if n, e := file.Write(append(raw, '\n')); e != nil || n != len(raw)+1 {
		return errors.New("Pod token replay journal write incomplete")
	}
	return file.Sync()
}
func podTokenOutcomeReplay(ctx context.Context, env *core.Env, f podTokenFixture, source, peer podTokenHandle, barrier podTokenBarrier, result *podTokenResult) error {
	r := &result.Replay
	r.SourceBeforeHTTP = 200
	r.PeerBeforeHTTP = 200
	r.ServiceBeforeHTTP = 200
	r.SourceExpiry = source.expiry.Format(time.RFC3339Nano)
	r.SourceBeforeCaptureID = source.captureID
	r.SourceAfterCaptureID = source.captureID
	r.PeerBeforeCaptureID = peer.captureID
	r.PeerAfterCaptureID = peer.captureID
	r.SameSourceHandle = true
	r.SamePeerHandle = true
	deadline := time.Now().Add(90 * time.Second)
	if margin := source.expiry.Add(-30 * time.Second); margin.Before(deadline) {
		deadline = margin
	}
	for time.Now().Before(deadline) {
		status, at, err := podTokenReplayAPI(ctx, env, source, f.peer.Name)
		if err != nil {
			r.SourceAfterHTTP = 0
			r.SourceAfterAt = at.Format(time.RFC3339Nano)
			return err
		}
		r.SourceAfterHTTP = status
		r.SourceAfterAt = at.Format(time.RFC3339Nano)
		if err := podTokenReplayPhase(env, "source-after", status, at, source.captureID); err != nil {
			return err
		}
		if status == 401 || barrier.Decision.SelectedAction != "rotate" {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	status, at, err := podTokenReplayAPI(ctx, env, peer, f.peer.Name)
	if err != nil {
		return err
	}
	r.PeerAfterHTTP = status
	if err := podTokenReplayPhase(env, "peer-after", status, at, peer.captureID); err != nil {
		return err
	}
	serviceStatus, member, sliceUID, err := podTokenServiceReady(ctx, env, f)
	r.ServiceAfterHTTP = serviceStatus
	r.ServiceAfterAt = podTokenUTC()
	r.ServiceAfterServiceUID = string(f.serviceUID)
	r.ServiceMemberPodUID = string(member)
	r.ServiceAfterEndpointSliceUID = string(sliceUID)
	r.ServiceMemberReady = err == nil
	r.ServiceMemberOwnerDeploymentUID = string(f.deploymentUID)
	if err != nil {
		return err
	}
	return nil
}

// RunPodBoundTokenCase is the sole unscored producer. It never creates an event
// or chooses a policy action; the console writes the one trusted barrier.
func RunPodBoundTokenCase(ctx context.Context, env *core.Env) (runErr error) {
	if env == nil || env.Config.PodBoundTokenFixture == nil || env.Config.Namespace != "voice" || env.Config.ProfileSHA256 == "" || env.Config.OutDir == "" {
		return errors.New("Pod token named-suite authority absent")
	}
	cfg := env.Config.PodBoundTokenFixture
	result := podTokenResult{Schema: "pod-bound-token-result-v1", RunID: cfg.RunID, Nonce: cfg.Nonce, TerminalStatus: "INCOMPLETE", SecurityEfficacy: "NOT_EVALUATED", SignalMode: "explicit-injected-typed-event", Stages: make([]podTokenStage, len(podTokenStageNames))}
	for i, name := range podTokenStageNames {
		result.Stages[i] = podTokenStage{Name: name, Status: "UNKNOWN"}
	}
	if cfg.ProtectedLedgerName != podTokenLedgerName(env.NamespaceUID()) {
		return errors.New("reviewed protected ledger pin differs from live Voice namespace UID")
	}
	if err := podTokenVerifySourceManifest(env); err != nil {
		return err
	}
	if err := podTokenNoCollision(ctx, env); err != nil {
		return err
	}
	if err := podTokenDisjointPrecreate(ctx, env); err != nil {
		return err
	}
	_, priorReservations, err := podTokenProtectedInventory(ctx, env, podTokenFixture{namespaceUID: env.NamespaceUID()})
	if err != nil {
		return err
	}
	if _, err := writePodTokenFile(env.Config.OutDir, "pod-bound-token-ledger-preflight.json", struct {
		Schema              string `json:"schema"`
		RunID               string `json:"runID"`
		Nonce               string `json:"nonce"`
		NamespaceUID        string `json:"namespaceUID"`
		ProtectedLedgerName string `json:"protectedLedgerName"`
		PriorReservations   int    `json:"priorReservations"`
		ObservedAt          string `json:"observedAt"`
	}{"pod-bound-token-ledger-preflight-v1", cfg.RunID, cfg.Nonce, string(env.NamespaceUID()), cfg.ProtectedLedgerName, priorReservations, podTokenUTC()}); err != nil {
		return err
	}
	managerUID, managerContainer, managerImage, err := podTokenManager(ctx, env)
	if err != nil {
		return err
	}
	podTokenStageSet(&result, 0, "CONFIRMED", env.Config.ProfileSHA256, "current source and cluster pinned")
	fixture, err := podTokenFixtureCreate(ctx, env)
	defer func() {
		if fixture.name != "" && result.Cleanup.Status == "" {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
			cleanup, _, cleanupErr := podTokenCleanupFixture(cleanupCtx, env, fixture)
			cancel()
			result.Cleanup = cleanup
			runErr = errors.Join(runErr, cleanupErr)
		}
		if fixture.name != "" && runErr != nil {
			if _, statErr := os.Stat(filepath.Join(env.Config.OutDir, podTokenTerminalFile)); os.IsNotExist(statErr) {
				runErr = errors.Join(runErr, podTokenWriteUnsafe(env, fixture, result.Cleanup, runErr))
			}
		}
	}()
	if err != nil {
		return err
	}
	podTokenStageSet(&result, 1, "CONFIRMED", podTokenHash([]byte(podTokenFixtureSummary(fixture))), "two controller-owned Ready Pods")
	sa, err := env.Kube.CoreV1().ServiceAccounts(env.Config.Namespace).Get(ctx, fixture.name, metav1.GetOptions{})
	if err != nil || sa.UID == "" {
		return errors.New("Pod token ServiceAccount identity unavailable")
	}
	source, err := podTokenCapture(ctx, env, fixture.source, sa.UID)
	if err != nil {
		return err
	}
	peer, err := podTokenCapture(ctx, env, fixture.peer, sa.UID)
	if err != nil {
		return err
	}
	if source.captureID == peer.captureID || source.token == peer.token {
		return errors.New("Pod token independent projected handles not distinct")
	}
	sourceHTTP, sourceAt, err := podTokenReplayAPI(ctx, env, source, fixture.peer.Name)
	if err != nil || sourceHTTP != 200 {
		return errors.New("source projected bearer API baseline not 200")
	}
	if err := podTokenReplayPhase(env, "source-before", sourceHTTP, sourceAt, source.captureID); err != nil {
		return err
	}
	peerHTTP, peerAt, err := podTokenReplayAPI(ctx, env, peer, fixture.peer.Name)
	if err != nil || peerHTTP != 200 {
		return errors.New("peer projected bearer API baseline not 200")
	}
	if err := podTokenReplayPhase(env, "peer-before", peerHTTP, peerAt, peer.captureID); err != nil {
		return err
	}
	if status, e := podTokenDirectReady(ctx, fixture.source, cfg.Nonce); e != nil || status != 200 {
		return errors.New("source direct route baseline unavailable")
	}
	if status, e := podTokenDirectReady(ctx, fixture.peer, cfg.Nonce); e != nil || status != 200 {
		return errors.New("peer direct route baseline unavailable")
	}
	serviceHTTP, _, _, err := podTokenServiceReady(ctx, env, fixture)
	if err != nil || serviceHTTP != 200 {
		return errors.New("owned Service route baseline unavailable")
	}
	telemetry := podTokenWarmMetric(ctx, env, fixture)
	result.Telemetry = telemetry
	podTokenStageSet(&result, 2, "CONFIRMED", telemetry.QuerySHA256, "capture-once projected handles and real route baselines")
	if err := podTokenCurrentPod(ctx, env, fixture.source); err != nil {
		return err
	}
	if err := podTokenCurrentPod(ctx, env, fixture.peer); err != nil {
		return err
	}
	if err := podTokenCurrentPolicy(ctx, env, fixture); err != nil {
		return err
	}
	if err := podTokenDisjointPrecreate(ctx, env); err != nil {
		return err
	}
	currentUID, currentContainer, currentImage, err := podTokenManager(ctx, env)
	if err != nil || currentUID != managerUID || currentContainer != managerContainer || currentImage != managerImage {
		return errors.New("manager incarnation changed before request")
	}
	request := podTokenRequest{Schema: "pod-bound-token-request-v1", RunID: cfg.RunID, Nonce: cfg.Nonce, ClusterUID: cfg.ClusterUID, Namespace: env.Config.Namespace, NamespaceUID: string(env.NamespaceUID()), SourcePodName: fixture.source.Name, SourcePodUID: string(fixture.source.UID), DeploymentUID: string(fixture.deploymentUID), ReplicaSetUID: string(fixture.replicaSetUID), PeerPodName: fixture.peer.Name, PeerPodUID: string(fixture.peer.UID), ServiceName: fixture.name, ServiceUID: string(fixture.serviceUID), PolicyName: fixture.name, PolicyUID: string(fixture.policyUID), PolicyGeneration: fixture.policyGeneration, PolicySpecSHA256: fixture.policySpecSHA, ManagerPodUID: managerUID, ManagerContainerID: managerContainer, ManagerImageID: managerImage, ProfileSHA256: env.Config.ProfileSHA256, SourceBeforeHTTP: sourceHTTP, PeerBeforeHTTP: peerHTTP, ServiceBeforeHTTP: serviceHTTP, SourceExpiry: source.expiry.Format(time.RFC3339Nano), RequestedAt: podTokenUTC(), SourceCaptureID: source.captureID, PeerCaptureID: peer.captureID, MetricStatus: telemetry.ProducerStatus, MetricFirstAt: telemetry.FirstAt, MetricSecondAt: telemetry.SecondAt, MetricFirstValue: telemetry.FirstValue, MetricSecondValue: telemetry.SecondValue, MetricSourcePodName: telemetry.SourcePodName, PodMonitorUID: telemetry.PodMonitorUID, MetricQuerySHA256: telemetry.QuerySHA256}
	requestSHA, err := writePodTokenFile(env.Config.OutDir, podTokenRequestFile, request)
	if err != nil {
		return err
	}
	result.Admission = podTokenAdmission{ClusterUID: request.ClusterUID, Namespace: request.Namespace, NamespaceUID: request.NamespaceUID, ManagerPodUID: request.ManagerPodUID, ManagerContainerID: request.ManagerContainerID, ManagerImageID: request.ManagerImageID, DeploymentUID: request.DeploymentUID, ReplicaSetUID: request.ReplicaSetUID, PolicyUID: request.PolicyUID, PolicyGeneration: request.PolicyGeneration, PolicySpecSHA256: request.PolicySpecSHA256, SourcePodUID: request.SourcePodUID, PeerPodUID: request.PeerPodUID, ServiceUID: request.ServiceUID, ProfileSHA256: request.ProfileSHA256, Available: true}
	barrierCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	barrier, barrierSHA, err := podTokenWaitBarrier(barrierCtx, env.Config.OutDir, request, requestSHA)
	cancel()
	if err != nil {
		return err
	}
	result.Event = barrier.Event
	result.Decision = barrier.Decision
	result.Operation = barrier.Operation
	podTokenStageSet(&result, 3, "CONFIRMED", requestSHA, "authenticated audit start committed by coordinator")
	podTokenStageSet(&result, 4, "CONFIRMED", barrierSHA, "sole trusted typed event read back")
	podTokenStageSet(&result, 5, "CONFIRMED", barrier.DecisionRowSHA, "one attributed decision")
	if barrier.Decision.SelectedAction == "rotate" && barrier.Decision.DispatchOutcome == "emitted" && barrier.Operation.TerminationStatus == "REQUEST_CONFIRMED" {
		waitCtx, done := context.WithTimeout(ctx, 75*time.Second)
		for !podTokenOriginalAbsent(waitCtx, env, fixture) {
			select {
			case <-waitCtx.Done():
				break
			case <-time.After(2 * time.Second):
			}
			if waitCtx.Err() != nil {
				break
			}
		}
		done()
		result.Operation.OriginalPodAbsent = podTokenOriginalAbsent(ctx, env, fixture)
		if result.Operation.OriginalPodAbsent {
			if err := podTokenCreatePhase(env, "ORIGINAL_POD_ABSENT", "pods", fixture.source.Name, fixture.source.UID); err != nil {
				return err
			}
		}
	}
	operationReason := "no native request dispatched"
	if barrier.Operation.TerminationStatus == "REQUEST_CONFIRMED" {
		operationReason = "exact native request receipt"
	}
	podTokenStageSet(&result, 6, "CONFIRMED", barrier.Operation.ReceiptSHA256, operationReason)
	replayErr := podTokenOutcomeReplay(ctx, env, fixture, source, peer, barrier, &result)
	if replayErr == nil {
		podTokenStageSet(&result, 7, "CONFIRMED", podTokenHash([]byte(result.Replay.SourceAfterAt+result.Replay.ServiceAfterAt)), "same captured handles and routed Service rechecked")
	} else {
		podTokenStageSet(&result, 7, "UNKNOWN", "", "independent replay incomplete")
	}
	observationEndedAt := podTokenUTC()
	end := podTokenObservationEnd{Schema: "pod-bound-token-observation-end-v1", RunID: cfg.RunID, Nonce: cfg.Nonce, RequestSHA256: requestSHA, BarrierSHA256: barrierSHA, ObservationEndedAt: observationEndedAt}
	endSHA, endErr := writePodTokenFile(env.Config.OutDir, "pod-bound-token-observation-end.json", end)
	commitOK := false
	if endErr == nil {
		commitCtx, done := context.WithTimeout(ctx, 90*time.Second)
		commitErr := podTokenWaitCommit(commitCtx, env.Config.OutDir, request, requestSHA, barrierSHA, endSHA)
		done()
		commitOK = commitErr == nil
		runErr = errors.Join(runErr, commitErr)
	} else {
		runErr = errors.Join(runErr, endErr)
	}
	cleanupCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
	cleanup, protectedAbsent, cleanupErr := podTokenCleanupFixture(cleanupCtx, env, fixture)
	done()
	result.Cleanup = cleanup
	runErr = errors.Join(runErr, cleanupErr)
	eventClean := false
	if commitOK {
		ackCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		eventErr := podTokenWaitEventCleanup(ackCtx, env.Config.OutDir, request, barrier.Event.UID)
		done()
		eventClean = eventErr == nil
		runErr = errors.Join(runErr, eventErr)
	}
	if !eventClean {
		result.Cleanup.Status = "UNCONFIRMED"
		result.Cleanup.Absent = false
	}
	if result.Cleanup.Absent {
		podTokenStageSet(&result, 8, "CONFIRMED", result.Cleanup.InventorySHA256, "exact UID inventory and protected reservation absent")
	} else {
		podTokenStageSet(&result, 8, "UNKNOWN", result.Cleanup.InventorySHA256, "cleanup debt retained")
	}
	result.Replay.SameSourceHandle = result.Replay.SourceBeforeCaptureID != "" && result.Replay.SourceBeforeCaptureID == result.Replay.SourceAfterCaptureID
	result.Replay.SamePeerHandle = result.Replay.PeerBeforeCaptureID != "" && result.Replay.PeerBeforeCaptureID == result.Replay.PeerAfterCaptureID
	replayAt, replayTimeErr := time.Parse(time.RFC3339Nano, result.Replay.SourceAfterAt)
	result.MechanismObserved = result.Decision.SelectedAction == "rotate" && result.Decision.DispatchOutcome == "emitted" && result.Decision.RequestRateStatus == "MEASURED_FRESH" && result.Telemetry.ProducerStatus == "MEASURED_FRESH" && result.Operation.TerminationStatus == "REQUEST_CONFIRMED" && result.Operation.OriginalPodAbsent && result.Replay.SourceAfterHTTP == 401 && result.Replay.PeerAfterHTTP == 200 && result.Replay.ServiceAfterHTTP == 200 && result.Replay.ServiceMemberReady && result.Replay.ServiceMemberPodUID != string(fixture.source.UID) && result.Replay.SameSourceHandle && result.Replay.SamePeerHandle && replayTimeErr == nil && replayAt.Before(source.expiry) && result.Cleanup.Absent && eventClean && commitOK && replayErr == nil
	if result.Cleanup.Absent && commitOK && replayErr == nil {
		result.TerminalStatus = "COMPLETE"
	} else if !result.Cleanup.Absent {
		result.TerminalStatus = "UNSAFE"
	}
	phasesRaw, phaseErr := os.ReadFile(filepath.Join(env.Config.OutDir, podTokenPhaseFile))
	if phaseErr != nil || len(phasesRaw) == 0 || len(phasesRaw) > 256<<10 {
		return errors.Join(runErr, errors.New("Pod token final phase journal unavailable"))
	}
	artifact := podTokenArtifact{Result: result, RequestSHA256: requestSHA, BarrierSHA256: barrierSHA, PhaseJournalSHA256: podTokenHash(phasesRaw), ObservationEndedAt: observationEndedAt}
	artifactSHA, artifactErr := writePodTokenFile(env.Config.OutDir, podTokenArtifactFile, artifact)
	runErr = errors.Join(runErr, artifactErr)
	if artifactErr == nil {
		_, terminalErr := writePodTokenFile(env.Config.OutDir, podTokenTerminalFile, podTokenTerminal{Schema: "pod-bound-token-terminal-v1", RunID: cfg.RunID, Nonce: cfg.Nonce, ArtifactSHA256: artifactSHA, CleanupStatus: result.Cleanup.Status, ProtectedReservationAbsent: protectedAbsent && eventClean, FinishedAt: podTokenUTC()})
		runErr = errors.Join(runErr, terminalErr)
	}
	if replayErr != nil {
		return errors.Join(runErr, replayErr)
	}
	return runErr
}
