package scenarios

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// RunMongoExposure is the one-use unscored installed configuration baseline.
// The console must already have captured an authenticated manager audit cursor
// before it invokes this harness. The harness never emits a SecurityEvent.
func RunMongoExposure(ctx context.Context, env *core.Env) (runErr error) {
	return runMongoExposureWith(ctx, env, mongoExposureDependencies{
		captureSource: captureMongoExposureSource,
		chooseNode:    mongoExposureChooseNode,
		forward:       forwardNATSPod,
		connect:       newMongoExposureDriver,
		clientLogs: func(ctx context.Context, env *core.Env, name string, limit int64) ([]byte, error) {
			return env.Kube.CoreV1().Pods(env.Config.Namespace).GetLogs(name, &corev1.PodLogOptions{Container: "read-once", LimitBytes: &limit}).DoRaw(ctx)
		},
	})
}

// Test seams replace only I/O producers. The lifecycle, durable intents,
// exact Kubernetes UID checks and cleanup remain the real production path.
type mongoExposureDependencies struct {
	captureSource func(context.Context, *core.Env) (mongoExposureSource, error)
	chooseNode    func(context.Context, *core.Env) (mongoExposureNode, error)
	forward       func(context.Context, *rest.Config, string, string, int) (int, func() error, error)
	connect       func(context.Context, int) (mongoExposureStore, error)
	clientLogs    func(context.Context, *core.Env, string, int64) ([]byte, error)
}

func runMongoExposureWith(ctx context.Context, env *core.Env, deps mongoExposureDependencies) (runErr error) {
	if env == nil || env.Kube == nil || env.Ctrl == nil || env.Rest == nil || env.Guard == nil || env.Config.MongoExposureFixture == nil || env.Config.OutDir == "" || env.NamespaceUID() == "" {
		return errors.New("Mongo exact named-suite authority incomplete")
	}
	f := env.Config.MongoExposureFixture
	if err := ClaimMongoExposureRun(env.Config.OutDir, f.RunID, f.Nonce); err != nil {
		return err
	}
	db, coll, podName := mongoExposureNames(f.Nonce)
	artifact := mongoExposureArtifact{Schema: mongoExposureArtifactSchema, RunID: f.RunID, Nonce: f.Nonce, Namespace: env.Config.Namespace, ClusterUID: types.UID(f.ClusterUID),
		Database: db, Collection: coll, DocumentSHA256: mongoExposureDocumentSHA(f.Nonce), ClientPodName: podName, ClientRead: "UNKNOWN", LegitimateBefore: "UNKNOWN", LegitimateAfter: "UNKNOWN",
		ObservedFinding: "UNKNOWN", Validity: "INCONCLUSIVE", Cleanup: "UNCONFIRMED", SecurityOutcome: "NOT_EVALUATED", StartedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	terminal := mongoExposureTerminal{}
	var store mongoExposureStore
	var closeForward func() error
	collectionCreated := false
	collectionCreateAttempted := false
	clientCreateAttempted := false
	clientUID := types.UID("")
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
		defer cancel()
		if clientCreateAttempted && clientUID != "" {
			terminal.ClientPodAbsent = mongoExposureDeleteClient(cleanupCtx, env, artifact.Node, clientUID, f.Nonce, podName) == nil
			if !terminal.ClientPodAbsent {
				runErr = errors.Join(runErr, errors.New("Mongo exact client Pod cleanup unconfirmed"))
			}
		} else if !clientCreateAttempted {
			terminal.ClientPodAbsent = true
		}
		if store != nil && collectionCreated && artifact.CollectionUUID != "" {
			terminal.CollectionAbsent = env.Guard.AssertMutationAllowed(env.Config.Namespace) == nil &&
				mongoExposureDropOwned(cleanupCtx, store, env.Config.OutDir, f.RunID, f.Nonce, db, coll, artifact.CollectionUUID) == nil
			if !terminal.CollectionAbsent {
				runErr = errors.Join(runErr, errors.New("Mongo exact collection cleanup unconfirmed"))
			}
		} else if !collectionCreateAttempted {
			terminal.CollectionAbsent = true
		}
		if store != nil {
			if err := store.Close(cleanupCtx); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("Mongo driver close: %w", err))
			}
		}
		if closeForward != nil {
			if err := closeForward(); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("Mongo forward close: %w", err))
			}
		}
		if artifact.Source.NamespaceUID != "" {
			ns, err := env.Kube.CoreV1().Namespaces().Get(cleanupCtx, env.Config.Namespace, metav1.GetOptions{})
			terminal.NamespacePreserved = err == nil && ns.UID == artifact.Source.NamespaceUID && ns.DeletionTimestamp == nil
		}
		if !terminal.NamespacePreserved {
			runErr = errors.Join(runErr, errors.New("Mongo existing namespace identity no longer confirmed"))
		}
		if runErr == nil && terminal.CollectionAbsent && terminal.ClientPodAbsent && terminal.NamespacePreserved {
			artifact.Cleanup = "CONFIRMED_ABSENT"
			if artifact.ClientRead == "UNAUTHENTICATED_EXACT_READ" && artifact.LegitimateBefore == "EXACT_READ" && artifact.LegitimateAfter == "EXACT_READ" {
				artifact.Validity = "MEASUREMENT_COMPLETE"
			}
		}
		artifact.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if artifact.Source.NamespaceUID != "" {
			runErr = errors.Join(runErr, writeMongoExposureArtifact(env.Config.OutDir, artifact, terminal))
		}
	}()

	source, err := deps.captureSource(ctx, env)
	if err != nil {
		return err
	}
	if source.NamespaceUID != env.NamespaceUID() {
		return errors.New("Mongo source namespace differs from admitted UID")
	}
	artifact.Source = source
	artifact.Node, err = deps.chooseNode(ctx, env)
	if err != nil {
		return err
	}
	if err = env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	// Port-forward is to the exact API-bound server Pod, not a Service that may
	// route to a different incarnation. It is closed and verified in the defer.
	port, closeFn, err := deps.forward(ctx, env.Rest, env.Config.Namespace, source.PodName, 27017)
	if err != nil {
		return err
	}
	closeForward = closeFn
	store, err = deps.connect(ctx, port)
	if err != nil {
		return err
	}
	serverVersion, err := store.ServerVersion(ctx)
	if err != nil || serverVersion != "7.0.40" {
		return errors.New("Mongo server version differs from UUID-guarded drop contract 7.0.40")
	}
	artifact.ServerVersion = serverVersion
	if err := store.SourceConfiguration(ctx); err != nil {
		return err
	}
	if current, err := deps.captureSource(ctx, env); err != nil || current != source {
		return errors.New("Mongo source changed after driver connection")
	}
	if existing, err := store.CollectionUUID(ctx, db, coll); err != nil || existing != "" {
		return errors.New("Mongo owned collection name already exists or absence unconfirmed")
	}
	if err = mongoExposurePhase(env.Config.OutDir, f.RunID, f.Nonce, "CREATE_INTENT", "collection", db+"."+coll, ""); err != nil {
		return err
	}
	if err = env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	collectionCreateAttempted = true
	if err = store.CreateCollection(ctx, db, coll); err != nil {
		return fmt.Errorf("Mongo collection create uncertain; no retry/adoption: %w", err)
	}
	collectionCreated = true
	if err = mongoExposurePhase(env.Config.OutDir, f.RunID, f.Nonce, "CREATE_ACK", "collection", db+"."+coll, ""); err != nil {
		return err
	}
	artifact.CollectionUUID, err = store.CollectionUUID(ctx, db, coll)
	if err != nil || len(artifact.CollectionUUID) != 32 {
		return errors.New("Mongo created collection UUID unconfirmed")
	}
	if err = mongoExposurePhase(env.Config.OutDir, f.RunID, f.Nonce, "UUID_CONFIRMED", "collection", db+"."+coll, artifact.CollectionUUID); err != nil {
		return err
	}
	doc := mongoExposureDoc(f.Nonce)
	if err = mongoExposurePhase(env.Config.OutDir, f.RunID, f.Nonce, "INSERT_INTENT", "document", f.Nonce, ""); err != nil {
		return err
	}
	if err = env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	insertedID, err := store.Insert(ctx, db, coll, doc)
	if err != nil {
		return fmt.Errorf("Mongo synthetic insert uncertain; no retry: %w", err)
	}
	ackID, ok := insertedID.(string)
	if !ok {
		return errors.New("Mongo insert ACK type differs")
	}
	if err = mongoExposurePhase(env.Config.OutDir, f.RunID, f.Nonce, "INSERT_ACK", "document", f.Nonce, ackID); err != nil {
		return err
	}
	if ackID != f.Nonce {
		return errors.New("Mongo insert ACK exact ID differs")
	}
	if err = mongoExposureLegitimateRead(ctx, store, db, coll, doc); err != nil {
		return fmt.Errorf("Mongo legitimate before: %w", err)
	}
	artifact.LegitimateBefore = "EXACT_READ"
	if current, err := deps.captureSource(ctx, env); err != nil || current != source {
		return errors.New("Mongo source changed before separate client")
	}
	want := mongoExposureClientPod(f.Nonce, artifact.Node.Name)
	if err = mongoExposurePhase(env.Config.OutDir, f.RunID, f.Nonce, "CREATE_INTENT", "pod", podName, ""); err != nil {
		return err
	}
	clientCreateAttempted = true
	created, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Create(ctx, want, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("Mongo client Pod CREATE uncertain; no retry/adoption: %w", err)
	}
	clientUID = created.UID
	artifact.ClientPodUID = clientUID
	if clientUID == "" {
		return errors.New("Mongo client Pod CREATE ACK lacks UID")
	}
	if err = mongoExposurePhase(env.Config.OutDir, f.RunID, f.Nonce, "CREATED", "pod", podName, string(clientUID)); err != nil {
		return err
	}
	if err = mongoExposureClientIdentity(created, want, clientUID); err != nil {
		return err
	}
	client, err := mongoExposureWaitClient(ctx, env, want, clientUID, artifact.Node)
	if err != nil {
		return err
	}
	preLogClient := client.DeepCopy()
	artifact.ClientImageID = client.Status.ContainerStatuses[0].ImageID
	artifact.ClientContainerID = client.Status.ContainerStatuses[0].ContainerID
	limit := int64(4097)
	logCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	raw, err := deps.clientLogs(logCtx, env, podName, limit)
	cancel()
	if err != nil || len(raw) > 4096 {
		return errors.New("Mongo exact client raw reply unavailable or oversized")
	}
	postLogClient, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil || mongoExposureStableClientLogSource(preLogClient, postLogClient, want, clientUID) != nil {
		return errors.New("Mongo log source Pod or process changed across read")
	}
	// Retain original accepted bytes private for later independent inspection;
	// no raw document is copied into a public artifact or console projection.
	if err = mongoExposureExclusive(env.Config.OutDir, "mongo-exposure-original-reply.log", raw); err != nil {
		return err
	}
	artifact.RawReplySHA256 = mongoExposureReplyHash(raw)
	artifact.RawReplyBytes = len(raw)
	artifact.ClientRead, artifact.ClientDocumentSHA256, err = mongoExposureReply(raw, f.Nonce)
	if err != nil {
		return err
	}
	if artifact.ClientRead == "UNAUTHENTICATED_EXACT_READ" && artifact.ClientDocumentSHA256 == artifact.DocumentSHA256 {
		artifact.ObservedFinding = "EXPOSED"
	}
	if err = mongoExposureLegitimateRead(ctx, store, db, coll, doc); err != nil {
		return fmt.Errorf("Mongo legitimate after: %w", err)
	}
	artifact.LegitimateAfter = "EXACT_READ"
	if current, err := deps.captureSource(ctx, env); err != nil || !reflect.DeepEqual(current, source) {
		return errors.New("Mongo source/manager/policy route changed after client read")
	}
	artifact.ObservationEndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return nil
}

func mongoExposureLegitimateRead(ctx context.Context, store mongoExposureStore, db, coll string, want mongoExposureDocument) error {
	got, err := store.Read(ctx, db, coll, want.ID)
	if err != nil || got != want {
		return errors.New("Mongo exact legitimate document read differs")
	}
	count, err := store.Count(ctx, db, coll)
	if err != nil || count != 1 {
		return errors.New("Mongo legitimate collection has non-singleton contents")
	}
	return nil
}

func mongoExposureWaitClient(ctx context.Context, env *core.Env, want *corev1.Pod, uid types.UID, node mongoExposureNode) (*corev1.Pod, error) {
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, want.Name, metav1.GetOptions{})
		if err != nil || mongoExposureClientIdentity(pod, want, uid) != nil {
			return nil, errors.New("Mongo client Pod replacement or authority drift")
		}
		if pod.Spec.NodeName != "" {
			if err = mongoExposureRequireNode(ctx, env, pod, node); err != nil {
				return nil, err
			}
		}
		if pod.Status.Phase == corev1.PodSucceeded && len(pod.Status.ContainerStatuses) == 1 {
			status := pod.Status.ContainerStatuses[0]
			if status.Name != "read-once" || status.ContainerID == "" || strings.TrimPrefix(status.ImageID, "docker-pullable://") != mongoExposureClientImage || status.RestartCount != 0 || status.State.Terminated == nil || status.State.Terminated.ExitCode != 0 || pod.Spec.NodeName == "" || pod.Status.PodIP == "" || pod.Status.HostIP == "" {
				return nil, errors.New("Mongo client process identity or exit differs")
			}
			return pod, nil
		}
		if pod.Status.Phase == corev1.PodFailed {
			return nil, errors.New("Mongo client process failed; no exact read claim")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("Mongo client scheduling/process deadline; CNI availability unknown")
		case <-tick.C:
		}
	}
}

func mongoExposureDeleteClient(ctx context.Context, env *core.Env, node mongoExposureNode, uid types.UID, nonce, name string) error {
	if uid == "" {
		return errors.New("Mongo client UID absent; no adoption")
	}
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil || pod.UID != uid || pod.Labels[mongoExposureOwnerLabel] != nonce || pod.Spec.NodeName != "" && pod.Spec.NodeName != node.Name {
		return errors.New("Mongo client cleanup current UID/owner differs")
	}
	if err = env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	if err = mongoExposurePhase(env.Config.OutDir, env.Config.MongoExposureFixture.RunID, nonce, "DELETE_INTENT", "pod", name, string(uid)); err != nil {
		return err
	}
	if err = env.Kube.CoreV1().Pods(env.Config.Namespace).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		current, e := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(e) {
			return mongoExposurePhase(env.Config.OutDir, env.Config.MongoExposureFixture.RunID, nonce, "ABSENT", "pod", name, string(uid))
		}
		if e != nil || current.UID != uid {
			return errors.New("Mongo client cleanup absence/replacement unconfirmed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("Mongo client UID deletion not confirmed")
		case <-tick.C:
		}
	}
}

func mongoExposureDropOwned(ctx context.Context, store mongoExposureStore, out, runID, nonce, db, coll, uuid string) error {
	current, err := store.CollectionUUID(ctx, db, coll)
	if err != nil || current != uuid {
		return errors.New("Mongo cleanup collection UUID differs; no drop")
	}
	if err = mongoExposureLegitimateRead(ctx, store, db, coll, mongoExposureDoc(nonce)); err != nil {
		return fmt.Errorf("Mongo cleanup owned record differs: %w", err)
	}
	if err = mongoExposurePhase(out, runID, nonce, "DROP_INTENT", "collection", db+"."+coll, uuid); err != nil {
		return err
	}
	if err = store.Drop(ctx, db, coll, uuid); err != nil {
		return err
	}
	if err = mongoExposurePhase(out, runID, nonce, "DROP_ACK", "collection", db+"."+coll, uuid); err != nil {
		return err
	}
	current, err = store.CollectionUUID(ctx, db, coll)
	if err != nil || current != "" {
		return errors.New("Mongo exact collection absence not confirmed after drop")
	}
	return mongoExposurePhase(out, runID, nonce, "ABSENT", "collection", db+"."+coll, uuid)
}
