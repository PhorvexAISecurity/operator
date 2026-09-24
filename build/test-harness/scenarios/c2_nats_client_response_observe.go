package scenarios

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func natsResponseClientIncarnation(ctx context.Context, env *core.Env, fixture natsResponseFixture, allowPhoenixQuarantine bool) error {
	return natsResponseObservedPodIncarnation(ctx, env, fixture, fixture.Client, true, allowPhoenixQuarantine)
}

func natsResponseObservedPodIncarnation(ctx context.Context, env *core.Env, fixture natsResponseFixture,
	target natsResponsePodIdentity, source, allowPhoenixQuarantine bool) error {
	pod, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, target.Name, metav1.GetOptions{})
	if err != nil || pod.UID != target.UID || pod.DeletionTimestamp != nil ||
		pod.Labels[natsResponseOwnerLabel] != env.Config.NATSExposureFixture.Nonce ||
		len(pod.Spec.Containers) != 1 || len(pod.Status.ContainerStatuses) != 1 {
		return errors.New("NATS response original observer Pod identity changed")
	}
	if source {
		if pod.Labels[natsResponseRoleLabel] != "source" {
			return errors.New("NATS response original source role changed")
		}
	} else if pod.Labels[natsResponseRoleLabel] != "" || len(pod.OwnerReferences) != 1 ||
		pod.OwnerReferences[0].APIVersion != "apps/v1" || pod.OwnerReferences[0].Kind != "ReplicaSet" ||
		pod.OwnerReferences[0].UID != fixture.ReplicaSetUID || pod.OwnerReferences[0].Controller == nil ||
		!*pod.OwnerReferences[0].Controller {
		return errors.New("NATS response original peer owner or role changed")
	}
	componentOriginal := pod.Labels[natsResponseComponentLabel] == "consumer"
	componentMovedByPhoenix := pod.Labels[natsResponseComponentLabel] == "" &&
		pod.Annotations[natsResponseComponentLabel] == "consumer"
	if !componentOriginal && !(source && allowPhoenixQuarantine && componentMovedByPhoenix) {
		return errors.New("NATS response original client component binding changed")
	}
	container, status := pod.Spec.Containers[0], pod.Status.ContainerStatuses[0]
	if container.Name != "observer" || container.Image != env.Config.NATSExposureFixture.ObserverImage ||
		len(container.Command) != 3 || container.Command[0] != "/app/nats-owned-observer" ||
		container.Command[1] != "--response-config" || container.Command[2] != "/config/observer.json" ||
		len(container.Env) != 2 || container.Env[0].Name != "POD_UID" || container.Env[0].ValueFrom == nil ||
		container.Env[0].ValueFrom.FieldRef == nil || container.Env[0].ValueFrom.FieldRef.FieldPath != "metadata.uid" ||
		container.Env[1].Name != "NATS_RESPONSE_SERVICE" || container.Env[1].Value != "1" ||
		len(container.VolumeMounts) != 1 || container.VolumeMounts[0].Name != "config" ||
		container.VolumeMounts[0].MountPath != "/config" || !container.VolumeMounts[0].ReadOnly ||
		container.VolumeMounts[0].SubPath != "" || container.VolumeMounts[0].SubPathExpr != "" ||
		len(pod.Spec.Volumes) != 1 || pod.Spec.Volumes[0].ConfigMap == nil || pod.Spec.Volumes[0].ConfigMap.Name != fixture.Name ||
		status.Name != "observer" || status.RestartCount != 0 || status.ContainerID != target.ContainerID ||
		status.ImageID != target.ImageID || !sameImageDigest(status.ImageID, env.Config.NATSExposureFixture.ObserverImage) {
		return errors.New("NATS response original observer process restarted or changed")
	}
	return nil
}

func natsResponseObserverLog(ctx context.Context, env *core.Env, fixture natsResponseFixture, route natsRouteIdentity, want int, allowPhoenixQuarantine bool) ([]byte, []natsResponseObserverReceipt, error) {
	return natsResponseLogForPod(ctx, env, fixture, route, fixture.Client, true, want, allowPhoenixQuarantine)
}

func natsResponsePeerLog(ctx context.Context, env *core.Env, fixture natsResponseFixture, route natsRouteIdentity, want int) ([]byte, []natsResponseObserverReceipt, error) {
	return natsResponseLogForPod(ctx, env, fixture, route, fixture.Peer, false, want, false)
}

func natsResponseLogForPod(ctx context.Context, env *core.Env, fixture natsResponseFixture, route natsRouteIdentity,
	target natsResponsePodIdentity, source bool, want int, allowPhoenixQuarantine bool) ([]byte, []natsResponseObserverReceipt, error) {
	if err := natsResponseObservedPodIncarnation(ctx, env, fixture, target, source, allowPhoenixQuarantine); err != nil {
		return nil, nil, err
	}
	stream, err := env.Kube.CoreV1().Pods(env.Config.Namespace).GetLogs(target.Name,
		&corev1.PodLogOptions{Container: "observer", Timestamps: false, Previous: false}).Stream(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer stream.Close()
	raw, err := io.ReadAll(io.LimitReader(stream, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 || !strings.HasSuffix(string(raw), "\n") {
		return nil, nil, errors.New("NATS response original client log missing or oversized")
	}
	if err := natsResponseObservedPodIncarnation(ctx, env, fixture, target, source, allowPhoenixQuarantine); err != nil {
		return nil, nil, err
	}
	subjects, payloads := natsResponseSubjects(env.Config.NATSExposureFixture.Nonce), natsResponsePayloads(env.Config.NATSExposureFixture.Nonce)
	allowed := map[string]bool{}
	for _, broker := range route.Brokers {
		allowed[broker.ServerID] = true
	}
	id := natsResponseObserverIdentity{Nonce: env.Config.NATSExposureFixture.Nonce, PodUID: target.UID,
		SubjectM0: subjects[0], SubjectM1: subjects[1], PayloadM0SHA256: natsSHA(payloads[0]),
		PayloadM1SHA256: natsSHA(payloads[1]), ServerIDs: allowed}
	receipts, err := validateNATSResponseLog(raw, id, want)
	if err != nil {
		return nil, nil, err
	}
	return raw, receipts, nil
}

func natsResponsePersistM0Prefix(out string, raw []byte) (string, error) {
	return natsResponsePersistPrefix(out, "nats-response-m0-prefix.jsonl", raw)
}

func natsResponsePersistPeerM0Prefix(out string, raw []byte) (string, error) {
	return natsResponsePersistPrefix(out, "nats-response-peer-m0-prefix.jsonl", raw)
}

func natsResponsePersistPrefix(out, name string, raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return "", errors.New("NATS response M0 prefix invalid")
	}
	if err := writeNATSResponseExclusive(filepath.Join(out, name), raw); err != nil {
		return "", err
	}
	return natsSHA(raw), nil
}
