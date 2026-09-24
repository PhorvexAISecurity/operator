package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var errNATSResponsePending = errors.New("NATS response original consumers not Ready")

func natsResponseConsumerSnapshot(ctx context.Context, env *core.Env, fixture natsResponseFixture) ([]corev1.Pod, types.UID, error) {
	if env.NamespaceUID() != fixture.NamespaceUID || fixture.DeploymentUID == "" || fixture.Name == "" {
		return nil, "", errors.New("NATS response namespace or Deployment create identity absent")
	}
	dep, err := env.Kube.AppsV1().Deployments(env.Config.Namespace).Get(ctx, fixture.Name, metav1.GetOptions{})
	if err != nil || dep.UID != fixture.DeploymentUID || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 2 ||
		dep.Spec.Selector == nil || dep.Spec.Selector.MatchLabels[natsResponseOwnerLabel] != env.Config.NATSExposureFixture.Nonce ||
		dep.Spec.Selector.MatchLabels[natsResponseComponentLabel] != "consumer" {
		return nil, "", errors.New("NATS response Deployment identity or selection changed")
	}
	if dep.Status.ObservedGeneration < dep.Generation || dep.Status.ReadyReplicas != 2 || dep.Status.UpdatedReplicas != 2 {
		return nil, "", errNATSResponsePending
	}
	selector := fmt.Sprintf("%s=%s,%s=consumer", natsResponseOwnerLabel, env.Config.NATSExposureFixture.Nonce, natsResponseComponentLabel)
	sets, err := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 10})
	if err != nil || sets.Continue != "" || sets.RemainingItemCount != nil {
		return nil, "", errors.New("NATS response ReplicaSet inventory incomplete")
	}
	if len(sets.Items) == 0 {
		return nil, "", errNATSResponsePending
	}
	if len(sets.Items) != 1 {
		return nil, "", errors.New("NATS response has multiple or foreign ReplicaSets")
	}
	rs := &sets.Items[0]
	if !natsResponseOwnedReplicaSet(rs, dep) {
		return nil, "", errors.New("NATS response ReplicaSet owner differs")
	}
	pods, err := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 10})
	if err != nil || pods.Continue != "" || pods.RemainingItemCount != nil {
		return nil, "", errors.New("NATS response Pod inventory incomplete")
	}
	if len(pods.Items) < 2 {
		return nil, "", errNATSResponsePending
	}
	if len(pods.Items) != 2 {
		return nil, "", errors.New("NATS response original Pod set is not exactly two")
	}
	sort.Slice(pods.Items, func(i, j int) bool { return pods.Items[i].Name < pods.Items[j].Name })
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || len(p.Status.ContainerStatuses) == 0 {
			return nil, "", errNATSResponsePending
		}
		if _, err := natsResponseReadyPod(p, rs.UID, rs.Name, env.Config.NATSExposureFixture.Nonce,
			env.Config.NATSExposureFixture.NodeName, env.Config.NATSExposureFixture.ObserverImage); err != nil {
			return nil, "", err
		}
	}
	return pods.Items, rs.UID, nil
}

func natsResponseOwnedReplicaSet(rs *appsv1.ReplicaSet, dep *appsv1.Deployment) bool {
	if rs == nil || dep == nil || rs.UID == "" || rs.DeletionTimestamp != nil || rs.Spec.Replicas == nil || *rs.Spec.Replicas != 2 || len(rs.OwnerReferences) != 1 {
		return false
	}
	owner := rs.OwnerReferences[0]
	return owner.APIVersion == "apps/v1" && owner.Kind == "Deployment" && owner.Name == dep.Name && owner.UID == dep.UID && owner.Controller != nil && *owner.Controller
}

func natsResponseAwaitConsumers(ctx context.Context, env *core.Env, fixture natsResponseFixture) ([]corev1.Pod, types.UID, error) {
	deadline := time.NewTimer(70 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		pods, rsUID, err := natsResponseConsumerSnapshot(ctx, env, fixture)
		if err == nil {
			return pods, rsUID, nil
		}
		if !errors.Is(err, errNATSResponsePending) {
			return nil, "", err
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-deadline.C:
			return nil, "", errors.New("NATS response consumer readiness timed out")
		case <-ticker.C:
		}
	}
}

func natsResponseAssignSource(ctx context.Context, env *core.Env, fixture *natsResponseFixture, pods []corev1.Pod, rsUID types.UID) error {
	if fixture == nil || len(pods) != 2 || rsUID == "" || pods[0].UID == pods[1].UID ||
		pods[0].Labels[natsResponseRoleLabel] != "" || pods[1].Labels[natsResponseRoleLabel] != "" ||
		pods[0].ResourceVersion == "" || pods[0].UID == "" {
		return errors.New("NATS response source role assignment not uniquely admitted")
	}
	source := pods[0]
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return err
	}
	if err := natsResponsePhase(env, "SOURCE_ROLE_PATCH_INTENT", "pods", source.Name, source.UID); err != nil {
		return err
	}
	patch, err := json.Marshal([]map[string]any{
		{"op": "test", "path": "/metadata/uid", "value": string(source.UID)},
		{"op": "test", "path": "/metadata/resourceVersion", "value": source.ResourceVersion},
		{"op": "add", "path": "/metadata/labels/fixture.phorvex.ai~1role", "value": "source"},
	})
	if err != nil {
		return err
	}
	updated, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Patch(ctx, source.Name, types.JSONPatchType, patch, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("NATS response source role patch uncertain; no retry: %w", err)
	}
	if updated.UID != source.UID || updated.Labels[natsResponseRoleLabel] != "source" {
		return errors.New("NATS response role patch returned different Pod")
	}
	if err := natsResponsePhase(env, "SOURCE_ROLE_PATCHED", "pods", source.Name, source.UID); err != nil {
		return err
	}
	actual, err := env.Kube.CoreV1().Pods(env.Config.Namespace).Get(ctx, source.Name, metav1.GetOptions{})
	if err != nil || actual.UID != source.UID || actual.Labels[natsResponseRoleLabel] != "source" {
		return errors.New("NATS response source role not current")
	}
	client, err := natsResponseReadyPod(actual, rsUID, source.OwnerReferences[0].Name, env.Config.NATSExposureFixture.Nonce,
		env.Config.NATSExposureFixture.NodeName, env.Config.NATSExposureFixture.ObserverImage)
	if err != nil {
		return err
	}
	fixture.Client = client
	fixture.ReplicaSetUID = rsUID
	fixture.Peer, err = natsResponseReadyPod(&pods[1], rsUID, source.OwnerReferences[0].Name, env.Config.NATSExposureFixture.Nonce,
		env.Config.NATSExposureFixture.NodeName, env.Config.NATSExposureFixture.ObserverImage)
	return err
}
