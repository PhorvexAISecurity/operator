package scenarios

import (
	"context"
	"errors"

	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

type natsResponseManagerIdentity struct {
	DeploymentUID types.UID `json:"deploymentUID"`
	ReplicaSetUID types.UID `json:"replicaSetUID"`
	PodName       string    `json:"podName"`
	PodUID        types.UID `json:"podUID"`
	ContainerID   string    `json:"containerID"`
	ImageID       string    `json:"imageID"`
}

// Capture the currently installed manager process by controller ownership and
// image digest. The console callback independently rechecks this incarnation
// before creating the trusted event and while joining its audit decision.
func natsResponseManager(ctx context.Context, env *core.Env) (natsResponseManagerIdentity, error) {
	var id natsResponseManagerIdentity
	f := env.Config.NATSExposureFixture
	if f == nil || f.ManagerNamespace == "" || f.ManagerDeployment == "" || f.ManagerImageID == "" {
		return id, errors.New("NATS response manager source configuration absent")
	}
	dep, err := env.Kube.AppsV1().Deployments(f.ManagerNamespace).Get(ctx, f.ManagerDeployment, metav1.GetOptions{})
	if err != nil || dep.UID == "" || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 ||
		dep.Status.ObservedGeneration < dep.Generation || dep.Status.ReadyReplicas != 1 || dep.Spec.Selector == nil {
		return id, errors.New("NATS response manager Deployment not exact current singleton")
	}
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || selector.Empty() {
		return id, errors.New("NATS response manager Deployment selector unavailable")
	}
	sets, err := env.Kube.AppsV1().ReplicaSets(f.ManagerNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 20})
	if err != nil || sets.Continue != "" || sets.RemainingItemCount != nil {
		return id, errors.New("NATS response manager ReplicaSet owner ambiguous")
	}
	var active *appsv1.ReplicaSet
	for i := range sets.Items {
		rs := &sets.Items[i]
		if rs.Spec.Replicas == nil || *rs.Spec.Replicas == 0 {
			continue // retained, inactive rollout history is not a new manager process
		}
		if active != nil || *rs.Spec.Replicas != 1 || rs.Status.ReadyReplicas != 1 || rs.UID == "" ||
			rs.DeletionTimestamp != nil || len(rs.OwnerReferences) != 1 ||
			rs.OwnerReferences[0].APIVersion != "apps/v1" || rs.OwnerReferences[0].Kind != "Deployment" ||
			rs.OwnerReferences[0].Name != dep.Name || rs.OwnerReferences[0].UID != dep.UID ||
			rs.OwnerReferences[0].Controller == nil || !*rs.OwnerReferences[0].Controller {
			return id, errors.New("NATS response manager active ReplicaSet differs")
		}
		active = rs
	}
	if active == nil {
		return id, errors.New("NATS response manager active ReplicaSet absent")
	}
	rs := *active
	pods, err := env.Kube.CoreV1().Pods(f.ManagerNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 10})
	if err != nil || pods.Continue != "" || pods.RemainingItemCount != nil || len(pods.Items) != 1 {
		return id, errors.New("NATS response manager Pod incarnation ambiguous")
	}
	p := pods.Items[0]
	if p.UID == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning ||
		p.Labels["app.kubernetes.io/component"] != "manager" || len(p.OwnerReferences) != 1 ||
		p.OwnerReferences[0].UID != rs.UID || p.OwnerReferences[0].Kind != "ReplicaSet" ||
		p.OwnerReferences[0].Controller == nil || !*p.OwnerReferences[0].Controller ||
		len(p.Spec.Containers) != 1 || p.Spec.Containers[0].Name != "manager" ||
		len(p.Status.ContainerStatuses) != 1 || p.Status.ContainerStatuses[0].Name != "manager" ||
		p.Status.ContainerStatuses[0].RestartCount != 0 || !p.Status.ContainerStatuses[0].Ready ||
		p.Status.ContainerStatuses[0].ContainerID == "" || p.Status.ContainerStatuses[0].ImageID != f.ManagerImageID {
		return id, errors.New("NATS response manager Pod or image incarnation differs")
	}
	ready := false
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready || !selector.Matches(labels.Set(p.Labels)) {
		return id, errors.New("NATS response manager selector or readiness differs")
	}
	return natsResponseManagerIdentity{DeploymentUID: dep.UID, ReplicaSetUID: rs.UID, PodName: p.Name,
		PodUID: p.UID, ContainerID: p.Status.ContainerStatuses[0].ContainerID, ImageID: p.Status.ContainerStatuses[0].ImageID}, nil
}
