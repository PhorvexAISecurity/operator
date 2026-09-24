package scenarios

import (
	"context"
	"errors"
	"fmt"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type mongoExposureNode struct {
	Name string    `json:"name"`
	UID  types.UID `json:"uid"`
}

func mongoExposureNodeReady(node *corev1.Node) bool {
	if node == nil || node.UID == "" || node.Spec.Unschedulable || len(node.Spec.Taints) != 0 {
		return false
	}
	ready := false
	for _, c := range node.Status.Conditions {
		if c.Type == corev1.NodeReady {
			ready = c.Status == corev1.ConditionTrue
		}
	}
	return ready && node.Status.Allocatable.Cpu().MilliValue() > 0 && node.Status.Allocatable.Memory().Value() > 0 && node.Status.Allocatable.Pods().Value() > 0
}

// This is a metadata lower bound, not proof of a free AWS CNI IP. A scheduling
// failure remains UNKNOWN and incurs only exact-UID Pod cleanup.
func mongoExposureChooseNode(ctx context.Context, env *core.Env) (mongoExposureNode, error) {
	var chosen mongoExposureNode
	if env == nil || env.Config.MongoExposureFixture == nil {
		return chosen, errors.New("Mongo node authority absent")
	}
	nodes, err := env.Kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 32})
	if err != nil || nodes.Continue != "" || nodes.RemainingItemCount != nil || len(nodes.Items) > 32 {
		return chosen, errors.New("Mongo bounded Node inventory incomplete")
	}
	byName := map[string]*corev1.Node{}
	for i := range nodes.Items {
		byName[nodes.Items[i].Name] = &nodes.Items[i]
	}
	for _, name := range env.Config.MongoExposureFixture.AllowedNodeNames {
		node := byName[name]
		if !mongoExposureNodeReady(node) {
			continue
		}
		pods, err := env.Kube.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=" + name, Limit: 200})
		if err != nil || pods.Continue != "" || pods.RemainingItemCount != nil || len(pods.Items) > 200 {
			return chosen, fmt.Errorf("Mongo assigned Pod-resource inventory incomplete on %s", name)
		}
		cpu, memory, podCount := int64(0), int64(0), int64(0)
		for i := range pods.Items {
			p := &pods.Items[i]
			if p.Spec.NodeName != name || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
				continue
			}
			podCount++
			// Sum both ordinary and init requests: overestimation avoids a false
			// headroom assertion while this one small client is admitted.
			for _, c := range append(append([]corev1.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
				cpu += c.Resources.Requests.Cpu().MilliValue()
				memory += c.Resources.Requests.Memory().Value()
			}
			cpu += p.Spec.Overhead.Cpu().MilliValue()
			memory += p.Spec.Overhead.Memory().Value()
		}
		if node.Status.Allocatable.Cpu().MilliValue()-cpu < 50 || node.Status.Allocatable.Memory().Value()-memory < 128<<20 || node.Status.Allocatable.Pods().Value()-podCount < 1 {
			continue
		}
		return mongoExposureNode{Name: name, UID: node.UID}, nil
	}
	return chosen, errors.New("Mongo no currently Ready untainted allowed CPU node has 50m/128Mi and a Pod slot")
}

func mongoExposureRequireNode(ctx context.Context, env *core.Env, pod *corev1.Pod, pin mongoExposureNode) error {
	if pod == nil || pin.Name == "" || pin.UID == "" || pod.Spec.NodeName != pin.Name {
		return errors.New("Mongo client scheduled node/IP does not match admitted placement")
	}
	node, err := env.Kube.CoreV1().Nodes().Get(ctx, pin.Name, metav1.GetOptions{})
	if err != nil || node.UID != pin.UID || !mongoExposureNodeReady(node) {
		return errors.New("Mongo client node UID/readiness changed")
	}
	return nil
}
