package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"

	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// Mongo exposure is a configuration baseline on one already installed source.
// These identities are refreshed before and after the single synthetic read.
type mongoExposureSource struct {
	NamespaceUID       types.UID `json:"namespaceUID"`
	DeploymentUID      types.UID `json:"deploymentUID"`
	ReplicaSetUID      types.UID `json:"replicaSetUID"`
	PodName            string    `json:"podName"`
	PodUID             types.UID `json:"podUID"`
	PodIP              string    `json:"podIP"`
	NodeName           string    `json:"nodeName"`
	ContainerID        string    `json:"containerID"`
	ImageID            string    `json:"imageID"`
	PVCUID             types.UID `json:"pvcUID"`
	ServiceUID         types.UID `json:"serviceUID"`
	EndpointSliceUID   types.UID `json:"endpointSliceUID"`
	PolicyUID          types.UID `json:"policyUID"`
	PolicyGeneration   int64     `json:"policyGeneration"`
	PolicySpecSHA256   string    `json:"policySpecSHA256"`
	ManagerPodUID      types.UID `json:"managerPodUID"`
	ManagerContainerID string    `json:"managerContainerID"`
	ManagerImageID     string    `json:"managerImageID"`
}

func mongoExposureOwner(refs []metav1.OwnerReference, kind, name string, uid types.UID) bool {
	if len(refs) != 1 {
		return false
	}
	r := refs[0]
	return r.APIVersion == "apps/v1" && r.Kind == kind && r.Name == name && r.UID == uid && r.Controller != nil && *r.Controller
}

func mongoExposureReady(p *corev1.Pod, container, imageID string) bool {
	if p == nil || p.UID == "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || p.Spec.NodeName == "" ||
		len(p.Spec.Containers) != 1 || p.Spec.Containers[0].Name != container || len(p.Status.ContainerStatuses) != 1 {
		return false
	}
	c := p.Status.ContainerStatuses[0]
	if c.Name != container || !c.Ready || c.RestartCount != 0 || c.ContainerID == "" || c.ImageID != imageID {
		return false
	}
	for _, cond := range p.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func mongoExposureSingleton(ctx context.Context, env *core.Env, namespace, deployment, imageID, container string) (*appsv1.Deployment, *appsv1.ReplicaSet, *corev1.Pod, error) {
	dep, err := env.Kube.AppsV1().Deployments(namespace).Get(ctx, deployment, metav1.GetOptions{})
	if err != nil || dep.UID == "" || dep.DeletionTimestamp != nil || dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 ||
		dep.Status.ObservedGeneration < dep.Generation || dep.Status.ReadyReplicas != 1 || dep.Spec.Selector == nil {
		return nil, nil, nil, errors.New("Mongo source Deployment is not one current Ready replica")
	}
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil || selector.Empty() {
		return nil, nil, nil, errors.New("Mongo source selector unavailable")
	}
	sets, err := env.Kube.AppsV1().ReplicaSets(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 20})
	if err != nil || sets.Continue != "" || sets.RemainingItemCount != nil {
		return nil, nil, nil, errors.New("Mongo source ReplicaSet list incomplete")
	}
	var rs *appsv1.ReplicaSet
	for i := range sets.Items {
		candidate := &sets.Items[i]
		if candidate.Spec.Replicas == nil || *candidate.Spec.Replicas == 0 {
			continue
		}
		if rs != nil || candidate.UID == "" || candidate.DeletionTimestamp != nil || *candidate.Spec.Replicas != 1 || candidate.Status.ReadyReplicas != 1 ||
			!mongoExposureOwner(candidate.OwnerReferences, "Deployment", dep.Name, dep.UID) {
			return nil, nil, nil, errors.New("Mongo source active ReplicaSet ambiguous")
		}
		rs = candidate
	}
	if rs == nil {
		return nil, nil, nil, errors.New("Mongo source active ReplicaSet absent")
	}
	pods, err := env.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String(), Limit: 10})
	if err != nil || pods.Continue != "" || pods.RemainingItemCount != nil || len(pods.Items) != 1 {
		return nil, nil, nil, errors.New("Mongo source Pod ambiguous")
	}
	pod := &pods.Items[0]
	if !mongoExposureOwner(pod.OwnerReferences, "ReplicaSet", rs.Name, rs.UID) || !selector.Matches(labels.Set(pod.Labels)) || !mongoExposureReady(pod, container, imageID) {
		return nil, nil, nil, errors.New("Mongo source Pod owner, selector or process differs")
	}
	return dep, rs, pod, nil
}

func captureMongoExposureSource(ctx context.Context, env *core.Env) (mongoExposureSource, error) {
	var source mongoExposureSource
	if env == nil || env.Config.MongoExposureFixture == nil || env.Config.Namespace != "document-store" {
		return source, errors.New("Mongo source fixture unavailable")
	}
	f := env.Config.MongoExposureFixture
	ns, err := env.Kube.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{})
	if err != nil || ns.UID == "" || ns.DeletionTimestamp != nil {
		return source, errors.New("Mongo namespace UID unavailable")
	}
	source.NamespaceUID = ns.UID
	dep, rs, pod, err := mongoExposureSingleton(ctx, env, env.Config.Namespace, f.MongoDeployment, f.MongoImageID, "mongo")
	if err != nil {
		return source, err
	}
	source.DeploymentUID, source.ReplicaSetUID, source.PodName, source.PodUID, source.PodIP, source.NodeName = dep.UID, rs.UID, pod.Name, pod.UID, pod.Status.PodIP, pod.Spec.NodeName
	source.ContainerID, source.ImageID = pod.Status.ContainerStatuses[0].ContainerID, pod.Status.ContainerStatuses[0].ImageID
	source.PVCUID, err = mongoExposurePVC(ctx, env, pod)
	if err != nil {
		return source, err
	}
	svc, err := env.Kube.CoreV1().Services(env.Config.Namespace).Get(ctx, f.MongoService, metav1.GetOptions{})
	if err != nil || svc.UID == "" || svc.DeletionTimestamp != nil || svc.Spec.Type != corev1.ServiceTypeClusterIP || svc.Spec.ClusterIP == "" || svc.Spec.Selector["app"] != "mongo" || len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 27017 {
		return source, errors.New("Mongo Service route differs")
	}
	source.ServiceUID = svc.UID
	slices, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + svc.Name, Limit: 10})
	if err != nil || slices.Continue != "" || slices.RemainingItemCount != nil || len(slices.Items) != 1 {
		return source, errors.New("Mongo EndpointSlice route ambiguous")
	}
	es := slices.Items[0]
	if err := mongoExposureServiceRoute(svc, &es, pod); err != nil {
		return source, err
	}
	source.EndpointSliceUID = es.UID
	policy := &unstructured.Unstructured{}
	policy.SetGroupVersionKind(schema.GroupVersionKind{Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicy"})
	if err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: env.Config.Namespace, Name: f.PolicyName}, policy); err != nil || policy.GetUID() == "" || policy.GetDeletionTimestamp() != nil || policy.GetGeneration() < 1 {
		return source, errors.New("Mongo policy identity unavailable")
	}
	if err := mongoExposurePolicyCurrent(policy); err != nil {
		return source, err
	}
	tenant, _, _ := unstructured.NestedString(policy.Object, "spec", "tenant")
	mode, _, _ := unstructured.NestedString(policy.Object, "spec", "mode")
	selectedApp, _, _ := unstructured.NestedString(policy.Object, "spec", "selector", "matchLabels", "app")
	if err := mongoExposurePolicySelectsPod(policy, pod); err != nil {
		return source, err
	}
	reactiveOnly, _, _ := unstructured.NestedBool(policy.Object, "spec", "triggers", "reactiveOnly")
	minAvailable, _, _ := unstructured.NestedInt64(policy.Object, "spec", "slo", "minAvailableReplicas")
	if tenant != "mongo" || mode != "active" || selectedApp != "mongo" || !reactiveOnly || minAvailable != 1 {
		return source, errors.New("Mongo policy target, mode or reactive trigger differs")
	}
	spec, err := json.Marshal(policy.Object["spec"])
	if err != nil || len(spec) == 0 || string(spec) == "null" {
		return source, errors.New("Mongo policy spec unavailable")
	}
	h := sha256.Sum256(spec)
	source.PolicyUID, source.PolicyGeneration, source.PolicySpecSHA256 = policy.GetUID(), policy.GetGeneration(), hex.EncodeToString(h[:])
	_, _, manager, err := mongoExposureSingleton(ctx, env, f.ManagerNamespace, f.ManagerDeployment, f.ManagerImageID, "manager")
	if err != nil {
		return source, err
	}
	source.ManagerPodUID, source.ManagerContainerID, source.ManagerImageID = manager.UID, manager.Status.ContainerStatuses[0].ContainerID, manager.Status.ContainerStatuses[0].ImageID
	return source, nil
}

func mongoExposurePVC(ctx context.Context, env *core.Env, pod *corev1.Pod) (types.UID, error) {
	if pod == nil || len(pod.Spec.Containers) != 1 {
		return "", errors.New("Mongo PVC Pod shape unavailable")
	}
	volumeName := ""
	for _, volume := range pod.Spec.Volumes {
		if volume.PersistentVolumeClaim == nil {
			continue
		}
		if volumeName != "" || volume.PersistentVolumeClaim.ClaimName != "mongo-data" || volume.PersistentVolumeClaim.ReadOnly {
			return "", errors.New("Mongo mounted PVC source differs")
		}
		volumeName = volume.Name
	}
	if volumeName == "" {
		return "", errors.New("Mongo PVC volume absent")
	}
	mounted := false
	for _, mount := range pod.Spec.Containers[0].VolumeMounts {
		if mount.Name == volumeName && mount.MountPath == "/data/db" && !mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == "" {
			mounted = true
		}
	}
	if !mounted {
		return "", errors.New("Mongo PVC not mounted writable by source container")
	}
	pvc, err := env.Kube.CoreV1().PersistentVolumeClaims(pod.Namespace).Get(ctx, "mongo-data", metav1.GetOptions{})
	if err != nil || pvc.UID == "" || pvc.DeletionTimestamp != nil || pvc.Status.Phase != corev1.ClaimBound || pvc.Spec.VolumeName == "" {
		return "", errors.New("Mongo PVC current bound identity unavailable")
	}
	return pvc.UID, nil
}

func mongoExposurePolicySelectsPod(policy *unstructured.Unstructured, pod *corev1.Pod) error {
	if policy == nil || pod == nil {
		return errors.New("Mongo policy or exact Pod absent")
	}
	selectorRaw, found, err := unstructured.NestedMap(policy.Object, "spec", "selector")
	if err != nil || !found || len(selectorRaw) == 0 {
		return errors.New("Mongo policy selector unavailable")
	}
	var selector metav1.LabelSelector
	raw, err := json.Marshal(selectorRaw)
	if err != nil || json.Unmarshal(raw, &selector) != nil {
		return errors.New("Mongo policy selector invalid")
	}
	compiled, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil || compiled.Empty() || !compiled.Matches(labels.Set(pod.Labels)) {
		return errors.New("Mongo policy does not select exact source Pod")
	}
	return nil
}

func mongoExposurePolicyCurrent(policy *unstructured.Unstructured) error {
	if policy == nil || policy.GetUID() == "" || policy.GetGeneration() < 1 || policy.GetDeletionTimestamp() != nil {
		return errors.New("Mongo policy UID/generation unavailable")
	}
	observed, found, err := unstructured.NestedInt64(policy.Object, "status", "observedGeneration")
	if err != nil || !found || observed < policy.GetGeneration() {
		return errors.New("Mongo policy current generation is not observed")
	}
	return nil
}

func mongoExposureServiceRoute(svc *corev1.Service, es *discoveryv1.EndpointSlice, pod *corev1.Pod) error {
	if svc == nil || es == nil || pod == nil || svc.UID == "" || es.UID == "" || pod.UID == "" || es.DeletionTimestamp != nil ||
		es.Namespace != svc.Namespace || pod.Namespace != svc.Namespace || es.Labels[discoveryv1.LabelServiceName] != svc.Name ||
		len(svc.Spec.Selector) == 0 || !labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(pod.Labels)) ||
		len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 27017 || svc.Spec.Ports[0].Protocol != "" && svc.Spec.Ports[0].Protocol != corev1.ProtocolTCP ||
		len(es.Endpoints) != 1 || len(es.Ports) != 1 || es.Ports[0].Port == nil || *es.Ports[0].Port != 27017 ||
		es.Ports[0].Protocol != nil && *es.Ports[0].Protocol != corev1.ProtocolTCP {
		return errors.New("Mongo Service/EndpointSlice selector, port or identity differs")
	}
	endpointPortName := ""
	if es.Ports[0].Name != nil {
		endpointPortName = *es.Ports[0].Name
	}
	if endpointPortName != svc.Spec.Ports[0].Name {
		return errors.New("Mongo EndpointSlice port name differs from Service")
	}
	targetPort := svc.Spec.Ports[0].TargetPort
	if targetPort.Type == intstr.Int {
		if targetPort.IntVal != 0 && targetPort.IntVal != 27017 {
			return errors.New("Mongo Service target port differs")
		}
	} else {
		matched := false
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if port.Name == targetPort.StrVal && port.ContainerPort == 27017 && (port.Protocol == "" || port.Protocol == corev1.ProtocolTCP) {
					matched = true
				}
			}
		}
		if !matched {
			return errors.New("Mongo named Service target port differs")
		}
	}
	ip := net.ParseIP(pod.Status.PodIP)
	if ip == nil || es.AddressType != discoveryv1.AddressTypeIPv4 && es.AddressType != discoveryv1.AddressTypeIPv6 || es.AddressType == discoveryv1.AddressTypeIPv4 && ip.To4() == nil || es.AddressType == discoveryv1.AddressTypeIPv6 && ip.To4() != nil {
		return errors.New("Mongo EndpointSlice address family differs")
	}
	e := es.Endpoints[0]
	if len(e.Addresses) != 1 || e.Addresses[0] != pod.Status.PodIP || e.TargetRef == nil || e.TargetRef.Kind != "Pod" || e.TargetRef.Namespace != pod.Namespace ||
		e.TargetRef.Name != pod.Name || e.TargetRef.UID != pod.UID || e.Conditions.Ready == nil || !*e.Conditions.Ready ||
		e.Conditions.Terminating != nil && *e.Conditions.Terminating || e.Conditions.Serving != nil && !*e.Conditions.Serving {
		return errors.New("Mongo EndpointSlice member is not the exact usable Pod")
	}
	if len(es.OwnerReferences) != 1 || es.OwnerReferences[0].APIVersion != "v1" || es.OwnerReferences[0].Kind != "Service" || es.OwnerReferences[0].Name != svc.Name || es.OwnerReferences[0].UID != svc.UID || es.OwnerReferences[0].Controller == nil || !*es.OwnerReferences[0].Controller {
		return errors.New("Mongo EndpointSlice Service owner differs")
	}
	return nil
}
