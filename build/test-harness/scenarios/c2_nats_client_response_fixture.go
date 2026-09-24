package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/r6security/phoenix-test-harness/internal/core"
)

const natsResponseScenario = "c2-nats-owned-client-response"
const natsResponseFixtureNamespace = "phorvex-nats-exposure-fixture"
const natsResponseOwnerLabel = "fixture.phorvex.ai/owner-nonce"
const natsResponseRoleLabel = "fixture.phorvex.ai/role"
const natsResponseComponentLabel = "fixture.phorvex.ai/component"

var natsResponsePolicyGVK = schema.GroupVersionKind{Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicy"}

type natsResponsePodIdentity struct {
	Name        string    `json:"name"`
	UID         types.UID `json:"uid"`
	IP          string    `json:"ip"`
	ContainerID string    `json:"containerID"`
	ImageID     string    `json:"imageID"`
}

type natsResponseFixture struct {
	Name             string                  `json:"name"`
	NamespaceUID     types.UID               `json:"namespaceUID"`
	ConfigMapUID     types.UID               `json:"configMapUID"`
	ConfigSHA256     string                  `json:"configSHA256"`
	DeploymentUID    types.UID               `json:"deploymentUID"`
	ReplicaSetUID    types.UID               `json:"replicaSetUID"`
	ServiceUID       types.UID               `json:"serviceUID"`
	PDBUID           types.UID               `json:"pdbUID"`
	PolicyUID        types.UID               `json:"policyUID"`
	PolicyGen        int64                   `json:"policyGeneration"`
	PolicySpecSHA256 string                  `json:"policySpecSHA256"`
	Client           natsResponsePodIdentity `json:"client"`
	Peer             natsResponsePodIdentity `json:"peer"`
}

func natsResponseName(nonce string) string { return "nats-response-" + nonce }

func natsResponseLabels(nonce string) map[string]string {
	return map[string]string{natsResponseOwnerLabel: nonce, core.OwnedLabelKey: core.OwnedLabelValue,
		core.ScenarioLabelKey: natsResponseScenario, core.TrialLabelKey: "0"}
}

func natsResponseSubjects(nonce string) [2]string {
	return [2]string{"cat.response." + nonce + ".m0", "cat.response." + nonce + ".m1"}
}

func natsResponsePayloads(nonce string) [2][]byte {
	return [2][]byte{[]byte("phorvex-owned-nats-response:" + nonce + ":M0"), []byte("phorvex-owned-nats-response:" + nonce + ":M1")}
}

func natsResponseObserverConfig(nonce string, route natsRouteIdentity) ([]byte, error) {
	subjects, payloads := natsResponseSubjects(nonce), natsResponsePayloads(nonce)
	ids := make([]string, 0, len(route.Brokers))
	for _, b := range route.Brokers {
		if b.ServerID == "" {
			return nil, errors.New("broker server ID absent")
		}
		ids = append(ids, b.ServerID)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return nil, errors.New("NATS response route has no serving broker")
	}
	data := map[string]any{"brokerURL": "nats://nats.nats.svc.cluster.local:4222", "nonce": nonce,
		"subjects": subjects, "expectedPayloadSHA256": []string{natsSHA(payloads[0]), natsSHA(payloads[1])},
		"allowedServerIDs": ids, "connectTimeoutMillis": 3000, "flushTimeoutMillis": 3000,
		"m0TimeoutMillis": 120000, "m1TimeoutMillis": 300000}
	raw, err := json.Marshal(data)
	if err != nil || len(raw) > 2048 {
		return nil, errors.New("NATS response observer config oversized")
	}
	return raw, nil
}

func natsResponseConfigMap(env *core.Env, name string, config []byte) *corev1.ConfigMap {
	immutable := true
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace,
		Labels: natsResponseLabels(env.Config.NATSExposureFixture.Nonce)}, Immutable: &immutable,
		Data: map[string]string{"observer.json": string(config)}}
}

func natsResponseDeployment(env *core.Env, name string) *appsv1.Deployment {
	no, yes := false, true
	user, replicas := int64(65532), int32(2)
	selectLabels := map[string]string{natsResponseOwnerLabel: env.Config.NATSExposureFixture.Nonce, natsResponseComponentLabel: "consumer"}
	container := corev1.Container{Name: "observer", Image: env.Config.NATSExposureFixture.ObserverImage,
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"/app/nats-owned-observer", "--response-config", "/config/observer.json"},
		Env: []corev1.EnvVar{
			{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
			{Name: "NATS_RESPONSE_SERVICE", Value: "1"},
		},
		Ports: []corev1.ContainerPort{{Name: "ready", ContainerPort: 8080, Protocol: corev1.ProtocolTCP}},
		ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromString("ready")}},
			PeriodSeconds: 3, TimeoutSeconds: 1},
		SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes,
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}},
		Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("25m"), corev1.ResourceMemory: resource.MustParse("32Mi")},
			Limits: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("64Mi")}},
		VolumeMounts: []corev1.VolumeMount{{Name: "config", MountPath: "/config", ReadOnly: true}},
	}
	templateLabels := natsResponseLabels(env.Config.NATSExposureFixture.Nonce)
	templateLabels[natsResponseComponentLabel] = "consumer"
	template := corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: templateLabels},
		Spec: corev1.PodSpec{NodeName: env.Config.NATSExposureFixture.NodeName, AutomountServiceAccountToken: &no,
			RestartPolicy: corev1.RestartPolicyAlways,
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &user,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			Containers: []corev1.Container{container},
			Volumes: []corev1.Volume{{Name: "config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: name}}}}},
		}}
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace,
		Labels: natsResponseLabels(env.Config.NATSExposureFixture.Nonce)},
		Spec: appsv1.DeploymentSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: selectLabels}, Template: template}}
}

func natsResponseService(env *core.Env, name string) *corev1.Service {
	return &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace,
		Labels: natsResponseLabels(env.Config.NATSExposureFixture.Nonce)},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{natsResponseOwnerLabel: env.Config.NATSExposureFixture.Nonce, natsResponseComponentLabel: "consumer"},
			Ports:    []corev1.ServicePort{{Name: "ready", Port: 8080, TargetPort: intstr.FromString("ready"), Protocol: corev1.ProtocolTCP}}}}
}

func natsResponsePDB(env *core.Env, name string) *policyv1.PodDisruptionBudget {
	return &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace,
		Labels: natsResponseLabels(env.Config.NATSExposureFixture.Nonce)},
		Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: ptrIntstr(intstr.FromInt(1)),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{natsResponseOwnerLabel: env.Config.NATSExposureFixture.Nonce, natsResponseComponentLabel: "consumer"}}}}
}

func ptrIntstr(value intstr.IntOrString) *intstr.IntOrString { return &value }

func natsResponsePolicy(env *core.Env, name string) *unstructured.Unstructured {
	nonce := env.Config.NATSExposureFixture.Nonce
	p := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy",
		"metadata": map[string]any{"name": name, "namespace": env.Config.Namespace,
			"labels": map[string]any{natsResponseOwnerLabel: nonce, core.OwnedLabelKey: core.OwnedLabelValue,
				core.ScenarioLabelKey: natsResponseScenario, core.TrialLabelKey: "0"}},
		"spec": map[string]any{
			"tenant": nonce, "selector": map[string]any{"matchLabels": map[string]any{natsResponseOwnerLabel: nonce, natsResponseRoleLabel: "source"}},
			"mode": "active", "actions": map[string]any{"enabled": []any{"rotate", "quarantine"}},
			"triggers":   map[string]any{"eventDriven": true, "reactiveOnly": true, "eventAgeHorizon": "1h"},
			"budget":     map[string]any{"tickInterval": "5s", "antiOverRotationWindow": "90s", "proactiveFloor": "15m", "maxMovesPerTick": int64(1), "maxGracePeriodSeconds": int64(30)},
			"slo":        map[string]any{"minAvailableReplicas": int64(1), "costCeiling": "1.2"},
			"objective":  map[string]any{"costWeights": map[string]any{"normSparsity": "0.4", "flowDisruption": "0.6"}, "lambda": "0.4"},
			"assetValue": map[string]any{"weightSecrets": "0.8", "blastRadiusFromGraph": false},
		}}}
	p.SetGroupVersionKind(natsResponsePolicyGVK)
	return p
}

// A random nonce is not sufficient evidence that a manager tenant or another
// fixture policy is free. This inventory is complete and checked before create.
func noNATSResponsePolicyCollision(ctx context.Context, env *core.Env) error {
	nonce := env.Config.NATSExposureFixture.Nonce
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{Group: "phorvex.ai", Version: "v1alpha1", Kind: "PhorvexPolicyList"})
	if err := env.Ctrl.List(ctx, list); err != nil || list.GetContinue() != "" || list.GetRemainingItemCount() != nil {
		return errors.New("NATS response policy inventory incomplete")
	}
	proposedSource := labels.Set{natsResponseOwnerLabel: nonce, natsResponseComponentLabel: "consumer", natsResponseRoleLabel: "source"}
	proposedPeer := labels.Set{natsResponseOwnerLabel: nonce, natsResponseComponentLabel: "consumer"}
	for i := range list.Items {
		p := &list.Items[i]
		tenant, _, err := unstructured.NestedString(p.Object, "spec", "tenant")
		if err != nil || tenant == nonce {
			return errors.New("NATS response tenant collides with an existing policy")
		}
		if p.GetNamespace() != env.Config.Namespace || p.GetDeletionTimestamp() != nil {
			continue
		}
		raw, found, err := unstructured.NestedMap(p.Object, "spec", "selector")
		if err != nil || !found {
			return errors.New("existing fixture policy selector unavailable")
		}
		var selector metav1.LabelSelector
		if err := decodeNATSResponseSelector(raw, &selector); err != nil {
			return err
		}
		compiled, err := metav1.LabelSelectorAsSelector(&selector)
		if err != nil || compiled.Matches(proposedSource) || compiled.Matches(proposedPeer) {
			return errors.New("existing policy could select a response consumer")
		}
	}
	return nil
}

func decodeNATSResponseSelector(raw map[string]any, out *metav1.LabelSelector) error {
	data, err := json.Marshal(raw)
	if err != nil || json.Unmarshal(data, out) != nil || reflect.DeepEqual(*out, metav1.LabelSelector{}) {
		return errors.New("existing policy selector cannot be verified")
	}
	return nil
}

func natsResponseCurrentPolicy(ctx context.Context, env *core.Env, name string, uid types.UID, generation int64, expected map[string]any) error {
	p := &unstructured.Unstructured{}
	p.SetGroupVersionKind(natsResponsePolicyGVK)
	if err := env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: env.Config.Namespace, Name: name}, p); err != nil || p.GetUID() != uid || p.GetGeneration() != generation || p.GetDeletionTimestamp() != nil {
		return errors.New("owned NATS response policy identity changed")
	}
	spec, found, err := unstructured.NestedMap(p.Object, "spec")
	if err != nil || !found || !reflect.DeepEqual(spec, expected) {
		return errors.New("owned NATS response policy spec changed")
	}
	return nil
}

// The apiserver may add CRD defaults on CREATE. The create response is the
// security baseline only after every requested value survived admission. Its
// full admitted spec is then compared verbatim on every later recheck.
func natsResponseAdmittedPolicySpec(requested, admitted *unstructured.Unstructured) (map[string]any, error) {
	if requested == nil || admitted == nil || admitted.GetUID() == "" || admitted.GetGeneration() < 1 ||
		admitted.GetNamespace() != requested.GetNamespace() || admitted.GetName() != requested.GetName() ||
		admitted.GetDeletionTimestamp() != nil || admitted.GroupVersionKind() != natsResponsePolicyGVK ||
		!reflect.DeepEqual(admitted.GetLabels(), requested.GetLabels()) {
		return nil, errors.New("NATS response policy create identity differs")
	}
	wanted, found, err := unstructured.NestedMap(requested.Object, "spec")
	if err != nil || !found {
		return nil, errors.New("NATS response requested policy spec absent")
	}
	got, found, err := unstructured.NestedMap(admitted.Object, "spec")
	if err != nil || !found || !natsResponseSpecContains(got, wanted) {
		return nil, errors.New("NATS response requested policy contract changed at admission")
	}
	return got, nil
}

func natsResponseSpecContains(got, wanted map[string]any) bool {
	for key, expect := range wanted {
		actual, ok := got[key]
		if !ok {
			return false
		}
		if child, ok := expect.(map[string]any); ok {
			actualChild, ok := actual.(map[string]any)
			if !ok || !natsResponseSpecContains(actualChild, child) {
				return false
			}
			continue
		}
		if !reflect.DeepEqual(actual, expect) {
			return false
		}
	}
	return true
}

func natsResponseWait(ctx context.Context, timeout time.Duration, predicate func(context.Context) error) error {
	limit := time.NewTimer(timeout)
	defer limit.Stop()
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := predicate(ctx); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-limit.C:
			return fmt.Errorf("NATS response fixture readiness not proven within %s", timeout)
		case <-tick.C:
		}
	}
}

// Only the two original ReplicaSet-owned, ready, first-incarnation observers
// can enter the M0/M1 case. Replacement Pods and restarted containers remain
// visible as cleanup debt, never substitute evidence for these identities.
func natsResponseReadyPod(p *corev1.Pod, rsUID types.UID, name, nonce, node, image string) (natsResponsePodIdentity, error) {
	var id natsResponsePodIdentity
	if p == nil || p.Namespace == "" || p.Name == "" || p.UID == "" || p.DeletionTimestamp != nil ||
		p.Status.Phase != corev1.PodRunning || p.Status.PodIP == "" || p.Spec.NodeName != node ||
		p.Labels[natsResponseOwnerLabel] != nonce || p.Labels[natsResponseComponentLabel] != "consumer" ||
		p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
		return id, errors.New("NATS response consumer Pod identity or ready state differs")
	}
	ownerCount := 0
	for _, ref := range p.OwnerReferences {
		if ref.Controller != nil && *ref.Controller && ref.APIVersion == "apps/v1" && ref.Kind == "ReplicaSet" &&
			ref.Name == name && ref.UID == rsUID {
			ownerCount++
		}
	}
	if ownerCount != 1 || len(p.OwnerReferences) != 1 || len(p.Spec.Containers) != 1 || len(p.Status.ContainerStatuses) != 1 ||
		len(p.Spec.Volumes) != 1 || p.Spec.Volumes[0].ConfigMap == nil || p.Spec.Volumes[0].ConfigMap.Name != natsResponseName(nonce) {
		return id, errors.New("NATS response consumer owner or source configuration differs")
	}
	container, status := p.Spec.Containers[0], p.Status.ContainerStatuses[0]
	if container.Name != "observer" || container.Image != image || len(container.Command) != 3 ||
		container.Command[0] != "/app/nats-owned-observer" || container.Command[1] != "--response-config" ||
		container.Command[2] != "/config/observer.json" || len(container.Args) != 0 ||
		len(container.VolumeMounts) != 1 || container.VolumeMounts[0].Name != "config" ||
		container.VolumeMounts[0].MountPath != "/config" || !container.VolumeMounts[0].ReadOnly ||
		container.VolumeMounts[0].SubPath != "" || container.VolumeMounts[0].SubPathExpr != "" ||
		len(container.Env) != 2 || container.Env[0].Name != "POD_UID" || container.Env[0].ValueFrom == nil ||
		container.Env[0].ValueFrom.FieldRef == nil || container.Env[0].ValueFrom.FieldRef.FieldPath != "metadata.uid" ||
		container.Env[1].Name != "NATS_RESPONSE_SERVICE" || container.Env[1].Value != "1" ||
		status.Name != "observer" || status.RestartCount != 0 || status.ContainerID == "" ||
		!sameImageDigest(status.ImageID, image) {
		return id, errors.New("NATS response observer process or first container incarnation differs")
	}
	ready := false
	for _, condition := range p.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			ready = true
		}
	}
	if !ready || !status.Ready {
		return id, errors.New("NATS response consumer not API Ready")
	}
	return natsResponsePodIdentity{Name: p.Name, UID: p.UID, IP: p.Status.PodIP,
		ContainerID: status.ContainerID, ImageID: status.ImageID}, nil
}

// EndpointSlice membership is an API-backed service control, not a claim that
// every packet actually traversed kube-proxy. Later HTTP checks separately
// exercise the real Service address and exact peer response identity.
func natsResponseEndpointMembers(slices []discoveryv1.EndpointSlice, serviceName string, serviceUID types.UID, client, peer natsResponsePodIdentity) error {
	return natsResponseEndpointMembersForPhase(slices, serviceName, serviceUID, client, peer, true)
}

func natsResponseEndpointMembersAfter(slices []discoveryv1.EndpointSlice, serviceName string, serviceUID types.UID, client, peer natsResponsePodIdentity) error {
	return natsResponseEndpointMembersForPhase(slices, serviceName, serviceUID, client, peer, false)
}

func natsResponseEndpointMembersForPhase(slices []discoveryv1.EndpointSlice, serviceName string, serviceUID types.UID, client, peer natsResponsePodIdentity, requireClient bool) error {
	if serviceName == "" || serviceUID == "" || client.UID == "" || peer.UID == "" || client.UID == peer.UID || len(slices) != 1 {
		return errors.New("NATS response EndpointSlice authority incomplete")
	}
	expected := map[types.UID]natsResponsePodIdentity{client.UID: client, peer.UID: peer}
	seen := map[types.UID]bool{}
	for _, slice := range slices {
		if slice.UID == "" || slice.DeletionTimestamp != nil || slice.Labels[discoveryv1.LabelServiceName] != serviceName ||
			slice.AddressType != discoveryv1.AddressTypeIPv4 || len(slice.Ports) != 1 || len(slice.OwnerReferences) != 1 {
			return errors.New("NATS response EndpointSlice identity differs")
		}
		owner := slice.OwnerReferences[0]
		if owner.APIVersion != "v1" || owner.Kind != "Service" || owner.Name != serviceName || owner.UID != serviceUID ||
			owner.Controller == nil || !*owner.Controller {
			return errors.New("NATS response EndpointSlice Service owner differs")
		}
		port := slice.Ports[0]
		if port.Name == nil || *port.Name != "ready" || port.Port == nil || *port.Port != 8080 ||
			port.Protocol == nil || *port.Protocol != corev1.ProtocolTCP {
			return errors.New("NATS response EndpointSlice health port differs")
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Namespace != slice.Namespace ||
				endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready ||
				endpoint.Conditions.Serving == nil || !*endpoint.Conditions.Serving ||
				endpoint.Conditions.Terminating == nil || *endpoint.Conditions.Terminating ||
				len(endpoint.Addresses) != 1 {
				return errors.New("NATS response EndpointSlice member not an exact Ready Pod")
			}
			pod, ok := expected[endpoint.TargetRef.UID]
			if !ok || pod.IP != endpoint.Addresses[0] || pod.Name != endpoint.TargetRef.Name || seen[endpoint.TargetRef.UID] {
				return errors.New("NATS response EndpointSlice member replaced, extra or duplicate")
			}
			seen[endpoint.TargetRef.UID] = true
		}
	}
	if !seen[peer.UID] || requireClient && !seen[client.UID] {
		return errors.New("NATS response Service lacks required original consumer endpoints")
	}
	return nil
}
