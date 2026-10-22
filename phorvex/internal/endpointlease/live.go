package endpointlease

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"

	"github.com/phorvex/phorvex/internal/eventtrust"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Pod is one current Ready public Service backend, identified by API UID and
// exact Pod IP. Status readback uses only these addresses, never event URLs.
type Pod struct{ Name, UID, IP, ProxyImageID, ProxyContainerID string }

type Live struct {
	State         State
	StateSHA256   string
	ServiceUID    string
	PolicyUID     string
	PolicyRV      string
	SecretUID     string
	SeedSHA256    string
	SourceSHA256  string
	SourceUID     string
	DeploymentUID string
	Pods          []Pod
}

var sourceFiles = []string{"guardrail_proxy.py", "dual_server.py", "endpoint_lease.py", "drain_v11.py", "drain_v11_init.py"}

// ValidateLive re-reads the exact public route, durable state, immutable source,
// and every Ready proxy incarnation. It intentionally never reads a Secret:
// only the authenticated proxy can attest Secret UID and seed from its own
// named API read and mounted bytes.
func ValidateLive(ctx context.Context, reader client.Reader, targetUID, approvedSourceSHA256, approvedProxyImage, approvedEngineImage string) (Live, error) {
	var out Live
	if reader == nil || !ValidUID(targetUID) || !ValidSHA(approvedSourceSHA256) || !validApprovedImage(approvedProxyImage) || !validApprovedImage(approvedEngineImage) {
		return out, errors.New("endpoint lease trusted source or target authority unavailable")
	}
	svc := &corev1.Service{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: ServiceName}, svc); err != nil {
		return out, err
	}
	if svc.DeletionTimestamp != nil || !ValidUID(string(svc.UID)) || len(svc.Spec.Selector) == 0 ||
		len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Protocol != corev1.ProtocolTCP || svc.Spec.Ports[0].Port != 8000 ||
		svc.Spec.Ports[0].TargetPort.Type != intstr.Int || svc.Spec.Ports[0].TargetPort.IntVal != 8000 {
		return out, errors.New("endpoint lease public Service authority differs")
	}
	policy := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: PolicyConfigMapName}, policy); err != nil {
		return out, err
	}
	if policy.DeletionTimestamp != nil || !ValidUID(string(policy.UID)) || policy.ResourceVersion == "" ||
		len(policy.Data) != 1 || len(policy.BinaryData) != 0 {
		return out, errors.New("endpoint lease durable policy object invalid")
	}
	state, err := ParseState(policy.Data[PolicyKey])
	if err != nil {
		return out, err
	}
	if state.ServiceUID != string(svc.UID) || state.ProxySourceSHA256 != approvedSourceSHA256 {
		return out, errors.New("endpoint lease durable policy source or Service changed")
	}
	source := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: SourceConfigMapName}, source); err != nil {
		return out, err
	}
	if source.DeletionTimestamp != nil || source.Immutable == nil || !*source.Immutable || !ValidUID(string(source.UID)) ||
		len(source.Data) != len(sourceFiles) || len(source.BinaryData) != 0 {
		return out, errors.New("endpoint lease immutable source object invalid")
	}
	parts := make([][]byte, len(sourceFiles))
	for i, name := range sourceFiles {
		value, exists := source.Data[name]
		if !exists || value == "" || len(value) > 256<<10 {
			return out, errors.New("endpoint lease source file absent or unbounded")
		}
		parts[i] = []byte(value)
	}
	actualSource := SourceSHA256(parts[0], parts[1], parts[2], parts[3], parts[4])
	if actualSource != approvedSourceSHA256 {
		return out, errors.New("endpoint lease executable source differs from reviewed digest")
	}
	dep := &appsv1.Deployment{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: ServiceName}, dep); err != nil {
		return out, err
	}
	if dep.DeletionTimestamp != nil || !ValidUID(string(dep.UID)) ||
		!proxySpecMatches(dep.Spec.Template.Spec, dep.Spec.Template.Annotations, approvedProxyImage, approvedEngineImage, approvedSourceSHA256, string(policy.UID), state) {
		return out, errors.New("endpoint lease Deployment template source/Secret/image gate differs")
	}
	list := &corev1.PodList{}
	if err := reader.List(ctx, list, client.InNamespace(Namespace), client.Limit(129)); err != nil {
		return out, err
	}
	if list.Continue != "" || len(list.Items) > 128 {
		return out, errors.New("endpoint lease Pod inventory incomplete")
	}
	podsByUID := map[string]*corev1.Pod{}
	for i := range list.Items {
		p := &list.Items[i]
		if p.UID != "" {
			if podsByUID[string(p.UID)] != nil {
				return out, errors.New("endpoint lease duplicate Pod UID")
			}
			podsByUID[string(p.UID)] = p
		}
	}
	slices := &discoveryv1.EndpointSliceList{}
	if err := reader.List(ctx, slices, client.InNamespace(Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: ServiceName}, client.Limit(129)); err != nil {
		return out, err
	}
	if slices.Continue != "" || len(slices.Items) == 0 || len(slices.Items) > 128 {
		return out, errors.New("endpoint lease EndpointSlice inventory incomplete")
	}
	readyUIDs := map[string]bool{}
	for i := range slices.Items {
		slice := &slices.Items[i]
		owner := metav1.GetControllerOf(slice)
		if slice.DeletionTimestamp != nil || owner == nil || owner.Kind != "Service" || owner.APIVersion != "v1" || owner.UID != svc.UID ||
			len(slice.Ports) != 1 || slice.Ports[0].Port == nil || *slice.Ports[0].Port != 8000 ||
			slice.Ports[0].Protocol == nil || *slice.Ports[0].Protocol != corev1.ProtocolTCP {
			return out, errors.New("endpoint lease EndpointSlice source/port differs")
		}
		for _, ep := range slice.Endpoints {
			if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
				continue
			}
			if ep.Conditions.Terminating != nil && *ep.Conditions.Terminating || ep.Conditions.Serving != nil && !*ep.Conditions.Serving {
				return out, errors.New("endpoint lease Ready endpoint is terminating or not serving")
			}
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" || (ep.TargetRef.Namespace != "" && ep.TargetRef.Namespace != Namespace) || !ValidUID(string(ep.TargetRef.UID)) ||
				readyUIDs[string(ep.TargetRef.UID)] || len(ep.Addresses) != 1 {
				return out, errors.New("endpoint lease Ready endpoint identity ambiguous")
			}
			p := podsByUID[string(ep.TargetRef.UID)]
			if p == nil || p.Name != ep.TargetRef.Name || p.Status.PodIP != ep.Addresses[0] || p.DeletionTimestamp != nil || !podReady(p) || !selectorMatches(svc.Spec.Selector, p.Labels) {
				return out, errors.New("endpoint lease Ready endpoint Pod/source differs")
			}
			if _, err := netip.ParseAddr(p.Status.PodIP); err != nil {
				return out, errors.New("endpoint lease Ready Pod IP invalid")
			}
			if !ownedByDeployment(ctx, reader, p, dep) || !proxySpecMatches(p.Spec, p.Annotations, approvedProxyImage, approvedEngineImage, approvedSourceSHA256, string(policy.UID), state) {
				return out, errors.New("endpoint lease Ready Pod owner or source gate differs")
			}
			imageID := ""
			for _, status := range p.Status.ContainerStatuses {
				if status.Name == ProxyContainerName && status.Ready && status.ContainerID != "" && imageIDMatches(approvedProxyImage, status.ImageID) {
					imageID = status.ImageID
				}
			}
			if imageID == "" {
				return out, errors.New("endpoint lease Ready proxy imageID unavailable or unreviewed")
			}
			engineReady := false
			for _, status := range p.Status.ContainerStatuses {
				if status.Name == "vllm" && status.Ready && status.ContainerID != "" && imageIDMatches(approvedEngineImage, status.ImageID) {
					engineReady = true
				}
			}
			if !engineReady {
				return out, errors.New("endpoint lease engine runtime image or readiness unverified")
			}
			readyUIDs[string(p.UID)] = true
			containerID := ""
			for _, status := range p.Status.ContainerStatuses {
				if status.Name == ProxyContainerName {
					containerID = status.ContainerID
				}
			}
			out.Pods = append(out.Pods, Pod{Name: p.Name, UID: string(p.UID), IP: p.Status.PodIP, ProxyImageID: imageID, ProxyContainerID: containerID})
		}
	}
	// A still-running Deployment sibling may retain an A request admitted while
	// it was a Ready backend, even after becoming NotReady or leaving the slice.
	// Do not start a cutover from a current Ready set that omits that process.
	for i := range list.Items {
		pod := &list.Items[i]
		if readyUIDs[string(pod.UID)] || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			continue
		}
		possiblyLease := selectorMatches(svc.Spec.Selector, pod.Labels) || pod.Annotations[SourceConfigMapAnnotation] == SourceConfigMapName
		if owner := metav1.GetControllerOf(pod); owner != nil && owner.Kind == "ReplicaSet" && strings.HasPrefix(owner.Name, ServiceName+"-") {
			possiblyLease = true
		}
		if !possiblyLease {
			continue
		}
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == ProxyContainerName && status.ContainerID != "" {
				return Live{}, errors.New("endpoint lease non-Ready possible proxy may retain an admitted old request")
			}
		}
	}
	if len(out.Pods) == 0 || len(out.Pods) > 16 || !readyUIDs[targetUID] {
		return Live{}, errors.New("endpoint lease selected target absent from bounded Ready Service set")
	}
	sort.Slice(out.Pods, func(i, j int) bool { return out.Pods[i].UID < out.Pods[j].UID })
	out.State = state
	out.StateSHA256 = SHA256([]byte(policy.Data[PolicyKey]))
	out.ServiceUID = string(svc.UID)
	out.PolicyUID = string(policy.UID)
	out.PolicyRV = policy.ResourceVersion
	out.SecretUID = state.SecretUID
	out.SeedSHA256 = state.SeedSHA256
	out.SourceSHA256 = actualSource
	out.SourceUID = string(source.UID)
	out.DeploymentUID = string(dep.UID)
	return out, nil
}

func selectorMatches(selector, labels map[string]string) bool {
	for k, v := range selector {
		actual, ok := labels[k]
		if !ok || actual != v {
			return false
		}
	}
	return true
}
func podReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
func ownedByDeployment(ctx context.Context, r client.Reader, p *corev1.Pod, d *appsv1.Deployment) bool {
	owner := metav1.GetControllerOf(p)
	if owner == nil || owner.Kind != "ReplicaSet" || owner.APIVersion != "apps/v1" {
		return false
	}
	rs := &appsv1.ReplicaSet{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: owner.Name}, rs); err != nil || rs.UID != owner.UID {
		return false
	}
	parent := metav1.GetControllerOf(rs)
	return parent != nil && parent.Kind == "Deployment" && parent.APIVersion == "apps/v1" && parent.UID == d.UID
}

func proxySpecMatches(spec corev1.PodSpec, annotations map[string]string, image, engineImage, sourceSHA, policyUID string, state State) bool {
	if annotations[SourceConfigMapAnnotation] != SourceConfigMapName || annotations[SourceSHAAnnotation] != sourceSHA || annotations[PolicyUIDAnnotation] != policyUID {
		return false
	}
	if annotations[EventCreatorAnnotation] != eventtrust.Injector() {
		return false
	}
	var sourceVolume, secretVolume string
	for _, v := range spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == SourceConfigMapName && (v.ConfigMap.Optional != nil && *v.ConfigMap.Optional || len(v.ConfigMap.Items) != 0) {
			return false
		}
		if v.ConfigMap != nil && v.ConfigMap.Name == SourceConfigMapName {
			if sourceVolume != "" {
				return false
			}
			sourceVolume = v.Name
		}
		if v.Secret != nil && v.Secret.SecretName == SecretName {
			if v.Secret.Optional != nil && *v.Secret.Optional || !secretItemsExact(v.Secret.Items) || secretVolume != "" {
				return false
			}
			secretVolume = v.Name
		}
	}
	if sourceVolume == "" || secretVolume == "" {
		return false
	}
	if len(spec.Containers) != 2 {
		return false
	}
	engineSeen, proxySeen := false, false
	for _, c := range spec.Containers {
		if c.Name == "vllm" {
			if engineSeen || !engineSpecMatches(c, engineImage) {
				return false
			}
			engineSeen = true
			continue
		}
		if c.Name != ProxyContainerName || proxySeen {
			return false
		}
		proxySeen = true
		if c.Image != image || len(c.Command) != 3 || c.Command[0] != "python3" || c.Command[1] != "-B" || c.Command[2] != "/src/dual_server.py" || len(c.Args) != 0 {
			return false
		}
		env := map[string]corev1.EnvVar{}
		for _, entry := range c.Env {
			if _, exists := env[entry.Name]; exists {
				return false
			}
			env[entry.Name] = entry
		}
		want := map[string]string{"PHORVEX_ENDPOINT_LEASE_REQUIRED": "true", "PHORVEX_ENDPOINT_LEASE_SECRET_DIR": "/etc/phorvex/endpoint-lease-keys",
			"PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID": policyUID, "PHORVEX_ENDPOINT_LEASE_SECRET_UID": state.SecretUID,
			"PHORVEX_ENDPOINT_LEASE_SERVICE_UID": state.ServiceUID, "PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256": sourceSHA}
		for k, v := range want {
			if env[k].Value != v || env[k].ValueFrom != nil {
				return false
			}
		}
		for _, k := range []string{"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"} {
			if _, ok := env[k]; ok {
				return false
			}
		}
		if env["POD_UID"].ValueFrom == nil || env["POD_UID"].ValueFrom.FieldRef == nil || env["POD_UID"].ValueFrom.FieldRef.FieldPath != "metadata.uid" {
			return false
		}
		mounted := map[string]int{}
		secretCount := 0
		for _, m := range c.VolumeMounts {
			if m.Name == sourceVolume {
				if !m.ReadOnly {
					return false
				}
				known := false
				for _, file := range sourceFiles {
					if m.MountPath == "/src/"+file && m.SubPath == file {
						mounted[file]++
						known = true
						break
					}
				}
				if !known {
					return false
				}
			}
			if m.Name == secretVolume && m.MountPath == "/etc/phorvex/endpoint-lease-keys" && m.ReadOnly && m.SubPath == "" {
				secretCount++
			}
			if m.MountPath == "/src" || strings.HasPrefix(m.MountPath, "/src/") && m.Name != sourceVolume {
				return false
			}
		}
		if secretCount != 1 || len(mounted) != len(sourceFiles) {
			return false
		}
		for _, file := range sourceFiles {
			if mounted[file] != 1 {
				return false
			}
		}
	}
	return engineSeen && proxySeen
}

// secretItemsExact accepts the whole Secret, or an explicit projection of exactly
// the proxy's three keys onto their own names. Either yields the same mounted
// files; a rename, omission, extra key, or per-file mode is not the reviewed shape.
func secretItemsExact(items []corev1.KeyToPath) bool {
	if len(items) == 0 {
		return true
	}
	want := map[string]bool{"client-a": true, "client-b": true, "seed": true}
	if len(items) != len(want) {
		return false
	}
	for _, item := range items {
		if !want[item.Key] || item.Path != item.Key || item.Mode != nil {
			return false
		}
		delete(want, item.Key)
	}
	return len(want) == 0
}

func engineSpecMatches(c corev1.Container, image string) bool {
	if c.Image != image || len(c.Command) != 0 {
		return false
	}
	host, port := 0, 0
	for i := 0; i < len(c.Args); i++ {
		switch c.Args[i] {
		case "--host":
			if i+1 >= len(c.Args) || c.Args[i+1] != "127.0.0.1" {
				return false
			}
			host++
			i++
		case "--port":
			if i+1 >= len(c.Args) || c.Args[i+1] != "8001" {
				return false
			}
			port++
			i++
		default:
			if strings.HasPrefix(c.Args[i], "--host=") || strings.HasPrefix(c.Args[i], "--port=") {
				return false
			}
		}
	}
	if host != 1 || port != 1 {
		return false
	}
	keyCount := 0
	for _, e := range c.Env {
		if e.Name != "VLLM_API_KEY" {
			continue
		}
		keyCount++
		if e.Value != "" || e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil || e.ValueFrom.SecretKeyRef.Name != "vllm-control" ||
			e.ValueFrom.SecretKeyRef.Key != "api-key" || e.ValueFrom.SecretKeyRef.Optional != nil && *e.ValueFrom.SecretKeyRef.Optional {
			return false
		}
	}
	return keyCount == 1
}

func validApprovedImage(image string) bool {
	i := strings.LastIndex(image, "@sha256:")
	return i > 0 && len(image) <= 253 && ValidSHA(image[i+8:]) && strings.IndexAny(image[:i], " \r\n\t@") < 0
}
func imageIDMatches(image, imageID string) bool {
	if !validApprovedImage(image) {
		return false
	}
	digest := image[strings.LastIndex(image, "@sha256:")+1:]
	for _, prefix := range []string{"docker-pullable://", "docker://", "containerd://"} {
		imageID = strings.TrimPrefix(imageID, prefix)
	}
	return imageID == image || imageID == digest
}
