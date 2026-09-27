package voicemcppolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	MCPNamespace            = "mcp"
	MCPServiceName          = "mcp-server"
	InstalledMCPURL         = "http://mcp-server.mcp.svc.cluster.local:8000/mcp/"
	MCPSourceAnnotation     = "phorvex.ai/voice-mcp-source-configmap"
	ReviewedMCPSourceSHA256 = "85cbd0f201b9b65e3b7cc770aed28884fc9835130cc61154499b873537883252"
)

type SourcePins struct {
	DeploymentUID string
	PodUID        string
	ServiceUID    string
	ConfigMapUID  string
	SourceSHA256  string
	ApprovedImage string // operator-configured reviewed repo@sha256, never supplied by the event
}

var approvedImagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}$`)

func ValidApprovedImage(image string) bool {
	return len(image) <= 253 && approvedImagePattern.MatchString(image)
}

type Source struct {
	Pins          SourcePins
	PodName       string
	ConfigMapName string
	PodIP         string
}

// RuntimeSourceSHA binds the MCP behavioral files in the four-file immutable
// Voice source bundle. The output file is admitted but has its own digest.
func RuntimeSourceSHA(cm *corev1.ConfigMap) (string, error) {
	if cm == nil || cm.Immutable == nil || !*cm.Immutable || cm.DeletionTimestamp != nil || len(cm.Data) != 4 || len(cm.BinaryData) != 0 || cm.Data["voice_output_policy.py"] == "" {
		return "", fmt.Errorf("voice MCP runtime source ConfigMap invalid")
	}
	h := sha256.New()
	for i, name := range []string{"bot.py", "voice_memory_policy.py", "voice_mcp_policy.py"} {
		value, ok := cm.Data[name]
		if !ok || value == "" {
			return "", fmt.Errorf("voice MCP runtime source file missing")
		}
		if i != 0 {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// BundleSourceSHA names the shared immutable source object by every projected
// file, so an unrelated Voice policy module cannot drift under the same name.
func BundleSourceSHA(cm *corev1.ConfigMap) (string, error) {
	if _, err := RuntimeSourceSHA(cm); err != nil {
		return "", err
	}
	h := sha256.New()
	for i, name := range []string{"bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py"} {
		if i != 0 {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(cm.Data[name]))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sourceMount(spec corev1.PodSpec, name string) bool {
	var volumeName string
	var testTokenVolume string
	for _, volume := range spec.Volumes {
		if volume.ConfigMap != nil && volume.ConfigMap.Name == name && (volume.ConfigMap.Optional == nil || !*volume.ConfigMap.Optional) {
			if volumeName != "" {
				return false
			}
			volumeName = volume.Name
		}
		if volume.Secret != nil && volume.Secret.SecretName == "voice-mcp-test-token" {
			if testTokenVolume != "" {
				return false
			}
			testTokenVolume = volume.Name
		}
	}
	if volumeName == "" || testTokenVolume == "" {
		return false
	}
	for _, container := range spec.Containers {
		if container.Name != "mcp-server" {
			continue
		}
		if container.WorkingDir != "/app" || len(container.Command) != 3 || container.Command[0] != "python3" ||
			container.Command[1] != "-B" || container.Command[2] != "/app/server.py" || len(container.Args) != 0 {
			return false
		}
		count := 0
		tokenCount := 0
		for _, mount := range container.VolumeMounts {
			if mount.Name == volumeName && mount.MountPath == "/app/server.py" && mount.ReadOnly && mount.SubPath == "server.py" {
				count++
			}
			if mount.Name == testTokenVolume && mount.MountPath == "/etc/phorvex/voice-mcp-test-token" && mount.ReadOnly && mount.SubPath == "" {
				tokenCount++
			}
		}
		return count == 1 && tokenCount == 1
	}
	return false
}

func servingReady(pod *corev1.Pod) bool {
	if pod == nil || pod.DeletionTimestamp != nil || pod.Status.PodIP == "" {
		return false
	}
	if _, err := netip.ParseAddr(pod.Status.PodIP); err != nil {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// CurrentSource revalidates a fixed installed MCP Service and its sole Ready
// endpoint. Event data may supply identities to compare but never object names,
// endpoint addresses, or replacement descriptor bytes.
func CurrentSource(ctx context.Context, reader client.Reader, want SourcePins) (Source, error) {
	if !ValidApprovedImage(want.ApprovedImage) {
		return Source{}, fmt.Errorf("voice MCP approved image unavailable")
	}
	return currentSource(ctx, reader, want, true)
}

// CurrentSourceForObservation binds the event to the installed MCP source
// before selection. It grants no action capability; dispatch also requires an
// independently configured approved image through CurrentSource.
func CurrentSourceForObservation(ctx context.Context, reader client.Reader, want SourcePins) (Source, error) {
	return currentSource(ctx, reader, want, false)
}

func currentSource(ctx context.Context, reader client.Reader, want SourcePins, requireImage bool) (Source, error) {
	var out Source
	if reader == nil || !ValidUID(want.DeploymentUID) || !ValidUID(want.PodUID) || !ValidUID(want.ServiceUID) ||
		!ValidUID(want.ConfigMapUID) || want.SourceSHA256 != ReviewedMCPSourceSHA256 {
		return out, fmt.Errorf("voice MCP source pins incomplete")
	}
	service := &corev1.Service{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: MCPNamespace, Name: MCPServiceName}, service); err != nil {
		return out, err
	}
	if string(service.UID) != want.ServiceUID || service.DeletionTimestamp != nil || len(service.Spec.Selector) == 0 ||
		len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Protocol != corev1.ProtocolTCP ||
		service.Spec.Ports[0].Port != 8000 || service.Spec.Ports[0].TargetPort.IntVal != 8000 {
		return out, fmt.Errorf("voice MCP Service identity, selector or port changed")
	}
	list := &corev1.PodList{}
	if err := reader.List(ctx, list, client.InNamespace(MCPNamespace), client.Limit(129)); err != nil {
		return out, err
	}
	if list.Continue != "" || len(list.Items) == 0 || len(list.Items) > 128 {
		return out, fmt.Errorf("voice MCP Pod inventory incomplete")
	}
	var pod *corev1.Pod
	for i := range list.Items {
		if string(list.Items[i].UID) == want.PodUID {
			if pod != nil {
				return out, fmt.Errorf("voice MCP Pod UID duplicate")
			}
			pod = &list.Items[i]
		}
	}
	if !servingReady(pod) {
		return out, fmt.Errorf("voice MCP source Pod unavailable")
	}
	current := &corev1.Pod{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: MCPNamespace, Name: pod.Name}, current); err != nil {
		return out, err
	}
	if string(current.UID) != want.PodUID || !servingReady(current) || current.Status.PodIP != pod.Status.PodIP {
		return out, fmt.Errorf("voice MCP source Pod identity changed")
	}
	for key, value := range service.Spec.Selector {
		actual, exists := current.Labels[key]
		if !exists || actual != value {
			return out, fmt.Errorf("voice MCP source Pod left Service selector")
		}
	}
	owner := metav1.GetControllerOf(current)
	if owner == nil || len(current.OwnerReferences) != 1 || owner.APIVersion != "apps/v1" || owner.Kind != "ReplicaSet" {
		return out, fmt.Errorf("voice MCP source Pod owner invalid")
	}
	rs := &appsv1.ReplicaSet{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: MCPNamespace, Name: owner.Name}, rs); err != nil {
		return out, err
	}
	if rs.UID != owner.UID || len(rs.OwnerReferences) != 1 {
		return out, fmt.Errorf("voice MCP source ReplicaSet changed")
	}
	parent := metav1.GetControllerOf(rs)
	if parent == nil || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" || string(parent.UID) != want.DeploymentUID {
		return out, fmt.Errorf("voice MCP source Deployment owner changed")
	}
	dep := &appsv1.Deployment{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: MCPNamespace, Name: parent.Name}, dep); err != nil {
		return out, err
	}
	if string(dep.UID) != want.DeploymentUID || dep.DeletionTimestamp != nil {
		return out, fmt.Errorf("voice MCP source Deployment changed")
	}
	if requireImage {
		var podImage string
		for _, container := range current.Spec.Containers {
			if container.Name == "mcp-server" {
				podImage = container.Image
			}
		}
		var templateImage string
		for _, container := range dep.Spec.Template.Spec.Containers {
			if container.Name == "mcp-server" {
				templateImage = container.Image
			}
		}
		statuses := 0
		for _, status := range current.Status.ContainerStatuses {
			if status.Name == "mcp-server" {
				if !status.Ready || status.ImageID != want.ApprovedImage || status.ContainerID == "" {
					return out, fmt.Errorf("voice MCP runtime image unverified")
				}
				statuses++
			}
		}
		if podImage != want.ApprovedImage || templateImage != want.ApprovedImage || statuses != 1 {
			return out, fmt.Errorf("voice MCP approved image changed")
		}
	}
	name := current.Annotations[MCPSourceAnnotation]
	if !strings.HasPrefix(name, "voice-mcp-source-") || dep.Spec.Template.Annotations[MCPSourceAnnotation] != name ||
		!sourceMount(current.Spec, name) || !sourceMount(dep.Spec.Template.Spec, name) {
		return out, fmt.Errorf("voice MCP source mount or annotation invalid")
	}
	cm := &corev1.ConfigMap{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: MCPNamespace, Name: name}, cm); err != nil {
		return out, err
	}
	if string(cm.UID) != want.ConfigMapUID || cm.DeletionTimestamp != nil || cm.Immutable == nil || !*cm.Immutable ||
		len(cm.Data) != 1 || len(cm.BinaryData) != 0 || cm.Data["server.py"] == "" {
		return out, fmt.Errorf("voice MCP source ConfigMap invalid")
	}
	h := sha256.Sum256([]byte(cm.Data["server.py"]))
	digest := hex.EncodeToString(h[:])
	if digest != want.SourceSHA256 || name != "voice-mcp-source-"+digest[:12] {
		return out, fmt.Errorf("voice MCP source bytes changed")
	}
	slices := &discoveryv1.EndpointSliceList{}
	if err := reader.List(ctx, slices, client.InNamespace(MCPNamespace), client.MatchingLabels{discoveryv1.LabelServiceName: MCPServiceName}, client.Limit(33)); err != nil {
		return out, err
	}
	if slices.Continue != "" || len(slices.Items) != 1 {
		return out, fmt.Errorf("voice MCP Service endpoint inventory incomplete")
	}
	slice := &slices.Items[0]
	if slice.Labels[discoveryv1.LabelServiceName] != MCPServiceName || len(slice.OwnerReferences) != 1 ||
		slice.OwnerReferences[0].APIVersion != "v1" || slice.OwnerReferences[0].Kind != "Service" ||
		slice.OwnerReferences[0].Name != MCPServiceName || slice.OwnerReferences[0].UID != service.UID ||
		len(slice.Endpoints) != 1 || len(slice.Ports) != 1 || slice.Ports[0].Port == nil || *slice.Ports[0].Port != 8000 ||
		slice.Ports[0].Protocol == nil || *slice.Ports[0].Protocol != corev1.ProtocolTCP {
		return out, fmt.Errorf("voice MCP endpoint ownership or port changed")
	}
	endpoint := slice.Endpoints[0]
	if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" ||
		(endpoint.TargetRef.Namespace != "" && endpoint.TargetRef.Namespace != MCPNamespace) ||
		string(endpoint.TargetRef.UID) != want.PodUID || len(endpoint.Addresses) != 1 || endpoint.Addresses[0] != current.Status.PodIP ||
		endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready ||
		endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
		return out, fmt.Errorf("voice MCP sole Ready endpoint changed")
	}
	out = Source{Pins: want, PodName: current.Name, ConfigMapName: name, PodIP: current.Status.PodIP}
	return out, nil
}
