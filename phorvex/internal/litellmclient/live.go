package litellmclient

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Pod struct{ Name, UID, IP, GatewayImageID string }
type Live struct {
	ServiceUID, SourceSHA256, SourceUID, ClientsUID, PolicyUID, PolicyRV string
	SeedSHA256                                                           string
	State                                                                State
	Pods                                                                 []Pod
}

func ValidateLive(ctx context.Context, r client.Reader, targetUID, peerUID string) (Live, error) {
	return validateLive(ctx, r, targetUID, peerUID, "")
}

func validateLive(ctx context.Context, r client.Reader, targetUID, peerUID, approvedGatewayImage string) (Live, error) {
	if r == nil || targetUID == "" || (peerUID != "" && targetUID == peerUID) {
		return Live{}, errors.New("owned-client reader or Pod identity absent")
	}
	svc := &corev1.Service{}
	if e := r.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: ServiceName}, svc); e != nil {
		return Live{}, e
	}
	if svc.DeletionTimestamp != nil || string(svc.UID) == "" || len(svc.Spec.Selector) != 1 || svc.Spec.Selector["app"] != "litellm" {
		return Live{}, errors.New("owned-client Service selector/identity differs")
	}
	portOK := false
	for _, p := range svc.Spec.Ports {
		if p.Port == 4000 && p.TargetPort.Type == intstr.Int && p.TargetPort.IntVal == 4001 {
			portOK = true
		}
	}
	if len(svc.Spec.Ports) != 1 || !portOK {
		return Live{}, errors.New("owned-client gateway is not Service target")
	}
	var pods corev1.PodList
	if e := r.List(ctx, &pods, client.InNamespace(Namespace), client.MatchingLabels{"app": "litellm"}); e != nil {
		return Live{}, e
	}
	if len(pods.Items) != 2 {
		return Live{}, fmt.Errorf("owned-client gateway requires exactly two Service Pods; got %d", len(pods.Items))
	}
	// Select authority from observed Pods, then verify the immutable bytes below.
	// Never derive a name from an arbitrary event/profile or an unapproved prefix.
	declaredSHA := pods.Items[0].Annotations[SourceSHAAnnotation]
	sourceName := ApprovedSourceConfigMap(declaredSHA)
	if sourceName == "" {
		return Live{}, errors.New("owned-client declared gateway source not reviewed")
	}
	enforceSourceBinding := approvedGatewayImage == ""
	if approvedGatewayImage == "" {
		approvedGatewayImage = pods.Items[0].Annotations[GatewayImageAnnotation]
		if !ApprovedRuntime(declaredSHA, approvedGatewayImage) {
			return Live{}, errors.New("owned-client gateway source/runtime pair not reviewed")
		}
	}
	imageMark := strings.LastIndex(approvedGatewayImage, "@sha256:")
	if imageMark < 1 || !ValidSHA(approvedGatewayImage[imageMark+8:]) {
		return Live{}, errors.New("owned-client gateway image has no reviewed digest pin")
	}
	imageDigest := approvedGatewayImage[imageMark+8:]
	source := &corev1.ConfigMap{}
	clients := &corev1.ConfigMap{}
	policy := &corev1.ConfigMap{}
	for _, item := range []struct {
		name string
		out  *corev1.ConfigMap
	}{{sourceName, source}, {ClientsConfigMapName, clients}, {PolicyConfigMapName, policy}} {
		if e := r.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: item.name}, item.out); e != nil {
			return Live{}, e
		}
		if item.out.DeletionTimestamp != nil || item.out.UID == "" {
			return Live{}, errors.New("owned-client ConfigMap identity differs")
		}
	}
	if source.Immutable == nil || !*source.Immutable || clients.Immutable == nil || !*clients.Immutable ||
		len(source.Data) != 1 || len(clients.Data) != 1 || len(policy.Data) != 1 ||
		len(source.BinaryData) != 0 || len(clients.BinaryData) != 0 || len(policy.BinaryData) != 0 || source.Data[SourceKey] == "" {
		return Live{}, errors.New("owned-client source/credential inventory not immutable")
	}
	sourceSHA := SHA256([]byte(source.Data[SourceKey]))
	if sourceSHA != declaredSHA || !ApprovedSource(sourceSHA) {
		return Live{}, errors.New("owned-client installed gateway source not reviewed")
	}
	inventory, e := ParseClients(clients.Data[ClientsKey])
	if e != nil {
		return Live{}, e
	}
	state, e := ParseState(policy.Data[PolicyKey])
	if e != nil {
		return Live{}, e
	}
	result := Live{ServiceUID: string(svc.UID), SourceSHA256: sourceSHA, SourceUID: string(source.UID),
		ClientsUID: string(clients.UID), PolicyUID: string(policy.UID), PolicyRV: policy.ResourceVersion,
		SeedSHA256: inventory.SeedSHA256, State: state}
	seen := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if enforceSourceBinding {
			if err := ValidateGatewaySourceBinding(p, sourceSHA, approvedGatewayImage); err != nil {
				return Live{}, err
			}
		}
		if p.DeletionTimestamp != nil || p.UID == "" || p.Status.PodIP == "" || seen[string(p.UID)] ||
			p.Annotations[SourceSHAAnnotation] != sourceSHA || p.Annotations[PolicyUIDAnnotation] != string(policy.UID) ||
			p.Annotations[ServiceUIDAnnotation] != string(svc.UID) || p.Annotations[SeedSHAAnnotation] != inventory.SeedSHA256 {
			return Live{}, errors.New("owned-client Pod lifetime/source/policy declaration differs")
		}
		seen[string(p.UID)] = true
		gateway := false
		gatewayImage := ""
		mainImage := ""
		volumes := map[string]corev1.VolumeSource{}
		for _, v := range p.Spec.Volumes {
			volumes[v.Name] = v.VolumeSource
		}
		for _, container := range p.Spec.Containers {
			if container.Name == "litellm" {
				mainImage = container.Image
			}
			if container.Name != GatewayContainerName {
				continue
			}
			gatewayImage = container.Image
			if len(container.Command) != 3 || container.Command[0] != "python3" || container.Command[1] != "-B" ||
				container.Command[2] != "/opt/phorvex/gateway.py" {
				break
			}
			env := map[string]corev1.EnvVar{}
			for _, entry := range container.Env {
				if _, exists := env[entry.Name]; exists {
					return Live{}, errors.New("owned-client duplicate gateway environment")
				}
				env[entry.Name] = entry
			}
			if env["PHORVEX_LITELLM_CLIENTS_FILE"].Value != "/etc/phorvex-litellm/clients.json" ||
				env["PHORVEX_LITELLM_TRIAL_SEED_FILE"].Value != "/etc/phorvex-litellm-seed/seed" ||
				env["PHORVEX_LITELLM_POLICY_FILE"].Value != "/etc/phorvex-litellm-policy/state.json" ||
				env["PHORVEX_LITELLM_STATUS_TOKEN_FILE"].Value != "/etc/phorvex-litellm-status/token" ||
				env["PHORVEX_LITELLM_POLICY_CONFIGMAP_UID"].Value != string(policy.UID) ||
				env["PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256"].Value != sourceSHA ||
				env["POD_UID"].ValueFrom == nil || env["POD_UID"].ValueFrom.FieldRef == nil ||
				env["POD_UID"].ValueFrom.FieldRef.FieldPath != "metadata.uid" {
				break
			}
			needed := map[string]string{
				"litellm-live-gateway-source": "/opt/phorvex",
				"litellm-live-clients":        "/etc/phorvex-litellm",
				"litellm-live-policy":         "/etc/phorvex-litellm-policy",
				"litellm-live-status":         "/etc/phorvex-litellm-status",
				"litellm-live-trial-seed":     "/etc/phorvex-litellm-seed",
			}
			for _, mount := range container.VolumeMounts {
				if mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == "" && needed[mount.Name] == mount.MountPath {
					delete(needed, mount.Name)
				}
			}
			if len(needed) != 0 {
				break
			}
			sourceVolume := volumes["litellm-live-gateway-source"].ConfigMap
			if sourceVolume == nil || (sourceVolume.Optional != nil && *sourceVolume.Optional) ||
				(len(sourceVolume.Items) != 0 && (len(sourceVolume.Items) != 1 ||
					sourceVolume.Items[0].Key != SourceKey || sourceVolume.Items[0].Path != SourceKey)) {
				break
			}
			gateway = volumes["litellm-live-gateway-source"].ConfigMap != nil &&
				volumes["litellm-live-gateway-source"].ConfigMap.Name == sourceName &&
				volumes["litellm-live-clients"].ConfigMap != nil &&
				volumes["litellm-live-clients"].ConfigMap.Name == ClientsConfigMapName &&
				volumes["litellm-live-policy"].ConfigMap != nil &&
				volumes["litellm-live-policy"].ConfigMap.Name == PolicyConfigMapName &&
				volumes["litellm-live-status"].Secret != nil &&
				volumes["litellm-live-trial-seed"].Secret != nil &&
				volumes["litellm-live-trial-seed"].Secret.SecretName == TrialSeedSecretName
		}
		if !gateway || mainImage == "" || gatewayImage != approvedGatewayImage ||
			p.Annotations[GatewayImageAnnotation] != approvedGatewayImage {
			return Live{}, errors.New("owned-client gateway container or read-only mount absent")
		}
		ready := false
		imageID := ""
		mainImageID := ""
		for _, status := range p.Status.ContainerStatuses {
			if status.Name == "litellm" && status.Ready && status.RestartCount == 0 {
				mainImageID = status.ImageID
			}
			if status.Name == GatewayContainerName && status.Ready && status.RestartCount == 0 && status.ImageID != "" {
				ready = true
				imageID = status.ImageID
			}
		}
		if !ready || mainImageID == "" || !strings.HasSuffix(imageID, "sha256:"+imageDigest) {
			return Live{}, errors.New("owned-client gateway not Ready on exact Pod")
		}
		result.Pods = append(result.Pods, Pod{Name: p.Name, UID: string(p.UID), IP: p.Status.PodIP, GatewayImageID: imageID})
	}
	if !seen[targetUID] || (peerUID != "" && !seen[peerUID]) {
		return Live{}, errors.New("owned-client target/peer UID differs")
	}
	var slices discoveryv1.EndpointSliceList
	if e := r.List(ctx, &slices, client.InNamespace(Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: ServiceName}); e != nil {
		return Live{}, e
	}
	if len(slices.Items) == 0 {
		return Live{}, errors.New("owned-client EndpointSlice inventory absent")
	}
	readyUIDs := map[string]bool{}
	ipByUID := map[string]string{}
	nameByUID := map[string]string{}
	for _, pod := range result.Pods {
		ipByUID[pod.UID] = pod.IP
		nameByUID[pod.UID] = pod.Name
	}
	for i := range slices.Items {
		portMatched := false
		for _, port := range slices.Items[i].Ports {
			if port.Port != nil && *port.Port == 4001 {
				portMatched = true
			}
		}
		if !portMatched {
			return Live{}, errors.New("owned-client EndpointSlice gateway port differs")
		}
		for _, ep := range slices.Items[i].Endpoints {
			if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" && ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				if ep.TargetRef.Name != nameByUID[string(ep.TargetRef.UID)] || len(ep.Addresses) != 1 || ep.Addresses[0] != ipByUID[string(ep.TargetRef.UID)] {
					return Live{}, errors.New("owned-client EndpointSlice Pod address differs")
				}
				readyUIDs[string(ep.TargetRef.UID)] = true
			}
		}
	}
	if len(readyUIDs) != 2 || !readyUIDs[targetUID] || (peerUID != "" && !readyUIDs[peerUID]) {
		return Live{}, errors.New("owned-client Service endpoint Pod set differs")
	}
	sort.Slice(result.Pods, func(i, j int) bool { return result.Pods[i].UID < result.Pods[j].UID })
	return result, nil
}

// ValidateGatewaySourceBinding checks what a Pod will execute, independently of
// its declaration. Console uses this after verifying the immutable source bytes.
func ValidateGatewaySourceBinding(p *corev1.Pod, sha, image string) error {
	if p == nil || !ApprovedRuntime(sha, image) {
		return errors.New("owned-client unapproved Pod source/runtime")
	}
	name := ApprovedSourceConfigMap(sha)
	var source *corev1.ConfigMapVolumeSource
	for _, volume := range p.Spec.Volumes {
		if volume.Name == "litellm-live-gateway-source" {
			if source != nil {
				return errors.New("owned-client repeated source volume")
			}
			source = volume.ConfigMap
		}
	}
	if source == nil || source.Name != name || (source.Optional != nil && *source.Optional) || (len(source.Items) > 0 && (len(source.Items) != 1 || source.Items[0].Key != SourceKey || source.Items[0].Path != SourceKey)) {
		return errors.New("owned-client Pod source volume differs")
	}
	found := false
	for _, container := range p.Spec.Containers {
		if container.Name != GatewayContainerName {
			continue
		}
		if found || container.Image != image || len(container.Command) != 3 || container.Command[0] != "python3" || container.Command[1] != "-B" || container.Command[2] != "/opt/phorvex/gateway.py" || len(container.Args) != 0 {
			return errors.New("owned-client Pod source command/image differs")
		}
		found = true
		env := map[string]bool{}
		sourceEnv := false
		for _, entry := range container.Env {
			if env[entry.Name] {
				return errors.New("owned-client repeated source environment")
			}
			env[entry.Name] = true
			if entry.Name == "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256" {
				sourceEnv = entry.Value == sha && entry.ValueFrom == nil
			}
		}
		mountOK := false
		mountPaths := map[string]bool{}
		for _, mount := range container.VolumeMounts {
			if mountPaths[mount.MountPath] || strings.HasPrefix(mount.MountPath, "/opt/phorvex/") {
				return errors.New("owned-client shadowed source mount")
			}
			mountPaths[mount.MountPath] = true
			if mount.Name == "litellm-live-gateway-source" {
				mountOK = mount.MountPath == "/opt/phorvex" && mount.ReadOnly && mount.SubPath == "" && mount.SubPathExpr == ""
			}
		}
		if !sourceEnv || !mountOK {
			return errors.New("owned-client Pod source environment/mount differs")
		}
	}
	if !found {
		return errors.New("owned-client Pod gateway missing")
	}
	return nil
}
