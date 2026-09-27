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
	return validateLive(ctx, r, targetUID, peerUID, ApprovedGatewayImage)
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
	}{{SourceConfigMapName, source}, {ClientsConfigMapName, clients}, {PolicyConfigMapName, policy}} {
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
	if sourceSHA != ApprovedSourceSHA256 {
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
	var pods corev1.PodList
	if e := r.List(ctx, &pods, client.InNamespace(Namespace), client.MatchingLabels{"app": "litellm"}); e != nil {
		return Live{}, e
	}
	if len(pods.Items) != 2 {
		return Live{}, fmt.Errorf("owned-client gateway requires exactly two Service Pods; got %d", len(pods.Items))
	}
	result := Live{ServiceUID: string(svc.UID), SourceSHA256: sourceSHA, SourceUID: string(source.UID),
		ClientsUID: string(clients.UID), PolicyUID: string(policy.UID), PolicyRV: policy.ResourceVersion,
		SeedSHA256: inventory.SeedSHA256, State: state}
	seen := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
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
				if mount.ReadOnly && needed[mount.Name] == mount.MountPath {
					delete(needed, mount.Name)
				}
			}
			if len(needed) != 0 {
				break
			}
			gateway = volumes["litellm-live-gateway-source"].ConfigMap != nil &&
				volumes["litellm-live-gateway-source"].ConfigMap.Name == SourceConfigMapName &&
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
