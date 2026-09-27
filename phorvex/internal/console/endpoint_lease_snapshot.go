package console

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type endpointLeaseSnapshot struct {
	ServiceUID, PolicyUID, ConfigMapUID, ConfigMapRV, SecretUID, SourceConfigMapUID, JournalUID string
	PolicyGeneration                                                                            int64
	State                                                                                       endpointLeaseState
	StateSHA256                                                                                 string
	Pods                                                                                        []corev1.Pod
}

func endpointLeaseProxyContainerID(pod corev1.Pod) string {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "guardrail" {
			return status.ContainerID
		}
	}
	return ""
}

func endpointLeaseEngineContainerID(pod corev1.Pod) string {
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "vllm" {
			return status.ContainerID
		}
	}
	return ""
}

func endpointLeaseSameProxyIncarnations(before, after []corev1.Pod) bool {
	if len(before) != len(after) {
		return false
	}
	for i := range before {
		if before[i].UID != after[i].UID || before[i].Name != after[i].Name ||
			endpointLeaseProxyContainerID(before[i]) == "" ||
			endpointLeaseProxyContainerID(before[i]) != endpointLeaseProxyContainerID(after[i]) ||
			endpointLeaseEngineContainerID(before[i]) == "" ||
			endpointLeaseEngineContainerID(before[i]) != endpointLeaseEngineContainerID(after[i]) {
			return false
		}
	}
	return true
}

func endpointLeaseReadyPod(pod *corev1.Pod, p endpointLeaseProfile, service *corev1.Service) bool {
	if pod == nil || pod.Namespace != "vllm" || pod.UID == "" || pod.DeletionTimestamp != nil ||
		pod.Status.Phase != corev1.PodRunning || pod.Annotations["phorvex.ai/endpoint-lease-source-sha256"] != p.ProxySourceSHA256 ||
		pod.Annotations["phorvex.ai/endpoint-lease-policy-configmap-uid"] != p.PolicyConfigMapUID ||
		pod.Annotations["phorvex.ai/endpoint-lease-event-creator"] != p.EventCreator ||
		len(pod.OwnerReferences) != 1 || metav1.GetControllerOf(pod) == nil || len(pod.Spec.Containers) != 2 {
		return false
	}
	for key, value := range service.Spec.Selector {
		if pod.Labels[key] != value {
			return false
		}
	}
	readyCount := 0
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady {
			if condition.Status != corev1.ConditionTrue {
				return false
			}
			readyCount++
		}
	}
	if readyCount != 1 {
		return false
	}
	statusCount := 0
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == "guardrail" && status.Ready && status.ContainerID != "" &&
			strings.HasSuffix(status.ImageID, p.ProxyImage[strings.LastIndex(p.ProxyImage, "@")+1:]) {
			statusCount++
		}
	}
	if statusCount != 1 {
		return false
	}
	guard := (*corev1.Container)(nil)
	engine := (*corev1.Container)(nil)
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "guardrail" {
			guard = &pod.Spec.Containers[i]
		} else if pod.Spec.Containers[i].Name == "vllm" {
			engine = &pod.Spec.Containers[i]
		}
	}
	if guard == nil || guard.Image != p.ProxyImage || len(guard.Command) != 3 || guard.Command[0] != "python3" ||
		guard.Command[1] != "-B" || guard.Command[2] != "/src/dual_server.py" || len(guard.Args) != 0 ||
		!endpointLeaseEngineBound(engine, pod.Status.ContainerStatuses, p) {
		return false
	}
	for _, pair := range []struct{ name, value string }{
		{"PHORVEX_ENDPOINT_LEASE_REQUIRED", "true"},
		{"PHORVEX_ENDPOINT_LEASE_SECRET_DIR", "/etc/phorvex/endpoint-lease-keys"},
		{"PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID", p.PolicyConfigMapUID},
		{"PHORVEX_ENDPOINT_LEASE_SECRET_UID", p.TenantSecretUID},
		{"PHORVEX_ENDPOINT_LEASE_SERVICE_UID", p.ServiceUID},
		{"PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256", p.ProxySourceSHA256},
	} {
		count := 0
		for _, env := range guard.Env {
			if env.Name == pair.name {
				if env.ValueFrom != nil || env.Value != pair.value {
					return false
				}
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	uidEnv := 0
	for _, env := range guard.Env {
		if env.Name == "POD_UID" && env.ValueFrom != nil && env.ValueFrom.FieldRef != nil &&
			env.ValueFrom.FieldRef.FieldPath == "metadata.uid" {
			uidEnv++
		}
	}
	if uidEnv != 1 {
		return false
	}
	volumes := map[string]corev1.Volume{}
	for _, volume := range pod.Spec.Volumes {
		if _, exists := volumes[volume.Name]; exists {
			return false
		}
		volumes[volume.Name] = volume
	}
	secretMount := 0
	sourceMounts := map[string]bool{}
	for _, mount := range guard.VolumeMounts {
		if mount.MountPath == "/src" || mount.MountPath == "/etc/phorvex" ||
			strings.HasPrefix(mount.MountPath, "/etc/phorvex/endpoint-lease-keys/") {
			return false
		}
		if mount.MountPath == "/etc/phorvex/endpoint-lease-keys" {
			volume := volumes[mount.Name]
			if !mount.ReadOnly || mount.SubPath != "" || volume.Secret == nil ||
				volume.Secret.SecretName != endpointLeaseTenantSecret || volume.Secret.Optional != nil && *volume.Secret.Optional {
				return false
			}
			secretMount++
		}
		if strings.HasPrefix(mount.MountPath, "/src/") {
			name := strings.TrimPrefix(mount.MountPath, "/src/")
			if name != "guardrail_proxy.py" && name != "dual_server.py" && name != "endpoint_lease.py" &&
				name != "drain_v11.py" && name != "drain_v11_init.py" {
				return false
			}
			volume := volumes[mount.Name]
			if sourceMounts[name] || !mount.ReadOnly || mount.SubPath != name || volume.ConfigMap == nil ||
				volume.ConfigMap.Name != p.SourceConfigMapName || volume.ConfigMap.Optional != nil && *volume.ConfigMap.Optional {
				return false
			}
			sourceMounts[name] = true
		}
	}
	return secretMount == 1 && len(sourceMounts) == 5
}

func endpointLeaseEngineBound(engine *corev1.Container, statuses []corev1.ContainerStatus, p endpointLeaseProfile) bool {
	if engine == nil || engine.Image != p.ApprovedEngineImage {
		return false
	}
	counts := map[string]int{"--host": 0, "--port": 0}
	for i, arg := range engine.Args {
		if arg == "--host" || arg == "--port" {
			if i+1 >= len(engine.Args) {
				return false
			}
			counts[arg]++
			if arg == "--host" && engine.Args[i+1] != "127.0.0.1" ||
				arg == "--port" && engine.Args[i+1] != "8001" {
				return false
			}
		}
		if strings.HasPrefix(arg, "--host=") || strings.HasPrefix(arg, "--port=") {
			return false
		}
	}
	if counts["--host"] != 1 || counts["--port"] != 1 {
		return false
	}
	keyCount := 0
	for _, env := range engine.Env {
		if env.Name == "VLLM_API_KEY" {
			if env.Value != "" || env.ValueFrom == nil || env.ValueFrom.SecretKeyRef == nil ||
				env.ValueFrom.SecretKeyRef.Name != "vllm-control" || env.ValueFrom.SecretKeyRef.Key != "api-key" ||
				env.ValueFrom.SecretKeyRef.Optional != nil && *env.ValueFrom.SecretKeyRef.Optional {
				return false
			}
			keyCount++
		}
	}
	if keyCount != 1 {
		return false
	}
	statusCount := 0
	for _, status := range statuses {
		if status.Name == "vllm" && status.Ready && status.ContainerID != "" &&
			strings.HasSuffix(status.ImageID, p.ApprovedEngineImage[strings.LastIndex(p.ApprovedEngineImage, "@")+1:]) {
			statusCount++
		}
	}
	return statusCount == 1
}

func endpointLeaseSourceSHA(data map[string]string) (string, bool) {
	names := []string{"guardrail_proxy.py", "dual_server.py", "endpoint_lease.py", "drain_v11.py", "drain_v11_init.py"}
	if len(data) != len(names) {
		return "", false
	}
	var all []byte
	for i, name := range names {
		part := data[name]
		if part == "" || len(part) > 1<<20 {
			return "", false
		}
		if i > 0 {
			all = append(all, 0)
		}
		all = append(all, part...)
	}
	return endpointLeaseSHA(all), true
}

func endpointLeaseSecretScope(secret *corev1.Secret, name, uid string, keys []string, immutable bool) bool {
	if secret == nil || secret.Name != name || string(secret.UID) != uid || len(secret.Data) != len(keys) ||
		len(secret.StringData) != 0 || secret.DeletionTimestamp != nil || secret.Immutable == nil || *secret.Immutable != immutable {
		return false
	}
	for _, key := range keys {
		if len(secret.Data[key]) == 0 {
			return false
		}
	}
	return true
}

func (s *Server) endpointLeaseSnapshot(ctx context.Context, kube kubernetes.Interface, p endpointLeaseProfile,
	tokens endpointLeaseTokens) (endpointLeaseSnapshot, error) {
	var snap endpointLeaseSnapshot
	service, err := kube.CoreV1().Services("vllm").Get(ctx, p.ServiceName, metav1.GetOptions{})
	if err != nil || string(service.UID) != p.ServiceUID || len(service.Spec.Selector) == 0 ||
		len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 8000 || service.Spec.Ports[0].Protocol != corev1.ProtocolTCP ||
		service.Spec.Ports[0].TargetPort.IntVal != 8000 {
		return snap, errors.New("endpoint lease public Service binding unavailable")
	}
	source, err := kube.CoreV1().ConfigMaps("vllm").Get(ctx, p.SourceConfigMapName, metav1.GetOptions{})
	if err != nil || string(source.UID) != p.SourceConfigMapUID || source.Immutable == nil || !*source.Immutable || len(source.BinaryData) != 0 {
		return snap, errors.New("endpoint lease immutable proxy source unavailable")
	}
	sourceSHA, okay := endpointLeaseSourceSHA(source.Data)
	if !okay || sourceSHA != p.ProxySourceSHA256 {
		return snap, errors.New("endpoint lease reviewed proxy source differs")
	}
	policyCM, err := kube.CoreV1().ConfigMaps("vllm").Get(ctx, endpointLeasePolicyCM, metav1.GetOptions{})
	if err != nil || string(policyCM.UID) != p.PolicyConfigMapUID || policyCM.ResourceVersion == "" ||
		len(policyCM.Data) != 1 || len(policyCM.BinaryData) != 0 {
		return snap, errors.New("endpoint lease policy ConfigMap unavailable")
	}
	state, err := parseEndpointLeaseState([]byte(policyCM.Data["state.json"]), p)
	if err != nil {
		return snap, err
	}
	journal, err := kube.CoreV1().ConfigMaps("phorvex-system").Get(ctx, endpointLeaseJournalCM, metav1.GetOptions{})
	if err != nil || string(journal.UID) != p.JournalUID || journal.ResourceVersion == "" ||
		len(journal.Data) != 1 || len(journal.BinaryData) != 0 || journal.Data["receipts.json"] == "" {
		return snap, errors.New("endpoint lease protected journal unavailable")
	}
	tenant, err := kube.CoreV1().Secrets("vllm").Get(ctx, endpointLeaseTenantSecret, metav1.GetOptions{})
	if err != nil || !endpointLeaseSecretScope(tenant, endpointLeaseTenantSecret, p.TenantSecretUID,
		[]string{"client-a", "client-b", "seed"}, true) || !endpointLeaseTokenValid(tenant.Data["client-a"]) ||
		!endpointLeaseTokenValid(tenant.Data["client-b"]) || len(tenant.Data["seed"]) < 32 || len(tenant.Data["seed"]) > 256 ||
		endpointLeaseSHA(tenant.Data["seed"]) != p.SeedSHA256 ||
		endpointLeaseSHA(tenant.Data["client-a"]) != p.ClientASHA256 ||
		endpointLeaseSHA(tenant.Data["client-b"]) != p.ClientBSHA256 ||
		endpointLeaseHMAC(tenant.Data["seed"], tokens.A) != p.ClientAHMAC ||
		endpointLeaseHMAC(tenant.Data["seed"], tokens.B) != p.ClientBHMAC {
		return snap, errors.New("endpoint lease tenant credential authority differs")
	}
	consoleSecret, err := kube.CoreV1().Secrets("phorvex-system").Get(ctx, endpointLeaseConsoleKey, metav1.GetOptions{})
	if err != nil || !endpointLeaseSecretScope(consoleSecret, endpointLeaseConsoleKey, p.ConsoleSecretUID,
		[]string{"client-a", "client-b"}, true) || !bytes.Equal(consoleSecret.Data["client-a"], tokens.A) ||
		!bytes.Equal(consoleSecret.Data["client-b"], tokens.B) || !bytes.Equal(tokens.A, tenant.Data["client-a"]) ||
		!bytes.Equal(tokens.B, tenant.Data["client-b"]) {
		return snap, errors.New("endpoint lease caller Secret copy differs")
	}
	var phorvexPolicy struct {
		Metadata struct {
			UID        string `json:"uid"`
			Generation int64  `json:"generation"`
		} `json:"metadata"`
		Spec struct {
			Mode     string `json:"mode"`
			Selector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"selector"`
			Actions struct {
				Enabled []string `json:"enabled"`
			} `json:"actions"`
		} `json:"spec"`
	}
	if err = s.scenarioObject("vllm", "phorvexpolicy", p.PolicyName, &phorvexPolicy); err != nil ||
		phorvexPolicy.Metadata.UID != p.PolicyUID || phorvexPolicy.Metadata.Generation != p.PolicyGeneration ||
		phorvexPolicy.Spec.Mode != "active" || len(phorvexPolicy.Spec.Selector.MatchLabels) == 0 ||
		len(phorvexPolicy.Spec.Actions.Enabled) < 2 {
		return snap, errors.New("endpoint lease normal policy alternatives unavailable")
	}
	enabled := false
	for _, action := range phorvexPolicy.Spec.Actions.Enabled {
		enabled = enabled || action == endpointLeaseAction
	}
	if !enabled {
		return snap, errors.New("endpoint lease action not available among normal choices")
	}
	slices, err := kube.DiscoveryV1().EndpointSlices("vllm").List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + p.ServiceName, Limit: 16})
	if err != nil || slices.Continue != "" || len(slices.Items) == 0 || len(slices.Items) > 8 {
		return snap, errors.New("endpoint lease EndpointSlice route unavailable")
	}
	seen := map[string]bool{}
	for _, slice := range slices.Items {
		if slice.Labels["kubernetes.io/service-name"] != p.ServiceName || slice.AddressType != "IPv4" ||
			len(slice.Ports) != 1 || slice.Ports[0].Port == nil || *slice.Ports[0].Port != 8000 ||
			slice.Ports[0].Protocol == nil || *slice.Ports[0].Protocol != corev1.ProtocolTCP {
			return endpointLeaseSnapshot{}, errors.New("endpoint lease route port differs")
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready ||
				endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating {
				continue
			}
			if endpoint.TargetRef == nil || endpoint.TargetRef.Kind != "Pod" || endpoint.TargetRef.Namespace != "vllm" ||
				endpoint.TargetRef.Name == "" || endpoint.TargetRef.UID == "" || seen[string(endpoint.TargetRef.UID)] ||
				len(endpoint.Addresses) != 1 {
				return endpointLeaseSnapshot{}, errors.New("endpoint lease ambiguous Ready target")
			}
			pod, e := kube.CoreV1().Pods("vllm").Get(ctx, endpoint.TargetRef.Name, metav1.GetOptions{})
			if e != nil || pod.UID != endpoint.TargetRef.UID || pod.Status.PodIP != endpoint.Addresses[0] ||
				!endpointLeaseReadyPod(pod, p, service) {
				return endpointLeaseSnapshot{}, errors.New("endpoint lease proxy Pod or source differs")
			}
			for key, value := range phorvexPolicy.Spec.Selector.MatchLabels {
				if pod.Labels[key] != value {
					return endpointLeaseSnapshot{}, errors.New("endpoint lease policy no longer selects serving Pod")
				}
			}
			seen[string(pod.UID)] = true
			snap.Pods = append(snap.Pods, *pod)
		}
	}
	if len(snap.Pods) == 0 || len(snap.Pods) > 8 {
		return endpointLeaseSnapshot{}, fmt.Errorf("endpoint lease Ready route cardinality unavailable")
	}
	sort.Slice(snap.Pods, func(i, j int) bool { return snap.Pods[i].Name < snap.Pods[j].Name })
	snap.ServiceUID, snap.PolicyUID, snap.PolicyGeneration = p.ServiceUID, p.PolicyUID, p.PolicyGeneration
	snap.ConfigMapUID, snap.ConfigMapRV, snap.SecretUID = string(policyCM.UID), policyCM.ResourceVersion, string(tenant.UID)
	snap.SourceConfigMapUID, snap.JournalUID = string(source.UID), string(journal.UID)
	snap.State, snap.StateSHA256 = state, endpointLeaseSHA([]byte(policyCM.Data["state.json"]))
	return snap, nil
}
