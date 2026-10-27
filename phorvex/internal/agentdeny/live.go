package agentdeny

import (
	"context"
	"errors"
	"sort"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Pod is one serving agent Pod that mounts the operator-owned deny-guard.
type Pod struct{ Name, UID, IP string }

// Live is the authoritative, boundary-read view of the agent deny-guard: the guard
// ConfigMap identity + its current ledger, the Service, and the serving Pods that mount
// the guard. The actuator CASes the guard ConfigMap by GuardUID/GuardRV.
type Live struct {
	ServiceUID string
	GuardUID   string
	GuardRV    string
	State      Guard
	Pods       []Pod
}

// ValidateLive reads the live agent deny-guard boundary in the given namespace. The
// agent app re-reads the guard ConfigMap mounted read-only at GuardMountPath. It requires
// the Service (app=agent-sim on ServingPort), the guard ConfigMap, and at least one serving
// Pod, each Ready and mounting the guard, with the target among them, cross-checked against
// the Service EndpointSlices. Namespace is a parameter (never a hard-coded literal).
func ValidateLive(ctx context.Context, r client.Reader, namespace, targetUID string) (Live, error) {
	if r == nil || namespace == "" || targetUID == "" {
		return Live{}, errors.New("agent-deny reader, namespace or Pod identity absent")
	}
	svc := &corev1.Service{}
	if e := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ServiceName}, svc); e != nil {
		return Live{}, e
	}
	if svc.DeletionTimestamp != nil || string(svc.UID) == "" || len(svc.Spec.Selector) != 1 || svc.Spec.Selector[AppLabel] != AppLabelValue {
		return Live{}, errors.New("agent-deny Service selector/identity differs")
	}
	portOK := false
	for _, p := range svc.Spec.Ports {
		if p.Port == ServingPort && p.TargetPort.Type == intstr.Int && p.TargetPort.IntVal == ServingPort {
			portOK = true
		}
	}
	if len(svc.Spec.Ports) != 1 || !portOK {
		return Live{}, errors.New("agent-deny app is not the Service target on serving port")
	}
	guard := &corev1.ConfigMap{}
	if e := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: GuardConfigMapName}, guard); e != nil {
		return Live{}, e
	}
	if guard.DeletionTimestamp != nil || guard.UID == "" {
		return Live{}, errors.New("agent-deny guard ConfigMap identity differs")
	}
	// The app-facing denied.json is always present; the operator ledger (StateKey) is absent
	// until the first deny. An absent/empty ledger is the canonical empty guard.
	state := Guard{Version: 2, Entries: []Entry{}}
	if raw := guard.Data[StateKey]; raw != "" {
		parsed, e := ParseState(raw)
		if e != nil {
			return Live{}, e
		}
		state = parsed
	}
	if raw := guard.Data[GuardKey]; raw != "" && !AppGuardMatches(raw, state) {
		return Live{}, errors.New("agent-deny app guard and operator ledger disagree")
	}
	var pods corev1.PodList
	if e := r.List(ctx, &pods, client.InNamespace(namespace), client.MatchingLabels{AppLabel: AppLabelValue}); e != nil {
		return Live{}, e
	}
	if len(pods.Items) == 0 {
		return Live{}, errors.New("agent-deny has no serving Pods")
	}
	result := Live{ServiceUID: string(svc.UID), GuardUID: string(guard.UID), GuardRV: guard.ResourceVersion, State: state}
	seen := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil || p.UID == "" || p.Status.PodIP == "" || seen[string(p.UID)] {
			return Live{}, errors.New("agent-deny Pod lifetime differs")
		}
		seen[string(p.UID)] = true
		if !podMountsGuard(p) {
			return Live{}, errors.New("agent-deny serving Pod does not mount the exact deny-guard read-only")
		}
		ready := false
		for _, status := range p.Status.ContainerStatuses {
			if status.Ready {
				ready = true
			}
		}
		if !ready {
			return Live{}, errors.New("agent-deny serving Pod not Ready")
		}
		result.Pods = append(result.Pods, Pod{Name: p.Name, UID: string(p.UID), IP: p.Status.PodIP})
	}
	if !seen[targetUID] {
		return Live{}, errors.New("agent-deny target UID absent from serving Pods")
	}
	var slices discoveryv1.EndpointSliceList
	if e := r.List(ctx, &slices, client.InNamespace(namespace), client.MatchingLabels{discoveryv1.LabelServiceName: ServiceName}); e != nil {
		return Live{}, e
	}
	if len(slices.Items) == 0 {
		return Live{}, errors.New("agent-deny EndpointSlice inventory absent")
	}
	ipByUID := map[string]string{}
	nameByUID := map[string]string{}
	for _, pod := range result.Pods {
		ipByUID[pod.UID] = pod.IP
		nameByUID[pod.UID] = pod.Name
	}
	readyUIDs := map[string]bool{}
	for i := range slices.Items {
		for _, ep := range slices.Items[i].Endpoints {
			if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" && ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				if ep.TargetRef.Name != nameByUID[string(ep.TargetRef.UID)] || len(ep.Addresses) != 1 || ep.Addresses[0] != ipByUID[string(ep.TargetRef.UID)] {
					return Live{}, errors.New("agent-deny EndpointSlice Pod address differs")
				}
				readyUIDs[string(ep.TargetRef.UID)] = true
			}
		}
	}
	if !readyUIDs[targetUID] {
		return Live{}, errors.New("agent-deny target Pod absent from Service endpoints")
	}
	sort.Slice(result.Pods, func(i, j int) bool { return result.Pods[i].UID < result.Pods[j].UID })
	return result, nil
}

// podMountsGuard verifies the Pod has the deny-guard ConfigMap mounted read-only at the
// contract mount path, so a deny the actuator writes reaches this Pod's app.
func podMountsGuard(p *corev1.Pod) bool {
	guardVolume := ""
	for _, v := range p.Spec.Volumes {
		if v.ConfigMap != nil && v.ConfigMap.Name == GuardConfigMapName {
			guardVolume = v.Name
		}
	}
	if guardVolume == "" {
		return false
	}
	for _, c := range p.Spec.Containers {
		for _, m := range c.VolumeMounts {
			if m.Name == guardVolume && m.ReadOnly && m.MountPath == GuardMountPath {
				return true
			}
		}
	}
	return false
}
