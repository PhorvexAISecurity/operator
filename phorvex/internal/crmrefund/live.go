package crmrefund

import (
	"context"
	"errors"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Pod is one serving mini-CRM Pod that mounts the operator-owned deny-guard.
type Pod struct{ Name, UID, IP string }

// Live is the authoritative, boundary-read view of the CRM deny-guard: the guard
// ConfigMap identity + its current ledger, the Service, and the serving Pods that
// mount the guard. The actuator CASes the guard ConfigMap by GuardUID/GuardRV.
type Live struct {
	ServiceUID string
	GuardUID   string
	GuardRV    string
	State      Guard
	Pods       []Pod
}

// ValidateLive reads the live CRM deny-guard boundary. Unlike the LiteLLM gateway there
// is no sidecar: the mini-CRM app re-reads the guard ConfigMap mounted read-only at
// GuardMountPath. It requires the reviewed Service (app=crm on 8080), the guard ConfigMap,
// and exactly the two serving Pods, each Ready and mounting the guard, with the target and
// (when given) peer among them.
func ValidateLive(ctx context.Context, r client.Reader, targetUID, peerUID string) (Live, error) {
	if r == nil || targetUID == "" || (peerUID != "" && targetUID == peerUID) {
		return Live{}, errors.New("crm-refund reader or Pod identity absent")
	}
	svc := &corev1.Service{}
	if e := r.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: ServiceName}, svc); e != nil {
		return Live{}, e
	}
	if svc.DeletionTimestamp != nil || string(svc.UID) == "" || len(svc.Spec.Selector) != 1 || svc.Spec.Selector["app"] != "crm" {
		return Live{}, errors.New("crm-refund Service selector/identity differs")
	}
	portOK := false
	for _, p := range svc.Spec.Ports {
		if p.Port == 8080 && p.TargetPort.Type == intstr.Int && p.TargetPort.IntVal == 8080 {
			portOK = true
		}
	}
	if len(svc.Spec.Ports) != 1 || !portOK {
		return Live{}, errors.New("crm-refund app is not the Service target on 8080")
	}
	guard := &corev1.ConfigMap{}
	if e := r.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: GuardConfigMapName}, guard); e != nil {
		return Live{}, e
	}
	if guard.DeletionTimestamp != nil || guard.UID == "" {
		return Live{}, errors.New("crm-refund guard ConfigMap identity differs")
	}
	// The app-facing denied.json is always present; the operator ledger (StateKey) is absent
	// until the first revoke. An absent/empty ledger is the canonical empty guard.
	state := Guard{Version: 2, Entries: []Entry{}}
	if raw := guard.Data[StateKey]; raw != "" {
		parsed, e := ParseState(raw)
		if e != nil {
			return Live{}, e
		}
		state = parsed
	}
	// The app-facing bytes must already agree with the ledger, or an out-of-band writer
	// touched the guard and the actuator must not build on it.
	if guard.Data[GuardKey] != "" && guard.Data[GuardKey] != state.EncodeAppGuard() {
		return Live{}, errors.New("crm-refund app guard and operator ledger disagree")
	}
	var pods corev1.PodList
	if e := r.List(ctx, &pods, client.InNamespace(Namespace), client.MatchingLabels{"app": "crm"}); e != nil {
		return Live{}, e
	}
	if len(pods.Items) != 2 {
		return Live{}, fmt.Errorf("crm-refund requires exactly two serving Pods; got %d", len(pods.Items))
	}
	result := Live{ServiceUID: string(svc.UID), GuardUID: string(guard.UID), GuardRV: guard.ResourceVersion, State: state}
	seen := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil || p.UID == "" || p.Status.PodIP == "" || seen[string(p.UID)] {
			return Live{}, errors.New("crm-refund Pod lifetime differs")
		}
		seen[string(p.UID)] = true
		if !podMountsGuard(p, string(guard.UID)) {
			return Live{}, errors.New("crm-refund serving Pod does not mount the exact deny-guard read-only")
		}
		ready := false
		for _, status := range p.Status.ContainerStatuses {
			if status.Ready {
				ready = true
			}
		}
		if !ready {
			return Live{}, errors.New("crm-refund serving Pod not Ready")
		}
		result.Pods = append(result.Pods, Pod{Name: p.Name, UID: string(p.UID), IP: p.Status.PodIP})
	}
	if !seen[targetUID] || (peerUID != "" && !seen[peerUID]) {
		return Live{}, errors.New("crm-refund target/peer UID differs")
	}
	var slices discoveryv1.EndpointSliceList
	if e := r.List(ctx, &slices, client.InNamespace(Namespace), client.MatchingLabels{discoveryv1.LabelServiceName: ServiceName}); e != nil {
		return Live{}, e
	}
	if len(slices.Items) == 0 {
		return Live{}, errors.New("crm-refund EndpointSlice inventory absent")
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
					return Live{}, errors.New("crm-refund EndpointSlice Pod address differs")
				}
				readyUIDs[string(ep.TargetRef.UID)] = true
			}
		}
	}
	if len(readyUIDs) != 2 || !readyUIDs[targetUID] || (peerUID != "" && !readyUIDs[peerUID]) {
		return Live{}, errors.New("crm-refund Service endpoint Pod set differs")
	}
	sort.Slice(result.Pods, func(i, j int) bool { return result.Pods[i].UID < result.Pods[j].UID })
	return result, nil
}

// podMountsGuard verifies the Pod has the deny-guard ConfigMap mounted read-only at the
// contract mount path, so a revoke the actuator writes reaches this Pod's app.
func podMountsGuard(p *corev1.Pod, guardUID string) bool {
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
