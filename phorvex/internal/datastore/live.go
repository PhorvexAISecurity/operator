package datastore

import (
	"context"
	"errors"
	"sort"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Pod is one serving datastore Pod that reflects the operator-owned store ConfigMap.
type Pod struct{ Name, UID, IP string }

// Live is the authoritative, boundary-read view of the datastore: the app-facing store
// ConfigMap identity + its current canonical sha, the operator-owned trusted snapshot
// (content + recomputed canonical sha), the Service, and the serving Pods. The actuator
// CASes the store ConfigMap by StoreUID/StoreRV and restores it from TrustedContent.
type Live struct {
	ServiceUID     string
	StoreUID       string
	StoreRV        string
	TrustedUID     string
	CurrentSHA     string // canonical sha256 of the live store content
	TrustedSHA     string // canonical sha256 of the trusted snapshot content (RECOMPUTED, not the stored label)
	TrustedContent []byte // the operator-owned known-good bytes to restore
	Pods           []Pod
}

// ValidateLive reads the live datastore boundary in the given namespace (parametric; never a
// hard-coded literal). It requires: the Service (app=rag-store on ServingPort); the app-facing
// store ConfigMap; the SEPARATE operator-owned trusted-snapshot ConfigMap whose content's
// recomputed canonical sha equals its own recorded sha label (so a tampered snapshot cannot
// defeat the oracle); and at least one Ready serving Pod cross-checked against the Service
// EndpointSlices, with the target among them.
func ValidateLive(ctx context.Context, r client.Reader, namespace, targetUID string) (Live, error) {
	if r == nil || namespace == "" || targetUID == "" {
		return Live{}, errors.New("datastore reader, namespace or Pod identity absent")
	}
	svc := &corev1.Service{}
	if e := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ServiceName}, svc); e != nil {
		return Live{}, e
	}
	if svc.DeletionTimestamp != nil || string(svc.UID) == "" || len(svc.Spec.Selector) != 1 || svc.Spec.Selector[AppLabel] != AppLabelValue {
		return Live{}, errors.New("datastore Service selector/identity differs")
	}
	portOK := false
	for _, p := range svc.Spec.Ports {
		if p.Port == ServingPort && p.TargetPort.Type == intstr.Int && p.TargetPort.IntVal == ServingPort {
			portOK = true
		}
	}
	if len(svc.Spec.Ports) != 1 || !portOK {
		return Live{}, errors.New("datastore app is not the Service target on serving port")
	}

	store := &corev1.ConfigMap{}
	if e := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: StoreConfigMapName}, store); e != nil {
		return Live{}, e
	}
	if store.DeletionTimestamp != nil || store.UID == "" {
		return Live{}, errors.New("datastore store ConfigMap identity differs")
	}
	currentSHA, e := CanonicalSHA([]byte(store.Data[StoreKey]))
	if e != nil {
		return Live{}, errors.New("datastore live content unparseable: " + e.Error())
	}

	trusted := &corev1.ConfigMap{}
	if e := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: TrustedSnapshotConfigMapName}, trusted); e != nil {
		return Live{}, e
	}
	if trusted.DeletionTimestamp != nil || trusted.UID == "" || trusted.UID == store.UID {
		return Live{}, errors.New("datastore trusted-snapshot ConfigMap identity differs")
	}
	trustedContent := []byte(trusted.Data[TrustedContentKey])
	trustedSHA, e := CanonicalSHA(trustedContent)
	if e != nil {
		return Live{}, errors.New("datastore trusted snapshot unparseable: " + e.Error())
	}
	// RECOMPUTE: never trust the recorded sha label blindly. The operator-owned snapshot's
	// content must hash to its own recorded label, or the trusted baseline is not credible.
	if label := trusted.Data[TrustedSHAKey]; !ValidSHA(label) || label != trustedSHA {
		return Live{}, errors.New("datastore trusted snapshot sha label does not match its content")
	}

	var pods corev1.PodList
	if e := r.List(ctx, &pods, client.InNamespace(namespace), client.MatchingLabels{AppLabel: AppLabelValue}); e != nil {
		return Live{}, e
	}
	if len(pods.Items) == 0 {
		return Live{}, errors.New("datastore has no serving Pods")
	}
	result := Live{ServiceUID: string(svc.UID), StoreUID: string(store.UID), StoreRV: store.ResourceVersion,
		TrustedUID: string(trusted.UID), CurrentSHA: currentSHA, TrustedSHA: trustedSHA, TrustedContent: trustedContent}
	seen := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.DeletionTimestamp != nil || p.UID == "" || p.Status.PodIP == "" || seen[string(p.UID)] {
			return Live{}, errors.New("datastore Pod lifetime differs")
		}
		seen[string(p.UID)] = true
		ready := false
		for _, status := range p.Status.ContainerStatuses {
			if status.Ready {
				ready = true
			}
		}
		if !ready {
			return Live{}, errors.New("datastore serving Pod not Ready")
		}
		result.Pods = append(result.Pods, Pod{Name: p.Name, UID: string(p.UID), IP: p.Status.PodIP})
	}
	if !seen[targetUID] {
		return Live{}, errors.New("datastore target UID absent from serving Pods")
	}
	var slices discoveryv1.EndpointSliceList
	if e := r.List(ctx, &slices, client.InNamespace(namespace), client.MatchingLabels{discoveryv1.LabelServiceName: ServiceName}); e != nil {
		return Live{}, e
	}
	if len(slices.Items) == 0 {
		return Live{}, errors.New("datastore EndpointSlice inventory absent")
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
					return Live{}, errors.New("datastore EndpointSlice Pod address differs")
				}
				readyUIDs[string(ep.TargetRef.UID)] = true
			}
		}
	}
	if !readyUIDs[targetUID] {
		return Live{}, errors.New("datastore target Pod absent from Service endpoints")
	}
	sort.Slice(result.Pods, func(i, j int) bool { return result.Pods[i].UID < result.Pods[j].UID })
	return result, nil
}
