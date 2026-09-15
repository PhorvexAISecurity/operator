package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const demoRouteKey = "phorvex.ai/route-key"

// An observation error is distinct from a false postcondition.
func demoUIDGone(ctx context.Context, r client.Reader, namespace, name string, uid types.UID) (bool, error) {
	var pod corev1.Pod
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &pod)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return pod.UID != uid, nil
}

func demoQuarantine(ctx context.Context, r client.Reader, before *corev1.Pod) (bool, error) {
	var pod corev1.Pod
	if err := r.Get(ctx, client.ObjectKeyFromObject(before), &pod); err != nil {
		return false, err
	}
	if pod.UID != before.UID || pod.DeletionTimestamp != nil || pod.Labels["phorvex.ai/quarantined"] != string(before.UID) {
		return false, nil
	}
	// Controller selector labels must be detached, not merely an ownerRef removed.
	if len(before.OwnerReferences) > 0 && (len(pod.OwnerReferences) != 0 || pod.Labels["app"] == before.Labels["app"]) {
		return false, nil
	}
	name := fmt.Sprintf("phorvex-quarantine-%x", sha256.Sum256([]byte(before.UID)))
	var np networkingv1.NetworkPolicy
	if err := r.Get(ctx, client.ObjectKey{Namespace: before.Namespace, Name: name}, &np); err != nil {
		return false, err
	}
	if np.UID == "" || len(np.OwnerReferences) != 1 || np.OwnerReferences[0].UID != before.UID || np.OwnerReferences[0].APIVersion != "v1" || np.OwnerReferences[0].Kind != "Pod" || np.OwnerReferences[0].Name != before.Name || np.Labels["app.kubernetes.io/managed-by"] != "phorvex" || np.Labels["phorvex.ai/quarantine-of"] != before.Name || len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 || len(np.Spec.PodSelector.MatchExpressions) != 0 || !reflect.DeepEqual(np.Spec.PodSelector.MatchLabels, map[string]string{"phorvex.ai/quarantined": string(before.UID)}) {
		return false, nil
	}
	typesSeen := map[networkingv1.PolicyType]bool{}
	for _, t := range np.Spec.PolicyTypes {
		typesSeen[t] = true
	}
	return len(typesSeen) == 2 && typesSeen[networkingv1.PolicyTypeIngress] && typesSeen[networkingv1.PolicyTypeEgress], nil
}

func demoQuarantineRolledBack(ctx context.Context, r client.Reader, before *corev1.Pod) (bool, error) {
	var pod corev1.Pod
	if err := r.Get(ctx, client.ObjectKeyFromObject(before), &pod); err != nil {
		return false, err
	}
	if pod.UID != before.UID || !reflect.DeepEqual(pod.Labels, before.Labels) || !reflect.DeepEqual(pod.OwnerReferences, before.OwnerReferences) {
		return false, nil
	}
	name := fmt.Sprintf("phorvex-quarantine-%x", sha256.Sum256([]byte(before.UID)))
	var np networkingv1.NetworkPolicy
	err := r.Get(ctx, client.ObjectKey{Namespace: before.Namespace, Name: name}, &np)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// Capacity is a precondition, not an after-effect claim: the scalar restitch
// deliberately pins the Service to the selected target.
func demoRouteRestitched(ctx context.Context, r client.Reader, before *corev1.Pod, service string) (bool, error) {
	var pod corev1.Pod
	if err := r.Get(ctx, client.ObjectKeyFromObject(before), &pod); err != nil {
		return false, err
	}
	var svc corev1.Service
	if err := r.Get(ctx, client.ObjectKey{Namespace: before.Namespace, Name: service}, &svc); err != nil {
		return false, err
	}
	key := pod.Labels[demoRouteKey]
	if pod.UID != before.UID || key == "" || key == before.Labels[demoRouteKey] || svc.Spec.Selector[demoRouteKey] != key {
		return false, nil
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(before.Namespace), client.MatchingLabels(svc.Spec.Selector)); err != nil {
		return false, err
	}
	ready := 0
	targetReady := false
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil {
			continue
		}
		for _, condition := range p.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				ready++
				if p.UID == before.UID {
					targetReady = true
				}
				break
			}
		}
	}
	return ready >= 1 && targetReady, nil
}

func demoReadySelected(ctx context.Context, r client.Reader, svc *corev1.Service) (int, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(svc.Namespace), client.MatchingLabels(svc.Spec.Selector)); err != nil {
		return 0, err
	}
	ready := 0
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil {
			continue
		}
		for _, condition := range p.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				ready++
				break
			}
		}
	}
	return ready, nil
}

func demoReceiptFinished(ctx context.Context, r client.Reader, journalNS, kind, policyUID, targetUID string) (bool, error) {
	digest := sha256.Sum256([]byte(kind + "/" + policyUID + "/" + targetUID))
	name := fmt.Sprintf("phorvex-operation-%x", digest[:20])
	var cm corev1.ConfigMap
	err := r.Get(ctx, client.ObjectKey{Namespace: journalNS, Name: name}, &cm)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}
