package ingest

import (
	"context"
	"errors"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

// workloadSpecObservation receives a read-only view of this tick's existing owner-read cache. A nil
// reader (including Phoenix-only observations) stays explicitly unavailable;
// this observability extension never silently broadens the reader's authority.
func workloadSpecObservation(ctx context.Context, r client.Reader, pod *corev1.Pod, now time.Time) model.WorkloadSpecObservation {
	out := model.WorkloadSpecObservation{Source: "controller-spec", ObservedAt: now}
	deny := func(reason string) model.WorkloadSpecObservation { out.Reason = reason; return out }
	if pod == nil || pod.UID == "" || pod.Namespace == "" || pod.DeletionTimestamp != nil {
		return deny("pod-identity-unavailable")
	}
	out.PodUID = string(pod.UID)
	if r == nil {
		return deny("owner-reader-unavailable")
	}
	owner, ok := singleController(pod.OwnerReferences)
	if !ok {
		return deny("controller-identity-unavailable")
	}
	out.Controller = model.ObjectIdentity{APIVersion: owner.APIVersion, Kind: owner.Kind, Namespace: pod.Namespace, Name: owner.Name, UID: string(owner.UID)}
	object, replicas, reason := readReplicaSpec(ctx, r, pod.Namespace, owner)
	if reason != "" {
		return deny(reason)
	}
	if owner.Kind == "ReplicaSet" {
		if len(object.GetOwnerReferences()) > 0 {
			parent, valid := singleController(object.GetOwnerReferences())
			if !valid || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" {
				return deny("replicaset-stable-owner-unavailable")
			}
			owner = parent
			object, replicas, reason = readReplicaSpec(ctx, r, pod.Namespace, owner)
			if reason != "" {
				return deny(reason)
			}
		}
	} else if len(object.GetOwnerReferences()) > 0 {
		// This bounded reader does not invent another controller-chain mapping.
		return deny("workload-parent-unsupported")
	}
	if replicas == nil || *replicas < 0 {
		return deny("workload-spec-replicas-unavailable")
	}
	if object.GetResourceVersion() == "" {
		return deny("workload-resource-version-unavailable")
	}
	out.Known = true
	out.Workload = model.ObjectIdentity{APIVersion: owner.APIVersion, Kind: owner.Kind, Namespace: pod.Namespace, Name: owner.Name, UID: string(owner.UID)}
	out.ResourceVersion, out.Generation, out.SpecReplicas = object.GetResourceVersion(), object.GetGeneration(), *replicas
	return out
}

func singleController(refs []metav1.OwnerReference) (metav1.OwnerReference, bool) {
	var found metav1.OwnerReference
	count := 0
	for _, ref := range refs {
		if ref.Controller != nil && *ref.Controller {
			found = ref
			count++
		}
	}
	return found, count == 1 && found.UID != "" && found.Name != "" && found.Kind != "" && found.APIVersion != ""
}

func readReplicaSpec(ctx context.Context, r client.Reader, namespace string, ref metav1.OwnerReference) (client.Object, *int32, string) {
	var object client.Object
	switch {
	case ref.APIVersion == "apps/v1" && ref.Kind == "Deployment":
		object = &appsv1.Deployment{}
	case ref.APIVersion == "apps/v1" && ref.Kind == "ReplicaSet":
		object = &appsv1.ReplicaSet{}
	case ref.APIVersion == "apps/v1" && ref.Kind == "StatefulSet":
		object = &appsv1.StatefulSet{}
	case ref.APIVersion == "v1" && ref.Kind == "ReplicationController":
		object = &corev1.ReplicationController{}
	default:
		return nil, nil, "workload-kind-has-no-supported-replica-spec"
	}
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, object); err != nil {
		if errors.Is(err, errOwnerObjectNotObserved) {
			return nil, nil, "owner-object-not-observed"
		}
		return nil, nil, "workload-object-unavailable"
	}
	if object.GetUID() != ref.UID || object.GetDeletionTimestamp() != nil {
		return nil, nil, "workload-identity-stale"
	}
	var replicas *int32
	switch typed := object.(type) {
	case *appsv1.Deployment:
		replicas = typed.Spec.Replicas
	case *appsv1.ReplicaSet:
		replicas = typed.Spec.Replicas
	case *appsv1.StatefulSet:
		replicas = typed.Spec.Replicas
	case *corev1.ReplicationController:
		replicas = typed.Spec.Replicas
	}
	return object, replicas, ""
}
