package ownership

import (
	"context"
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

func objectIdentity(apiVersion, kind, namespace, name string, uid types.UID) model.ObjectIdentity {
	return model.ObjectIdentity{APIVersion: apiVersion, Kind: kind, Namespace: namespace, Name: name, UID: string(uid)}
}

func exactController(refs []metav1.OwnerReference) (*metav1.OwnerReference, error) {
	var found *metav1.OwnerReference
	for i := range refs {
		if refs[i].Controller == nil || !*refs[i].Controller {
			continue
		}
		if found != nil {
			return nil, errors.New("multiple controlling owners")
		}
		copy := refs[i]
		found = &copy
	}
	if found == nil || found.UID == "" || found.Name == "" || found.APIVersion == "" || found.Kind == "" {
		return nil, errors.New("controlling owner identity unavailable")
	}
	return found, nil
}

// ResolveStableWorkloadOwner performs authoritative UID-bound reads. The
// immediate controller is retained separately from the stable owner: a
// ReplicaSet UID is never treated as a Deployment UID.
func ResolveStableWorkloadOwner(ctx context.Context, r client.Reader, namespace, podName, podUID string) (model.ObjectIdentity, model.ObjectIdentity, error) {
	if r == nil || namespace == "" || podName == "" || podUID == "" {
		return model.ObjectIdentity{}, model.ObjectIdentity{}, errors.New("workload owner input unavailable")
	}
	var pod corev1.Pod
	if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: podName}, &pod); err != nil {
		return model.ObjectIdentity{}, model.ObjectIdentity{}, fmt.Errorf("read target pod: %w", err)
	}
	if string(pod.UID) != podUID || pod.DeletionTimestamp != nil {
		return model.ObjectIdentity{}, model.ObjectIdentity{}, errors.New("target pod identity is stale")
	}
	owner, err := exactController(pod.OwnerReferences)
	if err != nil {
		return model.ObjectIdentity{}, model.ObjectIdentity{}, err
	}
	immediate := objectIdentity(owner.APIVersion, owner.Kind, namespace, owner.Name, owner.UID)
	switch {
	case owner.APIVersion == appsv1.SchemeGroupVersion.String() && owner.Kind == "ReplicaSet":
		var rs appsv1.ReplicaSet
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: owner.Name}, &rs); err != nil {
			return model.ObjectIdentity{}, model.ObjectIdentity{}, fmt.Errorf("read replica set: %w", err)
		}
		if rs.UID != owner.UID || rs.DeletionTimestamp != nil {
			return model.ObjectIdentity{}, model.ObjectIdentity{}, errors.New("replica set identity is stale")
		}
		deployment, err := exactController(rs.OwnerReferences)
		if err != nil || deployment.APIVersion != appsv1.SchemeGroupVersion.String() || deployment.Kind != "Deployment" {
			return model.ObjectIdentity{}, model.ObjectIdentity{}, errors.New("replica set stable deployment owner unavailable")
		}
		var dep appsv1.Deployment
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: deployment.Name}, &dep); err != nil {
			return model.ObjectIdentity{}, model.ObjectIdentity{}, fmt.Errorf("read deployment: %w", err)
		}
		if dep.UID != deployment.UID || dep.DeletionTimestamp != nil {
			return model.ObjectIdentity{}, model.ObjectIdentity{}, errors.New("deployment identity is stale")
		}
		return immediate, objectIdentity(deployment.APIVersion, deployment.Kind, namespace, deployment.Name, deployment.UID), nil
	case owner.APIVersion == appsv1.SchemeGroupVersion.String() && owner.Kind == "StatefulSet":
		var sts appsv1.StatefulSet
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: owner.Name}, &sts); err != nil {
			return model.ObjectIdentity{}, model.ObjectIdentity{}, fmt.Errorf("read stateful set: %w", err)
		}
		if sts.UID != owner.UID || sts.DeletionTimestamp != nil {
			return model.ObjectIdentity{}, model.ObjectIdentity{}, errors.New("stateful set identity is stale")
		}
		return immediate, immediate, nil
	case owner.APIVersion == appsv1.SchemeGroupVersion.String() && owner.Kind == "DaemonSet":
		var ds appsv1.DaemonSet
		if err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: owner.Name}, &ds); err != nil {
			return model.ObjectIdentity{}, model.ObjectIdentity{}, fmt.Errorf("read daemon set: %w", err)
		}
		if ds.UID != owner.UID || ds.DeletionTimestamp != nil {
			return model.ObjectIdentity{}, model.ObjectIdentity{}, errors.New("daemon set identity is stale")
		}
		return immediate, immediate, nil
	default:
		return model.ObjectIdentity{}, model.ObjectIdentity{}, fmt.Errorf("unsupported stable workload owner %s %s", owner.APIVersion, owner.Kind)
	}
}
