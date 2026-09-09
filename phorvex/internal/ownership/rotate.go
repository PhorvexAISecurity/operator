// Package ownership validates the supported replacement lifecycle for native rotate.
package ownership

import (
	"context"
	"github.com/phorvex/phorvex/internal/model"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Check supports ReplicaSets (including Deployment-owned sets) and legacy
// ReplicationControllers. Other lifecycles remain explicitly unsupported. This
// establishes current eligibility, never a guarantee of subsequent replacement.
func Check(ctx context.Context, r client.Reader, p *corev1.Pod) model.RotationOwnership {
	deny := func(reason string) model.RotationOwnership { return model.RotationOwnership{Reason: reason} }
	if p == nil {
		return deny("target-unavailable")
	}
	if _, ok := p.Annotations[corev1.MirrorPodAnnotationKey]; ok {
		return deny("mirror-pod")
	}
	if !p.DeletionTimestamp.IsZero() {
		return deny("target-terminating")
	}
	o := metav1.GetControllerOf(p)
	if o == nil {
		return deny("ownerless")
	}
	if o.UID == "" || o.Name == "" || r == nil {
		return deny("owner-unresolved")
	}
	key := client.ObjectKey{Namespace: p.Namespace, Name: o.Name}
	var owner client.Object
	var selector labels.Selector
	var desired, actual int32
	switch {
	case o.APIVersion == "apps/v1" && o.Kind == "ReplicaSet":
		rs := &appsv1.ReplicaSet{}
		if err := r.Get(ctx, key, rs); err != nil {
			return deny("owner-unresolved")
		}
		owner = rs
		actual = rs.Status.Replicas
		if rs.Spec.Replicas != nil {
			desired = *rs.Spec.Replicas
		}
		var err error
		selector, err = metav1.LabelSelectorAsSelector(rs.Spec.Selector)
		if err != nil || rs.Spec.Selector == nil {
			return deny("owner-state-ineligible")
		}
		if parent := metav1.GetControllerOf(rs); parent != nil {
			if parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" {
				return deny("owner-kind-unsupported")
			}
			d := &appsv1.Deployment{}
			if err := r.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: parent.Name}, d); err != nil {
				return deny("owner-unresolved")
			}
			if parent.UID == "" || d.UID != parent.UID {
				return deny("owner-uid-mismatch")
			}
			if !d.DeletionTimestamp.IsZero() {
				return deny("owner-terminating")
			}
			if d.Spec.Replicas == nil || *d.Spec.Replicas <= 0 || d.Spec.Paused {
				return deny("owner-state-ineligible")
			}
		}
	case o.APIVersion == "v1" && o.Kind == "ReplicationController":
		rc := &corev1.ReplicationController{}
		if err := r.Get(ctx, key, rc); err != nil {
			return deny("owner-unresolved")
		}
		owner = rc
		actual = rc.Status.Replicas
		if rc.Spec.Replicas != nil {
			desired = *rc.Spec.Replicas
		}
		if len(rc.Spec.Selector) == 0 {
			return deny("owner-state-ineligible")
		}
		selector = labels.SelectorFromSet(rc.Spec.Selector)
		if metav1.GetControllerOf(rc) != nil {
			return deny("owner-kind-unsupported")
		}
	default:
		return deny("owner-kind-unsupported")
	}
	if owner.GetUID() != o.UID {
		return deny("owner-uid-mismatch")
	}
	if !owner.GetDeletionTimestamp().IsZero() {
		return deny("owner-terminating")
	}
	if desired <= 0 || actual > desired || !selector.Matches(labels.Set(p.Labels)) {
		return deny("owner-state-ineligible")
	}
	return model.RotationOwnership{Eligible: true, OwnerUID: string(o.UID), OwnerResourceVersion: owner.GetResourceVersion()}
}
