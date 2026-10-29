package statefulrotation

import (
	"context"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/model"
)

// The CSI snapshot API is consumed unstructured: the operator does not vendor the external
// snapshotter client, and the API may legitimately be absent from a cluster.
var (
	VolumeSnapshotGVK      = schema.GroupVersionKind{Group: "snapshot.storage.k8s.io", Version: "v1", Kind: "VolumeSnapshot"}
	VolumeSnapshotClassGVK = schema.GroupVersionKind{Group: "snapshot.storage.k8s.io", Version: "v1", Kind: "VolumeSnapshotClass"}
)

// OwnerStatefulSet returns the Pod's controlling StatefulSet reference, or nil.
func OwnerStatefulSet(p *corev1.Pod) *metav1.OwnerReference {
	o := metav1.GetControllerOf(p)
	if o == nil || o.APIVersion != appsv1.SchemeGroupVersion.String() || o.Kind != "StatefulSet" {
		return nil
	}
	return o
}

// Observe reads the authoritative witness for one Pod. It returns nil when the Pod is not
// controlled by a StatefulSet or the owner declares no contract, so undeclared workloads
// carry no observation at all. Any failed read yields Complete=false with the reason.
func Observe(ctx context.Context, r client.Reader, p *corev1.Pod) *model.StatefulRotationObservation {
	ref := OwnerStatefulSet(p)
	if ref == nil || r == nil {
		return nil
	}
	sts := &appsv1.StatefulSet{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: ref.Name}, sts); err != nil {
		// Without the owner its declaration is unknown; report it only as incomplete.
		return &model.StatefulRotationObservation{OwnerName: ref.Name, Reason: "owner unreadable"}
	}
	if !Declared(sts.Annotations) {
		return nil
	}
	o := &model.StatefulRotationObservation{OwnerName: sts.Name, OwnerUID: string(sts.UID), OwnerResourceVersion: sts.ResourceVersion}
	contract, err := ParseContract(sts.Annotations)
	if err != nil {
		o.Invalid = err.Error()
		return o
	}
	o.Contract = contract
	if sts.UID != ref.UID {
		o.Reason = "owner UID differs from the Pod's controller reference"
		return o
	}
	if !sts.DeletionTimestamp.IsZero() {
		o.Reason = "owner terminating"
		return o
	}
	if !p.DeletionTimestamp.IsZero() {
		o.Reason = "target terminating"
		return o
	}
	if sts.Spec.Replicas != nil {
		o.Replicas = int(*sts.Spec.Replicas)
	}
	o.ReadyReplicas = int(sts.Status.ReadyReplicas)
	o.RolloutInProgress = sts.Status.ObservedGeneration < sts.Generation ||
		sts.Status.CurrentRevision == "" || sts.Status.CurrentRevision != sts.Status.UpdateRevision
	o.Leader = contract.LeaderLabelKey != "" && p.Labels[contract.LeaderLabelKey] == contract.LeaderLabelValue

	templates := map[string]bool{}
	for _, t := range sts.Spec.VolumeClaimTemplates {
		templates[t.Name+"-"+p.Name] = true
	}
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim == nil {
			continue
		}
		pvc := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: v.PersistentVolumeClaim.ClaimName}, pvc); err != nil {
			o.Reason = "claim " + v.PersistentVolumeClaim.ClaimName + " unreadable"
			return o
		}
		o.Claims = append(o.Claims, model.StatefulClaim{
			Name: pvc.Name, UID: string(pvc.UID),
			Bound:        pvc.Status.Phase == corev1.ClaimBound,
			Terminating:  !pvc.DeletionTimestamp.IsZero(),
			FromTemplate: templates[pvc.Name],
		})
	}
	if contract.SnapshotClass != "" {
		class := &unstructured.Unstructured{}
		class.SetGroupVersionKind(VolumeSnapshotClassGVK)
		o.SnapshotClassReady = r.Get(ctx, client.ObjectKey{Name: contract.SnapshotClass}, class) == nil
	}
	o.Complete = true
	return o
}

// PodReady reports the Pod's Ready condition.
func PodReady(p *corev1.Pod) bool {
	if p == nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
