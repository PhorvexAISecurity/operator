// Package persistence owns the conservative, shared controller-removal predicates.
// Every inventory read is authoritative; an incomplete read is never an empty inventory.
package persistence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

const (
	Annotation       = "phorvex.ai/persistence-observation-v1"
	ExemptAnnotation = "phorvex.ai/persistence-exempt"
	InventoryName    = "phorvex-persistence-inventory"
	Horizon          = 15 * time.Minute
	Source           = "PhorvexPersistenceObserver"
)

// Assertion includes an explicit zero (a missing JSON floor is not zero authority),
// immutable old/new child identities, and the selecting policy epoch.
type Assertion struct {
	ControllerName            string    `json:"controllerName"`
	OwnerKind                 string    `json:"ownerKind"`
	Namespace                 string    `json:"namespace"`
	OwnerDeclaredMinAvailable *int      `json:"ownerDeclaredMinAvailable"`
	Unmanaged                 bool      `json:"unmanaged"`
	NoLegitimateServiceRole   bool      `json:"noLegitimateServiceRole"`
	ObservedRecreation        bool      `json:"observedRecreation"`
	PolicyName                string    `json:"policyName"`
	PolicyUID                 string    `json:"policyUID"`
	PolicyGeneration          int64     `json:"policyGeneration"`
	TargetPodUID              string    `json:"targetPodUID"`
	RemovedPodUID             string    `json:"removedPodUID"`
	ReplacementPodUID         string    `json:"replacementPodUID"`
	ObservedAt                time.Time `json:"observedAt"`
	Replicas                  int       `json:"replicas"`
}

func Decode(raw string) (Assertion, error) {
	var a Assertion
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		return a, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return a, fmt.Errorf("trailing assertion data")
	}
	if a.ControllerName == "" || a.Namespace == "" || !SupportedKind(a.OwnerKind) || a.OwnerDeclaredMinAvailable == nil || *a.OwnerDeclaredMinAvailable != 0 || !a.Unmanaged || !a.NoLegitimateServiceRole || !a.ObservedRecreation || a.PolicyName == "" || a.PolicyUID == "" || a.PolicyGeneration <= 0 || a.TargetPodUID == "" || a.RemovedPodUID == "" || a.ReplacementPodUID == "" || a.RemovedPodUID == a.ReplacementPodUID || a.ObservedAt.IsZero() || a.Replicas <= 0 {
		return a, fmt.Errorf("incomplete controller persistence assertion")
	}
	return a, nil
}
func SupportedKind(k string) bool {
	return k == "Deployment" || k == "ReplicaSet" || k == "StatefulSet"
}
func Fresh(observed, now time.Time) bool {
	return !observed.IsZero() && !observed.After(now) && now.Sub(observed) < Horizon
}

// Owner always denotes the top supported owner. A Deployment's child ReplicaSet
// is never independently stoppable (the Deployment would restore it).
type Owner struct {
	Object             client.Object
	Kind               string
	Selector           *metav1.LabelSelector
	TemplateLabels     map[string]string
	Desired            int32
	Ready              int32
	ObservedGeneration int64
}

func ReadOwner(ctx context.Context, r client.Reader, ns, kind, name string) (Owner, error) {
	var o Owner
	o.Kind = kind
	key := client.ObjectKey{Namespace: ns, Name: name}
	switch kind {
	case "Deployment":
		v := &appsv1.Deployment{}
		if err := r.Get(ctx, key, v); err != nil {
			return o, err
		}
		o.Object = v
		o.Selector = v.Spec.Selector
		o.TemplateLabels = v.Spec.Template.Labels
		o.Ready = v.Status.ReadyReplicas
		o.ObservedGeneration = v.Status.ObservedGeneration
		if v.Spec.Replicas == nil || v.Spec.Paused {
			return o, fmt.Errorf("owner replicas absent or Deployment paused")
		}
		o.Desired = *v.Spec.Replicas
	case "ReplicaSet":
		v := &appsv1.ReplicaSet{}
		if err := r.Get(ctx, key, v); err != nil {
			return o, err
		}
		o.Object = v
		o.Selector = v.Spec.Selector
		o.TemplateLabels = v.Spec.Template.Labels
		o.Ready = v.Status.ReadyReplicas
		o.ObservedGeneration = v.Status.ObservedGeneration
		if v.Spec.Replicas == nil {
			return o, fmt.Errorf("owner replicas absent")
		}
		o.Desired = *v.Spec.Replicas
	case "StatefulSet":
		v := &appsv1.StatefulSet{}
		if err := r.Get(ctx, key, v); err != nil {
			return o, err
		}
		o.Object = v
		o.Selector = v.Spec.Selector
		o.TemplateLabels = v.Spec.Template.Labels
		o.Ready = v.Status.ReadyReplicas
		o.ObservedGeneration = v.Status.ObservedGeneration
		if v.Spec.Replicas == nil {
			return o, fmt.Errorf("owner replicas absent")
		}
		o.Desired = *v.Spec.Replicas
	default:
		return o, fmt.Errorf("unsupported owner kind %q", kind)
	}
	if o.Object.GetUID() == "" || o.Object.GetResourceVersion() == "" || o.Object.GetDeletionTimestamp() != nil || o.Selector == nil || len(o.Selector.MatchLabels)+len(o.Selector.MatchExpressions) == 0 {
		return o, fmt.Errorf("owner identity or selector unavailable")
	}
	if metav1.GetControllerOf(o.Object) != nil {
		return o, fmt.Errorf("enclosing controller can recreate owner")
	}
	return o, nil
}
func ResolvePodOwner(ctx context.Context, r client.Reader, p *corev1.Pod) (Owner, error) {
	ref := metav1.GetControllerOf(p)
	if ref == nil || ref.APIVersion != "apps/v1" || !SupportedKind(ref.Kind) || ref.UID == "" {
		return Owner{}, fmt.Errorf("unsupported or missing Pod owner")
	}
	if ref.Kind == "ReplicaSet" {
		rs := &appsv1.ReplicaSet{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: ref.Name}, rs); err != nil {
			return Owner{}, err
		}
		if rs.UID != ref.UID {
			return Owner{}, fmt.Errorf("ReplicaSet UID changed")
		}
		if parent := metav1.GetControllerOf(rs); parent != nil {
			if parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" || parent.UID == "" {
				return Owner{}, fmt.Errorf("unsupported enclosing owner")
			}
			ref = parent
		}
	}
	o, err := ReadOwner(ctx, r, p.Namespace, ref.Kind, ref.Name)
	if err != nil {
		return o, err
	}
	sel, err := metav1.LabelSelectorAsSelector(o.Selector)
	if err != nil || o.Object.GetUID() != ref.UID || !sel.Matches(labels.Set(p.Labels)) {
		return o, fmt.Errorf("Pod owner UID or selector changed")
	}
	return o, nil
}

// Children uses owner references, never a label-only deletion set. Deployment
// membership follows exact ReplicaSet -> Deployment UIDs, including old revisions.
func Children(ctx context.Context, r client.Reader, o Owner) ([]corev1.Pod, error) {
	ns := o.Object.GetNamespace()
	ids := map[string]bool{string(o.Object.GetUID()): true}
	if o.Kind == "Deployment" {
		var sets appsv1.ReplicaSetList
		if err := r.List(ctx, &sets, client.InNamespace(ns)); err != nil {
			return nil, err
		}
		for _, rs := range sets.Items {
			if ref := metav1.GetControllerOf(&rs); ref != nil && ref.APIVersion == "apps/v1" && ref.Kind == "Deployment" && ref.UID == o.Object.GetUID() {
				ids[string(rs.UID)] = true
			}
		}
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	out := []corev1.Pod{}
	for _, p := range pods.Items {
		if ref := metav1.GetControllerOf(&p); ref != nil && ref.APIVersion == "apps/v1" && ids[string(ref.UID)] && ((o.Kind == "Deployment" && ref.Kind == "ReplicaSet") || ref.Kind == o.Kind) {
			out = append(out, p)
		}
	}
	return out, nil
}

// CheckUnmanaged first requires protected positive attacker CREATE provenance,
// then rejects every known legitimacy signal. Inventory must exist in
// the protected operator namespace and cover this namespace explicitly; an absent
// inventory fails closed. Controller annotations are an additional operator escape.
func CheckUnmanaged(ctx context.Context, r client.Reader, operatorNS string, o Owner) error {
	if r == nil || operatorNS == "" {
		return fmt.Errorf("protected desired-state inventory unavailable")
	}
	if err := CheckAttackerProvenance(ctx, r, operatorNS, o); err != nil {
		return err
	}
	m := o.Object
	if m.GetAnnotations()[ExemptAnnotation] != "" {
		return fmt.Errorf("explicitly exempt owner")
	}
	for k, v := range m.GetLabels() {
		if v != "" && (k == "app.kubernetes.io/managed-by" || strings.HasPrefix(k, "argocd.argoproj.io/") || strings.HasPrefix(k, "kustomize.toolkit.fluxcd.io/") || strings.HasPrefix(k, "helm.toolkit.fluxcd.io/")) {
			return fmt.Errorf("managed owner provenance")
		}
	}
	for k, v := range m.GetAnnotations() {
		if v != "" && (strings.HasPrefix(k, "meta.helm.sh/") || strings.HasPrefix(k, "argocd.argoproj.io/") || k == "kubectl.kubernetes.io/last-applied-configuration") {
			return fmt.Errorf("declared owner provenance")
		}
	}
	if len(m.GetOwnerReferences()) > 0 {
		return fmt.Errorf("operator-owned controller")
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, client.ObjectKey{Namespace: operatorNS, Name: InventoryName}, &cm); err != nil {
		return err
	}
	var inventory map[string][]string
	if err := json.Unmarshal([]byte(cm.Data["controllers.json"]), &inventory); err != nil {
		return fmt.Errorf("invalid desired-state inventory: %w", err)
	}
	entries, ok := inventory[m.GetNamespace()]
	if !ok {
		return fmt.Errorf("namespace absent from reviewed desired-state inventory")
	}
	key := o.Kind + "/" + m.GetName()
	for _, v := range entries {
		if v == key || v == "*" {
			return fmt.Errorf("owner present in declared desired state")
		}
	}
	return nil
}

// CheckSafety proves that no legitimate Service floor depends on these children.
// The reviewed inventory names legitimate controllers and Services. A mixed Service
// may lose attacker endpoints only when enough independently Ready legitimate UIDs
// remain. An attacker-only, unmanaged Service carries no legitimate guarantee.
func CheckSafety(ctx context.Context, r client.Reader, operatorNS string, o Owner, children []corev1.Pod, policyName string) error {
	if err := CheckUnmanaged(ctx, r, operatorNS, o); err != nil {
		return err
	}
	ns := o.Object.GetNamespace()
	sets := []labels.Set{labels.Set(o.TemplateLabels)}
	uids := map[string]bool{}
	for _, p := range children {
		sets = append(sets, labels.Set(p.Labels))
		uids[string(p.UID)] = true
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, client.ObjectKey{Namespace: operatorNS, Name: InventoryName}, &cm); err != nil {
		return err
	}
	var inventory map[string][]string
	if err := json.Unmarshal([]byte(cm.Data["controllers.json"]), &inventory); err != nil {
		return err
	}
	declared := map[string]bool{}
	for _, v := range inventory[ns] {
		declared[v] = true
	}
	var policy v1alpha1.PhorvexPolicy
	if err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: policyName}, &policy); err != nil {
		return err
	}
	floor := policy.Spec.SLO.MinAvailableReplicas
	if floor < 1 {
		floor = 1
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(ns)); err != nil {
		return err
	}
	legitimate := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if uids[string(p.UID)] || p.DeletionTimestamp != nil {
			continue
		}
		owner, err := ResolvePodOwner(ctx, r, p)
		if err != nil {
			continue
		}
		// A read error is not provenance. Only a reviewed inventory entry or explicit
		// metadata can identify a legitimate owner for the remaining capacity count.
		legit := declared[owner.Kind+"/"+owner.Object.GetName()] || declared["*"] || ManagedMetadata(owner.Object)
		ready := false
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				ready = true
			}
		}
		if legit && ready {
			legitimate[string(p.UID)] = true
		}
	}
	var services corev1.ServiceList
	if err := r.List(ctx, &services, client.InNamespace(ns)); err != nil {
		return err
	}
	var endpoints discoveryv1.EndpointSliceList
	if err := r.List(ctx, &endpoints, client.InNamespace(ns)); err != nil {
		return err
	}
	for _, svc := range services.Items {
		affected := false
		if len(svc.Spec.Selector) > 0 {
			for _, set := range sets {
				if labels.SelectorFromSet(svc.Spec.Selector).Matches(set) {
					affected = true
				}
			}
		}
		legitService := declared["Service/"+svc.Name] || declared["*"] || ManagedMetadata(&svc)
		remaining := map[string]bool{}
		for _, slice := range endpoints.Items {
			if slice.Labels[discoveryv1.LabelServiceName] != svc.Name {
				continue
			}
			for _, ep := range slice.Endpoints {
				ref := ep.TargetRef
				if ref == nil || ref.Kind != "Pod" || (ref.Namespace != "" && ref.Namespace != ns) {
					continue
				}
				id := string(ref.UID)
				if uids[id] {
					affected = true
				}
				if legitimate[id] {
					legitService = true
					if ep.Conditions.Ready != nil && *ep.Conditions.Ready && (ep.Conditions.Terminating == nil || !*ep.Conditions.Terminating) {
						remaining[id] = true
					}
				}
			}
		}
		if affected && legitService && len(remaining) < floor {
			return fmt.Errorf("Service %s legitimate ready floor would fail: remaining=%d floor=%d", svc.Name, len(remaining), floor)
		}
	}
	var budgets policyv1.PodDisruptionBudgetList
	if err := r.List(ctx, &budgets, client.InNamespace(ns)); err != nil {
		return err
	}
	for _, b := range budgets.Items {
		if b.Spec.Selector == nil {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(b.Spec.Selector)
		if err != nil {
			return err
		}
		for _, set := range sets {
			if sel.Matches(set) {
				return fmt.Errorf("owner has a declared PDB guarantee")
			}
		}
	}
	var hpas autoscalingv2.HorizontalPodAutoscalerList
	if err := r.List(ctx, &hpas, client.InNamespace(ns)); err != nil {
		return err
	}
	for _, h := range hpas.Items {
		ref := h.Spec.ScaleTargetRef
		if ref.APIVersion == "apps/v1" && ref.Kind == o.Kind && ref.Name == o.Object.GetName() {
			return fmt.Errorf("HPA can restore desired replicas")
		}
	}
	return nil
}

// ManagedMetadata is a conservative exemption, not proof of an authenticated
// creator. Attackers can copy metadata to evade this detector; it never gives them
// authority to remove somebody else's controller.
func ManagedMetadata(m client.Object) bool {
	if m.GetAnnotations()[ExemptAnnotation] != "" || len(m.GetOwnerReferences()) > 0 {
		return true
	}
	for k, v := range m.GetLabels() {
		if v != "" && (k == "app.kubernetes.io/managed-by" || strings.HasPrefix(k, "argocd.argoproj.io/") || strings.HasPrefix(k, "kustomize.toolkit.fluxcd.io/") || strings.HasPrefix(k, "helm.toolkit.fluxcd.io/")) {
			return true
		}
	}
	for k, v := range m.GetAnnotations() {
		if v != "" && (strings.HasPrefix(k, "meta.helm.sh/") || strings.HasPrefix(k, "argocd.argoproj.io/") || k == "kubectl.kubernetes.io/last-applied-configuration") {
			return true
		}
	}
	return false
}

func CurrentPolicy(ctx context.Context, r client.Reader, ns, name, uid string, generation int64, pods []corev1.Pod) error {
	var p v1alpha1.PhorvexPolicy
	if err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, &p); err != nil {
		return err
	}
	if string(p.UID) != uid || p.Generation != generation || p.DeletionTimestamp != nil {
		return fmt.Errorf("policy epoch changed")
	}
	enabled := false
	for _, a := range p.Spec.Actions.Enabled {
		if string(a) == string(model.ActionControllerStop) {
			enabled = true
		}
	}
	if !enabled {
		return fmt.Errorf("controller-stop is not enabled in current policy")
	}
	sel, err := metav1.LabelSelectorAsSelector(&p.Spec.Selector)
	if err != nil || len(p.Spec.Selector.MatchLabels)+len(p.Spec.Selector.MatchExpressions) == 0 {
		return fmt.Errorf("policy selector unavailable")
	}
	for _, pod := range pods {
		if !sel.Matches(labels.Set(pod.Labels)) {
			return fmt.Errorf("child is outside current selecting policy")
		}
	}
	return nil
}
