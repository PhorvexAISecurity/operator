package actuator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type quarantinePlan struct {
	labels map[string]string
	via    []string
}

func quarantineOwnerSelector(ctx context.Context, r client.Reader, p *corev1.Pod) (*metav1.LabelSelector, error) {
	var owner *metav1.OwnerReference
	for i := range p.OwnerReferences {
		ref := &p.OwnerReferences[i]
		if ref.Controller != nil && *ref.Controller {
			if owner != nil {
				return nil, fmt.Errorf("quarantine: multiple controller owners")
			}
			owner = ref
		}
	}
	if owner == nil {
		return nil, nil
	}
	supported := (owner.APIVersion == "apps/v1" && (owner.Kind == "ReplicaSet" || owner.Kind == "StatefulSet" || owner.Kind == "DaemonSet")) || (owner.APIVersion == "batch/v1" && owner.Kind == "Job")
	if !supported {
		return nil, fmt.Errorf("quarantine: unsupported controller %s %s", owner.APIVersion, owner.Kind)
	}
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(owner.APIVersion)
	obj.SetKind(owner.Kind)
	if err := r.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: owner.Name}, obj); err != nil {
		return nil, fmt.Errorf("quarantine owner %s/%s: %w", owner.Kind, owner.Name, err)
	}
	if owner.UID == "" || owner.UID != obj.GetUID() {
		return nil, fmt.Errorf("quarantine: owner UID mismatch")
	}
	raw, found, err := unstructured.NestedMap(obj.Object, "spec", "selector")
	if err != nil || !found {
		return nil, fmt.Errorf("quarantine: owner selector unavailable")
	}
	sel := &metav1.LabelSelector{}
	if err = runtime.DefaultUnstructuredConverter.FromUnstructured(raw, sel); err != nil {
		return nil, err
	}
	if len(sel.MatchLabels)+len(sel.MatchExpressions) == 0 {
		return nil, fmt.Errorf("quarantine: empty owner selector cannot be broken")
	}
	if _, err = metav1.LabelSelectorAsSelector(sel); err != nil {
		return nil, err
	}
	return sel, nil
}
func protectedQuarantineKey(k string) bool { return k == quarantineLabel || k == quarantineEpochLabel }
func breakQuarantineSelector(out map[string]string, sel *metav1.LabelSelector, uid string) {
	// Conservative deterministic edits. Complete predicates are checked afterwards,
	// including contradictions introduced by other selectors. No guessed success.
	keys := make([]string, 0, len(sel.MatchLabels))
	for k := range sel.MatchLabels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	suffix := func(k string, forbidden []string) {
		if protectedQuarantineKey(k) {
			return
		}
		v := out[k] + "-quarantined"
		for _, x := range forbidden {
			if x == v {
				v = ""
				break
			}
		}
		if v == "" || len(validation.IsValidLabelValue(v)) > 0 {
			v = fmt.Sprintf("q-%x", sha256.Sum256([]byte(uid+"/"+k)))[:32]
		}
		out[k] = v
	}
	for _, k := range keys {
		suffix(k, []string{sel.MatchLabels[k]})
	}
	for _, e := range sel.MatchExpressions {
		if protectedQuarantineKey(e.Key) {
			continue
		}
		switch e.Operator {
		case metav1.LabelSelectorOpIn:
			suffix(e.Key, e.Values)
		case metav1.LabelSelectorOpExists:
			delete(out, e.Key)
		case metav1.LabelSelectorOpNotIn:
			if len(e.Values) > 0 {
				values := append([]string(nil), e.Values...)
				sort.Strings(values)
				out[e.Key] = values[0]
			}
		case metav1.LabelSelectorOpDoesNotExist:
			out[e.Key] = "quarantined"
		}
	}
}
func planQuarantine(ctx context.Context, r client.Reader, p *corev1.Pod) (quarantinePlan, error) {
	plan := quarantinePlan{labels: copyLabels(p.Labels)}
	if plan.labels == nil {
		plan.labels = map[string]string{}
	}
	owner, err := quarantineOwnerSelector(ctx, r, p)
	if err != nil {
		return plan, err
	}
	var svcs corev1.ServiceList
	if err = r.List(ctx, &svcs, client.InNamespace(p.Namespace)); err != nil {
		return plan, fmt.Errorf("quarantine Services: %w", err)
	}
	sort.Slice(svcs.Items, func(i, j int) bool { return svcs.Items[i].Name < svcs.Items[j].Name })
	if owner != nil {
		sel, _ := metav1.LabelSelectorAsSelector(owner)
		if sel.Matches(labels.Set(p.Labels)) {
			breakQuarantineSelector(plan.labels, owner, string(p.UID))
		}
		o := metav1.GetControllerOf(p)
		plan.via = append(plan.via, fmt.Sprintf("%s/%s UID=%s", o.Kind, o.Name, o.UID))
	}
	for _, svc := range svcs.Items {
		if len(svc.Spec.Selector) == 0 {
			continue
		}
		if labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(p.Labels)) {
			breakQuarantineSelector(plan.labels, &metav1.LabelSelector{MatchLabels: svc.Spec.Selector}, string(p.UID))
			plan.via = append(plan.via, "Service/"+svc.Name)
		}
	}
	plan.labels[quarantineLabel] = string(p.UID)
	plan.labels[quarantineEpochLabel] = p.ResourceVersion
	if owner != nil {
		sel, _ := metav1.LabelSelectorAsSelector(owner)
		if sel.Matches(labels.Set(plan.labels)) {
			return plan, fmt.Errorf("quarantine: proposed labels still match controller")
		}
	}
	for _, svc := range svcs.Items {
		if len(svc.Spec.Selector) > 0 && labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(plan.labels)) {
			return plan, fmt.Errorf("quarantine: proposed labels match Service %s", svc.Name)
		}
	}
	if len(plan.via) == 0 {
		plan.via = []string{"no owner or Service selector to break"}
	}
	return plan, nil
}
