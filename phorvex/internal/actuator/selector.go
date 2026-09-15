package actuator

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// targetSelector gives complete selectors precedence over the legacy labels-only
// field. The copy prevents callers from changing a prepared target after handoff.
func targetSelector(target TenantTarget) metav1.LabelSelector {
	if target.Selector != nil {
		return *target.Selector.DeepCopy()
	}
	labels := make(map[string]string, len(target.MatchLabels))
	for k, v := range target.MatchLabels {
		labels[k] = v
	}
	return metav1.LabelSelector{MatchLabels: labels}
}

// phoenixEqualities translates only selectors whose predicate is exactly a
// nonempty conjunction of key=value tests. In lists are intersected, and other
// requirements must be implied by those proven equalities.
func phoenixEqualities(sel metav1.LabelSelector) (map[string]string, error) {
	if _, err := metav1.LabelSelectorAsSelector(&sel); err != nil {
		return nil, fmt.Errorf("invalid selector: %w", err)
	}
	possible := make(map[string]map[string]bool)
	for k, v := range sel.MatchLabels {
		possible[k] = map[string]bool{v: true}
	}
	for _, req := range sel.MatchExpressions {
		if req.Operator != metav1.LabelSelectorOpIn {
			continue
		}
		values := make(map[string]bool, len(req.Values))
		for _, v := range req.Values {
			values[v] = true
		}
		if existing, ok := possible[req.Key]; ok {
			for v := range existing {
				if !values[v] {
					delete(existing, v)
				}
			}
		} else {
			possible[req.Key] = values
		}
	}
	// A negative constraint can narrow an already finite In/equality set to one
	// value. Without that finite proof, NotIn remains unrepresentable by a map.
	for _, req := range sel.MatchExpressions {
		if req.Operator != metav1.LabelSelectorOpNotIn {
			continue
		}
		if values, ok := possible[req.Key]; ok {
			for _, forbidden := range req.Values {
				delete(values, forbidden)
			}
		}
	}
	equalities := make(map[string]string, len(possible))
	for k, values := range possible {
		if len(values) == 0 {
			return nil, fmt.Errorf("contradictory selector on key %q", k)
		}
		if len(values) != 1 {
			return nil, fmt.Errorf("selector on key %q has %d possible values; Phoenix requires equality", k, len(values))
		}
		for v := range values {
			equalities[k] = v
		}
	}
	if len(equalities) == 0 {
		return nil, fmt.Errorf("selector has no proven equalities; Phoenix requires a nonempty equality guest list")
	}
	for _, req := range sel.MatchExpressions {
		value, proven := equalities[req.Key]
		switch req.Operator {
		case metav1.LabelSelectorOpIn:
			// Every In expression has already been intersected above.
		case metav1.LabelSelectorOpExists:
			if !proven {
				return nil, fmt.Errorf("unproven Exists requirement on key %q", req.Key)
			}
		case metav1.LabelSelectorOpNotIn:
			if !proven {
				return nil, fmt.Errorf("unproven NotIn requirement on key %q", req.Key)
			}
			for _, forbidden := range req.Values {
				if value == forbidden {
					return nil, fmt.Errorf("contradictory NotIn requirement on key %q", req.Key)
				}
			}
		case metav1.LabelSelectorOpDoesNotExist:
			if proven {
				return nil, fmt.Errorf("contradictory DoesNotExist requirement on key %q", req.Key)
			}
			return nil, fmt.Errorf("unrepresentable DoesNotExist requirement on key %q", req.Key)
		}
	}
	return equalities, nil
}
