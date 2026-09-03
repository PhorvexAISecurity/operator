/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package controller

import (
	"math"
	"regexp"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

const maxPolicyLambda = 10.0

var exposurePressureCapPattern = regexp.MustCompile(`^0\.[0-9]+$`)

var policyLambdaPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?$`)

// ValidatePhorvexPolicy is the canonical runtime validation shared by admission
// and reconciliation. Single-field duration syntax/minimums remain in the CRD's
// CEL schema; this function owns checks that need the decoded policy as a whole.
func ValidatePhorvexPolicy(p *v1alpha1.PhorvexPolicy) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if _, err := metav1.LabelSelectorAsSelector(&p.Spec.Selector); err != nil {
		errs = append(errs, field.Invalid(specPath.Child("selector"), p.Spec.Selector, err.Error()))
	}
	if p.Spec.EffectiveMode() == v1alpha1.ModeActive && len(p.Spec.Selector.MatchLabels) == 0 {
		errs = append(errs, field.Required(specPath.Child("selector", "matchLabels"),
			"active mode requires a matchLabels selector (the Phoenix AMTD guest list is matchLabels-only in P0)"))
	}

	if raw := p.Spec.Objective.Lambda; raw != "" {
		lambda, err := strconv.ParseFloat(raw, 64)
		if !policyLambdaPattern.MatchString(raw) || err != nil || math.IsNaN(lambda) || math.IsInf(lambda, 0) || lambda < 0 || lambda > maxPolicyLambda {
			errs = append(errs, field.Invalid(specPath.Child("objective", "lambda"), raw,
				"must be a decimal between 0 and 10"))
		}
	}
	if raw := p.Spec.Belief.ExposurePressureCap; raw != "" {
		cap, err := strconv.ParseFloat(raw, 64)
		if !exposurePressureCapPattern.MatchString(raw) || err != nil || math.IsNaN(cap) || math.IsInf(cap, 0) || cap <= 0 || cap >= 1 {
			errs = append(errs, field.Invalid(specPath.Child("belief", "exposurePressureCap"), raw,
				"exposurePressureCap must be a decimal strictly between 0 and 1 (M-143: the exposure-pressure term must stay a prior floor, never an annihilator)"))
		}
	}

	return errs
}
