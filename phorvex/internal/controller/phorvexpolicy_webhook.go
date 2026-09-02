/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

const policyValidationPath = "/validate-phorvex-ai-v1alpha1-phorvexpolicy"

// PhorvexPolicyValidator rejects cross-field-invalid policies before they are
// persisted. The reconciler invokes the same validator as a rolling-upgrade and
// defense-in-depth backstop.
type PhorvexPolicyValidator struct{}

// +kubebuilder:webhook:path=/validate-phorvex-ai-v1alpha1-phorvexpolicy,mutating=false,failurePolicy=fail,matchPolicy=Equivalent,sideEffects=None,timeoutSeconds=5,groups=phorvex.ai,resources=phorvexpolicies,verbs=create;update,versions=v1alpha1,name=vphorvexpolicy.phorvex.ai,admissionReviewVersions=v1

func (PhorvexPolicyValidator) ValidateCreate(_ context.Context, obj runtime.Object) (admission.Warnings, error) {
	return nil, validateAdmissionObject(obj)
}

func (PhorvexPolicyValidator) ValidateUpdate(_ context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	return nil, validateAdmissionObject(newObj)
}

func (PhorvexPolicyValidator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	return nil, nil
}

func validateAdmissionObject(obj runtime.Object) error {
	p, ok := obj.(*v1alpha1.PhorvexPolicy)
	if !ok {
		return apierrors.NewBadRequest(fmt.Sprintf("expected PhorvexPolicy, got %T", obj))
	}
	if errs := ValidatePhorvexPolicy(p); len(errs) > 0 {
		return apierrors.NewInvalid(schema.GroupKind{Group: v1alpha1.GroupVersion.Group, Kind: "PhorvexPolicy"}, p.Name, errs)
	}
	return nil
}

// SetupPhorvexPolicyWebhookWithManager registers the fail-closed validating
// endpoint. The API server calls it only for CREATE and UPDATE.
func SetupPhorvexPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&v1alpha1.PhorvexPolicy{}).
		WithValidator(PhorvexPolicyValidator{}).
		WithValidatorCustomPath(policyValidationPath).
		Complete()
}
