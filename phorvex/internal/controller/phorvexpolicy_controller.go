/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package controller holds the PhorvexPolicy reconciler. It does NOT make decisions
// or actuate — it simply keeps the runner.Manager's per-tenant registry in sync with
// the PhorvexPolicy CRs and validates them. All scoring/actuation happens in the
// single runner tick loop (so a tenant's cadence and the shared snapshot are
// honored), keeping the reconciler thin (one tenant in/out per change).
package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/runner"
)

// PhorvexPolicyReconciler syncs PhorvexPolicy CRs into the runner registry.
type PhorvexPolicyReconciler struct {
	client.Client
	Manager *runner.Manager
}

// +kubebuilder:rbac:groups=phorvex.ai,resources=phorvexpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=phorvex.ai,resources=phorvexpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=phorvex.ai,resources=phorvexpolicies/finalizers,verbs=update

// Reconcile registers/updates/removes a tenant policy.
func (r *PhorvexPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var p v1alpha1.PhorvexPolicy
	if err := r.Get(ctx, req.NamespacedName, &p); err != nil {
		if apierrors.IsNotFound(err) {
			r.Manager.Remove(req.NamespacedName)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if err := validate(&p); err != nil {
		r.setCondition(ctx, &p, "ValidationError", metav1.ConditionTrue, "Invalid", err.Error())
		// Do not register an invalid policy; surface the error and stop.
		return ctrl.Result{}, nil
	}

	if err := r.Manager.Upsert(&p); err != nil {
		r.setCondition(ctx, &p, "ValidationError", metav1.ConditionTrue, "SelectorError", err.Error())
		return ctrl.Result{}, nil
	}

	// Clear any prior validation error; the runner fills the operational status.
	r.setCondition(ctx, &p, "ValidationError", metav1.ConditionFalse, "Valid", "policy accepted")
	return ctrl.Result{}, nil
}

func (r *PhorvexPolicyReconciler) setCondition(ctx context.Context, p *v1alpha1.PhorvexPolicy, condType string, status metav1.ConditionStatus, reason, msg string) {
	var fresh v1alpha1.PhorvexPolicy
	if err := r.Get(ctx, client.ObjectKeyFromObject(p), &fresh); err != nil {
		return
	}
	if fresh.Status.Tenant == "" {
		fresh.Status.Tenant = p.EffectiveTenant()
	}
	meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: fresh.Generation,
	})
	_ = r.Status().Update(ctx, &fresh)
}

// validate checks the spec beyond CRD-level validation.
func validate(p *v1alpha1.PhorvexPolicy) error {
	if _, err := metav1.LabelSelectorAsSelector(&p.Spec.Selector); err != nil {
		return fmt.Errorf("invalid selector: %w", err)
	}
	if p.Spec.EffectiveMode() == v1alpha1.ModeActive && len(p.Spec.Selector.MatchLabels) == 0 {
		return fmt.Errorf("active mode requires a matchLabels selector (the Phoenix AMTD guest list is matchLabels-only in P0)")
	}
	return nil
}

// SetupWithManager wires the reconciler.
func (r *PhorvexPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.PhorvexPolicy{}).
		Named("phorvexpolicy").
		Complete(r)
}
