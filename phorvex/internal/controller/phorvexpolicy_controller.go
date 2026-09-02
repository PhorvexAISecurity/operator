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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
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

	if err := ValidatePhorvexPolicy(&p).ToAggregate(); err != nil {
		// Do not register an invalid policy; surface the error and stop.
		return ctrl.Result{}, r.setCondition(ctx, &p, "ValidationError", metav1.ConditionTrue, "Invalid", err.Error())
	}

	if err := r.Manager.Upsert(&p); err != nil {
		return ctrl.Result{}, r.setCondition(ctx, &p, "ValidationError", metav1.ConditionTrue, "SelectorError", err.Error())
	}

	// Clear any prior validation error; the runner fills the operational status.
	return ctrl.Result{}, r.setCondition(ctx, &p, "ValidationError", metav1.ConditionFalse, "Valid", "policy accepted")
}

func (r *PhorvexPolicyReconciler) setCondition(ctx context.Context, p *v1alpha1.PhorvexPolicy, condType string, status metav1.ConditionStatus, reason, msg string) error {
	key := client.ObjectKeyFromObject(p)
	tenant := p.EffectiveTenant()

	// The runner owns operational status while this reconciler owns ValidationError. Always
	// re-read after a conflict so retrying this condition cannot put a stale runner snapshot (most
	// importantly KillSwitchEngaged) back into the CR. Also skip an identical write: status updates
	// themselves trigger reconciliation, and writing the same condition on every event creates a
	// self-sustaining second status writer that competes with every runner tick.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh v1alpha1.PhorvexPolicy
		if err := r.Get(ctx, key, &fresh); err != nil {
			return err
		}

		changed := false
		if fresh.Status.Tenant == "" {
			fresh.Status.Tenant = tenant
			changed = true
		}
		current := meta.FindStatusCondition(fresh.Status.Conditions, condType)
		if current == nil || current.Status != status || current.Reason != reason ||
			current.Message != msg || current.ObservedGeneration != fresh.Generation {
			meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
				Type:               condType,
				Status:             status,
				Reason:             reason,
				Message:            msg,
				ObservedGeneration: fresh.Generation,
			})
			changed = true
		}
		if !changed {
			return nil
		}
		return r.Status().Update(ctx, &fresh)
	})
}

// SetupWithManager wires the reconciler.
func (r *PhorvexPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.PhorvexPolicy{}).
		Named("phorvexpolicy").
		Complete(r)
}
