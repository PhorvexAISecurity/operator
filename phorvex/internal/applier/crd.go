/*
 * Phorvex — P-VCLUSTER Pass 2 production applier: the REAL cluster-write behind the console apply-fix
 * Applier hook. Patches the tenant's PhorvexPolicy CRD (phorvex.ai/v1alpha1) in the tenant's namespace
 * via a controller-runtime client SCOPED to the per-namespace ServiceAccount, with the safety gate
 * RE-ASSERTED before the patch, a verify-then-rollback on a non-landing patch, and full audit.
 *
 * [PENDING-CLUSTER-VALIDATION] — real code; the K8s client is mocked in CI (the fake client). Validated
 * against a real cluster + a live per-namespace SA + the installed PhorvexPolicy CRD by the dev team.
 *
 * PREMORTEM (persona panel: Cloud-engineer / Pen-tester / MLSecOps / distributed-systems / DevOps):
 *   - a malicious/buggy patch (a degraded policy) → the gate is re-asserted HERE (defense-in-depth);
 *   - a wrong-namespace write → the resolved policy's namespace is asserted == the tenant namespace;
 *   - an ambiguous target (0 or >1 PhorvexPolicy) → fail-closed (refuse, never guess);
 *   - a partial apply / patch that does not land → verify-then-rollback to the captured spec;
 *   - a rollback failure → surfaced LOUDLY as needs-manual-intervention (never silently left half-applied).
 */

package applier

import (
	"context"
	"fmt"
	"strconv"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	phorvexv1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

// CRDApplier patches the tenant's PhorvexPolicy via a namespace-scoped client.
type CRDApplier struct {
	Client  client.Client                     // scoped to the tenant namespace (per-namespace SA)
	Gate    func(model.Policy) error          // PolicySafetyGate, re-asserted before the patch (injected)
	Audit   func(event string, f map[string]any)
	Timeout time.Duration
}

// NewCRDApplier wires the real applier. gate is the (proven) PolicySafetyGate; audit may be nil.
func NewCRDApplier(c client.Client, gate func(model.Policy) error, audit func(string, map[string]any)) *CRDApplier {
	return &CRDApplier{Client: c, Gate: gate, Audit: audit, Timeout: 15 * time.Second}
}

func (a *CRDApplier) emit(event string, f map[string]any) {
	if a.Audit != nil {
		a.Audit(event, f)
	}
}

func decimalStr(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// applyDelta writes ONLY the allowlisted policy fields into the CRD spec (mirrors the apply-fix allowlist;
// EnabledActions / action set are never touched here).
func applyDelta(spec *phorvexv1alpha1.PhorvexPolicySpec, c model.Policy) {
	spec.Objective.CostWeights.NormSparsity = decimalStr(c.NormSparsity)
	spec.Objective.CostWeights.FlowDisruption = decimalStr(c.FlowDisruption)
	maxMoves := c.MaxMovesPerTick
	spec.Budget.MaxMovesPerTick = &maxMoves
	spec.Budget.ProactiveFloor = metav1.Duration{Duration: c.ProactiveFloor}
}

func specMatches(spec phorvexv1alpha1.PhorvexPolicySpec, c model.Policy) bool {
	return spec.Objective.CostWeights.NormSparsity == decimalStr(c.NormSparsity) &&
		spec.Objective.CostWeights.FlowDisruption == decimalStr(c.FlowDisruption) &&
		spec.EffectiveMaxMovesPerTick() == c.MaxMovesPerTick &&
		spec.Budget.ProactiveFloor.Duration == c.ProactiveFloor
}

// Apply implements console.Applier: it patches the tenant's PhorvexPolicy to the candidate, gate-asserted,
// namespace-guarded, verify-then-rollback. Returns nil only when the patch is confirmed landed.
func (a *CRDApplier) Apply(tenant, namespace string, candidate model.Policy) error {
	if namespace == "" {
		return fmt.Errorf("CRD applier: empty namespace (refuse)")
	}
	// DEFENSE-IN-DEPTH: re-assert the safety gate. The manager already gated at submit AND approve; this
	// guarantees a gate-breaking delta can NEVER reach the cluster patch even via a direct applier call.
	if a.Gate != nil {
		if err := a.Gate(candidate); err != nil {
			a.emit("apply-fix.crd.gate-refused", map[string]any{"tenant": tenant, "namespace": namespace, "error": err.Error()})
			return fmt.Errorf("CRD applier: safety gate REFUSED before patch: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.Timeout)
	defer cancel()

	// RESOLVE the tenant's PhorvexPolicy in its namespace — exactly one, else fail-closed (never guess).
	var list phorvexv1alpha1.PhorvexPolicyList
	if err := a.Client.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("CRD applier: list PhorvexPolicy in %s: %w", namespace, err)
	}
	if len(list.Items) != 1 {
		return fmt.Errorf("CRD applier: expected exactly 1 PhorvexPolicy in namespace %q, found %d — ambiguous, refusing", namespace, len(list.Items))
	}
	pol := &list.Items[0]
	// WRONG-NAMESPACE GUARD: the resolved object MUST be in the tenant's namespace.
	if pol.Namespace != namespace {
		return fmt.Errorf("CRD applier: namespace mismatch (%s != %s) — refusing cross-namespace write", pol.Namespace, namespace)
	}

	old := pol.DeepCopy()
	applyDelta(&pol.Spec, candidate)
	if err := a.Client.Patch(ctx, pol, client.MergeFrom(old)); err != nil {
		// The patch failed — nothing was applied (MergeFrom is atomic at the API server). Fail-closed.
		a.emit("apply-fix.crd.patch-error", map[string]any{"tenant": tenant, "namespace": namespace, "policy": pol.Name, "error": err.Error()})
		return fmt.Errorf("CRD applier: patch %s/%s failed (no change applied): %w", namespace, pol.Name, err)
	}

	// VERIFY the patch LANDED; on a non-landing/partial apply, ROLL BACK to the captured spec.
	var check phorvexv1alpha1.PhorvexPolicy
	if err := a.Client.Get(ctx, client.ObjectKeyFromObject(pol), &check); err != nil {
		return fmt.Errorf("CRD applier: patched but could not verify %s/%s: %w", namespace, pol.Name, err)
	}
	if !specMatches(check.Spec, candidate) {
		rb := check.DeepCopy()
		rb.Spec = old.Spec
		if rbErr := a.Client.Patch(ctx, rb, client.MergeFrom(&check)); rbErr != nil {
			a.emit("apply-fix.crd.rollback-failed", map[string]any{"tenant": tenant, "namespace": namespace, "policy": pol.Name, "error": rbErr.Error()})
			return fmt.Errorf("CRD applier: patch did not land AND rollback FAILED for %s/%s — MANUAL INTERVENTION REQUIRED: %w", namespace, pol.Name, rbErr)
		}
		return fmt.Errorf("CRD applier: patch did not take effect for %s/%s — rolled back to the prior spec", namespace, pol.Name)
	}

	a.emit("apply-fix.crd.applied", map[string]any{"tenant": tenant, "namespace": namespace, "policy": pol.Name})
	return nil
}
