package runner

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"

	"github.com/phorvex/phorvex/api/v1alpha1"
)

// TenantCollisionCondition is set on every policy that shares its spec.tenant display name
// with another live policy (M-140).
//
// Under owner identity two such policies are two independent economic units with their own
// lambda, RLS model and belief prior. That is intentional and supported — but it is not what
// the display name suggests, and the legacy per-tenant series cannot describe both. The
// condition is the operator-visible record of that split.
//
// This is distinct from a REJECTED duplicate owner UID, which never reaches the registry at
// all: that is a conflicting actual identity and is refused by Upsert.
const TenantCollisionCondition = "TenantCollision"

// collisionState is the per-name ownership picture used to publish the condition.
func (m *Manager) collisionState() map[string][]types.NamespacedName {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byTenant := map[string][]types.NamespacedName{}
	for _, e := range m.policies {
		if e != nil {
			byTenant[e.tenant] = append(byTenant[e.tenant], e.key)
		}
	}
	return byTenant
}

// publishTenantCollisions sets or clears TenantCollision on every live policy through the
// real status path. Clearing matters as much as setting: a name that stops colliding must
// stop reporting one.
// PublishTenantCollisions is the exported entrypoint the tick uses; it is also how the
// controller-level test drives the real status path rather than a substitute.
func (m *Manager) PublishTenantCollisions(ctx context.Context) {
	if m.Client == nil {
		return
	}
	for tenant, owners := range m.collisionState() {
		sort.Slice(owners, func(i, j int) bool { return owners[i].String() < owners[j].String() })
		condition := metav1.Condition{
			Type:    TenantCollisionCondition,
			Status:  metav1.ConditionFalse,
			Reason:  "UniqueOwner",
			Message: fmt.Sprintf("spec.tenant %q resolves to exactly one policy-owned economic unit", tenant),
		}
		if len(owners) > 1 {
			names := make([]string, 0, len(owners))
			for _, o := range owners {
				names = append(names, o.String())
			}
			condition.Status = metav1.ConditionTrue
			condition.Reason = "SharedDisplayName"
			condition.Message = fmt.Sprintf(
				"spec.tenant %q is declared by %d policies (%s); each owns a SEPARATE lambda, cost model and belief prior, and phorvex_tenant_lambda is withdrawn while the name is ambiguous",
				tenant, len(owners), strings.Join(names, ", "))
		}
		for _, key := range owners {
			m.setTenantCollisionCondition(ctx, key, condition)
		}
	}
}

func (m *Manager) setTenantCollisionCondition(ctx context.Context, key types.NamespacedName, condition metav1.Condition) {
	var obj v1alpha1.PhorvexPolicy
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := m.Client.Get(ctx, key, &obj); err != nil {
			return err
		}
		existing := meta.FindStatusCondition(obj.Status.Conditions, condition.Type)
		if existing != nil && existing.Status == condition.Status && existing.Message == condition.Message &&
			existing.ObservedGeneration == obj.Generation {
			return nil // no write when nothing changed
		}
		condition.ObservedGeneration = obj.Generation
		meta.SetStatusCondition(&obj.Status.Conditions, condition)
		return m.Client.Status().Update(ctx, &obj)
	})
	if err != nil {
		m.Log.V(1).Info("tenant collision condition not written", "policy", key.String(), "error", err.Error())
	}
}
