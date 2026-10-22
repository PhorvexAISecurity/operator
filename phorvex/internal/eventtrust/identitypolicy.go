package eventtrust

import (
	"context"
	"fmt"
	"slices"
	"strings"

	admission "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The creator-identity guard (charts/phorvex securityevent-identity-policy.yaml): the
// annotation a SecurityEvent carries, the authenticated requester, and the rule that
// they agree. Expressions compare with their whitespace collapsed.
const (
	identityClaim      = "has(object.metadata.annotations) && 'phorvex.ai/creator-identity' in object.metadata.annotations ? object.metadata.annotations['phorvex.ai/creator-identity'] : ''"
	identityActor      = "request.userInfo.username"
	identityValidation = "variables.claim == '' || variables.claim == variables.actor"
)

// CheckIdentityPolicy returns nil when the named ValidatingAdmissionPolicy enforces the
// creator-identity guard on every SecurityEvent create and update, through a Deny
// binding of the same name. A release that does not install the guard itself, because
// another release on the cluster does (--event-identity-policy), trusts detector
// identities only while this holds.
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingadmissionpolicies;validatingadmissionpolicybindings,verbs=get
func CheckIdentityPolicy(ctx context.Context, c client.Reader, name string) error {
	var policy admission.ValidatingAdmissionPolicy
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &policy); err != nil {
		return fmt.Errorf("creator-identity policy %s: %w", name, err)
	}
	s := policy.Spec
	if s.FailurePolicy != nil && *s.FailurePolicy != admission.Fail {
		return fmt.Errorf("creator-identity policy %s does not fail closed", name)
	}
	if len(s.MatchConditions) > 0 || !matchesEverySecurityEvent(s.MatchConstraints) {
		return fmt.Errorf("creator-identity policy %s does not match every SecurityEvent create and update", name)
	}
	vars := map[string]string{}
	for _, v := range s.Variables {
		vars[v.Name] = collapse(v.Expression)
	}
	if vars["claim"] != identityClaim || vars["actor"] != identityActor ||
		!slices.ContainsFunc(s.Validations, func(v admission.Validation) bool { return collapse(v.Expression) == identityValidation }) {
		return fmt.Errorf("creator-identity policy %s does not require the stamp to name the requester", name)
	}
	var binding admission.ValidatingAdmissionPolicyBinding
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &binding); err != nil {
		return fmt.Errorf("creator-identity policy binding %s: %w", name, err)
	}
	b := binding.Spec
	if b.PolicyName != name || !slices.Contains(b.ValidationActions, admission.Deny) || b.ParamRef != nil ||
		(b.MatchResources != nil && !emptySelectors(b.MatchResources)) {
		return fmt.Errorf("creator-identity policy binding %s does not deny every SecurityEvent", name)
	}
	return nil
}

func matchesEverySecurityEvent(m *admission.MatchResources) bool {
	if m == nil || !emptySelectors(m) {
		return false
	}
	for _, r := range m.ExcludeResourceRules {
		if covers(r.RuleWithOperations) {
			return false
		}
	}
	for _, r := range m.ResourceRules {
		if covers(r.RuleWithOperations) && (r.Scope == nil || *r.Scope != admission.NamespacedScope) &&
			(hasAny(r.Operations, admission.OperationAll) || (hasAny(r.Operations, admission.Create) && hasAny(r.Operations, admission.Update))) {
			return true
		}
	}
	return false
}

func covers(r admission.RuleWithOperations) bool {
	return (slices.Contains(r.APIGroups, "amtd.r6security.com") || slices.Contains(r.APIGroups, "*")) &&
		(slices.Contains(r.Resources, "securityevents") || slices.Contains(r.Resources, "*"))
}

func hasAny(ops []admission.OperationType, op admission.OperationType) bool {
	return slices.Contains(ops, op) || slices.Contains(ops, admission.OperationAll)
}

func emptySelectors(m *admission.MatchResources) bool {
	return (m.NamespaceSelector == nil || (len(m.NamespaceSelector.MatchLabels) == 0 && len(m.NamespaceSelector.MatchExpressions) == 0)) &&
		(m.ObjectSelector == nil || (len(m.ObjectSelector.MatchLabels) == 0 && len(m.ObjectSelector.MatchExpressions) == 0))
}

func collapse(expression string) string {
	return strings.Join(strings.Fields(expression), " ")
}
