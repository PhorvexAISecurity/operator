package eventtrust

import (
	"strings"
	"testing"

	admission "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const guardName = "phorvex-system-phorvex-phorvex-se-creator-8acf73b8d0"

// The guard as the production release installs it (charts/phorvex
// securityevent-identity-policy.yaml), with its folded expressions.
func installedGuard() (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding) {
	fail, scope := admission.Fail, admission.AllScopes
	policy := &admission.ValidatingAdmissionPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: guardName},
		Spec: admission.ValidatingAdmissionPolicySpec{
			FailurePolicy: &fail,
			MatchConstraints: &admission.MatchResources{ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{
				Operations: []admission.OperationType{admission.Create, admission.Update},
				Rule:       admission.Rule{APIGroups: []string{"amtd.r6security.com"}, APIVersions: []string{"*"}, Resources: []string{"securityevents"}, Scope: &scope},
			}}}},
			Variables: []admission.Variable{
				{Name: "claim", Expression: "has(object.metadata.annotations) && 'phorvex.ai/creator-identity' in object.metadata.annotations\n  ? object.metadata.annotations['phorvex.ai/creator-identity']\n  : ''"},
				{Name: "actor", Expression: "request.userInfo.username"},
			},
			Validations: []admission.Validation{
				{Expression: "!variables.oldCompleted || variables.completed"},
				{Expression: "variables.claim == '' || variables.claim == variables.actor"},
			},
		},
	}
	binding := &admission.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: guardName},
		Spec:       admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: guardName, ValidationActions: []admission.ValidationAction{admission.Deny}},
	}
	return policy, binding
}

func guardReader(t *testing.T, objects ...client.Object) client.Reader {
	scheme := runtime.NewScheme()
	if err := admission.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func TestCheckIdentityPolicyAcceptsTheInstalledGuard(t *testing.T) {
	policy, binding := installedGuard()
	if err := CheckIdentityPolicy(t.Context(), guardReader(t, policy, binding), guardName); err != nil {
		t.Fatal(err)
	}
}

func TestCheckIdentityPolicyRefusesAWeakerGuard(t *testing.T) {
	ignore, namespaced := admission.Ignore, admission.NamespacedScope
	for name, weaken := range map[string]func(*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding) []client.Object{
		"absent": func(*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			return nil
		},
		"unbound": func(p *admission.ValidatingAdmissionPolicy, _ *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			return []client.Object{p}
		},
		"fails open": func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			p.Spec.FailurePolicy = &ignore
			return []client.Object{p, b}
		},
		"warns only": func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			b.Spec.ValidationActions = []admission.ValidationAction{admission.Warn}
			return []client.Object{p, b}
		},
		"create only": func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			p.Spec.MatchConstraints.ResourceRules[0].Operations = []admission.OperationType{admission.Create}
			return []client.Object{p, b}
		},
		"namespaced": func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			p.Spec.MatchConstraints.ResourceRules[0].Scope = &namespaced
			return []client.Object{p, b}
		},
		"selected namespaces": func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			b.Spec.MatchResources = &admission.MatchResources{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}}
			return []client.Object{p, b}
		},
		"conditional": func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			p.Spec.MatchConditions = []admission.MatchCondition{{Name: "some", Expression: "false"}}
			return []client.Object{p, b}
		},
		"another rule": func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			p.Spec.Validations = p.Spec.Validations[:1]
			return []client.Object{p, b}
		},
		"another actor": func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding) []client.Object {
			p.Spec.Variables[1].Expression = "'system:anonymous'"
			return []client.Object{p, b}
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy, binding := installedGuard()
			err := CheckIdentityPolicy(t.Context(), guardReader(t, weaken(policy, binding)...), guardName)
			if err == nil || !strings.Contains(err.Error(), guardName) {
				t.Fatalf("a %s guard was accepted: %v", name, err)
			}
		})
	}
}
