// Package startupauthz verifies the manager identity before active policy controllers start.
package startupauthz

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
)

const DefaultTimeout = 10 * time.Second

type Config struct {
	Backend           actuator.Backend
	OperatorNamespace string
	Timeout           time.Duration
	MIGAgent          *MIGAgentAccess
}

// MIGAgentAccess describes the optional M83 manager-to-agent path. These permissions are
// checked only when node execution is explicitly enabled.
type MIGAgentAccess struct {
	Namespace string
	DaemonSet string
}

type Requirement struct {
	Namespace string
	Verb      authz.Verb
	Reason    string
}

type Report struct {
	Policies       int
	ActivePolicies int
	DryRunPolicies int
	Namespaces     int
	Requirements   int
	NoPolicies     bool
}

type SSARClient interface {
	Create(context.Context, *authorizationv1.SelfSubjectAccessReview, metav1.CreateOptions) (*authorizationv1.SelfSubjectAccessReview, error)
}

// Check inventories all policies through the uncached reader and requires a known allow for
// every permission the selected backend may use. It deliberately does not share the runtime
// checker's fail-open cache: boot admission is bounded, uncached, and strict.
func Check(parent context.Context, reader client.Reader, reviews SSARClient, cfg Config) (Report, error) {
	if reader == nil {
		return Report{}, fmt.Errorf("startup authorization: policy inventory reader is unavailable")
	}
	if cfg.Backend != actuator.BackendPhoenix && cfg.Backend != actuator.BackendNative && cfg.Backend != actuator.BackendHybrid {
		return Report{}, fmt.Errorf("startup authorization: unsupported backend %q", cfg.Backend)
	}
	if cfg.OperatorNamespace == "" {
		return Report{}, fmt.Errorf("startup authorization: operator namespace is empty")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < 0 || timeout > 30*time.Second {
		return Report{}, fmt.Errorf("startup authorization: timeout must be positive and at most 30s")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	var policies v1alpha1.PhorvexPolicyList
	if err := reader.List(ctx, &policies); err != nil {
		return Report{}, fmt.Errorf("startup authorization: incomplete PhorvexPolicy inventory: %w", err)
	}
	if policies.Continue != "" || policies.RemainingItemCount != nil {
		return Report{}, fmt.Errorf("startup authorization: incomplete paginated PhorvexPolicy inventory")
	}
	report := Report{Policies: len(policies.Items), NoPolicies: len(policies.Items) == 0}
	requirements := map[string]Requirement{}
	namespaces := map[string]struct{}{}
	for i := range policies.Items {
		policy := &policies.Items[i]
		switch policy.Spec.EffectiveMode() {
		case v1alpha1.ModeDryRun:
			report.DryRunPolicies++
			continue
		case v1alpha1.ModeActive:
		default:
			return report, fmt.Errorf("startup authorization: policy %s/%s has unknown mode %q", policy.Namespace, policy.Name, policy.Spec.Mode)
		}
		if policy.Namespace == "" || policy.Name == "" {
			return report, fmt.Errorf("startup authorization: active policy inventory contains an object without namespace/name")
		}
		report.ActivePolicies++
		namespaces[policy.Namespace] = struct{}{}
		for _, action := range enabledActions(&policy.Spec) {
			if !actuator.KnownAction(action) {
				return report, fmt.Errorf("startup authorization: policy %s/%s contains unknown action %q", policy.Namespace, policy.Name, action)
			}
			if !accepted(cfg.Backend, action) {
				continue
			}
			addActionRequirements(requirements, cfg, policy.Namespace, action)
		}
		// Every active route performs uncached namespace and target-Pod authority
		// reads immediately before new work. Add these after action-specific reads
		// so the deduplicated requirement keeps the common safety reason.
		add(requirements, Requirement{
			Namespace: policy.Namespace,
			Verb:      authz.Verb{Resource: "namespaces", Name: policy.Namespace, Verb: "get", ClusterScoped: true},
			Reason:    "namespace dry-run actuation brake",
		})
		add(requirements, Requirement{
			Namespace: policy.Namespace,
			Verb:      authz.Verb{Resource: "pods", Verb: "get"},
			Reason:    "Pod opt-out actuation brake",
		})
	}
	report.Namespaces = len(namespaces)
	if report.ActivePolicies == 0 {
		return report, nil
	}
	// Native and hybrid managers reconcile protected receipts before due policies.
	// Recovery can require CAS advancement, exact cleanup, or acquisition of a
	// missing route target guard even after the originating policy was disabled.
	// Therefore the boot contract covers the full protected-journal lifecycle,
	// independent of the actions enabled by the current policy set.
	if cfg.Backend == actuator.BackendNative || cfg.Backend == actuator.BackendHybrid {
		for _, verb := range []string{"get", "list", "create", "update", "delete"} {
			add(requirements, Requirement{Namespace: cfg.OperatorNamespace, Verb: authz.Verb{Resource: "configmaps", Verb: verb}, Reason: "native protected recovery journal"})
		}
	}
	if cfg.MIGAgent != nil {
		if cfg.MIGAgent.Namespace == "" || cfg.MIGAgent.DaemonSet == "" {
			return report, fmt.Errorf("startup authorization: enabled MIG agent identity is incomplete")
		}
		add(requirements, Requirement{Namespace: cfg.MIGAgent.Namespace, Verb: authz.Verb{Resource: "pods", Verb: "get"}, Reason: "MIG agent identity"})
		add(requirements, Requirement{Namespace: cfg.MIGAgent.Namespace, Verb: authz.Verb{Resource: "pods", Verb: "list"}, Reason: "MIG agent discovery"})
		add(requirements, Requirement{Namespace: cfg.MIGAgent.Namespace, Verb: authz.Verb{Resource: "pods", Subresource: "exec", Verb: "create"}, Reason: "MIG agent execution"})
		add(requirements, Requirement{Namespace: cfg.MIGAgent.Namespace, Verb: authz.Verb{Group: "apps", Resource: "daemonsets", Name: cfg.MIGAgent.DaemonSet, Verb: "get"}, Reason: "MIG agent owner identity"})
	}
	if reviews == nil {
		return report, fmt.Errorf("startup authorization: SelfSubjectAccessReview client is unavailable")
	}
	ordered := make([]Requirement, 0, len(requirements))
	for _, requirement := range requirements {
		ordered = append(ordered, requirement)
	}
	sort.Slice(ordered, func(i, j int) bool { return requirementKey(ordered[i]) < requirementKey(ordered[j]) })
	report.Requirements = len(ordered)
	for _, requirement := range ordered {
		if err := review(ctx, reviews, requirement); err != nil {
			return report, err
		}
	}
	return report, nil
}

func enabledActions(spec *v1alpha1.PhorvexPolicySpec) []model.Action {
	if len(spec.Actions.Enabled) == 0 {
		return []model.Action{model.ActionRotate, model.ActionQuarantine}
	}
	out := make([]model.Action, 0, len(spec.Actions.Enabled))
	for _, action := range spec.Actions.Enabled {
		if action != v1alpha1.ActionNoop && action != v1alpha1.ActionDisable {
			out = append(out, model.Action(action))
		}
	}
	return out
}

func accepted(backend actuator.Backend, action model.Action) bool {
	for _, entry := range actuator.Repertoire(backend) {
		if entry.Action == action {
			return entry.Accepted
		}
	}
	return false
}

func addActionRequirements(out map[string]Requirement, cfg Config, namespace string, action model.Action) {
	route := actuator.RouteFor(cfg.Backend, action)
	for _, verb := range actuator.RequiredVerbsForBackend(cfg.Backend, action) {
		add(out, Requirement{Namespace: namespace, Verb: verb, Reason: string(action) + " actuation"})
	}
	// The capacity guard wraps every quarantine backend. Its inventory is therefore
	// required for native, Phoenix and the Phoenix route selected by hybrid.
	if action == model.ActionQuarantine {
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "namespaces", Name: namespace, Verb: "get", ClusterScoped: true}, Reason: "quarantine namespace identity"})
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "pods", Verb: "get"}, Reason: "quarantine target identity"})
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "pods", Verb: "list"}, Reason: "quarantine namespace capacity"})
		add(out, Requirement{Verb: authz.Verb{Group: "amtd.r6security.com", Resource: "securityevents", Verb: "list", ClusterScoped: true}, Reason: "quarantine legacy pending-work inventory"})
		for _, verb := range []string{"get", "create", "update"} {
			add(out, Requirement{Namespace: cfg.OperatorNamespace, Verb: authz.Verb{Resource: "configmaps", Verb: verb}, Reason: "quarantine capacity ledger"})
		}
	}
	if route == actuator.BackendPhoenix {
		for _, verb := range []string{"get", "create", "update"} {
			add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Group: "amtd.r6security.com", Resource: "adaptivemovingtargetdefenses", Verb: verb}, Reason: "Phoenix policy preparation"})
		}
		return
	}
	if route != actuator.BackendNative {
		return
	}
	add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "pods", Verb: "get"}, Reason: string(action) + " target identity"})
	if action == model.ActionQuarantine || action == model.ActionWarmSwap || action == model.ActionModelShardReplace || action == model.ActionMIGRebind || action == model.ActionAdapterRotate || action == model.ActionRouteRotate || action == model.ActionEndpointRotate {
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Group: "phorvex.ai", Resource: "phorvexpolicies", Verb: "get"}, Reason: string(action) + " current policy authority"})
		add(out, Requirement{Verb: authz.Verb{Resource: "namespaces", Name: namespace, Verb: "get", ClusterScoped: true}, Reason: string(action) + " current namespace authority"})
	}
	if action == model.ActionAdapterRotate {
		add(out, Requirement{Verb: authz.Verb{Group: "amtd.r6security.com", Resource: "securityevents", Verb: "get", ClusterScoped: true}, Reason: "adapter-rotate detector authority"})
		for _, verb := range []string{"get", "list", "create", "update", "delete"} {
			add(out, Requirement{Namespace: cfg.OperatorNamespace, Verb: authz.Verb{Resource: "configmaps", Verb: verb}, Reason: "adapter-rotate recovery journal"})
		}
	}
	if action == model.ActionRotate {
		for _, owner := range []authz.Verb{
			{Group: "apps", Resource: "replicasets", Verb: "get"},
			{Group: "apps", Resource: "deployments", Verb: "get"},
			{Resource: "replicationcontrollers", Verb: "get"},
		} {
			add(out, Requirement{Namespace: namespace, Verb: owner, Reason: "rotate owner safety"})
		}
	}
	if action == model.ActionQuarantine {
		for _, owner := range []authz.Verb{
			{Group: "apps", Resource: "replicasets", Verb: "get"},
			{Group: "apps", Resource: "statefulsets", Verb: "get"},
			{Group: "apps", Resource: "daemonsets", Verb: "get"},
			{Group: "apps", Resource: "deployments", Verb: "get"},
			{Resource: "replicationcontrollers", Verb: "get"},
			{Group: "batch", Resource: "jobs", Verb: "get"},
		} {
			add(out, Requirement{Namespace: namespace, Verb: owner, Reason: string(action) + " owner safety"})
		}
	}
	if action == model.ActionQuarantine {
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "get"}, Reason: "quarantine policy identity and recovery"})
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "services", Verb: "list"}, Reason: "quarantine service detachment"})
		for _, verb := range []string{"list", "delete"} {
			add(out, Requirement{Namespace: cfg.OperatorNamespace, Verb: authz.Verb{Resource: "configmaps", Verb: verb}, Reason: "quarantine capacity and recovery journal"})
		}
	}
	if action == model.ActionRouteRotate {
		for _, verb := range []string{"get", "list"} {
			add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "services", Verb: verb}, Reason: "route-rotate exact service scope"})
		}
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "pods", Verb: "list"}, Reason: "route-rotate ready backend inventory"})
	}
	if action == model.ActionEndpointRotate {
		for _, verb := range []string{"get", "list"} {
			add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "services", Verb: verb}, Reason: "endpoint-rotate exact service scope"})
		}
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "pods", Verb: "list"}, Reason: "endpoint-rotate target inventory"})
	}
	if action == model.ActionRouteRotate || action == model.ActionEndpointRotate {
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}, Reason: string(action) + " EndpointSlice convergence"})
		for _, verb := range []string{"get", "list", "create", "update", "delete"} {
			add(out, Requirement{Namespace: cfg.OperatorNamespace, Verb: authz.Verb{Resource: "configmaps", Verb: verb}, Reason: string(action) + " protected route journal"})
		}
	}
	if action == model.ActionRequestDrain {
		for _, verb := range []string{"get", "list"} {
			add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "services", Verb: verb}, Reason: "request-drain current service binding"})
		}
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}, Reason: "request-drain endpoint withdrawal confirmation"})
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Group: "phorvex.ai", Resource: "phorvexpolicies", Verb: "get"}, Reason: "request-drain current policy authority"})
		add(out, Requirement{Verb: authz.Verb{Resource: "namespaces", Name: namespace, Verb: "get", ClusterScoped: true}, Reason: "request-drain current namespace authority"})
		for _, verb := range []string{"get", "list", "create", "update", "delete"} {
			add(out, Requirement{Namespace: cfg.OperatorNamespace, Verb: authz.Verb{Resource: "configmaps", Verb: verb}, Reason: "request-drain recovery journal"})
		}
	}
	if action == model.ActionWarmSwap || action == model.ActionModelShardReplace {
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "pods", Verb: "list"}, Reason: string(action) + " complete warm pool inventory"})
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Resource: "services", Verb: "get"}, Reason: string(action) + " service binding"})
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Group: "apps", Resource: "replicasets", Verb: "get"}, Reason: string(action) + " ReplicaSet binding"})
		add(out, Requirement{Namespace: namespace, Verb: authz.Verb{Group: "apps", Resource: "deployments", Verb: "get"}, Reason: string(action) + " controller binding"})
	}
	if action == model.ActionWarmSwap || action == model.ActionModelShardReplace || action == model.ActionMIGRebind {
		for _, verb := range []string{"get", "list", "create", "update", "delete"} {
			add(out, Requirement{Namespace: cfg.OperatorNamespace, Verb: authz.Verb{Resource: "configmaps", Verb: verb}, Reason: string(action) + " recovery journal"})
		}
	}
}

func add(out map[string]Requirement, requirement Requirement) {
	if requirement.Verb.ClusterScoped {
		requirement.Namespace = ""
	}
	out[requirementKey(requirement)] = requirement
}

func requirementKey(requirement Requirement) string {
	return requirement.Namespace + "|" + requirement.Verb.String()
}

func review(ctx context.Context, reviews SSARClient, requirement Requirement) error {
	attributes := &authorizationv1.ResourceAttributes{
		Namespace:   requirement.Namespace,
		Group:       requirement.Verb.Group,
		Resource:    requirement.Verb.Resource,
		Subresource: requirement.Verb.Subresource,
		Name:        requirement.Verb.Name,
		Verb:        requirement.Verb.Verb,
	}
	response, err := reviews.Create(ctx, &authorizationv1.SelfSubjectAccessReview{Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: attributes}}, metav1.CreateOptions{})
	description := requirement.Verb.String() + " namespace=" + fmt.Sprintf("%q", requirement.Namespace)
	if err != nil {
		return fmt.Errorf("startup authorization unknown for %s (%s): %w", description, requirement.Reason, err)
	}
	if response == nil || response.Spec.ResourceAttributes == nil || response.Status.EvaluationError != "" || (response.Status.Allowed && response.Status.Denied) {
		return fmt.Errorf("startup authorization unknown for %s (%s): malformed SelfSubjectAccessReview response", description, requirement.Reason)
	}
	if !response.Status.Allowed || response.Status.Denied {
		reason := strings.TrimSpace(response.Status.Reason)
		if reason == "" {
			reason = "denied"
		}
		return fmt.Errorf("startup authorization denied for %s (%s): %s", description, requirement.Reason, reason)
	}
	return nil
}
