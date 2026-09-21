/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package actuator

import (
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/model"
)

// actionVerbs is the SINGLE SOURCE OF TRUTH for the RBAC verbs the T1-E capability gate
// reviews (via SelfSubjectAccessReview) before an action is offered to the optimizer.
// Each entry is the operations the action's native handler must have at dispatch,
// read from the handler code (the T1-E baseline verb table), NOT from RBAC markers.
//
// Broad scanner reads (get/list pods, owner-object gets) are intentionally excluded: they are broadly
// granted, and the gate's question is "may I ACTUATE?" — gating on the mutation both
// matches the semantics and BOUNDS SSAR amplification (P-BOUNDED-AUTHZ: fewer distinct
// verbs ⇒ fewer cache keys ⇒ fewer apiserver calls). Request-drain and scalar warm Service/
// EndpointSlice reads are included because they are action-specific confirmation authority,
// not scanner context.
// An empty entry is allowed for a
// generatable action that performs no cluster mutation (none today); disable/noop are
// declared-only, never generated, so they are deliberately absent.
//
// Every model.MutatingActions member MUST have an entry — verbs_test.go fails the build
// otherwise (the action-completeness pattern), so a new action forces a verb decision.
var actionVerbs = map[model.Action][]authz.Verb{
	model.ActionRotate: {{Resource: "pods", Verb: "delete"}},
	// Includes managed repair and proven legacy retirement; RequiredVerbs routing is unchanged.
	model.ActionQuarantine:          {{Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "create"}, {Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "update"}, {Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "delete"}, {Resource: "pods", Verb: "update"}},
	model.ActionDebugger:            {{Resource: "pods", Subresource: "ephemeralcontainers", Verb: "update"}},
	model.ActionCustomInject:        {{Resource: "pods", Subresource: "ephemeralcontainers", Verb: "update"}},
	model.ActionIdentityRotate:      {{Resource: "pods", Verb: "update"}},
	model.ActionRouteRotate:         {{Resource: "pods", Verb: "patch"}, {Resource: "services", Verb: "get"}, {Resource: "services", Verb: "list"}, {Resource: "services", Verb: "update"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionWarmSwap:            {{Resource: "pods", Verb: "update"}, {Resource: "pods", Verb: "patch"}, {Resource: "pods", Verb: "delete"}, {Resource: "services", Verb: "get"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionMIGRebind:           {{Resource: "pods", Verb: "update"}, {Resource: "pods", Verb: "delete"}},
	model.ActionKVReset:             {{Resource: "pods", Verb: "update"}},
	model.ActionEndpointRotate:      {{Resource: "pods", Verb: "patch"}, {Resource: "services", Verb: "get"}, {Resource: "services", Verb: "list"}, {Resource: "services", Verb: "update"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionModelShardReplace:   {{Resource: "pods", Verb: "update"}, {Resource: "pods", Verb: "patch"}, {Resource: "pods", Verb: "delete"}, {Resource: "services", Verb: "get"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionAdapterRotate:       {{Resource: "pods", Verb: "patch"}},
	model.ActionRequestDrain:        {{Resource: "pods", Verb: "patch"}, {Resource: "services", Verb: "get"}, {Resource: "services", Verb: "list"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionGuardrailRotate:     {{Resource: "pods", Verb: "update"}},
	model.ActionKVMigrateInvalidate: {{Resource: "pods", Verb: "update"}},
}

// phoenixRuleVerbs are the RBAC verbs a PHOENIX-ROUTED action needs. On that path the
// operator does NOT mutate pods — it CREATES a controlled SecurityEvent (RuleTypeFor) that
// Phoenix (R6) enacts. The operator holds this grant CLUSTER-WIDE (rbac.yaml base rule
// amtd.r6security.com/securityevents:[get,list,watch,create]), whereas the native pod
// verbs are bound only per phorvex.actuatorNamespaces. (M-160.)
var phoenixRuleVerbs = []authz.Verb{{Group: "amtd.r6security.com", Resource: "securityevents", Verb: "create", ClusterScoped: true}}

// RequiredVerbs returns the RBAC verbs the capability gate must confirm before action a is
// offered — ROUTING-AWARE (M-160). A Phoenix-routed action is gated on
// the SecurityEvent-create verb the operator actually uses, NOT the native handler's pod
// verbs it never touches on that path — the fix for the no-rbac false-exclusion of
// rotate/quarantine outside the native-bound namespaces. Native-routed actions keep their
// own verbs. A non-generatable/unmapped action returns nil (no RBAC gate).
//
// RequiredVerbsForBackend takes the resolved backend so native, Phoenix and hybrid runtime
// checks use the same RouteFor decision as dispatch. RequiredVerbs below preserves the
// established hybrid behavior for compatibility callers.
func RequiredVerbsForBackend(backend Backend, a model.Action) []authz.Verb {
	if RouteFor(backend, a) == BackendPhoenix {
		if accepted, _ := phoenixAccepts(a); accepted {
			return phoenixRuleVerbs
		}
		return nil
	}
	if RouteFor(backend, a) != BackendNative {
		return nil
	}
	return actionVerbs[a]
}

// RequiredVerbs retains the established hybrid routing for compatibility callers. Runtime
// capability and boot admission pass the resolved backend to RequiredVerbsForBackend.
func RequiredVerbs(a model.Action) []authz.Verb {
	return RequiredVerbsForBackend(BackendHybrid, a)
}
