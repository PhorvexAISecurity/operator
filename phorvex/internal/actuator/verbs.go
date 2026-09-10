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
// Each entry is the MUTATING operations the action's native handler actually performs,
// read from the handler code (the T1-E baseline verb table), NOT from RBAC markers.
//
// Reads (get/list pods, owner-object gets) are intentionally excluded: they are broadly
// granted, and the gate's question is "may I ACTUATE?" — gating on the mutation both
// matches the semantics and BOUNDS SSAR amplification (P-BOUNDED-AUTHZ: fewer distinct
// verbs ⇒ fewer cache keys ⇒ fewer apiserver calls). An empty entry is allowed for a
// generatable action that performs no cluster mutation (none today); disable/noop are
// declared-only, never generated, so they are deliberately absent.
//
// Every model.MutatingActions member MUST have an entry — verbs_test.go fails the build
// otherwise (the action-completeness pattern), so a new action forces a verb decision.
var actionVerbs = map[model.Action][]authz.Verb{
	model.ActionRotate: {{Resource: "pods", Verb: "delete"}},
	// Includes managed repair and proven legacy retirement; RequiredVerbs routing is unchanged.
	model.ActionQuarantine:          {{Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "create"}, {Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "update"}, {Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "delete"}, {Resource: "pods", Verb: "update"}},
	model.ActionDebugger:            {{Resource: "pods/ephemeralcontainers", Verb: "update"}},
	model.ActionCustomInject:        {{Resource: "pods/ephemeralcontainers", Verb: "update"}},
	model.ActionIdentityRotate:      {{Resource: "pods", Verb: "update"}},
	model.ActionRouteRotate:         {{Resource: "pods", Verb: "update"}, {Resource: "services", Verb: "update"}},
	model.ActionWarmSwap:            {{Resource: "pods", Verb: "update"}, {Resource: "pods", Verb: "delete"}, {Resource: "pods", Verb: "create"}},
	model.ActionMIGRebind:           {{Resource: "pods", Verb: "update"}, {Resource: "pods", Verb: "delete"}},
	model.ActionKVReset:             {{Resource: "pods", Verb: "update"}},
	model.ActionEndpointRotate:      {{Resource: "pods", Verb: "update"}, {Resource: "services", Verb: "update"}},
	model.ActionModelShardReplace:   {{Resource: "pods", Verb: "update"}, {Resource: "pods", Verb: "delete"}, {Resource: "pods", Verb: "create"}},
	model.ActionAdapterRotate:       {{Resource: "pods", Verb: "update"}},
	model.ActionRequestDrain:        {{Resource: "pods", Verb: "update"}},
	model.ActionGuardrailRotate:     {{Resource: "pods", Verb: "update"}},
	model.ActionKVMigrateInvalidate: {{Resource: "pods", Verb: "update"}},
}

// phoenixRuleVerbs are the RBAC verbs a PHOENIX-ROUTED action needs. On that path the
// operator does NOT mutate pods — it CREATES a controlled SecurityEvent (RuleTypeFor) that
// Phoenix (R6) enacts. The operator holds this grant CLUSTER-WIDE (rbac.yaml base rule
// amtd.r6security.com/securityevents:[get,list,watch,create]), whereas the native pod
// verbs are bound only per phorvex.actuatorNamespaces. (M-160.)
var phoenixRuleVerbs = []authz.Verb{{Group: "amtd.r6security.com", Resource: "securityevents", Verb: "create"}}

// RequiredVerbs returns the RBAC verbs the capability gate must confirm before action a is
// offered — ROUTING-AWARE (M-160). A Phoenix-routed action (RuleTypeFor != "") is gated on
// the SecurityEvent-create verb the operator actually uses, NOT the native handler's pod
// verbs it never touches on that path — the fix for the no-rbac false-exclusion of
// rotate/quarantine outside the native-bound namespaces. Native-routed actions keep their
// own verbs. A non-generatable/unmapped action returns nil (no RBAC gate).
//
// This tracks the HYBRID actuator's routing (the production default; hybrid.go delegates by
// exactly this RuleTypeFor). A pure-native actuator would take the native path for
// rotate/quarantine; making that precise is the Actuator-interface method (deferred).
func RequiredVerbs(a model.Action) []authz.Verb {
	if RuleTypeFor(a) != "" {
		return phoenixRuleVerbs
	}
	return actionVerbs[a]
}
