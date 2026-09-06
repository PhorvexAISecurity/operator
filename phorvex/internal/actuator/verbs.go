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
	model.ActionRotate:              {{Resource: "pods", Verb: "delete"}},
	model.ActionQuarantine:          {{Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "create"}, {Resource: "pods", Verb: "update"}},
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

// RequiredVerbs returns the RBAC verbs the capability gate must confirm before action a
// is offered. A non-generatable action (e.g. noop) or an unmapped one returns nil (no
// RBAC gate); the completeness test guarantees every generatable action is mapped.
func RequiredVerbs(a model.Action) []authz.Verb {
	return actionVerbs[a]
}
