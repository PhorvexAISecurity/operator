/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package actuator

import (
	"github.com/phorvex/phorvex/internal/authz"
	"github.com/phorvex/phorvex/internal/crmrefund"
	"github.com/phorvex/phorvex/internal/datastore"
	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/persistence"
	"github.com/phorvex/phorvex/internal/servingbudget"
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
	model.ActionRotate: {{Resource: "pods", Subresource: "eviction", Verb: "create"}},
	// Includes managed repair and proven legacy retirement; RequiredVerbs routing is unchanged.
	model.ActionQuarantine:   {{Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "create"}, {Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "update"}, {Group: "networking.k8s.io", Resource: "networkpolicies", Verb: "delete"}, {Resource: "pods", Verb: "update"}},
	model.ActionDebugger:     {{Resource: "pods", Subresource: "ephemeralcontainers", Verb: "update"}},
	model.ActionCustomInject: {{Resource: "pods", Subresource: "ephemeralcontainers", Verb: "update"}},
	// LIGHT identity-rotate: delete+recreate the dedicated SA (new UID) and remove legacy
	// token Secrets. SA get/create/delete + the protected rotation journal (operator ns).
	// Secret get/delete is appended per exact legacy-token name by IdentityRotationVerbs;
	// SA get/delete and the journal are name-pinned there too. Never Secret list or token issuance.
	model.ActionIdentityRotate:                {{Resource: "serviceaccounts", Verb: "get"}, {Resource: "serviceaccounts", Verb: "create"}, {Resource: "serviceaccounts", Verb: "delete"}, {Resource: "configmaps", Verb: "get", OperatorScoped: true}, {Resource: "configmaps", Verb: "create", OperatorScoped: true}, {Resource: "configmaps", Verb: "update", OperatorScoped: true}, {Resource: "configmaps", Verb: "list", OperatorScoped: true}},
	model.ActionRouteRotate:                   {{Resource: "pods", Verb: "patch"}, {Resource: "services", Verb: "get"}, {Resource: "services", Verb: "list"}, {Resource: "services", Verb: "update"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionWarmSwap:                      {{Resource: "pods", Verb: "update"}, {Resource: "pods", Verb: "patch"}, {Resource: "pods", Verb: "delete"}, {Resource: "services", Verb: "get"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionMIGRebind:                     {{Resource: "pods", Verb: "update"}, {Resource: "pods", Verb: "delete"}},
	model.ActionKVReset:                       {{Resource: "pods", Verb: "update"}},
	model.ActionEndpointRotate:                {{Resource: "pods", Verb: "patch"}, {Resource: "services", Verb: "get"}, {Resource: "services", Verb: "list"}, {Resource: "services", Verb: "update"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionModelShardReplace:             {{Resource: "pods", Verb: "update"}, {Resource: "pods", Verb: "patch"}, {Resource: "pods", Verb: "delete"}, {Resource: "services", Verb: "get"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionAdapterRotate:                 {{Resource: "pods", Verb: "patch"}},
	model.ActionRequestDrain:                  {{Resource: "pods", Verb: "patch"}, {Resource: "services", Verb: "get"}, {Resource: "services", Verb: "list"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	model.ActionGuardrailRotate:               {{Resource: "pods", Verb: "update"}},
	model.ActionKVMigrateInvalidate:           {{Resource: "pods", Verb: "update"}},
	model.ActionSensitiveOutputPolicyActivate: {{Resource: "configmaps", Verb: "get"}, {Resource: "configmaps", Verb: "update"}},
	model.ActionVoiceMemoryNoteRevoke:         {{Resource: "configmaps", Name: "voice-memory-policy", Verb: "get"}, {Resource: "configmaps", Name: "voice-memory-policy", Verb: "update"}, {Resource: "secrets", Name: "voice-memory-state-token", Verb: "get"}},
	model.ActionVoiceRefundPairDeny:           {{Resource: "configmaps", Name: "voice-refund-policy", Verb: "get"}, {Resource: "configmaps", Name: "voice-refund-policy", Verb: "update"}, {Resource: "secrets", Name: "voice-memory-state-token", Verb: "get"}},
	model.ActionVoiceMCPToolPin:               {{Resource: "configmaps", Name: "voice-mcp-tool-policy", Verb: "get"}, {Resource: "configmaps", Name: "voice-mcp-tool-policy", Verb: "update"}, {Resource: "secrets", Name: "voice-memory-state-token", Verb: "get"}},
	model.ActionVoiceOutputPolicyActivate:     {{Resource: "configmaps", Name: "voice-output-policy", Verb: "get"}, {Resource: "configmaps", Name: "voice-output-policy", Verb: "update"}, {Resource: "secrets", Name: "voice-memory-state-token", Verb: "get"}},
	model.ActionVoiceSessionAdmissionEnforce:  {{Resource: "configmaps", Name: "voice-session-admission-policy", Verb: "get"}, {Resource: "configmaps", Name: "voice-session-admission-policy", Verb: "update"}, {Resource: "configmaps", Name: "phorvex-voice-admission-journal", Verb: "get", OperatorScoped: true}, {Resource: "configmaps", Name: "phorvex-voice-admission-journal", Verb: "update", OperatorScoped: true}, {Resource: "secrets", Name: "voice-memory-state-token", Verb: "get"}, {Resource: "services", Name: "voice-bot", Verb: "get"}, {Group: "networking.k8s.io", Resource: "ingresses", Name: "voice-bot-public", Verb: "get"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	// Named like the Voice policy actions: the chart grants ConfigMap get/update in litellm ONLY on
	// the gateway's client-policy ConfigMap, so an unnamed namespace-wide update check is always
	// denied — the startup preflight then refuses to start the operator once a policy enables this
	// action, and the capability gate never offers it. The journal lives in the operator namespace.
	model.ActionLiteLLMClientRevoke: {{Resource: "configmaps", Name: litellmclient.PolicyConfigMapName, Verb: "get"}, {Resource: "configmaps", Name: litellmclient.PolicyConfigMapName, Verb: "update"}, {Resource: "configmaps", Name: litellmclient.JournalName, Verb: "get", OperatorScoped: true}, {Resource: "configmaps", Name: litellmclient.JournalName, Verb: "update", OperatorScoped: true}, {Resource: "pods", Verb: "get"}, {Resource: "pods", Verb: "list"}, {Resource: "services", Verb: "get"}},
	// The chart grants ConfigMap get/update in the crm namespace ONLY on the deny-guard
	// ConfigMap, so an unnamed namespace-wide update is denied and the startup preflight
	// refuses to start once a policy enables this action without the exact grant. No journal:
	// the guard ledger (state.json) is the idempotency record.
	model.ActionCRMRefundRevoke:     {{Resource: "configmaps", Name: crmrefund.GuardConfigMapName, Verb: "get"}, {Resource: "configmaps", Name: crmrefund.GuardConfigMapName, Verb: "update"}, {Resource: "pods", Verb: "get"}, {Resource: "pods", Verb: "list"}, {Resource: "services", Verb: "get"}},
	// Namespace-parametric: the chart grants ConfigMap get/update on the app-facing datastore
	// store CM plus read-only get on the operator-owned trusted-snapshot CM, per enabled
	// namespace. No journal: the store content hash is the idempotency record.
	model.ActionDatastoreRestore: {{Resource: "configmaps", Name: datastore.StoreConfigMapName, Verb: "get"}, {Resource: "configmaps", Name: datastore.StoreConfigMapName, Verb: "update"}, {Resource: "configmaps", Name: datastore.TrustedSnapshotConfigMapName, Verb: "get"}, {Resource: "pods", Verb: "get"}, {Resource: "pods", Verb: "list"}, {Resource: "services", Verb: "get"}},
	model.ActionEndpointLeaseRevoke: {{Resource: "configmaps", Name: "phorvex-endpoint-lease-policy", Verb: "get"}, {Resource: "configmaps", Name: "phorvex-endpoint-lease-policy", Verb: "update"}, {Resource: "configmaps", Name: "guardrail-proxy", Verb: "get"}, {Resource: "configmaps", Name: "phorvex-endpoint-lease-journal", Verb: "get", OperatorScoped: true}, {Resource: "configmaps", Name: "phorvex-endpoint-lease-journal", Verb: "update", OperatorScoped: true}, {Resource: "pods", Verb: "get"}, {Resource: "pods", Verb: "list"}, {Resource: "services", Verb: "get"}, {Group: "apps", Resource: "deployments", Verb: "get"}, {Group: "apps", Resource: "replicasets", Verb: "get"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	// controller-stop retires an attacker-created controller end-to-end: scale the exact
	// owner (Deployment/StatefulSet/ReplicaSet) to zero via the scale subresource
	// (UID/resourceVersion-bound JSON-patch), then delete its exact child Pods (UID
	// preconditions). The list verbs are the no-legitimate-service-floor safety proof
	// (persistence.CheckSafety) and the Deployment->ReplicaSet child enumeration; the
	// operator-scoped ConfigMap get is the reviewed desired-state inventory read.
	model.ActionControllerStop: {{Group: "apps", Resource: "deployments", Subresource: "scale", Verb: "get"}, {Group: "apps", Resource: "deployments", Subresource: "scale", Verb: "patch"}, {Group: "apps", Resource: "statefulsets", Subresource: "scale", Verb: "get"}, {Group: "apps", Resource: "statefulsets", Subresource: "scale", Verb: "patch"}, {Group: "apps", Resource: "replicasets", Subresource: "scale", Verb: "get"}, {Group: "apps", Resource: "replicasets", Subresource: "scale", Verb: "patch"}, {Resource: "pods", Verb: "delete"}, {Group: "apps", Resource: "replicasets", Verb: "list"}, {Group: "policy", Resource: "poddisruptionbudgets", Verb: "list"}, {Group: "autoscaling", Resource: "horizontalpodautoscalers", Verb: "list"}, {Resource: "services", Verb: "list"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}, {Resource: "configmaps", Name: persistence.InventoryName, Verb: "get", OperatorScoped: true}},
	// throttle writes ONLY the limiter's admission-budget ConfigMap (the proxy refreshes it
	// every second and enforces it for every request); the chart grants get/update on exactly
	// that named object, so an unnamed namespace-wide update is denied and the startup preflight
	// refuses to start once a policy enables throttle without the exact grant. The journal lives
	// in the operator namespace. No pods/eviction, no HPA (autoscaling), no deployments/scale
	// verbs — the replica count and HPA are deliberately never mutated.
	model.ActionThrottle: {{Group: "phorvex.ai", Resource: "phorvexpolicies", Name: "cost-defense", Verb: "get"}, {Group: "apps", Resource: "replicasets", Verb: "get"}, {Resource: "configmaps", Name: servingbudget.StatusName, Verb: "get"}, {Group: "amtd.r6security.com", Resource: "securityevents", Verb: "get", ClusterScoped: true}, {Resource: "configmaps", Name: servingbudget.ConfigName, Verb: "get"}, {Resource: "configmaps", Name: servingbudget.ConfigName, Verb: "update"}, {Resource: "configmaps", Name: servingbudget.JournalName, Verb: "get", OperatorScoped: true}, {Resource: "configmaps", Name: servingbudget.JournalName, Verb: "update", OperatorScoped: true}, {Resource: "pods", Verb: "get"}, {Resource: "pods", Verb: "list"}, {Resource: "services", Verb: "get"}, {Group: "apps", Resource: "deployments", Verb: "get"}, {Group: "discovery.k8s.io", Resource: "endpointslices", Verb: "list"}},
	// k8s-object-revert CASes a drifted operator-trusted ConfigMap's .data back to its snapshot.
	// get is the authoritative pre-read of each referenced ConfigMap (its snapshot annotation +
	// current data); update is the only mutation. Namespace-wide (not a fixed object name) because
	// the action is generic over any operator-trusted ConfigMap the flagged pod references; the
	// handler bounds itself to only-restore-the-operator-snapshot, so the broad verb is safe. Pod
	// reads are broad scanner context (excluded here by the T1-E rule).
	model.ActionK8sObjectRevert: {{Resource: "configmaps", Verb: "get"}, {Resource: "configmaps", Verb: "update"}},
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

// IdentityRotationVerbs resolves exact names for least-privilege SSAR. Namespace SA
// create remains unnamed because Kubernetes cannot name-restrict a create grant; the
// rotation journal (operator ns) and SA get/delete are name-pinned, and legacy Secret
// get/delete are appended per exact token name.
func IdentityRotationVerbs(verbs []authz.Verb, o *model.IdentityRotationObservation) []authz.Verb {
	out := append([]authz.Verb(nil), verbs...)
	if o == nil {
		return out
	}
	for i := range out {
		if out[i].Resource == "configmaps" && (out[i].Verb == "get" || out[i].Verb == "update") {
			out[i].Name = identityJournalName(Request{IdentityRotationObservation: o})
		}
		if out[i].Resource == "serviceaccounts" && out[i].Verb != "create" {
			out[i].Name = o.ServiceAccountName
		}
	}
	for _, s := range o.LegacyTokenSecrets {
		for _, v := range []string{"get", "delete"} {
			out = append(out, authz.Verb{Resource: "secrets", Name: s.Name, Verb: v})
		}
	}
	return out
}
