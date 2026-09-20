package actuator

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// TestRequiredVerbsCoversEveryMutatingAction is the single-source-of-truth guard verbs.go
// promises: every model.MutatingActions member MUST have an actionVerbs entry (an explicit
// empty entry is allowed for a generatable action that performs no cluster mutation).
// Declared-only actions (disable, noop) are not MutatingActions and are rejected by the
// second loop. So a NEW action forces a verb decision instead of silently skipping the
// capability gate's RBAC leg — the exact silent-gap class T1-E exists to kill. Mirrors the
// action-completeness pattern (mustCoverAllActions / crd_vocabulary_test).
func TestRequiredVerbsCoversEveryMutatingAction(t *testing.T) {
	known := map[model.Action]bool{}
	for _, a := range model.MutatingActions {
		known[a] = true
		if _, ok := actionVerbs[a]; !ok {
			t.Errorf("model.MutatingActions member %q has no actionVerbs entry (add its RBAC verbs, or an explicit empty entry if it performs no cluster mutation)", a)
		}
	}
	for a := range actionVerbs {
		if !known[a] {
			t.Errorf("actionVerbs has %q which is not a model.MutatingActions member (typo or a removed action left behind)", a)
		}
	}
}

// TestRequiredVerbsRoutingAware (M-160): a Phoenix-routed action (RuleTypeFor != "") is gated
// on the SecurityEvent-create verb the operator actually uses on that path — held cluster-wide —
// NOT the native pod verbs it never touches (which are bound only per actuatorNamespaces). A
// native-routed action keeps its own verbs. This is the fix for the no-rbac false-exclusion of
// rotate/quarantine outside the native-bound namespaces.
func TestRequiredVerbsRoutingAware(t *testing.T) {
	for _, a := range []model.Action{model.ActionRotate, model.ActionQuarantine} {
		got := RequiredVerbs(a)
		if len(got) != 1 || got[0].Group != "amtd.r6security.com" || got[0].Resource != "securityevents" || got[0].Verb != "create" || !got[0].ClusterScoped {
			t.Errorf("Phoenix-routed %q must gate on amtd.r6security.com/securityevents:create, got %+v", a, got)
		}
	}
	// Native-routed actions keep their native handler verbs.
	if got := RequiredVerbs(model.ActionKVReset); len(got) != 1 || got[0].Resource != "pods" || got[0].Verb != "update" {
		t.Errorf("native-routed kv-reset must keep pods/update, got %+v", got)
	}
	if got := RequiredVerbs(model.ActionRouteRotate); len(got) != 5 {
		t.Errorf("native-routed route-rotate must keep its 5 native write and confirmation verbs, got %+v", got)
	}
	for _, action := range []model.Action{model.ActionRouteRotate, model.ActionEndpointRotate} {
		verbs := RequiredVerbsForBackend(BackendNative, action)
		var podPatch, podUpdate, serviceGet, serviceList, serviceUpdate, endpointList, endpointMutation bool
		for _, verb := range verbs {
			podPatch = podPatch || (verb.Resource == "pods" && verb.Verb == "patch")
			podUpdate = podUpdate || (verb.Resource == "pods" && verb.Verb == "update")
			serviceGet = serviceGet || (verb.Resource == "services" && verb.Verb == "get")
			serviceList = serviceList || (verb.Resource == "services" && verb.Verb == "list")
			serviceUpdate = serviceUpdate || (verb.Resource == "services" && verb.Verb == "update")
			endpointList = endpointList || (verb.Group == "discovery.k8s.io" && verb.Resource == "endpointslices" && verb.Verb == "list")
			endpointMutation = endpointMutation || (verb.Resource == "endpointslices" && verb.Verb != "list")
		}
		if len(verbs) != 5 || !podPatch || podUpdate || !serviceGet || !serviceList || !serviceUpdate || !endpointList || endpointMutation {
			t.Errorf("%s permissions do not exactly match Pod patch, Service read/update, and read-only EndpointSlice confirmation: %+v", action, verbs)
		}
	}
}

func TestRequiredVerbsFollowResolvedBackend(t *testing.T) {
	nativeRotate := RequiredVerbsForBackend(BackendNative, model.ActionRotate)
	if len(nativeRotate) != 1 || nativeRotate[0].Resource != "pods" || nativeRotate[0].Verb != "delete" {
		t.Fatalf("native rotate permissions = %+v", nativeRotate)
	}
	hybridRotate := RequiredVerbsForBackend(BackendHybrid, model.ActionRotate)
	if len(hybridRotate) != 1 || hybridRotate[0].Resource != "securityevents" || !hybridRotate[0].ClusterScoped {
		t.Fatalf("hybrid rotate permissions = %+v", hybridRotate)
	}
	if got := RequiredVerbsForBackend(BackendPhoenix, model.ActionKVReset); len(got) != 0 {
		t.Fatalf("unsupported Phoenix action acquired permissions: %+v", got)
	}
	debugger := RequiredVerbsForBackend(BackendNative, model.ActionDebugger)
	if len(debugger) != 1 || debugger[0].Resource != "pods" || debugger[0].Subresource != "ephemeralcontainers" || debugger[0].Verb != "update" {
		t.Fatalf("debugger subresource permissions = %+v", debugger)
	}
	for _, action := range []model.Action{model.ActionWarmSwap, model.ActionModelShardReplace} {
		var patch, serviceGet, endpointList bool
		for _, verb := range RequiredVerbsForBackend(BackendNative, action) {
			patch = patch || (verb.Resource == "pods" && verb.Verb == "patch")
			serviceGet = serviceGet || (verb.Resource == "services" && verb.Verb == "get")
			endpointList = endpointList || (verb.Group == "discovery.k8s.io" && verb.Resource == "endpointslices" && verb.Verb == "list")
		}
		if !patch || !serviceGet || !endpointList {
			t.Fatalf("%s lacks Pod patch or exact Service/EndpointSlice observation authority", action)
		}
	}
	adapter := RequiredVerbsForBackend(BackendNative, model.ActionAdapterRotate)
	if len(adapter) != 1 || adapter[0].Resource != "pods" || adapter[0].Verb != "patch" {
		t.Fatalf("adapter-rotate permissions must match its optimistic completion patch: %+v", adapter)
	}
	var drainPatch, drainUpdate, endpointGet, endpointList bool
	for _, verb := range RequiredVerbsForBackend(BackendNative, model.ActionRequestDrain) {
		drainPatch = drainPatch || (verb.Resource == "pods" && verb.Verb == "patch")
		drainUpdate = drainUpdate || (verb.Resource == "pods" && verb.Verb == "update")
		endpointGet = endpointGet || (verb.Group == "discovery.k8s.io" && verb.Resource == "endpointslices" && verb.Verb == "get")
		endpointList = endpointList || (verb.Group == "discovery.k8s.io" && verb.Resource == "endpointslices" && verb.Verb == "list")
	}
	if !drainPatch || drainUpdate || endpointGet || !endpointList {
		t.Fatalf("request-drain permissions do not match patch + read-only EndpointSlice path: %+v", RequiredVerbsForBackend(BackendNative, model.ActionRequestDrain))
	}
}

// TestRequiredVerbsAreWellFormed: every declared verb names a resource and a verb (a blank
// tuple would make the SSAR meaningless / always-allow).
func TestRequiredVerbsAreWellFormed(t *testing.T) {
	for action, verbs := range actionVerbs {
		for _, v := range verbs {
			if v.Resource == "" || v.Verb == "" || strings.Contains(v.Resource, "/") {
				t.Errorf("action %q has a malformed verb %+v (resource and verb are required)", action, v)
			}
		}
	}
}
