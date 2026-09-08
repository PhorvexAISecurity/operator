package actuator

import (
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
		if len(got) != 1 || got[0].Group != "amtd.r6security.com" || got[0].Resource != "securityevents" || got[0].Verb != "create" {
			t.Errorf("Phoenix-routed %q must gate on amtd.r6security.com/securityevents:create, got %+v", a, got)
		}
	}
	// Native-routed actions keep their native handler verbs.
	if got := RequiredVerbs(model.ActionKVReset); len(got) != 1 || got[0].Resource != "pods" || got[0].Verb != "update" {
		t.Errorf("native-routed kv-reset must keep pods/update, got %+v", got)
	}
	if got := RequiredVerbs(model.ActionRouteRotate); len(got) != 2 {
		t.Errorf("native-routed route-rotate must keep its 2 native verbs, got %+v", got)
	}
}

// TestRequiredVerbsAreWellFormed: every declared verb names a resource and a verb (a blank
// tuple would make the SSAR meaningless / always-allow).
func TestRequiredVerbsAreWellFormed(t *testing.T) {
	for action, verbs := range actionVerbs {
		for _, v := range verbs {
			if v.Resource == "" || v.Verb == "" {
				t.Errorf("action %q has a malformed verb %+v (resource and verb are required)", action, v)
			}
		}
	}
}
