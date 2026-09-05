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
