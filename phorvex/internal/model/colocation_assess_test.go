package model

import (
	"encoding/json"
	"testing"
	"time"
)

func colocFixture() ColocationInput {
	p := Pod{Namespace: "a", Name: "leader", UID: "a1", Node: "n1"}
	q := Pod{Namespace: "b", Name: "neighbor", UID: "b1", Node: "n1"}
	return ColocationInput{Target: p, TargetKnown: true, Tenant: "A", Pods: []Pod{p, q},
		Membership:      map[string][]string{"a/leader": {"A"}, "b/neighbor": {"B"}},
		NamespaceLabels: map[string]map[string]string{"a": {}, "b": {}}, Events: map[string][]SecurityEventInfo{},
		PodsComplete: true, PoliciesComplete: true, EventsComplete: true, Now: time.Unix(123, 0)}
}
func TestColocationFactTrustInventory(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ColocationInput)
		want string
	}{
		{"untrusted peer", func(*ColocationInput) {}, "present"},
		{"directional peer", func(x *ColocationInput) { x.Peers = []string{"B"} }, "absent"},
		{"own tenant", func(x *ColocationInput) { x.Membership["b/neighbor"] = []string{"A"} }, "absent"},
		{"no policy", func(x *ColocationInput) { delete(x.Membership, "b/neighbor") }, "present"},
		{"ambiguous", func(x *ColocationInput) { x.Membership["b/neighbor"] = []string{"A", "B"} }, "unknown"},
		{"daemonset", func(x *ColocationInput) { x.Pods[1].OwnerKind = "DaemonSet" }, "absent"},
		{"kube namespace", func(x *ColocationInput) { x.Pods[1].Namespace = "kube-system" }, "absent"},
		{"declared infrastructure", func(x *ColocationInput) { x.NamespaceLabels["b"]["phorvex.ai/trust-class"] = "infrastructure" }, "absent"},
		{"monitoring name insufficient", func(x *ColocationInput) {
			x.Pods[1].Namespace = "monitoring"
			x.NamespaceLabels["monitoring"] = map[string]string{}
		}, "present"},
		{"unknown inventory", func(x *ColocationInput) { x.Pods = x.Pods[:1]; x.PodsComplete = false }, "unknown"},
		{"witness despite incomplete inventory", func(x *ColocationInput) { x.PodsComplete = false }, "present"},
		{"namespace unavailable", func(x *ColocationInput) { delete(x.NamespaceLabels, "b") }, "unknown"},
		{"policy list failed", func(x *ColocationInput) { x.PoliciesComplete = false }, "unknown"},
		{"event list failed cannot trust infrastructure", func(x *ColocationInput) { x.Pods[1].OwnerKind = "DaemonSet"; x.EventsComplete = false }, "unknown"},
		{"known unscheduled", func(x *ColocationInput) { x.Target.Node = "" }, "absent"},
		{"missing target", func(x *ColocationInput) { x.TargetKnown = false }, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := colocFixture()
			tt.edit(&x)
			a := AssessColocation(x)
			if a.State != tt.want {
				t.Fatalf("got %s (%s), want %s", a.State, a.Reason, tt.want)
			}
		})
	}
	// Reverse evaluation has no peer declaration: A trusting B does not imply B trusts A.
	x := colocFixture()
	x.Target = x.Pods[1]
	x.Tenant = "B"
	if AssessColocation(x).State != "present" {
		t.Fatal("reverse trust invented")
	}
}
func TestColocationDoesNotGuessEventHalfLife(t *testing.T) {
	// The source uses a linear horizon, not the half-life named in the ruling.
	// Until that binding is settled, before/at/after values cannot establish expiry.
	for _, age := range []time.Duration{0, time.Minute - time.Nanosecond, time.Minute, time.Minute + time.Nanosecond} {
		for _, missing := range []bool{false, true} {
			x := colocFixture()
			x.Pods[1].OwnerKind = "DaemonSet"
			x.Events["b/neighbor"] = []SecurityEventInfo{{Name: "det", Trust: "trusted", TargetsPod: true, Age: age, TimestampMissing: missing}}
			if a := AssessColocation(x); a.State != "unknown" {
				t.Fatalf("age=%v missing=%v -> %s", age, missing, a.State)
			}
		}
	}
	x := colocFixture()
	x.Peers = []string{"B"}
	x.Events["b/neighbor"] = []SecurityEventInfo{{Trust: "unstamped", TargetsPod: true}}
	if AssessColocation(x).State != "absent" {
		t.Fatal("untrusted detector affected classification")
	}
}
func TestColocationUnresolvedWeightAndDeterminism(t *testing.T) {
	x := colocFixture()
	a := AssessColocation(x)
	first, _ := json.Marshal(a)
	x.Pods[0], x.Pods[1] = x.Pods[1], x.Pods[0]
	b, _ := json.Marshal(AssessColocation(x))
	if string(first) != string(b) {
		t.Fatal("inventory order changed record")
	}
	for _, flag := range []bool{false, true} {
		x.CoverEnabled = flag
		a = AssessColocation(x)
		if a.Weight.Status != "UNRESOLVED" || a.Weight.Value != nil || a.ScoringAdmitted || a.EffectiveContribution != 0 || a.ScoringReason != "weight-unresolved" || a.PredictedCover || a.ConfirmedInvalidation {
			t.Fatalf("numeric admission: %+v", a)
		}
	}
}
func TestColocationObservedDestinationConditions(t *testing.T) {
	x := colocFixture()
	s := Pod{Namespace: "a", Name: "shadow", UID: "s", Node: "n2"}
	x.Pods = append(x.Pods, s)
	x.Membership["a/shadow"] = []string{"A"}
	bind := WarmSwapObservation{BindingKnown: true, Leader: x.Target, Shadow: s, ShadowReady: true, TriggerKnown: true, TriggerNode: "n1"}
	check := func(want string) {
		t.Helper()
		state, _ := ColocationCoverCondition(x, bind)
		if state != want {
			t.Fatalf("got %s want %s", state, want)
		}
	}
	check("true")
	bind.Shadow.Node = "n1"
	check("false")
	bind.Shadow.Node = "n2"
	bind.TriggerNode = "n2"
	check("false")
	bind.TriggerNode = "n1"
	bind.TriggerKnown = false
	check("unknown")
	bind.TriggerKnown = true
	x.PodsComplete = false
	check("unknown")
	x.PodsComplete = true
	x.Membership["a/shadow"] = []string{"B"}
	check("false")
	x.Membership["a/shadow"] = []string{"A"}
	x.Events["a/shadow"] = []SecurityEventInfo{{Trust: "trusted", TargetsPod: true}}
	check("unknown")
	delete(x.Events, "a/shadow")
	bind.BindingKnown = false
	check("unknown")
}
