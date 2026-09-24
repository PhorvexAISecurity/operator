package v1beta1

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestQuarantineNetworkPolicyNamePreservesLegacyAndAdmitsLongPods(t *testing.T) {
	if got := QuarantineNetworkPolicyName("nats", "nats-0"); got != "nats-nats-0-policy" {
		t.Fatalf("legacy identity changed: %q", got)
	}
	ns := "phorvex-nats-exposure-fixture"
	pod := "nats-response-" + strings.Repeat("a", 24) + "-1234567890-abcde"
	legacy := ns + "-" + pod + "-policy"
	if len(validation.IsValidLabelValue(legacy)) == 0 {
		t.Fatal("long legacy selector unexpectedly valid; regression no longer exercises admission")
	}
	got := QuarantineNetworkPolicyName(ns, pod)
	if len(got) > 63 || len(validation.IsValidLabelValue(got)) != 0 {
		t.Fatalf("new selector still fails Kubernetes API label validation: %q", got)
	}
	if got != QuarantineNetworkPolicyName(ns, pod) || got == QuarantineNetworkPolicyName(ns, pod+"x") ||
		got == QuarantineNetworkPolicyName(ns+"x", pod) {
		t.Fatal("long-name identity unstable or insufficiently bound")
	}
	maximum := QuarantineNetworkPolicyName(strings.Repeat("n", 63), strings.Repeat("p", 253))
	if len(maximum) > 63 || len(validation.IsValidLabelValue(maximum)) != 0 {
		t.Fatalf("maximum valid namespace/Pod tuple cannot be used as a selector: %q", maximum)
	}
	// These tuples produce the same raw hyphen-concatenated legacy name. The
	// NUL-separated digest must retain the namespace/Pod boundary.
	long := strings.Repeat("x", 55)
	if QuarantineNetworkPolicyName("team-a", "b-"+long) == QuarantineNetworkPolicyName("team", "a-b-"+long) {
		t.Fatal("long tuple boundaries collapsed into the same selector")
	}
}
