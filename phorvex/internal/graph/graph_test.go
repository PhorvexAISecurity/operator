/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package graph

import (
	"testing"

	"k8s.io/apimachinery/pkg/labels"
)

func TestResolveRBACLateral(t *testing.T) {
	roles := []Role{
		{Name: "pod-admin", Cluster: true, Rules: []PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create", "delete"}}}},
		{Namespace: "ns1", Name: "secret-reader", Rules: []PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}}},
		{Namespace: "ns1", Name: "readonly", Rules: []PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}}},
	}
	bindings := []RoleBinding{
		{Cluster: true, RoleRefKind: "ClusterRole", RoleRefName: "pod-admin", Subjects: []Subject{{Kind: "ServiceAccount", Namespace: "ns1", Name: "attacker"}}},
		{Namespace: "ns1", RoleRefKind: "Role", RoleRefName: "secret-reader", Subjects: []Subject{{Kind: "ServiceAccount", Namespace: "ns1", Name: "reader"}}},
		{Namespace: "ns1", RoleRefKind: "Role", RoleRefName: "readonly", Subjects: []Subject{{Kind: "ServiceAccount", Namespace: "ns1", Name: "benign"}}},
	}
	perms := ResolveRBAC(roles, bindings)

	if p := perms["ns1/attacker"]; !p.PodsWrite || !p.ClusterWide || !p.HasLateral() {
		t.Errorf("attacker should have cluster-wide pod-write lateral perms, got %+v", p)
	}
	if p := perms["ns1/reader"]; !p.SecretsRead || p.ClusterWide || !p.HasLateral() {
		t.Errorf("reader should have namespaced secrets-read lateral perms, got %+v", p)
	}
	if p := perms["ns1/benign"]; p.HasLateral() {
		t.Errorf("read-only pod get/list is NOT lateral, got %+v", p)
	}
}

func TestNetworkReachabilityDefaultAllow(t *testing.T) {
	// No NetworkPolicies => default allow => everyone reaches everyone (minus self).
	pods := []PodNode{
		{Namespace: "d", Name: "a", AssetValue: 1, Node: "n1"},
		{Namespace: "d", Name: "b", AssetValue: 1, Node: "n2"},
	}
	g := Build(Input{Pods: pods})
	if g.NeighborCount("d", "a") != 1 {
		t.Errorf("default-allow: a should reach b, neighbors=%d", g.NeighborCount("d", "a"))
	}
}

func TestNetworkPolicyIsolation(t *testing.T) {
	// b is ingress-isolated (deny-all ingress: an ingress policy selecting b with no
	// rules). a should NOT reach b on the network. Different nodes (no co-loc), no RBAC.
	denyAll := NetPol{
		Namespace:      "d",
		Selector:       mustSel(map[string]string{"app": "b"}),
		HasIngressType: true,
		Ingress:        nil, // selects b, allows nothing
	}
	pods := []PodNode{
		{Namespace: "d", Name: "a", Labels: map[string]string{"app": "a"}, AssetValue: 1, Node: "n1"},
		{Namespace: "d", Name: "b", Labels: map[string]string{"app": "b"}, AssetValue: 5, Node: "n2"},
	}
	g := Build(Input{Pods: pods, NetPols: []NetPol{denyAll}})
	for _, nb := range g.Neighbors("d", "a") {
		if nb == "d/b" {
			t.Errorf("deny-all ingress on b: a must NOT reach b, but does")
		}
	}
}

func TestBlastRadiusRanksHighValueReach(t *testing.T) {
	// gateway (default-allow egress) reaches the crown-jewel; "lonely" is egress-
	// isolated so it reaches nothing => much smaller blast radius.
	denyEgress := NetPol{
		Namespace:     "d",
		Selector:      mustSel(map[string]string{"role": "lonely"}),
		HasEgressType: true,
		Egress:        nil, // selects lonely, allows no egress => reaches nothing
	}
	pods := []PodNode{
		{Namespace: "d", Name: "gateway", Labels: map[string]string{"role": "gw"}, AssetValue: 0.1, Node: "n1"},
		{Namespace: "d", Name: "jewels", Labels: map[string]string{"role": "jewels"}, AssetValue: 10, Node: "n1"}, // same node => co-loc
		{Namespace: "d", Name: "lonely", Labels: map[string]string{"role": "lonely"}, AssetValue: 0.1, Node: "n9"},
	}
	g := Build(Input{Pods: pods, NetPols: []NetPol{denyEgress}})
	bg := g.BlastRadius("d", "gateway")
	bl := g.BlastRadius("d", "lonely")
	if bg <= bl {
		t.Errorf("gateway blast (%.3f) should exceed egress-isolated lonely blast (%.3f)", bg, bl)
	}
	if bg != 1.0 {
		t.Errorf("max blast radius should normalize to 1.0, got %.3f", bg)
	}
	if bl != 0 {
		t.Errorf("egress-isolated lonely should reach nothing => blast 0, got %.3f", bl)
	}
}

func mustSel(m map[string]string) labels.Selector {
	return labels.SelectorFromSet(labels.Set(m))
}

func TestNeighborsAreListedInAStableOrder(t *testing.T) {
	var pods []PodNode
	for _, name := range []string{"e", "b", "d", "a", "c", "f", "h", "g"} {
		pods = append(pods, PodNode{Namespace: "ns", Name: name, AssetValue: 1})
	}
	first := Build(Input{Pods: pods}).Neighbors("ns", "a")
	want := []string{"ns/b", "ns/c", "ns/d", "ns/e", "ns/f", "ns/g", "ns/h"}
	for i := 0; i < 20; i++ {
		got := Build(Input{Pods: pods}).Neighbors("ns", "a")
		if len(got) != len(want) {
			t.Fatalf("neighbours = %v", got)
		}
		for j := range want {
			if got[j] != want[j] || first[j] != want[j] {
				t.Fatalf("build %d listed neighbours %v, want %v", i, got, want)
			}
		}
	}
}
