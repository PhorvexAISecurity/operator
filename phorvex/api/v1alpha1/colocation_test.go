package v1alpha1

import "testing"

func TestColocationPolicyCopyIsIndependent(t *testing.T) {
	p := &PhorvexPolicySpec{Trust: TrustSpec{PeerPolicies: []string{"A"}}}
	copy := p.DeepCopy()
	copy.Trust.PeerPolicies[0] = "B"
	if p.Trust.PeerPolicies[0] != "A" {
		t.Fatal("peer list aliased")
	}
	if p.Cover.WarmSwap.Enabled {
		t.Fatal("default flag is on")
	}
}
